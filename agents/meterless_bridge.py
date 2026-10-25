"""
Real integration of the Meterless world-model software (not just its schema).

agents/world_model.py still builds the graph in pure Python (fallback mode, runs everywhere).
This module additionally sends the same statements to the REAL Meterless reference engine
(integrations/meterless/, unmodified reference, run with Node) and adopts what the engine
does on its own:

  - Conflict policy: if two statements about the same attribute contradict, the engine picks a
    winner by "source-priority" and marks the others as superseded (supersededBy).
    Order: internal before NVD before vendor - our principle "the internal check has the last word".
  - Audit log and event log with the origin of each statement.
  - Stable IDs: we compare every ID from our Python reimplementation with the ID of the real engine.

Without Node (or on any error) everything keeps running unchanged with the Python reimplementation.
"""

import hashlib
import json
import os
import queue
import shutil
import subprocess
import threading
from datetime import datetime, timezone

from .world_model import stable_entity_id

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BRIDGE = os.path.join(ROOT, "integrations", "meterless", "bridge.mjs")
BUNDLE = os.path.join(ROOT, "integrations", "meterless", "world-model.mjs")
MIN_NODE_MAJOR = 18
SOURCE_PRIORITY = ["internal_ticket", "nvd", "vendor_changelog"]   # internal has the last word


class EngineError(Exception):
    pass


def node_available():
    """(True, 'v22.1.0') or (False, reason)."""
    node = shutil.which("node")
    if not node:
        return False, "node not found in PATH (install Node.js >= 18 to use the real Meterless engine)"
    if not (os.path.exists(BRIDGE) and os.path.exists(BUNDLE)):
        return False, "integrations/meterless/ is incomplete"
    try:
        version = subprocess.run([node, "--version"], capture_output=True, text=True, timeout=10).stdout.strip()
        major = int(version.lstrip("v").split(".")[0])
    except Exception as e:  # broken installation, timeout, unexpected output
        return False, f"could not determine node version ({type(e).__name__})"
    if major < MIN_NODE_MAJOR:
        return False, f"node {version} is too old (need >= {MIN_NODE_MAJOR})"
    return True, version


class MeterlessEngine:
    """A running bridge process. Use as a context manager: 'with MeterlessEngine(...) as engine:'."""

    def __init__(self, namespace, timeout=20):
        self.namespace = namespace
        self.timeout = timeout
        self._next_id = 0
        self._proc = None
        self._out = queue.Queue()
        self._err = []

    def __enter__(self):
        self._proc = subprocess.Popen(
            [shutil.which("node"), BRIDGE], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, bufsize=1)
        threading.Thread(target=self._drain_out, daemon=True).start()
        threading.Thread(target=self._drain_err, daemon=True).start()
        return self

    def __exit__(self, *exc):
        try:
            self._proc.stdin.close()
            self._proc.wait(timeout=5)
        except Exception:
            self._proc.kill()
        return False

    def _drain_out(self):
        for line in self._proc.stdout:
            self._out.put(line)
        self._out.put(None)  # process ended

    def _drain_err(self):
        for line in self._proc.stderr:
            self._err.append(line.strip())

    def call(self, cmd, **args):
        self._next_id += 1
        try:
            self._proc.stdin.write(json.dumps({"id": self._next_id, "cmd": cmd, "args": args}) + "\n")
            self._proc.stdin.flush()
            line = self._out.get(timeout=self.timeout)
        except queue.Empty:
            raise EngineError(f"engine did not answer '{cmd}' within {self.timeout}s")
        except (BrokenPipeError, OSError):
            raise EngineError("engine process is gone: " + " ".join(self._err[-2:]))
        if line is None:
            raise EngineError("engine process ended unexpectedly: " + " ".join(self._err[-2:]))
        reply = json.loads(line)
        if not reply.get("ok"):
            raise EngineError(f"engine rejected '{cmd}': {reply.get('error')}")
        return reply["result"]


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _fact_for(key, claim):
    """Which statement a source makes about the vulnerability."""
    confidence = 1.0 if claim["certainty"] == "high" else 0.35     # the same value as the edge in world_model.py
    if key == "nvd":
        severity = str(claim.get("severity_claim", ""))
        if not severity or severity.startswith("UNKNOWN"):
            return None
        return "severity", severity, confidence
    return "remediation_status", {"certainty": claim["certainty"], "text": claim["raw_text"][:300]}, confidence


def _verdicts(facts):
    """Per attribute with several statements: who won, who was superseded (the 'why' explanation)."""
    by_pred = {}
    for f in facts:
        by_pred.setdefault(f["predicate"], []).append(f)
    out = []
    for predicate, group in by_pred.items():
        if len(group) < 2:
            continue
        winners = [f for f in group if not f["superseded_by"]]
        losers = [f for f in group if f["superseded_by"]]
        if winners:
            out.append({
                "predicate": predicate, "winner_source": winners[0]["source_kind"],
                "superseded_sources": [f["source_kind"] for f in losers],
                "explanation": (f"'{predicate}': {winners[0]['source_kind']} wins over "
                                f"{', '.join(f['source_kind'] for f in losers)} (conflict policy source-priority)"),
            })
    return out


def _fingerprint(claims, as_of):
    """Fingerprint of the evidence state. Same state -> the same stored world (repeatable, resumable).
    Changed state -> a NEW world: so stale statements from earlier runs never mix with new ones
    (an internal note deleted since would otherwise keep 'winning')."""
    parts = sorted([k, c["source_name"], c["raw_text"]] for k, c in claims.items() if c["certainty_method"] != "absent-source")
    return hashlib.sha256(json.dumps([as_of, parts], sort_keys=True).encode()).hexdigest()[:10]


def _quarantine_if_corrupt(directory, namespace):
    """The reference does NOT write its file atomically (writeFileSync): a crash mid-write can
    corrupt it. If it is unreadable, it is set aside and the world rebuilt from the sources - the evidence
    is readable again. True if a repair was needed."""
    path = os.path.join(directory, ".world", f"{namespace}.json")
    if not os.path.exists(path):
        return False
    try:
        with open(path) as f:
            json.load(f)
        return False
    except (ValueError, OSError):
        n = 1
        while os.path.exists(f"{path}.corrupt-{n}"):
            n += 1
        os.replace(path, f"{path}.corrupt-{n}")
        return True


def run_engine(case, claims, mode="auto", directory=None):
    """Sends this case's statements to the real engine. ALWAYS returns a dict (never an exception),
    except mode='on' and the engine is not usable - then EngineError.
      mode: 'auto' = use if possible | 'on' = required | 'off' = never
      directory: folder for the stored world (<directory>/.world/...). If omitted: in memory only."""
    if mode == "off":
        return {"used": False, "reason": "disabled (--meterless off)"}
    ok, info = node_available()
    if not ok:
        if mode == "on":
            raise EngineError(info)
        return {"used": False, "reason": info}
    try:
        return _run(case, claims, info, directory)
    except EngineError as e:
        if mode == "on":
            raise
        return {"used": False, "reason": f"engine error, Python implementation used instead: {e}"}


def _run(case, claims, node_version, directory):
    cve_id = case["cve_id"]
    as_of = case.get("as_of") or datetime.now(timezone.utc).strftime("%Y-%m-%d")
    at = f"{as_of}T12:00:00Z"            # observation time of the evidence state; all engine timestamps derive from it
    namespace = f"{cve_id}-{_fingerprint(claims, as_of)}"
    present = [(k, c) for k, c in claims.items() if c["certainty_method"] != "absent-source"]
    absent = [k for k, c in claims.items() if c["certainty_method"] == "absent-source"]
    recovered = _quarantine_if_corrupt(directory, namespace) if directory else False

    observations = [{"externalId": cve_id, "type": "case", "title": cve_id, "text": case.get("nickname", ""), "at": at,
                     "source": {"kind": "pipeline", "by": "main"}, "entities": [{"type": "vulnerability", "name": cve_id}]}]
    for key, claim in present:       # missing sources = no observation = no evidence statement
        observations.append({
            "externalId": f"{cve_id}:{key}", "type": "source_observation", "title": claim["source_name"],
            "text": claim["raw_text"], "at": at, "source": {"kind": key, "by": "source_mapper"},
            "entities": [{"type": "vulnerability", "name": cve_id}, {"type": "source", "name": claim["source_name"]}]})

    with MeterlessEngine(namespace=namespace) as engine:
        engine.call("init", namespace=namespace, conflictPolicy="source-priority", sourcePriority=SOURCE_PRIORITY,
                    storage="local" if directory else "memory", directory=directory)
        events_before = engine.call("snapshot")["event_count"]          # > 0: an earlier stored world was loaded
        run_record = engine.call("ingest", observations=observations)   # Meterless' canonical, repeatable path

        vuln_id = engine.call("idFor", type="vulnerability", name=cve_id)
        for key, claim in present:
            src_id = engine.call("idFor", type="source", name=claim["source_name"])
            engine.call("relate", **{"from": src_id, "to": vuln_id}, type="asserts_state",
                        attrs={"certainty": claim["certainty"]}, kind=key, by="source_mapper", at=at)
            fact = _fact_for(key, claim)
            if fact:
                predicate, value, confidence = fact
                engine.call("assertFact", about=vuln_id, predicate=predicate, value=value,
                            confidence=confidence, kind=key, by="source_mapper", at=at)
        snap = engine.call("snapshot")

    # Parity: the same ID as our Python reimplementation, AND the engine really created the entity
    engine_ids = {e["id"] for e in snap["entities"]}
    expected = [(cve_id, "vulnerability", vuln_id)] + [
        (c["source_name"], "source", None) for _, c in present]
    mismatches, checked = [], 0
    for name, type_, engine_id in expected:
        py_id = stable_entity_id(name, type_)
        checked += 1
        if py_id not in engine_ids or (engine_id is not None and engine_id != py_id):
            mismatches.append({"name": name, "python": py_id, "engine": engine_id or "(not in the engine)"})

    return {
        "used": True, "engine": "meterless-world-model-reference", "node": node_version,
        "policy": "source-priority", "source_priority": SOURCE_PRIORITY,
        "id_parity": {"checked": checked, "mismatches": mismatches},
        "absent_sources": absent,
        "run_record": run_record,
        "persistence": {"enabled": bool(directory), "namespace": namespace, "as_of": as_of,
                        "events_before": events_before, "new_events": snap["event_count"] - events_before,
                        "resumed": events_before > 0, "recovered_from_corrupt_store": recovered,
                        # False = the "superseded" markers were lost after the restart (limit of the reference) and
                        # were re-derived from the log
                        "live_state_consistent": snap["facts_live_consistent"],
                        "derived_state_rebuilt_from_log": not snap["facts_live_consistent"]},
        "verdicts": _verdicts(snap["facts"]),
        "facts": snap["facts"], "relationships": snap["relationships"],
        "audit": snap["audit"], "event_count": snap["event_count"],
        "events": snap["events"],          # only for the JSONL file; main.py removes it again before saving
    }


def evidence_jsonl(cve_id, engine, events):
    """Lines for logs/<CVE>_meterless.jsonl: run record, EVERY event of the log with its origin, every
    belief, audit entries - 'here is exactly why the system believed X, and from which observation'."""
    head = {k: engine[k] for k in ("engine", "node", "policy", "source_priority", "run_record", "persistence", "id_parity")}
    lines = [{"type": "run", "cve_id": cve_id, **head}]
    for ev in events:
        lines.append({"type": "event", "seq": ev["seq"], "kind": ev["kind"], "at": ev["at"],
                      "source": (ev["payload"] or {}).get("source"), "payload": ev["payload"]})
    for v in engine["verdicts"]:
        lines.append({"type": "belief", **v})
    for a in engine["audit"]:
        lines.append({"type": "audit", **a})
    return lines


def _clip(text, n=90):
    text = " ".join(str(text).split())
    return text if len(text) <= n else text[: n - 3] + "..."


def evidence_trail(engine, claims, cve_id):
    """Evidence trail for the report: what the system believes, which observation is behind it, what was superseded.
    This makes a consumer actually read the engine data (avoids 'stored != read')."""
    if not engine.get("used"):
        return ""
    name = lambda kind: claims[kind]["source_name"] if kind in claims else kind
    lines = ["", "--- EVIDENCE TRAIL (Meterless World Model) ---"]
    sev = [f for f in engine["facts"] if f["predicate"] == "severity"]
    if sev:
        lines.append(f"Baseline: {sev[-1]['value']} (from {name(sev[-1]['source_kind'])}).")
    rem = sorted((f for f in engine["facts"] if f["predicate"] == "remediation_status"), key=lambda f: f["asserted_at"])
    winner = next((f for f in rem if not f["superseded_by"]), None)
    if winner:
        lines.append(f"Remediation belief taken from: {name(winner['source_kind'])} "
                     f"(observed {winner['asserted_at'][:10]}, run {engine['run_record']['runId']}).")
        lines.append(f"  - {_clip(winner['value']['text'])}")
    for f in rem:
        if f["superseded_by"]:
            lines.append(f"  superseded: {name(f['source_kind'])} - {_clip(f['value']['text'])}")
    lines.append(f"Policy: {engine['policy']} ({' > '.join(engine['source_priority'])}). "
                 f"Record: {engine['event_count']} events, {len(engine['audit'])} audit entries "
                 f"(full log: logs/{cve_id}_meterless.jsonl).")
    return "\n".join(lines)


def engine_summary(engine):
    """One line for the trace."""
    if not engine.get("used"):
        return f"not used: {engine.get('reason')} (Python implementation only)"
    verdicts = "; ".join(v["explanation"] for v in engine["verdicts"]) or "no conflicting facts"
    p = engine["id_parity"]
    parity = f"id parity {p['checked'] - len(p['mismatches'])}/{p['checked']}"
    return f"Meterless engine on node {engine['node']}: {verdicts}; {parity}; {engine['event_count']} events"


# ---------------------------------------------------------------------------
# Timeline: the same case over several days in ONE engine session
# ---------------------------------------------------------------------------

def _day_before(date):
    from datetime import date as _d, timedelta
    y, m, d = (int(x) for x in date.split("-"))
    return (_d(y, m, d) - timedelta(days=1)).isoformat()


def _winner_info(facts):
    """Who won at 'remediation_status' NOW, who was superseded (state right after the day)."""
    rel = [f for f in facts if f["predicate"] == "remediation_status"]
    winners = [f for f in rel if not f["superseded_by"]]
    losers = [f for f in rel if f["superseded_by"]]
    return {
        "winner_source": winners[0]["source_kind"] if winners else None,
        "winner_asserted_at": winners[0]["asserted_at"] if winners else None,
        "superseded": [{"source": f["source_kind"], "asserted_at": f["asserted_at"]} for f in losers],
    }


def run_timeline_engine(cve_id, steps, mode="auto"):
    """steps: [{"date": "2026-10-24", "claims": {key: claim}}] - ONLY the statements NEW or changed on
    that day. Each statement enters the engine with the day's date (not the run's clock time).

    What the engine actually decided on each day is recorded (state right after the day). The
    engine's time query (entityAt) additionally checks independently: each source may only
    exist from its first day. NOTE: the reference engine does NOT reconstruct who would have won on an earlier day
    - it writes the winner into the live state, not the log; that is why it is recorded live."""
    if mode == "off":
        return {"used": False, "reason": "disabled (--meterless off)"}
    ok, info = node_available()
    if not ok:
        if mode == "on":
            raise EngineError(info)
        return {"used": False, "reason": info}
    try:
        return _run_timeline(cve_id, steps, info)
    except EngineError as e:
        if mode == "on":
            raise
        return {"used": False, "reason": f"engine error, replay without engine: {e}"}


def _run_timeline(cve_id, steps, node_version):
    at = lambda date: f"{date}T12:00:00Z"
    first_seen, per_day, mismatches = {}, [], []
    with MeterlessEngine(namespace=cve_id) as engine:
        engine.call("init", namespace=cve_id, conflictPolicy="source-priority", sourcePriority=SOURCE_PRIORITY)
        vuln = engine.call("upsertEntity", type="vulnerability", name=cve_id, kind="pipeline", by="timeline",
                           at=at(steps[0]["date"]))
        for step in steps:
            date = step["date"]
            for key, claim in step["claims"].items():
                src = engine.call("upsertEntity", type="source", name=claim["source_name"], kind=key, by="timeline", at=at(date))
                if key not in first_seen:
                    first_seen[key] = {"id": src["id"], "date": date}
                    engine.call("relate", **{"from": src["id"], "to": vuln["id"]}, type="asserts_state",
                                attrs={"certainty": claim["certainty"]}, kind=key, by="timeline", at=at(date))
                fact = _fact_for(key, claim)
                if fact:
                    predicate, value, confidence = fact
                    engine.call("assertFact", about=vuln["id"], predicate=predicate, value=value,
                                confidence=confidence, kind=key, by="timeline", at=at(date))
            snap = engine.call("snapshot")
            info = _winner_info(snap["facts"])
            info.update({"date": date, "event_count": snap["event_count"], "sources_seen": sorted(first_seen)})
            per_day.append(info)

        # Time-travel check: did each source exist at each date exactly when it had already been observed?
        checked = 0
        for step in steps:
            date = step["date"]
            for key, seen in first_seen.items():
                expected = seen["date"] <= date
                got = engine.call("entityAt", id=seen["id"], at=date) is not None
                checked += 1
                if expected != got:
                    mismatches.append({"date": date, "source": key, "expected_exists": expected, "engine_says_exists": got})
        before = _day_before(steps[0]["date"])
        checked += 1
        if engine.call("entityAt", id=vuln["id"], at=before) is not None:
            mismatches.append({"date": before, "source": "vulnerability", "expected_exists": False, "engine_says_exists": True})
        final = engine.call("snapshot")

    return {
        "used": True, "engine": "meterless-world-model-reference", "node": node_version,
        "policy": "source-priority", "source_priority": SOURCE_PRIORITY,
        "per_day": per_day,
        "time_travel": {"checked": checked, "mismatches": mismatches},
        "audit": final["audit"], "event_count": final["event_count"],
    }
