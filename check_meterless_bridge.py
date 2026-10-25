#!/usr/bin/env python3
"""
Checks the integration of the real Meterless world-model engine (agents/meterless_bridge.py).

  A) Fallback mode (needs NO Node): --meterless off, missing Node, broken bridge -> no crash,
     'on' reports the reason as an error.
  B) With the real engine (needs Node >= 18; otherwise B is skipped and that is stated):
     - all 12 sample cases: ID of our Python reimplementation == ID of the real engine (parity),
     - conflict policy: if vendor AND internal source are present, internal wins and the vendor is superseded,
     - missing sources produce no evidence statement and no crash.

Usage:  python3 check_meterless_bridge.py        (exit code 1 if something differs)
"""

import contextlib
import copy
import io
import json
import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

from agents import meterless_bridge as mb  # noqa: E402
from main import run_case  # noqa: E402

CASES = json.load(open(os.path.join(ROOT, "data", "sample", "cases.json")))
failures = 0


def check(name, ok, detail=""):
    global failures
    failures += not ok
    print(f"  {'OK    ' if ok else 'FAIL  '} {name}{('  - ' + detail) if detail and not ok else ''}")


def in_tmp(fn):
    """Runs fn in a throwaway folder (no files in the project)."""
    start = os.getcwd()
    os.chdir(tempfile.mkdtemp())
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            return fn()
    finally:
        os.chdir(start)


def run(case_id, mode="auto"):
    os.environ["METERLESS_MODE"] = mode
    result = in_tmp(lambda: run_case(case_id, CASES[case_id], verbose=False))
    return result


def engine_of(case_id):
    """The 'engine' field from the written world_model file would be in a throwaway folder; compute it directly."""
    from agents.source_mapper import map_sources
    from agents.trace import TraceLogger
    claims = in_tmp(lambda: map_sources(CASES[case_id], TraceLogger("tmp_mb")))
    return mb.run_engine(CASES[case_id], claims, mode="auto"), claims


def main():
    print("A) fallback mode (no Node needed)")
    _, claims = engine_of("CVE-2024-9999")
    off = mb.run_engine(CASES["CVE-2024-9999"], claims, mode="off")
    check("--meterless off: not used, with reason", off["used"] is False and "off" in off["reason"])
    check("--meterless off: the whole case still runs through", run("CVE-2024-9999", "off")["draft"]["resolved"] is True)

    saved_path = os.environ["PATH"]
    os.environ["PATH"] = tempfile_dir = tempfile.mkdtemp()      # empty PATH -> 'node' not findable
    try:
        no_node = mb.run_engine(CASES["CVE-2024-9999"], claims, mode="auto")
        check("without Node, auto: not used, reason named", no_node["used"] is False and "node" in no_node["reason"])
        try:
            mb.run_engine(CASES["CVE-2024-9999"], claims, mode="on")
            check("without Node, on: must report an error", False)
        except mb.EngineError as e:
            check("without Node, on: reports the reason as an error", "node" in str(e))
        check("without Node: the whole case still runs through", run("CVE-2024-9999", "auto")["draft"]["resolved"] is True)
    finally:
        os.environ["PATH"] = saved_path

    ok, version = mb.node_available()
    if not ok:
        print(f"\nB) skipped: {version}")
        print(f"\n{'all' if not failures else 'not all'} group A checks passed.")
        sys.exit(1 if failures else 0)

    # broken bridge mid-run (process exits immediately) -> fall back, no crash
    good_bridge = mb.BRIDGE
    broken = os.path.join(tempfile.mkdtemp(), "broken.mjs")
    open(broken, "w").write("process.exit(3);\n")
    mb.BRIDGE = broken
    try:
        res = mb.run_engine(CASES["CVE-2024-9999"], claims, mode="auto")
        check("bridge aborts, auto: fall back with reason", res["used"] is False and "engine" in res["reason"])
        try:
            mb.run_engine(CASES["CVE-2024-9999"], claims, mode="on")
            check("bridge aborts, on: must report error", False)
        except mb.EngineError:
            check("bridge aborts, on: reports error", True)
    finally:
        mb.BRIDGE = good_bridge

    print(f"\nB) real Meterless engine (node {version})")
    for case_id, case in CASES.items():
        engine, claims = engine_of(case_id)
        present = [k for k, c in claims.items() if c["certainty_method"] != "absent-source"]
        parity = engine.get("id_parity", {})
        check(f"{case_id}: engine used, ID parity {parity.get('checked', 0) - len(parity.get('mismatches', []))}"
              f"/{parity.get('checked', 0)}",
              engine.get("used") is True and not parity.get("mismatches") and parity.get("checked") == 1 + (
                  len([k for k in present])),
              detail=json.dumps(engine)[:160])
        both = "vendor_changelog" in present and "internal_ticket" in present
        verdict = [v for v in engine.get("verdicts", []) if v["predicate"] == "remediation_status"]
        if both:
            check(f"{case_id}: internal wins, vendor superseded",
                  bool(verdict) and verdict[0]["winner_source"] == "internal_ticket"
                  and verdict[0]["superseded_sources"] == ["vendor_changelog"], detail=str(verdict))
        else:
            check(f"{case_id}: without both sources no conflict verdict", not verdict, detail=str(verdict))
        missing = sorted(set(claims) - set(present))
        check(f"{case_id}: missing sources {missing or '-'} without an evidence statement",
              sorted(engine.get("absent_sources", [])) == missing)

    # the engine data really lands in the written file
    written = {}

    def capture():
        os.environ["METERLESS_MODE"] = "auto"
        run_case("CVE-2021-44228", CASES["CVE-2021-44228"], verbose=False)
        written.update(json.load(open("logs/CVE-2021-44228_world_model.json")))
    in_tmp(capture)
    check("world_model.json contains the 'engine' section with used=True",
          written.get("engine", {}).get("used") is True and "entities" in written and "edges" in written)

    print("\nC) repeatable, resumable, self-repairing")
    case = CASES["CVE-2021-44228"]
    claims = engine_of("CVE-2021-44228")[1]
    n_present = len([c for c in claims.values() if c["certainty_method"] != "absent-source"])
    facts_of = lambda r: sorted(f["id"] for f in r["facts"])

    d = tempfile.mkdtemp()
    r1 = mb.run_engine(case, claims, mode="on", directory=d)
    r2 = mb.run_engine(case, claims, mode="on", directory=d)
    check("1st run creates events and loads nothing", r1["persistence"]["new_events"] > 0 and r1["persistence"]["resumed"] is False)
    check("2nd run (different process, same evidence state): loads the stored world, creates 0 new events",
          r2["persistence"]["resumed"] is True and r2["persistence"]["new_events"] == 0, str(r2["persistence"]))
    check("2nd run: the run record skips every unchanged observation",
          r2["run_record"]["skippedUnchanged"] == 1 + n_present and r2["run_record"]["eventsAppended"] == 0, str(r2["run_record"]))
    check("2nd run: facts and verdicts identical to the 1st run", facts_of(r1) == facts_of(r2) and r1["verdicts"] == r2["verdicts"])
    check("1st run: the live state is correct, nothing had to be re-derived",
          r1["persistence"]["live_state_consistent"] is True and r1["persistence"]["derived_state_rebuilt_from_log"] is False)
    check("2nd run: the 'superseded' markers lost after the restart (limit of the reference) were noticed and re-derived from the log",
          r2["persistence"]["derived_state_rebuilt_from_log"] is True, str(r2["persistence"]))

    case2 = copy.deepcopy(case)
    del case2["sources"]["internal_ticket"]
    from agents.source_mapper import map_sources
    from agents.trace import TraceLogger
    claims2 = in_tmp(lambda: map_sources(case2, TraceLogger("tmp_mb2")))
    r3 = mb.run_engine(case2, claims2, mode="on", directory=d)
    check("different evidence state -> its own fresh world (nothing from earlier runs)",
          r3["persistence"]["namespace"] != r1["persistence"]["namespace"] and r3["persistence"]["resumed"] is False)
    check("without an internal note no stale internal statement 'wins' anymore",
          all(f["source_kind"] != "internal_ticket" for f in r3["facts"]) and r3["verdicts"] == [], str(r3["verdicts"]))

    path = os.path.join(d, ".world", r1["persistence"]["namespace"] + ".json")
    data = open(path).read()
    open(path, "w").write(data[: len(data) // 2])                       # a truncated write reproduced
    r4 = mb.run_engine(case, claims, mode="on", directory=d)
    check("corrupt file (half written): repaired, no crash",
          r4["used"] and r4["persistence"]["recovered_from_corrupt_store"] is True)
    check("... and the result equals that of a clean run", facts_of(r4) == facts_of(r1) and r4["verdicts"] == r1["verdicts"])
    check("... the broken file is quarantined (nothing is lost)",
          any(".corrupt-" in f for f in os.listdir(os.path.dirname(path))))

    # crash mid-run: the process is killed hard after reading in (kill -9)
    d5, d6 = tempfile.mkdtemp(), tempfile.mkdtemp()
    orig_call, counter = mb.MeterlessEngine.call, {"n": 0}

    def crashing(self, cmd, **args):
        counter["n"] += 1
        if counter["n"] == 7:
            self._proc.kill()
        return orig_call(self, cmd, **args)

    mb.MeterlessEngine.call = crashing
    try:
        mb.run_engine(case, claims, mode="on", directory=d5)
        crashed = False
    except mb.EngineError:
        crashed = True
    finally:
        mb.MeterlessEngine.call = orig_call
    resumed = mb.run_engine(case, claims, mode="on", directory=d5)
    clean = mb.run_engine(case, claims, mode="on", directory=d6)
    check("crash mid-run is reported as an error (not swallowed)", crashed)
    check("restart resumes the stored world (not from scratch)", resumed["persistence"]["resumed"] is True)
    check("... and ends in the same state as a clean run (same facts, same event count, no duplicates)",
          facts_of(resumed) == facts_of(clean) and resumed["event_count"] == clean["event_count"],
          f"{resumed['event_count']} vs {clean['event_count']}")

    print("\nD) JSONL evidence and evidence trail in the report (main.py)")
    tmp = tempfile.mkdtemp()
    env = dict(os.environ, LLM_PROVIDER="rule_based", METERLESS_MODE="on")
    run_main = lambda *a, e=env: subprocess.run([sys.executable, os.path.join(ROOT, "main.py"), *a], cwd=tmp, env=e,
                                                capture_output=True, text=True)
    p1 = run_main("--case", "CVE-2021-44228")
    jl = os.path.join(tmp, "logs", "CVE-2021-44228_meterless.jsonl")
    try:
        lines = [json.loads(l) for l in open(jl)]
        wm = json.load(open(os.path.join(tmp, "logs", "CVE-2021-44228_world_model.json")))["engine"]
        check("logs/<CVE>_meterless.jsonl: every line valid JSON, first line is the run", lines[0]["type"] == "run")
        check("... contains EVERY event of the log (count matches the engine)",
              len([l for l in lines if l["type"] == "event"]) == wm["event_count"])
        check("... contains the belief with winner/superseded and the audit entries",
              any(l["type"] == "belief" for l in lines) and any(l["type"] == "audit" for l in lines))
        check("... every event names its origin", all("source" in l for l in lines if l["type"] == "event"))
        check("the JSON summary stayed small (events are only in the JSONL file)", "events" not in wm)
    except (OSError, ValueError, KeyError) as e:
        check("logs/<CVE>_meterless.jsonl present and valid", False, str(e))
    check("report contains the evidence trail with the origin of the belief",
          "EVIDENCE TRAIL (Meterless World Model)" in p1.stdout and "Remediation belief taken from:" in p1.stdout)
    run_main("--case", "CVE-2021-44228")
    wm2 = json.load(open(os.path.join(tmp, "logs", "CVE-2021-44228_world_model.json")))["engine"]
    check("main.py twice in a row: the second run creates 0 new events",
          wm2["persistence"]["new_events"] == 0 and wm2["persistence"]["resumed"] is True, str(wm2["persistence"]))
    try:
        man = json.load(open(os.path.join(tmp, "logs", "meterless_manifest.json")))
        check("logs/meterless_manifest.json: valid, names mounted and not-mounted engines, each part with a consumer",
              "world-model" in man["engines_mounted"] and "h-mem" in man["engines_not_mounted"]
              and all(("consumed_by" in x) or ("note" in x) for x in man["world_model_parts"]))
        check("... and counts the cases that really ran through the engine", man["engines_mounted"]["world-model"]["cases_run_through_engine"] == 1)
    except (OSError, ValueError, KeyError) as e:
        check("logs/meterless_manifest.json present and valid", False, str(e))
    off = run_main("--case", "CVE-2021-44228", e=dict(env, METERLESS_MODE="off"))
    check("--meterless off: no evidence trail, no crash", "EVIDENCE TRAIL" not in off.stdout and off.returncode == 0)

    total_failed = failures
    print(f"\n{'all checks passed' if not total_failed else str(total_failed) + ' check(s) FAILED'}.")
    sys.exit(1 if total_failed else 0)


if __name__ == "__main__":
    main()
