"""
Timeline: how the assessment of ONE case evolves over days as evidence arrives bit by bit
(day 0 only the NVD entry, then the vendor statement, then a first internal status, then the final one).

Each day is decided with EXACTLY THE SAME logic as a normal case (agents/decision.py). With Node, the
same material is additionally fed, with dates, into the real Meterless engine (agents/meterless_bridge.py).

The timelines in data/sample/timelines.json are SIMULATED: NVD and vendor texts are real (paraphrased),
the dates and internal tickets are invented. This is stated in each timeline as a 'note' and shown in the viewer.
"""

import copy
import json
import os
import re

from .decision import NullTrace, decide
from .meterless_bridge import run_timeline_engine
from .next_steps import blockers
from .source_mapper import map_sources

SOURCE_KEYS = ("nvd", "vendor_changelog", "internal_ticket")
DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


class TimelineError(ValueError):
    pass


def load_timelines(path):
    if not os.path.exists(path):
        return {}
    try:
        return json.load(open(path))
    except (OSError, ValueError) as e:
        raise TimelineError(f"{path} cannot be read: {e}")


def validate(cve_id, timeline, cases):
    """Validates a timeline and, on errors, names WHAT and WHERE is wrong (instead of a KeyError)."""
    where = f"Timeline {cve_id}"
    base = timeline.get("base")
    if base not in cases:
        raise TimelineError(f"{where}: 'base' ({base!r}) is not a case in cases.json")
    days = timeline.get("days")
    if not isinstance(days, list) or not days:
        raise TimelineError(f"{where}: 'days' is missing or empty")
    last_date = ""
    for i, day in enumerate(days):
        label = f"{where}, day entry {i + 1}"
        if not isinstance(day, dict):
            raise TimelineError(f"{label}: must be an object")
        date = day.get("date")
        if not isinstance(date, str) or not DATE.match(date):
            raise TimelineError(f"{label}: 'date' is missing or not YYYY-MM-DD ({date!r})")
        if date <= last_date:
            raise TimelineError(f"{label}: date {date} is not after {last_date} (days must be ascending)")
        last_date = date
        if not day.get("event"):
            raise TimelineError(f"{label}: 'event' is missing")
        add = day.get("add")
        if not isinstance(add, dict) or not add:
            raise TimelineError(f"{label}: 'add' is missing or empty")
        for key, spec in add.items():
            if key not in SOURCE_KEYS:
                raise TimelineError(f"{label}: unknown source {key!r} (allowed: {', '.join(SOURCE_KEYS)})")
            if spec == "base":
                if key not in cases[base]["sources"]:
                    raise TimelineError(f"{label}: base case {base} has no source {key!r}")
            elif not (isinstance(spec, dict) and (spec.get("text") or spec.get("description"))):
                raise TimelineError(f"{label}: {key!r} must be 'base' or a source with 'text'")


def _short_why(blocking):
    return "; ".join(f"{src} - {kind}" for src, kind, _ in blocking[:2])


def build_timeline(cve_id, timeline, cases, mode="auto"):
    """Computes the timeline. Returns a dict (JSON-serializable), raises TimelineError on broken data."""
    validate(cve_id, timeline, cases)
    base = cases[timeline["base"]]
    sources, days_out, engine_steps, previous = {}, [], [], None

    for day in timeline["days"]:
        changed = {}
        for key, spec in day["add"].items():
            sources[key] = copy.deepcopy(base["sources"][key] if spec == "base" else spec)
            changed[key] = sources[key]

        case_view = {"cve_id": cve_id, "nickname": base.get("nickname", ""), "sources": copy.deepcopy(sources)}
        claims = map_sources(case_view, NullTrace())
        draft = decide(cve_id, claims, NullTrace())
        blocking = blockers(claims, draft)
        decision = "resolved" if draft["resolved"] else "unresolved"

        days_out.append({
            "day": day.get("day"), "date": day["date"], "event": day["event"],
            "evidence_added": sorted(changed), "evidence_present": sorted(sources),
            "decision": decision, "changed": previous is not None and decision != previous,
            "final_severity": draft["final_severity"], "revisions": draft["revision_count"],
            "certainty": {k: c["certainty"] for k, c in claims.items()},
            "blockers": [{"source": s, "kind": k, "text": t} for s, k, t in blocking],
            "why": ("resolved: vendor fix confirmed by the internal ticket" if draft["resolved"]
                    else _short_why(blocking) or "evidence is insufficient"),
        })
        previous = decision
        engine_steps.append({"date": day["date"], "claims": {k: claims[k] for k in changed}})

    return {
        "cve_id": cve_id, "title": timeline.get("title", cve_id), "note": timeline.get("note", ""),
        "days": days_out,
        "engine": run_timeline_engine(cve_id, engine_steps, mode=mode),
    }


def format_timeline(tl):
    lines = ["", f"TIMELINE {tl['cve_id']} - {tl['title']}", tl["note"] and f"  ({tl['note']})",
             f"{'day':>3}  {'date':<10}  {'decision':<10}  event / why", "-" * 110]
    lines = [l for l in lines if l]
    for d in tl["days"]:
        flag = "  <- changed" if d["changed"] else ""
        lines.append(f"{d['day']:>3}  {d['date']:<10}  {d['decision']:<10}  {d['event']}{flag}")
        lines.append(f"{'':>27}{d['why']}")
    eng = tl["engine"]
    if eng.get("used"):
        tt = eng["time_travel"]
        verdict = "agrees" if not tt["mismatches"] else f"DISAGREES ({len(tt['mismatches'])} mismatches)"
        lines.append(f"Meterless engine on node {eng['node']}: every evidence source existed exactly from its first day "
                     f"(time-travel check {verdict}, {tt['checked'] - len(tt['mismatches'])}/{tt['checked']}); "
                     f"{eng['event_count']} events logged")
    else:
        lines.append(f"Meterless engine: not used - {eng.get('reason')}")
    return "\n".join(lines)
