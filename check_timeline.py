#!/usr/bin/env python3
"""
Checks the timeline (agents/timeline.py, data/sample/timelines.json):

  A) Data validation: broken timelines give an understandable error message instead of a KeyError.
  B) Flow without the engine: the decision per day, evidence order, reasons, determinism.
  C) With the real Meterless engine (needs Node; otherwise skipped): the independent time-travel check,
     the winner per day, and that the engine changes nothing about the DECISIONS.
  D) main.py: writes <CVE>_timeline.json, shows the timeline, survives a broken timelines.json.

Usage:  python3 check_timeline.py        (exit code 1 if something differs)
"""

import copy
import json
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
os.environ["LLM_PROVIDER"] = "rule_based"   # this check tests fixed rules; a language model would vary between runs

from agents import meterless_bridge as mb  # noqa: E402
from agents.timeline import TimelineError, build_timeline  # noqa: E402

CASES = json.load(open(os.path.join(ROOT, "data", "sample", "cases.json")))
TIMELINES = json.load(open(os.path.join(ROOT, "data", "sample", "timelines.json")))
failures = 0


def check(name, ok, detail=""):
    global failures
    failures += not ok
    print(f"  {'OK    ' if ok else 'FAIL  '} {name}{('  - ' + detail) if detail and not ok else ''}")


def build(cve, mode="off", timeline=None):
    return build_timeline(cve, timeline or TIMELINES[cve], CASES, mode=mode)


def bad(mutate, expected_words):
    """A broken timeline must raise TimelineError with an expected keyword in the message."""
    tl = copy.deepcopy(TIMELINES["CVE-2017-5638"])
    mutate(tl)
    try:
        build("CVE-2017-5638", timeline=tl)
        return False, "no error"
    except TimelineError as e:
        return all(w in str(e) for w in expected_words), str(e)
    except Exception as e:  # exactly this must never happen: KeyError & co.
        return False, f"{type(e).__name__}: {e}"


def main():
    print("A) Data validation")
    for name, mutate, words in [
        ("unknown base case", lambda t: t.update(base="CVE-0000-0000"), ["base"]),
        ("no days", lambda t: t.update(days=[]), ["days"]),
        ("date in wrong format", lambda t: t["days"][1].update(date="29.09.2026"), ["date", "YYYY-MM-DD"]),
        ("days not ascending", lambda t: t["days"][2].update(date="2026-10-24"), ["ascending"]),
        ("unknown source", lambda t: t["days"][0]["add"].update(foo="base"), ["unknown source", "foo"]),
        ("empty 'add'", lambda t: t["days"][0].update(add={}), ["add"]),
        ("source without text", lambda t: t["days"][3]["add"].update(internal_ticket={"source_name": "x"}), ["text"]),
        ("entry is not an object", lambda t: t["days"].__setitem__(0, "broken"), ["object"]),
    ]:
        ok, msg = bad(mutate, words)
        check(f"{name} -> understandable message", ok, msg)

    print("\nB) Flow without the engine")
    struts = build("CVE-2017-5638")
    spring = build("CVE-2022-22965")
    for label, tl in (("Struts", struts), ("Spring4Shell", spring)):
        check(f"{label}: decision per day = unresolved, unresolved, unresolved, resolved",
              [d["decision"] for d in tl["days"]] == ["unresolved", "unresolved", "unresolved", "resolved"],
              str([d["decision"] for d in tl["days"]]))
        check(f"{label}: 'changed' only on the last day", [d["changed"] for d in tl["days"]] == [False, False, False, True])
        check(f"{label}: evidence is only added, never removed",
              all(set(a["evidence_present"]) <= set(b["evidence_present"]) for a, b in zip(tl["days"], tl["days"][1:])))
        check(f"{label}: never 'resolved' without an internal source",
              all("internal_ticket" in d["evidence_present"] for d in tl["days"] if d["decision"] == "resolved"))
    day0 = {(b["source"], b["kind"]) for b in struts["days"][0]["blockers"]}
    check("Struts day 0: internal 'no check recorded' and vendor 'no vendor statement'",
          {("internal", "no check recorded"), ("vendor", "no vendor statement")} <= day0, str(day0))
    check("Struts day 4 (the Equifax moment): internal 'unconfirmed item'",
          any(b["source"] == "internal" and b["kind"] == "unconfirmed item" for b in struts["days"][2]["blockers"]))
    check("Spring4Shell day 3: pending work is named",
          any(b["kind"] == "work still pending" for b in spring["days"][2]["blockers"]))
    check("Spring4Shell final state = decision of the normal case CVE-2022-22965 (resolved)",
          spring["days"][-1]["decision"] == "resolved" and CASES["CVE-2022-22965"]["expected_outcome"] == "resolved_downgrade")
    strip = lambda tl: [{k: v for k, v in d.items()} for d in tl["days"]]
    check("computed twice -> identical result (deterministic)", strip(build("CVE-2017-5638")) == strip(struts))
    check("without the engine: the reason is in the result", struts["engine"]["used"] is False and "off" in struts["engine"]["reason"])

    ok_node, version = mb.node_available()
    if not ok_node:
        print(f"\nC) skipped: {version}")
    else:
        print(f"\nC) real Meterless engine (node {version})")
        for cve in ("CVE-2017-5638", "CVE-2022-22965"):
            tl = build(cve, mode="on")
            eng = tl["engine"]
            tt = eng["time_travel"]
            check(f"{cve}: engine used", eng["used"] is True)
            check(f"{cve}: time-travel check with no mismatch ({tt['checked']} checks)",
                  tt["mismatches"] == [] and tt["checked"] >= 4 * 3, str(tt["mismatches"]))
            check(f"{cve}: decisions with engine == without engine",
                  [d["decision"] for d in tl["days"]] == [d["decision"] for d in build(cve)["days"]])
            pd = eng["per_day"]
            check(f"{cve} day 1 (vendor only): the vendor still wins",
                  pd[1]["winner_source"] == "vendor_changelog" and pd[1]["superseded"] == [])
            check(f"{cve} day 3/4 (first internal status): internal wins, vendor superseded",
                  pd[2]["winner_source"] == "internal_ticket" and [x["source"] for x in pd[2]["superseded"]] == ["vendor_changelog"])
            sup = sorted(x["source"] for x in pd[3]["superseded"])
            check(f"{cve} final state: new internal status supersedes the old one AND the vendor",
                  pd[3]["winner_source"] == "internal_ticket" and sup == ["internal_ticket", "vendor_changelog"], str(sup))
            check(f"{cve}: the engine's audit log is present", len(eng["audit"]) >= 4)

        # broken bridge mid-timeline -> fall back, same decisions
        good = mb.BRIDGE
        broken = os.path.join(tempfile.mkdtemp(), "broken.mjs")
        open(broken, "w").write("process.exit(3);\n")
        mb.BRIDGE = broken
        try:
            fb = build("CVE-2017-5638", mode="auto")
            check("crashing bridge: fall back with reason, same decisions",
                  fb["engine"]["used"] is False and [d["decision"] for d in fb["days"]] == [d["decision"] for d in struts["days"]])
        finally:
            mb.BRIDGE = good

    print("\nD) main.py")
    tmp = tempfile.mkdtemp()
    env = dict(os.environ, METERLESS_MODE="off", LLM_PROVIDER="rule_based")
    run = lambda *args, **kw: subprocess.run([sys.executable, os.path.join(ROOT, "main.py"), *args], cwd=tmp, env=env,
                                             capture_output=True, text=True, **kw)
    p = run("--case", "CVE-2017-5638")
    check("--case with timeline: runs through and shows it", p.returncode == 0 and "TIMELINE CVE-2017-5638" in p.stdout, p.stderr[-200:])
    try:
        saved = json.load(open(os.path.join(tmp, "logs", "CVE-2017-5638_timeline.json")))
        check("logs/<CVE>_timeline.json is valid", len(saved["days"]) == 4 and saved["days"][-1]["decision"] == "resolved")
    except (OSError, ValueError) as e:
        check("logs/<CVE>_timeline.json is valid", False, str(e))
    p = run("--case", "CVE-2024-9999")
    check("case without timeline: no timeline, no error", p.returncode == 0 and "TIMELINE" not in p.stdout)

    data_dir = os.path.join(tmp, "data")
    os.makedirs(data_dir)
    shutil.copy(os.path.join(ROOT, "data", "sample", "cases.json"), data_dir)
    open(os.path.join(data_dir, "timelines.json"), "w").write("{ this is not json")
    p = run("--case", "CVE-2017-5638", "--data", os.path.join(data_dir, "cases.json"))
    check("broken timelines.json: warning, the case itself still runs", p.returncode == 0 and "WARNING" in p.stderr and "1 case" in p.stdout,
          p.stderr[-200:])

    print(f"\n{'all checks passed' if not failures else str(failures) + ' check(s) FAILED'}.")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
