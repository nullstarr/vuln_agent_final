#!/usr/bin/env python3
"""
Checks the ranking "Which case do you start with?" (agents/triage.py):

  A) the sort rules, on artificial results (so each rule is exercised on its own),
  B) properties of the real ranking across all sample cases,
  C) that main.py actually writes it (triage.json plus one result per case).

Usage:  python3 check_triage.py        (exit code 1 if something differs)
"""

import contextlib
import io
import json
import os
import random
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
os.environ["METERLESS_MODE"] = "off"

from agents.triage import rank  # noqa: E402
from main import run_case  # noqa: E402

failures = 0


def check(name, ok, detail=""):
    global failures
    failures += not ok
    print(f"  {'OK    ' if ok else 'FAIL  '} {name}{('  - ' + detail) if detail and not ok else ''}")


def fake(cve, sev, cvss, resolved=False, steps=1, nickname=""):
    return {"cve_id": cve, "nickname": nickname, "baseline_severity": sev, "cvss": cvss, "resolved": resolved,
            "confidence": "x", "next_steps": ["s"] * steps,
            "blockers": [{"source": "internal", "kind": "unconfirmed item"}] * steps}


def order(results):
    return [r["cve_id"] for r in rank(results)]


def main():
    print("A) sort rules (artificial results)")
    check("unresolved before resolved, even if the resolved case weighs more",
          order([fake("R", "CRITICAL", 10, resolved=True), fake("U", "LOW", 2.0)]) == ["U", "R"])
    check("unresolved CRITICAL before unresolved HIGH",
          order([fake("H", "HIGH", 8.9), fake("C", "CRITICAL", 9.0)]) == ["C", "H"])
    check("unresolved HIGH before unresolved MEDIUM (tier 1 before tier 2)",
          order([fake("M", "MEDIUM", 6.9), fake("H", "HIGH", 7.0)]) == ["H", "M"])
    check("same tier: higher CVSS score first",
          order([fake("A", "CRITICAL", 9.1), fake("B", "CRITICAL", 9.8)]) == ["B", "A"])
    check("same CVSS score: more open steps first",
          order([fake("A", "HIGH", 8.0, steps=1), fake("B", "HIGH", 8.0, steps=3)]) == ["B", "A"])
    check("otherwise equal: by CVE number (always the same order)",
          order([fake("CVE-2", "HIGH", 8.0), fake("CVE-1", "HIGH", 8.0)]) == ["CVE-1", "CVE-2"])
    check("severity UNKNOWN is treated as HIGH to be safe (before MEDIUM)",
          order([fake("M", "MEDIUM", 6.0), fake("U", "UNKNOWN", None)]) == ["U", "M"])
    items = [fake(f"CVE-{i}", random.choice(["CRITICAL", "HIGH", "MEDIUM", "LOW"]), round(random.uniform(1, 10), 1),
                  resolved=random.random() < 0.3, steps=random.randint(0, 3)) for i in range(40)]
    shuffled = items[:]
    random.Random(1).shuffle(shuffled)
    check("order does not depend on the input order", order(items) == order(shuffled))

    print("\nB) real ranking across all sample cases")
    cases = json.load(open(os.path.join(ROOT, "data", "sample", "cases.json")))
    results = []
    for cid, case in cases.items():
        start = os.getcwd()
        os.chdir(tempfile.mkdtemp())
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                results.append(run_case(cid, case, verbose=False)["result"])
        finally:
            os.chdir(start)
    ranked = rank(results)
    check(f"all {len(cases)} cases are in the ranking", len(ranked) == len(cases))
    decisions = [r["decision"] for r in ranked]
    first_resolved = decisions.index("resolved") if "resolved" in decisions else len(decisions)
    check("all resolved cases come after all unresolved ones",
          all(d == "unresolved" for d in decisions[:first_resolved]) and all(d == "resolved" for d in decisions[first_resolved:]))
    unresolved = [r for r in ranked if r["decision"] == "unresolved"]
    best = max((r for r in results if not r["resolved"]),
               key=lambda r: ({"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(r["baseline_severity"], 3), r["cvss"] or 0))
    check(f"rank 1 is the unresolved case with the highest severity ({best['cve_id']})", ranked[0]["cve_id"] == best["cve_id"])
    check("every unresolved case names at least one reason",
          all("evidence is insufficient" not in r["why"] for r in unresolved))
    check("the reasons name only known sources",
          all(b["source"] in {"internal", "vendor", "nvd"} for r in results for b in r["blockers"]))
    r0004 = next(r for r in ranked if r["cve_id"] == "CVE-2023-0004")
    check("load-balancer trap (CVE-2023-0004): reason is the under-covered scope",
          "claim broader than backed" in r0004["why"], r0004["why"])
    check("no line is truncated", all(not r["why"].endswith("...") for r in ranked))

    print("\nC) main.py writes the ranking")
    tmp = tempfile.mkdtemp()
    env = dict(os.environ, METERLESS_MODE="off", LLM_PROVIDER="rule_based")
    proc = subprocess.run([sys.executable, os.path.join(ROOT, "main.py")], cwd=tmp, env=env, capture_output=True, text=True)
    logs = os.path.join(tmp, "logs")
    check("main.py runs through", proc.returncode == 0, proc.stderr[-200:])
    try:
        triage = json.load(open(os.path.join(logs, "triage.json")))
        check("logs/triage.json is valid and complete", len(triage) == len(cases) and triage[0]["rank"] == 1)
    except (OSError, ValueError) as e:
        check("logs/triage.json is valid and complete", False, str(e))
    n_results = len([f for f in os.listdir(logs) if f.endswith("_result.json")]) if os.path.isdir(logs) else 0
    check("one file <CVE>_result.json per case", n_results == len(cases), f"{n_results}")
    check("the ranking is also in the terminal", "TRIAGE - most urgent first" in proc.stdout)

    total = 8 + 8 + 3 + 1
    print(f"\n{'all' if not failures else 'not all'} checks passed ({failures} failures).")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
