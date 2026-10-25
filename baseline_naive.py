"""
The naive comparison: solves the same nine tasks with ONE single,
unchecked AI call, entirely without our agent chain - no Reconciler,
no feedback loop, no Challenge Agent, no word list, no
scope check. Exactly what most simple "AI reads text,
AI decides" solutions would do.

Uses the SAME llm_provider.py as main.py, hence the same model - so the
comparison is fair: the only difference is the architecture,
not the model behind it.

Usage:
    python3 baseline_naive.py
"""

import json
import sys

from agents import llm_provider

OUTCOME_TO_RESOLVED = {"resolved_downgrade": True, "unresolved": False}

SYSTEM_PROMPT = """You are a security analyst. You are given a CVE description, a vendor
statement, and an internal ticket about one specific environment. Decide: is this
vulnerability FULLY resolved in this specific environment, with no remaining gap?

Answer with exactly one word on the first line: YES or NO.
Then one short sentence explaining why."""


def build_prompt(case):
    # Missing sources (see CVE-2024-7001/7002/7003) must not crash the
    # naive comparison - the model then simply gets
    # the note that this source does not exist.
    s = case["sources"]
    nvd = s.get("nvd", {})
    vendor = s.get("vendor_changelog", {})
    internal = s.get("internal_ticket", {})
    return (
        f"CVE: {case['cve_id']}\n"
        f"NVD description: {nvd.get('description', '(no public database entry available)')} "
        f"(severity: {nvd.get('severity', 'unknown')}, CVSS {nvd.get('cvss_v3_score', 'unknown')})\n"
        f"Vendor statement: {vendor.get('text', '(no vendor statement available)')}\n"
        f"Internal ticket: {internal.get('text', '(no internal check recorded)')}\n"
    )


def parse_verdict(raw):
    if raw is None:
        return None, "no provider configured"
    first_line = raw.strip().splitlines()[0].strip().upper() if raw.strip() else ""
    if first_line.startswith("YES"):
        return True, raw
    if first_line.startswith("NO"):
        return False, raw
    return None, raw  # unparsable - counts as wrong, a naive system has no fallback for this


def main():
    import os
    provider = os.environ.get("LLM_PROVIDER", "rule_based")
    if provider == "rule_based":
        print("LLM_PROVIDER=rule_based - a naive baseline needs an actual model to call.")
        print("Set LLM_PROVIDER to ollama/anthropic/openai in .env first, then re-run.")
        sys.exit(1)

    cases = json.load(open("data/sample/cases.json"))
    correct, total, unparsable = 0, 0, 0

    for cve_id, case in cases.items():
        raw = llm_provider.complete(SYSTEM_PROMPT, build_prompt(case))
        verdict, reason = parse_verdict(raw)
        expected = OUTCOME_TO_RESOLVED.get(case.get("expected_outcome"))
        total += 1

        if verdict is None:
            unparsable += 1
            status = "UNPARSABLE"
        elif verdict == expected:
            correct += 1
            status = "OK"
        else:
            status = "WRONG"

        print(f"[{status:>10}] {cve_id}: model said resolved={verdict}, expected={expected}")
        print(f"             {reason[:140] if reason else ''}")

    print(f"\nNaive single-shot baseline: {correct}/{total} correct "
          f"({100*correct/total:.0f}%), {unparsable} response(s) unparsable")
    print("Compare against: python3 check_expected_outcomes.py (our full agent pipeline)")


if __name__ == "__main__":
    main()
