"""
Automatic check: runs every sample task and compares
the actual result with the "expected_outcome" stored in
cases.json. This would have flagged the earlier error (a local
model rated an explicitly uncertain note as certain) automatically BEFORE a
demo, instead of it surfacing only when reading the
finished report.

Usage:
    python3 check_expected_outcomes.py
Exits with code 1 if at least one case does not match the
expected result - usable as a simple pre-check before
recording the demo video.
"""

import json
import sys

from main import run_case

OUTCOME_TO_RESOLVED = {
    "resolved_downgrade": True,
    "unresolved": False,
}


def main():
    cases = json.load(open("data/sample/cases.json"))
    failures = []

    for cve_id, case in cases.items():
        expected = case.get("expected_outcome")
        expected_resolved = OUTCOME_TO_RESOLVED.get(expected)
        if expected_resolved is None:
            print(f"SKIP  {cve_id}: unknown expected_outcome '{expected}', no comparison possible")
            continue

        result = run_case(cve_id, case, verbose=False)
        actual_resolved = result["draft"]["resolved"]

        if actual_resolved == expected_resolved:
            print(f"OK    {cve_id}: resolved={actual_resolved} (expected: {expected})")
        else:
            print(f"FAIL  {cve_id}: resolved={actual_resolved}, but expected was {expected} "
                  f"(i.e. resolved={expected_resolved})")
            failures.append(cve_id)

    print()
    if failures:
        print(f"{len(failures)} of {len(cases)} cases differ from the expected result: {failures}")
        print("Check before giving a demo or making a recording.")
        sys.exit(1)
    else:
        print(f"All {len(cases)} cases match the expected result.")
        sys.exit(0)


if __name__ == "__main__":
    main()
