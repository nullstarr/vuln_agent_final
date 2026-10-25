#!/usr/bin/env python3
"""
Checks what the project does when parts of the three sources (NVD, vendor, internal) are missing or
incomplete. Two groups:

  A) all 8 combinations "source present / source missing"
  B) source is present, but incomplete (empty text, missing field, NVD without a rating, ...)

Required for every variant: NO crash, and the expected "resolved yes/no".
The starting case is CVE-2024-9999 (all three sources present, clearly resolved).

Usage:  python3 check_missing_sources.py        (exit code 1 if something differs)
"""

import contextlib
import copy
import io
import itertools
import json
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

from main import run_case  # noqa: E402

FULL = json.load(open(os.path.join(ROOT, "data", "sample", "cases.json")))["CVE-2024-9999"]

# Combination (NVD, vendor, internal) -> expected "resolved".
# (0, 1, 1) is intentional: vendor + internal check confirm the fix, the NVD only provides the
# baseline rating. If you prefer a missing NVD to mean "unresolved", change that in reconciler.py.
COMBOS = {
    (1, 1, 1): True,  (1, 1, 0): False, (1, 0, 1): False, (1, 0, 0): False,
    (0, 1, 1): True,  (0, 1, 0): False, (0, 0, 1): False, (0, 0, 0): False,
}


def _drop(*keys):
    return lambda c: [c["sources"]["nvd"].pop(k) for k in keys]


# Name -> (change to the starting case, expected "resolved")
MALFORMED = {
    "internal text empty":              (lambda c: c["sources"]["internal_ticket"].update(text=""), False),
    "internal text None":               (lambda c: c["sources"]["internal_ticket"].update(text=None), False),
    "internal source without text field": (lambda c: c["sources"]["internal_ticket"].pop("text"), False),
    "internal text is a number":        (lambda c: c["sources"]["internal_ticket"].update(text=12345), False),
    "NVD without score and severity":   (_drop("cvss_v3_score", "severity"), True),
    "NVD without score (severity only)": (_drop("cvss_v3_score"), True),
    "NVD without description":          (_drop("description"), True),
    "source without source_name":       (lambda c: c["sources"]["vendor_changelog"].pop("source_name"), True),
    "source without source_type":       (lambda c: c["sources"]["vendor_changelog"].pop("source_type"), True),
    "source without is_real_public_data": (lambda c: c["sources"]["vendor_changelog"].pop("is_real_public_data"), True),
    "case without 'sources'":           (lambda c: c.pop("sources"), False),
    "'sources' is empty":               (lambda c: c.update(sources={}), False),
}


def run(case):
    """Runs the case in a throwaway folder (no logs/history in the project)."""
    start, tmp = os.getcwd(), tempfile.mkdtemp()
    os.chdir(tmp)
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            return run_case(case.get("cve_id", "X"), case, verbose=False)["draft"]["resolved"], None
    except Exception as e:  # exactly this must never happen
        return None, f"{type(e).__name__}: {e}"
    finally:
        os.chdir(start)


def main():
    failures = 0

    def report(name, expected, got, err):
        nonlocal failures
        ok = err is None and got == expected
        failures += not ok
        shown = f"CRASH ({err})" if err else f"resolved={got}"
        print(f"  {'OK    ' if ok else 'FAIL  '} {name:36} expected resolved={expected}, was {shown}")

    print("A) combinations of the three sources (N = NVD, V = vendor, I = internal)")
    for combo, expected in COMBOS.items():
        case = copy.deepcopy(FULL)
        names = ["nvd", "vendor_changelog", "internal_ticket"]
        case["sources"] = {n: case["sources"][n] for n, keep in zip(names, combo) if keep}
        label = "".join(ch if keep else "-" for ch, keep in zip("NVI", combo))
        got, err = run(case)
        report(label, expected, got, err)

    print("\nB) source present, but incomplete")
    for name, (mutate, expected) in MALFORMED.items():
        case = copy.deepcopy(FULL)
        mutate(case)
        got, err = run(case)
        report(name, expected, got, err)

    total = len(COMBOS) + len(MALFORMED)
    print(f"\n{total - failures} of {total} variants as expected.")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
