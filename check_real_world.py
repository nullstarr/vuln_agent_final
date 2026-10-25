#!/usr/bin/env python3
"""Runs the cases in data/real_world/cases.json (real NVD/vendor texts, SYNTHETIC tickets) and compares with the expectation.
Known gaps are listed by name and not hidden: the rules were NOT tailored to these cases."""
import json, os, sys
here = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, here)
os.environ["LLM_PROVIDER"] = "rule_based"; os.environ["METERLESS_MODE"] = "off"
import io, contextlib
from main import run_case
KNOWN_GAPS = {"CVE-2024-6387": "OpenSSH says 'This release contains fixes for two security problems'; the fix-claim rule (agents/reconciler.py _FIX_CLAIM) does not know that wording, so the system stays on 'unresolved' (the safe direction)."}
cases = json.load(open(os.path.join(here, "data/real_world/cases.json")))
ok = gaps = bad = 0
for cid, c in cases.items():
    with contextlib.redirect_stdout(io.StringIO()):
        r = run_case(cid, c, verbose=False)
    resolved = bool(r["result"].get("resolved"))
    got = "resolved_downgrade" if resolved else "unresolved"
    if got == c["expected_outcome"]: ok += 1; print(f"PASS {cid}: {got}")
    elif cid in KNOWN_GAPS: gaps += 1; print(f"KNOWN GAP {cid}: expected {c['expected_outcome']}, got {got}\n   {KNOWN_GAPS[cid]}")
    else: bad += 1; print(f"FAIL {cid}: expected {c['expected_outcome']}, got {got}")
print(f"{ok} as expected, {gaps} known gap(s), {bad} unexpected"); sys.exit(1 if bad else 0)
