#!/usr/bin/env python3
"""
Checks two things that belong together:

  A) The "vendor announces a fix" path (e.g. 'Upgrade to 2.5.10.1') - the most common case in practice.
     It would be endangered by two errors: never being able to say "resolved" (too strict) or saying
     "resolved" on the bare vendor statement (too loose). Both are checked here.
  B) The "WHAT WOULD RESOLVE THIS" steps in the report: they must match the actual reason
     and must not appear for a resolved case.

The starting case is the real Struts/Equifax case (CVE-2017-5638, vendor: 'Upgrade to Struts 2.3.32 ...').

Usage:  python3 check_fix_path.py        (exit code 1 if something differs)
"""

import contextlib
import copy
import io
import json
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
os.environ["METERLESS_MODE"] = "off"      # this is not about the Meterless engine
os.environ["LLM_PROVIDER"] = "rule_based"   # this check tests fixed rules; a language model would vary between runs

from main import run_case  # noqa: E402

CASES = json.load(open(os.path.join(ROOT, "data", "sample", "cases.json")))
STRUTS = CASES["CVE-2017-5638"]
failures = 0


def run(case, case_id=None):
    start = os.getcwd()
    os.chdir(tempfile.mkdtemp())
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            return run_case(case_id or case["cve_id"], case, verbose=False)
    finally:
        os.chdir(start)


def check(name, ok, detail=""):
    global failures
    failures += not ok
    print(f"  {'OK    ' if ok else 'FAIL  '} {name}{('  - ' + detail) if detail and not ok else ''}")


def with_ticket(text):
    case = copy.deepcopy(STRUTS)
    case["sources"]["internal_ticket"]["text"] = text
    return case


def main():
    print("A) 'vendor announces a fix' path")
    full = run(with_ticket(
        "Dependency scan on 2026-10-24 covered all 14 customer-facing applications: all 14 run struts-core 2.5.16 "
        "or later. The dispute portal was upgraded in the October sprint (ticket OPS-3402) and re-tested the same day. "
        "No exceptions."))
    check("fix announced + internally fully backed with version -> resolved", full["draft"]["resolved"] is True)
    check("... and the report states that it was internally confirmed",
          "confirmed deployed" in full["draft"]["final_severity"], full["draft"]["final_severity"])

    no_version = run(with_ticket(
        "Verified on 2026-10-24 across all 14 customer-facing applications; every one passed the vulnerability scan. "
        "No exceptions."))
    check("fix announced, internally certain, but WITHOUT a version proof -> NOT resolved (too loose would be wrong)",
          no_version["draft"]["resolved"] is False)

    partial = run(CASES["CVE-2017-5638"])
    check("original case (13 of 14, one portal unconfirmed) -> unresolved", partial["draft"]["resolved"] is False)

    absent = copy.deepcopy(STRUTS)
    del absent["sources"]["internal_ticket"]
    check("fix announced, nothing internal at all -> unresolved", run(absent)["draft"]["resolved"] is False)

    no_fix = copy.deepcopy(STRUTS)
    no_fix["sources"]["vendor_changelog"]["text"] = "The vendor has not published any statement about a fix."
    no_fix["sources"]["internal_ticket"]["text"] = full["draft"] and with_ticket(
        "all 14 run struts-core 2.5.16 or later, upgraded and re-tested on 2026-10-24.")["sources"]["internal_ticket"]["text"]
    check("vendor states NO fix, internal perfect -> unresolved (vendor statement missing)",
          run(no_fix)["draft"]["resolved"] is False)

    print("\nB) 'WHAT WOULD RESOLVE THIS'")
    report = lambda case_id: run(CASES[case_id], case_id)["report"]
    check("resolved case (CVE-2024-9999): no steps", "WHAT WOULD RESOLVE" not in report("CVE-2024-9999"))
    check("resolved case (Spring4Shell, real): no steps", "WHAT WOULD RESOLVE" not in report("CVE-2022-22965"))
    r = report("CVE-2023-0002")
    check("partial coverage '2 of our 15' is named as a step", "2 of our 15" in r and "WHAT WOULD RESOLVE" in r)
    r = report("CVE-2014-0160")
    check("Heartbleed: the pending key rotation is in the step", "re-issuing the remaining 9" in r)
    r = report("CVE-2024-7001")
    check("internal source missing: step 'record a check'", "nobody has recorded a check" in r)
    r = report("CVE-2024-7002")
    check("vendor missing: step 'ask the vendor'", "Ask the vendor" in r)
    r = report("CVE-2024-7003")
    check("both missing: two steps, internal first", "1. Internal" in r and "2. Vendor" in r)
    r = run(no_version := with_ticket(
        "Verified on 2026-10-24 across all 14 customer-facing applications; every one passed the vulnerability scan. "
        "No exceptions."))["report"]
    check("fix without a version proof: step asks for the version per system", "State the deployed version" in r)

    print("\nC) version check (regression tests after feedback from a vulnerability manager)")
    def with_both(vendor, ticket):
        c = copy.deepcopy(STRUTS)
        c["sources"]["vendor_changelog"]["text"] = vendor
        c["sources"]["internal_ticket"]["text"] = ticket
        return c
    V = "The issue is fixed in 2.17.1. Upgrade to 2.17.1 or later."
    must_not_resolve = [
        "Running version 2.14.1 on all hosts, upgrade pending approval.",
        "We upgraded the test VM to 2.17.1. Production still runs 2.14.",
        "Installed 2.17.1 on prod. Note: the backup container image still bundles 2.14.",
        "Patched web01 to 2.17.1.",
        "Upgraded to 2.17.1 on all hosts in staging only.",
        "All hosts will be upgraded to 2.17.1 next week.",
        # 2nd round (feedback): slipped through because of the wording, not because of the version logic
        "Upgraded all production hosts to 2.17.1; the legacy box was left out.",
        "Upgraded all production hosts to 2.17.1, except the two SAP appliances.",
        "Upgraded all production hosts to 2.17.1; no one verified it on the hosts.",
        # 3rd round: without a named verification method (positive proof) it stays open
        "Patched all production hosts to 2.17.1 and the DMZ jump host will follow.",
        "Upgraded the production web servers to 2.17.1. The DR site still has to be done.",
        "Upgraded all production servers to 2.17.1; I think the batch servers were included.",
        "All prod web servers now run 2.17.1. The app and DB tier are owned by another team.",
    ]
    for t in must_not_resolve:
        check(f"false all-clear prevented: '{t[:60]}'", run(with_both(V, t))["draft"]["resolved"] is False)
    must_resolve = [
        "Upgraded all 41 production hosts to 2.17.1; verified with the rescan.",
        "All 14 applications upgraded from 2.14.1 to 2.17.1 and confirmed by the rescan.",
    ]
    must_resolve += [
        "Upgraded all production hosts to 2.17.1; nothing other than log4j was changed; verified with the scanner.",
    ]
    for t in must_resolve:
        check(f"real confirmation stays possible: '{t[:60]}'", run(with_both(V, t))["draft"]["resolved"] is True)
    # KNOWN, CONSERVATIVE false blocks: the shared uncertainty rules (agents/source_mapper.py) know "skipped" and "could not find"
    # as doubt words; they were NOT touched, so the dev/test split of the text collection stays valid. Consequence: real confirmations with
    # these words stay open (safe direction, costs only an alarm). The test records this so it does not go unnoticed.
    for t in ["Upgraded all production hosts to 2.17.1; no host was skipped; confirmed by the rescan on 2026-10-24.",
              "All production hosts now run 2.17.1; the rescan could not find 2.14 anywhere."]:
        check(f"known conservative block (stays open, safe direction): '{t[:55]}'", run(with_both(V, t))["draft"]["resolved"] is False)
    r = run(with_both(V, must_not_resolve[1]))["report"]
    check("report names the reason (old version still present)", "2.14" in r and "WHAT WOULD RESOLVE" in r)

    total = 32
    print(f"\n{total - failures} of {total} as expected.")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
