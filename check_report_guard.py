#!/usr/bin/env python3
"""
Checks the safeguard AFTER the AI wording of the report (agents/reporter.py: _report_is_coherent).

  BAD   = reports that MUST be rejected (false all-clear / contradiction)
  GOOD  = reports that MUST pass (the check must not reject too much)

The texts are real outputs from Ollama (llama3:latest) from the author's runs - except the one clearly marked
"constructed". All are reports for cases with the decision "unresolved" (resolved=False).

Usage:  python3 check_report_guard.py        (exit code 1 if something differs)
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from agents.reporter import _report_is_coherent  # noqa: E402

BAD = {
    "Log4Shell, real run: 'not confirmed ... which remain unaffected'": """Security Report: CVE-2021-44228

Summary:
The vulnerability CVE-2021-44228, with a critical severity (CVSS 10.0), has been assessed as unresolved. Despite efforts to mitigate the issue, the vulnerability remains unpatched.

Evidence:
Vendor evidence suggests that JNDI message lookups are disabled by default at startup via log4j2.formatMsgNoLookups=true, set in our base container image since the October hardening pass. However, this setting is not inherited by clusters that have been migrated to a customer-managed image, such as prod-cluster-1 and prod-cluster-2.

Internal evidence confirms that prod-cluster-3 and prod-cluster-4 are running the hardened base image with formatMsgNoLookups=true, as verified via env dump. However, the lookup setting on these clusters is not confirmed for prod-cluster-1 and prod-cluster-2, which remain unaffected.

Recommendation:
Given the unresolved status and low confidence, it is recommended that a human review be conducted to verify the effectiveness of the mitigation measures and confirm the vulnerability's status on all affected clusters.
""",
    "constructed: decision 'Resolved: False', but 'has been determined that the vulnerability is resolved'": """**CVE:** CVE-X
**Final Decision:** Resolved: False

**Summary:** After review, it has been determined that the vulnerability is resolved and no further action is needed.
""",
}

GOOD = {
    "CVE-2024-7002 (real): good internal work, vendor silent": """**Security Vulnerability Report**

**CVE:** CVE-2024-7002
**NVD Baseline:** HIGH (CVSS 7.5)
**Final Decision:** Resolved: False, Final Severity: HIGH

**Summary:**
The vulnerability CVE-2024-7002 has been assessed as HIGH severity, with a Confidence level of LOW due to the unresolved status. The final decision is that the vulnerability is not resolved.

**Evidence:**

* **Vendor Evidence:** No vendor statement is available yet.
* **Internal Evidence:**
  + Removed network access to ExampleReports via firewall rule FW-881, verified on all 5 instances this morning.
  + The service is no longer reachable from outside the internal VPN, confirmed with an external port scan showing no response.

**Recommendations:**
Due to the unresolved status and low confidence level, manual verification is strongly recommended to confirm the status of this vulnerability. Further investigation is necessary to determine the effectiveness of the measures taken to mitigate the vulnerability.
""",
    "CVE-2017-5638 (real): Equifax pattern, 'unclear whether ...'": """**Security Vulnerability Report**

**CVE:** CVE-2017-5638
**Severity:** CRITICAL (CVSS 9.8)
**Final Decision:** Resolved: False, Final Severity: CRITICAL

**Internal Evidence:**

A dependency scan across all 14 customer-facing applications revealed that 13 are confirmed to be on Struts-core 2.5.16 or later. However, the dispute-portal application, which was flagged for decommissioning in Q1, has an uncertain upgrade status. Its retirement ticket does not have a target date, and it is unclear whether it was included in a follow-up pass.

**Next Steps:**
Given the unresolved status of this vulnerability assessment, manual verification is strongly recommended to confirm the current state of the dispute-portal application and its upgrade status.
""",
    "CVE-2024-7003 (real): day one, nothing present": """**Security Vulnerability Report**

**CVE:** CVE-2024-7003
**Final Decision:** Resolved = False, Final Severity = CRITICAL

**Evidence:**
- **Vendor Evidence:** No vendor statement is available yet.
- **Internal Evidence:** No internal check or ticket has been recorded yet.
- **Confidence Level:** Low, indicating that the assessment is not yet confirmed.

**Recommendations:**
- Obtain a statement from the vendor to confirm the status of the vulnerability.
- Record an internal check or ticket to verify the assessment.
""",
    "vendor quote 'not affected' and 'unconfirmed' in SEPARATE sentences": """**Evidence:**
The vendor states that applications that do not override this property are not affected.
The internal ticket says the setting on prod-cluster-1 and prod-cluster-2 is unconfirmed.
""",
}


def main():
    failures = 0
    for group, cases, expected in (("BAD (must be rejected)", BAD, False),
                                   ("GOOD (must pass)", GOOD, True)):
        print(group)
        for name, text in cases.items():
            got = _report_is_coherent(text, resolved=False)
            ok = got == expected
            failures += not ok
            print(f"  {'OK    ' if ok else 'FAIL  '} {name}")
    total = len(BAD) + len(GOOD)
    print(f"\n{total - failures} of {total} as expected.")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
