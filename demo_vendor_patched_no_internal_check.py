"""
A scenario to watch: the vendor has responded and published a clear,
confident fix - but internally at OUR side simply
nobody has checked yet whether it is even relevant to us or
whether we already have the fix. No assumption, no uncertainty - the
internal source simply does not exist for this case.

This directly tests the core rule of this project: no matter how
convincing a vendor fix is, it is NEVER enough on its own; without a real internal
confirmation the case stays "unresolved", even if the vendor part
looks perfect.

Usage:
    python3 demo_vendor_patched_no_internal_check.py
"""

import json

from main import run_case

CASE = {
    "cve_id": "CVE-DEMO-0001",
    "nickname": "DEMO - vendor has shipped a confident fix, nobody internally has checked yet",
    "sources": {
        "nvd": {
            "source_type": "public_vulnerability_database",
            "source_name": "NVD-style entry",
            "is_real_public_data": False,
            "note": "SYNTHETIC - for this demo only.",
            "cvss_v3_score": 8.8,
            "severity": "HIGH",
            "description": "A deserialization flaw in ExampleQueue allows a remote attacker to execute "
                            "arbitrary code via a crafted message payload.",
            "affected_versions": "ExampleQueue 3.0 through 3.4",
            "fixed_version": "3.5",
            "auth_required": False,
            "user_interaction_required": False,
            "attack_vector": "network",
        },
        "vendor_changelog": {
            "source_type": "vendor_changelog",
            "source_name": "ExampleQueue security advisory (synthetic)",
            "is_real_public_data": False,
            "note": "SYNTHETIC - a genuinely strong, unconditional vendor fix, on purpose.",
            "text": "Unsafe deserialization is disabled by default in 3.5 and the vulnerable code "
                     "path has been completely removed from the codebase. There is no configuration "
                     "that re-enables the old behaviour.",
        },
        # internal_ticket IS DELIBERATELY OMITTED - exactly the scenario
        # this is about: nobody has checked internally.
    },
}


def main():
    print("Scenario: the vendor fix is strong and unambiguous - but nobody internally has ever checked.\n")
    result = run_case(CASE["cve_id"], CASE, verbose=True)

    print("\n" + "=" * 70)
    print("ASSESSMENT")
    print("=" * 70)
    print(f"Result: resolved={result['draft']['resolved']}")
    if result["draft"]["resolved"]:
        print("Unexpected - a missing internal proof should NEVER have led to 'resolved' here.")
    else:
        print("Expected: despite a convincing vendor fix the case stays 'unresolved',")
        print("because the internal confirmation is completely missing - a vendor fix alone never counts.")
        print("See the trace line 'backfill_missing_sources' above: this is not uncertainty,")
        print("it is a deliberate, permanent rule of this system.")


if __name__ == "__main__":
    main()
