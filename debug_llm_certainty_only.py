"""
Pure AI test, WITHOUT the word list as a comparison or safety net.

Calls _certainty_via_llm() directly for every source of every sample task
and shows only what the AI says on its own, with its reasoning.
Additionally: a simple, expected value per source (set by hand,
see EXPECTED below), so it is immediately visible whether the AI
alone - without any fallback - is correct.

IMPORTANT: this is a diagnostic tool, not part of the actual
program. The real flow (main.py) STILL uses the safety net
from source_mapper.map_sources() - this script only tests whether the
safety net is still needed at all, with the stricter instruction.

Usage:
    python3 debug_llm_certainty_only.py
"""

import json

from agents.source_mapper import _certainty_via_llm

# Set by hand, evident from each source's text itself -
# this is the truth we check the AI against on its own, independent
# of any word list.
EXPECTED = {
    ("CVE-2021-44228", "nvd"): "high",
    ("CVE-2021-44228", "vendor_changelog"): "low",  # names an exception itself
        # (applications that override the setting) - a careful
        # reading may count it as a borderline case, see test-run result
    ("CVE-2021-44228", "internal_ticket"): "low",   # 2 of 4 clusters unconfirmed
    ("CVE-2024-9999", "nvd"): "high",
    ("CVE-2024-9999", "vendor_changelog"): "high",
    ("CVE-2024-9999", "internal_ticket"): "high",   # all 3 instances directly confirmed
    ("CVE-2024-8888", "nvd"): "high",
    ("CVE-2024-8888", "vendor_changelog"): "low",   # names an exception itself
        # (upgraded-in-place legacy installs) - the same borderline case as above
    ("CVE-2024-8888", "internal_ticket"): "low",    # current value not found
    # New, deliberately UNAMBIGUOUS cases, without built-in borderline cases -
    # so the total is no longer skewed by a matter of opinion
    ("CVE-2023-0001", "nvd"): "high",
    ("CVE-2023-0001", "vendor_changelog"): "high",  # no restriction in the text
    ("CVE-2023-0001", "internal_ticket"): "high",   # all 12 instances, no exception
    ("CVE-2023-0002", "nvd"): "high",
    ("CVE-2023-0002", "vendor_changelog"): "low",   # vendor itself says "not verified"
    ("CVE-2023-0002", "internal_ticket"): "low",    # only 2 of 15 checked
    ("CVE-2023-0003", "nvd"): "high",               # strong "can/allows" language,
        # but that is exactly what the per-source-type distinction should now classify correctly
    ("CVE-2023-0003", "vendor_changelog"): "high",  # "no exceptions or opt-outs"
    ("CVE-2023-0003", "internal_ticket"): "high",   # all 8 instances, no exception
    # Two deliberately tricky cases, WITHOUT an obvious signal word -
    # meant to test whether the AI really understands the CONTENT, not just
    # searching for words like "unconfirmed"
    ("CVE-2023-0004", "nvd"): "high",
    ("CVE-2023-0004", "vendor_changelog"): "low",   # TRAP: with "fully
        # addresses" it sounds completely safe, but only covers one subset
        # (only internet-facing load balancers, not internal traffic)
    ("CVE-2023-0004", "internal_ticket"): "high",   # precise, not hedged -
        # names the same gap area honestly and completely
    ("CVE-2023-0005", "nvd"): "high",
    ("CVE-2023-0005", "vendor_changelog"): "high",
    ("CVE-2023-0005", "internal_ticket"): "high",   # TRAP: "if...then" sentence structure
        # only describes HOW the fix works, but is still
        # a complete, current, full check (all 6 instances,
        # all 40 attack patterns, today, none got through)
    # Second REAL vulnerability (Equifax/Apache Struts) - historically
    # exactly the pattern we test anyway: almost everything patched, ONE
    # overlooked application was enough for the real breach in 2017.
    ("CVE-2017-5638", "nvd"): "high",
    ("CVE-2017-5638", "vendor_changelog"): "high",  # Apache is
        # unambiguous here: no workaround, only the upgrade closes the gap
    ("CVE-2017-5638", "internal_ticket"): "low",    # 13 of 14 confirmed,
        # but exactly the one exception (the complaint portal) is
        # unconfirmed - the same error as in the real Equifax breach
    # Three cases with deliberately MISSING sources - only the actually
    # PRESENT sources are checked here; a missing source
    # never goes through _certainty_via_llm, see source_mapper.py's
    # _placeholder_claim(), which is a separate, fixed path.
    ("CVE-2024-7001", "nvd"): "high",
    ("CVE-2024-7001", "vendor_changelog"): "high",  # strong, unconditional,
        # no narrowly named subset - must not run into the scope trap
    ("CVE-2024-7002", "nvd"): "high",
    ("CVE-2024-7002", "internal_ticket"): "high",   # complete, current,
        # externally verified (port scan), no restriction in the text
    # Two real CVEs (public NVD facts, paraphrased vendor statements, synthetic internal tickets)
    ("CVE-2022-22965", "nvd"): "high", ("CVE-2022-22965", "vendor_changelog"): "high",
    ("CVE-2022-22965", "internal_ticket"): "high",   # complete, dated, re-test, no exception
    ("CVE-2014-0160", "nvd"): "high", ("CVE-2014-0160", "vendor_changelog"): "high",
    ("CVE-2014-0160", "internal_ticket"): "low",     # "31 of 40 reissued; the rest next week"
    ("CVE-2024-7003", "nvd"): "high",               # only this one source
        # exists here at all
}


def main():
    cases = json.load(open("data/sample/cases.json"))
    correct, total = 0, 0

    for cve_id, case in cases.items():
        print(f"\n{'='*70}\n{cve_id}\n{'='*70}")
        for key, src in case["sources"].items():
            text = src.get("text") or src.get("description")
            result = _certainty_via_llm(src["source_name"], text, source_type=src["source_type"])

            if result is None:
                print(f"  {key}: NO result - no provider/key configured, "
                      f"check LLM_PROVIDER in .env")
                continue

            certainty, reason = result
            expected = EXPECTED.get((cve_id, key))
            match = "OK  " if certainty == expected else "WRONG"
            total += 1
            correct += (certainty == expected)

            print(f"  [{match}] {key}: AI says {certainty.upper()}, expected {expected.upper()}")
            print(f"          Reasoning: {reason}")

    print(f"\n{'='*70}")
    if total == 0:
        print("Not a single call returned a result - check LLM_PROVIDER.")
    else:
        print(f"AI alone, WITHOUT the word list: {correct}/{total} correct ({100*correct/total:.0f}%)")


if __name__ == "__main__":
    main()
