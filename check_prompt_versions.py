#!/usr/bin/env python3
"""
Checks the selection of the prompt versions (CERTAINTY_PROMPT=v1|v2|v3|v4|v5|v6) without calling a language model, and protects the
measurement from a silent error: that the examples in the prompt come from the test collection (which would flatter the measurement).

Usage:  python3 check_prompt_versions.py        (exit code 1 if something differs)
"""

import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

from agents import llm_provider, source_mapper as sm  # noqa: E402

failures = 0
V2_MARK = "a short, plain statement that REPORTS a completed result"
V3_MARK = "Do not invent doubt"


def check(name, ok, detail=""):
    global failures
    failures += not ok
    print(f"  {'OK    ' if ok else 'FAIL  '} {name}{('  - ' + detail) if detail and not ok else ''}")


def system_prompt_for(version, source_type=None):
    """The system prompt that would actually go to the model (the model itself is replaced by a stub)."""
    if version is None:
        os.environ.pop("CERTAINTY_PROMPT", None)
    else:
        os.environ["CERTAINTY_PROMPT"] = version
    seen = {}
    orig = llm_provider.complete
    llm_provider.complete = lambda system, user: seen.setdefault("system", system) and "HIGH\nok"
    try:
        sm._certainty_via_llm("Ticket", "We checked all 3 servers.", source_type)
    finally:
        llm_provider.complete = orig
    return seen["system"]


def main():
    saved = os.environ.get("CERTAINTY_PROMPT")
    print("Prompt version selection")
    default, v1, v2, v3, odd = (system_prompt_for(v) for v in (None, "v1", "v2", "v3", "unsinn"))
    check("default (nothing set) is v2", V2_MARK in default and V3_MARK not in default)
    check("v1: neither the v2 nor the v3 addition", V2_MARK not in v1 and V3_MARK not in v1)
    check("v2: v2 addition, no v3 addition", V2_MARK in v2 and V3_MARK not in v2)
    check("v3 builds on v2 (contains v2 AND its own addition)", V2_MARK in v3 and V3_MARK in v3)
    check("unknown value -> fall back to v2 (no crash)", V2_MARK in odd and V3_MARK not in odd)
    nvd = [system_prompt_for(v, "public_vulnerability_database") for v in ("v1", "v2", "v3")]
    check("database entries (NVD) never get the strict standard, in any version",
          all(V2_MARK not in p and V3_MARK not in p and "standard vulnerability database description" in p for p in nvd))

    print("\nProtecting the measurement")
    examples = re.findall(r'^- "(.+?)"\s+->', sm.STRICT_NOTE_V3, flags=re.M | re.S)
    examples = [" ".join(x.split()) for x in examples]
    check("v3 names three examples", len(examples) == 3, str(len(examples)))
    corpus = [" ".join(json.loads(l)["text"].split()) for l in open(os.path.join(ROOT, "evaluation", "corpus.jsonl")) if l.strip()]
    clash = [x for x in examples if any(x in c or c in x for c in corpus)]
    check("no example in the prompt is in the test collection (otherwise the measurement would be flattered)", not clash, str(clash))

    print("\nv4-v6 (checklist, majority, cross-check) with a stub as the model")
    ck = re.findall(r'^- "(.+?)"\s*\n\s*->', sm.CHECKLIST_SYSTEM, flags=re.M | re.S)
    ck = [" ".join(x.split()) for x in ck]
    check("v4 names three examples", len(ck) == 3, str(len(ck)))
    clash4 = [x for x in ck if any(x in c or c in x for c in corpus)]
    check("no v4 example is in the test collection", not clash4, str(clash4))

    def fake(answers):
        """Stub: returns the prepared answers (list) one after another - counts the calls."""
        calls = []
        def complete(system, user):
            calls.append(system[:40])
            return answers[min(len(calls) - 1, len(answers) - 1)]
        return complete, calls

    NO5 = "Q1: NO\nQ2: NO\nQ3: NO\nQ4: NO\nQ5: NO\nEVIDENCE: none"
    YES1 = "Q1: YES\nQ2: NO\nQ3: NO\nQ4: NO\nQ5: NO\nEVIDENCE: 2 of 5"
    saved_c, sm.PARSE_FAILURES = llm_provider.complete, 0
    try:
        os.environ["CERTAINTY_PROMPT"] = "v4"
        llm_provider.complete, calls = fake([NO5])
        check("v4: five times NO -> high", sm._certainty_via_llm("t", "x", "internal_ticket")[0] == "high")
        llm_provider.complete, calls = fake([YES1])
        r = sm._certainty_via_llm("t", "x", "internal_ticket")
        check("v4: one YES is enough -> low, with evidence", r[0] == "low" and "2 of 5" in r[1], str(r))
        llm_provider.complete, calls = fake(["**Q1:** no\nq2 - No\nQ3: NO\nQ4: NO\nQ5: No"])
        check("v4: case and bold are read",
              sm._certainty_via_llm("t", "x", "internal_ticket")[0] == "high")
        llm_provider.complete, calls = fake(["I do not know.", "Nor that one."])
        r = sm._certainty_via_llm("t", "x", "internal_ticket")
        check("v4: unreadable (twice) -> low and counted, no crash",
              r[0] == "low" and sm.PARSE_FAILURES == 1 and len(calls) == 2, str((r, sm.PARSE_FAILURES, len(calls))))
        llm_provider.complete, calls = fake(["Q1: NO", NO5])
        check("v4: unreadable, then readable (second attempt) -> high",
              sm._certainty_via_llm("t", "x", "internal_ticket")[0] == "high")
        llm_provider.complete = lambda s, u: None
        check("v4: without a model -> None (fallback)", sm._certainty_via_llm("t", "x", "internal_ticket") is None)

        os.environ["CERTAINTY_PROMPT"] = "v5"
        llm_provider.complete, calls = fake(["LOW\nno", "HIGH\nok", NO5])
        check("v5: 1 of 3 LOW -> high; three calls", sm._certainty_via_llm("t", "x", "internal_ticket")[0] == "high" and len(calls) == 3)
        llm_provider.complete, calls = fake(["LOW\nno", "HIGH\nok", YES1])
        check("v5: 2 of 3 LOW -> low", sm._certainty_via_llm("t", "x", "internal_ticket")[0] == "low")

        os.environ["CERTAINTY_PROMPT"] = "v6"
        llm_provider.complete, calls = fake(["HIGH\nok"])
        check("v6: v2 says HIGH -> high, only one call", sm._certainty_via_llm("t", "x", "internal_ticket")[0] == "high" and len(calls) == 1)
        llm_provider.complete, calls = fake(["LOW\nhedge", NO5])
        r = sm._certainty_via_llm("t", "x", "internal_ticket")
        check("v6: v2 says LOW, checklist disagrees -> high", r[0] == "high" and len(calls) == 2, str(r))
        llm_provider.complete, calls = fake(["LOW\nhedge", YES1])
        check("v6: v2 says LOW, checklist confirms -> low", sm._certainty_via_llm("t", "x", "internal_ticket")[0] == "low")

        os.environ["CERTAINTY_PROMPT"] = "v4"
        llm_provider.complete, calls = fake(["HIGH\nok"])
        check("NVD entries take the old path even under v4 (no checklist prompt)",
              sm._certainty_via_llm("t", "x", "public_vulnerability_database")[0] == "high")
    finally:
        llm_provider.complete = saved_c
        sm.PARSE_FAILURES = 0

    if saved is None:
        os.environ.pop("CERTAINTY_PROMPT", None)
    else:
        os.environ["CERTAINTY_PROMPT"] = saved
    print(f"\n{'all checks passed' if not failures else str(failures) + ' check(s) FAILED'}.")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
