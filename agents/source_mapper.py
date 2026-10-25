"""
Agent 1: Source Mapper.

Takes the three raw sources of a task (NVD, vendor note, internal
ticket note) and brings each into a COMPARABLE form. The most important
part of that is a real assessment: does THIS source consider its statement
certain and complete, or does it sound uncertain/incomplete?

This is the point where an AI actually JUDGES, not just wording sentences
more nicely (only the Reporter does that at the end) - see
_certainty_via_llm(). With a key the AI decides this on substance,
with a reason that is logged. Without a key (example mode)
a fixed word list kicks in as a fallback - less clever, but always
available and always the same, which is exactly the required example mode.
"""

from . import llm_provider

CERTAINTY_MARKERS_LOW = ["unconfirmed", "unclear", "not confirmed", "no one has confirmed",
                         "could not find", "no later commit"]


def _certainty_from_keywords(text):
    """Fallback without AI - fixed word list, always the same, always available."""
    lowered = text.lower()
    for marker in CERTAINTY_MARKERS_LOW:
        if marker in lowered:
            return "low", f"keyword match ('{marker}')"
    return "high", "keyword check: no low-certainty phrase found"


import re  # noqa: E402

# Reservations that contain NO warning word from the old list. Each group describes a KIND of
# reservation (not a single sentence). Derived from the errors of the development half of the
# test collection (evaluation/) - the test half was not looked at for this.
_PARTIAL_COVERAGE = re.compile(r"\b(\d+)\s*(?:of|out of)\s*(?:our |the |all |those )?(\d+)\b", re.I)
_IMPLICIT_HEDGE_PATTERNS = [
    ("pending/scheduled", re.compile(
        r"\bscheduled for\b|\bplanned for\b|\bnext (?:week|month|sprint|release|quarter|maintenance)"
        r"|\b(?:not|n't) (?:\w+ ){0,2}yet\b|\byet to\b"
        r"|\bremaining (?:nodes|hosts|servers|instances|systems|clusters|sites|machines)\b|\bthe rest (?:are|is)\b", re.I)),
    ("stale", re.compile(
        r"\bas of last (?:year|quarter|month)\b"
        r"|\b(?:verified|checked|audited|confirmed|reviewed|tested)\s+(?:\w+\s+){0,2}\d+ (?:months?|years?) ago\b"
        r"|\bwhen we last (?:looked|checked)\b|\bnothing has been (?:checked|verified) since\b|\ba while back\b", re.I)),
    ("inference", re.compile(
        r"\bshould still\b|\bwe assume\b|\bassum(?:e|ed|ing)\b|\bprobabl[ey]\b", re.I)),
    ("exception clause", re.compile(
        r"\bunless\b|\bdo not override\b|\bthat override\b|\bmay still\b", re.I)),
    ("named gap", re.compile(
        r"\bexcluded from\b|\bskipped\b|\bout of scope\b", re.I)),
]


def _implicit_hedge_check(text):
    """Fourth, rule-based check: reservations WITHOUT a classic warning word - incomplete coverage
    ("11 of 13"), pending work, a stale check, an assumption, an exception clause, a named gap.
    Returns ("low", reason) or None (None = this check has nothing to report)."""
    for m in _PARTIAL_COVERAGE.finditer(text):
        if int(m.group(1)) < int(m.group(2)):
            return "low", f"implicit-hedge check: partial coverage ('{m.group(0)}') - not everything was confirmed"
    for name, pattern in _IMPLICIT_HEDGE_PATTERNS:
        m = pattern.search(text)
        if m:
            return "low", f"implicit-hedge check: {name} ('{m.group(0)}')"
    return None


# Words that signal a COMPLETE claim ("fully resolved")
_BROAD_CLAIM_WORDS = ["fully", "completely", "entirely"]
# Words that mark a recognizably NARROWER, EXPLICITLY NAMED subset -
# typical of real security advisories that patch only part of the system
# but phrase it to sound like a complete solution
_NARROW_SCOPE_WORDS = ["internet-facing", "public-facing", "externally-facing",
                       "external-only", "edge nodes", "load balancer", "perimeter"]


def _scope_overclaim_check(text):
    """Third, independent check, outside the word list AND the AI:
    recognizes exactly the pattern the AI failed on in a real test
    run - a complete claim ("fully addresses...") in the same
    text as a narrowly named subset ("internet-facing load
    balancers"). Fires ONLY when BOTH occur together, so genuine,
    actually complete solutions (e.g. "completely removed from the
    codebase", without any subset mention) are not wrongly counted as
    uncertain. Returns (certainty, reason) or None (no signal) -
    None does NOT mean 'safe', but 'this check has
    nothing to say here', the other two checks then decide."""
    lowered = text.lower()
    has_broad_claim = any(w in lowered for w in _BROAD_CLAIM_WORDS)
    matched_scope = next((w for w in _NARROW_SCOPE_WORDS if w in lowered), None)
    if has_broad_claim and matched_scope:
        return "low", (f"scope-overclaim check: text uses an absolute word (e.g. 'fully') "
                       f"together with a named narrower subset ('{matched_scope}') - the broad "
                       f"claim likely does not cover the full system")
    return None


import os  # noqa: E402

# Strict standard for vendor/internal notes. v1 = state of the first measurement (58% false alarms on
# the test half), v2 = reaction to the development half: v1 said only when something is UNCERTAIN,
# never that a short, clear success report is CERTAIN, and read "If/When/Should" as doubt.
# v3 = reaction to the ERRORS OF THE DEVELOPMENT HALF of v2 (the test half was not looked at for this): the model
# invented doubt (unnamed 'remaining servers', later changes), read a named date as staleness, demanded an
# explicit 'everything is safe' - and took 'fully solves the problem' at face value for only one named subset.
# Switch: CERTAINTY_PROMPT=v1 | v2 | v3 | v4 | v5 | v6 (default: v2; rules for a change: README and evaluation/RESULTS.md).
STRICT_NOTE_V1 = """This text describes the state of a SPECIFIC environment or product
version - here the strict standard applies in full: partial coverage,
staleness, or any hedge about the actual current state counts as LOW,
even if most of the text sounds confident."""

STRICT_NOTE_V2 = STRICT_NOTE_V1 + """

But a short, plain statement that REPORTS a completed result or a completed fix is HIGH.
It does not have to repeat dates, methods or scope to be certain - missing detail alone is
not a hedge. Only count what the text actually says or clearly implies: doubt, partial
coverage, pending work, an old check, an assumption, a named exclusion, or a broad claim
that is only backed for a narrower subset.

Technical "if / when / should" wording that merely DESCRIBES how a fix behaves (for example
"If an upload path contains '..', the filter rejects it") is NOT a hedge. Judge whether the
verification the text reports is complete, not whether the sentence contains a conditional."""


STRICT_NOTE_V3 = STRICT_NOTE_V2 + """

Judge only what the text SAYS. Do not invent doubt:
- Never speculate about systems, servers, instances or time periods the text does not mention. If the
  text names its own scope with a complete quantifier ("every one of the 8 servers", "all 20 instances",
  "against all 26 payloads"), that scope is covered completely - do NOT assume other, unnamed servers exist.
- A concrete date, version number or attached evidence is normal proof, not staleness. A check is stale
  only if the text itself says it is old or from another period than the claim.
- A text does not have to say "everything is secure". Reporting that every check passed, or that none of
  the payloads got through, IS a complete result.
- A sentence starting with "If / When / Should / Whenever" that describes how a fix behaves is a
  description, not a hedge; judge the verification the text reports afterwards.

But compare what the text CLAIMS with what it actually NAMES as backed. A sweeping conclusion ("fully
addresses the vulnerability", "completely resolves the issue", "the problem is entirely solved") that is
supported only for a narrower part of the environment (for example only the internet-facing, public-facing,
perimeter, edge, external or staging systems, or one named tier) is NOT backed: answer LOW.

Examples (invented for this prompt, not taken from any data set):
- "If the form field contains a script tag, the sanitizer strips it. We re-ran all 40 regression payloads
  against all 9 hosts; none got through."  -> HIGH (complete named scope, complete result)
- "The staging web tier is patched, so the whole vulnerability is now fixed."  -> LOW (sweeping claim, only
  one tier named)
- "Checked 3 of 11 hosts so far; the rest follow next week."  -> LOW (partial, pending)"""


def _strict_note(version=None):
    """The strict standard depending on CERTAINTY_PROMPT (or an explicitly passed version); unknown values
    fall back to the default v2."""
    version = version or os.environ.get("CERTAINTY_PROMPT", "v2")
    return {"v1": STRICT_NOTE_V1, "v3": STRICT_NOTE_V3}.get(version, STRICT_NOTE_V2)


# ---------------------------------------------------------------------------
# v4-v6: reaction to the result of v3 (see README, "Prompt v4-v6"). The idea: a small model judges
# poorly in ONE overall judgement with many rules (v3 added rules and got new false alarms).
#   v4  checklist: five narrowly framed yes/no questions about what the text SAYS; the CODE decides
#       (LOW as soon as one question is answered YES) - the model only fills it in.
#   v5  majority of three different prompts (v2, v3, v4): single outliers of one prompt count less.
#   v6  cross-check: v2 decides; if v2 says LOW, the v4 checklist must confirm it, otherwise HIGH.
# During development the test half was NOT looked at; only v3's category table was known
# (published in RESULTS.md). The examples below are invented and are not in the corpus (verified in
# check_prompt_versions.py).
# ---------------------------------------------------------------------------

CHECKLIST_SYSTEM = """You are a careful security analyst. Read the text and answer five factual questions
about what the text SAYS. Do not guess about anything the text does not mention; never invent other
servers, systems or time periods.

Q1 PARTIAL: Does the text say that only PART of the relevant systems, instances or period was checked or
   fixed, or that something is still open, not yet done, scheduled for later, or to follow? (A complete
   quantifier such as "all 12 servers", "every instance" or "none of the payloads got through" means NOT partial.)
Q2 DOUBT: Does the text itself express doubt - an assumption, an inference, "believed", "we think",
   "expected to", "should be" in the sense of "probably is", or say that something is unconfirmed or unknown?
Q3 OLD: Does the text itself say that its check or information is old, outdated, or from before the change
   it talks about?
Q4 EXCLUSION: Does the text name an exception, an exclusion, or a system that is not covered?
Q5 OVERCLAIM: Does the text draw a sweeping conclusion ("fully fixed", "completely resolved", "the whole
   problem is solved") while naming only a narrower part (one tier, only public-facing, only staging, only
   the edge) as backed?

Rules for answering:
- A conditional sentence that DESCRIBES how a fix behaves ("If the input contains X, the filter rejects it")
  is not doubt.
- A concrete date, version number or attached evidence is not "old".
- Missing detail alone is not doubt. A short plain report of a completed result answers NO to all five.

Examples (invented for this prompt):
- "All 6 gateways run the patched build; verified by script."
  -> Q1 NO, Q2 NO, Q3 NO, Q4 NO, Q5 NO
- "Two of the five nodes are done, the others are scheduled for next sprint."
  -> Q1 YES, Q2 NO, Q3 NO, Q4 NO, Q5 NO
- "The edge proxies are patched, so the whole issue is closed."
  -> Q1 NO, Q2 NO, Q3 NO, Q4 NO, Q5 YES

Answer with exactly five lines, "Q1: YES" or "Q1: NO" down to "Q5", and then a sixth line starting with
"EVIDENCE:" that quotes the phrase behind every YES (or says "none")."""

CHECKLIST_QUESTIONS = {
    "Q1": "partial coverage or pending work", "Q2": "doubt or assumption", "Q3": "stale information",
    "Q4": "named exclusion", "Q5": "sweeping claim backed only for a narrower part",
}
PARSE_FAILURES = 0  # how often the checklist was answered unreadably (counted cautiously as LOW); evaluate.py shows them


def _parse_checklist(raw):
    """Reads the five yes/no answers. Returns (certainty, reason) or None if not readable."""
    answers = {}
    for m in re.finditer(r"\bQ([1-5])\s*[:\-]\s*\**\s*(YES|NO)\b", raw or "", flags=re.I):
        answers.setdefault("Q" + m.group(1), m.group(2).upper())
    if len(answers) < 5:
        return None
    ev = re.search(r"EVIDENCE\s*:\s*(.+)", raw, flags=re.I)
    evidence = ev.group(1).strip() if ev else ""
    yes = [CHECKLIST_QUESTIONS[q] for q in sorted(answers) if answers[q] == "YES"]
    if yes:
        return "low", f"checklist: {'; '.join(yes)}" + (f" - {evidence}" if evidence and evidence.lower() != "none" else "")
    return "high", "checklist: no hedge found (all five questions answered NO)"


def _certainty_via_checklist(source_name, text):
    """v4. Unreadable answer -> a second attempt; after that cautiously LOW (and counted)."""
    global PARSE_FAILURES
    user_prompt = f"Source: {source_name}\n\nText:\n{text}"
    for _ in range(2):
        raw = llm_provider.complete(CHECKLIST_SYSTEM, user_prompt)
        if raw is None:
            return None  # no model configured
        parsed = _parse_checklist(raw)
        if parsed is not None:
            return parsed
    PARSE_FAILURES += 1
    return "low", "checklist answer not readable twice - treated cautiously as LOW"


def _certainty_via_llm(source_name, text, source_type=None):
    """Dispatches depending on CERTAINTY_PROMPT: v1-v3 = one call with a different standard, v4 = checklist,
    v5 = majority of v2/v3/v4, v6 = v2 with a cross-check by v4. Database entries (NVD) always take
    the old path (no strict standard, no checklist)."""
    version = os.environ.get("CERTAINTY_PROMPT", "v2")
    if source_type == "public_vulnerability_database" or version not in ("v4", "v5", "v6"):
        return _certainty_single(source_name, text, source_type, version)
    if version == "v4":
        return _certainty_via_checklist(source_name, text)
    if version == "v5":
        votes = [_certainty_single(source_name, text, source_type, "v2"),
                 _certainty_single(source_name, text, source_type, "v3"),
                 _certainty_via_checklist(source_name, text)]
        if any(v is None for v in votes):
            return None
        low = [v for v in votes if v[0] == "low"]
        if len(low) >= 2:
            return "low", f"majority LOW ({len(low)} of 3): {low[0][1]}"
        high = [v for v in votes if v[0] == "high"]
        return "high", f"majority HIGH ({len(high)} of 3): {high[0][1]}"
    first = _certainty_single(source_name, text, source_type, "v2")  # v6
    if first is None or first[0] == "high":
        return first
    check = _certainty_via_checklist(source_name, text)
    if check is None:
        return None
    if check[0] == "low":
        return "low", f"{first[1]} | confirmed by {check[1]}"
    return "high", f"first judgement LOW, not confirmed by the checklist: {check[1]}"


def _certainty_single(source_name, text, source_type=None, version=None):
    """Real AI assessment: does THIS source consider its own statement
    certain/complete enough to rely on? Returns
    (certainty, reason), or None if no key is configured
    (then the fallback in map_sources() kicks in).

    source_type distinguishes WHICH standard applies: an official
    database description (nvd) describes a mechanism in the
    USUAL "can trigger X" wording - that is the fixed
    description style for vulnerabilities, not uncertainty about the
    fact itself, and must not be counted as a hedge. For
    vendor and internal notes (which are about the state of the OWN
    environment) the strict standard still applies - an earlier
    test run showed that without this distinction a small model is too
    aggressive, reading every "can"/"allows" wording as uncertain,
    even where it is only the usual style."""
    if source_type == "public_vulnerability_database":
        scope_note = """This text is a standard vulnerability database description. It is EXPECTED
to use capability language like "can trigger", "allows an attacker to" -
that is the normal, fixed style for describing what a vulnerability's
mechanism does, NOT an expression of uncertainty about whether it is
true. Do NOT count that phrasing as a hedge by itself. Only answer LOW
if the text contains a genuine epistemic hedge about the FINDING itself
(e.g. "may be vulnerable", "suspected", "unverified report") - not about
what an attacker could then do once the mechanism is triggered."""
    else:
        scope_note = _strict_note(version)

    system_prompt = f"""You are a careful security analyst judging ONE thing: does this text, in
its OWN words, fully and completely confirm its claim - or is it partial,
hedged, incomplete, or stale?

{scope_note}

Beyond the note above, answer LOW if ANY of these apply:
- Explicit hedging about the actual state: "unconfirmed", "unclear", "unknown",
  "pending", "believed to be", "we think".
- Confirms only PART of the relevant scope and leaves another part
  unaddressed or explicitly unchecked (e.g. "3 of 5 servers checked").
- Relies on an OLD check with nothing more recent confirming the current
  state (e.g. "as of last year's audit").
- Infers or assumes rather than directly verifies.

Answer with exactly one word on the first line: HIGH or LOW.
Then one short sentence explaining why, quoting the specific phrase that
drove your judgement."""
    user_prompt = f"Source: {source_name}\n\nText:\n{text}"

    raw = llm_provider.complete(system_prompt, user_prompt)
    if raw is None:
        return None  # no key configured - caller uses the fallback

    lines = [l.strip() for l in raw.strip().splitlines() if l.strip()]
    if not lines:
        return None
    verdict = lines[0].strip().upper()
    reason = " ".join(lines[1:]) if len(lines) > 1 else raw.strip()

    if verdict.startswith("HIGH"):
        return "high", reason
    if verdict.startswith("LOW"):
        return "low", reason
    return None  # unexpected answer - better to fall back than to guess


REQUIRED_SOURCE_KEYS = ("nvd", "vendor_changelog", "internal_ticket")


def _placeholder_claim(key):
    """For a source that simply does NOT EXIST yet in the real
    world (e.g. a brand-new vulnerability the vendor has not yet
    published anything about, or an internal team that has not yet
    looked). Deliberately certainty='low' - the absence of
    evidence is not evidence of safety; a hole in the data must never
    silently pass as 'fine'. This source then flows
    normally through the same 'the most cautious assessment
    wins' logic as any other, no special case needed."""
    labels = {
        "nvd": "No public vulnerability database entry available yet",
        "vendor_changelog": "No vendor statement available yet",
        "internal_ticket": "No internal check/ticket recorded yet",
    }
    claim = {
        "source_key": key,
        "source_name": f"(absent) {labels.get(key, key)}",
        "source_type": "absent",
        "is_real_public_data": False,
        "raw_text": labels.get(key, f"No '{key}' source available."),
        "certainty": "low",
        "certainty_method": "absent-source",
        "certainty_reason": "This source does not exist for this case - treated as unconfirmed, not as safe.",
    }
    if key == "nvd":
        claim["severity_claim"] = "UNKNOWN (no NVD entry yet)"
        claim["cvss_v3_score"] = None
    return claim


def assess_certainty(source_name, text, source_type=None, use_llm=True):
    """Overall assessment of ONE source - the same logic for the real flow (map_sources)
    and for the test bench (evaluation/evaluate.py), so what really runs is what is measured.
    use_llm=False forces the pure rule version. Returns (certainty, reason, method)."""
    keyword_certainty, keyword_reason = _certainty_from_keywords(text)
    scope_result = _scope_overclaim_check(text)
    llm_result = (_certainty_via_llm(source_name, text, source_type=source_type)
              if use_llm else None)

    # Three independent checks - the MOST CAUTIOUS always wins.
    # scope_result is None when this third check has nothing to report
    # (no contradiction to the word list/AI in that case).
    if llm_result is None:
        certainty, reason, method = keyword_certainty, keyword_reason, "keyword-fallback"
    else:
        llm_certainty, llm_reason = llm_result
        if keyword_certainty == "low":
            # Safety net: the AI may NEVER rate a statement more certain
            # than the simple word check allows - a
            # real test run showed that a small local model
            # can make exactly this error (see README, section
            # "Why two checks"). The AI may, however, still judge
            # less certain than the word list alone would recognize.
            certainty = "low"
            reason = f"keyword check found a hedge the model missed or agreed with: {keyword_reason}"
            method = "keyword-override" if llm_certainty == "high" else "llm+keyword agree"
        else:
            certainty, reason, method = llm_certainty, llm_reason, "llm"

    implicit_result = _implicit_hedge_check(text)
    if implicit_result is not None and certainty == "high":
        certainty, reason = implicit_result
        method = "implicit-hedge-override"

    if scope_result is not None and certainty == "high":
        # The third check found something that neither the word list nor the AI
        # (in a real test run) had recognized - exactly the case
        # that led to introducing this check.
        certainty, reason = scope_result
        method = "scope-overclaim-override"

    return certainty, reason, method


DEFAULT_SOURCE_TYPE = {
    "nvd": "public_vulnerability_database",
    "vendor_changelog": "vendor_changelog",
    "internal_ticket": "internal_ticket",
}


def _clean_text(value):
    """Only real, non-empty text counts. None, '', only spaces, numbers, lists -> None."""
    return value.strip() if isinstance(value, str) and value.strip() else None


def baseline_text(nvd):
    """Readable baseline rating, even if the NVD entry has no rating (e.g. 'awaiting analysis')."""
    severity = nvd.get("severity_claim") or "UNKNOWN"
    score = nvd.get("cvss_v3_score")
    return f"{severity} (CVSS {score})" if score is not None else str(severity)


def map_sources(case, trace):
    """A source that is missing OR has no usable text is treated like a missing one
    (placeholder with certainty=low) - it must never crash the program."""
    claims, unusable = {}, []
    sources = case.get("sources") or {}
    for key, src in sources.items():
        if not isinstance(src, dict):
            unusable.append(key)
            continue
        text = _clean_text(src.get("text")) or _clean_text(src.get("description"))
        if text is None and key == "nvd" and (src.get("severity") or src.get("cvss_v3_score") is not None):
            text = "(no description provided)"      # rating present, only without a description
        if text is None:
            unusable.append(key)
            continue

        source_name = src.get("source_name") or key
        source_type = src.get("source_type") or DEFAULT_SOURCE_TYPE.get(key, key)
        certainty, reason, method = assess_certainty(source_name, text, source_type=source_type)

        claim = {
            "source_key": key,
            "source_name": source_name,
            "source_type": source_type,
            "is_real_public_data": bool(src.get("is_real_public_data", False)),
            "raw_text": text,
            "certainty": certainty,
            "certainty_method": method,
            "certainty_reason": reason,
        }
        if key == "nvd" or "cvss_v3_score" in src:
            claim["severity_claim"] = src.get("severity") or "UNKNOWN (no severity in the NVD entry)"
            claim["cvss_v3_score"] = src.get("cvss_v3_score")
        claims[key] = claim

    missing_keys = [k for k in REQUIRED_SOURCE_KEYS if k not in claims]
    for key in missing_keys:
        claims[key] = _placeholder_claim(key)
    if missing_keys:
        note = f"; present but unusable (empty/malformed): {unusable}" if unusable else ""
        trace.log(
            agent="SourceMapper", action="backfill_missing_sources",
            input_summary=f"case provided only {[k for k in sources if k not in unusable]}",
            output_summary=f"missing source(s) {missing_keys} treated as low-certainty placeholders, not a crash{note}",
            target_agent="Reconciler", status="ok",
        )

    certainty_summary = {k: f"{c['certainty']} ({c['certainty_method']})" for k, c in claims.items()}
    trace.log(
        agent="SourceMapper",
        action="map_sources",
        input_summary=f"{len(sources)} raw sources for {case.get('cve_id', '?')}",
        output_summary=f"{len(claims)} normalised claims; certainty={certainty_summary}",
        target_agent="Reconciler",
        status="ok",
        confidence=None,
    )
    return claims
