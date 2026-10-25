"""
Agent 4: Reporter.

Writes the final output for the security analyst: urgency,
confidence value, evidence path, and - if unresolved - a clear warning
instead of invented certainty.

Uses the language model only for the WORDING (see llm_provider.py) -
in example mode (no key) a fixed template kicks in that shows
exactly the same facts, just less elegantly worded.
The decision itself (resolved/unresolved, urgency) comes
exclusively from Reconciler + ChallengeAgent, never from the Reporter.
"""

import re

from . import llm_provider
from .source_mapper import baseline_text


def _confidence_label(draft):
    if draft["resolved"]:
        return "high" if draft["revision_count"] == 0 else "medium-high"
    return "low - unresolved, human review required"


def _template_report(draft, claims):
    nvd = claims["nvd"]
    lines = [
        f"CVE: {draft['cve_id']}",
        f"NVD baseline: {baseline_text(nvd)}",
        f"Final assessment: {draft['final_severity']}",
        f"Confidence: {_confidence_label(draft)}",
        f"Revisions during review: {draft['revision_count']}",
        "",
        "Evidence path:",
        f"  - NVD: {nvd['raw_text'][:200]}",
        f"  - Vendor changelog: {draft['conflict']['vendor_position']}",
        f"  - Internal ticket: {draft['conflict']['internal_position']}",
        "",
    ]
    if draft["resolved"]:
        lines.append("Conclusion: the vendor's stated default is independently confirmed by "
                      "the internal ticket. Downgrade accepted.")
    else:
        lines.append("Conclusion: NOT resolved. The evidence does not show that the issue is fixed "
                      "or safe in this environment; the section 'What would resolve this' names what "
                      "is missing. Treat it as unresolved, and do not downgrade urgency, until a "
                      "person has verified it.")
    return "\n".join(lines)


_UNCONFIRMED_MARKERS = ("not confirmed", "unconfirmed", "no one has confirmed", "unknown", "not verified",
                        "unverified", "could not find", "not been checked", "unclear")
_REASSURING_MARKERS = ("unaffected", "not affected", "not vulnerable", "no risk", "is safe", "are safe",
                       "remain safe", "remains safe", "already protected", "fully protected")


def _reassures_about_unconfirmed(report_text):
    """Second fixed check after the AI wording: a sentence that calls something UNCONFIRMED and
    reassures in the same sentence ("... not confirmed for prod-cluster-1, which remain unaffected"). That is the
    dangerous kind of error - a false all-clear - and appeared in a real run (Log4Shell, Ollama) in
    a report the first check let through. Deliberately coarse: when in doubt the report falls back to the
    fixed template (harmless) instead of delivering a false all-clear. Returns the sentence or None."""
    for sentence in re.split(r"(?<=[.!?])\s+|\n+", report_text):
        low = sentence.lower()
        if any(m in low for m in _UNCONFIRMED_MARKERS) and any(m in low for m in _REASSURING_MARKERS):
            return sentence.strip()
    return None


def _report_is_coherent(report_text, resolved):
    """Independent, fixed check AFTER the AI wording - the same
    principle as in the SourceMapper: the AI may word things more nicely, but
    never contradict the actual decision. A real test run
    showed a small local model occasionally doing exactly that -
    e.g. writing 'Final Decision: Resolved: False' and two sentences
    later claiming 'it has been determined that the vulnerability is resolved'.
    Returns False when such a contradiction is found - the caller then falls back
    to the always-consistent fixed template instead of delivering a
    contradictory report."""
    if _reassures_about_unconfirmed(report_text):
        return False  # applies to 'resolved' AND 'unresolved'

    if resolved:
        return True  # for 'resolved' the risk of a false all-clear is lower,
                      # no extra check needed

    lowered = report_text.lower()
    false_all_clear_phrases = [
        "vulnerability is resolved", "has been resolved", "issue is resolved",
        "determined that the vulnerability is resolved", "confirmed to be resolved",
        "vulnerability has been fixed", "is now resolved",
    ]
    for phrase in false_all_clear_phrases:
        idx = lowered.find(phrase)
        if idx == -1:
            continue
        # a quick look at the 15 characters before - if there is a
        # negation there ("not", "un-"), it is not a contradiction
        # but correctly negated wording
        preceding = lowered[max(0, idx - 15):idx]
        if "not" not in preceding and "un" not in preceding:
            return False
    return True


def write_report(draft, claims, trace):
    system_prompt = (
        "You are a security report writer. You are given a FINAL, ALREADY-DECIDED "
        "vulnerability assessment (severity, resolved/unresolved, and the evidence from "
        "three sources). Write a short, clear report for a security analyst. Do not change "
        "the decision, the severity, or invent any evidence not given to you. If the case is "
        "unresolved, say so plainly and recommend manual verification - do not soften it. "
        "Never write a sentence that states or implies the vulnerability IS resolved when "
        "the decision says it is not - that is a direct contradiction and is not acceptable. "
        "Use ONLY facts stated in the evidence. Never say that anything is unaffected, safe, protected, "
        "patched or unpatched unless the evidence says exactly that; anything the evidence calls "
        "unconfirmed, unknown or not checked must be described as unconfirmed, never as safe. Under "
        "'Vendor evidence' report only what the vendor statement says, and under 'Internal evidence' "
        "only what the internal ticket says."
    )
    user_prompt = (
        f"CVE: {draft['cve_id']}\n"
        f"NVD baseline: {baseline_text(claims['nvd'])}\n"
        f"Final decision (already made, do not change): resolved={draft['resolved']}, "
        f"final_severity={draft['final_severity']}\n"
        f"Confidence: {_confidence_label(draft)}\n"
        f"Vendor evidence: {draft['conflict']['vendor_position']}\n"
        f"Internal evidence: {draft['conflict']['internal_position']}\n"
        f"Revisions during review: {draft['revision_count']}\n"
    )

    llm_text = llm_provider.complete(system_prompt, user_prompt)
    coherent = llm_text is not None and _report_is_coherent(llm_text, draft["resolved"])

    if llm_text is not None and not coherent:
        report_text = _template_report(draft, claims)
        used_llm, method = False, "llm-rejected-incoherent"
    elif llm_text is not None:
        report_text = llm_text
        used_llm, method = True, "llm"
    else:
        report_text = _template_report(draft, claims)
        used_llm, method = False, "sample-mode template"

    trace.log(
        agent="Reporter",
        action=f"write_report ({method})",
        input_summary=f"final decision for {draft['cve_id']}: resolved={draft['resolved']}",
        output_summary=report_text[:120].replace("\n", " ") + "...",
        target_agent=None,
        status="ok",
        confidence=_confidence_label(draft),
    )
    return report_text
