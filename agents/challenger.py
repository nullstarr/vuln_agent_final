"""
Agent 3: Challenge Agent.

Checks whether a downgrade by the Reconciler is actually carried by the
INTERNAL note, not only by the (usually more convenient)
vendor note. Two possible outcomes:

  - approve: the internal note is certain/complete AND supports the
    downgrade -> the case counts as resolved.
  - reject: the internal note is uncertain/incomplete OR contradicts
    -> back to the Reconciler, with a concrete instruction on what exactly
    is missing.

A case that already on the first attempt does not rest on vendor text (because
the vendor note itself already suggests "not certain") is confirmed
unresolved directly, without an unnecessary second round.

Fixed rules, no language model - that is exactly what makes the decision itself
traceable and checkable, not only the explanation afterwards.
"""

MAX_REVISIONS = 1


from .next_steps import _quoted, _sentence
from .reconciler import resolution_supported


def _doubt_snippet(ticket):
    """The sentence that CARRIES the doubt (not the start of the text): in a long, mostly positive ticket the
    reservation often sits only in the second sentence. Without a quotable spot (e.g. a language model's reason): the reason itself."""
    quote = _quoted(ticket["certainty_reason"])
    snippet = _sentence(ticket["raw_text"], quote) or quote
    if snippet:
        return f"'{snippet}'"
    return f"({ticket['certainty_reason'][:140]})"


def review(draft, claims, trace):
    ticket = claims["internal_ticket"]

    if not draft["resolved"]:
        # The Reconciler itself already proposed no downgrade (the
        # vendor note alone did not suggest "safe") - nothing
        # to refute, confirm as unresolved directly.
        trace.log(
            agent="ChallengeAgent", action="approve (nothing to challenge)",
            input_summary="Reconciler's first draft already did not claim resolution",
            output_summary="Confirmed unresolved - flag for human review",
            target_agent="Reporter", status="approved",
        )
        return {"approved": True, "critique": None}

    if draft["basis"] == "vendor_changelog_only":
        if ticket["certainty"] == "low":
            critique = (
                f"Resolution relies only on the vendor changelog. The internal ticket "
                f"is not certain: {_doubt_snippet(ticket)} - "
                f"it does not confirm the vendor's claim holds here. Re-run "
                f"incorporating the internal ticket; do not resolve on vendor text alone."
            )
            trace.log(
                agent="ChallengeAgent", action="reject (internal evidence insufficient)",
                input_summary=f"draft resolved=True on vendor text alone for {draft['cve_id']}",
                output_summary=critique,
                target_agent="Reconciler", status="rejected",
            )
            return {"approved": False, "critique": critique}

        supported, why = resolution_supported(claims["vendor_changelog"]["raw_text"], ticket)
        if not supported:
            critique = (
                f"Resolution relies on the vendor announcement, but {why} "
                f"('{ticket['raw_text'][:90]}...'). Re-run incorporating the internal ticket; "
                f"do not resolve on the vendor announcement alone."
            )
            trace.log(
                agent="ChallengeAgent", action="reject (fix not confirmed as deployed)",
                input_summary=f"draft resolved=True on vendor text for {draft['cve_id']}",
                output_summary=critique,
                target_agent="Reconciler", status="rejected",
            )
            return {"approved": False, "critique": critique}

        # The internal note is certain AND (by construction of our rules)
        # it actually supports the downgrade - approve directly, but
        # still cross-check once explicitly against the internal note,
        # so the trace shows THAT it was checked, not just
        # that the vendor text went unchallenged.
        from .reconciler import _downgrade_label
        draft["final_severity"] = _downgrade_label(claims["nvd"], f"downgraded ({why})")
        trace.log(
            agent="ChallengeAgent", action="approve (internal ticket independently confirms)",
            input_summary=f"internal ticket certainty=high, text: '{ticket['raw_text'][:90]}...'",
            output_summary="Vendor claim independently confirmed by internal evidence - resolved",
            target_agent="Reporter", status="approved",
        )
        return {"approved": True, "critique": None}

    # Second round (after revision): the Reconciler has already incorporated the
    # internal note. Whether resolved is True or False - the result now
    # really reflects both sources, so approve.
    trace.log(
        agent="ChallengeAgent", action="approve (revised draft reflects internal ticket)",
        input_summary=f"revised basis: {draft['basis']}",
        output_summary=f"Final: resolved={draft['resolved']}",
        target_agent="Reporter", status="approved",
    )
    return {"approved": True, "critique": None}
