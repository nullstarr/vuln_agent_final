"""
"What would resolve this case?" - concrete, verifiable next steps for an UNRESOLVED case.

Purely rule-based (no language model): the steps come from the reasons the checks already recorded
(certainty_reason, e.g. "partial coverage ('2 of our 15')"). Nothing can be invented here,
and the report answers not only "why not resolved", but also "what is still missing".

Order by weight: first the INTERNAL source (it has the last word), then the vendor, then NVD.
Each step has a short keyword ("kind") that the ranking (triage.py) uses as its reason.
"""

import re

from .reconciler import deployment_check, _internal_confirms_deployment, _vendor_claims_fix, _vendor_suggests_safe

_QUOTE = re.compile(r"\('([^']+)'\)")


def _quoted(reason):
    m = _QUOTE.search(reason or "")
    return m.group(1) if m else None


def _sentence(text, fragment):
    """The whole sentence the match sits in - a fragment like 'scheduled for' alone tells the reader nothing."""
    if not fragment:
        return None
    for sent in re.split(r"(?<=[.!?])\s+", text):
        if fragment.lower() in sent.lower():
            sent = sent.strip()
            if len(sent) <= 130:
                return sent
            # long sentence: trim around the match so the supporting wording stays visible
            at = sent.lower().find(fragment.lower())
            start, end = max(0, at - 55), min(len(sent), at + len(fragment) + 55)
            return ("..." if start > 0 else "") + sent[start:end].strip() + ("..." if end < len(sent) else "")
    return None


def _step_for_low(label, claim):
    """(keyword, text) for a source rated uncertain - matching the KIND of the reservation."""
    reason, method = claim["certainty_reason"], claim["certainty_method"]
    q = _quoted(reason)
    q = _sentence(claim["raw_text"], q) or q
    if "partial coverage" in reason:
        return "only partly confirmed", f"{label}: only part was confirmed ('{q}'). Check the rest directly and record the result."
    if "pending/scheduled" in reason:
        return "work still pending", f"{label}: work is still pending ('{q}'). Complete it, re-verify, and update the record."
    if "stale" in reason:
        return "check too old", f"{label}: the check on record is too old ('{q}'). Re-run it now."
    if "inference" in reason:
        return "rests on an assumption", f"{label}: this rests on an assumption ('{q}'). Replace it with a direct check."
    if "exception clause" in reason:
        return "carries an exception", f"{label}: it carries an exception ('{q}'). Confirm the exception does not apply to our systems."
    if "named gap" in reason:
        return "something left out", f"{label}: something was left out ('{q}'). Bring it into scope, or document why it is not exposed."
    if "scope-overclaim" in reason:
        return "claim broader than backed", f"{label}: the claim is broader than what is backed. Verify the part of the environment it does not cover."
    if "keyword" in method:
        said = f" ('{q}')" if q else ""
        return "unconfirmed item", f"{label}: the text itself says something is unconfirmed{said}. Verify that item directly."
    return "doubt flagged", f"{label}: the assessment flagged doubt ({reason[:140]}). Resolve it and record the evidence."


def blockers(claims, draft):
    """List of (source, keyword, text), most important first; empty for a resolved case."""
    if draft["resolved"]:
        return []
    nvd, vendor, ticket = claims["nvd"], claims["vendor_changelog"], claims["internal_ticket"]
    out = []

    # 1. internal - has the last word
    if ticket["certainty_method"] == "absent-source":
        out.append(("internal", "no check recorded",
                    "Internal: nobody has recorded a check. Verify the affected systems directly and record the result."))
    elif ticket["certainty"] == "low":
        kind, text = _step_for_low("Internal", ticket)
        out.append(("internal", kind, text))
    elif _vendor_claims_fix(vendor["raw_text"]) and not _vendor_suggests_safe(vendor["raw_text"]) \
            and not _internal_confirms_deployment(ticket["raw_text"], vendor["raw_text"]):
        why = deployment_check(ticket["raw_text"], vendor["raw_text"])[1]
        out.append(("internal", "fix not shown deployed",
                    f"Internal: the vendor announces a fix, but the ticket does not show it deployed ({why}). "
                    "State the deployed version on every affected system, and which systems that covers."))

    # 2. vendor
    if vendor["certainty_method"] == "absent-source":
        out.append(("vendor", "no vendor statement",
                    "Vendor: no statement exists. Ask the vendor for one, or document an independent mitigation."))
    elif vendor["certainty"] == "low" and "scope-overclaim" in vendor["certainty_reason"]:
        kind, text = _step_for_low("Vendor", vendor)            # the real reason: the statement covers less than it claims
        out.append(("vendor", kind, text))
    elif not (_vendor_suggests_safe(vendor["raw_text"]) or _vendor_claims_fix(vendor["raw_text"])):
        if re.search(r"\bfix", vendor["raw_text"], re.I):
            out.append(("vendor", "no fix or safe-by-default claim",
                        "Vendor: the text mentions fixes, but not in a wording the rules recognise as a fix announcement (no 'fixed in <version>' or "
                        "'upgrade to <version>'). A person should read it: if it is a fix announcement, record the fixed version and the deployed version."))
        else:
            out.append(("vendor", "no fix or safe-by-default claim",
                        "Vendor: the statement neither announces a fix nor says the issue is safe by default. Obtain one that does."))
    elif vendor["certainty"] == "low":
        kind, text = _step_for_low("Vendor", vendor)
        out.append(("vendor", kind, text))

    # 3. NVD
    if nvd["certainty_method"] == "absent-source":
        out.append(("nvd", "no public entry yet",
                    "NVD: no public database entry exists yet. Re-check once one is published (the baseline severity is unknown)."))
    return out


def what_would_resolve(claims, draft):
    """Only the texts (for the report)."""
    return [text for _, _, text in blockers(claims, draft)]


def format_steps(steps):
    if not steps:
        return ""
    return "\n\n--- WHAT WOULD RESOLVE THIS ---\n" + "\n".join(f"{i}. {s}" for i, s in enumerate(steps, 1))
