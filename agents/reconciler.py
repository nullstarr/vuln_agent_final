"""
Agent 2: Reconciler.

First attempt (optimistic): relies ONLY on the vendor note,
because it usually gives the catchiest, most readable downgrade -
this is deliberately a too-simple first attempt, not a language-model
error, but built in so the Challenge Agent has something real to
check.

Revised attempt (after critique): brings in the internal ticket note
and may keep a downgrade ONLY when the internal
note actually carries it - otherwise the case stays open, with the
exact reservation from the internal note in the text.

Fixed rules, no language model.
"""


import re

from .source_mapper import baseline_text


def _downgrade_label(nvd, text):
    """'downgraded' is meaningless when there is no baseline rating at all (no NVD entry)."""
    if str(nvd.get("severity_claim", "")).startswith("UNKNOWN"):
        return "resolved on vendor + internal evidence (no baseline severity: no NVD score)"
    return text


def _vendor_suggests_safe(vendor_text):
    """Detects whether the vendor note suggests a downgrade. This
    list was deliberately extended after three additional test cases
    showed that the original, very short list recognized only the exact
    wordings of the first three examples, but not equally
    clearly reassuring statements worded differently - a real
    weakness of pure rule detection, not a language-model error."""
    lowered = vendor_text.lower()
    safe_phrases = [
        "disabled by default", "off by default", "not affected",
        "bound to 127.0.0.1", "removed from the codebase",
        "no remaining code path", "fully closed", "no exceptions",
        "no opt-outs", "completely removed",
        "closes the traversal vector entirely", "closes it entirely",
        # Added after the naive single-AI comparison (baseline_naive.py)
        # showed that CVE-2023-0005 was wrongly counted as unresolved by us,
        # even though the evidence (all 6 instances, all 40 attack patterns,
        # today, none got through) clearly argues for "resolved" - a real,
        # demonstrated error, not just a theoretical gap.
    ]
    return any(phrase in lowered for phrase in safe_phrases)


# "Vendor announces a fix" is the most common kind of vendor statement of all ("Fixed in 2.3.32",
# "Upgrade to 5.3.18"). The old list knew only downgrades like "disabled by default" - a system that
# can NEVER say "resolved" for an ordinary update notice, even when everything is internally confirmed
# (found by a test with the Equifax/Struts case, see README).
_FIX_CLAIM = re.compile(
    r"\b(?:fix(?:ed|es)?|patch(?:ed|es)?|resolved|addressed|remediated)\s+in\s+(?:[\w.-]+\s+){0,3}?v?\d+\.\d+"
    r"|\b(?:upgrade|update)\s+to\s+(?:[\w.-]+\s+){0,3}?v?\d+\.\d+"
    r"|\bfixed version\b|\bfix(?:es)?\s+(?:is|are)\s+(?:available|included|shipped)\b|\bare available and fix\b",
    re.I)
# Evidence that the fix RUNS AT OUR SITE (not just that it exists): a version in the context of
# "upgraded / running / deployed ..." or "2.5.16 or later".
_DEPLOYED = re.compile(
    r"\b(?:upgraded|updated|patched|runs?|running|deployed|rolled out|installed|on version|at version)\b[^.]{0,80}?\d+\.\d+"
    r"|\b\d+\.\d+(?:\.\d+)?[^.]{0,40}\b(?:or later|or newer|and above)\b", re.I)


def _vendor_claims_fix(vendor_text):
    return bool(_FIX_CLAIM.search(vendor_text))


# --- Version check (feedback from a vulnerability manager): "any version number next to
# 'running/installed'" used to be enough as evidence. That wrongly said "resolved" for four typical ticket texts.
# Now: fixed version from the vendor text, running versions from the ticket, comparison, plus hedges and scope.
_VER = re.compile(r"\bv?(\d+(?:\.\d+){1,3})\b(?!\.[xX*])")
_FIXED_VER = re.compile(
    r"\b(?:fix(?:ed|es)?|patch(?:ed|es)?|resolved|addressed|remediated)\s+in\s+(?:[\w.-]+\s+){0,3}?v?(\d+(?:\.\d+){1,3})"
    r"|\b(?:upgrade|update)\s+to\s+(?:[\w.-]+\s+){0,3}?v?(\d+(?:\.\d+){1,3})", re.I)
_PENDING = re.compile(r"\b(pending|awaiting|planned|scheduled|not yet|to be (?:upgraded|patched|deployed)|will be|approval|todo|tbd|waiting|queued|postponed)\b", re.I)
_NON_PROD = re.compile(r"\b(test|testing|staging|stage|dev|development|sandbox|lab|qa|non-?prod\w*)\b", re.I)
_PROD_OR_ALL = re.compile(r"(?<!non-)(?<!non)\bprod(?:uction)?\b", re.I)   # only "prod" counts; "all hosts in staging" does not
_SCOPE_ALL = re.compile(r"\b(all|every|each|entire|whole|fleet|\d+\s+of\s+\d+|\d+\s+(?:hosts?|servers?|systems?|applications?|apps?|clusters?|nodes?|machines?|services?))\b", re.I)
_SINGLE_HOST = re.compile(r"\b(?:[a-z]{2,}[-_]?\d{1,3}|one (?:host|server|system|node|machine)|a single (?:host|server|system))\b", re.I)
# Exceptions and missing checks in the ticket (second-round feedback: "the legacy box was left out", "except the two SAP
# appliances", "no one verified it on the hosts"). Deliberately ONLY in the fix path (deployment_check), not in the shared uncertainty rules
# of source_mapper.py: those are developed on the dev half of the text collection, and the test half must stay untouched.
_NO_EXCEPTIONS = re.compile(r"\bno (?:exceptions?|exclusions?|systems? (?:left out|excluded|skipped))\b", re.I)
_EXCLUSION = re.compile(r"\b(?:left out|except(?:ion|ions|ed)?\b|excluding|excluded|exempt\w*|omitted|not included|not covered|skipped|out of scope|apart from|other than|but not)\b", re.I)
_UNVERIFIED = re.compile(r"\b(?:no ?one|nobody|none of us|we have not|we haven't|has not been|hasn't been|not been|not yet|not|never|unable to)\s+(?:\w+\s+){0,2}?(?:verified|checked|confirmed|tested|validated)\b|\bunverified\b|\bnot (?:verified|checked|confirmed|tested|validated)\b", re.I)
# Third round of feedback: forever listing new warning words does not catch the next wording. Reverse the burden of proof:
# "resolved" needs a POSITIVE proof - a named verification method (scan, rescan, verified, confirmed by ...), plus version and scope.
_VERIFICATION = re.compile(r"\b(?:re-?scan\w*|scan(?:s|ned)?|scanner|verified|verification|confirmed|re-?tested|tested|inventory|audit(?:ed)?|"
                           r"checked (?:with|via|using|by)|compliance (?:check|report)|sbom|package list|config(?:uration)? management)\b", re.I)
# Negated exceptions/findings are NOT doubt: "no host was skipped", "nothing other than log4j was changed", "could not find 2.14 anywhere".
_NEGATED_EXCEPTION = re.compile(r"\bno\s+(?:\w+\s+){0,3}?(?:was|were|is|are|has been|have been)?\s*(?:skipped|left out|excluded|omitted|exempt\w*)\b"
                                r"|\bnothing\s+(?:other than|except|but)\b|\bnone\s+(?:were|was)\s+(?:skipped|left out|excluded|omitted)\b", re.I)
_ABSENT_OLD = re.compile(r"\b(?:could ?n[o']?t find|can(?:no|')t find|not found|no longer|nowhere|no trace|none (?:left|remain\w*)|removed|gone)\b", re.I)
_OLD_CONTEXT = re.compile(r"\b(from|previous(?:ly)?|before|formerly|used to|was running|was on|old version|prior)\b", re.I)


def _vtuple(v):
    return tuple(int(x) for x in v.split("."))


def _cmp(a, b):
    """-1/0/1; missing places count as 0 (2.17 == 2.17.0)."""
    ta, tb = _vtuple(a), _vtuple(b)
    n = max(len(ta), len(tb))
    ta, tb = ta + (0,) * (n - len(ta)), tb + (0,) * (n - len(tb))
    return (ta > tb) - (ta < tb)


def is_fixed(version, fixed_list):
    """Is 'version' fixed? Same branch (major.minor) as a fixed version: at least that one. Other branch:
    only if newer than every fixed branch (an older branch without a fix, e.g. 2.14 with fix 2.17.1, is not fixed)."""
    vt = _vtuple(version)[:2]
    same = [f for f in fixed_list if _vtuple(f)[:2] == vt]
    if same:
        return any(_cmp(version, f) >= 0 for f in same)
    return all(vt > _vtuple(f)[:2] for f in fixed_list)


def fixed_versions(vendor_text):
    """All versions named as 'fixed'. For 'fixed in / upgrade to' from the match onward (so further branches like
    '... or 5.2.20' count too, but not the affected versions named before); for 'X and Y are available and fix this' all in the sentence."""
    out = []
    for sent in re.split(r"(?<=[.;!?])\s+|\n", vendor_text or ""):
        m = _FIXED_VER.search(sent)
        if m:
            out += _VER.findall(sent[m.start():])
        elif _FIX_CLAIM.search(sent):
            out += _VER.findall(sent)
    return list(dict.fromkeys(out))


def deployment_check(ticket_text, vendor_text=""):
    """(ok, reason). ok only when the ticket shows the fixed version (or newer) is running - not just any number."""
    if not _DEPLOYED.search(ticket_text):
        return False, "the ticket names no deployed version"
    if _PENDING.search(ticket_text):
        return False, "the ticket says the upgrade is still pending or waiting for approval"
    cleaned = _NEGATED_EXCEPTION.sub("", _NO_EXCEPTIONS.sub("", ticket_text))
    m = _EXCLUSION.search(cleaned)
    if m:
        return False, f"the ticket names an exclusion or exception ('{m.group(0)}')"
    m = _UNVERIFIED.search(cleaned)
    if m:
        return False, f"the ticket says something was not verified ('{m.group(0)}')"
    fixed = fixed_versions(vendor_text)
    target = ", ".join(fixed) if fixed else None
    if not _VERIFICATION.search(ticket_text):
        return False, "the ticket names no verification method (scan, rescan, verified, confirmed by ...); a claim without proof does not count"
    sentences = [s for s in re.split(r"(?<=[.;!?])\s+|\n", ticket_text) if s.strip()]
    good = False
    for s in sentences:
        vers = _VER.findall(s)
        if not vers:
            continue
        deploy = bool(_DEPLOYED.search(s))
        if target:
            old = [v for v in vers if not is_fixed(v, fixed)]
            if old and not _ABSENT_OLD.search(s) and not (_OLD_CONTEXT.search(s) and len(old) < len(vers)):
                return False, f"the ticket mentions version {old[0]}, not covered by the fixed version(s) {target}, as still present"
            ok_vers = [v for v in vers if is_fixed(v, fixed)]
        else:
            ok_vers = vers
        if deploy and ok_vers:
            if _NON_PROD.search(s) and not _PROD_OR_ALL.search(s):
                continue                                    # test/staging only: does not count
            if _SINGLE_HOST.search(s) and not _SCOPE_ALL.search(s):
                continue                                    # a single host, no scope named
            good = True
    if not good:
        return False, "no sentence shows the fixed version running in production with a stated scope"
    return True, "ok"


def _internal_confirms_deployment(ticket_text, vendor_text=""):
    return deployment_check(ticket_text, vendor_text)[0]


def resolution_supported(vendor_text, ticket):
    """Does the evidence carry a 'resolved'? Returns (yes/no, kind). Shared by Reconciler
    (revision) and ChallengeAgent (review), so both apply the same rule."""
    if ticket["certainty"] != "high":
        return False, "internal ticket is not certain"
    if _vendor_suggests_safe(vendor_text):
        return True, "vendor default confirmed by internal check"
    if _vendor_claims_fix(vendor_text):
        ok, why = deployment_check(ticket["raw_text"], vendor_text)
        if ok:
            return True, "vendor fix confirmed deployed by internal check"
        return False, f"vendor announces a fix, but the internal ticket does not confirm it is deployed ({why})"
    return False, "vendor makes no safe-by-default or fix claim"


def build_draft(cve_id, claims, trace):
    """First, optimistic attempt - only the vendor note counts."""
    nvd, vendor, ticket = claims["nvd"], claims["vendor_changelog"], claims["internal_ticket"]
    vendor_safe = _vendor_suggests_safe(vendor["raw_text"]) or _vendor_claims_fix(vendor["raw_text"])
    first_label = ("downgraded (per vendor default)" if _vendor_suggests_safe(vendor["raw_text"])
                   else "downgraded (per vendor fix announcement)")

    draft = {
        "cve_id": cve_id,
        "resolved": vendor_safe,
        "final_severity": (_downgrade_label(nvd, first_label) if vendor_safe
                           else nvd["severity_claim"]),
        "basis": "vendor_changelog_only",
        "conflict": {
            "field": "actual_exposure_in_our_environment",
            "nvd_position": baseline_text(nvd),
            "vendor_position": vendor["raw_text"],
            "internal_position": ticket["raw_text"],
        },
        "revision_count": 0,
    }
    trace.log(
        agent="Reconciler", action="build_draft (vendor-only, optimistic)",
        input_summary=f"vendor claim for {cve_id}: '{vendor['raw_text'][:70]}...'",
        output_summary=f"resolved={draft['resolved']}, severity={draft['final_severity']}",
        target_agent="ChallengeAgent", status="ok",
    )
    return draft


def revise_draft(draft, claims, critique, trace):
    """Revision after critique - now the internal note counts too."""
    nvd, ticket = claims["nvd"], claims["internal_ticket"]
    internal_confirms_safe, why = resolution_supported(claims["vendor_changelog"]["raw_text"], ticket)

    draft["resolved"] = internal_confirms_safe
    draft["final_severity"] = (
        _downgrade_label(nvd, f"downgraded ({why})") if internal_confirms_safe
        else f"{nvd['severity_claim']} - NOT downgraded, internal evidence insufficient"
    )
    draft["basis"] = "vendor_changelog + internal_ticket"
    draft["revision_count"] += 1

    trace.log(
        agent="Reconciler", action="revise_draft (incorporating internal ticket)",
        input_summary=f"critique received: {critique}",
        output_summary=f"resolved={draft['resolved']}, severity={draft['final_severity']}",
        target_agent="ChallengeAgent", status="ok", retries=draft["revision_count"],
    )
    return draft
