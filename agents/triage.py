"""
Ranking "Which case do you start with?" - the question an analyst really has across many cases.

Deliberately simple and explainable (no weightings, no AI): almost every vulnerability is eventually
"fixed somewhere" - urgent is what is NOT resolved AND weighs heavily. Order:

  Tier 1  unresolved and CRITICAL/HIGH (or severity unknown: treated as HIGH to be safe),
          OR unresolved and known to be exploited (exploitation signal, agents/exploitation.py) - regardless of severity
  Tier 2  unresolved, but MEDIUM/LOW
  Tier 3  resolved (internally confirmed)

Within a tier: known-exploited cases first, then severity, then CVSS score, then number of open steps, then CVE number
(so the order is always the same). Each line names the reason in one sentence.
"""

from .reporter import _confidence_label
from .exploitation import signal as exploit_signal

SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
TIER_LABEL = {1: "act first", 2: "next", 3: "resolved"}


def baseline_word(nvd_claim):
    """CRITICAL/HIGH/MEDIUM/LOW or UNKNOWN - even if the NVD entry has no rating."""
    text = str(nvd_claim.get("severity_claim", "UNKNOWN")).upper()
    for word in SEVERITY_RANK:
        if text.startswith(word):
            return word
    return "UNKNOWN"


def build_result(case, claims, draft, steps, provider, blockers=()):
    """The structured result of ONE case (in addition to the report text) - basis for ranking and viewer."""
    nvd = claims["nvd"]
    return {
        "cve_id": case["cve_id"],
        "nickname": case.get("nickname", ""),
        "baseline_severity": baseline_word(nvd),
        "cvss": nvd.get("cvss_v3_score"),
        "final_severity": draft["final_severity"],
        "resolved": bool(draft["resolved"]),
        "confidence": _confidence_label(draft),
        "revisions": draft["revision_count"],
        "certainty": {k: c["certainty"] for k, c in claims.items()},
        "exploited_in_wild": exploit_signal(case)[0],      # True / False / None (= no signal recorded, i.e. UNKNOWN)
        "next_steps": list(steps),
        "blockers": [{"source": src, "kind": kind} for src, kind, _ in blockers],
        "mode": provider,
    }


def _tier(result):
    if result["resolved"]:
        return 3
    if result.get("exploited_in_wild") is True:
        return 1                                                                # exploited and unresolved: first
    return 1 if SEVERITY_RANK.get(result["baseline_severity"], 3) >= 3 else 2   # unknown -> treated as HIGH


def _why(result, tier):
    if tier == 3:
        return "resolved: vendor claim and internal evidence agree" + (" (known to be exploited: confirm the fix is deployed)" if result.get("exploited_in_wild") else "")
    sev = result["baseline_severity"]
    head = sev if sev != "UNKNOWN" else "severity unknown"
    if result.get("exploited_in_wild") is True:
        head += ", EXPLOITED"
    blockers = result.get("blockers") or []
    if not blockers:
        return f"{head}, unresolved: evidence is insufficient"
    return f"{head}, unresolved: " + "; ".join(f"{b['source']} - {b['kind']}" for b in blockers[:2])


def rank(results):
    """Sorted list, most important case first."""
    def key(r):
        return (_tier(r), 0 if r.get("exploited_in_wild") is True else 1, -SEVERITY_RANK.get(r["baseline_severity"], 3), -(r["cvss"] or 0.0),
                -len(r["next_steps"]), r["cve_id"])

    ranked = []
    for i, r in enumerate(sorted(results, key=key), 1):
        tier = _tier(r)
        ranked.append({
            "rank": i, "tier": tier, "tier_label": TIER_LABEL[tier], "cve_id": r["cve_id"],
            "nickname": r["nickname"], "baseline_severity": r["baseline_severity"], "cvss": r["cvss"],
            "decision": "resolved" if r["resolved"] else "unresolved", "confidence": r["confidence"],
            "open_steps": len(r["next_steps"]), "exploited_in_wild": r.get("exploited_in_wild"), "why": _why(r, tier),
        })
    return ranked


def format_table(ranked, width=110):
    lines = ["", "TRIAGE - most urgent first", f"{'#':>2}  {'CVE':<15} {'baseline':<9} {'decision':<11} why", "-" * width]
    for r in ranked:
        why = r["why"]
        lines.append(f"{r['rank']:>2}  {r['cve_id']:<15} {r['baseline_severity']:<9} {r['decision']:<11} {why}")
    return "\n".join(lines)
