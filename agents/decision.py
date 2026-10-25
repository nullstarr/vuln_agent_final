"""
The decision loop (Reconciler <-> ChallengeAgent), in ONE place - used by main.py (one case)
and by agents/timeline.py (the same case across several days), so both are guaranteed to apply the same logic.
"""

from .challenger import MAX_REVISIONS, review
from .reconciler import build_draft, revise_draft


class NullTrace:
    """Trace substitute when only the result matters (e.g. when computing a timeline)."""
    path = None

    def log(self, **kwargs):
        return None


def decide(cve_id, claims, trace):
    """Optimistic draft -> review -> revise if needed. Returns the finished draft."""
    draft = build_draft(cve_id, claims, trace)
    revisions = 0
    while revisions <= MAX_REVISIONS:
        result = review(draft, claims, trace)
        if result["approved"]:
            break
        draft = revise_draft(draft, claims, result["critique"], trace)
        revisions += 1
    # Safety net: if MAX_REVISIONS is exceeded, the last draft stands (no infinite loop).
    return draft
