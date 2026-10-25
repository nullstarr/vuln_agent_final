"""
Observes, across MANY cases, how often a particular kind of source is
completely missing (see source_mapper.py's absent-source handling). A
single missing internal note is chance. If the same kind of source is missing
across many cases in a row, that is a structural process problem at
the company itself - "you apparently have no general process to check your
own environment", not just "this one case has not been checked yet". That
is a different statement and deserves a different, separate
warning, apart from the single case report.

Deliberately ONE small module of its own, not mixed into source_mapper.py
- the question "how is this one case" and "how is
our process overall" are two different questions with
two different time horizons (one case vs. many cases).
"""

import json
import os
from datetime import datetime, timezone

HISTORY_PATH = "logs/source_availability_history.json"
MIN_CASES_FOR_SIGNAL = 3   # below this case count a rate says nothing yet
ABSENCE_RATE_THRESHOLD = 0.5
ROLLING_WINDOW = 20        # only the last N cases count; old incidents
                           # should not linger forever if the
                           # company's process has improved since


def _load_history():
    """Reads the history. If the file is missing, broken or has a foreign structure
    (e.g. an object instead of a list), the history starts empty - the analysis itself
    must never fail because of it."""
    if not os.path.exists(HISTORY_PATH):
        return []
    try:
        data = json.load(open(HISTORY_PATH))
    except (json.JSONDecodeError, OSError):
        return []
    if not isinstance(data, list):
        return []
    return [e for e in data if isinstance(e, dict) and isinstance(e.get("availability"), dict)]


def _save_history(history):
    os.makedirs(os.path.dirname(HISTORY_PATH), exist_ok=True)
    from .trace import write_text
    write_text(HISTORY_PATH, json.dumps(history, indent=2))


def record_availability(cve_id, claims, required_keys=("nvd", "vendor_changelog", "internal_ticket")):
    """Call after EVERY case - writes an entry recording which of the three
    kinds of source were really present this time (certainty_method !=
    'absent-source') or missing."""
    history = _load_history()
    entry = {
        "cve_id": cve_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "availability": {
            key: claims.get(key, {}).get("certainty_method") != "absent-source"
            for key in required_keys
        },
    }
    history.append(entry)
    _save_history(history)
    return entry


def check_process_health(required_keys=("nvd", "vendor_changelog", "internal_ticket")):
    """Looks ONLY at the past (the rolling window), not at
    the current case. Returns a list of warnings, one
    per kind of source that was missing too often - empty when (as yet) nothing
    is remarkable or too few cases exist to judge it."""
    history = _load_history()
    if len(history) < MIN_CASES_FOR_SIGNAL:
        return []

    recent = history[-ROLLING_WINDOW:]
    total = len(recent)
    warnings = []
    for key in required_keys:
        absent = sum(1 for e in recent if not e["availability"].get(key, True))
        rate = absent / total
        if rate >= ABSENCE_RATE_THRESHOLD:
            warnings.append(
                f"PROCESS SIGNAL: '{key}' evidence was missing in {absent} of the last "
                f"{total} cases this tool processed ({100*rate:.0f}%). This looks like a "
                f"structural gap in how your organization gathers this kind of evidence, "
                f"not just an isolated gap for this one case."
            )
    return warnings
