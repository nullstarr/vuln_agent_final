"""
Structured trace for agent actions.

Format exactly per the spec in the mentor guide: agent name, action,
input summary, output summary, target agent, status, confidence value,
retries, timestamp. Writes to stdout AND to logs/<case_id>.jsonl,
so a reviewer can both watch live and check the file after the run.

Every entry reflects a REAL call - nothing here is written
by hand afterwards; the module is called directly from each agent
while it runs.
"""

import json
import os
import sys
import time
from datetime import datetime, timezone


def write_text(path, text, mode="w"):
    """Writes a file. If it exists but belongs to someone else (typically: an earlier
    Docker run created it as root), it is deleted and recreated - which is allowed for whoever owns the
    FOLDER. If that fails too, there is a warning instead of a crash (the output file
    is incidental, the analysis itself is not). Returns True/False."""
    try:
        with open(path, mode) as f:
            f.write(text)
        return True
    except PermissionError as first:
        try:
            os.remove(path)
            with open(path, mode) as f:
                f.write(text)
            return True
        except OSError:
            print(f"WARNING: cannot write {path} ({first.strerror}) - skipped. "
                  f"Usually created by Docker as root; fix with: sudo chown -R $USER logs",
                  file=sys.stderr)
            return False
    except OSError as e:
        print(f"WARNING: cannot write {path} ({e.strerror}) - skipped.", file=sys.stderr)
        return False


class TraceLogger:
    def __init__(self, case_id, log_dir="logs"):
        self.case_id = case_id
        os.makedirs(log_dir, exist_ok=True)
        self.path = os.path.join(log_dir, f"{case_id}.jsonl")
        # A new run overwrites the old trace file for this case,
        # so the file always shows exactly the last run.
        write_text(self.path, "")

    def log(self, agent, action, input_summary, output_summary,
            target_agent=None, status="ok", confidence=None, retries=0):
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "case_id": self.case_id,
            "agent": agent,
            "action": action,
            "input_summary": input_summary,
            "output_summary": output_summary,
            "target_agent": target_agent,
            "status": status,
            "confidence": confidence,
            "retries": retries,
        }
        line = json.dumps(entry, ensure_ascii=False)
        print(f"[{entry['timestamp']}] {agent:>16} | {action:<22} -> {target_agent or '-':<16} "
              f"| status={status} conf={confidence} retries={retries}")
        print(f"    in:  {input_summary}")
        print(f"    out: {output_summary}")
        write_text(self.path, line + "\n", mode="a")
        return entry

    def read_all(self):
        if not os.path.exists(self.path):
            return []
        with open(self.path) as f:
            return [json.loads(line) for line in f if line.strip()]
