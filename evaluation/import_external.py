#!/usr/bin/env python3
"""
Reads the helpers' example sentences (evaluation/external/inbox/*.txt) and builds evaluation/external.jsonl from them,
in the same format as corpus.jsonl - the evaluation then runs with the existing tool:

  python3 evaluation/import_external.py
  python3 evaluation/evaluate.py --corpus evaluation/external.jsonl --split test --methods rules,llm,combined

Line format in the files:  H | sentence   (author says: confirmed without doubt)   or   L | sentence   (author says: doubt/gap)
The label is set by the HELPER, not us - that makes the number independent. File name = helper (count only, no names in the result).

Ground rules (fixed BEFORE the first result, see below):
  - NOTHING is tuned on this set (no rule, no prompt). What comes out is reported - even if it is bad.
  - Sentences that are already verbatim in our own corpus are skipped (and counted).
  - Everything is marked "test"; categories are named external_high / external_low.
"""

import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
INBOX = os.path.join(HERE, "external", "inbox")
OUT = os.path.join(HERE, "external.jsonl")
CORPUS = os.path.join(HERE, "corpus.jsonl")
LINE = re.compile(r"^\s*([HhLl])\s*\|\s*(.+?)\s*$")
MIN_LEN, MAX_LEN = 25, 400


def norm(t):
    return " ".join(t.lower().split())


def main():
    if not os.path.isdir(INBOX):
        sys.exit(f"Folder missing: {INBOX}")
    files = sorted(f for f in os.listdir(INBOX) if f.endswith(".txt"))
    if not files:
        sys.exit(f"No .txt files in {INBOX} - put the helpers' files in there.")
    own = set()
    if os.path.exists(CORPUS):
        own = {norm(json.loads(l)["text"]) for l in open(CORPUS) if l.strip()}

    rows, seen = [], set()
    skipped = {"format": 0, "short_long": 0, "duplicate": 0, "in_own_corpus": 0}
    per_helper = {}
    for fi, fn in enumerate(files, 1):
        for ln, line in enumerate(open(os.path.join(INBOX, fn), encoding="utf-8"), 1):
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            if re.match(r"^\s*\?\s*\|", line):
                skipped["unlabeled"] = skipped.get("unlabeled", 0) + 1
                continue
            m = LINE.match(line)
            if not m:
                skipped["format"] += 1
                print(f"  skipped (format, {fn}:{ln}): {line.strip()[:60]}")
                continue
            label, text = ("high" if m.group(1).upper() == "H" else "low"), m.group(2)
            if not MIN_LEN <= len(text) <= MAX_LEN:
                skipped["short_long"] += 1
                continue
            key = norm(text)
            if key in seen:
                skipped["duplicate"] += 1
                continue
            if key in own:
                skipped["in_own_corpus"] += 1
                continue
            seen.add(key)
            per_helper[fi] = per_helper.get(fi, 0) + 1
            rows.append({"id": f"external-h{fi}-{len(rows):04d}", "split": "test", "category": f"external_{label}",
                         "label": label, "source_type": "vendor_changelog", "template_index": fi, "text": text})

    with open(OUT, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    hi = sum(1 for r in rows if r["label"] == "high")
    print(f"{len(rows)} sentences from {len(per_helper)} helper(s) -> {OUT}  (high: {hi}, low: {len(rows) - hi})")
    print("skipped:", ", ".join(f"{k}={v}" for k, v in skipped.items() if v) or "nothing")
    if len(rows) < 30:
        print("Note: under 30 sentences the percentages are very rough - read as a sample, not a measurement.")


if __name__ == "__main__":
    main()
