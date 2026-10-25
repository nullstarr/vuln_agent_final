#!/usr/bin/env python3
"""
Measures how well the "certain (high) / uncertain (low)" assessment works across many texts.

Methods
  keyword    only the word list
  rules      all fixed rules together (= the example mode without AI)
  llm        only the language model (needs LLM_PROVIDER, e.g. ollama)
  combined   what the product really does: rules + language model, the most cautious wins

Two error types (low = "needs caution"):
  MISSED       text is low, but rated high   -> the DANGEROUS error
  FALSE ALARM  text is high, but rated low    -> only overcautious

Usage
  python3 evaluation/evaluate.py                          # rules only, immediately
  python3 evaluation/evaluate.py --methods keyword,rules
  set -a; source .env; set +a                              # for the language model
  python3 evaluation/evaluate.py --methods llm,combined    # ~ as many calls as texts
  python3 evaluation/evaluate.py --show-errors dev         # show errors of the development half

Errors of the "test" half are deliberately not shown: nothing is tuned on them.
"""

import argparse
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from agents import source_mapper as sm  # noqa: E402


def load_corpus(path):
    if not os.path.exists(path):
        sys.exit(f"{path} missing - first: python3 evaluation/make_corpus.py")
    return [json.loads(line) for line in open(path) if line.strip()]


def make_predictors(llm_cache):
    def cached_llm(source_name, text, source_type=None):
        key = (source_name, text, source_type)
        if key not in llm_cache:
            llm_cache[key] = sm_original_llm(source_name, text, source_type=source_type)
        return llm_cache[key]

    sm_original_llm = sm._certainty_via_llm
    sm._certainty_via_llm = cached_llm  # assess_certainty uses this name -> same answers for llm and combined

    def keyword(r):
        return sm._certainty_from_keywords(r["text"])[0]

    def rules(r):
        return sm.assess_certainty("evaluation", r["text"], r["source_type"], use_llm=False)[0]

    def llm(r):
        res = cached_llm("evaluation", r["text"], r["source_type"])
        return None if res is None else res[0]

    def combined(r):
        return sm.assess_certainty("evaluation", r["text"], r["source_type"], use_llm=True)[0]

    return {"keyword": keyword, "rules": rules, "llm": llm, "combined": combined}


def pct(a, b):
    return "  -  " if b == 0 else f"{100 * a / b:5.1f}%"


def summarize(rows, preds):
    """preds: list of 'high'/'low'. Returns: metrics."""
    n = len(rows)
    low = [(r, p) for r, p in zip(rows, preds) if r["label"] == "low"]
    high = [(r, p) for r, p in zip(rows, preds) if r["label"] == "high"]
    missed = sum(1 for r, p in low if p == "high")
    false_alarm = sum(1 for r, p in high if p == "low")
    correct = n - missed - false_alarm
    return dict(n=n, correct=correct, n_low=len(low), missed=missed, n_high=len(high), false_alarm=false_alarm)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--corpus", default=os.path.join(HERE, "corpus.jsonl"))
    ap.add_argument("--methods", default="keyword,rules")
    ap.add_argument("--split", choices=["dev", "test", "all"], default="all")
    ap.add_argument("--limit", type=int, default=None, help="only the first N texts (for quickly trying the model)")
    ap.add_argument("--show-errors", choices=["dev"], default=None, help="list the errors of the development half")
    ap.add_argument("--save", default=None, help="save the result as JSON")
    a = ap.parse_args()
    print(f"[prompt] CERTAINTY_PROMPT={os.environ.get('CERTAINTY_PROMPT', 'v2')} (applies only to the methods llm and combined)")

    rows = load_corpus(a.corpus)
    if a.split != "all":
        rows = [r for r in rows if r["split"] == a.split]
    if a.limit:
        rows = rows[: a.limit]

    llm_cache = {}
    predictors = make_predictors(llm_cache)
    methods = [m.strip() for m in a.methods.split(",") if m.strip()]
    unknown = [m for m in methods if m not in predictors]
    if unknown:
        sys.exit(f"Unknown method(s): {unknown}. Possible: {', '.join(predictors)}")

    results, saved = {}, {}
    for m in methods:
        t0, preds = time.time(), []
        for i, r in enumerate(rows, 1):
            try:
                p = predictors[m](r)
            except Exception as e:
                sys.exit(f"Method '{m}' failed on text {i}: {type(e).__name__}: {e}")
            if p is None:
                sys.exit(f"Method '{m}' returns no answer - is LLM_PROVIDER set (e.g. ollama) and is the service running?")
            preds.append(p)
            if m in ("llm", "combined") and i % 25 == 0:
                print(f"  ... {m}: {i}/{len(rows)}", file=sys.stderr)
        results[m] = preds
        print(f"[{m}] {len(rows)} texts in {time.time() - t0:.1f}s")

    # ---- overall table per method and half
    print("\n" + "=" * 78)
    print(f"{'Method':10}{'half':8}{'correct':>10}{'MISSED (dangerous)':>28}{'FALSE ALARM':>16}")
    print("-" * 78)
    for m in methods:
        for split in (["dev", "test"] if a.split == "all" else [a.split]):
            idx = [i for i, r in enumerate(rows) if r["split"] == split]
            s = summarize([rows[i] for i in idx], [results[m][i] for i in idx])
            saved[f"{m}/{split}"] = s
            print(f"{m:10}{split:8}{pct(s['correct'], s['n']):>10}"
                  f"{f'{s['missed']}/{s['n_low']} = ' + pct(s['missed'], s['n_low']):>28}"
                  f"{f'{s['false_alarm']}/{s['n_high']} = ' + pct(s['false_alarm'], s['n_high']):>16}")
    print("=" * 78)
    if os.environ.get("CERTAINTY_PROMPT") in ("v4", "v5", "v6"):
        print(f"[parse] unreadable checklist answers (counted cautiously as LOW): {sm.PARSE_FAILURES}")

    # ---- per category: how often the error is made
    print("\nBy error type (share classified WRONG; lower is better)")
    cats = list(dict.fromkeys(r["category"] for r in rows))
    print(f"{'Category':26}{'target':6}" + "".join(f"{m + '/' + sp:>16}" for m in methods
                                                    for sp in (["dev", "test"] if a.split == "all" else [a.split])))
    for c in cats:
        label = next(r["label"] for r in rows if r["category"] == c)
        line = f"{c:26}{label:6}"
        for m in methods:
            for sp in (["dev", "test"] if a.split == "all" else [a.split]):
                idx = [i for i, r in enumerate(rows) if r["category"] == c and r["split"] == sp]
                wrong = sum(1 for i in idx if results[m][i] != label)
                line += f"{f'{wrong}/{len(idx)}':>16}"
        print(line)

    if a.show_errors == "dev":
        print("\nErrors of the DEVELOPMENT HALF (rules may be improved on these):")
        for m in methods:
            errs = [(r, p) for r, p in zip(rows, results[m]) if r["split"] == "dev" and p != r["label"]]
            print(f"\n--- {m}: {len(errs)} errors ---")
            shown = set()
            for r, p in errs:
                key = (r["category"], r["template_index"])
                if key in shown:
                    continue
                shown.add(key)
                print(f"  [{r['category']}, target {r['label']}, was {p}] {r['text']}")
                if m in ("llm", "combined"):
                    hit = llm_cache.get(("evaluation", r["text"], r["source_type"]))
                    if hit:
                        print(f"      Model's reasoning: {hit[1][:260]}")

    if a.save:
        json.dump(saved, open(a.save, "w"), indent=1)
        print("\nsaved:", a.save)


if __name__ == "__main__":
    main()
