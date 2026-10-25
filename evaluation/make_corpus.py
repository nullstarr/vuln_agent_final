#!/usr/bin/env python3
"""
Generates evaluation/corpus.jsonl: many labeled source texts used to measure how well
the "certain (high) or uncertain (low)?" assessment works.

Structure
  - 3 kinds of "high" texts (complete, current, directly backed) and
    8 kinds of "low" texts (each with a different kind of reservation).
  - 6 different WORDINGS per kind. Wording 0-2 = "dev", 3-5 = "test".
    You may only improve on "dev"; "test" stays for an honest re-measurement.
  - Numbers, dates, versions, system names are inserted randomly (but with a fixed seed).

HONEST LIMIT: all texts were written by the same person who also writes the check rules.
This is NOT an independent data set. "test" measures whether rules carry beyond other wordings
- not how good they would be on real, foreign texts.

Usage: python3 evaluation/make_corpus.py
"""

import json
import os
import random

HERE = os.path.dirname(os.path.abspath(__file__))
SEED = 20261024
SYSTEMS = ["payments-api", "auth-service", "billing cluster", "edge gateway", "report server", "LDAP proxy"]

# (category, label, source_type, [6 wordings])
CATEGORIES = [
    # ---------------------------------------------------------------- HIGH
    ("vendor_complete", "high", "vendor_changelog", [
        "The vulnerable code path was removed entirely in version {ver}; no configuration can re-enable it.",
        "Fixed in {ver}: input is now validated before parsing, and the old behaviour no longer exists in the codebase.",
        "Starting with {ver} the affected feature is disabled by default and the underlying parser has been rewritten.",
        "Release {ver} closes the issue completely. The fix was verified by our security team through a full code audit on {date}.",
        "As of {ver} the flawed component is gone. Upgrading is the only step required, and it fully resolves the issue.",
        "Patched in {ver}. The vendor confirmed the fix against the original proof of concept and found no remaining attack path.",
    ]),
    ("internal_complete", "high", "internal_ticket", [
        "Verified on all {n} production instances on {date}; every instance reports version {ver}. No exceptions.",
        "Automated inventory scan this morning: all {n} hosts run {ver}. None are pinned to an older release.",
        "We checked every one of the {n} servers directly and confirmed the setting is off. Config dump dated {date} attached.",
        "Compliance run on {date} covered all {n} {sys} instances: all {n} passed, zero failures.",
        "Pulled the live configuration from each of the {n} nodes today. The risky flag is absent on all of them.",
        "All {n} instances were upgraded to {ver} and re-tested on {date}; the exploit no longer works on any of them.",
    ]),
    ("conditional_but_complete", "high", "internal_ticket", [
        "If a request path contains '../', the validator now rejects it. We replayed all {k} known payloads against all {n} instances today; none passed.",
        "When a crafted header is sent, the gateway returns 400 instead of processing it. Tested against all {n} instances on {date}, all behave identically.",
        "Should an attacker send an oversized payload, the parser aborts immediately. We confirmed this on every one of the {n} servers with the full test suite on {date}.",
        "If the legacy flag is set, startup now fails hard. This was verified in all {n} environments on {date}.",
        "Any request without a valid token is rejected before reaching the handler; we ran the {k} bypass attempts from the disclosure against all {n} instances, and every one was blocked.",
        "When the setting is missing, the service falls back to the safe default. Checked directly on all {n} hosts today.",
    ]),
    # ----------------------------------------------------------------- LOW
    ("explicit_hedge", "low", "internal_ticket", [
        "Checked the main cluster. The setting on the backup cluster is unconfirmed.",
        "We could not find the current value of the flag in the last deploy logs.",
        "No one has confirmed whether {sys} received the update.",
        "The live configuration of {sys} is unknown; nobody has looked since the migration.",
        "Whether the patch reached the {n} remote sites is unverified.",
        "We cannot confirm the status of {sys}; the result is undetermined.",
    ]),
    ("partial_count", "low", "internal_ticket", [
        "Only checked {a} of our {n} edge nodes so far. The remaining nodes have not been looked at.",
        "{a} out of {n} instances are confirmed patched.",
        "Confirmed on {a} of the {n} servers; the rest are still open.",
        "So far we inspected {a} hosts, and {n} are in scope.",
        "The scan finished for {a}/{n} nodes.",
        "Two thirds of the fleet is verified, the final third is still to be checked.",
    ]),
    ("pending_schedule", "low", "internal_ticket", [
        "The remaining nodes are scheduled for next week's maintenance window.",
        "Upgrade of {sys} has not happened yet; it is planned for the next sprint.",
        "We have yet to roll the fix out to {sys}.",
        "Remaining hosts will be patched during the quarterly window.",
        "The rollout is in progress and not finished.",
        "{sys} is on the backlog for the coming release.",
    ]),
    ("stale", "low", "internal_ticket", [
        "This was true as of last year's audit; nothing has been checked since.",
        "Last verified {n} months ago, before the migration.",
        "The flag was off when we last looked, which was a while back.",
        "Our records for {sys} date from the {yr} review.",
        "The check was done during the original rollout and never repeated.",
        "Based on an old inventory export from before the reorganisation.",
    ]),
    ("inference", "low", "internal_ticket", [
        "This should still be the case on {sys}.",
        "We assume the update was applied everywhere.",
        "Probably patched, since the standard image was used.",
        "As far as we know, the setting is disabled.",
        "The team believes the fix reached all hosts.",
        "Presumably unaffected because the feature is rarely used.",
    ]),
    ("exception_clause", "low", "vendor_changelog", [
        "Applications that do not override this system property are not affected.",
        "The feature is off by default unless an operator enables it in the config file.",
        "Deployments upgraded in place from older versions may still have it enabled.",
        "Not affected, except for installations that kept the legacy compatibility profile.",
        "Safe in the default setup; custom builds can behave differently.",
        "Fixed for new installs. Existing systems keep the previous behaviour until reconfigured.",
    ]),
    ("scope_overclaim", "low", "vendor_changelog", [
        "All internet-facing load balancers now enforce the patched configuration. This fully addresses the vulnerability.",
        "Every public-facing gateway has been updated, which completely resolves the issue.",
        "The perimeter proxies are patched and the problem is entirely solved.",
        "All customer-facing web servers run the fixed build; the vulnerability is fully closed.",
        "The front-end tier has been upgraded, completely eliminating the risk.",
        "External API endpoints were patched, so the issue is entirely handled.",
    ]),
    ("gap_named", "low", "internal_ticket", [
        "The dispute portal was excluded from the upgrade sprint.",
        "{sys} was skipped during the rollout because it is scheduled for retirement.",
        "The batch servers are out of scope for this patch.",
        "The old reporting host was not included in the scan.",
        "Legacy systems were left out of this round.",
        "We did not touch {sys}; it runs outside our standard pipeline.",
    ]),
]

SAMPLES = {"high": 10, "low": 6}


def fill(template, rng):
    n = rng.randint(6, 24)
    return template.format(
        n=n, a=rng.randint(1, n - 1), k=rng.randint(20, 60),
        ver=f"{rng.randint(1, 5)}.{rng.randint(0, 9)}.{rng.randint(0, 9)}",
        date="2026-10-24",
        sys=rng.choice(SYSTEMS), yr=rng.randint(2019, 2023),
    )


def main():
    rng = random.Random(SEED)
    rows, seen = [], set()
    for category, label, source_type, templates in CATEGORIES:
        for idx, template in enumerate(templates):
            for _ in range(SAMPLES[label]):
                text = fill(template, rng)
                if text in seen:      # do not artificially multiply wordings without placeholders
                    continue
                seen.add(text)
                rows.append(dict(id=f"{category}-{idx}-{len(rows):04d}", split="dev" if idx < 3 else "test",
                                 category=category, label=label, source_type=source_type,
                                 template_index=idx, text=text))
    out = os.path.join(HERE, "corpus.jsonl")
    with open(out, "w") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    print(f"{len(rows)} texts -> {out}")
    for split in ("dev", "test"):
        sub = [r for r in rows if r["split"] == split]
        print(f"  {split}: {len(sub)}  (high {sum(r['label']=='high' for r in sub)}, low {sum(r['label']=='low' for r in sub)})")


if __name__ == "__main__":
    main()
