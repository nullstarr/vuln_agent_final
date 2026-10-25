# Measurement: certainty assessment on the 286-text corpus

Run by the author with Ollama, model `llama3:latest` (no `OLLAMA_MODEL` set, so the code default
applies), **prompt v2** (the default; `CERTAINTY_PROMPT` unset), command:

```
python3 evaluation/evaluate.py --methods rules,llm,combined --show-errors dev
```

Corpus: `evaluation/corpus.jsonl`, 286 single-sentence texts written by the same person who wrote the rules
(not independent data). Wordings 0-2 are the **dev** half (rules and prompt were improved from its errors),
3-5 the **test** half (never used for tuning) - the test half is the fair number. "MISSED" = a hedged text rated
certain (the dangerous error); "FALSE ALARM" = a certain text rated hedged (the harmless one).

Earlier measurement for comparison (prompt v1, test half): model alone 64.1% correct, 1/56 hedges missed,
**50/86 false alarms**. Prompt v2 on the same half: 91.5% correct, **3/56** missed, **9/86** false alarms.

## Output, as printed (the harness prints only the first few errors per method)

```
[rules] 286 texts in 0.0s
[llm] 286 texts in 129.1s
[combined] 286 texts in 0.0s

==============================================================================
Method half correct MISSED (dangerous) FALSE ALARM
------------------------------------------------------------------------------
rules dev 100.0% 0/54 = 0.0% 0/90 = 0.0%
rules test 61.3% 55/56 = 98.2% 0/86 = 0.0%
llm dev 78.5% 3/54 = 5.6% 28/90 = 31.1%
llm test 91.5% 3/56 = 5.4% 9/86 = 10.5%
combined dev 80.6% 0/54 = 0.0% 28/90 = 31.1%
combined test 91.5% 3/56 = 5.4% 9/86 = 10.5%
==============================================================================

By error type (share classified WRONG; lower is better)
Category target rules/dev rules/test llm/dev llm/test combined/dev combined/test
vendor_complete high 0/30 0/30 5/30 0/30 5/30 0/30
internal_complete high 0/30 0/28 3/30 0/28 3/30 0/28
conditional_but_complete high 0/30 0/28 20/30 9/28 20/30 9/28
explicit_hedge low 0/6 13/13 0/6 0/13 0/6 0/13
partial_count low 0/18 13/13 0/18 0/13 0/18 0/13
pending_schedule low 0/7 6/7 0/7 0/7 0/7 0/7
stale low 0/6 8/8 0/6 0/8 0/6 0/8
inference low 0/5 3/3 0/5 0/3 0/5 0/3
exception_clause low 0/3 3/3 0/3 0/3 0/3 0/3
scope_overclaim low 0/3 3/3 3/3 3/3 0/3 3/3
gap_named low 0/6 6/6 0/6 0/6 0/6 0/6
```

## What the model got wrong on the dev half (excerpt, with the model's own reasoning)

- `vendor_complete`, should be high, was low: *"Starting with 2.0.8 the affected feature is disabled by default and the
 underlying parser has been rewritten."* - model: it "does not confirm the current state, leaving open the possibility
 that the feature may have been re-enabled ... since 2.0.8" (invented doubt).
- `internal_complete`, should be high, was low: *"We checked every one of the 8 servers directly and confirmed the setting
 is off. Config dump attached."* - model: "only confirms the state of 8 servers, leaving the remaining
 servers unaddressed, which is a partial coverage" (invented servers).
- `conditional_but_complete`, should be high, was low (two examples): *"If a request path contains '../', the validator
 now rejects it. We replayed all 26 known payloads against all 20 instances today; none passed."* and *"Should an attacker
 send an oversized payload, the parser aborts immediately. We confirmed this on every one of the 13 servers with the full
 test suite."*
- `scope_overclaim`, should be low, was high (three examples): *"All internet-facing load balancers now enforce the patched
 configuration. This fully addresses the vulnerability."*, *"Every public-facing gateway has been updated, which completely
 resolves the issue."*, *"The perimeter proxies are patched and the problem is entirely solved."* - the model takes the
 confident wording at face value; nothing in the sentence admits a doubt.

## Reading

- Prompt v2 turned a noisy model into a fairly quiet one on the test half (false alarms 58% -> 10.5%) at the price of two
 more missed hedges (1 -> 3 of 56). The three remaining misses on the test half are all `scope_overclaim`.
- The dev half is worse than the test half (31% false alarms). We do not know why; do not read the test number as "the model
 is this good everywhere".
- `combined` (most cautious wins) equals the model alone on the test half and removes the model's dev misses (rules were tuned
 on dev), so its dev row is not a fair measure of generalisation.

## Second run of the same prompt (noise check)

The author ran `CERTAINTY_PROMPT=v3 python3 evaluation/evaluate.py --methods llm,combined --show-errors dev`, but the first
output line of the current harness, `[prompt] CERTAINTY_PROMPT=...`, is **missing** from the output. It means the older project
version ran, which did not know v3 and fell back to v2. We therefore treat this run as a **repeat of the v2 measurement** - a
useful noise estimate: same prompt, `temperature: 0`, and still different results.

```
[llm] 286 texts in 142.0s
[combined] 286 texts in 0.0s
Method half correct MISSED (dangerous) FALSE ALARM
llm dev 75.7% 3/54 = 5.6% 32/90 = 35.6%
llm test 90.8% 3/56 = 5.4% 10/86 = 11.6%
combined dev 77.8% 0/54 = 0.0% 32/90 = 35.6%
combined test 90.8% 3/56 = 5.4% 10/86 = 11.6%
```

| | run 1 | run 2 |
|---|---|---|
| model dev: correct / false alarms of 90 | 78.5% / 28 | 75.7% / 32 |
| model test: correct / false alarms of 86 | 91.5% / 9 | 90.8% / 10 |
| missed hedges, dev of 54 / test of 56 | 3 / 3 | 3 / 3 |
| `conditional_but_complete` false alarms, dev of 30 / test of 28 | 20 / 9 | 20 / 10 |
| `scope_overclaim` missed on test | 3 of 3 | 3 of 3 |

Reading: the missed hedges and the `scope_overclaim` failure are stable; false alarms move by up to 4 texts on dev and 1 on
test between identical runs. Differences of one or two texts between prompts therefore cannot be told from noise - which is why
the adoption rule for prompt v3 (README) asks for a clear margin (at most 6 false alarms of 86 on the test half).

## Prompt v3, valid run (header line `[prompt] CERTAINTY_PROMPT=v3` present)

v3 was derived only from the dev-half errors (README). Adoption rule, fixed before any v3 result existed: on the test half at most
3 of 56 hedges missed **and** at most 6 of 86 false alarms. **Result: 1 of 56 missed (rule met), 22 of 86 false alarms (rule not
met) -> v3 is not adopted, v2 stays the default.** Output as printed:

```
[prompt] CERTAINTY_PROMPT=v3 (applies only to the methods llm and combined)
[llm] 286 texts in 138.8s
[combined] 286 texts in 0.0s

Method half correct MISSED (dangerous) FALSE ALARM
llm dev 77.8% 0/54 = 0.0% 32/90 = 35.6%
llm test 83.8% 1/56 = 1.8% 22/86 = 25.6%
combined dev 77.8% 0/54 = 0.0% 32/90 = 35.6%
combined test 83.8% 1/56 = 1.8% 22/86 = 25.6%

Category target llm/dev llm/test combined/dev combined/test
vendor_complete high 20/30 10/30 20/30 10/30
internal_complete high 10/30 1/28 10/30 1/28
conditional_but_complete high 2/30 11/28 2/30 11/28
explicit_hedge low 0/6 0/13 0/6 0/13
partial_count low 0/18 0/13 0/18 0/13
pending_schedule low 0/7 0/7 0/7 0/7
stale low 0/6 0/8 0/6 0/8
inference low 0/5 0/3 0/5 0/3
exception_clause low 0/3 0/3 0/3 0/3
scope_overclaim low 0/3 1/3 0/3 1/3
gap_named low 0/6 0/6 0/6 0/6
```

### v2 (two runs) against v3, by category (wrong / total)

| category | v2 dev | v3 dev | v2 test | v3 test |
|---|---|---|---|---|
| `vendor_complete` (should be high) | 5 / 7 of 30 | 20 of 30 | 0 / 0 of 30 | **10 of 30** |
| `internal_complete` (should be high) | 3 / 5 of 30 | 10 of 30 | 0 / 0 of 28 | 1 of 28 |
| `conditional_but_complete` (should be high) | 20 / 20 of 30 | **2 of 30** | 9 / 10 of 28 | 11 of 28 |
| `scope_overclaim` (should be low) | 3 / 3 of 3 | 0 of 3 | 3 / 3 of 3 | **1 of 3** |

### Reading

- **The dev gain did not carry over.** The pattern v3 was written against improved sharply on dev (`conditional_but_complete`
 20 -> 2 of 30) but not on test (9-10 -> 11 of 28). Tuning on the dev wordings fixed the dev wordings.
- **The new "compare what is claimed with what is named as backed" instruction made the model suspicious of ordinary
 statements.** It now reads "Fixed in 5.8.4 ..." as backed "only for a specific version" (`vendor_complete` on test 0 -> 10 of 30).
- **What it bought:** two fewer missed scope overclaims on test (3 -> 1 of 3, hedges missed 3 -> 1 of 56). **What it cost:**
 about 12 more false alarms on test (9-10 -> 22 of 86). The change is far outside the run-to-run noise (1-4 texts).
- We stop here. The rule said v2 stays, and further prompt iteration would only tune against the dev half again. The honest
 state: the model catches almost every hedge but still rates some plain statements as uncertain, and scope overclaims (a
 confident claim wider than what is named) remain the hardest category for both rules and model.

## Prompts v4, v5, v6 - plan fixed BEFORE any result exists

Why: v3 added rules and got 22/86 false alarms on the test half - a small local model (`llama3:latest`) judges worse when one
prompt carries many rules. The new candidates change the *structure*, not just the wording (`agents/source_mapper.py`):

- **v4 checklist:** five narrow yes/no questions about what the text says; the code decides (any YES = LOW). Unreadable
 answers are retried once, then counted as LOW and reported as `[parse]` in the evaluation output.
- **v5 majority:** v2, v3 and v4 each judge; two of three LOW = LOW (three model calls per text).
- **v6 verification:** v2 judges; if v2 says LOW, the checklist must confirm it, otherwise HIGH.

What was known when they were written: the dev-half errors (as before) and the *category table* of v3 on the test half
(published above). No test-half text was looked at. The prompt examples are invented and checked against the corpus
(`check_prompt_versions.py`). Because the category table was known, the test half is **not perfectly untouched** for v4-v6;
it is also already used for v1-v3. Read any test number accordingly.

Selection and adoption rule (fixed now, not changed after results):
1. Run each candidate on the **dev half only**: `CERTAINTY_PROMPT=v4 python3 evaluation/evaluate.py --methods llm --split dev`
 (same for v5, v6).
2. A candidate is eligible if on dev it misses at most 3 of 54 hedges **and** has at most 20 false alarms of 90 (v2: 28-32).
3. Of the eligible candidates, take the one with the fewest dev false alarms; ties go to the fewer model calls (v4 < v6 < v5).
 If none is eligible, **stop: no test run, v2 stays the default.**
4. Run the chosen candidate on the **test half twice**. Adopt only if **both** runs have at most 3 of 56 missed **and** at most
 6 of 86 false alarms (the rule v3 failed). Otherwise v2 stays, and the results are added here either way.

### Results v4-v6 (run by the author, `llama3:latest`)

Dev half (`--methods llm --split dev`, one run each; dev is the half the prompts were designed against, so these numbers are optimistic):

| candidate | missed of 54 | false alarms of 90 | model time | eligible (<=3 missed and <=20 false alarms)? |
|---|---|---|---|---|
| v4 checklist | 2 | 0 | 83 s | yes |
| v5 majority | 0 | 6 | 250 s | yes |
| v6 verification | 5 | 0 | 115 s | **no** (5 missed; scope overclaim 3/3 missed) |

Rule step 3 picks v4 (fewest dev false alarms, fewer model calls than v5). No unreadable checklist answers (`[parse]` 0 in all runs).

Test half, v4, **run twice** (`--methods llm,combined --split test`); both runs gave identical numbers:

```
llm test 92.3% 1/56 = 1.8% 10/86 = 11.6%
combined test 92.3% 1/56 = 1.8% 10/86 = 11.6%
vendor_complete 10/30 false alarms, exception_clause 1/3 missed, every other category 0 wrong
```

**Adoption rule (<=3/56 missed and <=6/86 false alarms in both runs): missed 1/56 - met; false alarms 10/86 - not met -> v4 is
not adopted, v2 stays the default.** Reading, labelled as such (not part of the rule): against v2 on the same half (3/56 missed,
9-10/86 false alarms) v4 misses fewer hedges (1 vs 3) at the same number of false alarms, and its two runs were identical
where v2's differed. The 10 false alarms are all `vendor_complete` (0/30 on dev, 10/30 on test), the same category that broke
under v3 (10/30) - a pattern a sentence-level checklist shares with v3's extra rules. We did not look at those test texts to tune
on them. Note that the 6/86 bar was set as a margin over v2's noise and v2 itself does not meet it either (9-10/86).
v5 and v6 were not run on the test half (v5 was not the pick; v6 was not eligible).

### v5 on the test half, as a second candidate (added after v4 failed)

Not part of the original plan, so it is labelled as an extra: v5 was eligible on dev (0/54 missed, 6/90 false alarms) but not
picked by the rule. After v4 missed the bar, the author asked for it to be measured too, with the same bar fixed beforehand
(at most 3/56 missed and at most 6/86 false alarms, both runs). It is the **second candidate on the test half**, so a pass would
have carried a multiple-comparisons caveat. Two runs, identical:

```
llm test 85.9% 1/56 = 1.8% 19/86 = 22.1%
vendor_complete 10/30, conditional_but_complete 9/28, scope_overclaim 1/3 missed, every other category 0 wrong
```

**Missed 1/56 (met), false alarms 19/86 (not met) -> v5 is not adopted, v2 stays the default.** The majority vote did not help:
the two prompts that raise false alarms on this half (v3: 22, v4: 10) outvote v2 often enough that v5 sits close to v3.
It also costs three model calls per text (about 227 s for 142 texts against 81 s for v4).

## Independent test set (kit prepared; results will be added here when sentences from other people exist)

`evaluation/external/HELPER_GUIDE.md` asks other people to write about 20 sentences each (10 they consider fully confirming, 10
with a doubt or gap) **and to label them themselves**. `evaluation/import_external.py` turns the files in `evaluation/external/inbox/`
into `evaluation/external.jsonl`; `evaluate.py --corpus evaluation/external.jsonl --split test` measures them. Rules fixed before any such
result: nothing is tuned on these sentences (no rule, no prompt), the numbers are reported as they come out, sentences already in our own
corpus are skipped, and below 30 sentences the percentages are labelled a sample, not a measurement.

### Real advisory sentences (set prepared, labels by the author, results pending)

`evaluation/external/real_sentences_TO_LABEL.txt`: 36 sentences taken from public pages (Spring, Apache Log4j and Struts, Red Hat,
Cisco, Broadcom/VMware, CERT/CC, Jenkins, heartbleed.com, GitHub Advisory Database), shuffled, **unlabelled**; the sources are in a
separate file the author opens only after labelling. The wording was fetched with a summarising tool and requested verbatim; small
deviations from the page are possible. Labels (H = complete, L = doubt/gap/partial) are set by the author without seeing the model's
answers; sentences that state no status are left unlabelled and skipped. Same rules as above: nothing is tuned on them, the result
is reported as it is. These sentences differ in style from our corpus (real advisories have fewer explicit hedges), so a low
"missed" count is not directly comparable with the corpus numbers.

#### Result on real advisory sentences (run by the author, `llama3:latest`, prompt v2)

The author labelled 24 of the 36 sentences (17 H = complete, 7 L = doubt/gap; the other 12 were left unlabelled and skipped), without
seeing any model output. Command: `python3 evaluation/evaluate.py --corpus evaluation/external.jsonl --split test --methods rules,llm,combined`.

```
rules test 66.7% 7/7 = 100.0% 1/17 = 5.9%
llm test 45.8% 0/7 = 0.0% 13/17 = 76.5%
combined test 45.8% 0/7 = 0.0% 13/17 = 76.5%
```

Nothing was tuned on these sentences. Reading, with the caveats it needs: (1) **n = 24 (7 hedged, 17 clear) is a sample, not a
measurement**; one text moves the model's false-alarm rate by about 6 points. (2) The pattern matches the corpus for the rules (they miss
hedges worded in ways they do not know: 7 of 7 here, 55 of 56 on the corpus test half) and the model again fails on the cautious side
(no hedge missed), **but its false-alarm rate on real wording (13 of 17) is far above the 9-10 of 86 on our own corpus**, so that corpus number
must not be generalised to real documents. (3) Part of this may be a task mismatch rather than model weakness: real advisory sentences
are taken out of context and many describe scope or give instructions, so "does this text fully confirm its claim" is often
legitimately not answered "yes"; the labels are one person's judgement. (4) No error analysis was done to tune anything; the sentences
stay out of every prompt and rule.

## Nemotron 3.5 lightning through NVIDIA's hosted API (run in the build window, 23 Oct 2026)

Run by the author on 2026-10-23 (build window, day 2) with `nvidia/nemotron-3.5-lightning-30b-a3b` on NVIDIA's free hosted
endpoint (build.nvidia.com), **prompt v2** (default), temperature 0, **thinking switched off** (`NVIDIA_ENABLE_THINKING=false`),
one run, 533.9 s for 286 calls (throttled to stay under the endpoint's rate limit). Command:

```
LLM_PROVIDER=nvidia python3 evaluation/evaluate.py --methods llm,combined --save evaluation/results_nemotron_lightning.json
```

Why thinking is off: with thinking on, this model spends all its tokens on reasoning (`content: null` after 3000 tokens in our
probe), so no answer arrives. With it off the same probe answered in 3 tokens. Raw files: `evaluation/results_nemotron_lightning.json`
and the printed run `evaluation/run_nemotron_lightning.txt`.

```
Method half correct MISSED (dangerous) FALSE ALARM
llm dev 88.2% 3/54 = 5.6% 14/90 = 15.6%
llm test 98.6% 2/56 = 3.6% 0/86 = 0.0%
combined dev 90.3% 0/54 = 0.0% 14/90 = 15.6%
combined test 98.6% 2/56 = 3.6% 0/86 = 0.0%
```

By category, the only wrong ones: `vendor_complete` 14/30 on dev (false alarms, 0/30 on test), `scope_overclaim` 3/3 (dev, model alone)
and 2/3 (test, also with the rules).

**Reading, without spin.**
- The adoption bar fixed earlier for prompts (test half: at most 3 of 56 hedges missed AND at most 6 of 86 false alarms) is
 met by this model on the test half: **2/56 and 0/86**. No earlier prompt/model pair met both (best before: 3/56 with 9-10/86).
- Both test-half misses are `scope_overclaim` (a claim that sounds complete but covers less than it says), the known weak spot
 of the rules too (see README "A limit we found").
- The dev half looks worse (14/90 false alarms, all in `vendor_complete`). The halves differ strongly for the same category
 (14/30 vs 0/30), which tells us this is one run on one model on 286 sentences written by one person: **not a general claim about the
 model**. The fair number is the test half, and it comes from a single run (temperature 0, but not repeated yet).
- Not an independent test: the corpus is the author's own (see top of this file). The independent kit (`evaluation/external.jsonl`)
 has not been run with this model.
- This ran against NVIDIA's API **directly**, not through Meterless Nightshift (no Linux x86_64 build; see README).

### Second run, same command (2026-10-23, 567.0 s), noise check

```
Method half correct MISSED (dangerous) FALSE ALARM
llm dev 90.3% 3/54 = 5.6% 11/90 = 12.2%
llm test 98.6% 2/56 = 3.6% 0/86 = 0.0%
combined dev 92.4% 0/54 = 0.0% 11/90 = 12.2%
combined test 98.6% 2/56 = 3.6% 0/86 = 0.0%
```

Compared with the first run (`results_nemotron_lightning.json` against `results_nemotron_lightning_run2.json`):
- **Test half: identical** (2/56 missed, 0/86 false alarms, same two categories).
- **Dev half: not identical.** False alarms 14/90 in run 1, 11/90 in run 2 (all in `vendor_complete`: 14/30 and 11/30); missed hedges 3/54 in both.
 So the hosted endpoint is **not fully deterministic even at temperature 0**, which is why we report both runs instead of the better one.
- Two runs show the test-half result is stable here; they do not make it a general result (one model, one prompt, the author's own corpus).

## Nemotron 3.5 lightning on the real advisory sentences (run in the build window, 24 Oct 2026)

Same 24 sentences as above (labelled by the author on 24 Oct, before any model output; the author is not a security expert; 17 H, 7 L).
Nothing was tuned on them. `LLM_PROVIDER=nvidia`, `NVIDIA_MODEL=nvidia/nemotron-3.5-lightning-30b-a3b`, thinking off, prompt v2,
file `evaluation/run_external_nemotron.txt`.

```
rules test 66.7% missed 7/7 = 100.0% false alarms 1/17 = 5.9%
llm test 41.7% missed 0/7 = 0.0% false alarms 14/17 = 82.4%
combined test 41.7% missed 0/7 = 0.0% false alarms 14/17 = 82.4%
```

Reading, without softening it:
- The result on our own corpus (0 of 86 false alarms for Nemotron) **does not carry over** to real advisory text: here Nemotron rates 14 of 17
 clear sentences as uncertain, about like llama3 (13/17). It still missed none of the 7 hedges; the rules missed all 7.
- Too careful is the safe direction (more cases go to a person), but it makes the AI mode noisy on real text.
- 24 sentences, labels by one non-expert author, one run: an indication, not a measurement. Real advisories contain few explicit status
 claims, so many "H" labels are judgement calls.
