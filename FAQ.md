# Hard questions, honest answers

Short answers to the questions a careful reviewer should ask. Where a claim has evidence, the file is named.

**1. The internal tickets are made up. Why should I trust any result?**
Internal tickets are private by nature; there is no public dataset of them. The NVD records and vendor advisories in the sample
cases are real or paraphrased from real ones; the internal tickets, the dates and the two fully fictional CVEs are **synthetic**, and
every source carries an `is_real_public_data` flag and a `note` saying so (`data/sample/cases.json`). The 14 cases show *how the
system reasons*, not how often real tickets look like this. Nothing here measures performance on real organisations' data. Three cases with real advisory wording (`data/real_world/`) exist; they showed one gap in our fix-claim rule, documented in the README.

**2. Your evaluation corpus was written by you. Isn't that circular?**
Partly, yes. The 286 one-sentence texts were written by the author of the rules (`evaluation/make_corpus.py`). We split them into a
dev half (rules and prompts were improved from its errors) and a test half (never used for tuning). The test half is the fair
number, and even it comes from the same author's wording habits. The 55-of-56 missed hedges of the rules on the test half show how
badly rules tuned on dev transfer; they were not hidden. A first check on wording we did not write exists: 24 real sentences from public
vendor and project advisories, labelled by the author without seeing any model output (`evaluation/external/`, `evaluation/RESULTS.md`).
Result: the rules missed 7 of 7 hedges (as on the corpus), the model missed none but flagged **13 of 17** clear sentences as
uncertain, far more than on our corpus. With n = 24 this is a sample, not a measurement, but it says the corpus's 9-10 of 86 should not be
read as the rate on real documents.

**3. What did Meterless actually do? Is it decoration?**
The unmodified Meterless **World Model** reference engine (TypeScript, Apache-2.0, exact commit in
`integrations/meterless/NOTICE.md`) runs for every case through a small Node bridge. It receives our three sources as facts with
provenance, applies the conflict policy `source-priority` (internal ticket > NVD > vendor), marks the losers superseded, and writes an
event log and audit trail; each report's **EVIDENCE TRAIL** is read from that state. What it does *not* do: the verdict follows the
priority order **we configured**, so it does not discover anything our rules do not already say. Its value is the auditable "which
fact superseded which, from which observation". We use only the World Model engine (not H-MEM, Markovian, Scout Intent, Swarm).
Without Node, a Python port takes over and the report says so (`--meterless auto|on|off`).

**4. Is the "reject and revise" loop real, or scripted for the demo?**
It runs on every case: the Reconciler writes a first draft, the Challenge Agent checks it against the sources, and a rejection sends it
back (`Revisions during review: N` in each report, every step in `logs/<CVE>.json`). The decision logic is rules, not a model
(`agents/reconciler.py`, `agents/challenger.py`, `agents/decision.py`). With an AI model, the model judges how certain a source text is
and writes the report wording; it does not decide "resolved". Whether the first draft is wrong depends on the case: for Log4Shell the
first draft takes the vendor's "off by default" at face value, and the internal ticket then contradicts it (that is the rejection you see).

**5. Why not just ask a large language model in one call?**
We tried (`baseline_naive.py`, 9 cases): it got 8 of 9, and the one disagreement was our keyword check being too narrow, which we fixed.
A single call is strong; we do not claim better accuracy on these cases. What a single answer lacks is an inspectable chain: which source
said what, why a draft was rejected, what is still missing. That is the track's point ("explain why"), not a score.

**6. What is the AI mode's real quality?**
Measured with Ollama `llama3:latest` on the test half (86 clear + 56 hedged texts): prompt v2 misses **3 of 56** hedges and flags **9-10
of 86** clear statements as uncertain (two identical runs differed by one text). The rules alone miss 55 of 56 but raise 0 false alarms.
Both fail in opposite directions; the product takes the more cautious of the checks (`evaluation/RESULTS.md`). On 24 real advisory sentences the model flagged 13 of 17 clear ones as uncertain (see question 2), so on real wording expect many more flags than on our corpus.

**7. You tried several prompts. Did you tune on the test half?**
Prompts v3, v4, v5 were each written from dev-half errors, with the adoption rule fixed **before** any test result. None met it, so the
default stays v2 and the failures are in `evaluation/RESULTS.md`. Caveat we state there: the test half is not perfectly untouched
(v1-v5 were all measured on it, and for v4-v6 the category table of v3 was known when they were written).

**8. Can it ever say "resolved"?**
Yes, but only when the internal ticket is itself certain **and** shows the fix deployed, and the checks find no contradiction (the "fix path",
`check_fix_path.py`). If a source is missing, a missing source counts as unconfirmed, never as safe. A vendor that never answers means the
system can never say "resolved": a deliberate choice, shown with CVE-2024-7002.

**9. What is NOT done?**
(The fix path now requires a positive proof for "resolved"; rule-based checks on free text stay brittle. Found by an AI review (Claude acting as a vulnerability manager; not a human user) and still open: findings per asset from a scanner instead of free-text tickets, EPSS and asset exposure in the ranking (a yes/no exploitation flag from the CISA KEV catalog is done, as urgency only), CSAF/VEX as a vendor source. A false "resolved" in rule mode that the same review found was fixed, see README.)
Zetaris is integrated and was checked live on a local instance (one instance, simulated tickets). The Meterless Runtime provider (Nightshift) is implemented but only ran against a stand-in server, because there is no Linux x86_64 build. Nemotron 3.5 lightning was run live through NVIDIA's API (not through Nightshift) and measured; on real advisory sentences it was noisy (see `evaluation/RESULTS.md`). Only three source types are modelled. Your own CVE can be run with `main.py --cve` (live NVD entry plus your own vendor and ticket texts); the live NVD call passed once, on one CVE. No SIEM, asset
inventory or real ticket system is connected. It produces a documented starting point for a human decision, not the decision.

**11. Does it send my data anywhere?**
Not in the default mode. Sample mode runs fully offline. The AI mode uses a **local** Ollama model. Hosted providers (Anthropic, OpenAI,
NVIDIA) are opt-in per `.env` and then receive the source texts.

**12. How do I know the safeguards work?**
`check_*.py` scripts, each printing its pass count (14/14 expected outcomes, 20/20 missing-source variants, 6/6 report guards, 13/13 fix
path, plus triage, timeline, prompt-version and Meterless-bridge checks, including a crash-resume test with `kill -9`). The key safeguards
were each deliberately broken to confirm the test then fails; not every single check was mutation-tested.

**13. How was Cursor used?**
Only for brainstorming. The code was written with Claude. Cursor is not part of the runtime system (see `metadata.json`).
