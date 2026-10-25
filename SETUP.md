# Setup — what to download

The project runs in **two modes**. Both are in this repository; the difference is one
setting (`LLM_PROVIDER` in `.env`).

| I want to… | Download | Effort |
|---|---|---|
| **Just run it** (no AI model) | Python 3 — nothing else | 1 minute |
| Run it in **Docker** | Docker Engine + Compose ≥ 2.24 | 5 minutes |
| Run it **with an AI model** (the fuller picture) | Ollama + the `llama3` model (~4.7 GB) + `pip install ollama` | 15–30 minutes, mostly the download |

### Which mode should I use?

Neither is "better" overall — they fail in **opposite directions**. Numbers: our 286-text test corpus
(test half, `evaluation/`; written by us, so read it as a coverage check, not as real-world frequency).

| Your situation | Use | Why |
|---|---|---|
| No model available, a quick look, CI, reproducible output | **rule-based** (default) | deterministic and instant; 0 false alarms in 86 clear texts — but it misses **55 of 56** hedges worded in ways its rules do not know |
| You would rather over-flag than miss a caveat (security triage) and can run Ollama | **AI-assisted** (`--provider ollama`) | misses **3 of 56** hedges (5.4%; prompt v2) and flags **9-10 of 86** clear statements as uncertain (10.5-11.6%; two identical runs), so a few more cases go to a human |
| Judging this project quickly | both, on one case | `python3 main.py --case CVE-2021-44228 --provider rule_based`, then again with `--provider ollama`; every run prints a `[mode]` line first and every report ends with a `MODE` note |

Heads-up: if your shell still has `LLM_PROVIDER` exported from an earlier `source .env`, it silently wins over the
default - so pass `--provider rule_based` (or `unset LLM_PROVIDER`) when you want the no-AI run.
Switch per run with `--provider rule_based|ollama` — no `.env` needed (add `anthropic`/`openai` only if you have set those up).

Nothing needs an account or an API key. `.env` is never committed; you create it yourself.

---

## 1. Without AI — the default (nothing to install)

Needs only Python 3 (tested on 3.12 and 3.14). The project uses the standard library only —
verified by running the full test set in an empty virtual environment.

```bash
git clone https://github.com/nullstarr/vuln_agent.git
cd vuln_agent
python3 main.py # all 14 sample cases
python3 check_expected_outcomes.py # compares every result with its documented expected outcome
python3 check_missing_sources.py # what happens when sources are missing or incomplete (20 variants)
python3 check_report_guard.py # the safeguard against false reassurance in AI-written reports
python3 check_meterless_bridge.py # the real Meterless engine: ID parity, conflict verdicts, fallbacks (needs Node)
python3 check_fix_path.py # 'vendor announces a fix' path and the 'what would resolve this' steps
python3 check_triage.py # the ranked 'where to start' list
python3 check_timeline.py # the day-by-day timelines, incl. the engine's time-travel check (needs Node)
python3 check_prompt_versions.py # which certainty prompt is used (v1/v2/v3) and that prompt examples never come from the test corpus
```

**What a run writes to `logs/`:** per case a trace (`*.jsonl`), a world-model summary, a report, a result file and - with Node - `<CVE>_meterless.jsonl` (the engine's evidence log); per run `triage.json` and `meterless_manifest.json`.

**Optional:** with Node.js >= 18 installed, every case is also run through Meterless' real World Model engine (nothing to `npm install`); without Node it falls back to the Python implementation. `--meterless on` makes it mandatory, `--meterless off` skips it.

Open `viewer.html` in any browser, click once, and choose the `logs/` folder to see the ranked triage table, the graphs and the reports.

In this mode there is **no AI model at all**: certainty comes from a keyword list and a
scope check, and reports come from a fixed template.

## 2. With AI — Ollama (free, local, nothing leaves your machine)

```bash
# 1. Ollama itself (Linux; other systems: https://ollama.com/download)
curl -fsSL https://ollama.com/install.sh | sh

# 2. The model we tested with (~4.7 GB download)
ollama pull llama3

# 3. The Python client, ideally in a virtual environment
python3 -m venv venv && source venv/bin/activate
pip install ollama

# 4. Tell the project to use it
cp .env.example .env
sed -i 's/^LLM_PROVIDER=.*/LLM_PROVIDER=ollama/' .env
set -a; source .env; set +a

# 5. Run
python3 main.py
# (shortcut without .env: python3 main.py --provider ollama)
```

On Linux the installer starts Ollama as a background service. If `ollama list` shows
`llama3:latest`, it is ready.

**Hardware:** roughly 5–6 GB of free memory (GPU memory or RAM). It also runs on a CPU, only much slower.

**How to tell which mode you are in:** the trace shows `(keyword-fallback)` and
`sample-mode template` without AI, and `(llm)` and `write_report (llm)` with AI.

## 3. Docker

```bash
docker compose build
docker compose run --rm vuln-agent # no AI, no .env needed
docker compose run --rm vuln-agent python3 check_expected_outcomes.py
```

For the AI mode inside Docker, create `.env` as in step 2.4 and keep Ollama running on the host.
This uses `network_mode: host` and therefore works on Linux only (see `README.md`).

## 4. Cloud models (Anthropic / OpenAI) — wired in, not tested end-to-end

`LLM_PROVIDER=anthropic` or `openai`, plus `pip install anthropic` / `pip install openai` and an API
key in `.env` (never in the code). We connected the Anthropic client but never completed a full run
with it (the account had no credit), and we have not tried OpenAI at all. Treat both as untested.

## 5. Only to rebuild the demo video (not needed to use the app)

`ffmpeg`, `python3-pil` (Pillow) and the DejaVu fonts, plus one voice engine
(`pip install edge-tts`, or Piper, or Kokoro — see `voice.py`). Then `python3 video/make_video.py`.

---

## What the AI mode adds — stated honestly

- **Decisions:** both modes get all 14 sample cases right. The AI mode was run on all 14 by the author (`llama3:latest`, prompt v2), including the real CVEs Spring4Shell (resolved) and Heartbleed (unresolved).
- **Where the rules stop.** We measured the rule-only assessment on a 286-text corpus we wrote ourselves
 (`evaluation/`, not independent data). On wordings the rules were *not* tuned on, it misses **55 of 56**
 hedged texts, with no false alarms. Word lists catch only what their author thought of; adding more
 words did not fix that. This is the gap a language model is meant to close.
- **The model finds the hedges and, with prompt v2, cries wolf much less.** Measured with Ollama (`llama3:latest`) on the
 test half of the corpus: prompt v1 missed 1 of 56 hedges but rated 50 of 86 (58%) clearly confirmed texts as
 uncertain; **prompt v2 (now the default) misses 3 of 56 (5.4%) and flags 9-10 of 86 (10.5-11.6%; two identical runs differed slightly)**; the rules miss 55 of 56
 and flag none. The most cautious check wins, so the combined mode equals the model there: it fails safe (more human
 review) and is now fairly quiet. The three remaining misses are all *scope overclaims* ("fully resolves the issue"
 about only a named subset); "if / should" sentences around a completed check are still often rated uncertain.
 A third prompt (v3, written from the dev errors) was tried and **not adopted**: it missed fewer hedges (1 of 56) but raised
 false alarms to 22 of 86. Full tables and the model's own reasoning for its mistakes: `evaluation/RESULTS.md`. To reproduce:
 ```bash
 set -a; source .env; set +a
 python3 evaluation/evaluate.py --methods rules,llm,combined --show-errors dev
 ```
 (`CERTAINTY_PROMPT=v1` reproduces the old numbers.)
- **A small local model made real mistakes** in earlier runs: it called a clearly hedged internal note
 "high certainty", overlooked a scope gap, and once wrote a report that contradicted its own decision.
 That is why the AI never decides alone: its judgements are cross-checked by rule-based safety nets
 (the most cautious check wins) and the resolved/unresolved logic is deterministic. Details in `README.md`.
