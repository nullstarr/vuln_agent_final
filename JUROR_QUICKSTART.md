# Check it yourself in 5 minutes

No account, no API key, no GPU needed. This is the default "sample mode" (no AI model).
Needs **either** Docker **or** Python 3.10+ (Node 18+ is optional: with Node the unmodified Meterless World Model engine runs;
without it a Python port takes over and the report says so).

## 1. Run it (1 minute)

```bash
git clone <this repository> && cd vuln_agent
docker compose run --rm vuln-agent            # or, without Docker:  python3 main.py
```

Expected: 14 cases run, then a ranked triage table (most urgent first). The first rows should look like this:

```
TRIAGE - most urgent first
 #  CVE             baseline  decision    why
 1  CVE-2021-44228  CRITICAL  unresolved  CRITICAL, EXPLOITED, unresolved: internal - unconfirmed item; vendor - carries an exception
 2  CVE-2017-5638   CRITICAL  unresolved  CRITICAL, EXPLOITED, unresolved: internal - unconfirmed item
 ...
10  CVE-2022-22965  CRITICAL  resolved    resolved: vendor claim and internal evidence agree
```

Then two "timelines" (Apache Struts and Spring4Shell): the decision stays `unresolved` until the internal evidence closes the gap
(Struts: day 4 "13 of 14 applications confirmed" -> still unresolved; day 9 "dispute portal upgraded and re-tested" -> `resolved`).
The tickets and dates in these timelines are **simulated** - the NVD and vendor texts are real or paraphrased.

## 2. See one decision explained (2 minutes)

```bash
docker compose run --rm vuln-agent python3 main.py --case CVE-2021-44228      # or: python3 main.py --case CVE-2021-44228
```

Read the report at the end. The vendor says "JNDI lookups are off by default" - a first draft would call this resolved. The
internal ticket says two of four clusters are unconfirmed, so the Challenge Agent **rejects** the draft ("Revisions during review: 1"),
and the report ends with `Conclusion: NOT resolved`, a **WHAT WOULD RESOLVE THIS** list (what to verify, quoted from the sources) and an
**EVIDENCE TRAIL** from the Meterless World Model (which source the belief came from, which was superseded).
The full step-by-step trace is in `logs/CVE-2021-44228.json`, the engine's event log in `logs/CVE-2021-44228_meterless.jsonl`.
Optional: three real advisories (synthetic tickets): `python3 check_real_world.py` (2 as intended, 1 known gap, explained in the README).
Zetaris data layer: `python3 check_zetaris.py` (offline, stand-in server); with a running Zetaris and key: `python3 setup_zetaris.py --run` then `python3 check_zetaris.py --live`.
Exploitation signal (urgency, never the verdict): `python3 check_exploitation.py`.
Service outages (AI provider or Zetaris down, handled openly): `python3 check_robustness.py`.
Meterless Runtime provider: `python3 check_meterless_runtime.py` (stand-in server; `--live` needs a real Nightshift Runtime).

Optional: try your own CVE: `python3 main.py --cve CVE-2021-44228 --vendor input_examples/byo_vendor.txt --internal input_examples/byo_internal.txt` (needs internet).

Optional: open `viewer.html` in a browser and pick the `logs/` folder once; it shows the cases as a table, source graphs and a timeline strip.

## 3. Run the safety nets (1 minute)

```bash
docker compose run --rm vuln-agent python3 check_expected_outcomes.py
```

Expected last line: `All 14 cases match the expected result.` (14 of 14 cases give the pre-written expected result).
More checks, each prints its own pass count: `check_missing_sources.py`, `check_report_guard.py`, `check_fix_path.py`,
`check_triage.py`, `check_timeline.py`, `check_meterless_bridge.py`, `check_prompt_versions.py`.

## Where to look for what

| You want to know | Look at |
|---|---|
| How the four agents decide and why a draft is rejected | `agents/reconciler.py`, `agents/challenger.py`, README "Why this is an agent system, not a pipeline" |
| Which Meterless engine part is really used (and which are not) | `logs/meterless_manifest.json` after a run, `integrations/meterless/NOTICE.md`, README |
| What was measured, honestly | `evaluation/RESULTS.md` (including the prompt versions that did **not** work) |
| What is simulated, what is not, and what is missing | [`FAQ.md`](FAQ.md) |

The optional AI mode (`--provider ollama`, needs Ollama and `llama3`) is described in `SETUP.md`; its numbers are in the README.
