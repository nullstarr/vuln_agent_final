"""
Orchestrator: runs the full flow for one or all tasks.

    SourceMapper -> Reconciler -> ChallengeAgent -+-> (back to Reconciler if rejected)
                                                   +-> Reporter (if approved)

Runs completely without credentials (LLM_PROVIDER=rule_based, default) - that
IS the required example mode, not a stopgap. With a real key
(LLM_PROVIDER=anthropic or openai) the Reporter writes the same
conclusion, only in more fluent language.

Usage:
    python3 main.py                       # all sample cases
    python3 main.py --case CVE-2021-44228 # one case
    python3 main.py --cve CVE-2021-44228 --vendor v.txt --internal t.txt   # your own case, NVD live
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from agents.envfile import load_env
from agents.trace import TraceLogger, write_text
from agents.source_mapper import map_sources
from agents.decision import decide
from agents.reporter import write_report
from agents.world_model import build_world_model, world_model_summary
from agents.meterless_bridge import run_engine, engine_summary, evidence_jsonl, evidence_trail
from agents.process_health import record_availability, check_process_health
from agents.next_steps import blockers as find_blockers, what_would_resolve, format_steps
from agents.triage import build_result, rank, format_table
from agents.timeline import TimelineError, build_timeline, format_timeline, load_timelines


def failure_note():
    from agents import llm_provider
    if not llm_provider.FAILURES:
        return ""
    n = sum(llm_provider.FAILURES.values())
    first = next(iter(llm_provider.FAILURES))
    return (f"\n\n--- AI PROVIDER PROBLEM ---\n{n} AI call(s) failed ({first}); for those the rule-based check was used instead.\n"
            "The result is still valid but is not AI-assisted for the affected sources.")


def mode_footer():
    """At the end of every report: which variant produced it - and what the other is better for.
    The statements rest on the measurement in evaluation/ (see README), not on guesswork."""
    provider = os.environ.get("LLM_PROVIDER", "rule_based").lower()
    if provider == "rule_based":
        return ("\n\n--- MODE: rule-based (no AI model) ---\n"
                "Deterministic and quiet: no false alarms in our test set, but it misses hedges worded in ways\n"
                "its rules do not know. An AI mode exists (--provider ollama): on our test half it caught 53 of 56\n"
                "unusual hedges (rules: 1) but wrongly flagged 9-10 of 86 clear statements as uncertain. See SETUP.md.")
    model = {"ollama": os.environ.get("OLLAMA_MODEL", "llama3:latest"),
             "nvidia": os.environ.get("NVIDIA_MODEL", "nvidia/llama-3.1-nemotron-70b-instruct"),
             "meterless": os.environ.get("METERLESS_MODEL", "meterless/auto")}.get(provider, "")
    label = f"{provider}{':' + model if model else ''}"
    from agents import llm_provider
    if llm_provider.SERVED:
        label += "; answered by: " + ", ".join(f"{k} x{v}" for k, v in sorted(llm_provider.SERVED.items()))
    if provider == "nvidia" and os.environ.get("NVIDIA_MODEL") == "nvidia/nemotron-3.5-lightning-30b-a3b":
        return (f"\n\n--- MODE: AI-assisted ({label}) ---\n"
                "Measured on our corpus with this model (thinking off, two runs): test half 2 of 56 hedges missed and 0 of 86 false alarms;\n"
                "dev half 3 of 54 missed by the model alone (0 with the rules) and 11-14 of 90 false alarms. The corpus is the author's own; on 24 real advisory sentences it flagged 14 of 17 clear ones (one run).\n"
                "Rule-based mode (--provider rule_based) is deterministic and needs no key. See evaluation/RESULTS.md.")
    return (f"\n\n--- MODE: AI-assisted ({label}) ---\n"
            "Catches unusual hedge wording the rules miss (test half: 3 of 56 missed), but flags some clear\n"
            "statements as uncertain (9-10 of 86) - more cases go to human review. Rule-based mode (--provider rule_based) is deterministic and\n"
            "quiet. See SETUP.md.")


def run_case(cve_id, case, verbose=True):
    case = dict(case)
    case.setdefault("cve_id", cve_id)
    trace = TraceLogger(case_id=cve_id)
    data_layer = case.pop("_data_layer", None)
    if data_layer:
        trace.log(agent="SourceMapper", action="data_layer", input_summary=f"case {cve_id}",
                  output_summary=data_layer, target_agent="Reconciler", status="ok")
    if verbose:
        print(f"\n{'='*70}\nCASE: {cve_id} ({case.get('nickname', '')})\n{'='*70}")

    claims = map_sources(case, trace)

    # Sponsor technology (Meterless): from exactly the same claims that were
    # just produced, builds an entity/edge graph following Meterless'
    # world-model schema - see agents/world_model.py for details on what is
    # taken verbatim and what is our own application of it.
    world_model = build_world_model(case, claims)
    # Real Meterless engine (Node) in addition to the Python reimplementation; without Node everything keeps running without it.
    logs_dir = os.path.dirname(trace.path)
    world_model["engine"] = run_engine(case, claims, mode=os.environ.get("METERLESS_MODE", "auto"), directory=logs_dir)
    engine_events = world_model["engine"].pop("events", [])      # belongs in the JSONL file, not in the JSON summary
    if world_model["engine"]["used"]:
        lines = evidence_jsonl(cve_id, world_model["engine"], engine_events)
        write_text(os.path.join(logs_dir, f"{cve_id}_meterless.jsonl"), "\n".join(json.dumps(l) for l in lines) + "\n")
    world_model_path = os.path.join(os.path.dirname(trace.path), f"{cve_id}_world_model.json")
    write_text(world_model_path, json.dumps(world_model, indent=2))
    trace.log(
        agent="SourceMapper", action="build_world_model (Meterless schema)",
        input_summary=f"{len(claims)} claims for {cve_id}",
        output_summary=world_model_summary(world_model) + f" -> {world_model_path}",
        target_agent="Reconciler", status="ok",
    )
    trace.log(
        agent="SourceMapper", action="meterless_engine",
        input_summary=f"{len(claims)} claims as facts/relations for {cve_id}",
        output_summary=engine_summary(world_model["engine"]),
        target_agent="Reconciler", status="ok" if world_model["engine"]["used"] else "skipped",
    )

    # Process signal: records ONLY which kinds of source were present this
    # time or missing, for the evaluation ACROSS MANY cases (see
    # process_health.py) - separate from the single case report, because it
    # answers a different question (process gap vs. single-case gap).
    record_availability(cve_id, claims)

    draft = decide(cve_id, claims, trace)

    report = write_report(draft, claims, trace)

    blocking = find_blockers(claims, draft)
    steps = [text for _, _, text in blocking]
    report += format_steps(steps)
    report += evidence_trail(world_model["engine"], claims, cve_id)

    process_warnings = check_process_health()
    if process_warnings:
        report += "\n\n--- PROCESS HEALTH (across recent cases, not just this one) ---\n"
        report += "\n".join(process_warnings)
        trace.log(
            agent="ProcessHealth", action="check_process_health",
            input_summary="rolling window of recent cases processed by this tool",
            output_summary=f"{len(process_warnings)} structural warning(s) raised",
            target_agent=None, status="warning",
        )

    from agents.exploitation import report_section
    report += "\n\n" + report_section(case)
    if data_layer:
        report += f"\n\n--- DATA LAYER ---\n{data_layer}"
    report += mode_footer() + failure_note()

    report_path = os.path.join(os.path.dirname(trace.path), f"{cve_id}_report.txt")
    write_text(report_path, report)

    result = build_result(case, claims, draft, steps, os.environ.get("LLM_PROVIDER", "rule_based"), blocking)
    result["engine_used"] = bool(world_model["engine"].get("used"))
    write_text(os.path.join(os.path.dirname(trace.path), f"{cve_id}_result.json"), json.dumps(result, indent=2))

    if verbose:
        print(f"\n--- REPORT ---\n{report}\n")
    return {"cve_id": cve_id, "draft": draft, "report": report, "report_path": report_path,
            "trace_path": trace.path, "world_model_path": world_model_path,
            "result": result, "revisions": draft["revision_count"]}


def apply_data_layer(targets, source):
    """Replace the file-based cases by the same cases read from Zetaris (SQL). 'auto' falls back to the files, openly."""
    from agents.zetaris_client import ZetarisClient, ZetarisError
    from agents.zetaris_sources import load_cases, load_exploitation
    try:
        client = ZetarisClient()
        loaded = load_cases(client, list(targets))
        exploit = load_exploitation(client, list(targets))
        missing = [c for c in targets if c not in loaded]
        if missing:
            raise ZetarisError("not found in Zetaris: " + ", ".join(missing) + " (run setup_zetaris.py and start the data server)")
    except ZetarisError as e:
        if source == "zetaris":
            sys.exit(f"ERROR: {e}")
        print(f"[data] Zetaris not used ({e}); reading the files instead.")
        return {k: {**v, "_data_layer": f"files (Zetaris unavailable: {str(e)[:120]})"} for k, v in targets.items()}
    print(f"[data] {len(loaded)} case(s) read from Zetaris (SQL view vuln.signals).")
    from agents.zetaris_sources import describe_query
    return {k: {**v, **({"exploitation": exploit[k]} if k in exploit else {}), "_data_layer": "Zetaris: " + describe_query([k])}
            for k, v in loaded.items()}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--case", default=None, help="A single CVE ID; if omitted: all")
    parser.add_argument("--data", default=os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "data", "sample", "cases.json"))
    parser.add_argument("--out", default=None, help="Write results as JSON to this path")
    parser.add_argument("--meterless", choices=["auto", "on", "off"], default=None,
                        help="Real Meterless engine (needs Node >= 18): auto = use if possible (default), on = required, off = never")
    parser.add_argument("--provider", choices=["rule_based", "ollama", "nvidia", "anthropic", "openai", "meterless"], default=None,
                        help="Choose the variant without .env: rule_based = no AI (default), ollama = with a local AI")
    parser.add_argument("--with-real", action="store_true", help="Also run the 3 real cases from data/real_world/cases.json (shared ranking)")
    parser.add_argument("--cve", default=None, help="Fetch your own CVE from the NVD (needs internet), e.g. CVE-2021-44228")
    parser.add_argument("--vendor", default=None, help="Text file with the vendor statement for --cve")
    parser.add_argument("--internal", default=None, help="Text file with the internal ticket for --cve")
    parser.add_argument("--nvd-file", default=None, help="Instead of a live fetch: use a saved NVD 2.0 JSON response")
    parser.add_argument("--source", choices=["files", "zetaris", "auto"], default="files",
                        help="Where the three sources are read from: files (default), zetaris (SQL view vuln.signals; error if unreachable), "
                             "auto (Zetaris if reachable, otherwise the files, and the report says so)")
    args = parser.parse_args()
    load_env()
    if args.provider:
        os.environ["LLM_PROVIDER"] = args.provider
    if args.meterless:
        os.environ["METERLESS_MODE"] = args.meterless
    provider = os.environ.get("LLM_PROVIDER", "rule_based")
    origin = ("--provider" if args.provider else
              "environment variable LLM_PROVIDER" if "LLM_PROVIDER" in os.environ else "default")
    hint = ("  <- no AI; add --provider ollama for the AI mode" if provider == "rule_based" else
            "  <- AI mode; add --provider rule_based to run without AI")
    print(f"[mode] {provider} (from {origin}){hint}")

    if args.cve:
        from agents.nvd_fetch import NvdError, fetch_nvd, parse_nvd_response, build_case
        try:
            if args.nvd_file:
                with open(args.nvd_file) as f:
                    raw = json.load(f)
            else:
                raw = fetch_nvd(args.cve, api_key=os.environ.get("NVD_API_KEY"))
            nvd_block = parse_nvd_response(raw, args.cve)
        except NvdError as e:
            sys.exit(f"ERROR: {e}")
        rd = lambda p: open(p, encoding="utf-8").read() if p else None
        cases = {args.cve: build_case(args.cve, nvd_block, rd(args.vendor), rd(args.internal))}
        print("[byo] your own case; missing sources count as unconfirmed, never as certain.")
        targets = cases
    else:
        with open(args.data) as f:
            cases = json.load(f)
        if args.with_real:
            with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "real_world", "cases.json")) as f:
                cases = {**cases, **json.load(f)}
        targets = {args.case: cases[args.case]} if args.case else cases
    if args.source != "files" and not args.cve:
        targets = apply_data_layer(targets, args.source)
    results = [run_case(cve_id, case) for cve_id, case in targets.items()]

    if args.out:
        with open(args.out, "w") as f:
            json.dump(results, f, indent=2)
        print(f"\nResults written to {args.out}")

    used_engine = sum(1 for r in results if r["result"].get("engine_used"))
    manifest = {
        "note": "Which Meterless parts are LIVE (and who reads what they write), which are dormant, and which engines are not mounted. Generated by main.py.",
        "engines_mounted": {"world-model": {
            "implementation": "unmodified Meterless TypeScript reference (Node >= 18), with a Python implementation of the schema as fallback",
            "cases_run_through_engine": used_engine, "cases_total": len(results)}},
        "engines_not_mounted": ["h-mem", "markovian", "scout-intent", "swarm-orchestration"],
        "world_model_parts": [
            {"part": "canonical ingest pipeline (idempotent)", "status": "live",
             "consumed_by": "run record in logs/<CVE>_meterless.jsonl; a re-run appends 0 events (check_meterless_bridge.py)"},
            {"part": "facts + conflict policy source-priority (internal > NVD > vendor)", "status": "live",
             "consumed_by": "EVIDENCE TRAIL section of every report; 'Meterless engine' panel in viewer.html"},
            {"part": "append log + audit trail as JSONL", "status": "live", "consumed_by": "logs/<CVE>_meterless.jsonl (every event with its source)"},
            {"part": "local persistence, resume, corruption recovery, derived state rebuilt from the log", "status": "live",
             "consumed_by": "every re-run (one stored world per evidence state)"},
            {"part": "time-travel query (entityAt)", "status": "live in timelines only", "consumed_by": "time-travel check in agents/timeline.py"},
            {"part": "stable content-hash entity IDs", "status": "live", "consumed_by": "ID parity check per case against the Python port"},
            {"part": "context builder, enrichment queue, merge queue, control plane", "status": "dormant", "note": "not used in this build"},
        ],
    }
    write_text(os.path.join(os.path.dirname(results[0]["trace_path"]), "meterless_manifest.json"), json.dumps(manifest, indent=2))

    if len(results) > 1:
        ranked = rank([r["result"] for r in results])
        write_text(os.path.join(os.path.dirname(results[0]["trace_path"]), "triage.json"), json.dumps(ranked, indent=2))
        print(format_table(ranked))

    # Timelines (data/sample/timelines.json) for the processed cases, if present
    try:
        timelines = load_timelines(os.path.join(os.path.dirname(args.data), "timelines.json"))
    except TimelineError as e:
        print(f"WARNING: {e}", file=sys.stderr)
        timelines = {}
    for tl_id in targets:
        if tl_id not in timelines:
            continue
        try:
            tl = build_timeline(tl_id, timelines[tl_id], cases, mode=os.environ.get("METERLESS_MODE", "auto"))
        except TimelineError as e:
            print(f"WARNING: {e}", file=sys.stderr)
            continue
        write_text(os.path.join(os.path.dirname(results[0]["trace_path"]), f"{tl_id}_timeline.json"), json.dumps(tl, indent=2))
        print(format_timeline(tl))

    print(f"\n{len(results)} case(s) processed. Logs are in logs/.")


if __name__ == "__main__":
    main()
