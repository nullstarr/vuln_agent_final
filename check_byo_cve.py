#!/usr/bin/env python3
"""Checks the bring-your-own-CVE mode offline (fixture). With --live additionally a real NVD fetch (needs internet)."""
import json, os, subprocess, sys, tempfile
here = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, here)
from agents.nvd_fetch import NvdError, parse_nvd_response, build_case, fetch_nvd
ok = 0; total = 0
def check(name, cond):
    global ok, total
    total += 1; ok += bool(cond); print(("PASS " if cond else "FAIL ") + name)
fx = json.load(open(os.path.join(here, "data/fixtures/nvd_sample_response.json")))
b = parse_nvd_response(fx, "CVE-2021-44228")
check("parse: score/severity/vector", (b["cvss_v3_score"], b["severity"], b["attack_vector"]) == (10.0, "CRITICAL", "network"))
check("parse: English description", b["description"].startswith("Apache Log4j2"))
try: parse_nvd_response(fx, "CVE-2000-0001"); check("wrong ID is rejected", False)
except NvdError: check("wrong ID is rejected", True)
try: fetch_nvd("log4shell"); check("invalid ID is rejected", False)
except NvdError: check("invalid ID is rejected", True)
c = build_case("CVE-2021-44228", b, "vendor says fine")
check("missing ticket stays missing", "internal_ticket" not in c["sources"])
env = dict(os.environ, LLM_PROVIDER="rule_based")
def run(*a):
    return subprocess.run([sys.executable, os.path.join(here, "main.py"), "--meterless", "off", *a], capture_output=True, text=True, env=env, cwd=here)
r = run("--cve", "CVE-2021-44228", "--nvd-file", os.path.join(here, "data/fixtures/nvd_sample_response.json"),
        "--vendor", os.path.join(here, "input_examples/byo_vendor.txt"), "--internal", os.path.join(here, "input_examples/byo_internal.txt"))
check("main.py --cve runs (fixture, vendor+ticket)", r.returncode == 0 and "unresolved" in r.stdout.lower())
r2 = run("--cve", "CVE-2021-44228", "--nvd-file", os.path.join(here, "data/fixtures/nvd_sample_response.json"))
check("NVD only: never 'resolved'", r2.returncode == 0 and "unresolved" in r2.stdout.lower())
if "--live" in sys.argv:
    try:
        live = parse_nvd_response(fetch_nvd("CVE-2021-44228"), "CVE-2021-44228")
        check("LIVE: NVD fetch + parser", live["cvss_v3_score"] == 10.0)
    except NvdError as e:
        check(f"LIVE: {e}", False)
print(f"{ok}/{total} passed"); sys.exit(0 if ok == total else 1)
