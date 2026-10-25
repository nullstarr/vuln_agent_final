"""
Robustness: what happens when a service is down. Offline; nothing is called for real.
  1. An AI provider that raises (down, bad key, no answer): the run goes on with the rules, nothing crashes, the failure is
     counted, and the report says so (never a silent fallback).
  2. Zetaris unreachable: --source zetaris stops with a clear message; --source auto falls back to the files and says so.
"""
import contextlib
import io
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
PASS, FAIL = [], []


def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print(("PASS " if ok else "FAIL ") + name + (f"  [{detail}]" if detail and not ok else ""))


import main as app
from agents import llm_provider as lp, source_mapper as sm

# 1. provider failure -> rules, openly
def boom(*a, **k):
    raise ConnectionError("service unreachable")

lp._complete = boom
os.environ["LLM_PROVIDER"] = "nvidia"
lp.FAILURES.clear(); lp._WARNED[0] = False
buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    out = lp.complete("s", "u")
check("a failing provider returns None instead of raising", out is None)
check("the failure is counted with its reason", sum(lp.FAILURES.values()) == 1 and "ConnectionError" in next(iter(lp.FAILURES)))
check("a warning is printed once", buf.getvalue().count("[warning]") == 1)
buf2 = io.StringIO()
with contextlib.redirect_stdout(buf2):
    lp.complete("s", "u")
check("the warning is not repeated for every call", "[warning]" not in buf2.getvalue() and sum(lp.FAILURES.values()) == 2)
with contextlib.redirect_stdout(io.StringIO()):
    c, reason, method = sm.assess_certainty("internal_ticket", "Two of the five clusters are patched; the rest is pending.", "internal_ticket")
check("certainty falls back to the rules and stays careful (low)", c == "low" and "llm" not in method.replace("implicit", ""), f"{c}/{method}")
check("the report carries an AI PROVIDER PROBLEM note", "AI PROVIDER PROBLEM" in app.failure_note() and "ConnectionError" in app.failure_note())
lp.FAILURES.clear()
check("no note when nothing failed", app.failure_note() == "")

# a whole case still runs with a dead provider
import json
cases = json.load(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "sample", "cases.json")))
with contextlib.redirect_stdout(io.StringIO()):
    r = app.run_case("CVE-2021-44228", cases["CVE-2021-44228"], verbose=False)
check("a full case runs to the same conclusion with a dead provider", r["draft"]["resolved"] is False, str(r["draft"])[:100])
check("and its report names the problem", "AI PROVIDER PROBLEM" in r["report"])

# 2. Zetaris down
os.environ.update(LLM_PROVIDER="rule_based", ZETARIS_REST_URL="http://127.0.0.1:9", ZETARIS_API_KEY="x", ZETARIS_ORG_ID="1")
t = {"CVE-2021-44228": cases["CVE-2021-44228"]}
try:
    with contextlib.redirect_stdout(io.StringIO()):
        app.apply_data_layer(t, "zetaris"); strict = False
except SystemExit as e:
    strict = "Zetaris" in str(e)
check("--source zetaris with Zetaris down stops with a clear message", strict)
with contextlib.redirect_stdout(io.StringIO()):
    got = app.apply_data_layer(t, "auto")
check("--source auto falls back to the files and says so", got["CVE-2021-44228"]["_data_layer"].startswith("files (Zetaris unavailable"))

print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
sys.exit(1 if FAIL else 0)
