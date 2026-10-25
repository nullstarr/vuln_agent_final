"""
Checks the NVIDIA provider logic (throttling, retry on HTTP 429, reasoning-model handling) with a FAKE `openai` module.
It proves our handling, not that NVIDIA behaves this way; the live behaviour was seen on 23 Oct 2026 (HTTP 429 after ~40 calls,
`content: null` with thinking on, `HIGH` with thinking off).
"""
import os
import sys
import types

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
PASS, FAIL = [], []


def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print(("PASS " if ok else "FAIL ") + name + (f"  [{detail}]" if detail and not ok else ""))


class RateLimitError(Exception):
    pass


calls, script = [], []


class _Msg:
    def __init__(self, c): self.content = c


class _Choice:
    def __init__(self, c): self.message = _Msg(c)


class _Resp:
    def __init__(self, c, model="nvidia/fake-model"):
        self.choices = [_Choice(c)]; self.model = model


class _Completions:
    def create(self, **kw):
        calls.append(kw)
        item = script.pop(0)
        if item == "429":
            raise RateLimitError("429")
        return _Resp(item)


class _Client:
    def __init__(self, **kw):
        self.chat = types.SimpleNamespace(completions=_Completions())


fake = types.ModuleType("openai")
fake.OpenAI, fake.RateLimitError = _Client, RateLimitError
sys.modules["openai"] = fake
from agents import llm_provider as lp

sleeps = []
lp.time.sleep = lambda s: sleeps.append(s)
os.environ.update(LLM_PROVIDER="nvidia", NVIDIA_API_KEY="k", NVIDIA_MODEL="nvidia/fake-model")

script[:] = ["HIGH\nok"]; lp.SERVED.clear()
os.environ["NVIDIA_ENABLE_THINKING"] = "false"
out = lp.complete("s", "u")
check("plain answer returned", out == "HIGH\nok")
check("thinking switched off -> extra_body chat_template_kwargs.enable_thinking=false", calls[-1].get("extra_body") == {"chat_template_kwargs": {"enable_thinking": False}})
check("answering model recorded", lp.SERVED.get("nvidia -> nvidia/fake-model") == 1, str(dict(lp.SERVED)))

del os.environ["NVIDIA_ENABLE_THINKING"]
calls.clear(); script[:] = ["x"]; lp.complete("s", "u")
check("thinking not touched unless asked", "extra_body" not in calls[-1])

script[:] = [None]
try:
    lp._complete("s", "u"); msg = ""
except ValueError as e:
    msg = str(e)
check("content null (reasoning ran out) -> clear error naming the two fixes", "NVIDIA_MAX_TOKENS" in msg and "NVIDIA_ENABLE_THINKING" in msg, msg)

sleeps.clear(); calls.clear(); script[:] = ["429", "429", "HIGH"]
out = lp.complete("s", "u")
check("HTTP 429 is retried with waiting, then succeeds", out == "HIGH" and len(calls) == 3 and sum(s for s in sleeps if s >= 15) >= 45, f"{len(calls)} calls, sleeps {sleeps}")

calls.clear(); script[:] = ["429"] * 6
try:
    lp._complete("s", "u"); gave_up = False
except RateLimitError:
    gave_up = True
check("after 6 tries the rate-limit error is raised by the provider", gave_up and len(calls) == 6)
calls.clear(); script[:] = ["429"] * 6; lp.FAILURES.clear()
check("...and the public call degrades to None and records the failure", lp.complete("s", "u") is None and sum(lp.FAILURES.values()) == 1)

script[:] = ["a", "b"]; lp._LAST_NVIDIA_CALL[0] = 0
lp.complete("s", "u"); sleeps.clear(); lp.complete("s", "u")
check("calls are spaced by NVIDIA_MIN_INTERVAL", any(0 < s <= 1.6 for s in sleeps), str(sleeps))

print(f"\n{len(PASS)} passed, {len(FAIL)} failed (fake openai module)")
sys.exit(1 if FAIL else 0)
