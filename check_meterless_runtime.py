"""
Checks the Meterless Runtime provider (LLM_PROVIDER=meterless) against a STAND-IN server that follows the contract of
Meterless' official "Add Meterless as a provider" prompt. It proves our client obeys that contract (URL normalisation,
headers, token rules, model discovery, states, plain-text content, which model answered). It does NOT prove that a real
Meterless Runtime behaves the same: no Linux x86_64 Nightshift build exists, so none could be run here.

    python3 check_meterless_runtime.py
    python3 check_meterless_runtime.py --live   # against a real Runtime from .env (METERLESS_BASE_URL / METERLESS_RUNTIME_TOKEN)
"""
import contextlib
import io
import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ["METERLESS_MODE"] = "off"
from agents import llm_provider, meterless_runtime as mr
from agents.envfile import load_env

PASS, FAIL = [], []
GOOD = "token-for-the-stand-in-only"


def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print(("PASS " if ok else "FAIL ") + name + (f"  [{detail}]" if detail and not ok else ""))


class StandIn(BaseHTTPRequestHandler):
    log = []
    models = [{"id": "meterless/auto"}, {"id": "meterless/fast"}, {"id": "meterless/custom-lane"}, {"id": "other/x"}]

    def _auth(self):
        return self.headers.get("Authorization") == "Bearer " + GOOD

    def do_GET(self):
        StandIn.log.append(("GET", self.path, dict(self.headers), None))
        if self.path == "/healthz":
            return self._send(200, {"ok": True})
        if not self._auth():
            return self._send(401, {"error": "unauthorized"})
        if self.path == "/v1/models":
            return self._send(200, {"data": StandIn.models})
        self._send(404, {})

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        StandIn.log.append(("POST", self.path, dict(self.headers), body))
        if not self._auth():
            return self._send(401, {"error": "unauthorized"})
        if self.path == "/v1/chat/completions":
            return self._send(200, {"model": "stand-in-model", "choices": [{"message": {"role": "assistant", "content": "HIGH\nstand-in answer"}}]})
        self._send(404, {})

    def _send(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)

    def log_message(self, *a):
        pass


def offline():
    # URL normalisation
    cases = {"localhost:8088": "http://localhost:8088/v1", "http://127.0.0.1:8088": "http://127.0.0.1:8088/v1",
             "http://127.0.0.1:8088/v1": "http://127.0.0.1:8088/v1", "http://h:1/v1/chat/completions": "http://h:1/v1",
             "http://h:1/v1/models": "http://h:1/v1", "http://h:1/healthz": "http://h:1/v1", "http://h:1/v1/": "http://h:1/v1", "": mr.DEFAULT_BASE}
    bad = {k: mr.normalize_base_url(k) for k, v in cases.items() if mr.normalize_base_url(k) != v}
    check("URL normalisation: host, /v1, /v1/models, /v1/chat/completions, /healthz -> <host>/v1", not bad, str(bad))
    check("URL normalisation never produces /v1/v1", "/v1/v1" not in mr.normalize_base_url("http://h:1/v1/v1"))

    # token rules
    for t in ("rt-local", "", "your-nightshift-runtime-token"):
        try:
            mr._token(t); ok = False
        except mr.MeterlessError:
            ok = True
        check(f"token {t!r} is rejected as a placeholder", ok)

    # connect link
    base, key = mr.parse_connect_link("http://10.0.0.5:8088/connect#k=SECRET123")
    check("connect link -> base URL and key", base == "http://10.0.0.5:8088/v1" and key == "SECRET123")
    try:
        mr.parse_connect_link("http://x/y"); ok = False
    except mr.MeterlessError:
        ok = True
    check("a string that is not a connect link is refused", ok)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), StandIn)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{srv.server_address[1]}"
    try:
        state, ids = mr.runtime_state(url, GOOD)
        check("online: /v1/models with the right token lists meterless/* ids", state == "online" and "meterless/auto" in ids, f"{state} {ids}")
        check("unknown meterless/* ids are kept, non-meterless ids are dropped", "meterless/custom-lane" in ids and "other/x" not in ids)
        state, _ = mr.runtime_state(url, "wrong-token")
        check("wrong token -> 'unauthorized' (not 'offline')", state == "unauthorized", state)
        state, _ = mr.runtime_state("http://127.0.0.1:9", GOOD, timeout=2)
        check("nothing listening -> 'offline'", state == "offline", state)

        text, served = mr.chat("sys", "user text", base_url=url, token=GOOD)
        check("chat returns a plain string and the model the service reports", text == "HIGH\nstand-in answer" and served == "stand-in-model", f"{text!r} {served!r}")
        m, p, h, body = [e for e in StandIn.log if e[0] == "POST"][-1]
        h = {k.lower(): v for k, v in h.items()}
        check("chat request: path /v1/chat/completions, model meterless/auto", p == "/v1/chat/completions" and body["model"] == "meterless/auto", f"{p} {body.get('model')}")
        check("chat request: Bearer token, meterless-app, meterless-scope: user",
              h.get("authorization") == "Bearer " + GOOD and h.get("meterless-app") == mr.APP_ID and h.get("meterless-scope") == "user")
        check("chat request: messages are plain strings (system + user)", all(isinstance(x["content"], str) for x in body["messages"]) and [x["role"] for x in body["messages"]] == ["system", "user"])
        g = [e for e in StandIn.log if e[0] == "GET" and e[1] == "/v1/models"][-1]
        check("model discovery carries meterless-app and the token", {k.lower(): v for k, v in g[2].items()}.get("meterless-app") == mr.APP_ID)
        try:
            mr.chat("s", "u", base_url=url, token="wrong-token"); msg = ""
        except mr.MeterlessError as e:
            msg = str(e)
        check("chat with a wrong token -> readable 'unauthorized' error", "unauthorized" in msg and "wrong-token" not in msg, msg)

        # through the provider switch and a full case
        os.environ.update(LLM_PROVIDER="meterless", METERLESS_BASE_URL=url, METERLESS_RUNTIME_TOKEN=GOOD)
        llm_provider.SERVED.clear()
        out = llm_provider.complete("s", "u")
        check("LLM_PROVIDER=meterless works through llm_provider.complete", out == "HIGH\nstand-in answer")
        check("which model answered is recorded", llm_provider.SERVED.get("meterless -> stand-in-model") == 1, str(dict(llm_provider.SERVED)))
        import main as app
        import json as _j
        cases = _j.load(open("data/sample/cases.json"))
        with contextlib.redirect_stdout(io.StringIO()):
            res = app.run_case("CVE-2021-44228", dict(cases["CVE-2021-44228"]), verbose=False)
        check("a full case runs with the Meterless provider and the report names the answering model",
              "answered by: meterless -> stand-in-model" in res["report"], res["report"][-300:])
    finally:
        srv.shutdown()
        os.environ["LLM_PROVIDER"] = "rule_based"
    try:
        os.environ["METERLESS_BASE_URL"] = "http://127.0.0.1:9"
        mr.chat("s", "u", token=GOOD, timeout=2); msg = ""
    except mr.MeterlessError as e:
        msg = str(e)
    check("Runtime not running -> 'offline ... is Nightshift running?'", "offline" in msg and "Nightshift" in msg, msg)


def live():
    load_env()
    state, ids = mr.runtime_state()
    check(f"LIVE: Runtime state is online ({state})", state == "online", str(ids))
    text, served = mr.chat("Reply with one word.", "Say: ready")
    check(f"LIVE: a chat request returns text (served by {served})", bool(text.strip()))


if __name__ == "__main__":
    try:
        live() if "--live" in sys.argv else offline()
    except mr.MeterlessError as e:
        FAIL.append(str(e)); print("FAIL", e)
    print(f"\n{len(PASS)} passed, {len(FAIL)} failed" + (" (live)" if "--live" in sys.argv else " (stand-in server, see header)"))
    sys.exit(1 if FAIL else 0)
