"""
Meterless Runtime as an AI provider (LLM_PROVIDER=meterless).

Implements the contract of Meterless' official "Add Meterless as a provider" prompt (meterless.ai/engines.html, POWER):
  - provider id `meterless`, default base URL http://127.0.0.1:8088/v1 (pasted URLs are normalised to <host>/v1)
  - POST /v1/chat/completions (OpenAI-compatible), GET /v1/models for discovery, /healthz only shows the process is up
  - every call: Authorization: Bearer <runtime token>, header `meterless-app` (stable lowercase app id);
    chat calls also `meterless-scope: user`; the placeholder token `rt-local` is rejected
  - model ids are routing MODES (meterless/auto, meterless/fast, ...), not model names; unknown meterless/* ids are kept
  - /v1/models decides the state: 401/403 -> "unauthorized", 200 with meterless/* ids -> "online", anything else -> "offline"
  - plain text stays a string; timeout 180 s (model loads can take minutes); the token is never logged

Settings (environment / .env): METERLESS_BASE_URL, METERLESS_RUNTIME_TOKEN, METERLESS_MODEL (default meterless/auto).
STATUS: verified against a stand-in server that follows this contract (check_meterless_runtime.py). Not run against a real
Meterless Runtime: Nightshift has no Linux x86_64 build (organizers' answer, 23 Oct 2026).
"""
import json
import os
import re
import urllib.error
import urllib.request

APP_ID = "vuln-conflict-resolver"
DEFAULT_BASE = "http://127.0.0.1:8088/v1"
PROBE_PORTS = (8088, 8090, 8787, 11434)
PROBE_HOSTS = ("127.0.0.1", "localhost", "[::1]")
_SUFFIXES = ("/v1/chat/completions", "/v1/models", "/healthz", "/v1")


class MeterlessError(Exception):
    pass


def normalize_base_url(url):
    """Any of host:port, http://host:port, .../v1, .../v1/models, .../healthz -> http://host:port/v1 (never /v1/v1)."""
    u = (url or "").strip()
    if not u:
        return DEFAULT_BASE
    if not re.match(r"^[a-z][a-z0-9+.-]*://", u, re.I):
        u = "http://" + u
    u = u.split("#")[0].split("?")[0].rstrip("/")
    changed = True
    while changed:
        changed = False
        for suf in _SUFFIXES:
            if u.endswith(suf):
                u = u[: -len(suf)].rstrip("/")
                changed = True
    return u + "/v1"


def parse_connect_link(link):
    """http://host:port/connect#k=KEY -> (base_url, key). The key must never be logged."""
    m = re.match(r"^(https?://[^/#?]+)/connect#k=(.+)$", (link or "").strip())
    if not m:
        raise MeterlessError("not a Meterless connect link (expected http://<host>:<port>/connect#k=<key>)")
    return normalize_base_url(m.group(1)), m.group(2)


def _token(token=None):
    t = (token or os.environ.get("METERLESS_RUNTIME_TOKEN", "")).strip()
    if not t or t in ("rt-local", "your-nightshift-runtime-token", "your-runtime-token") or t.startswith("<"):
        raise MeterlessError("METERLESS_RUNTIME_TOKEN is missing or a placeholder. Copy the real Runtime access token from "
                             "the Nightshift Console (the placeholder 'rt-local' is rejected).")
    return t


def _headers(token, chat=False):
    h = {"Authorization": "Bearer " + token, "meterless-app": APP_ID, "Content-Type": "application/json"}
    if chat:
        h["meterless-scope"] = "user"
    return h


def _request(url, token, body=None, chat=False, timeout=180):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, headers=_headers(token, chat), method="POST" if body is not None else "GET")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def runtime_state(base_url=None, token=None, timeout=10):
    """Returns (state, model_ids): state is 'online', 'unauthorized' or 'offline'."""
    base = normalize_base_url(base_url or os.environ.get("METERLESS_BASE_URL"))
    try:
        payload = _request(base + "/models", _token(token), timeout=timeout)
    except MeterlessError:
        raise
    except urllib.error.HTTPError as e:
        return ("unauthorized" if e.code in (401, 403) else "offline"), []
    except (urllib.error.URLError, OSError, TimeoutError, ValueError):
        return "offline", []
    ids = [m.get("id", "") for m in (payload.get("data") or []) if isinstance(m, dict)]
    ids = [i for i in ids if str(i).startswith("meterless/")]
    return ("online" if ids else "offline"), ids


def auto_detect(token=None, timeout=1.5):
    """Probe the usual local ports; return the first base URL that is online or unauthorized (else None)."""
    for host in PROBE_HOSTS:
        for port in PROBE_PORTS:
            base = f"http://{host}:{port}/v1"
            try:
                state, _ = runtime_state(base, token or "probe", timeout=timeout)
            except MeterlessError:
                continue
            if state in ("online", "unauthorized"):
                return base
    return None


def chat(system_prompt, user_prompt, model=None, base_url=None, token=None, timeout=180):
    """One chat request. Returns (text, served_model); served_model is what the Runtime reports it used."""
    base = normalize_base_url(base_url or os.environ.get("METERLESS_BASE_URL"))
    tok = _token(token)
    model = model or os.environ.get("METERLESS_MODEL", "meterless/auto")
    body = {"model": model, "temperature": 0, "max_tokens": 600,
            "messages": [{"role": "system", "content": system_prompt}, {"role": "user", "content": user_prompt}]}
    try:
        payload = _request(base + "/chat/completions", tok, body, chat=True, timeout=timeout)
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            raise MeterlessError("Meterless Runtime says unauthorized: check METERLESS_RUNTIME_TOKEN (copy it from the Nightshift Console)") from None
        raise MeterlessError(f"Meterless Runtime returned HTTP {e.code}: {e.read().decode('utf-8', 'replace')[:200]}") from None
    except (urllib.error.URLError, OSError, TimeoutError) as e:
        raise MeterlessError(f"Meterless Runtime offline at {base}: {getattr(e, 'reason', e)} (is Nightshift running?)") from None
    except ValueError:
        raise MeterlessError("Meterless Runtime returned a reply that is not JSON") from None
    try:
        text = payload["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError):
        raise MeterlessError("Meterless Runtime reply has no choices[0].message.content") from None
    if not isinstance(text, str):
        raise MeterlessError("Meterless Runtime returned non-text content")
    return text, str(payload.get("model") or model)
