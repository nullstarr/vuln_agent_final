"""Serves the three evidence sources as JSON, so Zetaris can register them as REST tables.

    GET /nvd      -> {"items": [ {cve_id, severity, description, ...}, ... ]}
    GET /vendor   -> {"items": [ {cve_id, text, ...}, ... ]}
    GET /tickets  -> {"items": [ {cve_id, text, ...}, ... ]}
    GET /exploitation -> {"items": [ {cve_id, exploited_in_wild, source_name, ...}, ... ]}   (urgency signal, not evidence)

The records come from data/sample/cases.json and data/real_world/cases.json (the same files the tool reads without Zetaris).
Synthetic records keep their 'note' field saying so. Runs inside Docker next to Zetaris (docker-compose.data.yml).
"""
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.environ.get("APP_ROOT", os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, ROOT)
from agents.zetaris_sources import flatten_cases, flatten_exploitation  # noqa: E402


def load_all(root=ROOT):
    cases = {}
    for rel in ("data/sample/cases.json", "data/real_world/cases.json"):
        with open(os.path.join(root, rel), encoding="utf-8") as f:
            d = json.load(f)
        cases.update(d if isinstance(d, dict) else {c["cve_id"]: c for c in d})
    return cases


def make_handler(cases):
    nvd, vendor, tickets = flatten_cases(cases)
    routes = {"/nvd": nvd, "/vendor": vendor, "/tickets": tickets, "/exploitation": flatten_exploitation(cases)}

    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            path = self.path.split("?")[0].rstrip("/")
            if path in routes:
                body = json.dumps({"items": routes[path]}).encode()
                self.send_response(200)
            else:
                body = b'{"error":"not found"}'
                self.send_response(404)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass
    return H


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8000"))
    ThreadingHTTPServer(("0.0.0.0", port), make_handler(load_all())).serve_forever()
