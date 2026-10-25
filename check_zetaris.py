"""
Checks the Zetaris data layer.

Default (offline): uses a STAND-IN server that mimics Zetaris' REST reply ({"data": [[...rows...]]}) and the
request rules from the Participant Setup Guide. This proves our code (request shape, SQL, row -> case, fallback,
errors), NOT that a real Zetaris accepts our setup SQL.

    python3 check_zetaris.py          # offline, no Zetaris needed
    python3 check_zetaris.py --live   # against the real instance in .env (after setup_zetaris.py --run)
"""
import json
import os
import sys
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault("LLM_PROVIDER", "rule_based")
os.environ["METERLESS_MODE"] = "off"

from agents.envfile import load_env
from agents.zetaris_client import ZetarisClient, ZetarisError
from agents.zetaris_sources import SIGNAL_COLS, NVD_COLS, TEXT_COLS, flatten_cases, load_cases, case_from_row
from integrations.zetaris.data_server import load_all, make_handler
from agents.exploitation import COLS as EXPLOIT_COLS
from agents.zetaris_sources import flatten_exploitation, load_exploitation
from integrations.zetaris.setup_statements import STATEMENTS
os.environ["LLM_PROVIDER"] = "rule_based"   # the data-path comparison must not depend on a language model
import main as app

PASS, FAIL = [], []


def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print(("PASS " if ok else "FAIL ") + name + (f"  [{detail}]" if detail and not ok else ""))


def exploit_rows(cases):
    return [[r.get(c) for c in EXPLOIT_COLS] for r in flatten_exploitation(cases)]


def rows_from_cases(cases):
    """What the SQL view vuln.signals would return: NVD LEFT JOIN vendor LEFT JOIN ticket."""
    nvd, vendor, ticket = flatten_cases(cases)
    v = {r["cve_id"]: r for r in vendor}
    t = {r["cve_id"]: r for r in ticket}
    out = []
    for n in nvd:
        row = [n.get("cve_id"), n.get("nickname"), n.get("as_of")] + [n.get(c) for c in NVD_COLS[3:]]
        for src in (v.get(n["cve_id"], {}), t.get(n["cve_id"], {})):
            row += [src.get(c) for c in TEXT_COLS[1:]]
        out.append(row)
    return out


class Stand_in(BaseHTTPRequestHandler):
    seen = []
    rows = []
    exploit = []
    mode = "ok"

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        Stand_in.seen.append((self.path, dict(self.headers), body))
        if Stand_in.mode == "401":
            self.send_response(401); self.end_headers(); self.wfile.write(b'{"message":"bad key"}'); return
        sql = body["sql"]
        rows = Stand_in.exploit if "FROM vuln.exploit_entries" in sql else Stand_in.rows
        if "WHERE cve_id IN" in sql:
            import re as _re
            ids = _re.findall(r"'(CVE-[^']+)'", sql.split("WHERE cve_id IN", 1)[1])
            rows = [r for r in rows if r[0] in ids]
        if sql.strip() == "SELECT 1":
            rows = [[1]]
        data = json.dumps({"data": rows}).encode()
        self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers(); self.wfile.write(data)

    def log_message(self, *a):
        pass


def serve(handler):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


def quiet_run(cid, case):
    import contextlib, io
    with contextlib.redirect_stdout(io.StringIO()):
        return app.run_case(cid, case, verbose=False)


def verdict(res):
    r = res["result"]
    return {k: r.get(k) for k in sorted(r) if k not in ("engine_used",)}


def offline():
    cases = load_all()
    check("17 cases available as source", len(cases) == 17, str(len(cases)))

    # setup statements
    check("11 setup statements, none ends with ';'", len(STATEMENTS) == 11 and not any(s.rstrip().endswith(";") for s in STATEMENTS))
    check("signals view uses LEFT JOIN for vendor and ticket", "LEFT JOIN vuln.vendor_entries" in STATEMENTS[-1] and "LEFT JOIN vuln.ticket_entries" in STATEMENTS[-1])

    # data server
    srv, base = serve(make_handler(cases))
    try:
        got = {p: json.loads(urllib.request.urlopen(base + p).read())["items"] for p in ("/nvd", "/vendor", "/tickets", "/exploitation")}
        check("data server: /exploitation has 6 records", len(got["/exploitation"]) == 6, str(len(got["/exploitation"])))
        check("data server: /nvd has 17 records, /vendor and /tickets 15", len(got["/nvd"]) == 17 and len(got["/vendor"]) == 15 and len(got["/tickets"]) == 15,
              str({k: len(v) for k, v in got.items()}))
        try:
            urllib.request.urlopen(base + "/nope"); code = 200
        except urllib.error.HTTPError as e:
            code = e.code
        check("data server: unknown path -> 404", code == 404)
    finally:
        srv.shutdown()

    # client against stand-in
    Stand_in.rows = rows_from_cases(cases)
    Stand_in.exploit = exploit_rows(cases)
    srv, base = serve(Stand_in)
    try:
        client = ZetarisClient(base, "1", "test-key")
        check("SELECT 1 returns [[1]]", client.run_sql("SELECT 1") == [[1]])
        path, headers, body = Stand_in.seen[-1]
        h = {k.lower(): v for k, v in headers.items()}
        check("request: path /sql-editor/sqls/run", path == "/sql-editor/sqls/run", path)
        check("request: Bearer key, X-Org-ID, fresh X-Request-ID",
              h.get("authorization") == "Bearer test-key" and h.get("x-org-id") == "1" and len(h.get("x-request-id", "")) == 36)
        check("request: body has queryId, sql, source, limit", all(k in body for k in ("queryId", "sql", "source", "limit")))

        loaded = load_cases(client)
        check("load_cases reads 17 cases", len(loaded) == 17, str(len(loaded)))
        check("SQL selects the view in fixed column order", f"FROM vuln.signals ORDER BY cve_id" in Stand_in.seen[-1][2]["sql"] and
              Stand_in.seen[-1][2]["sql"].startswith("SELECT cve_id, nickname, as_of"))
        # same content as the files
        same = all(loaded[c]["sources"].keys() == cases[c]["sources"].keys() for c in cases)
        check("every case has the same source keys as in the files (absent source stays absent)", same)
        text_same = all((loaded[c]["sources"].get("vendor_changelog") or {}).get("text") == (cases[c]["sources"].get("vendor_changelog") or {}).get("text")
                        for c in cases)
        check("vendor and ticket texts identical to the files", text_same)

        # one case selected
        one = load_cases(client, ["CVE-2021-44228"])
        check("WHERE cve_id IN (...) selects one case", list(one) == ["CVE-2021-44228"])
        try:
            load_cases(client, ["CVE-2021-44228'; DROP VIEW x"]); inj = False
        except ZetarisError:
            inj = True
        check("a non-CVE id is rejected before it reaches SQL", inj)

        # outcome equivalence: same decision from Zetaris data as from the files
        exploit = load_exploitation(client)
        check("exploitation: 6 rows, SQL reads vuln.exploit_entries", len(exploit) == 6 and "FROM vuln.exploit_entries ORDER BY cve_id" in Stand_in.seen[-1][2]["sql"], str(len(exploit)))
        check("exploitation: booleans survive the round trip (True/False, not strings)",
              exploit["CVE-2021-44228"]["exploited_in_wild"] is True and exploit["CVE-2024-7001"]["exploited_in_wild"] is False)
        check("a case without a row has no signal (unknown, not 'safe')", "CVE-2023-0001" not in exploit)
        diffs = []
        for cid in cases:
            a = quiet_run(cid, dict(cases[cid]))
            via = {**loaded[cid], **({"exploitation": exploit[cid]} if cid in exploit else {})}
            b = quiet_run(cid, via)
            if verdict(a) != verdict(b):
                diffs.append(cid)
        check("all 17 cases: identical result (incl. exploitation signal) from Zetaris rows and from files", not diffs, ", ".join(diffs))

        # wrong width
        try:
            case_from_row([1, 2, 3]); w = False
        except ZetarisError:
            w = True
        check("row with the wrong number of columns -> clear error", w)

        # --source auto falls back openly; zetaris is strict
        os.environ.update(ZETARIS_REST_URL=base, ZETARIS_ORG_ID="1", ZETARIS_API_KEY="k")
        t = app.apply_data_layer({"CVE-2021-44228": cases["CVE-2021-44228"]}, "auto")
        check("--source auto with Zetaris up: uses Zetaris", t["CVE-2021-44228"]["_data_layer"].startswith("Zetaris"))
        dl = t["CVE-2021-44228"]["_data_layer"]
        check("report text names the view, the three tables and the query", all(x in dl for x in ("vuln.signals", "vuln.nvd_entries", "vuln.vendor_entries", "vuln.ticket_entries", "WHERE cve_id IN ('CVE-2021-44228')")), dl[:200])
        Stand_in.mode = "401"
        t = app.apply_data_layer({"CVE-2021-44228": cases["CVE-2021-44228"]}, "auto")
        check("--source auto with a rejected key: falls back and says so", t["CVE-2021-44228"]["_data_layer"].startswith("files (Zetaris unavailable"))
        try:
            app.apply_data_layer({"CVE-2021-44228": cases["CVE-2021-44228"]}, "zetaris"); strict = False
        except SystemExit:
            strict = True
        check("--source zetaris with a rejected key: stops, no silent fallback", strict)
        try:
            ZetarisClient(base, "1", "k").run_sql("SELECT 1"); e401 = ""
        except ZetarisError as e:
            e401 = str(e)
        check("401 gives a readable message with the fix", "401" in e401 and "API key" in e401, e401)
        Stand_in.mode = "ok"
    finally:
        srv.shutdown()

    try:
        ZetarisClient("http://127.0.0.1:9", "1", "k", timeout=3).run_sql("SELECT 1"); down = ""
    except ZetarisError as e:
        down = str(e)
    check("unreachable server -> 'not reachable' message", "not reachable" in down, down)
    saved = {k: os.environ.pop(k) for k in ("ZETARIS_REST_URL", "ZETARIS_ORG_ID", "ZETARIS_API_KEY") if k in os.environ}
    try:
        ZetarisClient(); unconf = ""
    except ZetarisError as e:
        unconf = str(e)
    os.environ.update(saved)
    check("missing settings -> names the missing variables", "ZETARIS_API_KEY" in unconf, unconf)


def live():
    os.environ["LLM_PROVIDER"] = "rule_based"   # compare data paths only; a language model would vary between runs
    load_env()
    client = ZetarisClient()
    check("LIVE: SELECT 1", str(client.run_sql("SELECT 1")[0][0]) == "1")
    dbs = client.run_sql("SHOW LIGHTNING DATABASES")
    check("LIVE: database VULN_SIGNALS exists", any("VULN_SIGNALS" in str(r).upper() for r in dbs), str(dbs)[:200])
    cases = load_all()
    loaded = load_cases(client)
    check("LIVE: 17 cases from Zetaris", len(loaded) == 17, str(len(loaded)))
    exploit = load_exploitation(client)
    check("LIVE: exploitation signal read from Zetaris (6 rows)", len(exploit) == 6, str(len(exploit)))
    diffs = []
    for cid in cases:
        if cid not in loaded:
            diffs.append(cid); continue
        a = quiet_run(cid, dict(cases[cid]))
        b = quiet_run(cid, {**loaded[cid], **({"exploitation": exploit[cid]} if cid in exploit else {})})
        if verdict(a) != verdict(b):
            diffs.append(cid)
    check("LIVE: same result as from the files for all 17", not diffs, ", ".join(diffs))


if __name__ == "__main__":
    try:
        if "--live" in sys.argv:
            live()
        else:
            offline()
    except ZetarisError as e:
        FAIL.append("LIVE error: " + str(e)); print("FAIL", e)
    print(f"\n{len(PASS)} passed, {len(FAIL)} failed" + (" (stand-in server; see header)" if "--live" not in sys.argv else " (live)"))
    sys.exit(1 if FAIL else 0)
