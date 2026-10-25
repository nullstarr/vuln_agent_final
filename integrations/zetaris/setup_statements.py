"""The Lightning SQL that registers our three sources in Zetaris and builds the view agents read.

Pattern copied from Zetaris' own recipe open_data/rest_apis/sql/non_rate_limited/02_pokeapi_create.sql
(REST table -> flattening view with LATERAL VIEW explode). One statement per call, no trailing semicolon.
STATUS: written from the docs; it has to be run once against a live instance (setup_zetaris.py) before it counts.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from agents.zetaris_sources import NVD_COLS, TEXT_COLS, SIGNAL_COLS  # noqa: E402
from agents.exploitation import COLS as EXPLOIT_COLS  # noqa: E402

DB = "VULN_SIGNALS"
CONTAINER = "vuln"
BASE = os.environ.get("VULN_DATA_URL", "http://vulndata:8000")


def _rest(table, path):
    return (f'CREATE LIGHTNING REST TABLE {table} FROM {DB} REQUEST(\n'
            f'    endpoint "{BASE}/{path}",\n    method "get",\n    response_type "json",\n'
            f'    http_encoding "URLENCODED"\n) HEADER (\n) BODY ()')


def _flatten(view, table, cols):
    sel = ",\n    ".join(f"r.{c}" for c in cols)
    return (f"CREATE SCHEMASTORE VIEW {view} WITH CONTAINER {CONTAINER} AS\nSELECT\n    {sel}\n"
            f"FROM {DB.lower()}.{table}\nLATERAL VIEW explode(items) AS r")


def _signals():
    n = "n.{0} AS {0}".format
    parts = ["n.cve_id AS cve_id", "n.nickname AS nickname", "n.as_of AS as_of"]
    parts += [f"n.{c} AS nvd_{c}" for c in NVD_COLS[3:]]
    parts += [f"v.{c} AS vendor_{c}" for c in TEXT_COLS[1:]]
    parts += [f"t.{c} AS ticket_{c}" for c in TEXT_COLS[1:]]
    assert [p.split(" AS ")[1] for p in parts] == SIGNAL_COLS
    return ("CREATE SCHEMASTORE VIEW signals WITH CONTAINER " + CONTAINER + " AS\nSELECT\n    " + ",\n    ".join(parts) +
            f"\nFROM {CONTAINER}.nvd_entries n\nLEFT JOIN {CONTAINER}.vendor_entries v ON n.cve_id = v.cve_id\n"
            f"LEFT JOIN {CONTAINER}.ticket_entries t ON n.cve_id = t.cve_id")


STATEMENTS = [
    f'CREATE LIGHTNING DATABASE {DB} DESCRIBE BY "Vulnerability signals from NVD, vendor changelog and internal tickets"',
    f"CREATE SCHEMASTORE CONTAINER {CONTAINER}",
    _rest("nvd_records", "nvd"),
    _rest("vendor_records", "vendor"),
    _rest("ticket_records", "tickets"),
    _rest("exploit_records", "exploitation"),
    _flatten("nvd_entries", "nvd_records", NVD_COLS),
    _flatten("vendor_entries", "vendor_records", TEXT_COLS),
    _flatten("ticket_entries", "ticket_records", TEXT_COLS),
    _flatten("exploit_entries", "exploit_records", EXPLOIT_COLS),
    _signals(),
]
