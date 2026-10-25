"""
The three evidence sources, served through Zetaris.

Flow:   case files -> (integrations/zetaris/data_server.py) -> Zetaris REST tables -> SQL view vuln.signals
        -> load_cases() here -> the same case dicts the agents already use.

The agents are NOT changed for this: they get the same structure whether the case came from a file or from Zetaris.
A source that is absent in Zetaris (NULL after the LEFT JOIN) is left out of the case, exactly like a missing key in a file.
"""

from agents.exploitation import COLS as EXPLOIT_COLS
from agents.zetaris_client import CVE_RE, ZetarisError

NVD_COLS = ["cve_id", "nickname", "as_of", "source_name", "source_type", "is_real_public_data", "note",
            "cvss_v3_score", "severity", "description", "affected_versions", "fixed_version",
            "auth_required", "user_interaction_required", "attack_vector"]
TEXT_COLS = ["cve_id", "source_name", "source_type", "is_real_public_data", "note", "text"]

# Column order of the view vuln.signals (fixed, because rows come back as plain lists).
SIGNAL_COLS = (
    ["cve_id", "nickname", "as_of"]
    + ["nvd_" + c for c in NVD_COLS[3:]]
    + ["vendor_" + c for c in TEXT_COLS[1:]]
    + ["ticket_" + c for c in TEXT_COLS[1:]]
)
SOURCE_PREFIX = {"nvd": "nvd_", "vendor_changelog": "vendor_", "internal_ticket": "ticket_"}


def flatten_cases(cases):
    """Cases (as in data/*/cases.json) -> three flat record lists for the REST endpoints."""
    nvd, vendor, ticket = [], [], []
    for cve_id, case in cases.items():
        src = case.get("sources") or {}
        if isinstance(src.get("nvd"), dict):
            rec = {"cve_id": cve_id, "nickname": case.get("nickname"), "as_of": case.get("as_of")}
            rec.update({k: v for k, v in src["nvd"].items() if k in NVD_COLS})
            nvd.append(rec)
        for key, out in (("vendor_changelog", vendor), ("internal_ticket", ticket)):
            if isinstance(src.get(key), dict):
                rec = {"cve_id": cve_id}
                rec.update({k: v for k, v in src[key].items() if k in TEXT_COLS})
                out.append(rec)
    return nvd, vendor, ticket


def flatten_exploitation(cases):
    """Exploitation records (case['exploitation']) as flat rows for the fourth REST endpoint."""
    out = []
    for cve_id, case in cases.items():
        rec = case.get("exploitation")
        if isinstance(rec, dict):
            row = {"cve_id": cve_id}
            row.update({k: v for k, v in rec.items() if k in EXPLOIT_COLS})
            out.append(row)
    return out


def _num(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return v


def _bool(v):
    if isinstance(v, str):
        return v.strip().lower() == "true"
    return bool(v)


def case_from_row(row):
    """One row of vuln.signals -> a case dict. Raises ZetarisError if the row has the wrong width."""
    if len(row) != len(SIGNAL_COLS):
        raise ZetarisError(f"vuln.signals returned {len(row)} columns, expected {len(SIGNAL_COLS)}")
    r = dict(zip(SIGNAL_COLS, row))
    case = {"cve_id": r["cve_id"], "sources": {}}
    if r.get("nickname") is not None:
        case["nickname"] = r["nickname"]
    if r.get("as_of") is not None:
        case["as_of"] = r["as_of"]
    for key, pre in SOURCE_PREFIX.items():
        cols = {c[len(pre):]: v for c, v in r.items() if c.startswith(pre) and v is not None}
        if not cols:
            continue                        # source absent in Zetaris -> absent in the case
        if "is_real_public_data" in cols:
            cols["is_real_public_data"] = _bool(cols["is_real_public_data"])
        for b in ("auth_required", "user_interaction_required"):
            if b in cols:
                cols[b] = _bool(cols[b])
        if "cvss_v3_score" in cols:
            cols["cvss_v3_score"] = _num(cols["cvss_v3_score"])
        case["sources"][key] = cols
    return case


def build_sql(cve_ids=None):
    """The one SQL statement that reads the cases. Ids are validated before they go into SQL."""
    sql = "SELECT " + ", ".join(SIGNAL_COLS) + " FROM vuln.signals"
    if cve_ids:
        for c in cve_ids:
            if not CVE_RE.match(c):
                raise ZetarisError(f"not a CVE id: {c!r}")
        sql += " WHERE cve_id IN (" + ", ".join(f"'{c}'" for c in cve_ids) + ")"
    return sql + " ORDER BY cve_id"


def describe_query(cve_ids=None):
    """Short, readable form of the query for the report: which tables/view the three sources come from."""
    where = " WHERE cve_id IN (" + ", ".join(f"'{c}'" for c in cve_ids) + ")" if cve_ids else ""
    return ("SQL on Zetaris view vuln.signals (LEFT JOIN of three views over REST tables):\n"
            "  nvd_*     <- vuln.nvd_entries     <- REST /nvd     (NVD entry)\n"
            "  vendor_*  <- vuln.vendor_entries  <- REST /vendor  (vendor changelog)\n"
            "  ticket_*  <- vuln.ticket_entries  <- REST /tickets (internal ticket)\n"
            f"  SELECT {len(SIGNAL_COLS)} columns FROM vuln.signals{where} ORDER BY cve_id\n"
            "  A source whose columns are NULL is treated as absent (not as empty).\n"
            "  Second query: exploitation signal from vuln.exploit_entries <- REST /exploitation (no row = unknown, not 'safe').")


def load_cases(client, cve_ids=None):
    """Read cases from Zetaris with SQL. cve_ids=None reads all."""
    rows = client.run_sql(build_sql(cve_ids))
    return {c["cve_id"]: c for c in (case_from_row(r) for r in rows)}


def build_exploit_sql(cve_ids=None):
    sql = "SELECT " + ", ".join(EXPLOIT_COLS) + " FROM vuln.exploit_entries"
    if cve_ids:
        for c in cve_ids:
            if not CVE_RE.match(c):
                raise ZetarisError(f"not a CVE id: {c!r}")
        sql += " WHERE cve_id IN (" + ", ".join(f"'{c}'" for c in cve_ids) + ")"
    return sql + " ORDER BY cve_id"


def load_exploitation(client, cve_ids=None):
    """Second query: the exploitation signal per CVE (a CVE without a row simply has no signal = unknown)."""
    out = {}
    for row in client.run_sql(build_exploit_sql(cve_ids)):
        if len(row) != len(EXPLOIT_COLS):
            raise ZetarisError(f"exploitation row has {len(row)} columns, expected {len(EXPLOIT_COLS)}")
        rec = dict(zip(EXPLOIT_COLS, row))
        cid = rec.pop("cve_id")
        rec = {k: v for k, v in rec.items() if v is not None}
        if "exploited_in_wild" in rec:
            rec["exploited_in_wild"] = _bool(rec["exploited_in_wild"])
        if "is_real_public_data" in rec:
            rec["is_real_public_data"] = _bool(rec["is_real_public_data"])
        out[cid] = rec
    return out
