"""
Zetaris REST client (data layer).

One job: send ONE Lightning SQL statement to a Zetaris instance and return the rows.
The request shape follows the Participant Setup Guide (section 1.9) and Zetaris' getting-started repo:

    POST {ZETARIS_REST_URL}/sql-editor/sqls/run
    Authorization: Bearer <API key>   X-Org-ID: <org id>   X-Request-ID: <fresh UUID>
    body: {"queryId": <uuid>, "sql": "...", "source": "SqlEditor", "limit": N}
    reply: JSON with the result rows under "data" (list of rows)

Credentials come from the environment only (ZETARIS_REST_URL, ZETARIS_ORG_ID, ZETARIS_API_KEY);
nothing is hard-coded and nothing is logged. Errors raise ZetarisError with a readable message.
"""

import json
import os
import re
import uuid
import urllib.error
import urllib.request

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")


class ZetarisError(Exception):
    pass


class ZetarisClient:
    def __init__(self, rest_url=None, org_id=None, api_key=None, timeout=60):
        self.rest_url = (rest_url or os.environ.get("ZETARIS_REST_URL", "")).rstrip("/")
        self.org_id = str(org_id or os.environ.get("ZETARIS_ORG_ID", ""))
        self.api_key = api_key or os.environ.get("ZETARIS_API_KEY", "")
        self.timeout = timeout
        missing = [n for n, v in (("ZETARIS_REST_URL", self.rest_url), ("ZETARIS_ORG_ID", self.org_id),
                                  ("ZETARIS_API_KEY", self.api_key)) if not v]
        if missing:
            raise ZetarisError("Zetaris is not configured: missing " + ", ".join(missing) +
                               " (set them in .env; see .env.example)")

    def run_sql(self, sql, limit=1000):
        """Run one statement (no trailing semicolon) and return the rows as a list of lists."""
        sql = sql.strip().rstrip(";")
        body = json.dumps({"queryId": str(uuid.uuid4()), "sql": sql, "source": "SqlEditor", "limit": limit}).encode()
        req = urllib.request.Request(
            self.rest_url + "/sql-editor/sqls/run", data=body, method="POST",
            headers={"Authorization": "Bearer " + self.api_key, "X-Org-ID": self.org_id,
                     "X-Request-ID": str(uuid.uuid4()), "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            detail = e.read().decode("utf-8", "replace")[:300]
            hint = {401: " (API key rejected: create a new key and update ZETARIS_API_KEY)",
                    400: " (check ZETARIS_ORG_ID and the SQL)"}.get(e.code, "")
            raise ZetarisError(f"Zetaris returned HTTP {e.code}{hint}: {detail}") from None
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            raise ZetarisError(f"Zetaris not reachable at {self.rest_url}: {getattr(e, 'reason', e)}") from None
        except json.JSONDecodeError:
            raise ZetarisError("Zetaris returned a reply that is not JSON") from None
        if not isinstance(payload, dict):
            raise ZetarisError("unexpected reply from Zetaris (not a JSON object)")
        if payload.get("error") or payload.get("errors"):
            raise ZetarisError("Zetaris reported an error: " + str(payload.get("error") or payload.get("errors"))[:300])
        rows = payload.get("data")
        if rows is None:
            return []
        if not isinstance(rows, list):
            raise ZetarisError("unexpected reply from Zetaris: 'data' is not a list")
        return rows


def available():
    """True if the three settings exist (says nothing about whether the server answers)."""
    return all(os.environ.get(n) for n in ("ZETARIS_REST_URL", "ZETARIS_ORG_ID", "ZETARIS_API_KEY"))
