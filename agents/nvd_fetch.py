"""Bring-your-own-CVE: fetch a CVE live from the NVD API 2.0 and turn it, with your own texts (vendor, internal ticket), into a case.

Honesty: parse_nvd_response() is tested against a file built by hand from the documented NVD 2.0 schema
(data/fixtures/nvd_sample_response.json), NOT against a recorded live response. The network fetch itself is
only verified once someone has run it with internet (check_byo_cve.py --live; passed once, CVE-2021-44228)."""
import json
import re
import urllib.error
import urllib.parse
import urllib.request

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")


class NvdError(Exception):
    pass


def fetch_nvd(cve_id, timeout=20, api_key=None):
    if not CVE_RE.match(cve_id):
        raise NvdError(f"'{cve_id}' is not a CVE ID (expected e.g. CVE-2021-44228).")
    req = urllib.request.Request(NVD_URL + "?" + urllib.parse.urlencode({"cveId": cve_id}),
                                 headers={"User-Agent": "vuln-conflict-resolver/1.0"})
    if api_key:
        req.add_header("apiKey", api_key)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        raise NvdError(f"NVD responded with HTTP {e.code} (403/429 = rate limit: wait a few seconds or set NVD_API_KEY).")
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise NvdError(f"NVD unreachable: {e}. Without internet: use --nvd-file with a saved response.")
    except json.JSONDecodeError:
        raise NvdError("NVD did not return a valid JSON response.")


def parse_nvd_response(data, cve_id):
    """NVD 2.0 response -> our 'nvd' source block. If something is missing, the field stays empty instead of invented."""
    vulns = data.get("vulnerabilities") or []
    cve = next((v.get("cve", {}) for v in vulns if v.get("cve", {}).get("id") == cve_id), None)
    if cve is None:
        raise NvdError(f"{cve_id} is not in the NVD response (not yet published or wrong ID).")
    desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), None)
    score = severity = vector = None
    for key in ("cvssMetricV31", "cvssMetricV30"):
        m = (cve.get("metrics") or {}).get(key)
        if m:
            c = m[0].get("cvssData", {})
            score, severity, vector = c.get("baseScore"), c.get("baseSeverity"), c.get("attackVector")
            break
    return {
        "source_type": "public_vulnerability_database",
        "source_name": "NVD (National Vulnerability Database), API 2.0",
        "is_real_public_data": True,
        "note": f"Fetched from the NVD API 2.0; published {cve.get('published', '?')}, last modified {cve.get('lastModified', '?')}.",
        "cvss_v3_score": score,
        "severity": severity,
        "description": desc,
        "attack_vector": vector.lower() if isinstance(vector, str) else None,
    }


def build_case(cve_id, nvd_block, vendor_text=None, internal_text=None, vendor_name=None, internal_name=None, as_of=None):
    from datetime import date
    sources = {"nvd": nvd_block}
    if vendor_text:
        sources["vendor_changelog"] = {"source_type": "vendor_changelog", "source_name": vendor_name or "Vendor statement (user-provided)",
                                       "is_real_public_data": False, "note": "Text supplied by the user on the command line.", "text": vendor_text.strip()}
    if internal_text:
        sources["internal_ticket"] = {"source_type": "internal_ticket", "source_name": internal_name or "Internal ticket (user-provided)",
                                      "is_real_public_data": False, "note": "Text supplied by the user on the command line.", "text": internal_text.strip()}
    return {"cve_id": cve_id, "nickname": "user-supplied case", "sources": sources,
            "expected_conflict": "n/a (user-supplied case)", "expected_outcome": "n/a",
            "as_of": as_of or date.today().isoformat()}
