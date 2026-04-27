#!/usr/bin/env python3
import json
import urllib.request
from utils.constants import NVD_API_URL

def lookup_cve(cve_id):
    try:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        req = urllib.request.Request(url, headers={"User-Agent": "ContextPrivesc/1.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
            if data.get("vulnerabilities"):
                vuln = data["vulnerabilities"][0]["cve"]
                desc = vuln.get("descriptions", [{}])[0].get("value", "No description")
                metrics = vuln.get("metrics", {})
                cvss = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {})
                return {"id": cve_id, "description": desc[:300], "cvss_score": cvss.get("baseScore", "N/A"), "cvss_severity": cvss.get("baseSeverity", "N/A")}
    except:
        return {"id": cve_id, "error": "Failed to lookup"}
    return None
