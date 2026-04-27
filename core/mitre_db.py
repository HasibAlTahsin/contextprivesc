#!/usr/bin/env python3
from utils.constants import MITRE_TECHNIQUES

def get_technique(tid):
    return MITRE_TECHNIQUES.get(tid, {"name": "Unknown", "tactic": "Unknown"})

def enrich_finding(finding):
    if finding.get("mitre_id"):
        tech = get_technique(finding["mitre_id"])
        finding["mitre_name"] = tech.get("name", "")
        finding["mitre_tactic"] = tech.get("tactic", "")
    return finding
