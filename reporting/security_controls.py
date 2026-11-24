#!/usr/bin/env python3
"""Classify externally corroborated protective controls.

A 403 by itself never establishes which component caused it.
Evidence is opt-in and must contain both a CrowdSec alert and a matching
reverse-proxy access-log entry. This module does not create evidence.
"""
import json
from pathlib import Path
from urllib.parse import urlsplit


def classify_evidence(path, target):
    result = {"status": "UNVERIFIED", "events": [], "note": "No correlated WAF evidence supplied"}
    file = Path(path)
    if not file.is_file():
        return result
    try:
        source = json.loads(file.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        result["note"] = "WAF evidence file is unreadable or invalid JSON"
        return result
    events = source.get("events", []) if isinstance(source, dict) else []
    if not isinstance(events, list):
        result["note"] = "WAF evidence events must be a list"
        return result
    expected = urlsplit(target).hostname
    good = []
    for event in events:
        if not isinstance(event, dict):
            continue
        # Correlation is explicitly asserted by the operator who supplies
        # separate primary evidence; don't infer it from a 403 alone.
        try:
            status = int(event.get("http_status", 0))
        except (TypeError, ValueError):
            continue
        host = str(event.get("host", "")).lower().rstrip(".")
        if (status != 403 or not expected or host != expected.lower().rstrip(".")
                or not event.get("crowdsec_alert_id")
                or not event.get("crowdsec_rule")
                or not event.get("proxy_log_reference")
                or not event.get("crowdsec_alert_reference")):
            continue
        good.append({key: str(event[key]) for key in (
            "host", "crowdsec_alert_id", "crowdsec_rule",
            "proxy_log_reference", "crowdsec_alert_reference")})
    if good:
        return {
            "status": "CONTROL_EFFECTIVE",
            "events": good,
            "note": f"{len(good)} manually correlated CrowdSec/AppSec blocking event(s)",
        }
    result["note"] = "No same-host HTTP 403 with both CrowdSec and proxy evidence"
    return result
