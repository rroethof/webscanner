"""Conservative Nuclei diagnostics, independent of WAF control evidence.

Aggregate Nuclei error counters do not identify HTTP 403 causes.
Text signals are indicative only, not counted as distinct failed requests.
"""
import re
from pathlib import Path

RULES = (
    ("timeout", re.compile(r"\b(?:timed?\s*out|timeout|deadline exceeded)\b", re.I)),
    ("connection", re.compile(r"\b(?:connection refused|connection reset|connection aborted|no route to host|network unreachable|EOF)\b", re.I)),
    ("rate_limit", re.compile(r"\b(?:429|too many requests|rate.limit(?:ed|ing)?)\b", re.I)),
    ("http_403", re.compile(r"\b(?:HTTP[/ ](?:1\.[01]|2|3)[ ]+403|status(?: code)?[:= ]+403|403 Forbidden)\b", re.I)),
)


def diagnose(path, coverage):
    path = Path(path)
    aggregate = coverage.get("request_errors") if coverage.get("observed") else None
    evidence = {
        "classification": "UNKNOWN",
        "reported_request_errors": aggregate,
        "observed_log_signals": [],
        "unattributed_request_errors": aggregate,
        "note": "Nuclei aggregate errors are not attributable to CrowdSec or HTTP statuses without per-request evidence.",
    }
    if not path.is_file():
        return evidence
    log = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", path.read_text(errors="replace"))
    for category, pattern in RULES:
        if pattern.search(log):
            evidence["observed_log_signals"].append(category)
    if evidence["observed_log_signals"]:
        evidence["classification"] = "MIXED_OR_UNCONFIRMED"
        evidence["note"] = "Log contains diagnostic signals, but they cannot be matched to individual Nuclei request errors. WAF attribution remains unverified."
    return evidence
