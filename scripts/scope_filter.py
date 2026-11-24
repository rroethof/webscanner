#!/usr/bin/env python3
"""Restrict discovered URLs to the explicitly requested HTTP(S) origin.

Never accept a URL merely because its text starts with the target hostname.
This is a defensive output filter; the crawler itself must also use -fs fqdn.
"""
import argparse
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit


def origin(url):
    try:
        parsed = urlsplit(url)
        if parsed.scheme.lower() not in ("http", "https") or not parsed.hostname:
            return None
        if parsed.username is not None or parsed.password is not None:
            return None
        port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
        return parsed.scheme.lower(), parsed.hostname.lower().rstrip("."), port
    except (ValueError, AttributeError):
        return None


def filter_urls(target, lines):
    expected = origin(target)
    if expected is None:
        raise ValueError("Target must be an absolute HTTP(S) URL")
    allowed, rejected, seen = [], [], set()
    for line in lines:
        url = line.strip()
        if not url:
            continue
        if origin(url) != expected:
            rejected.append(url)
            continue
        parsed = urlsplit(url)
        normalized = urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, ""))
        if normalized not in seen:
            seen.add(normalized)
            allowed.append(normalized)
    return allowed, rejected


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target")
    ap.add_argument("input")
    ap.add_argument("output")
    ap.add_argument("rejected")
    args = ap.parse_args()
    src = Path(args.input)
    lines = src.read_text(encoding="utf-8", errors="replace").splitlines() if src.exists() else []
    allowed, rejected = filter_urls(args.target, lines)
    Path(args.output).write_text("".join(u + "\n" for u in allowed), encoding="utf-8")
    Path(args.rejected).write_text("".join(u + "\n" for u in rejected), encoding="utf-8")
    print(f"Scope filter: {len(allowed)} unique in-scope URLs, {len(rejected)} out-of-scope URLs rejected")


if __name__ == "__main__":
    main()
