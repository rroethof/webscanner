#!/usr/bin/env python3
"""Line-oriented UTC timestamps for the combined scanner log.

Reads a stream and writes each line immediately. It does not attempt to
interpret or redact tool output. Secrets in tool output must be handled by
the operator before sharing logs.
"""
import argparse
import datetime
import sys


def timestamp_lines(source, destination, timestamps=True):
    for line in source:
        if isinstance(line, bytes):
            line = line.decode("utf-8", errors="replace")
        prefix = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds") + " " if timestamps else ""
        destination.write(prefix + line)
        destination.flush()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--no-timestamps", action="store_true")
    args = parser.parse_args()
    timestamp_lines(sys.stdin.buffer, sys.stdout, not args.no_timestamps)


if __name__ == "__main__":
    main()
