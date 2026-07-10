#!/usr/bin/env python3
import sys

# Ensure UTF-8 output on Windows terminals to prevent UnicodeEncodeErrors with rich emojis
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

if __name__ == "__main__":
    from sentinel_scan.cli import run_cli
    run_cli()
