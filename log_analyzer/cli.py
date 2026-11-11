"""Command-line interface for Linux Log Analyzer."""

from __future__ import annotations

import argparse
import json
from datetime import date
from pathlib import Path
from typing import Sequence

from .parser import VALID_LEVELS
from .report import render_text, summarize


def iso_date(value: str) -> date:
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("Use YYYY-MM-DD") from exc


def positive_int(value: str) -> int:
    try:
        result = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("Expected a positive integer") from exc
    if result < 1:
        raise argparse.ArgumentTypeError("Expected a positive integer")
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="linux-log-analyzer",
        description="Summarize structured application logs and traditional syslog files.",
    )
    parser.add_argument("file", type=Path, help="UTF-8 log file to analyze")
    parser.add_argument("--format", dest="log_format", choices=("auto", "app", "syslog"), default="auto")
    parser.add_argument(
        "--syslog-year",
        type=positive_int,
        default=date.today().year,
        help="Year to assign to traditional syslog timestamps (default: current year)",
    )
    parser.add_argument("--since", type=iso_date, help="Include logs on/after YYYY-MM-DD")
    parser.add_argument("--until", type=iso_date, help="Include logs on/before YYYY-MM-DD")
    parser.add_argument(
        "--level",
        action="append",
        choices=VALID_LEVELS,
        help="Filter by severity; repeat for multiple levels (use uppercase)",
    )
    parser.add_argument("--service", help="Filter by exact service name (case-insensitive)")
    parser.add_argument("--contains", help="Filter messages containing text (case-insensitive)")
    parser.add_argument("--top-services", type=positive_int, default=5)
    parser.add_argument("--json", action="store_true", help="Output structured JSON")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.since and args.until and args.since > args.until:
        parser.error("--since must not be later than --until")
    if args.syslog_year > 9999:
        parser.error("--syslog-year must be at most 9999")

    try:
        with args.file.open("r", encoding="utf-8", errors="replace") as handle:
            summary = summarize(
                handle,
                log_format=args.log_format,
                syslog_year=args.syslog_year,
                since=args.since,
                until=args.until,
                levels=set(args.level) if args.level else None,
                service=args.service,
                contains=args.contains,
            )
    except OSError as exc:
        parser.exit(2, f"error: unable to read {args.file}: {exc.strerror or exc}\n")

    summary["file"] = str(args.file)
    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print(render_text(summary, top_services=args.top_services))
    return 0
