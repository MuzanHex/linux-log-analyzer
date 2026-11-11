"""Streaming summary statistics for log entries."""

from __future__ import annotations

from collections import Counter
from datetime import date, datetime
from typing import Iterable

from .parser import parse_line


def summarize(
    lines: Iterable[str],
    *,
    log_format: str = "auto",
    syslog_year: int,
    since: date | None = None,
    until: date | None = None,
    levels: set[str] | None = None,
    service: str | None = None,
    contains: str | None = None,
) -> dict:
    """Analyze lines in a single pass, storing only aggregate counts.

    Filtering applies to matched entries only. Parsed/skipped counters always
    describe the entire input file so users can assess data quality.
    """
    total_lines = parsed_lines = skipped_lines = matched_lines = 0
    level_counts: Counter[str] = Counter()
    service_counts: Counter[str] = Counter()
    daily_counts: Counter[str] = Counter()
    format_counts: Counter[str] = Counter()
    first: datetime | None = None
    last: datetime | None = None

    for line in lines:
        total_lines += 1
        entry = parse_line(line, log_format=log_format, syslog_year=syslog_year)
        if entry is None:
            skipped_lines += 1
            continue

        parsed_lines += 1
        format_counts[entry.source_format] += 1
        day = entry.timestamp.date()
        if since and day < since:
            continue
        if until and day > until:
            continue
        if levels and entry.level not in levels:
            continue
        if service and entry.service.casefold() != service.casefold():
            continue
        if contains and contains.casefold() not in entry.message.casefold():
            continue

        matched_lines += 1
        level_counts[entry.level] += 1
        service_counts[entry.service] += 1
        daily_counts[day.isoformat()] += 1
        if first is None or entry.timestamp < first:
            first = entry.timestamp
        if last is None or entry.timestamp > last:
            last = entry.timestamp

    return {
        "total_lines": total_lines,
        "parsed_lines": parsed_lines,
        "skipped_lines": skipped_lines,
        "matched_lines": matched_lines,
        "first_match": first.isoformat(sep=" ") if first else None,
        "last_match": last.isoformat(sep=" ") if last else None,
        "format_counts": dict(sorted(format_counts.items())),
        "level_counts": dict(sorted(level_counts.items())),
        "service_counts": dict(sorted(service_counts.items())),
        "daily_counts": dict(sorted(daily_counts.items())),
    }


def render_text(summary: dict, *, top_services: int = 5) -> str:
    """Create a human-readable report without printing potentially sensitive lines."""
    report = [
        "Linux Log Analyzer",
        "==================",
        f"File: {summary['file']}",
        f"Lines scanned: {summary['total_lines']}",
        f"Parsed lines: {summary['parsed_lines']}",
        f"Skipped lines: {summary['skipped_lines']}",
        f"Matched lines: {summary['matched_lines']}",
        f"First match: {summary['first_match'] or '—'}",
        f"Last match: {summary['last_match'] or '—'}",
        "",
        "Levels:",
    ]
    report.extend(f"  {level}: {count}" for level, count in summary["level_counts"].items())
    if not summary["level_counts"]:
        report.append("  (none)")
    report.extend(["", f"Top {top_services} services:"])
    top = sorted(summary["service_counts"].items(), key=lambda row: (-row[1], row[0].casefold()))
    report.extend(f"  {name}: {count}" for name, count in top[:top_services])
    if not top:
        report.append("  (none)")
    report.extend(["", "Entries per day:"])
    report.extend(f"  {day}: {count}" for day, count in summary["daily_counts"].items())
    if not summary["daily_counts"]:
        report.append("  (none)")
    return "\n".join(report)
