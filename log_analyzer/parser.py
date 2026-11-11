"""Parsers for two common, text-based log formats."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime


APP_PATTERN = re.compile(
    r"^(?P<stamp>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})\s+"
    r"\[?(?P<level>TRACE|DEBUG|INFO|WARN|WARNING|ERROR|CRITICAL|FATAL)\]?\s+"
    r"(?P<service>[A-Za-z0-9_./-]+):?\s+(?P<message>.*)$",
    flags=re.IGNORECASE,
)

SYSLOG_PATTERN = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
    r"(?P<clock>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+"
    r"(?P<service>[\w./-]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<message>.*)$",
    flags=re.IGNORECASE,
)

LEVEL_ALIASES = {"WARNING": "WARN", "FATAL": "CRITICAL"}
VALID_LEVELS = ("TRACE", "DEBUG", "INFO", "WARN", "ERROR", "CRITICAL", "UNKNOWN")


@dataclass(frozen=True)
class LogEntry:
    timestamp: datetime
    level: str
    service: str
    message: str
    source_format: str


def parse_line(line: str, *, log_format: str = "auto", syslog_year: int) -> LogEntry | None:
    """Parse a line, returning None when it is malformed or unsupported.

    Traditional RFC3164-style syslog does not carry a year or severity.
    Callers must supply a year; its severity is reported as UNKNOWN.
    """
    if log_format not in ("auto", "app", "syslog"):
        raise ValueError(f"Unsupported log format: {log_format}")

    raw = line.rstrip("\r\n")

    if log_format in ("auto", "app"):
        match = APP_PATTERN.fullmatch(raw)
        if match:
            try:
                timestamp = datetime.strptime(match["stamp"].replace("T", " "), "%Y-%m-%d %H:%M:%S")
            except ValueError:
                return None
            level = match["level"].upper()
            return LogEntry(
                timestamp=timestamp,
                level=LEVEL_ALIASES.get(level, level),
                service=match["service"],
                message=match["message"],
                source_format="app",
            )

    if log_format in ("auto", "syslog"):
        match = SYSLOG_PATTERN.fullmatch(raw)
        if match:
            try:
                timestamp = datetime.strptime(
                    f"{syslog_year} {match['month'].title()} {match['day']} {match['clock']}",
                    "%Y %b %d %H:%M:%S",
                )
            except ValueError:
                return None
            return LogEntry(
                timestamp=timestamp,
                level="UNKNOWN",  # Standard syslog lines lack explicit severity.
                service=match["service"],
                message=match["message"],
                source_format="syslog",
            )

    return None
