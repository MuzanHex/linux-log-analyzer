"""Unit tests for log parsing."""

import unittest

from log_analyzer.parser import parse_line


class ParserTests(unittest.TestCase):
    def test_plain_application_log(self):
        entry = parse_line("2026-10-17 09:00:01 INFO auth Login succeeded", syslog_year=2026)
        self.assertEqual(entry.level, "INFO")
        self.assertEqual(entry.service, "auth")
        self.assertEqual(entry.message, "Login succeeded")
        self.assertEqual(entry.timestamp.isoformat(), "2026-10-17T09:00:01")
        self.assertEqual(entry.source_format, "app")

    def test_bracketed_level_and_iso_separator(self):
        entry = parse_line("2026-10-17T09:00:01 [ERROR] sshd: Connection failed", syslog_year=2026)
        self.assertEqual((entry.level, entry.service), ("ERROR", "sshd"))

    def test_severity_aliases(self):
        warning = parse_line("2026-10-17 09:00:01 WARNING auth Slow response", syslog_year=2026)
        fatal = parse_line("2026-10-17 09:00:01 FATAL auth Unavailable", syslog_year=2026)
        self.assertEqual(warning.level, "WARN")
        self.assertEqual(fatal.level, "CRITICAL")

    def test_syslog_pid_and_supplied_year(self):
        entry = parse_line("Oct 17 09:10:03 ubuntu sshd[4242]: Accepted connection", syslog_year=2026)
        self.assertEqual(entry.service, "sshd")
        self.assertEqual(entry.level, "UNKNOWN")
        self.assertEqual(entry.timestamp.year, 2026)
        self.assertEqual(entry.source_format, "syslog")

    def test_reject_invalid_date(self):
        self.assertIsNone(parse_line("2026-02-30 09:00:01 INFO auth Impossible", syslog_year=2026))

    def test_reject_nonlog_line(self):
        self.assertIsNone(parse_line("not a supported log line", syslog_year=2026))

    def test_forced_format(self):
        raw = "Oct 17 09:10:03 ubuntu sshd[4242]: Accepted connection"
        self.assertIsNone(parse_line(raw, log_format="app", syslog_year=2026))
        self.assertIsNotNone(parse_line(raw, log_format="syslog", syslog_year=2026))

    def test_reject_invalid_format_option(self):
        with self.assertRaises(ValueError):
            parse_line("something", log_format="bogus", syslog_year=2026)


if __name__ == "__main__":
    unittest.main()
