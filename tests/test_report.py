"""Tests for aggregations, filtering, and presentation."""

import unittest
from datetime import date

from log_analyzer.report import render_text, summarize


LINES = [
    "2026-10-17 09:00:01 INFO auth Logged in\n",
    "2026-10-17 09:00:02 WARN api Slow request\n",
    "2026-10-18 09:00:03 ERROR auth Failed login\n",
    "Oct 18 09:10:03 ubuntu sshd[4242]: Accepted connection\n",
    "nonsense\n",
]


class ReportTests(unittest.TestCase):
    def test_counts_and_metadata(self):
        result = summarize(LINES, syslog_year=2026)
        self.assertEqual(result["total_lines"], 5)
        self.assertEqual(result["parsed_lines"], 4)
        self.assertEqual(result["skipped_lines"], 1)
        self.assertEqual(result["matched_lines"], 4)
        self.assertEqual(result["format_counts"], {"app": 3, "syslog": 1})
        self.assertEqual(result["level_counts"], {"ERROR": 1, "INFO": 1, "UNKNOWN": 1, "WARN": 1})
        self.assertEqual(result["daily_counts"], {"2026-10-17": 2, "2026-10-18": 2})

    def test_composed_filters(self):
        result = summarize(
            LINES, syslog_year=2026, since=date(2026, 10, 18),
            until=date(2026, 10, 18), levels={"ERROR"},
            service="AUTH", contains="failed",
        )
        self.assertEqual(result["matched_lines"], 1)
        self.assertEqual(result["service_counts"], {"auth": 1})
        self.assertEqual(result["parsed_lines"], 4)

    def test_no_match(self):
        result = summarize(LINES, syslog_year=2026, contains="unmatched text")
        self.assertEqual(result["matched_lines"], 0)
        self.assertIsNone(result["first_match"])
        self.assertIsNone(result["last_match"])

    def test_display_only_top_service(self):
        result = summarize(LINES, syslog_year=2026)
        result["file"] = "example.log"
        rendered = render_text(result, top_services=1)
        self.assertIn("  auth: 2", rendered)
        self.assertNotIn("  sshd: 1", rendered)


if __name__ == "__main__":
    unittest.main()
