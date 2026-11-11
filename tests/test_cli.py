"""Integration-style tests for the command-line interface."""

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from log_analyzer.cli import main


class CLITests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "test.log"
        self.path.write_text(
            "2026-10-17 08:00:00 INFO auth Login accepted\n"
            "2026-10-17 08:00:01 ERROR auth Login failed\n"
            "bad line\n",
            encoding="utf-8",
        )

    def test_json_mode(self):
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            code = main([str(self.path), "--level", "ERROR", "--json"])
        result = json.loads(stdout.getvalue())
        self.assertEqual(code, 0)
        self.assertEqual(result["matched_lines"], 1)
        self.assertEqual(result["skipped_lines"], 1)
        self.assertEqual(result["level_counts"], {"ERROR": 1})

    def test_text_mode(self):
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            code = main([str(self.path), "--top-services", "1"])
        self.assertEqual(code, 0)
        self.assertIn("Lines scanned: 3", stdout.getvalue())
        self.assertIn("Matched lines: 2", stdout.getvalue())

    def test_bad_date_range(self):
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as exc:
            main([str(self.path), "--since", "2026-10-18", "--until", "2026-10-17"])
        self.assertEqual(exc.exception.code, 2)

    def test_missing_file(self):
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as exc:
            main(["missing.log"])
        self.assertEqual(exc.exception.code, 2)

    def test_invalid_top_argument(self):
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as exc:
            main([str(self.path), "--top-services", "0"])
        self.assertEqual(exc.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
