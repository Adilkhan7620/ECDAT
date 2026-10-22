"""Tests for the scanner CLI entry point."""

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from scanner.main import main


class CliTests(unittest.TestCase):
    """Verify commands work without external security tools."""

    def test_scan_prints_json_summary(self) -> None:
        """A one-tool scan produces a controlled machine-readable result."""
        with tempfile.TemporaryDirectory() as directory, redirect_stdout(io.StringIO()) as output:
            exit_code = main(["scan", directory, "--scanner", "semgrep"])

        payload = json.loads(output.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertEqual(payload["target"], directory)
        self.assertEqual(payload["results"][0]["scanner"], "semgrep")

    def test_doctor_returns_success(self) -> None:
        """Tool availability reporting does not require scanners to be installed."""
        with redirect_stdout(io.StringIO()):
            self.assertEqual(main(["doctor"]), 0)
