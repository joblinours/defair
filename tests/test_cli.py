"""Tests for the DEFAIR CLI."""

import tempfile
from pathlib import Path

from click.testing import CliRunner

from defair.cli.main import cli


class TestCLI:
    def setup_method(self):
        self.runner = CliRunner()
        self.tmp_dir = tempfile.mkdtemp()
        self.db_path = str(Path(self.tmp_dir) / "test.db")
        self.base_args = ["--db", self.db_path]

    def test_help(self):
        result = self.runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "DEFAIR" in result.output
        assert "case" in result.output
        assert "evidence" in result.output

    def test_version(self):
        result = self.runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "0.1.0" in result.output

    def test_case_create(self):
        result = self.runner.invoke(cli, [*self.base_args, "case", "create", "Test Incident"])
        assert result.exit_code == 0
        assert "CASE-" in result.output
        assert "Test Incident" in result.output

    def test_cases_list_empty(self):
        result = self.runner.invoke(cli, [*self.base_args, "cases", "list"])
        assert result.exit_code == 0
        assert "No cases found" in result.output

    def test_cases_list_with_data(self):
        self.runner.invoke(cli, [*self.base_args, "case", "create", "Alpha"])
        self.runner.invoke(cli, [*self.base_args, "case", "create", "Beta"])
        result = self.runner.invoke(cli, [*self.base_args, "cases", "list"])
        assert result.exit_code == 0
        assert "Alpha" in result.output
        assert "Beta" in result.output

    def test_case_get(self):
        self.runner.invoke(cli, [*self.base_args, "case", "create", "Gamma"])
        result = self.runner.invoke(cli, [*self.base_args, "case", "get", "CASE-2026-001"])
        assert result.exit_code == 0
        assert "Gamma" in result.output

    def test_case_get_not_found(self):
        result = self.runner.invoke(cli, [*self.base_args, "case", "get", "CASE-9999-999"])
        assert result.exit_code == 1
        assert "not found" in result.output

    def test_evidence_add(self, sample_file):
        self.runner.invoke(cli, [*self.base_args, "case", "create", "EvidenceTest"])
        result = self.runner.invoke(
            cli, [*self.base_args, "evidence", "add", "CASE-2026-001", str(sample_file)]
        )
        assert result.exit_code == 0
        assert "EVD-001" in result.output
        assert "SHA-256" in result.output

    def test_evidence_add_file_not_found(self):
        self.runner.invoke(cli, [*self.base_args, "case", "create", "NoFile"])
        result = self.runner.invoke(
            cli, [*self.base_args, "evidence", "add", "CASE-2026-001", "/nonexistent/file"]
        )
        assert result.exit_code != 0
