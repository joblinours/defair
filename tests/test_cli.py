"""Tests for the DEFAIR CLI.

CLI tests run in two modes:
- "Inside container" tests: mock _is_inside_container → True, use local DB
- "Host proxy" tests: mock proxy_command to verify proxy dispatch
"""

import tempfile
from pathlib import Path
from unittest.mock import patch

from click.testing import CliRunner

from defair.cli.main import cli


def _inside_container():
    """Mock: pretend we're inside a container."""
    return True


class TestCLIInsideContainer:
    """Tests for CLI commands running inside a container (direct DB mode)."""

    def setup_method(self):
        self.runner = CliRunner()
        self.tmp_dir = tempfile.mkdtemp()
        self.db_path = str(Path(self.tmp_dir) / "test.db")
        self.base_args = ["--db", self.db_path]
        self._patch = patch("defair.cli.main._is_inside_container", _inside_container)
        self._patch.start()

    def teardown_method(self):
        self._patch.stop()

    def test_help(self):
        result = self.runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "DEFAIR" in result.output
        assert "case" in result.output
        assert "evidence" in result.output

    def test_version(self):
        result = self.runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "0.3.0" in result.output

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

    def test_evidence_list_empty(self):
        result = self.runner.invoke(cli, [*self.base_args, "evidence", "list"])
        assert result.exit_code == 0
        assert "No evidence" in result.output

    def test_evidence_list_with_data(self, sample_file):
        self.runner.invoke(cli, [*self.base_args, "case", "create", "ListEvdCase"])
        self.runner.invoke(
            cli, [*self.base_args, "evidence", "add", "CASE-2026-001", str(sample_file)]
        )
        result = self.runner.invoke(cli, [*self.base_args, "evidence", "list"])
        assert result.exit_code == 0
        assert "EVD-001" in result.output
        assert "sample.txt" in result.output

    def test_evidence_list_filter_by_case(self, sample_file):
        self.runner.invoke(cli, [*self.base_args, "case", "create", "FilterCase"])
        self.runner.invoke(
            cli, [*self.base_args, "evidence", "add", "CASE-2026-001", str(sample_file)]
        )
        result = self.runner.invoke(
            cli, [*self.base_args, "evidence", "list", "--case", "CASE-2026-001"]
        )
        assert result.exit_code == 0
        assert "EVD-001" in result.output

    def test_evidence_get(self, sample_file):
        self.runner.invoke(cli, [*self.base_args, "case", "create", "GetEvdCase"])
        self.runner.invoke(
            cli, [*self.base_args, "evidence", "add", "CASE-2026-001", str(sample_file)]
        )
        result = self.runner.invoke(cli, [*self.base_args, "evidence", "get", "EVD-001"])
        assert result.exit_code == 0
        assert "EVD-001" in result.output
        assert "sample.txt" in result.output

    def test_evidence_get_not_found(self):
        result = self.runner.invoke(cli, [*self.base_args, "evidence", "get", "EVD-999"])
        assert result.exit_code == 1
        assert "not found" in result.output

    def test_evidence_verify_ok(self, sample_file):
        self.runner.invoke(cli, [*self.base_args, "case", "create", "VerifyCase"])
        self.runner.invoke(
            cli, [*self.base_args, "evidence", "add", "CASE-2026-001", str(sample_file)]
        )
        result = self.runner.invoke(cli, [*self.base_args, "evidence", "verify", "EVD-001"])
        assert result.exit_code == 0
        assert "VERIFIED" in result.output


class TestCLIHostProxy:
    """Tests for CLI on host — verifies proxy dispatch via -c flag."""

    def setup_method(self):
        self.runner = CliRunner()
        self._patch = patch("defair.cli.main._is_inside_container", lambda: False)
        self._patch.start()

    def teardown_method(self):
        self._patch.stop()

    def test_case_create_requires_container(self):
        """On host without -c, case commands should fail with guidance."""
        result = self.runner.invoke(cli, ["case", "create", "Test"])
        assert result.exit_code == 1
        assert "No container specified" in result.output

    def test_cases_list_requires_container(self):
        result = self.runner.invoke(cli, ["cases", "list"])
        assert result.exit_code == 1
        assert "No container specified" in result.output

    def test_evidence_add_requires_container(self):
        result = self.runner.invoke(cli, ["evidence", "add", "CASE-2026-001", "/some/file"])
        assert result.exit_code == 1
        assert "No container specified" in result.output

    @patch("defair.cli.proxy.container_service.exec_in_container")
    def test_case_create_proxies(self, mock_exec):
        """With -c flag, case create should proxy into the container."""
        mock_exec.return_value = {
            "exit_code": 0,
            "stdout": "✓ Case created: CASE-2026-001\n  Name: Test\n",
            "stderr": "",
        }
        result = self.runner.invoke(cli, ["-c", "my-container", "case", "create", "Test"])
        assert result.exit_code == 0
        mock_exec.assert_called_once()
        call_args = mock_exec.call_args
        assert call_args[0][0] == "my-container"
        assert "defair" in call_args[0][1]
        assert "case" in call_args[0][1]
        assert "create" in call_args[0][1]
        assert "Test" in call_args[0][1]

    @patch("defair.cli.proxy.container_service.exec_in_container")
    def test_evidence_list_proxies(self, mock_exec):
        mock_exec.return_value = {
            "exit_code": 0,
            "stdout": "No evidence registered.\n",
            "stderr": "",
        }
        result = self.runner.invoke(cli, ["-c", "my-container", "evidence", "list"])
        assert result.exit_code == 0
        mock_exec.assert_called_once()
