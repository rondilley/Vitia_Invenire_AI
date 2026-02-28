"""Tests for the generic command runner collector."""

from __future__ import annotations

from vitia_invenire.collectors.command import CommandResult, run_cmd


class TestRunCmd:
    def test_successful_command(self):
        result = run_cmd(["echo", "hello"])
        assert result.success is True
        assert "hello" in result.stdout
        assert result.return_code == 0

    def test_failing_command(self):
        result = run_cmd(["false"])
        assert result.success is False
        assert result.return_code != 0

    def test_command_not_found(self):
        result = run_cmd(["nonexistent_command_xyz123"])
        assert result.success is False
        assert "not found" in result.stderr.lower() or "Command not found" in result.stderr

    def test_command_timeout(self):
        result = run_cmd(["sleep", "10"], timeout=1)
        assert result.success is False
        assert "timed out" in result.stderr.lower()

    def test_command_result_fields(self):
        result = run_cmd(["echo", "test"])
        assert isinstance(result, CommandResult)
        assert isinstance(result.success, bool)
        assert isinstance(result.stdout, str)
        assert isinstance(result.stderr, str)
        assert isinstance(result.return_code, int)

    def test_command_with_stderr(self):
        result = run_cmd(["ls", "/nonexistent_path_xyz"])
        assert result.success is False
        assert result.stderr  # should have error output
