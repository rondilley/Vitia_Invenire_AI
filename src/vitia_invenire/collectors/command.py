"""Generic subprocess runner for non-PowerShell commands."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass


@dataclass
class CommandResult:
    """Result of a subprocess command execution."""
    success: bool
    stdout: str
    stderr: str
    return_code: int


def run_cmd(
    args: list[str],
    timeout: int = 60,
    shell: bool = False,
    encoding: str = "utf-8",
) -> CommandResult:
    """Execute a command and return structured result.

    Args:
        args: Command and arguments list.
        timeout: Timeout in seconds.
        shell: Whether to run through the shell.
        encoding: Output encoding.

    Returns:
        CommandResult with stdout, stderr, return code, and success flag.
    """
    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            timeout=timeout,
            shell=shell,
            text=True,
            encoding=encoding,
            errors="replace",
        )
        return CommandResult(
            success=proc.returncode == 0,
            stdout=proc.stdout,
            stderr=proc.stderr,
            return_code=proc.returncode,
        )
    except subprocess.TimeoutExpired:
        return CommandResult(
            success=False,
            stdout="",
            stderr=f"Command timed out after {timeout} seconds",
            return_code=-1,
        )
    except FileNotFoundError:
        return CommandResult(
            success=False,
            stdout="",
            stderr=f"Command not found: {args[0] if args else '(empty)'}",
            return_code=-1,
        )
    except OSError as e:
        return CommandResult(
            success=False,
            stdout="",
            stderr=f"OS error executing command: {e}",
            return_code=-1,
        )
