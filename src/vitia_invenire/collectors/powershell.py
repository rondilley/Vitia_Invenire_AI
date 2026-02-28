"""PowerShell subprocess runner with JSON output parsing."""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field
from typing import Any

from vitia_invenire.platform import get_powershell_path, is_windows


@dataclass
class PowerShellResult:
    """Result of a PowerShell command execution."""
    success: bool
    output: str
    json_output: Any = field(default=None)
    error: str | None = None
    return_code: int = 0


def platform_available() -> bool:
    """Return True if PowerShell is available on this system."""
    return get_powershell_path() is not None


def run_ps(
    command: str,
    timeout: int = 60,
    as_json: bool = True,
) -> PowerShellResult:
    """Execute a PowerShell command and return structured result.

    Args:
        command: PowerShell command string to execute.
        timeout: Timeout in seconds.
        as_json: If True, appends '| ConvertTo-Json -Depth 10 -Compress'
                 to the command and parses the output as JSON.

    Returns:
        PowerShellResult with parsed output and error information.
    """
    ps_path = get_powershell_path()
    if ps_path is None:
        return PowerShellResult(
            success=False,
            output="",
            error="PowerShell not found on this system",
            return_code=-1,
        )

    full_command = command
    if as_json:
        full_command = f"{command} | ConvertTo-Json -Depth 10 -Compress"

    args = [
        ps_path,
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy", "Bypass",
        "-Command",
        full_command,
    ]

    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            timeout=timeout,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except subprocess.TimeoutExpired:
        return PowerShellResult(
            success=False,
            output="",
            error=f"PowerShell command timed out after {timeout} seconds",
            return_code=-1,
        )
    except FileNotFoundError:
        return PowerShellResult(
            success=False,
            output="",
            error=f"PowerShell executable not found: {ps_path}",
            return_code=-1,
        )
    except OSError as e:
        return PowerShellResult(
            success=False,
            output="",
            error=f"OS error executing PowerShell: {e}",
            return_code=-1,
        )

    stdout = proc.stdout.strip()
    # PowerShell sometimes emits UTF-8 BOM
    if stdout.startswith("\ufeff"):
        stdout = stdout[1:]

    stderr = proc.stderr.strip() if proc.stderr else None

    if proc.returncode != 0:
        return PowerShellResult(
            success=False,
            output=stdout,
            error=stderr or f"PowerShell exited with code {proc.returncode}",
            return_code=proc.returncode,
        )

    json_output = None
    if as_json and stdout:
        try:
            json_output = json.loads(stdout)
        except json.JSONDecodeError as e:
            return PowerShellResult(
                success=False,
                output=stdout,
                error=f"Failed to parse PowerShell JSON output: {e}",
                return_code=proc.returncode,
            )

    return PowerShellResult(
        success=True,
        output=stdout,
        json_output=json_output,
        error=stderr if stderr else None,
        return_code=proc.returncode,
    )
