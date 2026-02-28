"""WMI query wrapper using PowerShell Get-CimInstance.

Executes WMI/CIM queries via PowerShell subprocess rather than the
Python wmi module, enabling cross-platform development (Linux dev,
Windows target).
"""

from __future__ import annotations

from vitia_invenire.collectors.powershell import PowerShellResult, run_ps
from vitia_invenire.platform import is_windows


def platform_available() -> bool:
    """Return True if WMI queries are available (Windows with PowerShell)."""
    return is_windows()


def query(
    wmi_class: str,
    properties: list[str] | None = None,
    namespace: str = "root\\cimv2",
    where: str | None = None,
    timeout: int = 60,
) -> list[dict]:
    """Execute a WMI query and return results as a list of dicts.

    Args:
        wmi_class: WMI class name (e.g., 'Win32_BIOS').
        properties: List of property names to select. None = all properties.
        namespace: WMI namespace (default: root\\cimv2).
        where: Optional WMI filter expression (e.g., "Name='ACPI'").
        timeout: Timeout in seconds for the PowerShell command.

    Returns:
        List of dicts, each representing one WMI object with requested properties.
        Returns empty list on non-Windows or on error.
    """
    if not is_windows():
        return []

    cmd_parts = [f"Get-CimInstance -ClassName {wmi_class}"]

    if namespace != "root\\cimv2":
        cmd_parts.append(f"-Namespace '{namespace}'")

    if where:
        cmd_parts.append(f"-Filter \"{where}\"")

    if properties:
        prop_list = ", ".join(properties)
        cmd_parts.append(f"| Select-Object {prop_list}")

    command = " ".join(cmd_parts)
    result: PowerShellResult = run_ps(command, timeout=timeout, as_json=True)

    if not result.success or result.json_output is None:
        return []

    # PowerShell returns a single object (dict) if only one result,
    # or a list of objects if multiple. Normalize to list.
    if isinstance(result.json_output, dict):
        return [result.json_output]
    if isinstance(result.json_output, list):
        return result.json_output
    return []


def query_raw(command: str, timeout: int = 60) -> PowerShellResult:
    """Execute a raw PowerShell/WMI command and return the full result.

    Use this for complex queries that don't fit the simple Get-CimInstance pattern.

    Args:
        command: Full PowerShell command string.
        timeout: Timeout in seconds.

    Returns:
        PowerShellResult with parsed JSON output.
    """
    return run_ps(command, timeout=timeout, as_json=True)
