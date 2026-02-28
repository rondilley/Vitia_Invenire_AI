"""Platform detection, privilege checks, and tool availability."""

from __future__ import annotations

import os
import shutil
import socket
import sys


def is_windows() -> bool:
    """Return True if running on Windows."""
    return sys.platform == "win32"


def is_admin() -> bool:
    """Return True if running with administrator privileges on Windows.

    Returns False on non-Windows platforms.
    """
    if not is_windows():
        return False
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def has_tool(name: str) -> bool:
    """Return True if the named tool is available on PATH."""
    return shutil.which(name) is not None


def _read_registry_value(path: str, name: str) -> str | None:
    """Read a single registry value from HKLM. Returns None on failure."""
    try:
        from vitia_invenire.collectors import registry
        val = registry.read_value(registry.HKEY_LOCAL_MACHINE, path, name)
        if val is not None:
            return str(val.data)
    except Exception:
        pass
    return None


def _fix_product_name(product_name: str, build_number: str | None) -> str:
    """Fix Windows ProductName registry value for Windows 11.

    The registry ProductName often reads "Windows 10 Pro" even on Windows 11
    (build >= 22000). This corrects the name based on the build number.
    """
    if not build_number:
        return product_name
    try:
        if int(build_number) >= 22000 and "Windows 10" in product_name:
            return product_name.replace("Windows 10", "Windows 11")
    except (ValueError, TypeError):
        pass
    return product_name


def get_os_version() -> str:
    """Return the OS version string.

    On Windows, reads the registry to produce a human-friendly string like
    "Windows 11 Pro 25H2 (Build 26200.7840)" instead of the raw
    sys.getwindowsversion() output.
    """
    if not is_windows():
        return f"{sys.platform} ({os.uname().release})"

    nt_key = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
    product_name = _read_registry_value(nt_key, "ProductName")
    display_version = _read_registry_value(nt_key, "DisplayVersion")
    build_number = _read_registry_value(nt_key, "CurrentBuildNumber")
    ubr = _read_registry_value(nt_key, "UBR")

    if product_name:
        product_name = _fix_product_name(product_name, build_number)
        parts = [product_name]
        if display_version:
            parts.append(display_version)
        if build_number:
            build_str = build_number
            if ubr:
                build_str = f"{build_number}.{ubr}"
            parts.append(f"(Build {build_str})")
        return " ".join(parts)

    # Fallback to sys.getwindowsversion()
    try:
        ver = sys.getwindowsversion()
        return f"Windows {ver.major}.{ver.minor}.{ver.build}"
    except AttributeError:
        return f"Windows (Python {sys.version})"


def get_hostname() -> str:
    """Return the system hostname."""
    return socket.gethostname()


def get_system_info() -> object | None:
    """Collect system information matching Windows Settings > System > About.

    Returns a SystemInfo instance on Windows, None on other platforms.
    Each field is individually guarded so partial data is returned on errors.
    """
    if not is_windows():
        return None

    from vitia_invenire.collectors import registry, wmi_collector
    from vitia_invenire.collectors.powershell import run_ps
    from vitia_invenire.models import SystemInfo

    info = SystemInfo(hostname=get_hostname())

    # Registry-based fields
    nt_key = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
    reg_map = {
        "os_product_name": (nt_key, "ProductName"),
        "os_display_version": (nt_key, "DisplayVersion"),
        "os_edition_id": (nt_key, "EditionID"),
        "product_id": (nt_key, "ProductId"),
    }

    for field_name, (path, value_name) in reg_map.items():
        try:
            val = registry.read_value(registry.HKEY_LOCAL_MACHINE, path, value_name)
            if val is not None:
                setattr(info, field_name, str(val.data))
        except Exception:
            pass

    # Build number with UBR
    try:
        build = _read_registry_value(nt_key, "CurrentBuildNumber")
        ubr = _read_registry_value(nt_key, "UBR")
        if build:
            info.os_build = f"{build}.{ubr}" if ubr else build
            # Fix Windows 10 -> 11 naming for builds >= 22000
            if info.os_product_name:
                info.os_product_name = _fix_product_name(info.os_product_name, build)
    except Exception:
        pass

    # Device ID from SQMClient
    try:
        val = registry.read_value(
            registry.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\SQMClient",
            "MachineId",
        )
        if val is not None:
            info.device_id = str(val.data)
    except Exception:
        pass

    # WMI-based fields
    try:
        rows = wmi_collector.query(
            "Win32_ComputerSystem",
            properties=["SystemType", "TotalPhysicalMemory"],
        )
        if rows:
            row = rows[0]
            info.system_type = str(row.get("SystemType", ""))
            try:
                ram_bytes = int(row.get("TotalPhysicalMemory", 0))
                info.installed_ram_gb = round(ram_bytes / (1024 ** 3), 1)
            except (ValueError, TypeError):
                pass
    except Exception:
        pass

    try:
        rows = wmi_collector.query(
            "Win32_Processor",
            properties=["Name", "NumberOfCores", "NumberOfLogicalProcessors"],
        )
        if rows:
            row = rows[0]
            info.processor_name = str(row.get("Name", ""))
            try:
                info.processor_cores = int(row.get("NumberOfCores", 0))
            except (ValueError, TypeError):
                pass
            try:
                info.processor_logical = int(row.get("NumberOfLogicalProcessors", 0))
            except (ValueError, TypeError):
                pass
    except Exception:
        pass

    # Experience pack version
    try:
        result = run_ps(
            "(Get-AppxPackage -Name MicrosoftWindows.Client.CBS -ErrorAction SilentlyContinue).Version",
            timeout=15,
            as_json=False,
        )
        if result.success and result.output.strip():
            info.experience_pack = result.output.strip()
    except Exception:
        pass

    return info


def get_powershell_path() -> str | None:
    """Return path to PowerShell executable, or None if not found.

    Prefers pwsh (PowerShell 7+) over powershell.exe (Windows PowerShell 5.1).
    """
    for name in ("pwsh", "powershell.exe", "powershell"):
        path = shutil.which(name)
        if path:
            return path
    return None
