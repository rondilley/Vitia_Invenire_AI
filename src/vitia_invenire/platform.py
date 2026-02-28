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


def get_os_version() -> str:
    """Return the OS version string."""
    if is_windows():
        try:
            ver = sys.getwindowsversion()
            return f"Windows {ver.major}.{ver.minor}.{ver.build}"
        except AttributeError:
            return f"Windows (Python {sys.version})"
    return f"{sys.platform} ({os.uname().release})"


def get_hostname() -> str:
    """Return the system hostname."""
    return socket.gethostname()


def get_powershell_path() -> str | None:
    """Return path to PowerShell executable, or None if not found.

    Prefers pwsh (PowerShell 7+) over powershell.exe (Windows PowerShell 5.1).
    """
    for name in ("pwsh", "powershell.exe", "powershell"):
        path = shutil.which(name)
        if path:
            return path
    return None
