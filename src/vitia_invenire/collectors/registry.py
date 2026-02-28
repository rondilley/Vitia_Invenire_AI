"""Windows Registry reader abstraction.

Wraps the winreg standard library module with platform guards and
WOW64 support. Returns empty results on non-Windows platforms.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from vitia_invenire.platform import is_windows

# Registry hive constants (match winreg values for use as pass-through)
HKEY_LOCAL_MACHINE = 0x80000002
HKEY_CURRENT_USER = 0x80000001
HKEY_CLASSES_ROOT = 0x80000000
HKEY_USERS = 0x80000003

# Common type constants
REG_SZ = 1
REG_EXPAND_SZ = 2
REG_BINARY = 3
REG_DWORD = 4
REG_MULTI_SZ = 7
REG_QWORD = 11


@dataclass
class RegistryValue:
    """A single registry value with name, data, and type."""
    name: str
    data: Any
    type: int


def platform_available() -> bool:
    """Return True if the Windows registry is accessible."""
    return is_windows()


def read_key(hive: int, path: str, wow64_32: bool = False) -> list[RegistryValue]:
    """Read all values from a registry key.

    Args:
        hive: Registry hive constant (e.g., HKEY_LOCAL_MACHINE).
        path: Subkey path (e.g., 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion').
        wow64_32: If True, access the 32-bit registry view on 64-bit Windows.

    Returns:
        List of RegistryValue objects, or empty list on error/non-Windows.
    """
    if not is_windows():
        return []

    try:
        import winreg

        access = winreg.KEY_READ
        if wow64_32:
            access |= winreg.KEY_WOW64_32KEY

        values = []
        with winreg.OpenKey(hive, path, 0, access) as key:
            i = 0
            while True:
                try:
                    name, data, reg_type = winreg.EnumValue(key, i)
                    values.append(RegistryValue(name=name, data=data, type=reg_type))
                    i += 1
                except OSError:
                    break
        return values

    except OSError:
        return []
    except ImportError:
        return []


def read_value(hive: int, path: str, name: str, wow64_32: bool = False) -> RegistryValue | None:
    """Read a single named value from a registry key.

    Args:
        hive: Registry hive constant.
        path: Subkey path.
        name: Value name to read.
        wow64_32: If True, access the 32-bit registry view.

    Returns:
        RegistryValue if found, None otherwise.
    """
    if not is_windows():
        return None

    try:
        import winreg

        access = winreg.KEY_READ
        if wow64_32:
            access |= winreg.KEY_WOW64_32KEY

        with winreg.OpenKey(hive, path, 0, access) as key:
            data, reg_type = winreg.QueryValueEx(key, name)
            return RegistryValue(name=name, data=data, type=reg_type)

    except OSError:
        return None
    except ImportError:
        return None


def enumerate_subkeys(hive: int, path: str, wow64_32: bool = False) -> list[str]:
    """Enumerate all subkey names under a registry key.

    Args:
        hive: Registry hive constant.
        path: Subkey path.
        wow64_32: If True, access the 32-bit registry view.

    Returns:
        List of subkey names, or empty list on error/non-Windows.
    """
    if not is_windows():
        return []

    try:
        import winreg

        access = winreg.KEY_READ
        if wow64_32:
            access |= winreg.KEY_WOW64_32KEY

        subkeys = []
        with winreg.OpenKey(hive, path, 0, access) as key:
            i = 0
            while True:
                try:
                    subkeys.append(winreg.EnumKey(key, i))
                    i += 1
                except OSError:
                    break
        return subkeys

    except OSError:
        return []
    except ImportError:
        return []
