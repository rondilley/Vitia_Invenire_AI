"""DLL-HIJACK-001: Detect DLL hijacking in running processes.

For running processes, compare loaded DLL paths against expected
System32/SysWOW64 locations. A standard Windows DLL loaded from a
non-standard path is flagged as HIGH.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from vitia_invenire.checks.base import BaseCheck
from vitia_invenire.collectors.powershell import run_ps
from vitia_invenire.models import Category, Finding, Severity

# Standard Windows DLL directories (lowercase for comparison)
_STANDARD_DLL_DIRS = {
    r"c:\windows\system32",
    r"c:\windows\syswow64",
    r"c:\windows\system32\drivers",
    r"c:\windows\winsxs",
    r"c:\windows",
    r"c:\windows\systemapps",
    r"c:\windows\assembly",
    r"c:\windows\microsoft.net",
}

# Well-known Windows DLL names that should only load from system directories
# These are common DLL hijack targets
_KNOWN_SYSTEM_DLLS = {
    "kernel32.dll", "kernelbase.dll", "ntdll.dll",
    "user32.dll", "gdi32.dll", "advapi32.dll",
    "shell32.dll", "ole32.dll", "oleaut32.dll",
    "msvcrt.dll", "ws2_32.dll", "wsock32.dll",
    "crypt32.dll", "bcrypt.dll", "ncrypt.dll",
    "secur32.dll", "sspicli.dll",
    "comctl32.dll", "comdlg32.dll",
    "shlwapi.dll", "urlmon.dll",
    "winhttp.dll", "wininet.dll",
    "version.dll", "dbghelp.dll", "dbgcore.dll",
    "wintrust.dll", "imagehlp.dll",
    "setupapi.dll", "cfgmgr32.dll",
    "userenv.dll", "profapi.dll",
    "netapi32.dll", "samcli.dll",
    "wtsapi32.dll", "powrprof.dll",
    "dnsapi.dll", "iphlpapi.dll",
    "mswsock.dll", "nsi.dll",
    "rpcrt4.dll", "sspicli.dll",
    "clbcatq.dll", "propsys.dll",
    "cryptbase.dll", "cryptsp.dll",
    "msasn1.dll", "gpapi.dll",
    "wldap32.dll", "dwrite.dll",
    "d3d11.dll", "dxgi.dll",
    "dwmapi.dll", "uxtheme.dll",
    "msi.dll", "cabinet.dll",
    "wevtapi.dll", "tdh.dll",
    "pdh.dll", "perfos.dll",
    "psapi.dll", "sechost.dll",
    "bcryptprimitives.dll", "ucrtbase.dll",
    "msvcp_win.dll", "win32u.dll",
    "gdi32full.dll", "api-ms-win-core-synch-l1-2-0.dll",
    "api-ms-win-core-processthreads-l1-1-0.dll",
    "fltlib.dll", "amsi.dll",
    "wldp.dll", "wintrust.dll",
    "dpapi.dll", "cng.sys",
}

# Legitimate non-system DLL directories
_LEGITIMATE_NON_SYSTEM_DIRS = {
    r"c:\program files",
    r"c:\program files (x86)",
    r"c:\programdata\microsoft",
    r"c:\windows\assembly",
    r"c:\windows\microsoft.net",
    r"c:\windows\winsxs",
    r"c:\windows\systemapps",
    r"c:\windows\immersivecontrolpanel",
}


def _is_standard_location(dll_path: str) -> bool:
    """Check if a DLL path is in a standard Windows directory."""
    path_lower = dll_path.lower()
    parent = os.path.dirname(path_lower)

    for std_dir in _STANDARD_DLL_DIRS:
        if parent == std_dir or parent.startswith(std_dir + "\\"):
            return True

    return False


def _is_known_system_dll(dll_name: str) -> bool:
    """Check if a DLL name is a known Windows system DLL."""
    return dll_name.lower() in _KNOWN_SYSTEM_DLLS


def _is_legitimate_non_system(dll_path: str) -> bool:
    """Check if the path is in a legitimate non-system directory (e.g., Program Files)."""
    path_lower = dll_path.lower()
    for legit_dir in _LEGITIMATE_NON_SYSTEM_DIRS:
        if path_lower.startswith(legit_dir):
            return True
    return False


class DllHijackDetectCheck(BaseCheck):
    """Detect DLL hijacking by comparing loaded DLL paths against expected locations."""

    CHECK_ID = "DLL-HIJACK-001"
    NAME = "DLL Hijack Detection"
    DESCRIPTION = (
        "For running processes, compare loaded DLL paths against expected "
        "System32/SysWOW64 locations. Standard Windows DLLs loaded from "
        "non-standard paths may indicate DLL hijacking."
    )
    CATEGORY = Category.BINARY_INTEGRITY
    REQUIRES_ADMIN = False

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        hijack_suspects: list[dict] = []
        total_modules_checked = 0
        total_processes_checked = 0

        # First try using psutil for loaded module enumeration
        modules_data = self._enumerate_modules_psutil()
        if not modules_data:
            # Fall back to PowerShell
            modules_data = self._enumerate_modules_powershell()

        for proc_info in modules_data:
            total_processes_checked += 1
            pid = proc_info.get("pid", 0)
            proc_name = proc_info.get("name", "Unknown")
            proc_exe = proc_info.get("exe", "Unknown")
            modules = proc_info.get("modules", [])

            for mod_path in modules:
                total_modules_checked += 1
                if not mod_path:
                    continue

                dll_name = os.path.basename(mod_path).lower()

                # Check if this is a known system DLL loaded from non-standard location
                if _is_known_system_dll(dll_name) and not _is_standard_location(mod_path):
                    # Exclude WinSxS and .NET assembly redirections which are legitimate
                    if _is_legitimate_non_system(mod_path):
                        continue

                    hijack_suspects.append({
                        "process_name": proc_name,
                        "pid": pid,
                        "process_exe": proc_exe,
                        "dll_name": dll_name,
                        "loaded_from": mod_path,
                        "expected_location": "System32 or SysWOW64",
                    })

        if hijack_suspects:
            # Deduplicate by (dll_name, loaded_from)
            seen_combos: set[tuple[str, str]] = set()
            unique_suspects: list[dict] = []
            for suspect in hijack_suspects:
                key = (suspect["dll_name"], suspect["loaded_from"].lower())
                if key not in seen_combos:
                    seen_combos.add(key)
                    unique_suspects.append(suspect)

            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Potential DLL Hijacking Detected",
                description=(
                    f"{len(unique_suspects)} known Windows system DLL(s) are "
                    f"loaded from non-standard locations. This is a strong "
                    f"indicator of DLL search order hijacking, which allows "
                    f"an attacker to execute arbitrary code in the context "
                    f"of legitimate processes."
                ),
                severity=Severity.HIGH,
                category=self.CATEGORY,
                affected_item="Loaded DLL Modules",
                evidence=json.dumps(unique_suspects, indent=2),
                recommendation=(
                    "Investigate each DLL loaded from a non-standard path. "
                    "Compare the file hash against the legitimate system DLL. "
                    "Check the sideloading DLL for malicious code. "
                    "Consider enabling CWDIllegalInDllSearch registry mitigation."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1574/001/",
                    "https://attack.mitre.org/techniques/T1574/002/",
                    "https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order",
                ],
            ))

        # Summary finding
        findings.append(Finding(
            check_id=self.CHECK_ID,
            title="DLL Hijack Detection Summary",
            description=(
                f"Checked {total_modules_checked} loaded modules across "
                f"{total_processes_checked} processes."
            ),
            severity=Severity.INFO,
            category=self.CATEGORY,
            affected_item="Running Processes",
            evidence=(
                f"Processes checked: {total_processes_checked}\n"
                f"Modules checked: {total_modules_checked}\n"
                f"Potential hijacks: {len(hijack_suspects)}"
            ),
            recommendation="Regularly audit loaded DLL paths for unauthorized sideloading.",
            references=[],
        ))

        return findings

    def _enumerate_modules_psutil(self) -> list[dict]:
        """Enumerate loaded modules for all processes using psutil."""
        try:
            import psutil
        except ImportError:
            return []

        results: list[dict] = []
        for proc in psutil.process_iter(["pid", "name", "exe"]):
            try:
                info = proc.info
                pid = info.get("pid", 0)
                name = info.get("name", "Unknown")
                exe = info.get("exe", "Unknown")

                try:
                    memory_maps = proc.memory_maps(grouped=False)
                    module_paths = [
                        m.path for m in memory_maps
                        if m.path and m.path.lower().endswith(".dll")
                    ]
                except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
                    # If memory_maps fails, try a simpler approach on Windows
                    module_paths = []

                results.append({
                    "pid": pid,
                    "name": name,
                    "exe": exe,
                    "modules": module_paths,
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        return results

    def _enumerate_modules_powershell(self) -> list[dict]:
        """Enumerate loaded modules via PowerShell as a fallback."""
        ps_script = (
            "Get-Process | Where-Object { $_.Modules -ne $null } | "
            "Select-Object -First 100 | ForEach-Object {"
            "  $proc = $_;"
            "  try {"
            "    $mods = $proc.Modules | ForEach-Object { $_.FileName };"
            "    [PSCustomObject]@{"
            "      pid = $proc.Id;"
            "      name = $proc.ProcessName;"
            "      exe = $proc.Path;"
            "      modules = @($mods);"
            "    }"
            "  } catch { }"
            "}"
        )
        result = run_ps(ps_script, timeout=60, as_json=True)
        if not result.success or not result.json_output:
            return []

        output = result.json_output
        if isinstance(output, dict):
            output = [output]

        processed: list[dict] = []
        for entry in output:
            modules_raw = entry.get("modules", [])
            if isinstance(modules_raw, str):
                modules_raw = [modules_raw]
            processed.append({
                "pid": entry.get("pid", 0),
                "name": entry.get("name", "Unknown"),
                "exe": entry.get("exe", "Unknown"),
                "modules": [m for m in modules_raw if m],
            })

        return processed
