"""PROC-001: Enumerate running processes and check executable integrity.

Uses psutil to enumerate processes, hashes executables, and flags
processes running from suspicious locations (TEMP, Downloads, AppData)
as HIGH and processes with no executable path as CRITICAL.
"""

from __future__ import annotations

import hashlib
import json
import os

from vitia_invenire.checks.base import BaseCheck
from vitia_invenire.collectors.powershell import run_ps
from vitia_invenire.models import Category, Finding, Severity

# Suspicious directory patterns (case-insensitive check)
_SUSPICIOUS_DIRS = [
    "\\temp\\",
    "\\tmp\\",
    "\\downloads\\",
    "\\appdata\\local\\temp",
    "\\appdata\\roaming\\",
    "\\appdata\\local\\",
    "\\users\\public\\",
    "\\programdata\\",
    "\\recycle",
    "$recycle.bin",
]

# Legitimate paths that should not trigger alerts even if they
# match a suspicious directory pattern above.
_LEGITIMATE_PATHS = [
    "\\microsoft\\",
    "\\windows\\",
    "\\windowsapps\\",
    "\\packages\\",
    "\\vitiainvenire\\",
]

# Read buffer size for hashing
_READ_BUFFER_SIZE = 65536


def _compute_sha256(file_path: str) -> str | None:
    """Compute SHA256 of a file, returning hex digest or None on error."""
    try:
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            while True:
                chunk = f.read(_READ_BUFFER_SIZE)
                if not chunk:
                    break
                sha256.update(chunk)
        return sha256.hexdigest()
    except (PermissionError, OSError, FileNotFoundError):
        return None


def _is_suspicious_path(exe_path: str) -> tuple[bool, str]:
    """Check if an executable path is in a suspicious location.

    Returns (is_suspicious, reason) tuple.
    """
    path_lower = exe_path.lower()

    for pattern in _SUSPICIOUS_DIRS:
        if pattern in path_lower:
            # Check if the path is under a known-legitimate subdirectory.
            # Many standard Windows services and apps run from AppData
            # or ProgramData under Microsoft/ or Windows/ subdirectories.
            for legit in _LEGITIMATE_PATHS:
                if legit in path_lower:
                    return False, ""
            return True, f"Executable running from suspicious location matching '{pattern}'"

    return False, ""


class ProcessIntegrityCheck(BaseCheck):
    """Enumerate running processes and check executable path integrity."""

    CHECK_ID = "PROC-001"
    NAME = "Process Integrity Check"
    DESCRIPTION = (
        "Enumerate running processes via psutil, hash their executables, "
        "flag processes from TEMP/Downloads/AppData as HIGH, and processes "
        "with no executable path as CRITICAL."
    )
    CATEGORY = Category.BINARY_INTEGRITY
    REQUIRES_ADMIN = False

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        # Use psutil to enumerate processes
        try:
            import psutil
            processes = []
            for proc in psutil.process_iter(["pid", "name", "exe", "username", "cmdline", "ppid"]):
                try:
                    info = proc.info
                    processes.append({
                        "pid": info.get("pid"),
                        "name": info.get("name", ""),
                        "exe": info.get("exe"),
                        "username": info.get("username"),
                        "cmdline": info.get("cmdline"),
                        "ppid": info.get("ppid"),
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
        except ImportError:
            # Fall back to PowerShell if psutil is not available
            processes = self._enumerate_processes_powershell()

        no_path_processes: list[dict] = []
        suspicious_path_processes: list[dict] = []
        all_process_summary: list[dict] = []
        hashed_exes: dict[str, str] = {}

        # Identify the tool's own process and its direct children so we can
        # exclude them from state capture (they pollute baseline comparisons).
        own_pid = os.getpid()
        own_child_pids: set[int] = set()
        for proc_info in processes:
            if proc_info.get("ppid") == own_pid:
                own_child_pids.add(proc_info.get("pid", -1))
        tool_pids = {own_pid} | own_child_pids

        for proc in processes:
            pid = proc.get("pid", 0)
            name = proc.get("name", "Unknown")
            exe_path = proc.get("exe")
            username = proc.get("username", "Unknown")

            entry = {
                "pid": pid,
                "name": name,
                "exe": exe_path or "N/A",
                "username": username,
            }

            # Check for processes with no executable path
            if not exe_path:
                # Many kernel and protected processes legitimately have no
                # file path visible to non-elevated processes. Low PIDs
                # (typically under 200) are almost always kernel threads.
                name_lower = name.lower()
                is_known_system = (
                    pid in (0, 4)
                    or pid < 200
                    or name_lower in (
                        "system idle process", "system", "registry",
                        "secure system", "memory compression", "idle",
                        "smss", "csrss", "wininit", "services",
                        "lsaiso", "svchost", "fontdrvhost",
                    )
                )
                if not is_known_system:
                    entry["reason"] = "No executable path available"
                    no_path_processes.append(entry)
                all_process_summary.append(entry)
                continue

            # Hash the executable (cache to avoid re-hashing same paths)
            if exe_path not in hashed_exes:
                sha256 = _compute_sha256(exe_path)
                hashed_exes[exe_path] = sha256 or "hash_failed"
            entry["sha256"] = hashed_exes.get(exe_path, "hash_failed")

            # Check for suspicious execution locations
            is_suspicious, reason = _is_suspicious_path(exe_path)
            if is_suspicious:
                entry["reason"] = reason
                suspicious_path_processes.append(entry)

            all_process_summary.append(entry)

        # Capture unique executable state for baseline comparison.
        # Exclude the tool's own process and its children to keep baselines clean.
        unique_exes: dict[str, dict] = {}
        for p in all_process_summary:
            if p.get("pid") in tool_pids:
                continue
            exe = p.get("exe", "N/A")
            if exe and exe != "N/A" and exe not in unique_exes:
                unique_exes[exe] = {
                    "exe": exe,
                    "name": p.get("name", ""),
                    "sha256": p.get("sha256", ""),
                    "username": p.get("username", ""),
                }
        self.context["state"] = list(unique_exes.values())

        # Report processes with no executable path
        if no_path_processes:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Processes With No Executable Path",
                description=(
                    f"{len(no_path_processes)} running process(es) have no "
                    f"associated executable file path. This may indicate "
                    f"process hollowing, fileless malware, or heavily obfuscated "
                    f"execution. Processes without a file on disk cannot be "
                    f"scanned by traditional antivirus."
                ),
                severity=Severity.CRITICAL,
                category=self.CATEGORY,
                affected_item="Running Processes",
                evidence=json.dumps(no_path_processes, indent=2, default=str),
                recommendation=(
                    "Investigate each process without an executable path. "
                    "Use Process Monitor or Volatility to analyze memory and "
                    "determine the true origin of the process."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1055/012/",
                    "https://attack.mitre.org/techniques/T1059/001/",
                ],
            ))

        # Report processes from suspicious locations
        if suspicious_path_processes:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Processes Running From Suspicious Locations",
                description=(
                    f"{len(suspicious_path_processes)} process(es) are running "
                    f"from suspicious locations (TEMP, Downloads, AppData, "
                    f"Public user directories). Malware commonly executes "
                    f"from these writable user directories to evade detection."
                ),
                severity=Severity.HIGH,
                category=self.CATEGORY,
                affected_item="Running Processes",
                evidence=json.dumps(suspicious_path_processes, indent=2, default=str),
                recommendation=(
                    "Investigate each process running from a suspicious location. "
                    "Verify the executable hash against known-good databases. "
                    "Consider implementing application whitelisting (AppLocker/WDAC) "
                    "to prevent execution from user-writable directories."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1204/002/",
                    "https://attack.mitre.org/techniques/T1036/",
                ],
            ))

        # Summary finding
        unique_exes = len(set(
            p.get("exe", "") for p in all_process_summary if p.get("exe") and p["exe"] != "N/A"
        ))
        findings.append(Finding(
            check_id=self.CHECK_ID,
            title="Process Integrity Summary",
            description=(
                f"Enumerated {len(all_process_summary)} running processes "
                f"with {unique_exes} unique executable paths. "
                f"Hashed {len(hashed_exes)} unique executables."
            ),
            severity=Severity.INFO,
            category=self.CATEGORY,
            affected_item="Running Processes",
            evidence=(
                f"Total processes: {len(all_process_summary)}\n"
                f"Unique executables: {unique_exes}\n"
                f"Processes without path: {len(no_path_processes)}\n"
                f"Processes in suspicious locations: {len(suspicious_path_processes)}"
            ),
            recommendation="Regularly audit running processes for unauthorized executables.",
            references=[],
        ))

        return findings

    def _enumerate_processes_powershell(self) -> list[dict]:
        """Fallback: enumerate processes via PowerShell if psutil is unavailable."""
        ps_script = (
            "Get-Process | Select-Object Id, ProcessName, Path, "
            "@{N='Username';E={try{$_.GetOwner().User}catch{'N/A'}}}"
        )
        result = run_ps(ps_script, timeout=30, as_json=True)
        if not result.success or not result.json_output:
            return []

        processes = result.json_output
        if isinstance(processes, dict):
            processes = [processes]

        return [
            {
                "pid": p.get("Id", 0),
                "name": p.get("ProcessName", "Unknown"),
                "exe": p.get("Path"),
                "username": p.get("Username", "Unknown"),
                "cmdline": None,
                "ppid": None,
            }
            for p in processes
        ]
