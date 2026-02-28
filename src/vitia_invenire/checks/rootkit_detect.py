"""ROOTKIT-001: Cross-validation rootkit detection.

Cross-validates process, service, and driver lists obtained from multiple
independent sources (psutil, Get-Process, WMI, registry, driverquery).
Discrepancies between sources may indicate a rootkit hiding processes,
services, or drivers from certain APIs. Also runs SFC to detect system
file tampering.
"""

from __future__ import annotations

import csv
import io

import psutil

from vitia_invenire.checks.base import BaseCheck
from vitia_invenire.collectors.powershell import run_ps
from vitia_invenire.models import Category, Finding, Severity

# PIDs that are reported inconsistently across APIs and should be ignored
_IGNORED_PIDS = {0, 4}

# Win32 service types that indicate actual services (not drivers)
# 0x10 = Win32OwnProcess, 0x20 = Win32ShareProcess
_WIN32_SERVICE_TYPES = {16, 32}


class RootkitDetectionCheck(BaseCheck):
    """Cross-validate process, service, and driver lists from multiple sources."""

    CHECK_ID = "ROOTKIT-001"
    NAME = "Cross-Validation Rootkit Detection"
    DESCRIPTION = (
        "Cross-validates process, service, and driver lists from multiple "
        "independent sources to detect hidden or rootkit processes. "
        "Discrepancies between psutil, Get-Process, WMI, registry, and "
        "driverquery may indicate a rootkit concealing its presence from "
        "certain enumeration APIs."
    )
    CATEGORY = Category.MALWARE
    REQUIRES_ADMIN = True

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        self._cross_validate_processes(findings)
        self._cross_validate_services(findings)
        self._cross_validate_drivers(findings)
        self._check_sfc(findings)

        return findings

    def _cross_validate_processes(self, findings: list[Finding]) -> None:
        """Compare process lists from psutil, Get-Process, and WMI."""

        # Source 1: psutil
        psutil_procs: dict[int, str] = {}
        try:
            for p in psutil.process_iter(["pid", "name"]):
                try:
                    pid = p.info["pid"]
                    name = p.info["name"] or ""
                    psutil_procs[pid] = name
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
        except psutil.Error as exc:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="psutil process enumeration failed",
                description=f"Could not enumerate processes via psutil: {exc}",
                severity=Severity.MEDIUM,
                category=self.CATEGORY,
                affected_item="psutil process enumeration",
                evidence=f"psutil.Error: {exc}",
                recommendation="Verify psutil is installed and functional.",
            ))

        # Source 2: PowerShell Get-Process
        ps_procs: dict[int, str] = {}
        ps_result = run_ps(
            "Get-Process | Select-Object Id, ProcessName",
            as_json=True,
            timeout=30,
        )
        if ps_result.success and ps_result.json_output is not None:
            data = ps_result.json_output
            if isinstance(data, dict):
                data = [data]
            for entry in data:
                pid = entry.get("Id")
                name = entry.get("ProcessName", "")
                if pid is not None:
                    ps_procs[int(pid)] = str(name)
        else:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Get-Process enumeration failed",
                description=(
                    f"Could not enumerate processes via Get-Process: "
                    f"{ps_result.error or 'unknown error'}"
                ),
                severity=Severity.MEDIUM,
                category=self.CATEGORY,
                affected_item="Get-Process enumeration",
                evidence=f"Error: {ps_result.error or 'no output'}",
                recommendation="Verify PowerShell is functional.",
            ))

        # Source 3: WMI Win32_Process
        wmi_procs: dict[int, str] = {}
        wmi_result = run_ps(
            "Get-CimInstance Win32_Process | Select-Object ProcessId, Name",
            as_json=True,
            timeout=30,
        )
        if wmi_result.success and wmi_result.json_output is not None:
            data = wmi_result.json_output
            if isinstance(data, dict):
                data = [data]
            for entry in data:
                pid = entry.get("ProcessId")
                name = entry.get("Name", "")
                if pid is not None:
                    wmi_procs[int(pid)] = str(name)
        else:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="WMI process enumeration failed",
                description=(
                    f"Could not enumerate processes via Win32_Process: "
                    f"{wmi_result.error or 'unknown error'}"
                ),
                severity=Severity.MEDIUM,
                category=self.CATEGORY,
                affected_item="WMI process enumeration",
                evidence=f"Error: {wmi_result.error or 'no output'}",
                recommendation="Verify WMI service is running.",
            ))

        # Cross-validate: check each source for PIDs missing from BOTH others
        all_pids = set(psutil_procs.keys()) | set(ps_procs.keys()) | set(wmi_procs.keys())
        hidden_count = 0

        for pid in sorted(all_pids):
            if pid in _IGNORED_PIDS:
                continue

            in_psutil = pid in psutil_procs
            in_ps = pid in ps_procs
            in_wmi = pid in wmi_procs

            sources_present = []
            sources_absent = []
            if in_psutil:
                sources_present.append("psutil")
            else:
                sources_absent.append("psutil")
            if in_ps:
                sources_present.append("Get-Process")
            else:
                sources_absent.append("Get-Process")
            if in_wmi:
                sources_present.append("WMI")
            else:
                sources_absent.append("WMI")

            # Flag if present in exactly one source but missing from both others
            if len(sources_present) == 1:
                hidden_count += 1
                name = (
                    psutil_procs.get(pid)
                    or ps_procs.get(pid)
                    or wmi_procs.get(pid)
                    or "Unknown"
                )
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title=f"Hidden process detected: PID {pid} ({name})",
                    description=(
                        f"Process with PID {pid} ({name}) appears in "
                        f"{sources_present[0]} but is missing from "
                        f"{', '.join(sources_absent)}. A process visible to "
                        "only one enumeration API may be hidden by a rootkit."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.CATEGORY,
                    affected_item=f"PID {pid}: {name}",
                    evidence=(
                        f"PID: {pid}\n"
                        f"Name: {name}\n"
                        f"Visible in: {', '.join(sources_present)}\n"
                        f"Missing from: {', '.join(sources_absent)}"
                    ),
                    recommendation=(
                        "Investigate this process immediately. Use kernel-level "
                        "tools (e.g., Volatility, WinDbg) to examine the process. "
                        "A process hidden from multiple APIs is a strong indicator "
                        "of rootkit activity."
                    ),
                    references=[
                        "https://attack.mitre.org/techniques/T1014/",
                        "https://attack.mitre.org/techniques/T1564/",
                    ],
                ))

        # Summary
        findings.append(Finding(
            check_id=self.CHECK_ID,
            title="Process cross-validation summary",
            description=(
                f"Cross-validated process lists from three sources. "
                f"psutil: {len(psutil_procs)} processes, "
                f"Get-Process: {len(ps_procs)} processes, "
                f"WMI: {len(wmi_procs)} processes. "
                f"{hidden_count} potential hidden process(es) detected."
            ),
            severity=Severity.INFO,
            category=self.CATEGORY,
            affected_item="Process Cross-Validation",
            evidence=(
                f"psutil process count: {len(psutil_procs)}\n"
                f"Get-Process count: {len(ps_procs)}\n"
                f"WMI process count: {len(wmi_procs)}\n"
                f"Hidden process candidates: {hidden_count}"
            ),
            recommendation="Regularly cross-validate process lists to detect rootkits.",
        ))

    def _cross_validate_services(self, findings: list[Finding]) -> None:
        """Compare service lists from Get-Service, WMI, and the registry."""

        # Source 1: PowerShell Get-Service
        ps_services: dict[str, dict] = {}
        ps_result = run_ps(
            "Get-Service | Select-Object Name, Status, StartType, DisplayName",
            as_json=True,
            timeout=30,
        )
        if ps_result.success and ps_result.json_output is not None:
            data = ps_result.json_output
            if isinstance(data, dict):
                data = [data]
            for entry in data:
                name = str(entry.get("Name", "")).lower()
                if name:
                    ps_services[name] = entry
        else:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Get-Service enumeration failed",
                description=(
                    f"Could not enumerate services via Get-Service: "
                    f"{ps_result.error or 'unknown error'}"
                ),
                severity=Severity.MEDIUM,
                category=self.CATEGORY,
                affected_item="Get-Service enumeration",
                evidence=f"Error: {ps_result.error or 'no output'}",
                recommendation="Verify PowerShell is functional.",
            ))

        # Source 2: WMI Win32_Service
        wmi_services: dict[str, dict] = {}
        wmi_result = run_ps(
            "Get-CimInstance Win32_Service | Select-Object Name, State, StartMode, DisplayName",
            as_json=True,
            timeout=30,
        )
        if wmi_result.success and wmi_result.json_output is not None:
            data = wmi_result.json_output
            if isinstance(data, dict):
                data = [data]
            for entry in data:
                name = str(entry.get("Name", "")).lower()
                if name:
                    wmi_services[name] = entry
        else:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="WMI service enumeration failed",
                description=(
                    f"Could not enumerate services via Win32_Service: "
                    f"{wmi_result.error or 'unknown error'}"
                ),
                severity=Severity.MEDIUM,
                category=self.CATEGORY,
                affected_item="WMI service enumeration",
                evidence=f"Error: {wmi_result.error or 'no output'}",
                recommendation="Verify WMI service is running.",
            ))

        # Source 3: Registry enumeration
        reg_services: dict[str, str] = {}
        reg_result = run_ps(
            "Get-ChildItem 'HKLM:\\SYSTEM\\CurrentControlSet\\Services' "
            "| Select-Object PSChildName",
            as_json=True,
            timeout=30,
        )
        if reg_result.success and reg_result.json_output is not None:
            data = reg_result.json_output
            if isinstance(data, dict):
                data = [data]
            for entry in data:
                name = str(entry.get("PSChildName", "")).lower()
                if name:
                    reg_services[name] = name
        else:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Registry service enumeration failed",
                description=(
                    f"Could not enumerate services from registry: "
                    f"{reg_result.error or 'unknown error'}"
                ),
                severity=Severity.MEDIUM,
                category=self.CATEGORY,
                affected_item="Registry service enumeration",
                evidence=f"Error: {reg_result.error or 'no output'}",
                recommendation="Verify registry access is available.",
            ))

        # Cross-validate: find services in registry but not in Get-Service
        # AND not in WMI. Only flag Win32 service types (not drivers).
        hidden_count = 0
        for reg_name in sorted(reg_services.keys()):
            if reg_name in ps_services or reg_name in wmi_services:
                continue

            # Check if this is a Win32 service type (not a driver)
            type_result = run_ps(
                f"Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\{reg_name}' "
                "-Name Start,Type -ErrorAction SilentlyContinue "
                "| Select-Object Start,Type",
                as_json=True,
                timeout=10,
            )
            if not type_result.success or type_result.json_output is None:
                continue

            type_data = type_result.json_output
            if isinstance(type_data, list):
                type_data = type_data[0] if type_data else {}

            svc_type = type_data.get("Type")
            if svc_type is None:
                continue

            try:
                svc_type_int = int(svc_type)
            except (ValueError, TypeError):
                continue

            if svc_type_int not in _WIN32_SERVICE_TYPES:
                continue

            hidden_count += 1
            start_value = type_data.get("Start", "Unknown")
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title=f"Hidden service detected: {reg_name}",
                description=(
                    f"Service '{reg_name}' exists in the registry as a Win32 "
                    "service but is not visible via Get-Service or WMI "
                    "Win32_Service. A service hidden from standard enumeration "
                    "APIs may indicate rootkit activity or tampering."
                ),
                severity=Severity.HIGH,
                category=self.CATEGORY,
                affected_item=f"Service: {reg_name}",
                evidence=(
                    f"Service Name: {reg_name}\n"
                    f"Registry Path: HKLM\\SYSTEM\\CurrentControlSet\\Services\\{reg_name}\n"
                    f"Service Type: {svc_type_int} (Win32 service)\n"
                    f"Start Value: {start_value}\n"
                    "Visible in: Registry\n"
                    "Missing from: Get-Service, WMI"
                ),
                recommendation=(
                    "Investigate this hidden service immediately. Examine the "
                    "service binary referenced in the registry ImagePath value. "
                    "A Win32 service visible only in the registry is a strong "
                    "indicator of rootkit concealment."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1543/003/",
                    "https://attack.mitre.org/techniques/T1014/",
                ],
            ))

        # Summary
        findings.append(Finding(
            check_id=self.CHECK_ID,
            title="Service cross-validation summary",
            description=(
                f"Cross-validated service lists from three sources. "
                f"Get-Service: {len(ps_services)} services, "
                f"WMI: {len(wmi_services)} services, "
                f"Registry: {len(reg_services)} entries. "
                f"{hidden_count} potential hidden service(s) detected."
            ),
            severity=Severity.INFO,
            category=self.CATEGORY,
            affected_item="Service Cross-Validation",
            evidence=(
                f"Get-Service count: {len(ps_services)}\n"
                f"WMI service count: {len(wmi_services)}\n"
                f"Registry entries: {len(reg_services)}\n"
                f"Hidden service candidates: {hidden_count}"
            ),
            recommendation="Regularly cross-validate service lists to detect rootkits.",
        ))

    def _cross_validate_drivers(self, findings: list[Finding]) -> None:
        """Compare driver lists from WMI and driverquery."""

        # Source 1: WMI Win32_SystemDriver
        wmi_drivers: dict[str, dict] = {}
        wmi_result = run_ps(
            "Get-CimInstance Win32_SystemDriver "
            "| Select-Object Name, DisplayName, State, PathName",
            as_json=True,
            timeout=30,
        )
        if wmi_result.success and wmi_result.json_output is not None:
            data = wmi_result.json_output
            if isinstance(data, dict):
                data = [data]
            for entry in data:
                name = str(entry.get("Name", "")).lower()
                if name:
                    wmi_drivers[name] = entry
        else:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="WMI driver enumeration failed",
                description=(
                    f"Could not enumerate drivers via Win32_SystemDriver: "
                    f"{wmi_result.error or 'unknown error'}"
                ),
                severity=Severity.MEDIUM,
                category=self.CATEGORY,
                affected_item="WMI driver enumeration",
                evidence=f"Error: {wmi_result.error or 'no output'}",
                recommendation="Verify WMI service is running.",
            ))

        # Source 2: driverquery /v /fo csv
        dq_drivers: dict[str, dict] = {}
        dq_result = run_ps(
            "driverquery /v /fo csv",
            as_json=False,
            timeout=30,
        )
        if dq_result.success and dq_result.output:
            try:
                reader = csv.DictReader(io.StringIO(dq_result.output))
                for row in reader:
                    # driverquery CSV uses "Module Name" as the driver name
                    name = str(row.get("Module Name", "")).lower().strip()
                    if name:
                        dq_drivers[name] = dict(row)
            except (csv.Error, KeyError, ValueError) as exc:
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title="driverquery CSV parsing failed",
                    description=f"Could not parse driverquery CSV output: {exc}",
                    severity=Severity.MEDIUM,
                    category=self.CATEGORY,
                    affected_item="driverquery output",
                    evidence=f"Parse error: {exc}",
                    recommendation="Verify driverquery is functional.",
                ))
        else:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="driverquery enumeration failed",
                description=(
                    f"Could not enumerate drivers via driverquery: "
                    f"{dq_result.error or 'unknown error'}"
                ),
                severity=Severity.MEDIUM,
                category=self.CATEGORY,
                affected_item="driverquery enumeration",
                evidence=f"Error: {dq_result.error or 'no output'}",
                recommendation="Verify driverquery.exe is available.",
            ))

        # Cross-validate: find drivers in one source but not the other
        discrepancy_count = 0
        all_driver_names = set(wmi_drivers.keys()) | set(dq_drivers.keys())

        for name in sorted(all_driver_names):
            in_wmi = name in wmi_drivers
            in_dq = name in dq_drivers

            if in_wmi and not in_dq:
                discrepancy_count += 1
                driver_info = wmi_drivers[name]
                display_name = str(driver_info.get("DisplayName", name))
                state = str(driver_info.get("State", "Unknown"))
                path = str(driver_info.get("PathName", "Unknown"))
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title=f"Driver discrepancy detected: {name}",
                    description=(
                        f"Driver '{name}' ({display_name}) appears in WMI "
                        "Win32_SystemDriver but not in driverquery output. "
                        "This discrepancy may indicate a rootkit hiding a "
                        "driver from certain enumeration methods."
                    ),
                    severity=Severity.HIGH,
                    category=self.CATEGORY,
                    affected_item=f"Driver: {name}",
                    evidence=(
                        f"Driver Name: {name}\n"
                        f"Display Name: {display_name}\n"
                        f"State: {state}\n"
                        f"Path: {path}\n"
                        "Visible in: WMI\n"
                        "Missing from: driverquery"
                    ),
                    recommendation=(
                        "Investigate this driver discrepancy. Use kernel-level "
                        "tools to examine the driver module. Verify the driver "
                        "binary signature and origin."
                    ),
                    references=[
                        "https://attack.mitre.org/techniques/T1014/",
                    ],
                ))
            elif in_dq and not in_wmi:
                discrepancy_count += 1
                driver_info = dq_drivers[name]
                display_name = str(driver_info.get("Display Name", name))
                state = str(driver_info.get("Status", "Unknown"))
                driver_type = str(driver_info.get("Driver Type", "Unknown"))
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title=f"Driver discrepancy detected: {name}",
                    description=(
                        f"Driver '{name}' ({display_name}) appears in "
                        "driverquery output but not in WMI Win32_SystemDriver. "
                        "This discrepancy may indicate a rootkit hiding a "
                        "driver from WMI enumeration."
                    ),
                    severity=Severity.HIGH,
                    category=self.CATEGORY,
                    affected_item=f"Driver: {name}",
                    evidence=(
                        f"Driver Name: {name}\n"
                        f"Display Name: {display_name}\n"
                        f"Status: {state}\n"
                        f"Type: {driver_type}\n"
                        "Visible in: driverquery\n"
                        "Missing from: WMI"
                    ),
                    recommendation=(
                        "Investigate this driver discrepancy. Use kernel-level "
                        "tools to examine the driver module. Verify the driver "
                        "binary signature and origin."
                    ),
                    references=[
                        "https://attack.mitre.org/techniques/T1014/",
                    ],
                ))

        # Summary
        findings.append(Finding(
            check_id=self.CHECK_ID,
            title="Driver cross-validation summary",
            description=(
                f"Cross-validated driver lists from two sources. "
                f"WMI: {len(wmi_drivers)} drivers, "
                f"driverquery: {len(dq_drivers)} drivers. "
                f"{discrepancy_count} discrepancy(ies) detected."
            ),
            severity=Severity.INFO,
            category=self.CATEGORY,
            affected_item="Driver Cross-Validation",
            evidence=(
                f"WMI driver count: {len(wmi_drivers)}\n"
                f"driverquery count: {len(dq_drivers)}\n"
                f"Discrepancies: {discrepancy_count}"
            ),
            recommendation="Regularly cross-validate driver lists to detect rootkits.",
        ))

    def _check_sfc(self, findings: list[Finding]) -> None:
        """Run System File Checker to detect system file tampering."""

        sfc_result = run_ps(
            "sfc /verifyonly",
            as_json=False,
            timeout=120,
        )

        if not sfc_result.success:
            # SFC may fail if not truly elevated or if CBS service has issues
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="System File Checker could not run",
                description=(
                    "SFC /verifyonly could not complete. This may occur if the "
                    "Windows Component-Based Servicing (CBS) infrastructure is "
                    "damaged or if the process lacks sufficient privileges."
                ),
                severity=Severity.MEDIUM,
                category=self.CATEGORY,
                affected_item="System File Checker",
                evidence=f"Error: {sfc_result.error or 'unknown error'}",
                recommendation=(
                    "Try running 'sfc /verifyonly' manually from an elevated "
                    "command prompt. If CBS is damaged, run "
                    "'DISM /Online /Cleanup-Image /RestoreHealth' first."
                ),
                references=[
                    "https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/sfc",
                ],
            ))
            return

        output = sfc_result.output

        # Check for violations in SFC output
        output_lower = output.lower()

        if "windows resource protection found" in output_lower:
            # SFC found integrity violations
            # Extract relevant lines for evidence
            violation_lines = []
            for line in output.splitlines():
                line_stripped = line.strip()
                if line_stripped:
                    violation_lines.append(line_stripped)

            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="System file integrity violations detected",
                description=(
                    "System File Checker (SFC) found Windows Resource "
                    "Protection integrity violations. Modified system files "
                    "may indicate rootkit activity, supply chain tampering, "
                    "or system corruption."
                ),
                severity=Severity.HIGH,
                category=self.CATEGORY,
                affected_item="Windows System Files",
                evidence="\n".join(violation_lines[:50]),
                recommendation=(
                    "Run 'DISM /Online /Cleanup-Image /RestoreHealth' followed "
                    "by 'sfc /scannow' to repair system files. If violations "
                    "recur, investigate for rootkit activity. Review CBS.log at "
                    "C:\\Windows\\Logs\\CBS\\CBS.log for details on affected files."
                ),
                references=[
                    "https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/sfc",
                    "https://attack.mitre.org/techniques/T1014/",
                ],
            ))
        elif "did not find any integrity violations" in output_lower:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="System File Checker passed",
                description=(
                    "SFC /verifyonly completed and found no integrity "
                    "violations in protected system files."
                ),
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="Windows System Files",
                evidence="Windows Resource Protection did not find any integrity violations.",
                recommendation="No action required.",
            ))
        else:
            # Unexpected output -- report it for manual review
            trimmed_output = output[:500] if len(output) > 500 else output
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="System File Checker returned unexpected output",
                description=(
                    "SFC /verifyonly completed but produced unexpected output "
                    "that could not be automatically parsed."
                ),
                severity=Severity.MEDIUM,
                category=self.CATEGORY,
                affected_item="System File Checker",
                evidence=trimmed_output,
                recommendation=(
                    "Review the SFC output manually. Run 'sfc /verifyonly' "
                    "from an elevated command prompt and inspect the results."
                ),
            ))
