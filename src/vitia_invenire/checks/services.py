"""SVC-001: Windows services security assessment.

Enumerates Windows services via Win32_Service and checks for services
running from TEMP/APPDATA directories, unquoted service paths, and
services running as SYSTEM from non-standard directories.
"""

from __future__ import annotations

import re

from vitia_invenire.checks.base import BaseCheck
from vitia_invenire.collectors import wmi_collector
from vitia_invenire.models import Category, Finding, Severity

# Directories that are considered system/trusted for SYSTEM-level services
_SYSTEM_DIRS: list[str] = [
    "C:\\WINDOWS\\",
    "C:\\WINDOWS\\SYSTEM32\\",
    "C:\\WINDOWS\\SYSWOW64\\",
    "C:\\PROGRAM FILES\\",
    "C:\\PROGRAM FILES (X86)\\",
    "C:\\PROGRAMDATA\\",
]

# Directories that indicate potentially suspicious service locations
_SUSPICIOUS_DIRS: list[str] = [
    "\\TEMP\\",
    "\\TMP\\",
    "\\APPDATA\\",
    "\\USERS\\",
    "\\DOWNLOADS\\",
    "\\DESKTOP\\",
    "\\DOCUMENTS\\",
]


def _extract_path_from_pathname(pathname: str) -> str:
    """Extract the executable path from a service PathName value.

    Handles quoted paths, paths with arguments, and environment variables.
    """
    if not pathname:
        return ""

    cleaned = pathname.strip()

    # If path starts with a quote, extract up to the closing quote
    if cleaned.startswith('"'):
        end_quote = cleaned.find('"', 1)
        if end_quote > 0:
            return cleaned[1:end_quote]
        return cleaned[1:]

    # Otherwise take everything up to the first space followed by a dash or slash
    # (which would be an argument)
    parts = cleaned.split()
    if parts:
        # Build path by joining parts until we find one that looks like an argument
        path_parts: list[str] = []
        for part in parts:
            if part.startswith("-") or part.startswith("/"):
                break
            path_parts.append(part)
            # Stop if this part ends with .exe, .sys, .dll
            if re.search(r"\.(exe|sys|dll|ocx)$", part, re.IGNORECASE):
                break
        return " ".join(path_parts)

    return cleaned


def _is_unquoted_service_path(pathname: str) -> bool:
    """Check if a service path with spaces is unquoted (exploitable)."""
    if not pathname:
        return False

    cleaned = pathname.strip()

    # Already quoted
    if cleaned.startswith('"'):
        return False

    # Extract path portion (before arguments)
    exe_path = _extract_path_from_pathname(cleaned)

    # Check if the path contains spaces (the vulnerability condition)
    if " " in exe_path:
        return True

    return False


class ServicesCheck(BaseCheck):
    """Analyze Windows services for security vulnerabilities."""

    CHECK_ID = "SVC-001"
    NAME = "Services Security Audit"
    DESCRIPTION = (
        "Enumerates Windows services and checks for services running "
        "from suspicious directories (TEMP/APPDATA), unquoted service "
        "paths, and SYSTEM-level services in non-standard locations."
    )
    CATEGORY = Category.SERVICES
    REQUIRES_ADMIN = False

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        service_rows = wmi_collector.query(
            "Win32_Service",
            properties=[
                "Name", "DisplayName", "PathName", "State",
                "StartMode", "StartName", "Description",
                "ServiceType",
            ],
        )

        if not service_rows:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Failed to enumerate services",
                description="Win32_Service query returned no results.",
                severity=Severity.MEDIUM,
                category=self.CATEGORY,
                affected_item="Win32_Service",
                evidence="WMI query returned empty results",
                recommendation="Verify WMI service is running.",
            ))
            return findings

        suspicious_path_count = 0
        unquoted_count = 0
        system_nonstandard_count = 0
        total_services = len(service_rows)

        for svc in service_rows:
            name = str(svc.get("Name", "Unknown"))
            display_name = str(svc.get("DisplayName", name))
            pathname = str(svc.get("PathName", ""))
            state = str(svc.get("State", "Unknown"))
            start_mode = str(svc.get("StartMode", "Unknown"))
            start_name = str(svc.get("StartName", ""))
            svc_desc = str(svc.get("Description", ""))

            exe_path = _extract_path_from_pathname(pathname)
            upper_path = exe_path.upper()
            upper_pathname = pathname.upper()

            # Check for services in suspicious directories (TEMP, APPDATA, etc.)
            for sus_dir in _SUSPICIOUS_DIRS:
                if sus_dir in upper_path:
                    suspicious_path_count += 1
                    findings.append(Finding(
                        check_id=self.CHECK_ID,
                        title=f"Service in suspicious directory: {display_name}",
                        description=(
                            f"Service '{display_name}' ({name}) runs from a suspicious "
                            f"directory containing '{sus_dir.strip(chr(92))}'. "
                            "Legitimate services rarely run from user-writable locations."
                        ),
                        severity=Severity.HIGH,
                        category=self.CATEGORY,
                        affected_item=f"Service: {name}",
                        evidence=(
                            f"Service: {display_name}\n"
                            f"Name: {name}\n"
                            f"Path: {pathname}\n"
                            f"State: {state}\n"
                            f"Start Mode: {start_mode}\n"
                            f"Account: {start_name}"
                        ),
                        recommendation=(
                            f"Investigate service '{name}'. If unauthorized, disable: "
                            f"Stop-Service -Name '{name}'; Set-Service -Name '{name}' -StartupType Disabled"
                        ),
                        references=[
                            "https://attack.mitre.org/techniques/T1543/003/",
                        ],
                    ))
                    break

            # Check for unquoted service paths
            if _is_unquoted_service_path(pathname):
                unquoted_count += 1
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title=f"Unquoted service path: {display_name}",
                    description=(
                        f"Service '{display_name}' ({name}) has an unquoted path "
                        "containing spaces. An attacker who can write to parent "
                        "directories can hijack the service by placing a malicious "
                        "executable at an intermediate path."
                    ),
                    severity=Severity.MEDIUM,
                    category=self.CATEGORY,
                    affected_item=f"Service: {name}",
                    evidence=(
                        f"Service: {display_name}\n"
                        f"Unquoted Path: {pathname}\n"
                        f"State: {state}\n"
                        f"Account: {start_name}"
                    ),
                    recommendation=(
                        f"Fix the service path by adding quotes. In an elevated command prompt: "
                        f"sc config \"{name}\" binPath= \"\\\"{exe_path}\\\"\""
                    ),
                    references=[
                        "https://attack.mitre.org/techniques/T1574/009/",
                    ],
                ))

            # Check for SYSTEM services running from non-system directories
            if start_name and "LOCALSYSTEM" in start_name.upper().replace(" ", ""):
                is_system_dir = any(upper_path.startswith(sd) for sd in _SYSTEM_DIRS)
                if exe_path and not is_system_dir:
                    system_nonstandard_count += 1
                    findings.append(Finding(
                        check_id=self.CHECK_ID,
                        title=f"SYSTEM service in non-standard location: {display_name}",
                        description=(
                            f"Service '{display_name}' ({name}) runs as LocalSystem "
                            "but is located outside standard system directories. "
                            "SYSTEM-level services from non-standard paths may indicate "
                            "persistence mechanisms or supply chain compromise."
                        ),
                        severity=Severity.HIGH,
                        category=self.CATEGORY,
                        affected_item=f"Service: {name}",
                        evidence=(
                            f"Service: {display_name}\n"
                            f"Path: {pathname}\n"
                            f"Account: {start_name}\n"
                            f"State: {state}\n"
                            f"Start Mode: {start_mode}"
                        ),
                        recommendation=(
                            f"Verify the legitimacy of service '{name}' running as SYSTEM "
                            "from a non-standard directory. Review the service binary."
                        ),
                        references=[
                            "https://attack.mitre.org/techniques/T1543/003/",
                        ],
                    ))

        # Summary finding
        findings.append(Finding(
            check_id=self.CHECK_ID,
            title="Service security audit summary",
            description=(
                f"Audited {total_services} services. "
                f"{suspicious_path_count} in suspicious directories, "
                f"{unquoted_count} with unquoted paths, "
                f"{system_nonstandard_count} SYSTEM services in non-standard locations."
            ),
            severity=Severity.INFO,
            category=self.CATEGORY,
            affected_item="Windows Services",
            evidence=(
                f"Total services: {total_services}\n"
                f"Suspicious paths: {suspicious_path_count}\n"
                f"Unquoted paths: {unquoted_count}\n"
                f"SYSTEM non-standard: {system_nonstandard_count}"
            ),
            recommendation="Regularly audit service configurations.",
        ))

        return findings
