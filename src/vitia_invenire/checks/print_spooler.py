"""SPOOL-001: Print Spooler Security Audit.

Checks the Print Spooler service status, inspects Point and Print
registry settings that enable PrintNightmare-style attacks, and
examines the spool driver directory for unsigned DLLs that may
indicate exploitation or persistence.
"""

from __future__ import annotations

from vitia_invenire.checks.base import BaseCheck
from vitia_invenire.collectors import registry
from vitia_invenire.collectors.powershell import run_ps
from vitia_invenire.models import Category, Finding, Severity

# Registry paths for Point and Print configuration
_POINT_AND_PRINT_PATH = (
    "SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers\\PointAndPrint"
)
_POINT_AND_PRINT_ALT_PATH = (
    "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Print\\Providers"
)

# Spooler service registry path
_SPOOLER_SVC_PATH = "SYSTEM\\CurrentControlSet\\Services\\Spooler"

# Spool driver directory
_SPOOL_DRIVER_DIR = "C:\\Windows\\System32\\spool\\drivers"


class PrintSpoolerCheck(BaseCheck):
    """Audit Print Spooler service and Point and Print security."""

    CHECK_ID = "SPOOL-001"
    NAME = "Print Spooler Security Audit"
    DESCRIPTION = (
        "Checks Print Spooler service status, Point and Print registry "
        "settings (NoWarningNoElevationOnInstall), and scans the spool "
        "driver directory for unsigned DLLs."
    )
    CATEGORY = Category.CONFIGURATION
    REQUIRES_ADMIN = False

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        # Check Print Spooler service status
        svc_result = run_ps(
            "Get-Service -Name Spooler -ErrorAction SilentlyContinue | "
            "Select-Object Name, Status, StartType, DisplayName",
            timeout=15,
            as_json=True,
        )

        spooler_running = False
        if svc_result.success and svc_result.json_output:
            svc_data = svc_result.json_output
            if isinstance(svc_data, list):
                svc_data = svc_data[0] if svc_data else {}
            status = str(svc_data.get("Status", "")).lower()
            start_type = str(svc_data.get("StartType", ""))

            # PowerShell Status enum: 1=Stopped, 4=Running
            spooler_running = status in ("running", "4")

            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Print Spooler Service Status",
                description=(
                    f"The Print Spooler service is "
                    f"{'running' if spooler_running else 'stopped'}. "
                    f"Start type: {start_type}."
                ),
                severity=Severity.INFO if not spooler_running else Severity.LOW,
                category=self.CATEGORY,
                affected_item="Spooler Service",
                evidence=(
                    f"Service: Spooler\n"
                    f"Status: {'Running' if spooler_running else 'Stopped'}\n"
                    f"Start Type: {start_type}"
                ),
                recommendation=(
                    "If printing is not required, disable the Print Spooler "
                    "service to reduce attack surface (PrintNightmare, etc.)."
                ),
                references=[
                    "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527",
                ],
            ))
        else:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Print Spooler Service Not Found",
                description="Could not query the Print Spooler service status.",
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="Spooler Service",
                evidence="Get-Service -Name Spooler returned no results.",
                recommendation="No action required if printing is not needed.",
                references=[
                    "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527",
                ],
            ))

        # Check Point and Print registry settings
        no_warning = registry.read_value(
            registry.HKEY_LOCAL_MACHINE,
            _POINT_AND_PRINT_PATH,
            "NoWarningNoElevationOnInstall",
        )
        no_warning_update = registry.read_value(
            registry.HKEY_LOCAL_MACHINE,
            _POINT_AND_PRINT_PATH,
            "UpdatePromptSettings",
        )
        restrict_driver = registry.read_value(
            registry.HKEY_LOCAL_MACHINE,
            _POINT_AND_PRINT_PATH,
            "RestrictDriverInstallationToAdministrators",
        )

        pnp_evidence_parts: list[str] = []
        pnp_dangerous = False

        if no_warning is not None:
            pnp_evidence_parts.append(
                f"NoWarningNoElevationOnInstall: {no_warning.data}"
            )
            if no_warning.data == 1:
                pnp_dangerous = True
        else:
            pnp_evidence_parts.append(
                "NoWarningNoElevationOnInstall: Not configured"
            )

        if no_warning_update is not None:
            pnp_evidence_parts.append(
                f"UpdatePromptSettings: {no_warning_update.data}"
            )
            if no_warning_update.data == 1:
                pnp_dangerous = True
        else:
            pnp_evidence_parts.append(
                "UpdatePromptSettings: Not configured"
            )

        if restrict_driver is not None:
            pnp_evidence_parts.append(
                f"RestrictDriverInstallationToAdministrators: {restrict_driver.data}"
            )
            if restrict_driver.data == 0:
                pnp_dangerous = True
        else:
            pnp_evidence_parts.append(
                "RestrictDriverInstallationToAdministrators: Not configured "
                "(secure default after KB5005010)"
            )

        if pnp_dangerous:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Insecure Point and Print Configuration (PrintNightmare)",
                description=(
                    "Point and Print is configured to allow driver installation "
                    "without elevation or warnings. This is the exact "
                    "configuration that enables PrintNightmare "
                    "(CVE-2021-34527) exploitation for local privilege "
                    "escalation and remote code execution."
                ),
                severity=Severity.HIGH,
                category=self.CATEGORY,
                affected_item="Point and Print Registry",
                evidence="\n".join(pnp_evidence_parts),
                recommendation=(
                    "Set NoWarningNoElevationOnInstall to 0, "
                    "UpdatePromptSettings to 0, and "
                    "RestrictDriverInstallationToAdministrators to 1 at "
                    f"HKLM\\{_POINT_AND_PRINT_PATH}. Apply Microsoft "
                    "security update KB5005010 or later."
                ),
                references=[
                    "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527",
                    "https://support.microsoft.com/en-us/topic/kb5005010-restricting-installation-of-new-printer-drivers-after-applying-the-july-6-2021-updates-31b91c02-05bc-4ada-a7ea-183b129578a7",
                ],
            ))
        else:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Point and Print Configuration Reviewed",
                description=(
                    "Point and Print settings do not indicate a vulnerable "
                    "PrintNightmare configuration."
                ),
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="Point and Print Registry",
                evidence="\n".join(pnp_evidence_parts),
                recommendation="Continue to monitor Point and Print settings.",
                references=[
                    "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527",
                ],
            ))

        # Scan spool driver directory for unsigned DLLs
        dll_check_result = run_ps(
            f"Get-ChildItem -Path '{_SPOOL_DRIVER_DIR}' -Recurse -Filter '*.dll' "
            "-ErrorAction SilentlyContinue | "
            "ForEach-Object { "
            "  $sig = Get-AuthenticodeSignature $_.FullName -ErrorAction SilentlyContinue; "
            "  [PSCustomObject]@{ "
            "    Path = $_.FullName; "
            "    Name = $_.Name; "
            "    Size = $_.Length; "
            "    LastWriteTime = $_.LastWriteTime.ToString('o'); "
            "    SignatureStatus = if ($sig) { $sig.Status.ToString() } else { 'Unknown' }; "
            "    SignerSubject = if ($sig -and $sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { 'None' } "
            "  } "
            "} | Where-Object { $_.SignatureStatus -ne 'Valid' }",
            timeout=60,
            as_json=True,
        )

        if dll_check_result.success and dll_check_result.json_output:
            unsigned_dlls = dll_check_result.json_output
            if isinstance(unsigned_dlls, dict):
                unsigned_dlls = [unsigned_dlls]

            if unsigned_dlls:
                evidence_lines = []
                for dll in unsigned_dlls[:50]:
                    evidence_lines.append(
                        f"DLL: {dll.get('Name', 'Unknown')}\n"
                        f"  Path: {dll.get('Path', 'Unknown')}\n"
                        f"  Size: {dll.get('Size', 0)} bytes\n"
                        f"  Last Modified: {dll.get('LastWriteTime', 'Unknown')}\n"
                        f"  Signature: {dll.get('SignatureStatus', 'Unknown')}\n"
                        f"  Signer: {dll.get('SignerSubject', 'None')}"
                    )
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title="Unsigned DLLs in Spool Driver Directory",
                    description=(
                        f"{len(unsigned_dlls)} unsigned or invalidly signed "
                        f"DLL(s) found in the print spooler driver directory. "
                        f"Unsigned DLLs in this location may indicate "
                        f"PrintNightmare exploitation or printer driver-based "
                        f"persistence."
                    ),
                    severity=Severity.HIGH,
                    category=self.CATEGORY,
                    affected_item=_SPOOL_DRIVER_DIR,
                    evidence=(
                        f"Total unsigned DLLs: {len(unsigned_dlls)}\n\n"
                        + "\n\n".join(evidence_lines)
                        + (f"\n\n... and {len(unsigned_dlls) - 50} more"
                           if len(unsigned_dlls) > 50 else "")
                    ),
                    recommendation=(
                        "Investigate each unsigned DLL. Compare file hashes "
                        "against known printer driver files. Remove any "
                        "unauthorized DLLs and investigate for compromise."
                    ),
                    references=[
                        "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527",
                        "https://attack.mitre.org/techniques/T1547/012/",
                    ],
                ))

        return findings
