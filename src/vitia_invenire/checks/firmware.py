"""FW-001: Firmware security posture assessment.

Queries Win32_BIOS for version and manufacturer information, checks
Secure Boot status, TPM presence and version, Device Guard configuration,
and enumerates UEFI NVRAM variables to detect non-standard firmware
modifications.
"""

from __future__ import annotations

from vitia_invenire.checks.base import BaseCheck
from vitia_invenire.collectors import wmi_collector
from vitia_invenire.collectors.powershell import run_ps
from vitia_invenire.models import Category, Finding, Severity

# Well-known UEFI variable GUIDs from the UEFI specification
_KNOWN_UEFI_GUIDS: set[str] = {
    "8BE4DF61-93CA-11D2-AA0D-00E098032B8C",  # EFI Global Variable
    "05AD34BA-6F02-4214-952E-4DA0398E2BB9",  # Secure Boot DB
    "D719B2CB-3D3A-4596-A3BC-DAD00E67656F",  # UEFI Shell
    "C12A7328-F81F-11D2-BA4B-00A0C93EC93B",  # EFI System Partition
    "4D1ED05-38C7-4A6A-9CC6-4BCCA8B38C14",   # MS UEFI CA
    "77FA9ABD-0359-4D32-BD60-28F4E78F784B",  # Microsoft Variable
    "0ABBA7DC-E516-4167-BBAF-F68F95D26AE",   # Microsoft PCA
    "A7717414-C616-4977-9420-844712A735BF",   # Windows Boot Manager
    "4A67B082-0A4C-41CF-B6C7-440B29BB8C4F",  # KEK
    "D9BEF73D-E1FD-4042-B15B-1642CDE3F89E",  # Intel ME
}


class FirmwareSecurityCheck(BaseCheck):
    """Assess firmware security configuration including UEFI, Secure Boot, and TPM."""

    CHECK_ID = "FW-001"
    NAME = "Firmware Security Assessment"
    DESCRIPTION = (
        "Queries BIOS information, Secure Boot status, TPM configuration, "
        "Device Guard, and UEFI NVRAM variables to assess firmware-level "
        "security posture and detect potential tampering."
    )
    CATEGORY = Category.FIRMWARE
    REQUIRES_ADMIN = True

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        self._check_bios_info(findings)
        self._check_secure_boot(findings)
        self._check_tpm(findings)
        self._check_device_guard(findings)
        self._check_uefi_variables(findings)

        return findings

    def _check_bios_info(self, findings: list[Finding]) -> None:
        """Query Win32_BIOS for version and manufacturer details."""
        bios_rows = wmi_collector.query(
            "Win32_BIOS",
            properties=[
                "Manufacturer", "Name", "Version", "SMBIOSBIOSVersion",
                "ReleaseDate", "SerialNumber", "BIOSVersion",
            ],
        )

        if not bios_rows:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Unable to query BIOS information",
                description="Failed to query Win32_BIOS via WMI. BIOS assessment is incomplete.",
                severity=Severity.MEDIUM,
                category=self.CATEGORY,
                affected_item="Win32_BIOS",
                evidence="WMI query returned no results",
                recommendation="Verify WMI service is running and accessible.",
            ))
            return

        for bios in bios_rows:
            manufacturer = str(bios.get("Manufacturer", "Unknown"))
            bios_name = str(bios.get("Name", "Unknown"))
            version = str(bios.get("SMBIOSBIOSVersion", bios.get("Version", "Unknown")))
            release_date = str(bios.get("ReleaseDate", "Unknown"))
            serial = str(bios.get("SerialNumber", "Unknown"))

            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="BIOS information collected",
                description=f"BIOS manufacturer: {manufacturer}, version: {version}",
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="System BIOS",
                evidence=(
                    f"Manufacturer: {manufacturer}\n"
                    f"Name: {bios_name}\n"
                    f"Version: {version}\n"
                    f"Release Date: {release_date}\n"
                    f"Serial Number: {serial}"
                ),
                recommendation="Keep BIOS firmware updated to the latest version from the manufacturer.",
                references=[
                    "https://learn.microsoft.com/en-us/windows/security/hardware-security/",
                ],
            ))

    def _check_secure_boot(self, findings: list[Finding]) -> None:
        """Check whether Secure Boot is enabled via Confirm-SecureBootUEFI."""
        result = run_ps("Confirm-SecureBootUEFI", timeout=15, as_json=False)

        if not result.success:
            if "Cmdlet not supported" in str(result.error) or "not recognized" in str(result.error):
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title="Secure Boot status unavailable",
                    description=(
                        "The Confirm-SecureBootUEFI cmdlet is not available. "
                        "This system may use legacy BIOS instead of UEFI."
                    ),
                    severity=Severity.MEDIUM,
                    category=self.CATEGORY,
                    affected_item="Secure Boot",
                    evidence=f"Error: {result.error or 'cmdlet not available'}",
                    recommendation="Consider migrating to UEFI with Secure Boot enabled.",
                ))
            else:
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title="Secure Boot check failed",
                    description=f"Could not determine Secure Boot status: {result.error}",
                    severity=Severity.MEDIUM,
                    category=self.CATEGORY,
                    affected_item="Secure Boot",
                    evidence=result.output[:500] if result.output else "No output",
                    recommendation="Manually verify Secure Boot status in UEFI firmware settings.",
                ))
            return

        output_lower = result.output.strip().lower()
        if output_lower == "true":
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Secure Boot is enabled",
                description="UEFI Secure Boot is enabled on this system.",
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="Secure Boot",
                evidence="Confirm-SecureBootUEFI returned True",
                recommendation="No action needed. Secure Boot is properly configured.",
            ))
        elif output_lower == "false":
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Secure Boot is disabled",
                description=(
                    "UEFI Secure Boot is disabled on this system. Without Secure Boot, "
                    "the system is vulnerable to bootkit and rootkit attacks that load "
                    "malicious code before the operating system."
                ),
                severity=Severity.MEDIUM,
                category=self.CATEGORY,
                affected_item="Secure Boot",
                evidence="Confirm-SecureBootUEFI returned False",
                recommendation=(
                    "Enable Secure Boot in UEFI firmware settings. Ensure the OS was "
                    "installed in UEFI mode and all drivers are signed."
                ),
                references=[
                    "https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-secure-boot",
                ],
            ))

    def _check_tpm(self, findings: list[Finding]) -> None:
        """Query TPM presence and version via Get-Tpm."""
        result = run_ps(
            "Get-Tpm | Select-Object TpmPresent, TpmReady, TpmEnabled, "
            "TpmActivated, TpmOwned, ManufacturerId, ManufacturerIdTxt, "
            "ManufacturerVersion, ManagedAuthLevel, AutoProvisioning",
            timeout=20,
            as_json=True,
        )

        if not result.success or result.json_output is None:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="TPM not detected or query failed",
                description=(
                    "Could not query TPM information. The system may not have a TPM chip, "
                    "or it may be disabled in firmware settings."
                ),
                severity=Severity.MEDIUM,
                category=self.CATEGORY,
                affected_item="Trusted Platform Module",
                evidence=f"Get-Tpm error: {result.error or 'no TPM data returned'}",
                recommendation=(
                    "Ensure the system has a TPM 2.0 chip and it is enabled in UEFI settings. "
                    "TPM is required for BitLocker, Windows Hello, and Credential Guard."
                ),
                references=[
                    "https://learn.microsoft.com/en-us/windows/security/hardware-security/tpm/tpm-fundamentals",
                ],
            ))
            return

        tpm_data = result.json_output
        if isinstance(tpm_data, list) and len(tpm_data) > 0:
            tpm_data = tpm_data[0]

        tpm_present = tpm_data.get("TpmPresent", False)
        tpm_ready = tpm_data.get("TpmReady", False)
        tpm_enabled = tpm_data.get("TpmEnabled", False)
        manufacturer = str(tpm_data.get("ManufacturerIdTxt", "Unknown"))
        version = str(tpm_data.get("ManufacturerVersion", "Unknown"))

        evidence_lines = [
            f"TpmPresent: {tpm_present}",
            f"TpmReady: {tpm_ready}",
            f"TpmEnabled: {tpm_enabled}",
            f"TpmActivated: {tpm_data.get('TpmActivated', 'N/A')}",
            f"TpmOwned: {tpm_data.get('TpmOwned', 'N/A')}",
            f"Manufacturer: {manufacturer}",
            f"Version: {version}",
            f"AutoProvisioning: {tpm_data.get('AutoProvisioning', 'N/A')}",
        ]

        if not tpm_present:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="TPM is not present",
                description=(
                    "No Trusted Platform Module was detected on this system. "
                    "Without a TPM, hardware-backed encryption and attestation are unavailable."
                ),
                severity=Severity.MEDIUM,
                category=self.CATEGORY,
                affected_item="Trusted Platform Module",
                evidence="\n".join(evidence_lines),
                recommendation="Install or enable a TPM 2.0 module for hardware-backed security.",
            ))
        elif not tpm_enabled or not tpm_ready:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="TPM is present but not fully enabled",
                description=(
                    f"TPM is present (manufacturer: {manufacturer}) but is not fully "
                    f"enabled or ready. TpmEnabled={tpm_enabled}, TpmReady={tpm_ready}."
                ),
                severity=Severity.MEDIUM,
                category=self.CATEGORY,
                affected_item="Trusted Platform Module",
                evidence="\n".join(evidence_lines),
                recommendation="Fully enable and initialize the TPM in firmware settings.",
            ))
        else:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="TPM is present and enabled",
                description=f"TPM from {manufacturer} (version {version}) is enabled and ready.",
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="Trusted Platform Module",
                evidence="\n".join(evidence_lines),
                recommendation="No action needed. TPM is properly configured.",
            ))

    def _check_device_guard(self, findings: list[Finding]) -> None:
        """Check Device Guard / Credential Guard status via Win32_DeviceGuard."""
        dg_rows = wmi_collector.query(
            "Win32_DeviceGuard",
            properties=[
                "AvailableSecurityProperties",
                "CodeIntegrityPolicyEnforcementStatus",
                "RequiredSecurityProperties",
                "SecurityServicesConfigured",
                "SecurityServicesRunning",
                "UsermodeCodeIntegrityPolicyEnforcementStatus",
                "VirtualizationBasedSecurityStatus",
            ],
            namespace="root\\Microsoft\\Windows\\DeviceGuard",
        )

        if not dg_rows:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Device Guard status unavailable",
                description=(
                    "Unable to query Win32_DeviceGuard. Device Guard / Credential Guard "
                    "information is not available on this system."
                ),
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="Device Guard",
                evidence="WMI query to root\\Microsoft\\Windows\\DeviceGuard returned no results",
                recommendation="Device Guard requires Windows Enterprise or Education edition.",
            ))
            return

        for dg in dg_rows:
            vbs_status = dg.get("VirtualizationBasedSecurityStatus", 0)
            services_running = dg.get("SecurityServicesRunning", [])
            services_configured = dg.get("SecurityServicesConfigured", [])
            ci_status = dg.get("CodeIntegrityPolicyEnforcementStatus", 0)

            if services_running is None:
                services_running = []
            if services_configured is None:
                services_configured = []

            vbs_labels = {0: "Off", 1: "Configured", 2: "Running"}
            vbs_text = vbs_labels.get(vbs_status, f"Unknown ({vbs_status})")

            service_names = {
                1: "Credential Guard",
                2: "HVCI (Hypervisor Code Integrity)",
                3: "System Guard Secure Launch",
                4: "SMM Firmware Measurement",
            }

            running_names = [service_names.get(s, f"Service {s}") for s in services_running]
            configured_names = [service_names.get(s, f"Service {s}") for s in services_configured]

            evidence_text = (
                f"VBS Status: {vbs_text}\n"
                f"Services Configured: {', '.join(configured_names) if configured_names else 'None'}\n"
                f"Services Running: {', '.join(running_names) if running_names else 'None'}\n"
                f"Code Integrity Status: {ci_status}"
            )

            if vbs_status < 2:
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title="Virtualization-Based Security is not running",
                    description=(
                        f"VBS status is '{vbs_text}'. Virtualization-Based Security "
                        "provides hardware-level isolation for Credential Guard and HVCI."
                    ),
                    severity=Severity.MEDIUM,
                    category=self.CATEGORY,
                    affected_item="Device Guard / VBS",
                    evidence=evidence_text,
                    recommendation=(
                        "Enable Virtualization-Based Security via Group Policy or registry. "
                        "Requires Hyper-V capable hardware with IOMMU."
                    ),
                    references=[
                        "https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity",
                    ],
                ))
            else:
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title="Virtualization-Based Security is running",
                    description=f"VBS is active with services: {', '.join(running_names) if running_names else 'base VBS only'}",
                    severity=Severity.INFO,
                    category=self.CATEGORY,
                    affected_item="Device Guard / VBS",
                    evidence=evidence_text,
                    recommendation="No action needed. VBS is properly configured.",
                ))

    def _check_uefi_variables(self, findings: list[Finding]) -> None:
        """Enumerate UEFI NVRAM variable GUIDs and flag non-standard ones."""
        ps_cmd = (
            "$sig = '[DllImport(\"kernel32.dll\", SetLastError=true)]"
            "public static extern uint GetFirmwareEnvironmentVariableA("
            "string lpName, string lpGuid, IntPtr pBuffer, uint nSize);';"
            "$type = Add-Type -MemberDefinition $sig -Name FWEnv -Namespace Win32 -PassThru;"
            "$guids = @();"
            "foreach ($g in @("
            "'8BE4DF61-93CA-11D2-AA0D-00E098032B8C',"
            "'05AD34BA-6F02-4214-952E-4DA0398E2BB9',"
            "'D719B2CB-3D3A-4596-A3BC-DAD00E67656F',"
            "'77FA9ABD-0359-4D32-BD60-28F4E78F784B',"
            "'A7717414-C616-4977-9420-844712A735BF',"
            "'4A67B082-0A4C-41CF-B6C7-440B29BB8C4F',"
            "'D9BEF73D-E1FD-4042-B15B-1642CDE3F89E'"
            ")) {"
            "$buf = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(1024);"
            "$ret = $type::GetFirmwareEnvironmentVariableA('', \"{$g}\", $buf, 1024);"
            "$err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error();"
            "[System.Runtime.InteropServices.Marshal]::FreeHGlobal($buf);"
            "$guids += @{GUID=$g; ReturnValue=$ret; LastError=$err}"
            "};"
            "$guids"
        )

        result = run_ps(ps_cmd, timeout=20, as_json=True)

        if not result.success or result.json_output is None:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="UEFI NVRAM variable enumeration unavailable",
                description=(
                    "Could not enumerate UEFI firmware variables. This may indicate "
                    "a legacy BIOS system or insufficient privileges."
                ),
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="UEFI NVRAM Variables",
                evidence=f"Error: {result.error or 'query failed'}",
                recommendation="UEFI variable access requires administrator privileges and UEFI firmware.",
            ))
            return

        var_data = result.json_output
        if isinstance(var_data, dict):
            var_data = [var_data]

        accessible_guids: list[str] = []
        non_standard_guids: list[str] = []

        for entry in var_data:
            guid = str(entry.get("GUID", "")).upper()
            ret_val = entry.get("ReturnValue", 0)
            last_error = entry.get("LastError", 0)

            # ERROR_ENVVAR_NOT_FOUND (203) means the variable namespace exists
            # but the empty-name query found nothing. Return > 0 means data was read.
            if ret_val > 0 or last_error == 203:
                accessible_guids.append(guid)
                if guid not in {g.upper() for g in _KNOWN_UEFI_GUIDS}:
                    non_standard_guids.append(guid)

        if non_standard_guids:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Non-standard UEFI variable GUIDs detected",
                description=(
                    f"Found {len(non_standard_guids)} UEFI variable GUID(s) that are not "
                    "part of the standard UEFI specification or known Microsoft/Intel namespaces. "
                    "This may indicate firmware implants or unauthorized firmware modifications."
                ),
                severity=Severity.HIGH,
                category=self.CATEGORY,
                affected_item="UEFI NVRAM Variables",
                evidence=f"Non-standard GUIDs: {', '.join(non_standard_guids)}",
                recommendation=(
                    "Investigate the non-standard UEFI variable GUIDs. Compare against "
                    "the hardware vendor documentation. Consider re-flashing firmware "
                    "if unauthorized variables are confirmed."
                ),
                references=[
                    "https://uefi.org/specs/UEFI/2.10/03_Boot_Manager.html",
                ],
            ))
        else:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="UEFI NVRAM variables appear standard",
                description=f"Checked {len(accessible_guids)} UEFI variable namespaces; all are recognized.",
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="UEFI NVRAM Variables",
                evidence=f"Accessible GUIDs: {', '.join(accessible_guids) if accessible_guids else 'None'}",
                recommendation="No action needed.",
            ))
