"""POL-003: Virtualization-Based Security Configuration Assessment.

Queries DeviceGuard WMI for VBS status, Credential Guard, and HVCI.
Checks registry for LSASS Protected Process Light (PPL) and Core
Isolation Memory Integrity settings to evaluate hardware-backed
security isolation.
"""

from __future__ import annotations

from vitia_invenire.checks.base import BaseCheck
from vitia_invenire.collectors import registry
from vitia_invenire.collectors.powershell import run_ps
from vitia_invenire.models import Category, Finding, Severity

# Registry paths for supplementary checks
_LSA_PATH = r"SYSTEM\CurrentControlSet\Control\Lsa"
_HVCI_PATH = (
    r"SYSTEM\CurrentControlSet\Control\DeviceGuard"
    r"\Scenarios\HypervisorEnforcedCodeIntegrity"
)

# VBS status names from Win32_DeviceGuard
_VBS_STATUS_NAMES: dict[int, str] = {
    0: "Not enabled",
    1: "Enabled but not running",
    2: "Running",
}

# Security services IDs in SecurityServicesRunning / SecurityServicesConfigured
_SECURITY_SERVICE_NAMES: dict[int, str] = {
    0: "No services running",
    1: "Credential Guard",
    2: "HVCI (Hypervisor-Enforced Code Integrity)",
    3: "System Guard Secure Launch",
    4: "SMM Firmware Measurement",
}

# Required security properties
_REQUIRED_PROPERTY_NAMES: dict[int, str] = {
    1: "Hypervisor support",
    2: "Secure Boot",
    3: "DMA Protection",
    4: "Secure Memory Overwrite",
    5: "NX Protections",
    6: "SMM Mitigations",
    7: "MBEC/Mode-Based Execute Control",
    8: "APIC Virtualization",
}


class VBSConfigCheck(BaseCheck):
    """Assess Virtualization-Based Security configuration and status."""

    CHECK_ID = "POL-003"
    NAME = "Virtualization-Based Security"
    DESCRIPTION = (
        "Queries DeviceGuard WMI for VBS status, Credential Guard, and "
        "HVCI (Hypervisor-Enforced Code Integrity). Checks registry for "
        "LSASS Protected Process Light and Core Isolation Memory Integrity "
        "to evaluate hardware-backed security isolation."
    )
    CATEGORY = Category.POLICY
    REQUIRES_ADMIN = False

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        self._check_vbs_status(findings)
        self._check_lsass_ppl(findings)
        self._check_memory_integrity_registry(findings)

        return findings

    def _check_vbs_status(self, findings: list[Finding]) -> None:
        """Query DeviceGuard WMI for VBS and security services status."""
        result = run_ps(
            "Get-CimInstance -ClassName Win32_DeviceGuard "
            "-Namespace root\\Microsoft\\Windows\\DeviceGuard "
            "-ErrorAction SilentlyContinue "
            "| Select-Object VirtualizationBasedSecurityStatus, "
            "SecurityServicesRunning, SecurityServicesConfigured, "
            "RequiredSecurityProperties, AvailableSecurityProperties",
            timeout=15,
            as_json=True,
        )

        if not result.success or result.json_output is None:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="DeviceGuard WMI query failed",
                description=(
                    "Could not query Win32_DeviceGuard WMI class. VBS status "
                    f"cannot be determined. Error: {result.error or 'no data returned'}"
                ),
                severity=Severity.MEDIUM,
                category=self.CATEGORY,
                affected_item="DeviceGuard WMI",
                evidence=result.output[:500] if result.output else "No output",
                recommendation=(
                    "Verify the DeviceGuard WMI namespace is accessible. "
                    "This may require Windows 10 1607 or later."
                ),
            ))
            return

        dg_data = result.json_output
        if isinstance(dg_data, list) and len(dg_data) > 0:
            dg_data = dg_data[0]

        # Parse VBS status
        vbs_status = dg_data.get("VirtualizationBasedSecurityStatus")
        try:
            vbs_status_int = int(vbs_status) if vbs_status is not None else -1
        except (ValueError, TypeError):
            vbs_status_int = -1

        vbs_status_name = _VBS_STATUS_NAMES.get(
            vbs_status_int, f"Unknown ({vbs_status})"
        )

        # Parse running services
        services_running = dg_data.get("SecurityServicesRunning", [])
        if services_running is None:
            services_running = []
        if isinstance(services_running, (int, float)):
            services_running = [int(services_running)]

        # Parse configured services
        services_configured = dg_data.get("SecurityServicesConfigured", [])
        if services_configured is None:
            services_configured = []
        if isinstance(services_configured, (int, float)):
            services_configured = [int(services_configured)]

        # Parse available and required security properties
        available_props = dg_data.get("AvailableSecurityProperties", [])
        if available_props is None:
            available_props = []
        if isinstance(available_props, (int, float)):
            available_props = [int(available_props)]

        required_props = dg_data.get("RequiredSecurityProperties", [])
        if required_props is None:
            required_props = []
        if isinstance(required_props, (int, float)):
            required_props = [int(required_props)]

        # Build evidence
        running_names = [
            _SECURITY_SERVICE_NAMES.get(s, f"Unknown ({s})")
            for s in services_running
        ]
        configured_names = [
            _SECURITY_SERVICE_NAMES.get(s, f"Unknown ({s})")
            for s in services_configured
        ]
        available_names = [
            _REQUIRED_PROPERTY_NAMES.get(p, f"Property {p}")
            for p in available_props
        ]
        required_names = [
            _REQUIRED_PROPERTY_NAMES.get(p, f"Property {p}")
            for p in required_props
        ]

        evidence_lines = [
            f"VBS Status: {vbs_status_int} ({vbs_status_name})",
            f"Security Services Running: {', '.join(running_names) if running_names else 'none'}",
            f"Security Services Configured: {', '.join(configured_names) if configured_names else 'none'}",
            f"Available Security Properties: {', '.join(available_names) if available_names else 'none'}",
            f"Required Security Properties: {', '.join(required_names) if required_names else 'none'}",
        ]
        evidence_text = "\n".join(evidence_lines)

        self.context["vbs_status"] = vbs_status_int
        self.context["services_running"] = list(services_running)

        # VBS not running
        if vbs_status_int != 2:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Virtualization-Based Security is not running",
                description=(
                    f"VBS status is: {vbs_status_name}. VBS provides hardware-based "
                    "isolation for critical Windows security features including "
                    "Credential Guard and HVCI. Without VBS, these protections "
                    "are unavailable, leaving credentials and kernel code "
                    "vulnerable to memory-based attacks."
                ),
                severity=Severity.HIGH,
                category=self.CATEGORY,
                affected_item="VBS Status",
                evidence=evidence_text,
                recommendation=(
                    "Enable VBS in BIOS/UEFI settings (enable virtualization "
                    "technology). Configure VBS via Group Policy: Computer "
                    "Configuration > Administrative Templates > System > "
                    "Device Guard > Turn On Virtualization Based Security."
                ),
                references=[
                    "https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity",
                    "https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/",
                ],
            ))

        # Credential Guard check
        credential_guard_running = 1 in services_running
        credential_guard_configured = 1 in services_configured

        if not credential_guard_running:
            if credential_guard_configured:
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title="Credential Guard configured but not running",
                    description=(
                        "Credential Guard is configured but not currently running. "
                        "This may indicate VBS is not active, the hardware does not "
                        "support it, or the feature failed to start. Without "
                        "Credential Guard, NTLM hashes and Kerberos tickets in "
                        "LSASS memory are vulnerable to credential theft tools."
                    ),
                    severity=Severity.HIGH,
                    category=self.CATEGORY,
                    affected_item="Credential Guard",
                    evidence=evidence_text,
                    recommendation=(
                        "Ensure VBS is enabled and running. Check Event Viewer "
                        "for DeviceGuard errors. Verify hardware support for "
                        "virtualization extensions."
                    ),
                    references=[
                        "https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/",
                        "https://attack.mitre.org/techniques/T1003/001/",
                    ],
                ))
            else:
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title="Credential Guard is not configured",
                    description=(
                        "Credential Guard is not configured or running. NTLM "
                        "password hashes and Kerberos TGTs stored in LSASS "
                        "process memory are unprotected and can be extracted "
                        "by credential dumping tools such as Mimikatz."
                    ),
                    severity=Severity.HIGH,
                    category=self.CATEGORY,
                    affected_item="Credential Guard",
                    evidence=evidence_text,
                    recommendation=(
                        "Enable Credential Guard via Group Policy or registry. "
                        "Requires UEFI Secure Boot, VBS support, and TPM 2.0 "
                        "(recommended). Configure via: Computer Configuration > "
                        "Administrative Templates > System > Device Guard."
                    ),
                    references=[
                        "https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/",
                        "https://attack.mitre.org/techniques/T1003/001/",
                    ],
                ))

        # HVCI check
        hvci_running = 2 in services_running
        hvci_configured = 2 in services_configured

        if not hvci_running:
            if hvci_configured:
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title="HVCI configured but not running",
                    description=(
                        "Hypervisor-Enforced Code Integrity is configured but "
                        "not currently running. HVCI prevents unsigned or "
                        "malicious kernel-mode code from executing by verifying "
                        "all code loaded into the kernel through the hypervisor."
                    ),
                    severity=Severity.MEDIUM,
                    category=self.CATEGORY,
                    affected_item="HVCI",
                    evidence=evidence_text,
                    recommendation=(
                        "Ensure VBS is enabled and running. Check for "
                        "incompatible drivers that may prevent HVCI from starting."
                    ),
                    references=[
                        "https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity",
                    ],
                ))
            else:
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title="HVCI is not active",
                    description=(
                        "Hypervisor-Enforced Code Integrity (Memory Integrity) "
                        "is not active. Without HVCI, kernel-mode code integrity "
                        "is enforced only by the OS kernel itself, which is "
                        "vulnerable to kernel exploits that bypass code signing."
                    ),
                    severity=Severity.MEDIUM,
                    category=self.CATEGORY,
                    affected_item="HVCI",
                    evidence=evidence_text,
                    recommendation=(
                        "Enable HVCI (Memory Integrity) via Windows Security > "
                        "Device Security > Core Isolation. Some older drivers "
                        "may be incompatible and need updating."
                    ),
                    references=[
                        "https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity",
                    ],
                ))

        # Summary of VBS assessment
        active_services: list[str] = []
        if credential_guard_running:
            active_services.append("Credential Guard")
        if hvci_running:
            active_services.append("HVCI")
        if 3 in services_running:
            active_services.append("System Guard Secure Launch")

        findings.append(Finding(
            check_id=self.CHECK_ID,
            title="VBS configuration assessment complete",
            description=(
                f"VBS status: {vbs_status_name}. "
                f"Active security services: "
                f"{', '.join(active_services) if active_services else 'none'}."
            ),
            severity=Severity.INFO,
            category=self.CATEGORY,
            affected_item="Virtualization-Based Security",
            evidence=evidence_text,
            recommendation=(
                "Review VBS configuration against organizational security "
                "requirements."
            ),
            references=[
                "https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity",
            ],
        ))

    def _check_lsass_ppl(self, findings: list[Finding]) -> None:
        """Check if LSASS is running as Protected Process Light (PPL)."""
        ppl_val = registry.read_value(
            registry.HKEY_LOCAL_MACHINE, _LSA_PATH, "RunAsPPL"
        )

        if ppl_val is None:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="LSASS RunAsPPL not configured",
                description=(
                    "The RunAsPPL registry value is not set under "
                    "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa. LSASS is not "
                    "configured to run as a Protected Process Light. Without "
                    "PPL protection, credential dumping tools can attach to "
                    "the LSASS process and extract plaintext passwords, NTLM "
                    "hashes, and Kerberos tickets from memory."
                ),
                severity=Severity.HIGH,
                category=self.CATEGORY,
                affected_item="LSASS Protection",
                evidence="RunAsPPL: not found (not configured)",
                recommendation=(
                    "Enable LSASS PPL by setting RunAsPPL to 1 under "
                    "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa. A reboot "
                    "is required. On Windows 11 22H2+, consider enabling the "
                    "newer LSASS protection via Windows Security settings."
                ),
                references=[
                    "https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection",
                    "https://attack.mitre.org/techniques/T1003/001/",
                ],
            ))
            return

        try:
            ppl_enabled = int(ppl_val.data)
        except (ValueError, TypeError):
            ppl_enabled = -1

        evidence_text = f"RunAsPPL: {ppl_val.data}"

        if ppl_enabled == 0:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="LSASS RunAsPPL is explicitly disabled",
                description=(
                    "RunAsPPL is set to 0, explicitly disabling LSASS Protected "
                    "Process Light. Credential dumping tools can freely access "
                    "LSASS process memory to extract credentials. This is worse "
                    "than the value being absent because it suggests deliberate "
                    "disabling, which may indicate tampering."
                ),
                severity=Severity.HIGH,
                category=self.CATEGORY,
                affected_item="LSASS Protection",
                evidence=evidence_text,
                recommendation=(
                    "Set RunAsPPL to 1 immediately and investigate who or "
                    "what disabled LSASS protection. Check for signs of "
                    "credential theft."
                ),
                references=[
                    "https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection",
                    "https://attack.mitre.org/techniques/T1003/001/",
                ],
            ))
        elif ppl_enabled == 1 or ppl_enabled == 2:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="LSASS Protected Process Light is enabled",
                description=(
                    f"RunAsPPL is set to {ppl_enabled}. LSASS is running with "
                    "Protected Process Light protection, preventing non-protected "
                    "processes from opening LSASS for memory access."
                ),
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="LSASS Protection",
                evidence=evidence_text,
                recommendation="No action needed. LSASS PPL is active.",
                references=[
                    "https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection",
                ],
            ))

    def _check_memory_integrity_registry(self, findings: list[Finding]) -> None:
        """Check Core Isolation Memory Integrity registry setting."""
        hvci_reg_val = registry.read_value(
            registry.HKEY_LOCAL_MACHINE, _HVCI_PATH, "Enabled"
        )

        if hvci_reg_val is None:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Core Isolation Memory Integrity registry not configured",
                description=(
                    "The HVCI Enabled registry value is not present. Core "
                    "Isolation Memory Integrity may not have been explicitly "
                    "configured via registry."
                ),
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="Memory Integrity Registry",
                evidence=(
                    "Registry key not found: "
                    "HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard"
                    "\\Scenarios\\HypervisorEnforcedCodeIntegrity\\Enabled"
                ),
                recommendation=(
                    "If HVCI is desired, set the Enabled value to 1 under "
                    "the HypervisorEnforcedCodeIntegrity scenario key."
                ),
            ))
            return

        try:
            hvci_enabled = int(hvci_reg_val.data)
        except (ValueError, TypeError):
            hvci_enabled = -1

        evidence_text = (
            f"HypervisorEnforcedCodeIntegrity\\Enabled: {hvci_reg_val.data}"
        )

        if hvci_enabled == 0:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Core Isolation Memory Integrity disabled in registry",
                description=(
                    "The HVCI registry key Enabled is set to 0. Memory "
                    "Integrity (Core Isolation) is explicitly disabled. This "
                    "may have been done to accommodate incompatible drivers "
                    "or may indicate tampering to allow loading of unsigned "
                    "kernel code."
                ),
                severity=Severity.MEDIUM,
                category=self.CATEGORY,
                affected_item="Memory Integrity Registry",
                evidence=evidence_text,
                recommendation=(
                    "Enable Memory Integrity by setting the Enabled value to 1. "
                    "Check for driver compatibility issues that may have caused "
                    "this to be disabled."
                ),
                references=[
                    "https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity",
                ],
            ))
        elif hvci_enabled == 1:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Core Isolation Memory Integrity enabled in registry",
                description=(
                    "The HVCI registry key Enabled is set to 1. Memory "
                    "Integrity (Core Isolation) is configured to be active."
                ),
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="Memory Integrity Registry",
                evidence=evidence_text,
                recommendation="No action needed. Memory Integrity is configured.",
            ))
