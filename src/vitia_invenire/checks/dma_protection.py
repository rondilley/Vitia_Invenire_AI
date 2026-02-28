"""DMA-001: Kernel DMA Protection and Thunderbolt Security Audit.

Checks Kernel DMA Protection status via DeviceGuard WMI or msinfo32.
Inspects Thunderbolt security level via registry. DMA attacks via
Thunderbolt or other external buses can read/write physical memory
to bypass OS security entirely.
"""

from __future__ import annotations

from vitia_invenire.checks.base import BaseCheck
from vitia_invenire.collectors import registry
from vitia_invenire.collectors.powershell import run_ps
from vitia_invenire.models import Category, Finding, Severity

# Thunderbolt security level registry path
_TB_SECURITY_PATH = (
    "SYSTEM\\CurrentControlSet\\Services\\TbtHostController\\Settings"
)
_TB_ALT_PATH = (
    "SOFTWARE\\Intel\\ThunderboltSoftware"
)

# Thunderbolt security levels
_TB_SECURITY_LEVELS: dict[int, str] = {
    0: "None (SL0) - No security, all devices allowed",
    1: "User Authorization (SL1) - User must approve devices",
    2: "Secure Connect (SL2) - User approval + challenge-response",
    3: "Display Port Only (SL3) - Only DP tunneling, no PCIe",
    4: "USB Only (SL4) - Only USB tunneling, no PCIe",
}


class DMAProtectionCheck(BaseCheck):
    """Audit Kernel DMA Protection and Thunderbolt security."""

    CHECK_ID = "DMA-001"
    NAME = "DMA Protection and Thunderbolt Audit"
    DESCRIPTION = (
        "Checks Kernel DMA Protection via DeviceGuard WMI, inspects "
        "Thunderbolt security level, and evaluates exposure to "
        "DMA-based hardware attacks."
    )
    CATEGORY = Category.FIRMWARE
    REQUIRES_ADMIN = False

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        # Check Kernel DMA Protection via msinfo32 approach
        dma_result = run_ps(
            "# Check Kernel DMA Protection status "
            "$dg = Get-CimInstance -ClassName Win32_DeviceGuard "
            "  -Namespace 'root\\Microsoft\\Windows\\DeviceGuard' "
            "  -ErrorAction SilentlyContinue; "
            "# Also check via SystemInfo registry "
            "$kernelDma = (Get-ItemProperty "
            "  'HKLM:\\SOFTWARE\\Policies\\Microsoft\\FVE' "
            "  -ErrorAction SilentlyContinue).DisableExternalDMAUnderLock; "
            "# Check msinfo32 output "
            "$msinfo = systeminfo.exe 2>&1 | Select-String 'DMA'; "
            "[PSCustomObject]@{ "
            "  AvailableSecurityProperties = if ($dg) { $dg.AvailableSecurityProperties } else { @() }; "
            "  SecurityServicesRunning = if ($dg) { $dg.SecurityServicesRunning } else { @() }; "
            "  VBSStatus = if ($dg) { $dg.VirtualizationBasedSecurityStatus } else { $null }; "
            "  DisableExternalDMAUnderLock = $kernelDma; "
            "  MSInfoDMA = if ($msinfo) { $msinfo.Line } else { 'Not found' } "
            "}",
            timeout=20,
            as_json=True,
        )

        dma_protection_enabled = False
        dma_evidence_parts: list[str] = []

        if dma_result.success and dma_result.json_output:
            dg_data = dma_result.json_output
            if isinstance(dg_data, list):
                dg_data = dg_data[0] if dg_data else {}

            available_props = dg_data.get("AvailableSecurityProperties", [])
            if isinstance(available_props, (list, tuple)):
                # Property 7 = Kernel DMA Protection available
                dma_protection_enabled = 7 in available_props
                dma_evidence_parts.append(
                    f"Available Security Properties: "
                    f"{', '.join(str(p) for p in available_props)}"
                )
            else:
                dma_evidence_parts.append(
                    f"Available Security Properties: {available_props}"
                )

            vbs = dg_data.get("VBSStatus")
            if vbs is not None:
                vbs_names = {0: "Not enabled", 1: "Enabled not running", 2: "Running"}
                dma_evidence_parts.append(f"VBS Status: {vbs_names.get(vbs, str(vbs))}")

            disable_dma_lock = dg_data.get("DisableExternalDMAUnderLock")
            if disable_dma_lock is not None:
                dma_evidence_parts.append(
                    f"DisableExternalDMAUnderLock: {disable_dma_lock}"
                )

            msinfo_dma = dg_data.get("MSInfoDMA", "Not found")
            if msinfo_dma and msinfo_dma != "Not found":
                dma_evidence_parts.append(f"SystemInfo DMA: {msinfo_dma}")

        # Check Thunderbolt presence and security level
        tb_present = False
        tb_security_level = -1

        # Check for Thunderbolt via PnP devices
        tb_device_result = run_ps(
            "Get-CimInstance Win32_PnPEntity -ErrorAction SilentlyContinue | "
            "Where-Object { $_.Name -like '*Thunderbolt*' } | "
            "Select-Object Name, DeviceID, Manufacturer, Status",
            timeout=15,
            as_json=True,
        )

        tb_devices: list[dict] = []
        if tb_device_result.success and tb_device_result.json_output:
            data = tb_device_result.json_output
            if isinstance(data, dict):
                tb_devices = [data]
            elif isinstance(data, list):
                tb_devices = data
            tb_present = len(tb_devices) > 0

        # Check Thunderbolt security level in registry
        tb_sec_val = registry.read_value(
            registry.HKEY_LOCAL_MACHINE, _TB_SECURITY_PATH, "SecurityLevel"
        )
        if tb_sec_val is not None:
            tb_security_level = tb_sec_val.data

        # Also check alternative registry path
        if tb_security_level < 0:
            tb_sec_alt = registry.read_value(
                registry.HKEY_LOCAL_MACHINE, _TB_ALT_PATH, "SecurityLevel"
            )
            if tb_sec_alt is not None:
                tb_security_level = tb_sec_alt.data

        # Report DMA protection findings
        if tb_present and not dma_protection_enabled:
            tb_evidence = []
            for dev in tb_devices:
                tb_evidence.append(
                    f"  {dev.get('Name', 'Unknown')} "
                    f"({dev.get('Manufacturer', 'Unknown')})"
                )

            tb_level_desc = _TB_SECURITY_LEVELS.get(
                tb_security_level,
                f"Unknown (level {tb_security_level})"
                if tb_security_level >= 0
                else "Not configured / unable to determine",
            )

            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="DMA Protection Disabled With Thunderbolt Present",
                description=(
                    "Kernel DMA Protection is not enabled but Thunderbolt "
                    "ports are present on this system. Without DMA protection, "
                    "a malicious Thunderbolt device can perform Direct Memory "
                    "Access attacks to read/write physical memory, bypass "
                    "login screens, extract encryption keys, and install "
                    "persistent backdoors."
                ),
                severity=Severity.HIGH,
                category=self.CATEGORY,
                affected_item="DMA Protection / Thunderbolt",
                evidence=(
                    "Kernel DMA Protection: DISABLED\n"
                    f"Thunderbolt Security Level: {tb_level_desc}\n"
                    f"Thunderbolt Devices:\n" + "\n".join(tb_evidence)
                    + "\n\n" + "\n".join(dma_evidence_parts)
                ),
                recommendation=(
                    "Enable Kernel DMA Protection in BIOS (requires compatible "
                    "hardware). Set Thunderbolt security level to at least SL1 "
                    "(User Authorization) or SL2 (Secure Connect). Consider "
                    "SL3 (DisplayPort only) if PCIe tunneling is not needed."
                ),
                references=[
                    "https://docs.microsoft.com/en-us/windows/security/information-protection/kernel-dma-protection-for-thunderbolt",
                    "https://thunderclap.io/",
                    "https://attack.mitre.org/techniques/T1200/",
                ],
            ))
        elif tb_present and dma_protection_enabled:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Kernel DMA Protection Active With Thunderbolt",
                description=(
                    "Kernel DMA Protection is enabled and Thunderbolt ports "
                    "are present. DMA attacks via Thunderbolt are mitigated."
                ),
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="DMA Protection / Thunderbolt",
                evidence="\n".join(dma_evidence_parts),
                recommendation="No action required.",
                references=[
                    "https://docs.microsoft.com/en-us/windows/security/information-protection/kernel-dma-protection-for-thunderbolt",
                ],
            ))
        elif not tb_present and not dma_protection_enabled:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="DMA Protection Not Active",
                description=(
                    "Kernel DMA Protection is not enabled. While no Thunderbolt "
                    "ports were detected, other DMA-capable interfaces (PCIe, "
                    "FireWire, SD Express) may still be present."
                ),
                severity=Severity.LOW,
                category=self.CATEGORY,
                affected_item="DMA Protection",
                evidence="\n".join(dma_evidence_parts) if dma_evidence_parts else "No DMA protection data available.",
                recommendation=(
                    "Consider enabling Kernel DMA Protection if supported by "
                    "the hardware to protect against physical DMA attacks."
                ),
                references=[
                    "https://docs.microsoft.com/en-us/windows/security/information-protection/kernel-dma-protection-for-thunderbolt",
                ],
            ))

        # Check Thunderbolt security level specifically
        if tb_present and tb_security_level >= 0:
            level_desc = _TB_SECURITY_LEVELS.get(
                tb_security_level, f"Unknown ({tb_security_level})"
            )

            if tb_security_level == 0:
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title="Thunderbolt Security Level: None (SL0)",
                    description=(
                        "Thunderbolt security is set to SL0 (None). All "
                        "devices are automatically connected without any "
                        "authorization. This provides no protection against "
                        "malicious Thunderbolt devices."
                    ),
                    severity=Severity.HIGH,
                    category=self.CATEGORY,
                    affected_item="Thunderbolt Security Level",
                    evidence=f"Thunderbolt Security Level: {level_desc}",
                    recommendation=(
                        "Increase Thunderbolt security level to at least SL1 "
                        "(User Authorization) in BIOS settings."
                    ),
                    references=[
                        "https://thunderspy.io/",
                    ],
                ))
            elif tb_security_level == 1:
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title="Thunderbolt Security Level: User Authorization (SL1)",
                    description=(
                        "Thunderbolt security is set to SL1 (User Authorization). "
                        "Users must approve new devices before they get PCIe "
                        "access. This provides basic protection but may be "
                        "vulnerable to Thunderspy attacks on pre-2019 hardware."
                    ),
                    severity=Severity.LOW,
                    category=self.CATEGORY,
                    affected_item="Thunderbolt Security Level",
                    evidence=f"Thunderbolt Security Level: {level_desc}",
                    recommendation=(
                        "Consider upgrading to SL2 (Secure Connect) for "
                        "challenge-response authentication of devices."
                    ),
                    references=[
                        "https://thunderspy.io/",
                    ],
                ))

        # Check for FireWire/1394 (another DMA vector)
        fw_result = run_ps(
            "Get-CimInstance Win32_PnPEntity -ErrorAction SilentlyContinue | "
            "Where-Object { $_.Name -like '*1394*' -or $_.Name -like '*FireWire*' } | "
            "Select-Object Name, DeviceID",
            timeout=10,
            as_json=True,
        )

        if fw_result.success and fw_result.json_output:
            fw_data = fw_result.json_output
            if isinstance(fw_data, dict):
                fw_data = [fw_data]
            if fw_data:
                fw_names = [str(d.get("Name", "Unknown")) for d in fw_data]
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title="FireWire/IEEE 1394 Interface Detected",
                    description=(
                        f"{len(fw_data)} FireWire/1394 interface(s) detected. "
                        f"FireWire provides direct DMA access and can be used "
                        f"for memory forensics or attacks."
                    ),
                    severity=Severity.MEDIUM,
                    category=self.CATEGORY,
                    affected_item="FireWire Interface",
                    evidence="\n".join(f"  - {n}" for n in fw_names),
                    recommendation=(
                        "Disable FireWire ports if not needed. Use Kernel DMA "
                        "Protection to mitigate DMA attacks."
                    ),
                    references=[
                        "https://attack.mitre.org/techniques/T1200/",
                    ],
                ))

        return findings
