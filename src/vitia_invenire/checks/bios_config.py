"""BIOS-CFG-001: Check BIOS/UEFI configuration for risky settings.

Checks Wake on LAN, PXE boot, and USB boot priority via WMI and
registry queries. Flags WoL enabled as MEDIUM, PXE enabled as MEDIUM.
"""

from __future__ import annotations

import json

from vitia_invenire.checks.base import BaseCheck
from vitia_invenire.collectors import registry, wmi_collector
from vitia_invenire.collectors.powershell import run_ps
from vitia_invenire.models import Category, Finding, Severity


def _safe_str(value: object) -> str:
    if value is None:
        return "Unknown"
    return str(value)


class BiosConfigCheck(BaseCheck):
    """Check BIOS/UEFI settings for risky configurations."""

    CHECK_ID = "BIOS-CFG-001"
    NAME = "BIOS/UEFI Configuration Audit"
    DESCRIPTION = (
        "Check BIOS/UEFI settings including Wake on LAN, PXE boot, "
        "and USB boot priority via WMI and registry queries."
    )
    CATEGORY = Category.FIRMWARE
    REQUIRES_ADMIN = False

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        # --- Wake on LAN check ---
        # WoL is typically configured per network adapter via registry
        # and can be checked via WMI Win32_NetworkAdapterConfiguration
        wol_findings = self._check_wake_on_lan()
        findings.extend(wol_findings)

        # --- PXE Boot check ---
        pxe_findings = self._check_pxe_boot()
        findings.extend(pxe_findings)

        # --- USB Boot Priority check ---
        usb_boot_findings = self._check_usb_boot()
        findings.extend(usb_boot_findings)

        # --- General BIOS info ---
        bios_info_findings = self._collect_bios_info()
        findings.extend(bios_info_findings)

        return findings

    def _check_wake_on_lan(self) -> list[Finding]:
        """Check if Wake on LAN is enabled on any network adapter."""
        results: list[Finding] = []
        wol_enabled_adapters: list[dict] = []

        # Query network adapters with WoL capability via PowerShell
        # The registry key for each NIC stores WoL settings
        ps_script = (
            "Get-NetAdapter | ForEach-Object {"
            "  $adapterName = $_.Name;"
            "  $ifDesc = $_.InterfaceDescription;"
            "  $wolMagic = (Get-NetAdapterAdvancedProperty -Name $_.Name "
            "    -RegistryKeyword '*WakeOnMagicPacket' -ErrorAction SilentlyContinue);"
            "  $wolPattern = (Get-NetAdapterAdvancedProperty -Name $_.Name "
            "    -RegistryKeyword '*WakeOnPattern' -ErrorAction SilentlyContinue);"
            "  $pmWake = (Get-NetAdapterPowerManagement -Name $_.Name -ErrorAction SilentlyContinue);"
            "  [PSCustomObject]@{"
            "    AdapterName = $adapterName;"
            "    InterfaceDescription = $ifDesc;"
            "    WakeOnMagicPacket = if ($wolMagic) { $wolMagic.RegistryValue } else { 'N/A' };"
            "    WakeOnPattern = if ($wolPattern) { $wolPattern.RegistryValue } else { 'N/A' };"
            "    WakeOnMagicPacketFromPM = if ($pmWake) { $pmWake.WakeOnMagicPacket.ToString() } else { 'N/A' };"
            "  }"
            "}"
        )
        ps_result = run_ps(ps_script, timeout=30, as_json=True)
        if ps_result.success and ps_result.json_output:
            adapters = ps_result.json_output
            if isinstance(adapters, dict):
                adapters = [adapters]

            for adapter in adapters:
                wol_magic = str(adapter.get("WakeOnMagicPacket", "N/A"))
                wol_pattern = str(adapter.get("WakeOnPattern", "N/A"))
                wol_pm = str(adapter.get("WakeOnMagicPacketFromPM", "N/A"))

                # Registry value "1" or PowerManagement "Enabled" means WoL is on
                wol_on = (
                    wol_magic == "1"
                    or wol_pattern == "1"
                    or "enabled" in wol_pm.lower()
                )
                if wol_on:
                    wol_enabled_adapters.append({
                        "adapter": _safe_str(adapter.get("AdapterName")),
                        "interface": _safe_str(adapter.get("InterfaceDescription")),
                        "wake_on_magic_packet": wol_magic,
                        "wake_on_pattern": wol_pattern,
                        "wake_from_pm": wol_pm,
                    })

        if wol_enabled_adapters:
            results.append(Finding(
                check_id=self.CHECK_ID,
                title="Wake on LAN Enabled",
                description=(
                    f"Wake on LAN is enabled on {len(wol_enabled_adapters)} "
                    f"network adapter(s). WoL allows the system to be powered "
                    f"on remotely via specially crafted network packets, which "
                    f"could be abused by an attacker on the local network."
                ),
                severity=Severity.MEDIUM,
                category=self.CATEGORY,
                affected_item="Network Adapters (WoL)",
                evidence=json.dumps(wol_enabled_adapters, indent=2),
                recommendation=(
                    "Disable Wake on LAN in the BIOS/UEFI settings and in the "
                    "network adapter advanced properties unless it is required "
                    "for legitimate remote management."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1557/",
                ],
            ))

        return results

    def _check_pxe_boot(self) -> list[Finding]:
        """Check if PXE network boot is enabled."""
        results: list[Finding] = []
        pxe_indicators: list[dict] = []

        # Check boot configuration data for network boot entries
        ps_script = (
            "try {"
            "  $bcd = bcdedit /enum firmware 2>&1;"
            "  $bcdStr = $bcd -join \"`n\";"
            "  [PSCustomObject]@{"
            "    RawOutput = $bcdStr;"
            "    HasPxe = ($bcdStr -match 'PXE' -or $bcdStr -match 'Network' -or $bcdStr -match 'IPv[46]');"
            "  }"
            "} catch {"
            "  [PSCustomObject]@{ RawOutput = $_.Exception.Message; HasPxe = $false }"
            "}"
        )
        ps_result = run_ps(ps_script, timeout=30, as_json=True)
        if ps_result.success and ps_result.json_output:
            data = ps_result.json_output
            has_pxe = data.get("HasPxe", False)
            raw = _safe_str(data.get("RawOutput"))

            if has_pxe:
                pxe_indicators.append({
                    "source": "BCD Firmware Entries",
                    "detail": "PXE/Network boot entry found in BCD firmware enumeration",
                    "raw_excerpt": raw[:2000] if len(raw) > 2000 else raw,
                })

        # Check registry for PXE-related boot settings
        # HKLM\SYSTEM\CurrentControlSet\Services\PXE
        pxe_reg_values = registry.read_key(
            registry.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Services\PXE",
        )
        if pxe_reg_values:
            pxe_indicators.append({
                "source": "Registry PXE Service",
                "detail": "PXE service registry key exists",
                "values": [{"name": v.name, "data": str(v.data)} for v in pxe_reg_values],
            })

        # Check for WDS (Windows Deployment Services) client
        wds_values = registry.read_key(
            registry.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Services\WdsServer",
        )
        if wds_values:
            pxe_indicators.append({
                "source": "WDS Server Service",
                "detail": "Windows Deployment Services server registry key found",
            })

        if pxe_indicators:
            results.append(Finding(
                check_id=self.CHECK_ID,
                title="PXE/Network Boot Enabled",
                description=(
                    "PXE or network boot capability is detected on this system. "
                    "An attacker with network access could potentially serve a "
                    "malicious boot image to the system if PXE is enabled in "
                    "the BIOS boot order."
                ),
                severity=Severity.MEDIUM,
                category=self.CATEGORY,
                affected_item="PXE Boot Configuration",
                evidence=json.dumps(pxe_indicators, indent=2),
                recommendation=(
                    "Disable PXE/network boot in BIOS/UEFI settings unless "
                    "required for legitimate deployment purposes. If PXE is needed, "
                    "ensure the PXE server uses HTTPS boot with certificate "
                    "validation."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1542/003/",
                ],
            ))

        return results

    def _check_usb_boot(self) -> list[Finding]:
        """Check if USB boot is high in the boot order."""
        results: list[Finding] = []

        # Query boot order via BCD
        ps_script = (
            "try {"
            "  $bcd = bcdedit /enum firmware 2>&1;"
            "  $bcdStr = $bcd -join \"`n\";"
            "  $hasUsb = ($bcdStr -match 'USB' -or $bcdStr -match 'Removable');"
            "  [PSCustomObject]@{"
            "    RawOutput = $bcdStr;"
            "    HasUsbBoot = $hasUsb;"
            "  }"
            "} catch {"
            "  [PSCustomObject]@{ RawOutput = $_.Exception.Message; HasUsbBoot = $false }"
            "}"
        )
        ps_result = run_ps(ps_script, timeout=30, as_json=True)
        if ps_result.success and ps_result.json_output:
            data = ps_result.json_output
            has_usb = data.get("HasUsbBoot", False)
            raw = _safe_str(data.get("RawOutput"))

            if has_usb:
                results.append(Finding(
                    check_id=self.CHECK_ID,
                    title="USB Boot Entry Present in Firmware Boot Order",
                    description=(
                        "A USB or removable media boot entry is present in the "
                        "firmware boot order. This allows booting from USB devices, "
                        "which could be used by an attacker with physical access "
                        "to boot a malicious operating system."
                    ),
                    severity=Severity.LOW,
                    category=self.CATEGORY,
                    affected_item="USB Boot Order",
                    evidence=raw[:3000] if len(raw) > 3000 else raw,
                    recommendation=(
                        "If USB boot is not needed, disable it in BIOS/UEFI settings. "
                        "Set a strong BIOS/UEFI password to prevent unauthorized "
                        "boot order changes."
                    ),
                    references=[
                        "https://attack.mitre.org/techniques/T1200/",
                    ],
                ))

        return results

    def _collect_bios_info(self) -> list[Finding]:
        """Collect general BIOS configuration information."""
        results: list[Finding] = []

        bios_rows = wmi_collector.query(
            "Win32_BIOS",
            properties=["Manufacturer", "Name", "SMBIOSBIOSVersion",
                         "ReleaseDate", "Version", "SerialNumber",
                         "PrimaryBIOS", "BIOSVersion"],
        )

        system_rows = wmi_collector.query(
            "Win32_ComputerSystem",
            properties=["Manufacturer", "Model", "SystemType",
                         "BootupState", "ChassisBootupState",
                         "PowerOnPasswordStatus", "AdminPasswordStatus"],
        )

        evidence_parts: list[str] = []

        for row in bios_rows:
            evidence_parts.append(
                f"BIOS Manufacturer: {_safe_str(row.get('Manufacturer'))}\n"
                f"BIOS Version: {_safe_str(row.get('SMBIOSBIOSVersion'))}\n"
                f"BIOS Name: {_safe_str(row.get('Name'))}\n"
                f"Release Date: {_safe_str(row.get('ReleaseDate'))}"
            )

        # Check password protection status
        for row in system_rows:
            admin_pw = row.get("AdminPasswordStatus")
            poweron_pw = row.get("PowerOnPasswordStatus")
            evidence_parts.append(
                f"\nSystem: {_safe_str(row.get('Manufacturer'))} {_safe_str(row.get('Model'))}\n"
                f"System Type: {_safe_str(row.get('SystemType'))}\n"
                f"Admin Password Status: {_safe_str(admin_pw)}\n"
                f"Power-On Password Status: {_safe_str(poweron_pw)}"
            )
            # WMI AdminPasswordStatus: 1=Disabled, 2=Enabled, 3=Not Implemented, 4=Unknown
            if admin_pw == 1 or admin_pw is None:
                results.append(Finding(
                    check_id=self.CHECK_ID,
                    title="BIOS Administrator Password Not Set",
                    description=(
                        "The BIOS/UEFI administrator password is not set or is "
                        "disabled. Without a BIOS password, anyone with physical "
                        "access can change firmware settings including boot order, "
                        "Secure Boot, and virtualization settings."
                    ),
                    severity=Severity.MEDIUM,
                    category=self.CATEGORY,
                    affected_item="BIOS Password",
                    evidence=f"AdminPasswordStatus: {admin_pw}",
                    recommendation=(
                        "Set a strong BIOS/UEFI administrator password to prevent "
                        "unauthorized firmware configuration changes."
                    ),
                    references=[
                        "https://attack.mitre.org/techniques/T1542/001/",
                    ],
                ))

        if evidence_parts:
            results.append(Finding(
                check_id=self.CHECK_ID,
                title="BIOS/UEFI Configuration Summary",
                description="General BIOS/UEFI configuration and system information.",
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="BIOS Configuration",
                evidence="\n".join(evidence_parts),
                recommendation="Review BIOS/UEFI configuration for security best practices.",
                references=[
                    "https://learn.microsoft.com/en-us/windows/security/operating-system-security/system-security/secure-the-windows-10-boot-process",
                ],
            ))

        return results
