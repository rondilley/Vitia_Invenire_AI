"""POL-007: USB AutoRun/AutoPlay policy assessment.

Checks NoDriveTypeAutoRun, DisableAutoplay, and removable storage
restriction policies to assess whether the system is protected against
USB-based attack vectors such as autorun malware and BadUSB.
"""

from __future__ import annotations

from vitia_invenire.checks.base import BaseCheck
from vitia_invenire.collectors import registry
from vitia_invenire.models import Category, Finding, Severity

# Registry paths
_EXPLORER_POLICIES_PATH = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
_AUTOPLAY_HANDLERS_PATH = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers"
_REMOVABLE_STORAGE_PATH = r"SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices"

# NoDriveTypeAutoRun bitmask: 0xFF disables autorun for all drive types
_AUTORUN_ALL_DISABLED = 0xFF

# Removable storage restriction subkeys to check
_STORAGE_RESTRICTION_SUBKEYS = ["Deny_Read", "Deny_Write", "Deny_Execute"]


class UsbAutorunCheck(BaseCheck):
    """Assess USB AutoRun/AutoPlay and removable storage policies."""

    CHECK_ID = "POL-007"
    NAME = "USB AutoRun/AutoPlay Policy"
    DESCRIPTION = (
        "Checks NoDriveTypeAutoRun, DisableAutoplay, and removable "
        "storage device restriction policies to assess protection "
        "against USB-based attack vectors."
    )
    CATEGORY = Category.POLICY
    REQUIRES_ADMIN = False

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        issues_found = 0

        issues_found += self._check_no_drive_type_autorun(
            findings,
            registry.HKEY_LOCAL_MACHINE,
            "HKLM",
        )
        issues_found += self._check_no_drive_type_autorun(
            findings,
            registry.HKEY_CURRENT_USER,
            "HKCU",
        )
        issues_found += self._check_disable_autoplay(findings)
        issues_found += self._check_removable_storage_restrictions(findings)

        # Summary finding
        findings.append(Finding(
            check_id=self.CHECK_ID,
            title="USB AutoRun/AutoPlay policy assessment summary",
            description=(
                f"Assessed AutoRun, AutoPlay, and removable storage "
                f"restriction policies. {issues_found} issue(s) identified."
            ),
            severity=Severity.INFO,
            category=self.CATEGORY,
            affected_item="USB/AutoRun Policies",
            evidence=(
                f"Controls checked: NoDriveTypeAutoRun (HKLM), "
                f"NoDriveTypeAutoRun (HKCU), DisableAutoplay, "
                f"RemovableStorageDevices restrictions\n"
                f"Issues found: {issues_found}"
            ),
            recommendation=(
                "Disable AutoRun for all drive types, disable AutoPlay, "
                "and consider restricting removable storage device access "
                "where operationally feasible."
            ),
        ))

        return findings

    def _check_no_drive_type_autorun(
        self,
        findings: list[Finding],
        hive: int,
        hive_name: str,
    ) -> int:
        """Check NoDriveTypeAutoRun registry value for a given hive."""
        val = registry.read_value(
            hive,
            _EXPLORER_POLICIES_PATH,
            "NoDriveTypeAutoRun",
        )

        if val is None:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title=f"NoDriveTypeAutoRun not configured in {hive_name}",
                description=(
                    f"The NoDriveTypeAutoRun value is not set in "
                    f"{hive_name}\\{_EXPLORER_POLICIES_PATH}. Without this "
                    f"value, AutoRun is enabled for most drive types, "
                    f"allowing malicious autorun.inf files on USB drives "
                    f"to execute automatically when inserted."
                ),
                severity=Severity.HIGH,
                category=self.CATEGORY,
                affected_item=f"{hive_name} NoDriveTypeAutoRun",
                evidence=(
                    f"Registry: {hive_name}\\{_EXPLORER_POLICIES_PATH}\n"
                    f"Value: NoDriveTypeAutoRun\n"
                    f"Current: not configured\n"
                    f"Expected: 0xFF (255) to disable all drive types"
                ),
                recommendation=(
                    f"Set NoDriveTypeAutoRun to 0xFF via Group Policy: "
                    f"Computer Configuration > Administrative Templates > "
                    f"Windows Components > AutoPlay Policies > "
                    f"Turn off AutoPlay (All drives). "
                    f"Or set DWORD value NoDriveTypeAutoRun = 255 at "
                    f"{hive_name}\\{_EXPLORER_POLICIES_PATH}."
                ),
                references=[
                    "https://learn.microsoft.com/en-us/windows/win32/shell/autoplay-reg",
                    "https://attack.mitre.org/techniques/T1091/",
                ],
            ))
            return 1

        try:
            current_value = int(val.data)
        except (ValueError, TypeError):
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title=f"NoDriveTypeAutoRun has unexpected value in {hive_name}",
                description=(
                    f"The NoDriveTypeAutoRun value in {hive_name} is set to "
                    f"'{val.data}' which could not be parsed as an integer."
                ),
                severity=Severity.MEDIUM,
                category=self.CATEGORY,
                affected_item=f"{hive_name} NoDriveTypeAutoRun",
                evidence=(
                    f"Registry: {hive_name}\\{_EXPLORER_POLICIES_PATH}\n"
                    f"Value: NoDriveTypeAutoRun = {val.data} (type: {val.type})"
                ),
                recommendation="Verify and correct the NoDriveTypeAutoRun registry value.",
            ))
            return 1

        if current_value != _AUTORUN_ALL_DISABLED:
            # Determine which drive types are still enabled
            enabled_types: list[str] = []
            drive_type_bits = {
                0x01: "Unknown drives",
                0x04: "Removable drives",
                0x08: "Fixed drives",
                0x10: "Network drives",
                0x20: "CD-ROM drives",
                0x40: "RAM disks",
                0x80: "Reserved",
            }
            for bit, drive_type in drive_type_bits.items():
                if not (current_value & bit):
                    enabled_types.append(drive_type)

            findings.append(Finding(
                check_id=self.CHECK_ID,
                title=f"AutoRun not fully disabled in {hive_name}",
                description=(
                    f"NoDriveTypeAutoRun in {hive_name} is set to "
                    f"0x{current_value:02X} ({current_value}), but 0xFF (255) "
                    f"is required to disable AutoRun for all drive types. "
                    f"AutoRun remains enabled for: "
                    f"{', '.join(enabled_types) if enabled_types else 'some types'}."
                ),
                severity=Severity.HIGH,
                category=self.CATEGORY,
                affected_item=f"{hive_name} NoDriveTypeAutoRun",
                evidence=(
                    f"Registry: {hive_name}\\{_EXPLORER_POLICIES_PATH}\n"
                    f"Value: NoDriveTypeAutoRun = 0x{current_value:02X} ({current_value})\n"
                    f"Expected: 0xFF (255)\n"
                    f"AutoRun still enabled for: {', '.join(enabled_types)}"
                ),
                recommendation=(
                    f"Set NoDriveTypeAutoRun to 0xFF (255) to disable AutoRun "
                    f"for all drive types via Group Policy or direct registry edit."
                ),
                references=[
                    "https://learn.microsoft.com/en-us/windows/win32/shell/autoplay-reg",
                    "https://attack.mitre.org/techniques/T1091/",
                ],
            ))
            return 1

        findings.append(Finding(
            check_id=self.CHECK_ID,
            title=f"AutoRun is fully disabled in {hive_name}",
            description=(
                f"NoDriveTypeAutoRun in {hive_name} is set to 0xFF, "
                f"disabling AutoRun for all drive types."
            ),
            severity=Severity.INFO,
            category=self.CATEGORY,
            affected_item=f"{hive_name} NoDriveTypeAutoRun",
            evidence=(
                f"Registry: {hive_name}\\{_EXPLORER_POLICIES_PATH}\n"
                f"Value: NoDriveTypeAutoRun = 0x{current_value:02X} ({current_value})"
            ),
            recommendation="No action needed.",
        ))
        return 0

    def _check_disable_autoplay(self, findings: list[Finding]) -> int:
        """Check if AutoPlay is disabled via the AutoplayHandlers key."""
        val = registry.read_value(
            registry.HKEY_LOCAL_MACHINE,
            _AUTOPLAY_HANDLERS_PATH,
            "DisableAutoplay",
        )

        if val is None:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="AutoPlay DisableAutoplay value not configured",
                description=(
                    "The DisableAutoplay value is not set in "
                    f"HKLM\\{_AUTOPLAY_HANDLERS_PATH}. AutoPlay may "
                    "present a dialog when removable media is inserted, "
                    "which could be leveraged for social engineering attacks."
                ),
                severity=Severity.MEDIUM,
                category=self.CATEGORY,
                affected_item="DisableAutoplay",
                evidence=(
                    f"Registry: HKLM\\{_AUTOPLAY_HANDLERS_PATH}\n"
                    f"Value: DisableAutoplay\n"
                    f"Current: not configured\n"
                    f"Expected: 1"
                ),
                recommendation=(
                    "Set DisableAutoplay to 1 via Group Policy: "
                    "Computer Configuration > Administrative Templates > "
                    "Windows Components > AutoPlay Policies > "
                    "Turn off AutoPlay. "
                    f"Or set DWORD DisableAutoplay = 1 at "
                    f"HKLM\\{_AUTOPLAY_HANDLERS_PATH}."
                ),
                references=[
                    "https://learn.microsoft.com/en-us/windows/win32/shell/autoplay-reg",
                ],
            ))
            return 1

        try:
            current_value = int(val.data)
        except (ValueError, TypeError):
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="DisableAutoplay has unexpected value",
                description=(
                    f"The DisableAutoplay value is set to '{val.data}' "
                    "which could not be parsed as an integer."
                ),
                severity=Severity.MEDIUM,
                category=self.CATEGORY,
                affected_item="DisableAutoplay",
                evidence=(
                    f"Registry: HKLM\\{_AUTOPLAY_HANDLERS_PATH}\n"
                    f"Value: DisableAutoplay = {val.data} (type: {val.type})"
                ),
                recommendation="Verify and correct the DisableAutoplay registry value.",
            ))
            return 1

        if current_value != 1:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="AutoPlay is not disabled",
                description=(
                    f"DisableAutoplay is set to {current_value} instead of 1. "
                    "AutoPlay presents a dialog when removable media is "
                    "inserted, which could be leveraged for social engineering "
                    "or automated execution attacks."
                ),
                severity=Severity.MEDIUM,
                category=self.CATEGORY,
                affected_item="DisableAutoplay",
                evidence=(
                    f"Registry: HKLM\\{_AUTOPLAY_HANDLERS_PATH}\n"
                    f"Value: DisableAutoplay = {current_value}\n"
                    f"Expected: 1"
                ),
                recommendation=(
                    "Set DisableAutoplay to 1 to fully disable AutoPlay behavior."
                ),
                references=[
                    "https://learn.microsoft.com/en-us/windows/win32/shell/autoplay-reg",
                ],
            ))
            return 1

        findings.append(Finding(
            check_id=self.CHECK_ID,
            title="AutoPlay is disabled",
            description="DisableAutoplay is set to 1, disabling AutoPlay prompts.",
            severity=Severity.INFO,
            category=self.CATEGORY,
            affected_item="DisableAutoplay",
            evidence=(
                f"Registry: HKLM\\{_AUTOPLAY_HANDLERS_PATH}\n"
                f"Value: DisableAutoplay = {current_value}"
            ),
            recommendation="No action needed.",
        ))
        return 0

    def _check_removable_storage_restrictions(self, findings: list[Finding]) -> int:
        """Check if removable storage device restrictions are configured."""
        subkeys = registry.enumerate_subkeys(
            registry.HKEY_LOCAL_MACHINE,
            _REMOVABLE_STORAGE_PATH,
        )

        restrictions_found: list[str] = []
        for subkey in subkeys:
            # Check each device class for deny policies
            for restriction in _STORAGE_RESTRICTION_SUBKEYS:
                val = registry.read_value(
                    registry.HKEY_LOCAL_MACHINE,
                    _REMOVABLE_STORAGE_PATH + "\\" + subkey,
                    restriction,
                )
                if val is not None:
                    try:
                        if int(val.data) == 1:
                            restrictions_found.append(f"{subkey}: {restriction}")
                    except (ValueError, TypeError):
                        pass

        if not subkeys or not restrictions_found:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="No removable storage restrictions configured",
                description=(
                    "No removable storage device restriction policies were "
                    "found. Without these policies, users can freely read "
                    "from and write to removable USB storage devices, "
                    "increasing the risk of data exfiltration and malware "
                    "introduction via USB."
                ),
                severity=Severity.LOW,
                category=self.CATEGORY,
                affected_item="RemovableStorageDevices",
                evidence=(
                    f"Registry: HKLM\\{_REMOVABLE_STORAGE_PATH}\n"
                    f"Subkeys found: {len(subkeys)}\n"
                    f"Active restrictions: none"
                ),
                recommendation=(
                    "Consider configuring removable storage restrictions "
                    "via Group Policy: Computer Configuration > "
                    "Administrative Templates > System > Removable Storage "
                    "Access. Deny read/write/execute as appropriate for "
                    "the organization's security requirements."
                ),
                references=[
                    "https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-storage",
                    "https://attack.mitre.org/techniques/T1091/",
                ],
            ))
            return 1

        findings.append(Finding(
            check_id=self.CHECK_ID,
            title=f"Removable storage restrictions configured ({len(restrictions_found)})",
            description=(
                f"Found {len(restrictions_found)} removable storage "
                f"restriction(s) across {len(subkeys)} device class(es)."
            ),
            severity=Severity.INFO,
            category=self.CATEGORY,
            affected_item="RemovableStorageDevices",
            evidence=(
                f"Registry: HKLM\\{_REMOVABLE_STORAGE_PATH}\n"
                f"Active restrictions:\n"
                + "\n".join(f"  {r}" for r in restrictions_found)
            ),
            recommendation="Review restrictions to ensure they meet security requirements.",
        ))
        return 0
