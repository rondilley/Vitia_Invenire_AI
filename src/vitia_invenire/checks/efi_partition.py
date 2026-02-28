"""ESP-001: EFI System Partition inspection.

Mounts the EFI System Partition via mountvol, enumerates all files,
and checks for unexpected directories or files that may indicate
bootkit infection (e.g., BlackLotus indicators).
"""

from __future__ import annotations

import re

from vitia_invenire.checks.base import BaseCheck
from vitia_invenire.collectors.command import run_cmd
from vitia_invenire.collectors.powershell import run_ps
from vitia_invenire.models import Category, Finding, Severity

# Expected top-level directories in the EFI System Partition
_EXPECTED_EFI_DIRS: set[str] = {
    "EFI",
    "BOOT",
    "SYSTEM VOLUME INFORMATION",
    "$RECYCLE.BIN",
}

# Expected subdirectories under EFI
_EXPECTED_EFI_SUBDIRS: set[str] = {
    "BOOT",
    "MICROSOFT",
    "HP",
    "DELL",
    "LENOVO",
    "ASUS",
    "ACER",
    "MSI",
    "INTEL",
    "SAMSUNG",
    "VMWARE",
    "UBUNTU",
    "DEBIAN",
    "REDHAT",
    "SUSE",
    "FEDORA",
    "GRUB",
}

# Known BlackLotus indicators
_BLACKLOTUS_INDICATORS: list[str] = [
    "system32",
    "grubx64.efi.bak",
    "winload.efi.bak",
    "bootmgfw.efi.bak",
    "bootmgfw_backup.efi",
]


class EfiPartitionCheck(BaseCheck):
    """Inspect the EFI System Partition for bootkit indicators."""

    CHECK_ID = "ESP-001"
    NAME = "EFI System Partition Inspection"
    DESCRIPTION = (
        "Mounts and inspects the EFI System Partition for unexpected "
        "files or directories that may indicate bootkit infection, "
        "such as BlackLotus or other UEFI-level threats."
    )
    CATEGORY = Category.FIRMWARE
    REQUIRES_ADMIN = True

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        # Find an available drive letter for mounting
        mount_letter = self._find_available_drive_letter()
        if not mount_letter:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="No available drive letter for ESP mount",
                description="Could not find an available drive letter to mount the EFI System Partition.",
                severity=Severity.MEDIUM,
                category=self.CATEGORY,
                affected_item="EFI System Partition",
                evidence="All drive letters Z-G are in use",
                recommendation="Free up a drive letter and retry.",
            ))
            return findings

        mount_path = f"{mount_letter}:\\"
        mounted = False

        try:
            # Mount the EFI System Partition
            mounted = self._mount_esp(findings, mount_letter)
            if not mounted:
                return findings

            # Enumerate all files in the ESP
            self._enumerate_esp_files(findings, mount_path)

        finally:
            # Always unmount
            if mounted:
                self._unmount_esp(mount_letter)

        return findings

    def _find_available_drive_letter(self) -> str | None:
        """Find an available drive letter for mounting."""
        result = run_ps(
            "$used = (Get-PSDrive -PSProvider FileSystem).Name; "
            "'Z','Y','X','W','V','U','T','S','R','Q','P','O','N','M','L','K','J','I','H','G' | "
            "Where-Object { $_ -notin $used } | Select-Object -First 1",
            timeout=10,
            as_json=False,
        )
        if result.success and result.output.strip():
            letter = result.output.strip()
            if len(letter) == 1 and letter.isalpha():
                return letter
        return None

    def _mount_esp(self, findings: list[Finding], drive_letter: str) -> bool:
        """Mount the EFI System Partition to the specified drive letter."""
        # Find the ESP volume
        vol_result = run_ps(
            "$espVol = Get-Partition | Where-Object { $_.GptType -eq "
            "'{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}' } | "
            "Select-Object -First 1 -ExpandProperty AccessPaths | "
            "Where-Object { $_ -match '\\\\\\\\\\?\\\\' }; "
            "if ($espVol) { $espVol } else { 'NOT_FOUND' }",
            timeout=15,
            as_json=False,
        )

        if not vol_result.success or "NOT_FOUND" in vol_result.output:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="EFI System Partition not found",
                description=(
                    "Could not locate the EFI System Partition (GPT type "
                    "c12a7328-f81f-11d2-ba4b-00a0c93ec93b). This system may "
                    "use legacy BIOS boot."
                ),
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="EFI System Partition",
                evidence=f"Get-Partition output: {vol_result.output[:300] if vol_result.output else 'none'}",
                recommendation="No action needed if this is a legacy BIOS system.",
            ))
            return False

        esp_volume = vol_result.output.strip()

        # Mount using mountvol
        mount_result = run_cmd(
            ["mountvol", f"{drive_letter}:", esp_volume],
            timeout=15,
        )

        if not mount_result.success:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Failed to mount EFI System Partition",
                description=f"mountvol command failed: {mount_result.stderr[:300] if mount_result.stderr else 'unknown error'}",
                severity=Severity.MEDIUM,
                category=self.CATEGORY,
                affected_item="EFI System Partition",
                evidence=f"mountvol {drive_letter}: {esp_volume}\nError: {mount_result.stderr[:300] if mount_result.stderr else 'none'}",
                recommendation="Try mounting manually: mountvol Z: <ESP_VOLUME_PATH>",
            ))
            return False

        return True

    def _unmount_esp(self, drive_letter: str) -> None:
        """Unmount the EFI System Partition."""
        run_cmd(["mountvol", f"{drive_letter}:", "/D"], timeout=10)

    def _enumerate_esp_files(self, findings: list[Finding], mount_path: str) -> None:
        """List all files in the ESP and check for suspicious content."""
        # Enumerate all files recursively
        result = run_ps(
            f"Get-ChildItem -Path '{mount_path}' -Recurse -Force -ErrorAction SilentlyContinue | "
            "Select-Object FullName, Name, Length, LastWriteTime, "
            "@{N='IsDir';E={$_.PSIsContainer}}, Extension",
            timeout=30,
            as_json=True,
        )

        if not result.success or result.json_output is None:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Failed to enumerate ESP contents",
                description=f"Could not list files in ESP at {mount_path}.",
                severity=Severity.MEDIUM,
                category=self.CATEGORY,
                affected_item=mount_path,
                evidence=f"Error: {result.error or 'unknown'}",
                recommendation="Manually inspect the ESP contents.",
            ))
            return

        files = result.json_output
        if isinstance(files, dict):
            files = [files]

        total_files = len(files)
        suspicious_files: list[str] = []
        blacklotus_indicators: list[str] = []
        unexpected_dirs: list[str] = []

        # Enumerate top-level directories
        top_result = run_ps(
            f"Get-ChildItem -Path '{mount_path}' -Force -Directory -ErrorAction SilentlyContinue | "
            "Select-Object Name",
            timeout=10,
            as_json=True,
        )

        if top_result.success and top_result.json_output is not None:
            top_dirs = top_result.json_output
            if isinstance(top_dirs, dict):
                top_dirs = [top_dirs]

            for td in top_dirs:
                dir_name = str(td.get("Name", "")).upper()
                if dir_name and dir_name not in _EXPECTED_EFI_DIRS:
                    unexpected_dirs.append(dir_name)

        # Check EFI subdirectories
        efi_sub_result = run_ps(
            f"Get-ChildItem -Path '{mount_path}EFI' -Force -Directory -ErrorAction SilentlyContinue | "
            "Select-Object Name",
            timeout=10,
            as_json=True,
        )

        if efi_sub_result.success and efi_sub_result.json_output is not None:
            efi_subs = efi_sub_result.json_output
            if isinstance(efi_subs, dict):
                efi_subs = [efi_subs]

            for es in efi_subs:
                sub_name = str(es.get("Name", "")).upper()
                if sub_name and sub_name not in _EXPECTED_EFI_SUBDIRS:
                    unexpected_dirs.append(f"EFI\\{sub_name}")

        # Check all files for suspicious patterns
        for f in files:
            full_name = str(f.get("FullName", ""))
            name = str(f.get("Name", "")).lower()
            is_dir = f.get("IsDir", False)
            extension = str(f.get("Extension", "")).lower()

            relative_path = full_name.replace(mount_path, "").lower()

            # Check for BlackLotus indicators
            for indicator in _BLACKLOTUS_INDICATORS:
                if indicator in relative_path:
                    blacklotus_indicators.append(full_name)
                    break

            # Check for suspicious file types that should not be in ESP
            if not is_dir and extension in (".exe", ".dll", ".sys", ".bat", ".cmd",
                                             ".ps1", ".vbs", ".js", ".hta"):
                # EFI files are .efi, not .exe/.dll
                if extension not in (".efi",):
                    suspicious_files.append(full_name)

            # Check for files outside the EFI directory
            if not is_dir and not relative_path.startswith("efi"):
                if extension not in ("", ".log", ".txt"):
                    suspicious_files.append(full_name)

        # Report BlackLotus indicators
        if blacklotus_indicators:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="BlackLotus bootkit indicators detected",
                description=(
                    "Files matching known BlackLotus UEFI bootkit indicators were found "
                    "in the EFI System Partition. BlackLotus is a UEFI bootkit that can "
                    "bypass Secure Boot and persist below the operating system."
                ),
                severity=Severity.CRITICAL,
                category=self.CATEGORY,
                affected_item="EFI System Partition",
                evidence="Indicator files:\n" + "\n".join(f"  {f}" for f in blacklotus_indicators),
                recommendation=(
                    "This system may be infected with the BlackLotus bootkit. "
                    "Perform a full forensic investigation. Re-flash the UEFI firmware "
                    "and reinstall the operating system from trusted media."
                ),
                references=[
                    "https://www.welivesecurity.com/2023/03/01/blacklotus-uefi-bootkit-myth-confirmed/",
                    "https://www.microsoft.com/en-us/security/blog/2023/04/11/guidance-for-investigating-attacks-using-cve-2022-21894-the-blacklotus-campaign/",
                ],
            ))

        # Report unexpected directories
        if unexpected_dirs:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title=f"Unexpected directories in ESP ({len(unexpected_dirs)})",
                description=(
                    "Non-standard directories were found in the EFI System Partition. "
                    "The ESP should only contain boot-related EFI files."
                ),
                severity=Severity.HIGH,
                category=self.CATEGORY,
                affected_item="EFI System Partition",
                evidence="Unexpected directories:\n" + "\n".join(f"  {d}" for d in unexpected_dirs),
                recommendation="Investigate unexpected ESP directories for bootkit or other malicious content.",
            ))

        # Report suspicious files
        if suspicious_files:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title=f"Suspicious files in ESP ({len(suspicious_files)})",
                description=(
                    "Files with non-EFI extensions or in unexpected locations were "
                    "found in the EFI System Partition."
                ),
                severity=Severity.HIGH,
                category=self.CATEGORY,
                affected_item="EFI System Partition",
                evidence="Suspicious files:\n" + "\n".join(f"  {f}" for f in suspicious_files[:30]),
                recommendation="Investigate suspicious files in the ESP.",
            ))

        # Summary
        findings.append(Finding(
            check_id=self.CHECK_ID,
            title="EFI System Partition inspection summary",
            description=(
                f"Inspected {total_files} files/directories in the ESP. "
                f"Found {len(blacklotus_indicators)} BlackLotus indicators, "
                f"{len(unexpected_dirs)} unexpected directories, "
                f"{len(suspicious_files)} suspicious files."
            ),
            severity=Severity.INFO,
            category=self.CATEGORY,
            affected_item="EFI System Partition",
            evidence=(
                f"Total items: {total_files}\n"
                f"BlackLotus indicators: {len(blacklotus_indicators)}\n"
                f"Unexpected dirs: {len(unexpected_dirs)}\n"
                f"Suspicious files: {len(suspicious_files)}"
            ),
            recommendation="Regularly inspect the ESP for unauthorized modifications.",
        ))
