"""RECOV-001: Check Windows Recovery Environment integrity.

Checks WinRE configuration via reagentc /info, hashes winre.wim,
and checks the WinRE version via DISM. Requires administrator privileges.
"""

from __future__ import annotations

import hashlib
import json
import os
import re

from vitia_invenire.checks.base import BaseCheck
from vitia_invenire.collectors.command import run_cmd
from vitia_invenire.collectors.powershell import run_ps
from vitia_invenire.models import Category, Finding, Severity

# Read buffer for hashing
_READ_BUFFER_SIZE = 65536

# Common WinRE locations
_WINRE_COMMON_PATHS = [
    r"C:\Recovery\WindowsRE\winre.wim",
    r"C:\Windows\System32\Recovery\winre.wim",
]


def _compute_sha256(file_path: str) -> str | None:
    """Compute SHA256 hash of a file."""
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


class RecoveryPartitionCheck(BaseCheck):
    """Check Windows Recovery Environment configuration and integrity."""

    CHECK_ID = "RECOV-001"
    NAME = "Recovery Environment Check"
    DESCRIPTION = (
        "Check WinRE via reagentc /info, hash winre.wim, "
        "and check version via DISM."
    )
    CATEGORY = Category.OEM_PREINSTALL
    REQUIRES_ADMIN = True

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        # 1. Check reagentc status
        reagentc_info = self._get_reagentc_info()
        winre_status = reagentc_info.get("status", "Unknown")
        winre_location = reagentc_info.get("location", "")

        evidence_parts: list[str] = [
            f"WinRE Status: {winre_status}",
            f"WinRE Location: {winre_location or 'Not found'}",
        ]

        if winre_status.lower() in ("disabled", "unknown"):
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Windows Recovery Environment Is Disabled",
                description=(
                    "The Windows Recovery Environment (WinRE) is disabled or "
                    "not configured. Without WinRE, the system cannot perform "
                    "automatic repair, startup repair, or system reset. "
                    "An attacker could have disabled WinRE to prevent recovery "
                    "after persistence."
                ),
                severity=Severity.MEDIUM,
                category=self.CATEGORY,
                affected_item="Windows Recovery Environment",
                evidence="\n".join(evidence_parts),
                recommendation=(
                    "Re-enable WinRE using 'reagentc /enable' from an elevated "
                    "command prompt. If WinRE files are missing, they may need "
                    "to be restored from installation media."
                ),
                references=[
                    "https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/reagentc-command-line-options",
                ],
            ))

        # 2. Locate and hash winre.wim
        winre_path = self._find_winre_wim(winre_location)

        if winre_path and os.path.exists(winre_path):
            file_size = os.path.getsize(winre_path)
            sha256 = _compute_sha256(winre_path)

            evidence_parts.append(f"WinRE WIM path: {winre_path}")
            evidence_parts.append(f"WinRE WIM size: {file_size} bytes ({file_size / (1024*1024):.1f} MB)")
            evidence_parts.append(f"WinRE WIM SHA256: {sha256 or 'hash_failed'}")

            # 3. Check WinRE version via DISM
            dism_info = self._get_winre_version_dism(winre_path)
            if dism_info:
                evidence_parts.append(f"WinRE version info: {json.dumps(dism_info, indent=2)}")

                winre_version = dism_info.get("version", "Unknown")
                evidence_parts.append(f"WinRE image version: {winre_version}")

            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Recovery Environment Inventory",
                description=(
                    f"Windows Recovery Environment is present. WinRE WIM "
                    f"located at {winre_path} ({file_size / (1024*1024):.1f} MB)."
                ),
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item=winre_path,
                evidence="\n".join(evidence_parts),
                recommendation=(
                    "Compare the WinRE WIM hash against known-good versions. "
                    "A tampered winre.wim could be used as a persistence "
                    "mechanism that survives normal OS recovery."
                ),
                references=[
                    "https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/deploy-windows-re",
                    "https://attack.mitre.org/techniques/T1542/",
                ],
            ))
        else:
            evidence_parts.append("WinRE WIM file: Not found")
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="WinRE WIM File Not Found",
                description=(
                    "The winre.wim file could not be located on this system. "
                    "It may be on an inaccessible recovery partition, deleted, "
                    "or the recovery environment may not be properly configured."
                ),
                severity=Severity.LOW,
                category=self.CATEGORY,
                affected_item="winre.wim",
                evidence="\n".join(evidence_parts),
                recommendation=(
                    "Verify WinRE configuration with 'reagentc /info'. "
                    "The WinRE WIM may be on a separate recovery partition "
                    "that requires mounting."
                ),
                references=[
                    "https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/reagentc-command-line-options",
                ],
            ))

        # 4. Check recovery partition existence
        partition_info = self._check_recovery_partition()
        if partition_info:
            evidence_parts.append(f"Recovery partition info: {json.dumps(partition_info, indent=2)}")

            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Recovery Partition Summary",
                description=(
                    f"Found {len(partition_info)} recovery-type partition(s)."
                ),
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="Recovery Partition",
                evidence=json.dumps(partition_info, indent=2, default=str),
                recommendation="Verify recovery partition contents are intact.",
                references=[],
            ))

        return findings

    def _get_reagentc_info(self) -> dict:
        """Run reagentc /info and parse the output."""
        result = run_cmd(["reagentc", "/info"], timeout=30)
        info: dict = {"raw_output": result.stdout}

        if not result.success:
            info["status"] = "Unknown"
            info["error"] = result.stderr
            return info

        output = result.stdout

        # Parse status
        status_match = re.search(r"Windows RE status:\s*(.+)", output, re.IGNORECASE)
        if status_match:
            info["status"] = status_match.group(1).strip()
        else:
            # Try alternate format
            if "enabled" in output.lower():
                info["status"] = "Enabled"
            elif "disabled" in output.lower():
                info["status"] = "Disabled"
            else:
                info["status"] = "Unknown"

        # Parse location
        loc_match = re.search(r"Windows RE location:\s*(.+)", output, re.IGNORECASE)
        if loc_match:
            info["location"] = loc_match.group(1).strip()

        # Parse BCD identifier
        bcd_match = re.search(r"Boot Configuration Data \(BCD\) identifier:\s*(.+)", output, re.IGNORECASE)
        if bcd_match:
            info["bcd_id"] = bcd_match.group(1).strip()

        # Parse recovery image location
        img_match = re.search(r"Recovery image location:\s*(.+)", output, re.IGNORECASE)
        if img_match:
            info["recovery_image"] = img_match.group(1).strip()

        return info

    def _find_winre_wim(self, reagentc_location: str) -> str | None:
        """Locate the winre.wim file."""
        # Try the reagentc-reported location first
        if reagentc_location:
            # reagentc reports something like "\\?\GLOBALROOT\device\harddisk0\partition3\Recovery\WindowsRE"
            # or a drive-letter path
            if "\\Recovery\\WindowsRE" in reagentc_location:
                # Try common drive letters
                for drive in ["C", "D", "E"]:
                    candidate = f"{drive}:\\Recovery\\WindowsRE\\winre.wim"
                    if os.path.exists(candidate):
                        return candidate

        # Try common paths
        for path in _WINRE_COMMON_PATHS:
            if os.path.exists(path):
                return path

        return None

    def _get_winre_version_dism(self, winre_path: str) -> dict | None:
        """Get WinRE image version using DISM."""
        result = run_cmd(
            ["dism", "/Get-WimInfo", f"/WimFile:{winre_path}", "/Index:1"],
            timeout=60,
        )

        if not result.success:
            return None

        info: dict = {}
        output = result.stdout

        version_match = re.search(r"Version\s*:\s*(.+)", output)
        if version_match:
            info["version"] = version_match.group(1).strip()

        name_match = re.search(r"Name\s*:\s*(.+)", output)
        if name_match:
            info["name"] = name_match.group(1).strip()

        desc_match = re.search(r"Description\s*:\s*(.+)", output)
        if desc_match:
            info["description"] = desc_match.group(1).strip()

        size_match = re.search(r"Size\s*:\s*(.+)", output)
        if size_match:
            info["size"] = size_match.group(1).strip()

        arch_match = re.search(r"Architecture\s*:\s*(.+)", output)
        if arch_match:
            info["architecture"] = arch_match.group(1).strip()

        return info if info else None

    def _check_recovery_partition(self) -> list[dict]:
        """Check for recovery partitions using PowerShell."""
        ps_script = (
            "Get-Partition | Where-Object { $_.Type -eq 'Recovery' -or $_.GptType -eq '{de94bba4-06d1-4d40-a16a-bfd50179d6ac}' } | "
            "Select-Object DiskNumber, PartitionNumber, Size, Type, GptType, DriveLetter"
        )
        result = run_ps(ps_script, timeout=30, as_json=True)
        if result.success and result.json_output:
            output = result.json_output
            if isinstance(output, dict):
                return [output]
            if isinstance(output, list):
                return output
        return []
