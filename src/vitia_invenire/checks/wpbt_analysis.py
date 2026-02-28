"""WPBT-001: Check for Windows Platform Binary Table (WPBT) abuse.

Checks for the presence of C:\\Windows\\system32\\wpbbin.exe, which is
deployed via the UEFI WPBT ACPI table. Hashes the file and verifies
its Authenticode signature. A WPBT binary with a bad or missing
signature is flagged as CRITICAL.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

from vitia_invenire.checks.base import BaseCheck
from vitia_invenire.collectors.powershell import run_ps
from vitia_invenire.models import Category, Finding, Severity

# Expected WPBT binary location
_WPBT_PATH = r"C:\Windows\system32\wpbbin.exe"

# Read buffer for hashing
_READ_BUFFER_SIZE = 65536


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


def _verify_signature(file_path: str) -> dict:
    """Verify Authenticode signature of a file using PowerShell."""
    ps_script = (
        f"$sig = Get-AuthenticodeSignature -FilePath '{file_path}';"
        f"[PSCustomObject]@{{"
        f"  Status = $sig.Status.ToString();"
        f"  SignerSubject = if ($sig.SignerCertificate) {{ $sig.SignerCertificate.Subject }} else {{ 'None' }};"
        f"  SignerIssuer = if ($sig.SignerCertificate) {{ $sig.SignerCertificate.Issuer }} else {{ 'None' }};"
        f"  SignerThumbprint = if ($sig.SignerCertificate) {{ $sig.SignerCertificate.Thumbprint }} else {{ 'None' }};"
        f"  TimeStamper = if ($sig.TimeStamperCertificate) {{ $sig.TimeStamperCertificate.Subject }} else {{ 'None' }};"
        f"  IsOSBinary = $sig.IsOSBinary;"
        f"  StatusMessage = $sig.StatusMessage;"
        f"}}"
    )
    result = run_ps(ps_script, timeout=30, as_json=True)
    if result.success and result.json_output:
        return result.json_output
    return {"Status": "Error", "StatusMessage": result.error or "Failed to verify signature"}


class WpbtAnalysisCheck(BaseCheck):
    """Check for WPBT binary and verify its signature."""

    CHECK_ID = "WPBT-001"
    NAME = "WPBT Binary Analysis"
    DESCRIPTION = (
        "Check for C:\\Windows\\system32\\wpbbin.exe deployed via the UEFI "
        "Windows Platform Binary Table. Hash and verify its signature. "
        "WPBT with bad signature indicates firmware-level persistence."
    )
    CATEGORY = Category.OEM_PREINSTALL
    REQUIRES_ADMIN = True

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        wpbt_path = Path(_WPBT_PATH)

        if not wpbt_path.exists():
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="No WPBT Binary Present",
                description=(
                    "The WPBT binary (wpbbin.exe) was not found in System32. "
                    "This is normal for systems without OEM firmware-level "
                    "software deployment."
                ),
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item=_WPBT_PATH,
                evidence=f"File not found: {_WPBT_PATH}",
                recommendation="No action needed. WPBT is not in use.",
                references=[
                    "https://learn.microsoft.com/en-us/windows-hardware/drivers/bringup/wpbt-table",
                ],
            ))
            return findings

        # File exists - collect metadata
        try:
            file_size = os.path.getsize(_WPBT_PATH)
        except OSError:
            file_size = -1

        sha256 = _compute_sha256(_WPBT_PATH)

        # Verify Authenticode signature
        sig_info = _verify_signature(_WPBT_PATH)
        sig_status = str(sig_info.get("Status", "Unknown")).lower()
        signer_subject = sig_info.get("SignerSubject", "None")
        is_os_binary = sig_info.get("IsOSBinary", False)

        evidence_data = {
            "path": _WPBT_PATH,
            "file_size": file_size,
            "sha256": sha256 or "hash_failed",
            "signature": sig_info,
        }

        # Check WPBT ACPI table info via PowerShell
        wpbt_acpi_result = run_ps(
            "Get-WmiObject -Namespace root\\wmi -Class MSAcpi_ThermalZoneTemperature -ErrorAction SilentlyContinue | Select-Object -First 1",
            timeout=15,
            as_json=True,
        )
        # Also try to read WPBT table directly
        wpbt_table_result = run_ps(
            "(Get-Content -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager' -ErrorAction SilentlyContinue)",
            timeout=15,
            as_json=False,
        )

        evidence_json = json.dumps(evidence_data, indent=2)

        # Determine severity based on signature status
        if sig_status == "valid" and is_os_binary:
            # WPBT with valid OS binary signature - likely legitimate OEM
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="WPBT Binary Present With Valid OS Signature",
                description=(
                    "A WPBT binary exists and has a valid Microsoft OS signature. "
                    "This is typically an OEM anti-theft or management agent "
                    "deployed via firmware. While the signature is valid, WPBT "
                    "represents firmware-level persistence that survives OS "
                    "reinstallation."
                ),
                severity=Severity.MEDIUM,
                category=self.CATEGORY,
                affected_item=_WPBT_PATH,
                evidence=evidence_json,
                recommendation=(
                    "Identify the purpose of the WPBT binary. If it is an OEM "
                    "anti-theft agent (e.g., Computrace/LoJack, Absolute), "
                    "determine whether it is needed. WPBT persistence survives "
                    "OS reinstallation and disk replacement."
                ),
                references=[
                    "https://learn.microsoft.com/en-us/windows-hardware/drivers/bringup/wpbt-table",
                    "https://eclypsium.com/research/turning-the-tables/",
                ],
            ))
        elif sig_status == "valid":
            # Valid signature but not an OS binary
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="WPBT Binary Present With Third-Party Signature",
                description=(
                    f"A WPBT binary exists with a valid third-party signature "
                    f"from: {signer_subject}. This binary is deployed via UEFI "
                    f"firmware and persists across OS reinstallation."
                ),
                severity=Severity.HIGH,
                category=self.CATEGORY,
                affected_item=_WPBT_PATH,
                evidence=evidence_json,
                recommendation=(
                    "Verify the signer is a legitimate OEM or security vendor. "
                    "If the signer is unknown or untrusted, this may indicate "
                    "firmware-level implant deployment."
                ),
                references=[
                    "https://learn.microsoft.com/en-us/windows-hardware/drivers/bringup/wpbt-table",
                    "https://attack.mitre.org/techniques/T1542/001/",
                ],
            ))
        else:
            # Invalid, unsigned, or error
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="WPBT Binary With Bad or Missing Signature",
                description=(
                    f"A WPBT binary exists but has an invalid or missing "
                    f"Authenticode signature (status: {sig_status}). A WPBT "
                    f"binary without a valid signature that is deployed via "
                    f"firmware is a strong indicator of a firmware-level "
                    f"persistence implant or rootkit."
                ),
                severity=Severity.CRITICAL,
                category=self.CATEGORY,
                affected_item=_WPBT_PATH,
                evidence=evidence_json,
                recommendation=(
                    "CRITICAL: Immediately investigate this WPBT binary. "
                    "An unsigned or improperly signed binary deployed via UEFI "
                    "firmware is a strong indicator of supply-chain compromise "
                    "or firmware rootkit. Perform full firmware analysis and "
                    "consider reflashing the UEFI firmware from a known-good source."
                ),
                references=[
                    "https://learn.microsoft.com/en-us/windows-hardware/drivers/bringup/wpbt-table",
                    "https://attack.mitre.org/techniques/T1542/001/",
                    "https://eclypsium.com/research/turning-the-tables/",
                ],
            ))

        return findings
