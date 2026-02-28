"""SB-KEY-001: Validate Secure Boot UEFI key databases.

Queries PK, KEK, db, and dbx via PowerShell Get-SecureBootUEFI.
Validates that PK is from a known OEM, KEK contains Microsoft,
and dbx is populated. Unknown PK = CRITICAL. Empty dbx = HIGH.
Requires administrator privileges.
"""

from __future__ import annotations

import json

from vitia_invenire.checks.base import BaseCheck
from vitia_invenire.collectors.powershell import run_ps
from vitia_invenire.models import Category, Finding, Severity

# Known OEM PK issuers (common Secure Boot Platform Key signers)
_KNOWN_PK_ISSUERS = [
    "microsoft",
    "dell",
    "lenovo",
    "hp",
    "hewlett-packard",
    "hewlett packard",
    "asus",
    "acer",
    "samsung",
    "toshiba",
    "fujitsu",
    "intel",
    "supermicro",
    "gigabyte",
    "msi",
    "apple",
    "vmware",
    "hyper-v",
    "qemu",
    "american megatrends",
    "ami",
    "phoenix",
    "insyde",
    "surface",
]


def _query_secure_boot_variable(variable_name: str) -> dict | None:
    """Query a single Secure Boot UEFI variable and return parsed info."""
    # Get-SecureBootUEFI returns the raw bytes; we extract cert info with
    # a PowerShell script that parses the signature database
    ps_script = (
        f"try {{"
        f"  $var = Get-SecureBootUEFI -Name '{variable_name}';"
        f"  if ($null -eq $var) {{ Write-Output 'null'; return }}"
        f"  $bytes = $var.Bytes;"
        f"  $result = @{{"
        f"    Name = '{variable_name}';"
        f"    ByteCount = $bytes.Length;"
        f"    Attributes = $var.Attributes;"
        f"  }};"
        f"  Write-Output ($result)"
        f"}} catch {{"
        f"  Write-Output @{{ Name = '{variable_name}'; Error = $_.Exception.Message }}"
        f"}}"
    )
    result = run_ps(ps_script, timeout=30, as_json=True)
    if result.success and result.json_output:
        return result.json_output
    return None


def _query_secure_boot_certs(variable_name: str) -> list[dict]:
    """Extract certificate subjects from a Secure Boot signature database variable."""
    # Use PowerShell to parse the EFI Signature List format and extract
    # X.509 certificate subject names
    ps_script = (
        f"try {{"
        f"  $var = Get-SecureBootUEFI -Name '{variable_name}';"
        f"  if ($null -eq $var) {{ Write-Output @(); return }}"
        f"  $bytes = $var.Bytes;"
        f"  $certs = @();"
        f"  $offset = 0;"
        f"  while ($offset -lt $bytes.Length) {{"
        f"    try {{"
        f"      $sigListSize = [BitConverter]::ToUInt32($bytes, $offset + 4 + 16);"
        f"      $headerSize = [BitConverter]::ToUInt32($bytes, $offset + 4 + 16 + 4);"
        f"      $sigSize = [BitConverter]::ToUInt32($bytes, $offset + 4 + 16 + 4 + 4);"
        f"      if ($sigListSize -eq 0) {{ break }}"
        f"      $certOffset = $offset + 28 + $headerSize + 16;"
        f"      $certLength = $sigSize - 16;"
        f"      if ($certLength -gt 0 -and ($certOffset + $certLength) -le $bytes.Length) {{"
        f"        try {{"
        f"          $certBytes = $bytes[$certOffset..($certOffset + $certLength - 1)];"
        f"          $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($certBytes);"
        f"          $certs += @{{"
        f"            Subject = $cert.Subject;"
        f"            Issuer = $cert.Issuer;"
        f"            Thumbprint = $cert.Thumbprint;"
        f"            NotBefore = $cert.NotBefore.ToString('o');"
        f"            NotAfter = $cert.NotAfter.ToString('o');"
        f"          }};"
        f"        }} catch {{ }}"
        f"      }}"
        f"      $offset += $sigListSize;"
        f"    }} catch {{ break }}"
        f"  }}"
        f"  Write-Output $certs"
        f"}} catch {{"
        f"  Write-Output @()"
        f"}}"
    )
    result = run_ps(ps_script, timeout=30, as_json=True)
    if result.success and result.json_output:
        if isinstance(result.json_output, list):
            return result.json_output
        if isinstance(result.json_output, dict):
            return [result.json_output]
    return []


def _is_known_oem_pk(subject: str) -> bool:
    """Check if a PK certificate subject is from a known OEM."""
    subject_lower = subject.lower()
    for oem in _KNOWN_PK_ISSUERS:
        if oem in subject_lower:
            return True
    return False


class SecureBootKeysCheck(BaseCheck):
    """Validate Secure Boot PK, KEK, db, and dbx key databases."""

    CHECK_ID = "SB-KEY-001"
    NAME = "Secure Boot Key Validation"
    DESCRIPTION = (
        "Query PK, KEK, db, and dbx Secure Boot UEFI variables. Validate that "
        "the Platform Key is from a known OEM, the KEK contains Microsoft, and "
        "the revocation database (dbx) is populated."
    )
    CATEGORY = Category.FIRMWARE
    REQUIRES_ADMIN = True

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        # First check if Secure Boot is enabled at all
        sb_result = run_ps(
            "Confirm-SecureBootUEFI",
            timeout=15,
            as_json=False,
        )
        secure_boot_enabled = sb_result.success and "true" in sb_result.output.lower()

        if not secure_boot_enabled:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Secure Boot Is Disabled",
                description=(
                    "Secure Boot is not enabled on this system. Without Secure Boot, "
                    "the system is vulnerable to bootkits and firmware-level rootkits."
                ),
                severity=Severity.CRITICAL,
                category=self.CATEGORY,
                affected_item="UEFI Secure Boot",
                evidence=f"Confirm-SecureBootUEFI returned: {sb_result.output}",
                recommendation=(
                    "Enable Secure Boot in UEFI firmware settings. Ensure the OS "
                    "and all boot components are signed."
                ),
                references=[
                    "https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-secure-boot",
                    "https://attack.mitre.org/techniques/T1542/",
                ],
            ))
            # Still try to query keys even if SB is disabled

        # Query each Secure Boot variable
        variables_info: dict[str, dict | None] = {}
        certs_info: dict[str, list[dict]] = {}

        for var_name in ["PK", "KEK", "db", "dbx"]:
            variables_info[var_name] = _query_secure_boot_variable(var_name)
            certs_info[var_name] = _query_secure_boot_certs(var_name)

        # Analyze PK (Platform Key)
        pk_certs = certs_info.get("PK", [])
        pk_info = variables_info.get("PK")

        if not pk_certs and (not pk_info or pk_info.get("ByteCount", 0) == 0):
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="No Platform Key (PK) Found",
                description=(
                    "The Secure Boot Platform Key is not set. Without a PK, "
                    "Secure Boot is in setup mode and anyone with physical access "
                    "can enroll arbitrary keys."
                ),
                severity=Severity.CRITICAL,
                category=self.CATEGORY,
                affected_item="Secure Boot PK",
                evidence="PK variable is empty or absent.",
                recommendation=(
                    "Enroll a proper Platform Key through UEFI firmware setup "
                    "or via OEM provisioning tools."
                ),
                references=[
                    "https://wiki.archlinux.org/title/Unified_Extensible_Firmware_Interface/Secure_Boot",
                ],
            ))
        else:
            pk_known = False
            pk_subjects: list[str] = []
            for cert in pk_certs:
                subj = cert.get("Subject", "")
                pk_subjects.append(subj)
                if _is_known_oem_pk(subj):
                    pk_known = True

            if not pk_known and pk_subjects:
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title="Unknown Platform Key Issuer",
                    description=(
                        "The Secure Boot Platform Key is not from a recognized OEM. "
                        "This could indicate a custom PK has been enrolled, which "
                        "may be intentional (custom Secure Boot) or malicious."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.CATEGORY,
                    affected_item="Secure Boot PK",
                    evidence=json.dumps(pk_certs, indent=2, default=str),
                    recommendation=(
                        "Verify the Platform Key issuer is legitimate. If this is "
                        "not a corporate-managed custom Secure Boot deployment, "
                        "reset PK to factory defaults."
                    ),
                    references=[
                        "https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/windows-secure-boot-key-creation-and-management-guidance",
                    ],
                ))
            elif pk_known:
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title="Platform Key From Known OEM",
                    description="The Secure Boot Platform Key is from a recognized manufacturer.",
                    severity=Severity.INFO,
                    category=self.CATEGORY,
                    affected_item="Secure Boot PK",
                    evidence=json.dumps(pk_certs, indent=2, default=str),
                    recommendation="No action needed. PK is from a known OEM.",
                    references=[],
                ))

        # Analyze KEK (Key Exchange Key)
        kek_certs = certs_info.get("KEK", [])
        has_microsoft_kek = False
        for cert in kek_certs:
            subj = cert.get("Subject", "").lower()
            issuer = cert.get("Issuer", "").lower()
            if "microsoft" in subj or "microsoft" in issuer:
                has_microsoft_kek = True

        if kek_certs and not has_microsoft_kek:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Microsoft KEK Not Found",
                description=(
                    "The Key Exchange Key database does not contain a Microsoft "
                    "certificate. This may prevent Windows Update from updating "
                    "the Secure Boot revocation database (dbx)."
                ),
                severity=Severity.HIGH,
                category=self.CATEGORY,
                affected_item="Secure Boot KEK",
                evidence=json.dumps(kek_certs, indent=2, default=str),
                recommendation=(
                    "Ensure the Microsoft KEK certificate is enrolled in the "
                    "Secure Boot KEK database."
                ),
                references=[
                    "https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/windows-secure-boot-key-creation-and-management-guidance",
                ],
            ))
        elif kek_certs:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="KEK Database Contains Microsoft Certificate",
                description=f"KEK database contains {len(kek_certs)} certificate(s) including Microsoft.",
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="Secure Boot KEK",
                evidence=json.dumps(kek_certs, indent=2, default=str),
                recommendation="No action needed.",
                references=[],
            ))

        # Analyze dbx (Revocation Database)
        dbx_info = variables_info.get("dbx")
        dbx_byte_count = 0
        if dbx_info and isinstance(dbx_info, dict):
            dbx_byte_count = dbx_info.get("ByteCount", 0) or 0

        if dbx_byte_count == 0:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Secure Boot Revocation Database (dbx) Is Empty",
                description=(
                    "The dbx revocation database is empty. This means no "
                    "known-vulnerable bootloaders or shims have been revoked, "
                    "leaving the system exposed to boot-level attacks using "
                    "previously signed but vulnerable binaries."
                ),
                severity=Severity.HIGH,
                category=self.CATEGORY,
                affected_item="Secure Boot dbx",
                evidence=f"dbx ByteCount: {dbx_byte_count}",
                recommendation=(
                    "Apply the latest Secure Boot dbx update from Microsoft "
                    "via Windows Update or manually from "
                    "https://www.uefi.org/revocationlistfile"
                ),
                references=[
                    "https://uefi.org/revocationlistfile",
                    "https://support.microsoft.com/en-us/topic/kb5025885",
                ],
            ))
        else:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Secure Boot dbx Is Populated",
                description=(
                    f"The dbx revocation database contains {dbx_byte_count} bytes "
                    f"of revocation data."
                ),
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="Secure Boot dbx",
                evidence=f"dbx ByteCount: {dbx_byte_count}",
                recommendation=(
                    "Ensure dbx is kept up to date via Windows Update to revoke "
                    "newly discovered vulnerable bootloaders."
                ),
                references=[
                    "https://uefi.org/revocationlistfile",
                ],
            ))

        # Analyze db (Authorized Signatures Database) - informational
        db_certs = certs_info.get("db", [])
        if db_certs:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Secure Boot Authorized Signatures Database",
                description=f"The db database contains {len(db_certs)} authorized certificate(s).",
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="Secure Boot db",
                evidence=json.dumps(db_certs, indent=2, default=str),
                recommendation="Review authorized certificates for unexpected entries.",
                references=[],
            ))

        return findings
