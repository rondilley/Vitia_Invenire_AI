"""POL-004: BitLocker Drive Encryption Status Assessment.

Queries Get-BitLockerVolume to check encryption status, protection
state, encryption method, and key protectors for all volumes.
Flags unencrypted system volumes, suspended protection, missing TPM
key protectors, and weak encryption methods.
"""

from __future__ import annotations

from vitia_invenire.checks.base import BaseCheck
from vitia_invenire.collectors.powershell import run_ps
from vitia_invenire.models import Category, Finding, Severity

# Preferred encryption methods in order of strength
_STRONG_METHODS = {
    "XtsAes256", "XtsAes128", "Aes256", "Aes128",
}

# Methods considered weak or legacy
_WEAK_METHODS = {
    "Aes128Diffuser", "Aes256Diffuser",
}

# Human-friendly volume type names
_VOLUME_TYPE_NAMES: dict[str, str] = {
    "OperatingSystem": "Operating System",
    "FixedData": "Fixed Data",
    "RemovableData": "Removable Data",
}


class BitLockerStatusCheck(BaseCheck):
    """Assess BitLocker drive encryption status for all volumes."""

    CHECK_ID = "POL-004"
    NAME = "BitLocker Status"
    DESCRIPTION = (
        "Queries BitLocker volume status to check encryption state, "
        "protection status, encryption method, and key protectors. "
        "Verifies that the system volume and data volumes are encrypted "
        "with strong algorithms and TPM-backed key protection."
    )
    CATEGORY = Category.POLICY
    REQUIRES_ADMIN = True

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        result = run_ps(
            "Get-BitLockerVolume -ErrorAction SilentlyContinue "
            "| Select-Object MountPoint, VolumeStatus, EncryptionMethod, "
            "EncryptionPercentage, LockStatus, ProtectionStatus, "
            "VolumeType, KeyProtector",
            timeout=20,
            as_json=True,
        )

        if not result.success or result.json_output is None:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="BitLocker status unavailable",
                description=(
                    "Could not query BitLocker volume status. BitLocker "
                    "may not be available on this edition of Windows, the "
                    "BitLocker feature may not be installed, or the command "
                    "requires administrator privileges. "
                    f"Error: {result.error or 'no data returned'}"
                ),
                severity=Severity.MEDIUM,
                category=self.CATEGORY,
                affected_item="BitLocker",
                evidence=result.output[:500] if result.output else "No output",
                recommendation=(
                    "Run this assessment as Administrator. Verify that "
                    "BitLocker is available on this Windows edition (Pro, "
                    "Enterprise, or Education)."
                ),
            ))
            # Still emit summary
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="BitLocker assessment could not complete",
                description="BitLocker query failed; no volumes assessed.",
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="BitLocker",
                evidence=f"Error: {result.error or 'no output'}",
                recommendation="Retry with administrator privileges.",
            ))
            return findings

        volumes = result.json_output
        if isinstance(volumes, dict):
            volumes = [volumes]

        if not volumes:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="No BitLocker volumes found",
                description=(
                    "Get-BitLockerVolume returned no volumes. BitLocker "
                    "may not be configured on any drive."
                ),
                severity=Severity.MEDIUM,
                category=self.CATEGORY,
                affected_item="BitLocker",
                evidence="Get-BitLockerVolume returned empty result",
                recommendation=(
                    "Enable BitLocker on the system drive at minimum. "
                    "Use manage-bde or the BitLocker control panel."
                ),
                references=[
                    "https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/",
                ],
            ))
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="BitLocker assessment complete",
                description="No BitLocker-managed volumes detected.",
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="BitLocker",
                evidence="Volumes found: 0",
                recommendation="Enable BitLocker for full disk encryption.",
            ))
            return findings

        volume_evidence: list[str] = []
        encrypted_count = 0
        total_count = len(volumes)

        for volume in volumes:
            mount_point = str(volume.get("MountPoint", "Unknown"))
            volume_status = str(volume.get("VolumeStatus", "Unknown"))
            encryption_method = str(volume.get("EncryptionMethod", "None"))
            encryption_pct = volume.get("EncryptionPercentage", 0)
            lock_status = str(volume.get("LockStatus", "Unknown"))
            protection_status = str(volume.get("ProtectionStatus", "Unknown"))
            volume_type = str(volume.get("VolumeType", "Unknown"))
            key_protectors = volume.get("KeyProtector", [])

            if encryption_pct is None:
                encryption_pct = 0
            try:
                encryption_pct = int(encryption_pct)
            except (ValueError, TypeError):
                encryption_pct = 0

            volume_type_display = _VOLUME_TYPE_NAMES.get(volume_type, volume_type)

            # Normalize key protectors
            if key_protectors is None:
                key_protectors = []
            if isinstance(key_protectors, dict):
                key_protectors = [key_protectors]

            protector_types: list[str] = []
            for kp in key_protectors:
                if isinstance(kp, dict):
                    kp_type = str(kp.get("KeyProtectorType", "Unknown"))
                    protector_types.append(kp_type)
                elif isinstance(kp, str):
                    protector_types.append(kp)

            vol_evidence = (
                f"Volume: {mount_point} ({volume_type_display})\n"
                f"  Status: {volume_status}\n"
                f"  Encryption Method: {encryption_method}\n"
                f"  Encryption: {encryption_pct}%\n"
                f"  Lock Status: {lock_status}\n"
                f"  Protection: {protection_status}\n"
                f"  Key Protectors: {', '.join(protector_types) if protector_types else 'none'}"
            )
            volume_evidence.append(vol_evidence)

            is_system = volume_type == "OperatingSystem"

            # Determine if volume is encrypted
            # VolumeStatus values: FullyEncrypted, EncryptionInProgress,
            # FullyDecrypted, DecryptionInProgress, etc.
            fully_encrypted = "FullyEncrypted" in volume_status
            encrypting = "EncryptionInProgress" in volume_status

            if fully_encrypted or encrypting:
                encrypted_count += 1

            # Check: not encrypted at all
            if not fully_encrypted and not encrypting:
                severity = Severity.CRITICAL if is_system else Severity.HIGH
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title=f"Volume {mount_point} is not encrypted",
                    description=(
                        f"{'The system volume' if is_system else 'Data volume'} "
                        f"{mount_point} ({volume_type_display}) is not encrypted "
                        f"with BitLocker. Volume status: {volume_status}. "
                        f"Data on this volume is accessible to anyone with "
                        f"physical access to the device, including supply chain "
                        f"intermediaries."
                    ),
                    severity=severity,
                    category=self.CATEGORY,
                    affected_item=f"BitLocker: {mount_point}",
                    evidence=vol_evidence,
                    recommendation=(
                        f"Enable BitLocker on {mount_point}: "
                        f"manage-bde -on {mount_point} -RecoveryPassword"
                    ),
                    references=[
                        "https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/",
                    ],
                ))
                continue

            # Check: protection suspended
            # ProtectionStatus: 0=Off, 1=On, 2=Unknown
            protection_off = (
                protection_status == "0"
                or protection_status.lower() == "off"
            )
            if protection_off and fully_encrypted:
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title=f"BitLocker protection suspended on {mount_point}",
                    description=(
                        f"Volume {mount_point} is encrypted but BitLocker "
                        f"protection is suspended (off). While suspended, the "
                        f"encryption key is stored unprotected on disk, "
                        f"rendering the encryption ineffective. An attacker "
                        f"with physical access can read the volume without "
                        f"needing the recovery key or TPM."
                    ),
                    severity=Severity.HIGH,
                    category=self.CATEGORY,
                    affected_item=f"BitLocker: {mount_point}",
                    evidence=vol_evidence,
                    recommendation=(
                        f"Resume BitLocker protection: "
                        f"manage-bde -protectors -enable {mount_point}"
                    ),
                    references=[
                        "https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/",
                    ],
                ))

            # Check: no TPM key protector on system volume
            if is_system:
                has_tpm_protector = any(
                    "tpm" in pt.lower() for pt in protector_types
                )
                if not has_tpm_protector and protector_types:
                    findings.append(Finding(
                        check_id=self.CHECK_ID,
                        title=(
                            f"No TPM key protector on system volume {mount_point}"
                        ),
                        description=(
                            f"The system volume {mount_point} is encrypted but "
                            f"does not have a TPM-based key protector. Without "
                            f"TPM binding, the encryption key is not sealed to "
                            f"the hardware platform. The disk could be moved to "
                            f"another machine and unlocked with just the password "
                            f"or recovery key."
                        ),
                        severity=Severity.HIGH,
                        category=self.CATEGORY,
                        affected_item=f"BitLocker Key Protector: {mount_point}",
                        evidence=vol_evidence,
                        recommendation=(
                            "Add a TPM key protector to the system volume: "
                            "manage-bde -protectors -add C: -TPM"
                        ),
                        references=[
                            "https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/bitlocker-countermeasures",
                        ],
                    ))

            # Check: weak encryption method
            if encryption_method and encryption_method != "None":
                is_xts = encryption_method.startswith("Xts")
                is_weak = encryption_method in _WEAK_METHODS
                is_128_non_xts = (
                    encryption_method == "Aes128"
                    and not is_xts
                )

                if is_weak:
                    findings.append(Finding(
                        check_id=self.CHECK_ID,
                        title=(
                            f"Weak encryption method on {mount_point}: "
                            f"{encryption_method}"
                        ),
                        description=(
                            f"Volume {mount_point} uses legacy encryption "
                            f"method {encryption_method} with the Elephant "
                            f"diffuser, which is deprecated. XTS-AES-256 is "
                            f"the recommended encryption method for BitLocker."
                        ),
                        severity=Severity.MEDIUM,
                        category=self.CATEGORY,
                        affected_item=f"BitLocker Encryption: {mount_point}",
                        evidence=vol_evidence,
                        recommendation=(
                            "Decrypt and re-encrypt the volume with XTS-AES-256. "
                            "Configure Group Policy to require XTS-AES-256 for "
                            "new volumes."
                        ),
                        references=[
                            "https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/bitlocker-group-policy-settings",
                        ],
                    ))
                elif is_128_non_xts:
                    findings.append(Finding(
                        check_id=self.CHECK_ID,
                        title=(
                            f"Non-XTS encryption on {mount_point}: "
                            f"{encryption_method}"
                        ),
                        description=(
                            f"Volume {mount_point} uses {encryption_method} "
                            f"instead of the recommended XTS-AES mode. XTS mode "
                            f"provides better protection against manipulation of "
                            f"encrypted data on disk."
                        ),
                        severity=Severity.MEDIUM,
                        category=self.CATEGORY,
                        affected_item=f"BitLocker Encryption: {mount_point}",
                        evidence=vol_evidence,
                        recommendation=(
                            "Consider re-encrypting with XTS-AES-256. Set "
                            "Group Policy to require XTS-AES for new volumes."
                        ),
                    ))

        # Summary finding
        evidence_all = "\n\n".join(volume_evidence)
        findings.append(Finding(
            check_id=self.CHECK_ID,
            title="BitLocker assessment complete",
            description=(
                f"Assessed {total_count} volume(s). "
                f"{encrypted_count} encrypted, "
                f"{total_count - encrypted_count} not encrypted."
            ),
            severity=Severity.INFO,
            category=self.CATEGORY,
            affected_item="BitLocker",
            evidence=evidence_all,
            recommendation=(
                "Ensure all volumes containing sensitive data are encrypted "
                "with BitLocker using XTS-AES-256 and TPM key protection."
            ),
            references=[
                "https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/",
            ],
        ))

        return findings
