"""INTEGRITY-001: Cross-path data integrity validation.

Queries the same system data (e.g., BIOS version) through multiple
collection paths (WMI and registry) and flags inconsistencies. Also
hashes and verifies signatures of critical kernel binaries on disk.
"""

from __future__ import annotations

from vitia_invenire.checks.base import BaseCheck
from vitia_invenire.collectors import registry, wmi_collector
from vitia_invenire.collectors.powershell import run_ps
from vitia_invenire.models import Category, Finding, Severity

# Critical kernel binaries to hash and verify
_CRITICAL_BINARIES: list[tuple[str, str]] = [
    ("C:\\Windows\\System32\\ntoskrnl.exe", "Windows NT Kernel"),
    ("C:\\Windows\\System32\\hal.dll", "Hardware Abstraction Layer"),
    ("C:\\Windows\\System32\\ci.dll", "Code Integrity Module"),
]


class IntegrityCheck(BaseCheck):
    """Cross-validate system data from multiple sources and verify kernel binaries."""

    CHECK_ID = "INTEGRITY-001"
    NAME = "Cross-Path Integrity Validation"
    DESCRIPTION = (
        "Queries the same system data through WMI and registry to detect "
        "inconsistencies that may indicate rootkits or tampering. Also "
        "hashes and verifies signatures of critical kernel binaries."
    )
    CATEGORY = Category.FIRMWARE
    REQUIRES_ADMIN = False

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        self._cross_validate_bios(findings)
        self._cross_validate_os_version(findings)
        self._cross_validate_computer_name(findings)
        self._verify_kernel_binaries(findings)

        return findings

    def _cross_validate_bios(self, findings: list[Finding]) -> None:
        """Compare BIOS info from WMI vs registry."""
        # WMI source
        wmi_bios = wmi_collector.query(
            "Win32_BIOS",
            properties=["SMBIOSBIOSVersion", "Manufacturer", "Version", "ReleaseDate"],
        )

        wmi_version = ""
        wmi_manufacturer = ""
        if wmi_bios:
            wmi_version = str(wmi_bios[0].get("SMBIOSBIOSVersion", wmi_bios[0].get("Version", "")))
            wmi_manufacturer = str(wmi_bios[0].get("Manufacturer", ""))

        # Registry source
        reg_path = r"HARDWARE\DESCRIPTION\System\BIOS"
        reg_version_val = registry.read_value(
            registry.HKEY_LOCAL_MACHINE, reg_path, "BIOSVersion"
        )
        reg_vendor_val = registry.read_value(
            registry.HKEY_LOCAL_MACHINE, reg_path, "BIOSVendor"
        )

        reg_version = str(reg_version_val.data) if reg_version_val else ""
        reg_vendor = str(reg_vendor_val.data) if reg_vendor_val else ""

        evidence_text = (
            f"WMI BIOS Version: {wmi_version}\n"
            f"WMI BIOS Manufacturer: {wmi_manufacturer}\n"
            f"Registry BIOS Version: {reg_version}\n"
            f"Registry BIOS Vendor: {reg_vendor}"
        )

        if not wmi_version and not reg_version:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="BIOS information unavailable from both sources",
                description="Could not retrieve BIOS version from WMI or registry.",
                severity=Severity.MEDIUM,
                category=self.CATEGORY,
                affected_item="BIOS Version Cross-Validation",
                evidence=evidence_text,
                recommendation="Verify WMI and registry access.",
            ))
            return

        # Compare versions - normalize for comparison
        wmi_norm = wmi_version.strip().upper()
        reg_norm = reg_version.strip().upper()

        # If both sources have data, compare
        if wmi_norm and reg_norm:
            # Registry BIOSVersion sometimes contains the version as part of a larger string
            if wmi_norm not in reg_norm and reg_norm not in wmi_norm and wmi_norm != reg_norm:
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title="BIOS version mismatch between WMI and registry",
                    description=(
                        "The BIOS version reported by WMI does not match the registry. "
                        "Inconsistencies between data sources may indicate a rootkit that "
                        "is intercepting WMI queries to hide its modifications."
                    ),
                    severity=Severity.HIGH,
                    category=self.CATEGORY,
                    affected_item="BIOS Version Cross-Validation",
                    evidence=evidence_text,
                    recommendation=(
                        "Investigate the BIOS version discrepancy. Boot from known-good "
                        "media to compare. Consider re-flashing BIOS firmware."
                    ),
                    references=[
                        "https://attack.mitre.org/techniques/T1014/",
                    ],
                ))
            else:
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title="BIOS version consistent across sources",
                    description="BIOS version matches between WMI and registry.",
                    severity=Severity.INFO,
                    category=self.CATEGORY,
                    affected_item="BIOS Version Cross-Validation",
                    evidence=evidence_text,
                    recommendation="No action needed.",
                ))

        # Compare manufacturer/vendor
        wmi_mfg = wmi_manufacturer.strip().upper()
        reg_vnd = reg_vendor.strip().upper()

        if wmi_mfg and reg_vnd and wmi_mfg != reg_vnd:
            if wmi_mfg not in reg_vnd and reg_vnd not in wmi_mfg:
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title="BIOS manufacturer mismatch between WMI and registry",
                    description=(
                        f"WMI reports manufacturer '{wmi_manufacturer}' but registry "
                        f"reports vendor '{reg_vendor}'. This inconsistency is suspicious."
                    ),
                    severity=Severity.HIGH,
                    category=self.CATEGORY,
                    affected_item="BIOS Manufacturer Cross-Validation",
                    evidence=evidence_text,
                    recommendation="Investigate the manufacturer discrepancy.",
                ))

    def _cross_validate_os_version(self, findings: list[Finding]) -> None:
        """Compare OS version from WMI vs registry."""
        wmi_os = wmi_collector.query(
            "Win32_OperatingSystem",
            properties=["Version", "BuildNumber", "Caption"],
        )

        wmi_build = ""
        wmi_caption = ""
        if wmi_os:
            wmi_build = str(wmi_os[0].get("BuildNumber", ""))
            wmi_caption = str(wmi_os[0].get("Caption", ""))

        reg_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
        reg_build_val = registry.read_value(
            registry.HKEY_LOCAL_MACHINE, reg_path, "CurrentBuildNumber"
        )
        reg_product_val = registry.read_value(
            registry.HKEY_LOCAL_MACHINE, reg_path, "ProductName"
        )

        reg_build = str(reg_build_val.data) if reg_build_val else ""
        reg_product = str(reg_product_val.data) if reg_product_val else ""

        evidence_text = (
            f"WMI Build: {wmi_build}\n"
            f"WMI Caption: {wmi_caption}\n"
            f"Registry Build: {reg_build}\n"
            f"Registry Product: {reg_product}"
        )

        if wmi_build and reg_build:
            if wmi_build.strip() != reg_build.strip():
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title="OS build number mismatch between WMI and registry",
                    description=(
                        f"WMI reports build '{wmi_build}' but registry reports '{reg_build}'. "
                        "This may indicate WMI interception or registry manipulation."
                    ),
                    severity=Severity.HIGH,
                    category=self.CATEGORY,
                    affected_item="OS Build Cross-Validation",
                    evidence=evidence_text,
                    recommendation="Investigate the OS build number discrepancy.",
                    references=[
                        "https://attack.mitre.org/techniques/T1014/",
                    ],
                ))
            else:
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title="OS build number consistent across sources",
                    description=f"OS build {wmi_build} matches between WMI and registry.",
                    severity=Severity.INFO,
                    category=self.CATEGORY,
                    affected_item="OS Build Cross-Validation",
                    evidence=evidence_text,
                    recommendation="No action needed.",
                ))

    def _cross_validate_computer_name(self, findings: list[Finding]) -> None:
        """Compare computer name from WMI vs registry vs environment."""
        wmi_cs = wmi_collector.query(
            "Win32_ComputerSystem",
            properties=["Name", "DNSHostName"],
        )

        wmi_name = ""
        if wmi_cs:
            wmi_name = str(wmi_cs[0].get("Name", ""))

        reg_path = r"SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName"
        reg_name_val = registry.read_value(
            registry.HKEY_LOCAL_MACHINE, reg_path, "ComputerName"
        )
        reg_name = str(reg_name_val.data) if reg_name_val else ""

        # Also check via environment variable
        env_result = run_ps("$env:COMPUTERNAME", timeout=5, as_json=False)
        env_name = env_result.output.strip() if env_result.success else ""

        evidence_text = (
            f"WMI ComputerName: {wmi_name}\n"
            f"Registry ComputerName: {reg_name}\n"
            f"Environment ComputerName: {env_name}"
        )

        names = [n.upper().strip() for n in [wmi_name, reg_name, env_name] if n]
        unique_names = set(names)

        if len(unique_names) > 1:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Computer name mismatch across sources",
                description=(
                    f"Computer name differs between data sources: {', '.join(unique_names)}. "
                    "This is unusual and may indicate system tampering."
                ),
                severity=Severity.HIGH,
                category=self.CATEGORY,
                affected_item="Computer Name Cross-Validation",
                evidence=evidence_text,
                recommendation="Investigate why computer names differ across data sources.",
            ))
        elif unique_names:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Computer name consistent across sources",
                description=f"Computer name '{names[0]}' is consistent across all sources checked.",
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="Computer Name Cross-Validation",
                evidence=evidence_text,
                recommendation="No action needed.",
            ))

    def _verify_kernel_binaries(self, findings: list[Finding]) -> None:
        """Hash and verify signatures of critical kernel binaries."""
        for file_path, description in _CRITICAL_BINARIES:
            # Get file hash
            hash_result = run_ps(
                f"if (Test-Path '{file_path}') {{ "
                f"$hash = Get-FileHash -Path '{file_path}' -Algorithm SHA256; "
                f"$sig = Get-AuthenticodeSignature -FilePath '{file_path}'; "
                "@{{ "
                "Path=$hash.Path; "
                "SHA256=$hash.Hash; "
                "SignatureStatus=$sig.Status.ToString(); "
                "Signer=if($sig.SignerCertificate){{$sig.SignerCertificate.Subject}}else{{''}}; "
                "TimeStamper=if($sig.TimeStamperCertificate){{$sig.TimeStamperCertificate.Subject}}else{{''}} "
                "}} }} else {{ "
                f"@{{ Path='{file_path}'; SHA256='FILE_NOT_FOUND'; SignatureStatus='NotFound'; Signer=''; TimeStamper='' }} "
                "}}",
                timeout=30,
                as_json=True,
            )

            if not hash_result.success or hash_result.json_output is None:
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title=f"Failed to verify {description}",
                    description=f"Could not hash or verify signature of {file_path}.",
                    severity=Severity.MEDIUM,
                    category=self.CATEGORY,
                    affected_item=file_path,
                    evidence=f"Error: {hash_result.error or 'unknown'}",
                    recommendation=f"Manually verify {file_path} with sigcheck.exe.",
                ))
                continue

            data = hash_result.json_output
            if isinstance(data, list) and len(data) > 0:
                data = data[0]

            sha256 = str(data.get("SHA256", "Unknown"))
            sig_status = str(data.get("SignatureStatus", "Unknown"))
            signer = str(data.get("Signer", ""))
            timestamper = str(data.get("TimeStamper", ""))

            evidence_text = (
                f"Path: {file_path}\n"
                f"SHA256: {sha256}\n"
                f"Signature Status: {sig_status}\n"
                f"Signer: {signer}\n"
                f"Timestamper: {timestamper}"
            )

            if sha256 == "FILE_NOT_FOUND":
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title=f"Critical kernel binary missing: {description}",
                    description=f"{file_path} was not found on disk. This is highly unusual.",
                    severity=Severity.HIGH,
                    category=self.CATEGORY,
                    affected_item=file_path,
                    evidence=evidence_text,
                    recommendation="Investigate why this critical system file is missing. Run sfc /scannow.",
                ))
            elif sig_status == "NotSigned":
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title=f"Unsigned kernel binary: {description}",
                    description=(
                        f"Critical kernel binary {file_path} is not digitally signed. "
                        "All Windows kernel binaries should be signed by Microsoft."
                    ),
                    severity=Severity.HIGH,
                    category=self.CATEGORY,
                    affected_item=file_path,
                    evidence=evidence_text,
                    recommendation="This file may have been tampered with. Run sfc /scannow and compare hashes.",
                    references=[
                        "https://attack.mitre.org/techniques/T1014/",
                    ],
                ))
            elif sig_status in ("HashMismatch", "InvalidSignature"):
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title=f"Invalid signature on kernel binary: {description}",
                    description=(
                        f"Critical kernel binary {file_path} has an invalid signature "
                        f"(status: {sig_status}). This indicates the file has been modified."
                    ),
                    severity=Severity.HIGH,
                    category=self.CATEGORY,
                    affected_item=file_path,
                    evidence=evidence_text,
                    recommendation="This file may have been tampered with. Reimage the system.",
                    references=[
                        "https://attack.mitre.org/techniques/T1014/",
                    ],
                ))
            elif sig_status == "Valid":
                # Check that signer is Microsoft
                if "Microsoft" not in signer:
                    findings.append(Finding(
                        check_id=self.CHECK_ID,
                        title=f"Non-Microsoft signer for kernel binary: {description}",
                        description=(
                            f"Critical kernel binary {file_path} is signed, but the signer "
                            f"is '{signer}' rather than Microsoft. This is unexpected."
                        ),
                        severity=Severity.HIGH,
                        category=self.CATEGORY,
                        affected_item=file_path,
                        evidence=evidence_text,
                        recommendation="Investigate why a kernel binary is not signed by Microsoft.",
                    ))
                else:
                    findings.append(Finding(
                        check_id=self.CHECK_ID,
                        title=f"Kernel binary verified: {description}",
                        description=f"{file_path} has a valid Microsoft signature.",
                        severity=Severity.INFO,
                        category=self.CATEGORY,
                        affected_item=file_path,
                        evidence=evidence_text,
                        recommendation="No action needed.",
                    ))
