"""CATALOG-001: Verify system files against Windows catalog signatures.

Checks .exe, .dll, and .sys files in System32, SysWOW64, and drivers
against the Windows catalog system using PowerShell Get-AuthenticodeSignature.
The IsOSBinary property identifies files verified via Microsoft-signed
catalog entries (.cat files in catroot). HashMismatch status indicates
a file was modified from its catalog version -- a strong tampering indicator.
"""

from __future__ import annotations

import json
from pathlib import Path

from vitia_invenire.checks.base import BaseCheck
from vitia_invenire.collectors.powershell import run_ps
from vitia_invenire.models import Category, Finding, Severity

_DEFAULT_SCAN_PATHS = [
    r"C:\Windows\System32",
    r"C:\Windows\SysWOW64",
    r"C:\Windows\System32\drivers",
]

_TARGET_EXTENSIONS = {".exe", ".dll", ".sys"}

_MAX_FILES = 2000

_PS_BATCH_SIZE = 50


def _enumerate_files(
    scan_paths: list[str],
    extensions: set[str],
    max_files: int,
) -> list[str]:
    """Enumerate target binary files in scan directories up to max_files."""
    target_files: list[str] = []
    seen: set[str] = set()

    for scan_dir in scan_paths:
        dir_path = Path(scan_dir)
        if not dir_path.exists() or not dir_path.is_dir():
            continue
        try:
            for entry in dir_path.iterdir():
                if len(target_files) >= max_files:
                    return target_files
                try:
                    if entry.is_file() and entry.suffix.lower() in extensions:
                        resolved = str(entry.resolve())
                        if resolved not in seen:
                            seen.add(resolved)
                            target_files.append(resolved)
                except (PermissionError, OSError):
                    continue
        except (PermissionError, OSError):
            continue

    return target_files


def _batch_verify(file_paths: list[str]) -> list[dict]:
    """Verify files against Windows catalogs using PowerShell in batches.

    For each file, retrieves both the SHA256 hash and the catalog
    signature status (including IsOSBinary) via Get-AuthenticodeSignature.
    """
    all_results: list[dict] = []

    for i in range(0, len(file_paths), _PS_BATCH_SIZE):
        batch = file_paths[i:i + _PS_BATCH_SIZE]
        paths_array = ",".join(f"'{p}'" for p in batch)
        ps_script = (
            f"@({paths_array}) | ForEach-Object {{"
            f"  $hash = Get-FileHash -Path $_ -Algorithm SHA256 -ErrorAction SilentlyContinue;"
            f"  $sig = Get-AuthenticodeSignature -FilePath $_ -ErrorAction SilentlyContinue;"
            f"  [PSCustomObject]@{{"
            f"    FilePath = $_;"
            f"    SHA256 = if($hash){{$hash.Hash}}else{{'Error'}};"
            f"    Status = if($sig){{$sig.Status.ToString()}}else{{'Error'}};"
            f"    IsOSBinary = if($sig){{$sig.IsOSBinary}}else{{$false}};"
            f"    Signer = if($sig -and $sig.SignerCertificate){{$sig.SignerCertificate.Subject}}else{{'None'}};"
            f"    StatusMessage = if($sig){{$sig.StatusMessage}}else{{''}};"
            f"  }}"
            f"}}"
        )
        result = run_ps(ps_script, timeout=120, as_json=True)
        if result.success and result.json_output:
            output = result.json_output
            if isinstance(output, dict):
                output = [output]
            all_results.extend(output)

    return all_results


class CatalogIntegrityCheck(BaseCheck):
    """Verify system files against Windows catalog signatures."""

    CHECK_ID = "CATALOG-001"
    NAME = "Windows Catalog Integrity Verification"
    DESCRIPTION = (
        "Verify .exe, .dll, and .sys files in System32, SysWOW64, and "
        "drivers against Windows catalog signatures. HashMismatch "
        "indicates a file was modified from its catalog version."
    )
    CATEGORY = Category.BINARY_INTEGRITY
    REQUIRES_ADMIN = False

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        # Enumerate target files
        target_files = _enumerate_files(
            list(_DEFAULT_SCAN_PATHS),
            set(_TARGET_EXTENSIONS),
            _MAX_FILES,
        )

        if not target_files:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="No System Files Found for Catalog Verification",
                description="No target binary files were found in the system directories.",
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="System Binaries",
                evidence=f"Directories searched: {json.dumps(_DEFAULT_SCAN_PATHS)}",
                recommendation="Verify scan paths and permissions.",
                references=[],
            ))
            return findings

        # Batch verify against catalogs
        verify_results = _batch_verify(target_files)

        if not verify_results:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Catalog Verification Failed",
                description=(
                    "PowerShell Get-AuthenticodeSignature returned no results. "
                    "Catalog verification requires Windows with PowerShell."
                ),
                severity=Severity.LOW,
                category=self.CATEGORY,
                affected_item="System Binaries",
                evidence="No verification results returned.",
                recommendation="Ensure PowerShell is available and the system has catalog files.",
                references=[],
            ))
            return findings

        # Classify results
        catalog_verified: list[dict] = []
        third_party_signed: list[dict] = []
        hash_mismatch: list[dict] = []
        not_signed: list[dict] = []
        errors: list[dict] = []

        for entry in verify_results:
            fp = entry.get("FilePath", "")
            sha256 = entry.get("SHA256", "Error")
            status = str(entry.get("Status", "")).strip()
            is_os = entry.get("IsOSBinary", False)
            signer = entry.get("Signer", "None")
            message = entry.get("StatusMessage", "")
            ext = Path(fp).suffix.lower()

            record = {
                "file": fp,
                "sha256": sha256,
                "status": status,
                "is_os_binary": is_os,
                "signer": signer,
                "extension": ext,
                "message": message,
            }

            if status == "Error" or sha256 == "Error":
                errors.append(record)
            elif status == "HashMismatch":
                hash_mismatch.append(record)
            elif status == "NotSigned":
                not_signed.append(record)
            elif status == "Valid" and is_os:
                catalog_verified.append(record)
            elif status == "Valid" and not is_os:
                third_party_signed.append(record)
            else:
                # Other statuses (NotTrusted, UnknownError, etc.)
                not_signed.append(record)

        total = len(verify_results)
        verified_count = len(catalog_verified)
        verification_rate = (verified_count / total * 100) if total > 0 else 0.0

        self.context = {
            "total_files": total,
            "catalog_verified": verified_count,
            "third_party_signed": len(third_party_signed),
            "hash_mismatch": len(hash_mismatch),
            "not_signed": len(not_signed),
            "errors": len(errors),
            "verification_rate_pct": round(verification_rate, 1),
            "hash_mismatch_files": hash_mismatch[:200],
            "not_signed_files": not_signed[:200],
            "third_party_files": third_party_signed[:200],
            "_all_results": [
                {
                    "file": e.get("FilePath", ""),
                    "sha256": e.get("SHA256", ""),
                    "status": str(e.get("Status", "")),
                    "is_os_binary": e.get("IsOSBinary", False),
                    "signer": e.get("Signer", "None"),
                }
                for e in verify_results
            ],
        }

        # Generate findings based on severity matrix

        # HashMismatch -- always CRITICAL regardless of file type
        if hash_mismatch:
            sys_mismatches = [r for r in hash_mismatch if r["extension"] == ".sys"]
            exe_dll_mismatches = [r for r in hash_mismatch if r["extension"] in (".exe", ".dll")]

            if sys_mismatches:
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title="Catalog Hash Mismatch on Kernel Drivers (.sys)",
                    description=(
                        f"{len(sys_mismatches)} kernel driver(s) have hashes that do not "
                        f"match their Windows catalog entries. This is a strong indicator "
                        f"of file tampering or unauthorized modification of critical "
                        f"system drivers."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.CATEGORY,
                    affected_item="Tampered Kernel Drivers",
                    evidence=json.dumps(sys_mismatches[:50], indent=2),
                    recommendation=(
                        "Immediately investigate each driver with a hash mismatch. "
                        "Compare against known-good copies from Microsoft Update Catalog. "
                        "A hash mismatch on a .sys file in a supply chain context is a "
                        "critical finding that may indicate rootkit deployment."
                    ),
                    references=[
                        "https://attack.mitre.org/techniques/T1014/",
                        "https://learn.microsoft.com/en-us/windows-hardware/drivers/install/catalog-files",
                    ],
                ))

            if exe_dll_mismatches:
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title="Catalog Hash Mismatch on System Binaries (.exe/.dll)",
                    description=(
                        f"{len(exe_dll_mismatches)} system executable(s) or library(ies) "
                        f"have hashes that do not match their Windows catalog entries. "
                        f"These files have been modified from the version distributed "
                        f"by Microsoft via Windows Update."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.CATEGORY,
                    affected_item="Tampered System Binaries",
                    evidence=json.dumps(exe_dll_mismatches[:50], indent=2),
                    recommendation=(
                        "Investigate each binary with a hash mismatch. Use 'sfc /scannow' "
                        "or compare against Windows Update Catalog versions. Modified "
                        "system binaries in a supply chain assessment indicate possible "
                        "trojanized OS components."
                    ),
                    references=[
                        "https://attack.mitre.org/techniques/T1554/",
                        "https://learn.microsoft.com/en-us/windows-hardware/drivers/install/catalog-files",
                    ],
                ))

        # NotSigned
        unsigned_sys = [r for r in not_signed if r["extension"] == ".sys"]
        unsigned_exe = [r for r in not_signed if r["extension"] == ".exe"]
        unsigned_dll = [r for r in not_signed if r["extension"] == ".dll"]

        if unsigned_sys:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Unsigned Kernel Drivers Not in Any Catalog (.sys)",
                description=(
                    f"{len(unsigned_sys)} kernel driver(s) are not signed and do not "
                    f"appear in any Windows catalog. Legitimate Windows drivers are "
                    f"always catalog-signed or Authenticode-signed."
                ),
                severity=Severity.HIGH,
                category=self.CATEGORY,
                affected_item="Unsigned Kernel Drivers",
                evidence=json.dumps(unsigned_sys[:30], indent=2),
                recommendation=(
                    "Investigate each unsigned driver. Third-party hardware drivers "
                    "should still be Authenticode-signed. Unsigned .sys files in "
                    "system directories are suspicious."
                ),
                references=[
                    "https://learn.microsoft.com/en-us/windows-hardware/drivers/install/driver-signing",
                ],
            ))

        if unsigned_exe:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Unsigned Executables Not in Any Catalog (.exe)",
                description=(
                    f"{len(unsigned_exe)} executable(s) in system directories are not "
                    f"signed and do not appear in any Windows catalog."
                ),
                severity=Severity.MEDIUM,
                category=self.CATEGORY,
                affected_item="Unsigned System Executables",
                evidence=json.dumps(unsigned_exe[:30], indent=2),
                recommendation=(
                    "Verify that unsigned executables are legitimate. They may be "
                    "third-party utilities or indicators of supply chain tampering."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1036/005/",
                ],
            ))

        if unsigned_dll:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Unsigned DLLs Not in Any Catalog (.dll)",
                description=(
                    f"{len(unsigned_dll)} DLL(s) in system directories are not signed "
                    f"and do not appear in any Windows catalog."
                ),
                severity=Severity.LOW,
                category=self.CATEGORY,
                affected_item="Unsigned System DLLs",
                evidence=json.dumps(unsigned_dll[:30], indent=2),
                recommendation=(
                    "Review unsigned DLLs. Many third-party DLLs in System32 are "
                    "legitimate but should be tracked for baseline comparison."
                ),
                references=[],
            ))

        # Valid but not OS binary (third-party signed) -- informational
        if third_party_signed:
            sys_third_party = [r for r in third_party_signed if r["extension"] == ".sys"]
            if sys_third_party:
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title="Third-Party Signed Drivers in System Directories",
                    description=(
                        f"{len(sys_third_party)} driver(s) are validly signed but not "
                        f"by Microsoft (not in Windows catalogs). These are third-party "
                        f"drivers that should be verified against expected hardware."
                    ),
                    severity=Severity.INFO,
                    category=self.CATEGORY,
                    affected_item="Third-Party Drivers",
                    evidence=json.dumps(sys_third_party[:20], indent=2),
                    recommendation=(
                        "Verify third-party drivers match the expected hardware "
                        "configuration. Unexpected drivers may indicate supply chain "
                        "additions."
                    ),
                    references=[],
                ))

        # Summary finding
        findings.append(Finding(
            check_id=self.CHECK_ID,
            title="Catalog Integrity Verification Summary",
            description=(
                f"Verified {total} files against Windows catalogs. "
                f"{verified_count} catalog-verified ({verification_rate:.1f}%), "
                f"{len(third_party_signed)} third-party signed, "
                f"{len(hash_mismatch)} hash mismatch, "
                f"{len(not_signed)} unsigned, "
                f"{len(errors)} errors."
            ),
            severity=Severity.INFO,
            category=self.CATEGORY,
            affected_item="System Binaries",
            evidence=(
                f"Total files checked: {total}\n"
                f"Catalog verified (IsOSBinary=True): {verified_count}\n"
                f"Verification rate: {verification_rate:.1f}%\n"
                f"Third-party signed (Valid, IsOSBinary=False): {len(third_party_signed)}\n"
                f"Hash mismatch: {len(hash_mismatch)}\n"
                f"Unsigned/not in catalog: {len(not_signed)}\n"
                f"Errors: {len(errors)}"
            ),
            recommendation="Address all hash mismatch and unsigned findings.",
            references=[
                "https://learn.microsoft.com/en-us/windows-hardware/drivers/install/catalog-files",
            ],
        ))

        return findings
