"""SIG-001: Verify Authenticode signatures on system binaries.

Verifies Authenticode signatures on .exe, .dll, and .sys files in
System32 and drivers directories. Unsigned .sys files are flagged
as HIGH, and unsigned .exe files in System32 are flagged as HIGH.
Uses the signify library for signature verification, with PowerShell
Get-AuthenticodeSignature as a fallback.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from vitia_invenire.checks.base import BaseCheck
from vitia_invenire.collectors.powershell import run_ps
from vitia_invenire.models import Category, Finding, Severity

# Directories to scan
_SYSTEM_DIRS = [
    r"C:\Windows\System32",
    r"C:\Windows\System32\drivers",
]

# File extensions to verify
_TARGET_EXTENSIONS = {".exe", ".dll", ".sys"}

# Maximum files to check (signature verification is expensive)
_MAX_FILES_TO_CHECK = 1000

# Batch size for PowerShell queries
_PS_BATCH_SIZE = 50


def _verify_signatures_powershell(file_paths: list[str]) -> list[dict]:
    """Verify Authenticode signatures using PowerShell Get-AuthenticodeSignature.

    Processes files in batches to avoid command-line length limits.
    Returns a list of dicts with file path, status, and signer info.
    """
    all_results: list[dict] = []

    for i in range(0, len(file_paths), _PS_BATCH_SIZE):
        batch = file_paths[i:i + _PS_BATCH_SIZE]
        # Build a PowerShell array of paths
        paths_array = ",".join(f"'{p}'" for p in batch)
        ps_script = (
            f"@({paths_array}) | ForEach-Object {{"
            f"  $sig = Get-AuthenticodeSignature -FilePath $_ -ErrorAction SilentlyContinue;"
            f"  if ($sig) {{"
            f"    [PSCustomObject]@{{"
            f"      FilePath = $_;"
            f"      Status = $sig.Status.ToString();"
            f"      SignerCert = if ($sig.SignerCertificate) {{ $sig.SignerCertificate.Subject }} else {{ 'None' }};"
            f"      Issuer = if ($sig.SignerCertificate) {{ $sig.SignerCertificate.Issuer }} else {{ 'None' }};"
            f"      Thumbprint = if ($sig.SignerCertificate) {{ $sig.SignerCertificate.Thumbprint }} else {{ 'None' }};"
            f"      TimeStamper = if ($sig.TimeStamperCertificate) {{ $sig.TimeStamperCertificate.Subject }} else {{ 'None' }};"
            f"      IsOSBinary = $sig.IsOSBinary;"
            f"      StatusMessage = $sig.StatusMessage;"
            f"    }}"
            f"  }} else {{"
            f"    [PSCustomObject]@{{"
            f"      FilePath = $_;"
            f"      Status = 'Error';"
            f"      SignerCert = 'None';"
            f"      Issuer = 'None';"
            f"      Thumbprint = 'None';"
            f"      TimeStamper = 'None';"
            f"      IsOSBinary = $false;"
            f"      StatusMessage = 'Could not retrieve signature';"
            f"    }}"
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


def _verify_signatures_signify(file_paths: list[str]) -> list[dict]:
    """Verify Authenticode signatures using the signify library.

    Returns a list of dicts with file path, signed status, and signer info.
    """
    try:
        from signify.authenticode import SignedPEFile
    except ImportError:
        return []

    results: list[dict] = []
    for fp in file_paths:
        entry = {
            "FilePath": fp,
            "Status": "Unknown",
            "SignerCert": "None",
            "Issuer": "None",
            "StatusMessage": "",
        }
        try:
            with open(fp, "rb") as fh:
                signed_pe = SignedPEFile(fh)
                signed_pe.verify()
                # If verify() does not raise, signature is valid
                entry["Status"] = "Valid"
                try:
                    for signed_data in signed_pe.signed_datas:
                        if signed_data.signer_info and signed_data.signer_info.serial_number:
                            for cert in signed_data.certificates:
                                entry["SignerCert"] = str(cert.subject)
                                entry["Issuer"] = str(cert.issuer)
                                break
                except (AttributeError, StopIteration, TypeError):
                    entry["SignerCert"] = "Certificate details unavailable"
        except Exception as exc:
            # signify raises various exceptions for unsigned or invalid signatures
            exc_name = type(exc).__name__
            if "signed" in str(exc).lower() or "signature" in str(exc).lower():
                entry["Status"] = "NotSigned"
                entry["StatusMessage"] = str(exc)
            else:
                entry["Status"] = "SignatureNotValid"
                entry["StatusMessage"] = f"{exc_name}: {exc}"

        results.append(entry)

    return results


class SignatureVerifyCheck(BaseCheck):
    """Verify Authenticode signatures on system binaries."""

    CHECK_ID = "SIG-001"
    NAME = "Authenticode Signature Verification"
    DESCRIPTION = (
        "Verify Authenticode signatures on system binaries in System32 "
        "and drivers directories. Unsigned .sys = HIGH, unsigned .exe "
        "in System32 = HIGH."
    )
    CATEGORY = Category.BINARY_INTEGRITY
    REQUIRES_ADMIN = False

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        # Enumerate target files
        target_files = self._enumerate_files()
        if not target_files:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="No System Binaries Found for Signature Verification",
                description="No target binary files were found in the system directories.",
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="System Binaries",
                evidence=f"Directories searched: {json.dumps(_SYSTEM_DIRS)}",
                recommendation="Verify scan paths and permissions.",
                references=[],
            ))
            return findings

        # Limit file count
        files_to_check = target_files[:_MAX_FILES_TO_CHECK]

        # Try signify first, fall back to PowerShell
        sig_results = _verify_signatures_signify(files_to_check)
        if not sig_results:
            # Signify not available, use PowerShell
            sig_results = _verify_signatures_powershell(files_to_check)

        if not sig_results:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Signature Verification Failed",
                description=(
                    "Could not verify signatures. Neither the signify library "
                    "nor PowerShell Get-AuthenticodeSignature returned results."
                ),
                severity=Severity.LOW,
                category=self.CATEGORY,
                affected_item="System Binaries",
                evidence="No verification results returned.",
                recommendation="Install signify (pip install signify) or ensure PowerShell is available.",
                references=[],
            ))
            return findings

        # Categorize results
        unsigned_sys: list[dict] = []
        unsigned_exe: list[dict] = []
        unsigned_dll: list[dict] = []
        invalid_sig: list[dict] = []
        valid_count = 0
        total_checked = len(sig_results)

        for result in sig_results:
            fp = result.get("FilePath", "")
            status = str(result.get("Status", "")).lower()
            ext = Path(fp).suffix.lower()

            if status in ("valid", "true"):
                valid_count += 1
                continue

            if status in ("notsigned", "not signed", "unsigned"):
                entry = {
                    "file": fp,
                    "status": result.get("Status"),
                    "message": result.get("StatusMessage", ""),
                }
                if ext == ".sys":
                    unsigned_sys.append(entry)
                elif ext == ".exe":
                    unsigned_exe.append(entry)
                elif ext == ".dll":
                    unsigned_dll.append(entry)
            elif status in ("signaturenotvalid", "hasherror", "incompatible", "error"):
                invalid_sig.append({
                    "file": fp,
                    "status": result.get("Status"),
                    "signer": result.get("SignerCert", "None"),
                    "message": result.get("StatusMessage", ""),
                })

        self.context = {
            "total_checked": total_checked,
            "valid": valid_count,
            "unsigned_sys": len(unsigned_sys),
            "unsigned_exe": len(unsigned_exe),
            "unsigned_dll": len(unsigned_dll),
            "invalid": len(invalid_sig),
        }

        # Unsigned .sys drivers
        if unsigned_sys:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Unsigned Kernel Driver Files (.sys) Detected",
                description=(
                    f"{len(unsigned_sys)} kernel driver file(s) in the drivers "
                    f"directory lack Authenticode signatures. Unsigned drivers "
                    f"could indicate tampered or malicious kernel modules, "
                    f"especially if Driver Signature Enforcement is bypassed."
                ),
                severity=Severity.HIGH,
                category=self.CATEGORY,
                affected_item="Unsigned Kernel Drivers",
                evidence=json.dumps(unsigned_sys, indent=2),
                recommendation=(
                    "Investigate each unsigned driver. Compare file hashes against "
                    "known-good databases. Unsigned .sys files in the drivers "
                    "directory are highly suspicious on modern Windows systems."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1014/",
                    "https://learn.microsoft.com/en-us/windows-hardware/drivers/install/driver-signing",
                ],
            ))

        # Unsigned .exe in System32
        if unsigned_exe:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Unsigned Executables (.exe) in System32",
                description=(
                    f"{len(unsigned_exe)} executable(s) in System32 lack "
                    f"Authenticode signatures. System binaries in System32 "
                    f"are expected to be signed by Microsoft or the hardware "
                    f"vendor."
                ),
                severity=Severity.HIGH,
                category=self.CATEGORY,
                affected_item="Unsigned System Executables",
                evidence=json.dumps(unsigned_exe, indent=2),
                recommendation=(
                    "Verify that unsigned executables are legitimate. They may "
                    "be third-party utilities installed to System32 (bad practice) "
                    "or indicators of tampering."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1036/005/",
                ],
            ))

        # Invalid signatures
        if invalid_sig:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="System Binaries With Invalid Signatures",
                description=(
                    f"{len(invalid_sig)} system binary(ies) have Authenticode "
                    f"signatures that failed validation. This could indicate "
                    f"file tampering, corrupted binaries, or expired certificates."
                ),
                severity=Severity.CRITICAL,
                category=self.CATEGORY,
                affected_item="Invalid Signature Binaries",
                evidence=json.dumps(invalid_sig, indent=2),
                recommendation=(
                    "Investigate each binary with an invalid signature immediately. "
                    "Compare file hashes against known-good versions. An invalid "
                    "signature on a system binary is a strong indicator of tampering."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1553/002/",
                ],
            ))

        # Summary
        unsigned_total = len(unsigned_sys) + len(unsigned_exe) + len(unsigned_dll)
        findings.append(Finding(
            check_id=self.CHECK_ID,
            title="Signature Verification Summary",
            description=(
                f"Verified signatures on {total_checked} files. "
                f"{valid_count} valid, {unsigned_total} unsigned, "
                f"{len(invalid_sig)} invalid."
            ),
            severity=Severity.INFO,
            category=self.CATEGORY,
            affected_item="System Binaries",
            evidence=(
                f"Total checked: {total_checked}\n"
                f"Valid signatures: {valid_count}\n"
                f"Unsigned .sys: {len(unsigned_sys)}\n"
                f"Unsigned .exe: {len(unsigned_exe)}\n"
                f"Unsigned .dll: {len(unsigned_dll)}\n"
                f"Invalid signatures: {len(invalid_sig)}"
            ),
            recommendation="Address all unsigned and invalid signature findings.",
            references=[],
        ))

        return findings

    def _enumerate_files(self) -> list[str]:
        """Enumerate target binary files in system directories."""
        target_files: list[str] = []
        seen: set[str] = set()

        for scan_dir in _SYSTEM_DIRS:
            dir_path = Path(scan_dir)
            if not dir_path.exists() or not dir_path.is_dir():
                continue
            try:
                for entry in dir_path.iterdir():
                    try:
                        if entry.is_file() and entry.suffix.lower() in _TARGET_EXTENSIONS:
                            resolved = str(entry.resolve())
                            if resolved not in seen:
                                seen.add(resolved)
                                target_files.append(resolved)
                    except (PermissionError, OSError):
                        continue
            except (PermissionError, OSError):
                continue

        return target_files
