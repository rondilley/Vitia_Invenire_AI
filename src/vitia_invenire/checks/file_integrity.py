"""FILE-001: System file integrity verification.

Runs sfc /verifyonly and DISM /Online /Cleanup-Image /CheckHealth
to check Windows system file integrity. Also hashes and verifies
Authenticode signatures of critical kernel binaries.
"""

from __future__ import annotations

import importlib.resources
import json
import re

from vitia_invenire.checks.base import BaseCheck
from vitia_invenire.collectors.command import run_cmd
from vitia_invenire.collectors.powershell import run_ps
from vitia_invenire.models import Category, Finding, Severity


def _load_kernel_binaries() -> list[dict]:
    """Load kernel binary definitions from the data file."""
    try:
        ref = importlib.resources.files("vitia_invenire.data").joinpath("kernel_binaries.json")
        raw = ref.read_text(encoding="utf-8")
        data = json.loads(raw)
        if isinstance(data, list):
            return data
    except (FileNotFoundError, json.JSONDecodeError, TypeError, AttributeError):
        return []
    return []


class FileIntegrityCheck(BaseCheck):
    """Verify Windows system file integrity and kernel binary signatures."""

    CHECK_ID = "FILE-001"
    NAME = "System File Integrity"
    DESCRIPTION = (
        "Runs System File Checker and DISM health check, then hashes "
        "and verifies Authenticode signatures of critical kernel binaries "
        "including ntoskrnl.exe, hal.dll, ci.dll, and others."
    )
    CATEGORY = Category.HARDENING
    REQUIRES_ADMIN = True

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        self._run_sfc_verify(findings)
        self._run_dism_checkhealth(findings)
        self._verify_kernel_binaries(findings)

        return findings

    def _run_sfc_verify(self, findings: list[Finding]) -> None:
        """Run sfc /verifyonly and report results."""
        result = run_cmd(["sfc", "/verifyonly"], timeout=300)

        if not result.success:
            # SFC returns non-zero if it finds integrity violations
            output = result.stdout if result.stdout else ""
            stderr = result.stderr if result.stderr else ""

            if "integrity violations" in output.lower() or "found corrupt files" in output.lower():
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title="System File Checker found integrity violations",
                    description=(
                        "SFC detected corrupted or modified Windows system files. "
                        "This may indicate tampering, malware infection, or system damage."
                    ),
                    severity=Severity.MEDIUM,
                    category=self.CATEGORY,
                    affected_item="Windows System Files",
                    evidence=output[:2000] if output else f"stderr: {stderr[:1000]}",
                    recommendation=(
                        "Run 'sfc /scannow' to repair corrupted files. "
                        "If repairs fail, run DISM /Online /Cleanup-Image /RestoreHealth first."
                    ),
                    references=[
                        "https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/sfc",
                    ],
                ))
            else:
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title="System File Checker returned an error",
                    description=f"SFC exited with code {result.return_code}.",
                    severity=Severity.MEDIUM,
                    category=self.CATEGORY,
                    affected_item="System File Checker",
                    evidence=f"Exit code: {result.return_code}\nOutput: {output[:1000]}\nError: {stderr[:500]}",
                    recommendation="Run SFC manually as administrator: sfc /verifyonly",
                ))
        else:
            output = result.stdout if result.stdout else ""
            if "did not find any integrity violations" in output.lower():
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title="System File Checker found no integrity violations",
                    description="SFC verified all Windows system files are intact.",
                    severity=Severity.INFO,
                    category=self.CATEGORY,
                    affected_item="Windows System Files",
                    evidence="SFC reported no integrity violations",
                    recommendation="No action needed.",
                ))
            else:
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title="System File Checker completed",
                    description="SFC completed verification.",
                    severity=Severity.INFO,
                    category=self.CATEGORY,
                    affected_item="Windows System Files",
                    evidence=output[:1000] if output else "No detailed output",
                    recommendation="Review SFC output for any issues.",
                ))

    def _run_dism_checkhealth(self, findings: list[Finding]) -> None:
        """Run DISM /Online /Cleanup-Image /CheckHealth."""
        result = run_cmd(
            ["DISM", "/Online", "/Cleanup-Image", "/CheckHealth"],
            timeout=120,
        )

        output = result.stdout if result.stdout else ""
        stderr = result.stderr if result.stderr else ""

        if not result.success:
            if "repairable" in output.lower() or "corrupted" in output.lower():
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title="DISM found component store corruption",
                    description=(
                        "DISM detected corruption in the Windows component store. "
                        "This may prevent Windows Update and system repairs from working."
                    ),
                    severity=Severity.MEDIUM,
                    category=self.CATEGORY,
                    affected_item="Windows Component Store",
                    evidence=output[:2000] if output else f"stderr: {stderr[:1000]}",
                    recommendation=(
                        "Run 'DISM /Online /Cleanup-Image /RestoreHealth' to repair. "
                        "An internet connection or installation media is needed."
                    ),
                    references=[
                        "https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/repair-a-windows-image",
                    ],
                ))
            else:
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title="DISM health check returned an error",
                    description=f"DISM exited with code {result.return_code}.",
                    severity=Severity.MEDIUM,
                    category=self.CATEGORY,
                    affected_item="Windows Component Store",
                    evidence=f"Exit code: {result.return_code}\nOutput: {output[:1000]}\nError: {stderr[:500]}",
                    recommendation="Run DISM manually as administrator.",
                ))
        else:
            if "no component store corruption" in output.lower() or "healthy" in output.lower():
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title="DISM component store is healthy",
                    description="DISM reports the Windows component store has no corruption.",
                    severity=Severity.INFO,
                    category=self.CATEGORY,
                    affected_item="Windows Component Store",
                    evidence="DISM reported component store is healthy",
                    recommendation="No action needed.",
                ))
            else:
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title="DISM health check completed",
                    description="DISM completed the health check.",
                    severity=Severity.INFO,
                    category=self.CATEGORY,
                    affected_item="Windows Component Store",
                    evidence=output[:1000] if output else "No detailed output",
                    recommendation="Review DISM output.",
                ))

    def _verify_kernel_binaries(self, findings: list[Finding]) -> None:
        """Hash and verify signatures of critical kernel binaries."""
        kernel_binaries = _load_kernel_binaries()
        if not kernel_binaries:
            # Fallback to a minimal set if data file is missing
            kernel_binaries = [
                {"filename": "ntoskrnl.exe", "expected_signer": "Microsoft Windows", "description": "Windows NT Kernel"},
                {"filename": "hal.dll", "expected_signer": "Microsoft Windows", "description": "Hardware Abstraction Layer"},
                {"filename": "ci.dll", "expected_signer": "Microsoft Windows", "description": "Code Integrity Module"},
                {"filename": "ndis.sys", "expected_signer": "Microsoft Windows", "description": "NDIS driver"},
                {"filename": "tcpip.sys", "expected_signer": "Microsoft Windows", "description": "TCP/IP driver"},
            ]

        system32 = "C:\\Windows\\System32"
        drivers_dir = "C:\\Windows\\System32\\drivers"

        verified_count = 0
        unsigned_count = 0
        invalid_count = 0
        missing_count = 0

        for binary in kernel_binaries:
            filename = str(binary.get("filename", ""))
            expected_signer = str(binary.get("expected_signer", "Microsoft Windows"))
            description = str(binary.get("description", ""))

            if not filename:
                continue

            # Determine full path based on extension
            if filename.endswith(".sys"):
                file_path = f"{drivers_dir}\\{filename}"
            else:
                file_path = f"{system32}\\{filename}"

            # For win32k*.sys, check both locations
            if filename.startswith("win32k"):
                file_path = f"{system32}\\{filename}"

            verify_result = run_ps(
                f"if (Test-Path '{file_path}') {{ "
                f"$hash = Get-FileHash -Path '{file_path}' -Algorithm SHA256 -ErrorAction SilentlyContinue; "
                f"$sig = Get-AuthenticodeSignature -FilePath '{file_path}' -ErrorAction SilentlyContinue; "
                "@{ "
                "Exists=$true; "
                "SHA256=if($hash){$hash.Hash}else{'ERROR'}; "
                "Status=if($sig){$sig.Status.ToString()}else{'Unknown'}; "
                "Signer=if($sig -and $sig.SignerCertificate){$sig.SignerCertificate.Subject}else{''}; "
                "Issuer=if($sig -and $sig.SignerCertificate){$sig.SignerCertificate.Issuer}else{''} "
                "} } else { "
                "@{ Exists=$false; SHA256=''; Status='NotFound'; Signer=''; Issuer='' } "
                "}",
                timeout=30,
                as_json=True,
            )

            if not verify_result.success or verify_result.json_output is None:
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title=f"Verification failed for {filename}",
                    description=f"Could not verify {description} at {file_path}.",
                    severity=Severity.MEDIUM,
                    category=self.CATEGORY,
                    affected_item=file_path,
                    evidence=f"Error: {verify_result.error or 'unknown'}",
                    recommendation=f"Manually verify {file_path}.",
                ))
                continue

            data = verify_result.json_output
            if isinstance(data, list) and len(data) > 0:
                data = data[0]

            exists = data.get("Exists", False)
            sha256 = str(data.get("SHA256", "Unknown"))
            sig_status = str(data.get("Status", "Unknown"))
            signer = str(data.get("Signer", ""))
            issuer = str(data.get("Issuer", ""))

            evidence_text = (
                f"File: {file_path}\n"
                f"Description: {description}\n"
                f"SHA256: {sha256}\n"
                f"Signature: {sig_status}\n"
                f"Signer: {signer}\n"
                f"Issuer: {issuer}"
            )

            if not exists:
                missing_count += 1
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title=f"Critical kernel binary missing: {filename}",
                    description=f"{description} ({file_path}) is missing from the system.",
                    severity=Severity.HIGH,
                    category=self.CATEGORY,
                    affected_item=file_path,
                    evidence=evidence_text,
                    recommendation="Run sfc /scannow to restore missing system files.",
                ))
            elif sig_status == "NotSigned":
                unsigned_count += 1
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title=f"Unsigned kernel binary: {filename}",
                    description=(
                        f"{description} ({file_path}) is not digitally signed. "
                        "All kernel binaries must be signed by Microsoft. An unsigned "
                        "kernel binary is a critical indicator of compromise."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.CATEGORY,
                    affected_item=file_path,
                    evidence=evidence_text,
                    recommendation=(
                        "This is a critical finding. Investigate immediately. "
                        "Compare the hash against known-good values. Consider reimaging."
                    ),
                    references=[
                        "https://attack.mitre.org/techniques/T1014/",
                    ],
                ))
            elif sig_status in ("HashMismatch", "InvalidSignature"):
                invalid_count += 1
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title=f"Invalid signature on kernel binary: {filename}",
                    description=(
                        f"{description} ({file_path}) has an invalid signature "
                        f"(status: {sig_status}). The file may have been tampered with."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.CATEGORY,
                    affected_item=file_path,
                    evidence=evidence_text,
                    recommendation="Investigate immediately. This may indicate rootkit infection.",
                    references=[
                        "https://attack.mitre.org/techniques/T1014/",
                    ],
                ))
            elif sig_status == "Valid":
                verified_count += 1
                if expected_signer.lower() not in signer.lower():
                    findings.append(Finding(
                        check_id=self.CHECK_ID,
                        title=f"Unexpected signer for kernel binary: {filename}",
                        description=(
                            f"{description} ({file_path}) is validly signed but by "
                            f"'{signer}' instead of the expected '{expected_signer}'."
                        ),
                        severity=Severity.HIGH,
                        category=self.CATEGORY,
                        affected_item=file_path,
                        evidence=evidence_text,
                        recommendation="Investigate the unexpected signer.",
                    ))

        # Summary
        findings.append(Finding(
            check_id=self.CHECK_ID,
            title="Kernel binary verification summary",
            description=(
                f"Verified {len(kernel_binaries)} kernel binaries. "
                f"{verified_count} valid, {unsigned_count} unsigned, "
                f"{invalid_count} invalid, {missing_count} missing."
            ),
            severity=Severity.INFO,
            category=self.CATEGORY,
            affected_item="Kernel Binaries",
            evidence=(
                f"Total checked: {len(kernel_binaries)}\n"
                f"Valid: {verified_count}\n"
                f"Unsigned: {unsigned_count}\n"
                f"Invalid: {invalid_count}\n"
                f"Missing: {missing_count}"
            ),
            recommendation="All kernel binaries should have valid Microsoft signatures.",
        ))
