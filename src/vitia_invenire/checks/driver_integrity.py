"""DRV-001: Driver integrity verification.

Enumerates loaded system drivers via Win32_SystemDriver and verifies
their Authenticode signatures via Get-AuthenticodeSignature. Unsigned
or invalidly signed drivers represent a significant security risk.
"""

from __future__ import annotations

from vitia_invenire.checks.base import BaseCheck
from vitia_invenire.collectors import wmi_collector
from vitia_invenire.collectors.powershell import run_ps
from vitia_invenire.models import Category, Finding, Severity


class DriverIntegrityCheck(BaseCheck):
    """Verify digital signatures of loaded system drivers."""

    CHECK_ID = "DRV-001"
    NAME = "Driver Integrity Verification"
    DESCRIPTION = (
        "Enumerates loaded system drivers and verifies their Authenticode "
        "digital signatures. Unsigned or invalidly signed drivers may "
        "indicate rootkits, test drivers, or supply chain compromise."
    )
    CATEGORY = Category.DRIVERS
    REQUIRES_ADMIN = True

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        # Enumerate loaded drivers via WMI
        driver_rows = wmi_collector.query(
            "Win32_SystemDriver",
            properties=[
                "Name", "DisplayName", "PathName", "State",
                "StartMode", "ServiceType", "Description",
            ],
            where="State='Running'",
        )

        if not driver_rows:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Failed to enumerate loaded drivers",
                description="Win32_SystemDriver query returned no results.",
                severity=Severity.MEDIUM,
                category=self.CATEGORY,
                affected_item="Win32_SystemDriver",
                evidence="WMI query returned empty results",
                recommendation="Verify WMI service is running and accessible.",
            ))
            return findings

        # Collect driver paths for batch signature verification
        driver_map: dict[str, dict] = {}
        for row in driver_rows:
            name = str(row.get("Name", "Unknown"))
            path = str(row.get("PathName", ""))

            # Normalize path: strip \??\ prefix and similar
            cleaned_path = path
            if cleaned_path.startswith("\\??\\"):
                cleaned_path = cleaned_path[4:]
            elif cleaned_path.startswith("\\SystemRoot\\"):
                cleaned_path = cleaned_path.replace("\\SystemRoot\\", "C:\\Windows\\", 1)

            if cleaned_path:
                driver_map[cleaned_path] = row

        if not driver_map:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="No driver paths available for verification",
                description="Could not extract file paths from loaded drivers.",
                severity=Severity.MEDIUM,
                category=self.CATEGORY,
                affected_item="System Drivers",
                evidence=f"Total drivers enumerated: {len(driver_rows)}, paths extracted: 0",
                recommendation="Manually verify driver signatures using sigcheck or PowerShell.",
            ))
            return findings

        # Verify signatures in batches to avoid command length limits
        paths_list = list(driver_map.keys())
        batch_size = 50
        unsigned_drivers: list[str] = []
        invalid_drivers: list[str] = []
        signed_count = 0

        for batch_start in range(0, len(paths_list), batch_size):
            batch = paths_list[batch_start:batch_start + batch_size]

            # Build PowerShell array of paths
            paths_ps = ", ".join(f"'{p}'" for p in batch)
            sig_cmd = (
                f"@({paths_ps}) | ForEach-Object {{ "
                "$path = $_; "
                "if (Test-Path $path) {{ "
                "$sig = Get-AuthenticodeSignature -FilePath $path -ErrorAction SilentlyContinue; "
                "@{{ Path=$path; Status=if($sig){{$sig.Status.ToString()}}else{{'NotFound'}}; "
                "Signer=if($sig -and $sig.SignerCertificate){{$sig.SignerCertificate.Subject}}else{{''}}; "
                "TimeStamperCert=if($sig -and $sig.TimeStamperCertificate){{$sig.TimeStamperCertificate.Subject}}else{{''}} }} "
                "}} else {{ "
                "@{{ Path=$path; Status='FileNotFound'; Signer=''; TimeStamperCert='' }} "
                "}} }}"
            )

            sig_result = run_ps(sig_cmd, timeout=120, as_json=True)

            if not sig_result.success or sig_result.json_output is None:
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title=f"Signature verification batch failed (batch at index {batch_start})",
                    description=f"Failed to verify signatures: {sig_result.error or 'unknown error'}",
                    severity=Severity.MEDIUM,
                    category=self.CATEGORY,
                    affected_item="Driver Signature Verification",
                    evidence=f"Batch size: {len(batch)}, error: {sig_result.error or 'none'}",
                    recommendation="Retry or use sigcheck.exe for manual verification.",
                ))
                continue

            sig_data = sig_result.json_output
            if isinstance(sig_data, dict):
                sig_data = [sig_data]

            for entry in sig_data:
                path = str(entry.get("Path", "Unknown"))
                status = str(entry.get("Status", "Unknown"))
                signer = str(entry.get("Signer", ""))
                timestamper = str(entry.get("TimeStamperCert", ""))

                driver_info = driver_map.get(path, {})
                driver_name = str(driver_info.get("DisplayName", driver_info.get("Name", path)))
                start_mode = str(driver_info.get("StartMode", "Unknown"))

                if status == "FileNotFound":
                    continue

                if status == "NotSigned":
                    unsigned_drivers.append(path)
                    findings.append(Finding(
                        check_id=self.CHECK_ID,
                        title=f"Unsigned driver: {driver_name}",
                        description=(
                            f"Running driver '{driver_name}' at '{path}' has no "
                            "Authenticode signature. Unsigned kernel-mode drivers can "
                            "execute arbitrary code with full system privileges."
                        ),
                        severity=Severity.HIGH,
                        category=self.CATEGORY,
                        affected_item=path,
                        evidence=(
                            f"Driver: {driver_name}\n"
                            f"Path: {path}\n"
                            f"Signature Status: NotSigned\n"
                            f"Start Mode: {start_mode}"
                        ),
                        recommendation=(
                            "Investigate the origin of this unsigned driver. "
                            "Legitimate drivers should always be signed. "
                            "Consider removing or replacing with a signed version."
                        ),
                        references=[
                            "https://learn.microsoft.com/en-us/windows-hardware/drivers/install/kernel-mode-code-signing-policy--windows-vista-and-later-",
                        ],
                    ))
                elif status in ("HashMismatch", "InvalidSignature", "UnknownError"):
                    invalid_drivers.append(path)
                    findings.append(Finding(
                        check_id=self.CHECK_ID,
                        title=f"Invalid signature on driver: {driver_name}",
                        description=(
                            f"Running driver '{driver_name}' at '{path}' has an invalid "
                            f"Authenticode signature (status: {status}). This may indicate "
                            "the file has been tampered with after signing."
                        ),
                        severity=Severity.HIGH,
                        category=self.CATEGORY,
                        affected_item=path,
                        evidence=(
                            f"Driver: {driver_name}\n"
                            f"Path: {path}\n"
                            f"Signature Status: {status}\n"
                            f"Signer: {signer}\n"
                            f"Start Mode: {start_mode}"
                        ),
                        recommendation=(
                            "This driver may have been modified after it was signed. "
                            "Verify the driver from a known-good source. Consider "
                            "reimaging if tampering is confirmed."
                        ),
                        references=[
                            "https://attack.mitre.org/techniques/T1014/",
                        ],
                    ))
                elif status == "Valid":
                    signed_count += 1

        # Summary finding
        total = len(driver_map)
        findings.append(Finding(
            check_id=self.CHECK_ID,
            title="Driver integrity verification summary",
            description=(
                f"Verified {total} loaded drivers. "
                f"{signed_count} validly signed, "
                f"{len(unsigned_drivers)} unsigned, "
                f"{len(invalid_drivers)} with invalid signatures."
            ),
            severity=Severity.INFO,
            category=self.CATEGORY,
            affected_item="System Drivers",
            evidence=(
                f"Total loaded drivers: {total}\n"
                f"Signed: {signed_count}\n"
                f"Unsigned: {len(unsigned_drivers)}\n"
                f"Invalid: {len(invalid_drivers)}"
            ),
            recommendation="All kernel-mode drivers should be validly signed.",
        ))

        return findings
