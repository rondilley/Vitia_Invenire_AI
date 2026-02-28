"""FWUPD-001: Firmware Update Currency.

Checks whether BIOS firmware and system drivers are current by
analyzing release dates. Outdated firmware may contain known
vulnerabilities that have been patched in newer versions.
"""

from __future__ import annotations

from datetime import datetime, timezone

from vitia_invenire.checks.base import BaseCheck
from vitia_invenire.collectors.powershell import run_ps
from vitia_invenire.models import Category, Finding, Severity


def _parse_iso_date(date_str: str) -> datetime | None:
    """Parse an ISO 8601 date string into a datetime object.

    Handles various formats returned by PowerShell's ToString('o')
    including with and without timezone offsets.

    Returns None if parsing fails.
    """
    if not date_str or date_str in ("Unknown", "None", ""):
        return None

    # Try common ISO formats
    for fmt in (
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S%z",
        "%Y-%m-%d %H:%M:%S",
        "%Y%m%d%H%M%S.%f%z",
    ):
        try:
            return datetime.strptime(date_str, fmt)
        except ValueError:
            continue

    # Try parsing just the date portion
    try:
        return datetime.strptime(date_str[:10], "%Y-%m-%d")
    except (ValueError, IndexError):
        pass

    return None


class FirmwareCurrencyCheck(BaseCheck):
    """Check whether BIOS firmware and drivers are up to date."""

    CHECK_ID = "FWUPD-001"
    NAME = "Firmware Update Currency"
    DESCRIPTION = (
        "Checks BIOS firmware release date and oldest system driver dates "
        "to identify outdated firmware that may contain known vulnerabilities. "
        "Flags BIOS older than 2 years and drivers older than 5 years."
    )
    CATEGORY = Category.FIRMWARE
    REQUIRES_ADMIN = False

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        summary_evidence: list[str] = []
        now = datetime.now(timezone.utc)

        # --- BIOS release date ---
        bios_result = run_ps(
            "Get-CimInstance Win32_BIOS | Select-Object SerialNumber, "
            "Manufacturer, Name, SMBIOSBIOSVersion, ReleaseDate, "
            "@{N='ReleaseDateStr';E={$_.ReleaseDate.ToString('o')}}",
            timeout=15,
            as_json=True,
        )

        bios_manufacturer = "Unknown"
        bios_version = "Unknown"
        bios_serial = "Unknown"
        bios_name = "Unknown"
        bios_age_days: int | None = None
        bios_date_str = "Unknown"

        if bios_result.success and bios_result.json_output is not None:
            bios_data = bios_result.json_output
            if isinstance(bios_data, list):
                bios_data = bios_data[0] if bios_data else {}

            bios_manufacturer = str(bios_data.get("Manufacturer", "Unknown"))
            bios_version = str(bios_data.get("SMBIOSBIOSVersion", "Unknown"))
            bios_serial = str(bios_data.get("SerialNumber", "Unknown"))
            bios_name = str(bios_data.get("Name", "Unknown"))
            raw_date = str(bios_data.get("ReleaseDateStr", ""))

            bios_date = _parse_iso_date(raw_date)
            if bios_date is not None:
                # Ensure timezone-aware comparison
                if bios_date.tzinfo is None:
                    bios_date = bios_date.replace(tzinfo=timezone.utc)
                delta = now - bios_date
                bios_age_days = delta.days
                bios_date_str = bios_date.strftime("%Y-%m-%d")
            else:
                bios_date_str = raw_date if raw_date else "Unknown"

            summary_evidence.append(
                f"BIOS Manufacturer: {bios_manufacturer}\n"
                f"BIOS Version: {bios_version}\n"
                f"BIOS Name: {bios_name}\n"
                f"BIOS Serial: {bios_serial}\n"
                f"BIOS Release Date: {bios_date_str}\n"
                f"BIOS Age: {bios_age_days} days"
                if bios_age_days is not None
                else f"BIOS Manufacturer: {bios_manufacturer}\n"
                     f"BIOS Version: {bios_version}\n"
                     f"BIOS Name: {bios_name}\n"
                     f"BIOS Serial: {bios_serial}\n"
                     f"BIOS Release Date: {bios_date_str}\n"
                     f"BIOS Age: unable to determine"
            )

            # Evaluate BIOS age severity
            if bios_age_days is not None:
                bios_age_years = bios_age_days / 365.25
                if bios_age_days >= 1096:  # 3+ years
                    findings.append(Finding(
                        check_id=self.CHECK_ID,
                        title="BIOS firmware is significantly outdated",
                        description=(
                            f"The BIOS firmware from {bios_manufacturer} "
                            f"(version {bios_version}) was released on "
                            f"{bios_date_str}, which is approximately "
                            f"{bios_age_years:.1f} years old. BIOS firmware "
                            "older than 3 years is likely missing critical "
                            "security patches for known vulnerabilities "
                            "such as SMM exploits and privilege escalation."
                        ),
                        severity=Severity.HIGH,
                        category=self.CATEGORY,
                        affected_item="BIOS Firmware",
                        evidence=(
                            f"Manufacturer: {bios_manufacturer}\n"
                            f"Version: {bios_version}\n"
                            f"Release Date: {bios_date_str}\n"
                            f"Age: {bios_age_days} days ({bios_age_years:.1f} years)"
                        ),
                        recommendation=(
                            "Update BIOS firmware to the latest version from "
                            f"the system manufacturer ({bios_manufacturer}). "
                            "Review the manufacturer's security advisories for "
                            "vulnerabilities addressed in newer firmware releases."
                        ),
                        references=[
                            "https://attack.mitre.org/techniques/T1542/001/",
                            "https://learn.microsoft.com/en-us/windows-hardware/drivers/bringup/firmware-update",
                        ],
                    ))
                elif bios_age_days >= 731:  # 2+ years
                    findings.append(Finding(
                        check_id=self.CHECK_ID,
                        title="BIOS firmware is outdated",
                        description=(
                            f"The BIOS firmware from {bios_manufacturer} "
                            f"(version {bios_version}) was released on "
                            f"{bios_date_str}, which is approximately "
                            f"{bios_age_years:.1f} years old. BIOS firmware "
                            "older than 2 years may be missing important "
                            "security updates."
                        ),
                        severity=Severity.MEDIUM,
                        category=self.CATEGORY,
                        affected_item="BIOS Firmware",
                        evidence=(
                            f"Manufacturer: {bios_manufacturer}\n"
                            f"Version: {bios_version}\n"
                            f"Release Date: {bios_date_str}\n"
                            f"Age: {bios_age_days} days ({bios_age_years:.1f} years)"
                        ),
                        recommendation=(
                            "Check for BIOS firmware updates from "
                            f"{bios_manufacturer}. Apply any available security "
                            "updates following the manufacturer's update procedures."
                        ),
                        references=[
                            "https://attack.mitre.org/techniques/T1542/001/",
                            "https://learn.microsoft.com/en-us/windows-hardware/drivers/bringup/firmware-update",
                        ],
                    ))
        else:
            summary_evidence.append(
                f"BIOS query failed: {bios_result.error or 'No output'}"
            )

        # --- Oldest system drivers ---
        driver_result = run_ps(
            "Get-CimInstance Win32_PnPSignedDriver | "
            "Where-Object { $_.DriverDate -ne $null } | "
            "Sort-Object DriverDate | "
            "Select-Object -First 5 DeviceName, DriverVersion, "
            "@{N='DriverDateStr';E={$_.DriverDate.ToString('o')}}, "
            "Manufacturer",
            timeout=30,
            as_json=True,
        )

        if driver_result.success and driver_result.json_output is not None:
            drivers = driver_result.json_output
            if isinstance(drivers, dict):
                drivers = [drivers]

            if drivers:
                old_driver_entries: list[dict[str, str]] = []
                driver_evidence_lines: list[str] = []

                for drv in drivers:
                    device_name = str(drv.get("DeviceName", "Unknown"))
                    driver_version = str(drv.get("DriverVersion", "Unknown"))
                    manufacturer = str(drv.get("Manufacturer", "Unknown"))
                    raw_driver_date = str(drv.get("DriverDateStr", ""))

                    driver_date = _parse_iso_date(raw_driver_date)
                    if driver_date is not None:
                        if driver_date.tzinfo is None:
                            driver_date = driver_date.replace(tzinfo=timezone.utc)
                        driver_age_days = (now - driver_date).days
                        driver_date_formatted = driver_date.strftime("%Y-%m-%d")
                        driver_age_years = driver_age_days / 365.25
                    else:
                        driver_age_days = 0
                        driver_date_formatted = raw_driver_date if raw_driver_date else "Unknown"
                        driver_age_years = 0.0

                    entry = {
                        "device_name": device_name,
                        "driver_version": driver_version,
                        "manufacturer": manufacturer,
                        "driver_date": driver_date_formatted,
                        "age_days": str(driver_age_days),
                        "age_years": f"{driver_age_years:.1f}",
                    }
                    old_driver_entries.append(entry)

                    driver_evidence_lines.append(
                        f"  {device_name}\n"
                        f"    Version: {driver_version}\n"
                        f"    Manufacturer: {manufacturer}\n"
                        f"    Driver Date: {driver_date_formatted}\n"
                        f"    Age: {driver_age_days} days ({driver_age_years:.1f} years)"
                    )

                summary_evidence.append("")
                summary_evidence.append("Oldest 5 drivers:")
                summary_evidence.extend(driver_evidence_lines)

                # Check if oldest driver is 5+ years old
                oldest_age_days = max(
                    int(e["age_days"]) for e in old_driver_entries
                )
                if oldest_age_days >= 1826:  # 5+ years
                    oldest_age_years = oldest_age_days / 365.25
                    findings.append(Finding(
                        check_id=self.CHECK_ID,
                        title="System contains drivers older than 5 years",
                        description=(
                            f"The oldest system driver is approximately "
                            f"{oldest_age_years:.1f} years old. Very old "
                            "drivers may contain known vulnerabilities and "
                            "lack modern security mitigations. While not "
                            "always exploitable, outdated drivers increase "
                            "the overall attack surface."
                        ),
                        severity=Severity.LOW,
                        category=self.CATEGORY,
                        affected_item="System Drivers",
                        evidence="\n".join(driver_evidence_lines),
                        recommendation=(
                            "Review the oldest drivers and check for available "
                            "updates from their manufacturers. Prioritize drivers "
                            "for network, storage, and security-critical devices."
                        ),
                        references=[
                            "https://attack.mitre.org/techniques/T1068/",
                            "https://learn.microsoft.com/en-us/windows-hardware/drivers/install/updating-drivers",
                        ],
                    ))
        else:
            summary_evidence.append(
                f"\nDriver query failed: {driver_result.error or 'No output'}"
            )

        # INFO summary finding
        findings.append(Finding(
            check_id=self.CHECK_ID,
            title="Firmware Update Currency Summary",
            description=(
                f"Assessed BIOS firmware currency for {bios_manufacturer} "
                f"{bios_version} and reviewed oldest system driver dates."
            ),
            severity=Severity.INFO,
            category=self.CATEGORY,
            affected_item="System Firmware and Drivers",
            evidence="\n".join(summary_evidence),
            recommendation=(
                "Maintain firmware and drivers at their latest vendor-supported "
                "versions. Establish a firmware update policy and monitor vendor "
                "security advisories."
            ),
            references=[
                "https://learn.microsoft.com/en-us/windows-hardware/drivers/bringup/firmware-update",
                "https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-bios",
            ],
        ))

        return findings
