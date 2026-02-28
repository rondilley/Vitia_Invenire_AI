"""FW-SUB-001: Deep enumeration of devices with embedded firmware/processors.

Enumerates audio codecs, WiFi, Bluetooth, NIC, GPU, NVMe, Thunderbolt,
webcam, fingerprint reader, TPM, Intel CSME, USB controllers, SD card
readers, WWAN modems, and embedded controllers using Win32_PnPSignedDriver.
Flags unsigned or self-signed drivers as HIGH severity.
"""

from __future__ import annotations

import json

from vitia_invenire.checks.base import BaseCheck
from vitia_invenire.collectors import wmi_collector
from vitia_invenire.models import Category, Finding, Severity


def _safe_str(value: object) -> str:
    if value is None:
        return "Unknown"
    return str(value)


# Map of subsystem label to Win32_PnPSignedDriver filter conditions.
# Each entry: (label, WMI WHERE clause)
_SUBSYSTEM_QUERIES: list[tuple[str, str]] = [
    ("Audio Codec", "DeviceClass = 'MEDIA' OR DeviceClass = 'AudioEndpoint'"),
    ("WiFi Adapter", "DeviceClass = 'NET' AND DeviceName LIKE '%Wi-Fi%'"),
    ("WiFi Adapter (alt)", "DeviceClass = 'NET' AND DeviceName LIKE '%Wireless%'"),
    ("Bluetooth Controller", "DeviceClass = 'Bluetooth'"),
    ("NIC (Ethernet)", "DeviceClass = 'NET' AND DeviceName LIKE '%Ethernet%'"),
    ("NIC (alt)", "DeviceClass = 'NET' AND DeviceName LIKE '%Gigabit%'"),
    ("GPU", "DeviceClass = 'Display'"),
    ("NVMe Controller", "DeviceName LIKE '%NVMe%'"),
    ("Thunderbolt Controller", "DeviceName LIKE '%Thunderbolt%'"),
    ("Webcam / Camera", "DeviceClass = 'Camera' OR DeviceClass = 'Image'"),
    ("Fingerprint Reader", "DeviceName LIKE '%Fingerprint%' OR DeviceName LIKE '%Biometric%'"),
    ("USB Controller", "DeviceClass = 'USB'"),
    ("SD Card Reader", "DeviceName LIKE '%SD%Card%' OR DeviceName LIKE '%Card Reader%'"),
    ("WWAN / Cellular Modem", "DeviceName LIKE '%WWAN%' OR DeviceName LIKE '%Cellular%' OR DeviceName LIKE '%Mobile Broadband%'"),
    ("Intel ME/CSME", "DeviceName LIKE '%Management Engine%' OR DeviceName LIKE '%MEI%' OR DeviceName LIKE '%CSME%'"),
    ("Embedded Controller", "DeviceName LIKE '%Embedded Controller%' OR DeviceName LIKE '%ACPI\\\\EC%'"),
]

# Properties to retrieve for each signed driver
_DRIVER_PROPERTIES = [
    "DeviceName", "Manufacturer", "DriverVersion", "DriverDate",
    "DeviceID", "DeviceClass", "InfName", "Signer",
    "DriverProviderName", "IsSigned", "FriendlyName",
]

# Known trusted driver signers (case-insensitive substring match)
_TRUSTED_SIGNERS = [
    "microsoft windows",
    "microsoft corporation",
    "microsoft windows hardware compatibility publisher",
    "whql",
]


def _is_trusted_signer(signer: str | None) -> bool:
    """Check whether the signer is a known trusted entity."""
    if not signer:
        return False
    signer_lower = signer.lower().strip()
    for trusted in _TRUSTED_SIGNERS:
        if trusted in signer_lower:
            return True
    return False


def _is_self_signed(signer: str | None, manufacturer: str | None) -> bool:
    """Heuristic: if the signer matches the manufacturer exactly, consider self-signed."""
    if not signer or not manufacturer:
        return False
    signer_clean = signer.lower().strip()
    mfg_clean = manufacturer.lower().strip()
    # Skip the comparison if signer is a known trusted entity
    if _is_trusted_signer(signer):
        return False
    # If the signer is exactly the manufacturer or a substring, it may be self-signed
    # This is a heuristic; truly self-signed certs are rare on modern Windows
    return signer_clean == mfg_clean


class SubsystemFirmwareCheck(BaseCheck):
    """Deep enumeration of subsystem firmware and driver signing status."""

    CHECK_ID = "FW-SUB-001"
    NAME = "Subsystem Firmware Enumeration"
    DESCRIPTION = (
        "Enumerate every device with its own firmware or embedded processor "
        "(audio, WiFi, BT, NIC, GPU, NVMe, Thunderbolt, webcam, fingerprint, "
        "TPM, Intel CSME, USB controllers, SD readers, WWAN, EC). "
        "Uses Win32_PnPSignedDriver to check driver signer and version. "
        "Flags unsigned or self-signed drivers."
    )
    CATEGORY = Category.FIRMWARE
    REQUIRES_ADMIN = False

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        all_subsystems: list[dict] = []
        unsigned_drivers: list[dict] = []
        self_signed_drivers: list[dict] = []
        seen_device_ids: set[str] = set()

        for label, where_clause in _SUBSYSTEM_QUERIES:
            rows = wmi_collector.query(
                "Win32_PnPSignedDriver",
                properties=_DRIVER_PROPERTIES,
                where=where_clause,
            )
            for row in rows:
                device_id = _safe_str(row.get("DeviceID"))
                # Deduplicate across overlapping queries
                if device_id in seen_device_ids:
                    continue
                seen_device_ids.add(device_id)

                signer = row.get("Signer")
                is_signed = row.get("IsSigned")
                manufacturer = row.get("Manufacturer")

                entry = {
                    "subsystem": label,
                    "device_name": _safe_str(row.get("DeviceName")),
                    "manufacturer": _safe_str(manufacturer),
                    "driver_version": _safe_str(row.get("DriverVersion")),
                    "driver_date": _safe_str(row.get("DriverDate")),
                    "signer": _safe_str(signer),
                    "is_signed": is_signed,
                    "inf_name": _safe_str(row.get("InfName")),
                    "device_id": device_id,
                    "driver_provider": _safe_str(row.get("DriverProviderName")),
                }
                all_subsystems.append(entry)

                # Check for unsigned driver
                if is_signed is False or (is_signed is not True and not signer):
                    unsigned_drivers.append(entry)
                elif _is_self_signed(signer, manufacturer):
                    self_signed_drivers.append(entry)

        # Also query TPM from security namespace
        tpm_rows = wmi_collector.query(
            "Win32_Tpm",
            properties=["ManufacturerIdTxt", "ManufacturerVersion",
                         "ManufacturerVersionFull20", "SpecVersion",
                         "IsActivated_InitialValue", "IsEnabled_InitialValue"],
            namespace="root\\cimv2\\Security\\MicrosoftTpm",
        )
        for row in tpm_rows:
            entry = {
                "subsystem": "TPM",
                "device_name": "Trusted Platform Module",
                "manufacturer": _safe_str(row.get("ManufacturerIdTxt")),
                "driver_version": _safe_str(row.get("ManufacturerVersion")),
                "spec_version": _safe_str(row.get("SpecVersion")),
                "is_signed": "N/A (firmware)",
                "signer": "N/A (firmware)",
            }
            all_subsystems.append(entry)

        # Inventory finding
        inventory_json = json.dumps(all_subsystems, indent=2, default=str)
        findings.append(Finding(
            check_id=self.CHECK_ID,
            title="Subsystem Firmware Inventory",
            description=(
                f"Enumerated {len(all_subsystems)} subsystem devices with "
                f"embedded firmware across {len(seen_device_ids)} unique device IDs."
            ),
            severity=Severity.INFO,
            category=self.CATEGORY,
            affected_item="Subsystem Firmware Devices",
            evidence=inventory_json,
            recommendation="Review subsystem firmware versions and driver signing status.",
            references=[
                "https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-pnpsigneddriver",
            ],
        ))

        # Unsigned driver finding
        if unsigned_drivers:
            unsigned_json = json.dumps(unsigned_drivers, indent=2, default=str)
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Unsigned Subsystem Drivers Detected",
                description=(
                    f"{len(unsigned_drivers)} subsystem driver(s) are not signed. "
                    f"Unsigned drivers bypass Windows driver signature enforcement "
                    f"and may indicate tampered, test-signed, or malicious drivers."
                ),
                severity=Severity.HIGH,
                category=self.CATEGORY,
                affected_item="Unsigned Drivers",
                evidence=unsigned_json,
                recommendation=(
                    "Investigate all unsigned drivers. Replace with signed versions "
                    "from the device manufacturer. Enable Driver Signature Enforcement "
                    "in Windows Secure Boot settings."
                ),
                references=[
                    "https://learn.microsoft.com/en-us/windows-hardware/drivers/install/driver-signing",
                    "https://attack.mitre.org/techniques/T1014/",
                ],
            ))

        # Self-signed driver finding
        if self_signed_drivers:
            self_signed_json = json.dumps(self_signed_drivers, indent=2, default=str)
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Self-Signed Subsystem Drivers Detected",
                description=(
                    f"{len(self_signed_drivers)} subsystem driver(s) appear to be "
                    f"self-signed (signer matches manufacturer). Self-signed drivers "
                    f"are not validated by a trusted certificate authority."
                ),
                severity=Severity.HIGH,
                category=self.CATEGORY,
                affected_item="Self-Signed Drivers",
                evidence=self_signed_json,
                recommendation=(
                    "Verify that self-signed drivers are legitimate and from a trusted "
                    "vendor. Where possible, obtain WHQL-signed driver versions."
                ),
                references=[
                    "https://learn.microsoft.com/en-us/windows-hardware/drivers/install/whql-release-signature",
                ],
            ))

        return findings
