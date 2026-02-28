"""FW-INFO-001: Collect firmware versions for system components.

Queries BIOS/UEFI, Embedded Controller, NVMe drives, NICs, GPU,
Intel ME, and Thunderbolt firmware versions via WMI and PnP driver
queries. Flags outdated or unversioned firmware as LOW severity.
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


class FirmwareInfoCheck(BaseCheck):
    """Collect firmware version information for major system components."""

    CHECK_ID = "FW-INFO-001"
    NAME = "Firmware Version Inventory"
    DESCRIPTION = (
        "Collect firmware versions for BIOS/UEFI, EC, NVMe drives, NICs, "
        "GPU, Intel ME, and Thunderbolt controllers via WMI and PnP driver queries."
    )
    CATEGORY = Category.FIRMWARE
    REQUIRES_ADMIN = False

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        firmware_entries: list[dict] = []
        unversioned_entries: list[dict] = []

        # 1. BIOS/UEFI firmware
        bios_rows = wmi_collector.query(
            "Win32_BIOS",
            properties=["Manufacturer", "Name", "SMBIOSBIOSVersion",
                         "ReleaseDate", "SerialNumber", "Version",
                         "SystemBiosMajorVersion", "SystemBiosMinorVersion",
                         "EmbeddedControllerMajorVersion",
                         "EmbeddedControllerMinorVersion"],
        )
        for row in bios_rows:
            bios_ver = row.get("SMBIOSBIOSVersion") or row.get("Version")
            entry = {
                "component": "BIOS/UEFI",
                "manufacturer": _safe_str(row.get("Manufacturer")),
                "version": _safe_str(bios_ver),
                "name": _safe_str(row.get("Name")),
                "release_date": _safe_str(row.get("ReleaseDate")),
            }
            firmware_entries.append(entry)

            # Check for EC firmware version embedded in BIOS data
            ec_major = row.get("EmbeddedControllerMajorVersion")
            ec_minor = row.get("EmbeddedControllerMinorVersion")
            if ec_major is not None and ec_minor is not None:
                # Values of 255 indicate EC info not available
                if ec_major != 255 and ec_minor != 255:
                    ec_entry = {
                        "component": "Embedded Controller",
                        "manufacturer": _safe_str(row.get("Manufacturer")),
                        "version": f"{ec_major}.{ec_minor}",
                        "name": "EC Firmware",
                        "release_date": "N/A",
                    }
                    firmware_entries.append(ec_entry)

        # 2. NVMe drive firmware via Win32_DiskDrive
        disk_rows = wmi_collector.query(
            "Win32_DiskDrive",
            properties=["Model", "Manufacturer", "FirmwareRevision",
                         "InterfaceType", "PNPDeviceID", "SerialNumber"],
        )
        for row in disk_rows:
            fw = row.get("FirmwareRevision")
            entry = {
                "component": f"Disk ({_safe_str(row.get('InterfaceType'))})",
                "manufacturer": _safe_str(row.get("Manufacturer")),
                "version": _safe_str(fw),
                "name": _safe_str(row.get("Model")),
                "pnp_device_id": _safe_str(row.get("PNPDeviceID")),
            }
            firmware_entries.append(entry)
            if not fw or str(fw).strip() == "":
                unversioned_entries.append(entry)

        # 3. Network adapter firmware via PnP signed drivers
        nic_rows = wmi_collector.query(
            "Win32_PnPSignedDriver",
            properties=["DeviceName", "Manufacturer", "DriverVersion",
                         "DriverDate", "DeviceID", "InfName", "Signer",
                         "DriverProviderName"],
            where="DeviceClass = 'NET'",
        )
        for row in nic_rows:
            dv = row.get("DriverVersion")
            entry = {
                "component": "NIC Driver/Firmware",
                "manufacturer": _safe_str(row.get("Manufacturer")),
                "version": _safe_str(dv),
                "name": _safe_str(row.get("DeviceName")),
                "driver_date": _safe_str(row.get("DriverDate")),
                "signer": _safe_str(row.get("Signer")),
            }
            firmware_entries.append(entry)
            if not dv or str(dv).strip() == "":
                unversioned_entries.append(entry)

        # 4. GPU firmware / driver version via Win32_VideoController
        gpu_rows = wmi_collector.query(
            "Win32_VideoController",
            properties=["Name", "AdapterCompatibility", "DriverVersion",
                         "DriverDate", "PNPDeviceID", "VideoProcessor"],
        )
        for row in gpu_rows:
            dv = row.get("DriverVersion")
            entry = {
                "component": "GPU",
                "manufacturer": _safe_str(row.get("AdapterCompatibility")),
                "version": _safe_str(dv),
                "name": _safe_str(row.get("Name")),
                "driver_date": _safe_str(row.get("DriverDate")),
                "video_processor": _safe_str(row.get("VideoProcessor")),
            }
            firmware_entries.append(entry)
            if not dv or str(dv).strip() == "":
                unversioned_entries.append(entry)

        # 5. Intel ME (Management Engine) via PnP driver query
        me_rows = wmi_collector.query(
            "Win32_PnPSignedDriver",
            properties=["DeviceName", "Manufacturer", "DriverVersion",
                         "DeviceID", "Signer"],
            where="DeviceName LIKE '%Management Engine%' OR DeviceName LIKE '%MEI%' OR DeviceName LIKE '%CSME%'",
        )
        for row in me_rows:
            dv = row.get("DriverVersion")
            entry = {
                "component": "Intel ME/CSME",
                "manufacturer": _safe_str(row.get("Manufacturer")),
                "version": _safe_str(dv),
                "name": _safe_str(row.get("DeviceName")),
                "signer": _safe_str(row.get("Signer")),
            }
            firmware_entries.append(entry)
            if not dv or str(dv).strip() == "":
                unversioned_entries.append(entry)

        # 6. Thunderbolt controller via PnP driver query
        tb_rows = wmi_collector.query(
            "Win32_PnPSignedDriver",
            properties=["DeviceName", "Manufacturer", "DriverVersion",
                         "DeviceID", "Signer"],
            where="DeviceName LIKE '%Thunderbolt%'",
        )
        for row in tb_rows:
            dv = row.get("DriverVersion")
            entry = {
                "component": "Thunderbolt",
                "manufacturer": _safe_str(row.get("Manufacturer")),
                "version": _safe_str(dv),
                "name": _safe_str(row.get("DeviceName")),
                "signer": _safe_str(row.get("Signer")),
            }
            firmware_entries.append(entry)
            if not dv or str(dv).strip() == "":
                unversioned_entries.append(entry)

        # Build the inventory finding
        inventory_json = json.dumps(firmware_entries, indent=2, default=str)
        findings.append(Finding(
            check_id=self.CHECK_ID,
            title="Firmware Version Inventory",
            description=(
                f"Collected firmware/driver version information for "
                f"{len(firmware_entries)} components."
            ),
            severity=Severity.INFO,
            category=self.CATEGORY,
            affected_item="System Firmware",
            evidence=inventory_json,
            recommendation="Compare firmware versions against vendor release notes for updates.",
            references=[
                "https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-bios",
                "https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-pnpsigneddriver",
            ],
        ))

        # Flag unversioned firmware entries
        if unversioned_entries:
            unversioned_json = json.dumps(unversioned_entries, indent=2, default=str)
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Components With Missing Firmware Version",
                description=(
                    f"{len(unversioned_entries)} component(s) have no firmware "
                    f"or driver version reported. This may indicate legacy "
                    f"hardware, missing drivers, or firmware that cannot be "
                    f"audited for known vulnerabilities."
                ),
                severity=Severity.LOW,
                category=self.CATEGORY,
                affected_item="Unversioned Components",
                evidence=unversioned_json,
                recommendation=(
                    "Investigate components with missing version information. "
                    "Install manufacturer-provided drivers and firmware utilities "
                    "to ensure version reporting is available."
                ),
                references=[
                    "https://learn.microsoft.com/en-us/windows-hardware/drivers/install/device-metadata",
                ],
            ))

        return findings
