"""HW-001: Full hardware fingerprint via WMI.

Queries Win32_Processor, Win32_BaseBoard, Win32_PhysicalMemory,
Win32_DiskDrive, Win32_NetworkAdapter, Win32_VideoController,
Win32_PnPEntity (USB/BT/camera/audio), Win32_Battery,
Win32_DesktopMonitor, Win32_Tpm, Win32_ComputerSystemProduct.
Collects all into HardwareComponent objects and reports as INFO findings.
"""

from __future__ import annotations

import json

from vitia_invenire.checks.base import BaseCheck
from vitia_invenire.collectors import wmi_collector
from vitia_invenire.models import Category, Finding, HardwareComponent, Severity

# WMI classes and the component_type label for each
_WMI_COMPONENT_MAP: list[tuple[str, str, list[str] | None]] = [
    (
        "Win32_Processor",
        "Processor",
        ["Name", "Manufacturer", "NumberOfCores", "NumberOfLogicalProcessors",
         "MaxClockSpeed", "ProcessorId", "Architecture", "SocketDesignation"],
    ),
    (
        "Win32_BaseBoard",
        "Baseboard",
        ["Manufacturer", "Product", "SerialNumber", "Version"],
    ),
    (
        "Win32_PhysicalMemory",
        "Memory",
        ["Manufacturer", "PartNumber", "SerialNumber", "Capacity",
         "Speed", "MemoryType", "FormFactor", "BankLabel", "DeviceLocator"],
    ),
    (
        "Win32_DiskDrive",
        "DiskDrive",
        ["Model", "Manufacturer", "SerialNumber", "InterfaceType",
         "MediaType", "Size", "FirmwareRevision", "PNPDeviceID"],
    ),
    (
        "Win32_NetworkAdapter",
        "NetworkAdapter",
        ["Name", "Manufacturer", "MACAddress", "AdapterType",
         "PNPDeviceID", "NetConnectionID", "Speed"],
    ),
    (
        "Win32_VideoController",
        "VideoController",
        ["Name", "AdapterCompatibility", "DriverVersion", "VideoProcessor",
         "AdapterRAM", "PNPDeviceID", "DriverDate"],
    ),
    (
        "Win32_Battery",
        "Battery",
        ["Name", "Manufacturer", "DeviceID", "DesignVoltage",
         "DesignCapacity", "FullChargeCapacity", "Chemistry"],
    ),
    (
        "Win32_DesktopMonitor",
        "Monitor",
        ["Name", "MonitorManufacturer", "MonitorType", "PNPDeviceID",
         "ScreenHeight", "ScreenWidth"],
    ),
    (
        "Win32_ComputerSystemProduct",
        "SystemProduct",
        ["Name", "Vendor", "Version", "IdentifyingNumber", "UUID"],
    ),
]

# PnP device categories identified by compatible ID or class GUID substrings
_PNP_CATEGORIES = {
    "USB": "USB\\\\",
    "Bluetooth": "BTH",
    "Camera": "Image",
    "AudioDevice": "MEDIA",
}

# TPM is queried from a different namespace
_TPM_NAMESPACE = "root\\cimv2\\Security\\MicrosoftTpm"
_TPM_CLASS = "Win32_Tpm"


def _safe_str(value: object) -> str:
    """Convert a value to string, handling None gracefully."""
    if value is None:
        return "Unknown"
    return str(value)


def _build_component(component_type: str, row: dict) -> HardwareComponent:
    """Build a HardwareComponent from a WMI result row."""
    manufacturer = (
        row.get("Manufacturer")
        or row.get("AdapterCompatibility")
        or row.get("MonitorManufacturer")
        or row.get("Vendor")
        or "Unknown"
    )
    model = (
        row.get("Name")
        or row.get("Product")
        or row.get("Model")
        or row.get("PartNumber")
        or "Unknown"
    )
    serial = (
        row.get("SerialNumber")
        or row.get("IdentifyingNumber")
        or row.get("DeviceID")
    )
    firmware = row.get("FirmwareRevision") or row.get("Version")
    driver = row.get("DriverVersion")
    pnp_id = row.get("PNPDeviceID") or row.get("PnpDeviceId") or row.get("DeviceID")

    # Collect all remaining properties
    props = {k: v for k, v in row.items() if v is not None}

    return HardwareComponent(
        component_type=component_type,
        manufacturer=_safe_str(manufacturer),
        model=_safe_str(model),
        serial_number=str(serial) if serial else None,
        firmware_version=str(firmware) if firmware else None,
        driver_version=str(driver) if driver else None,
        pnp_device_id=str(pnp_id) if pnp_id else None,
        properties=props,
    )


class HardwareInventoryCheck(BaseCheck):
    """Comprehensive hardware inventory via WMI queries."""

    CHECK_ID = "HW-001"
    NAME = "Hardware Inventory"
    DESCRIPTION = (
        "Full hardware fingerprint via WMI covering processors, memory, "
        "disks, network adapters, video controllers, batteries, monitors, "
        "USB/Bluetooth/camera/audio PnP devices, TPM, and system product info."
    )
    CATEGORY = Category.HARDWARE
    REQUIRES_ADMIN = False

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        all_components: list[HardwareComponent] = []

        # Query each standard WMI class
        for wmi_class, comp_type, props in _WMI_COMPONENT_MAP:
            rows = wmi_collector.query(wmi_class, properties=props)
            for row in rows:
                component = _build_component(comp_type, row)
                all_components.append(component)

        # Query PnP devices by category
        for label, prefix in _PNP_CATEGORIES.items():
            pnp_rows = wmi_collector.query(
                "Win32_PnPEntity",
                properties=["Name", "Manufacturer", "DeviceID",
                            "PNPDeviceID", "Description", "Service",
                            "ClassGuid", "CompatibleID"],
                where=f"PNPDeviceID LIKE '{prefix}%'",
            )
            for row in pnp_rows:
                component = _build_component(label, row)
                all_components.append(component)

        # Query TPM from security namespace
        tpm_rows = wmi_collector.query(
            _TPM_CLASS,
            properties=["IsActivated_InitialValue", "IsEnabled_InitialValue",
                         "IsOwned_InitialValue", "ManufacturerId",
                         "ManufacturerIdTxt", "ManufacturerVersion",
                         "ManufacturerVersionFull20", "PhysicalPresenceVersionInfo",
                         "SpecVersion"],
            namespace=_TPM_NAMESPACE,
        )
        for row in tpm_rows:
            comp = HardwareComponent(
                component_type="TPM",
                manufacturer=_safe_str(row.get("ManufacturerIdTxt")),
                model="Trusted Platform Module",
                serial_number=None,
                firmware_version=_safe_str(row.get("ManufacturerVersion")),
                properties={k: v for k, v in row.items() if v is not None},
            )
            all_components.append(comp)

        # Build per-component-type summary for the evidence
        type_counts: dict[str, int] = {}
        for comp in all_components:
            type_counts[comp.component_type] = type_counts.get(comp.component_type, 0) + 1

        # Build fingerprint dict from SystemProduct/Baseboard/TPM components
        fingerprint: dict = {}
        for comp in all_components:
            if comp.component_type == "SystemProduct":
                fingerprint["system_manufacturer"] = comp.properties.get("Vendor", comp.manufacturer)
                fingerprint["system_model"] = comp.properties.get("Name", comp.model)
                fingerprint["system_serial"] = comp.properties.get("IdentifyingNumber", comp.serial_number or "")
                fingerprint["system_uuid"] = comp.properties.get("UUID", "")
            elif comp.component_type == "Baseboard":
                fingerprint.setdefault("bios_vendor", comp.manufacturer)
                fingerprint.setdefault("bios_version", comp.firmware_version or "")

        # Ensure required fingerprint fields have defaults
        for key in ("hostname", "system_manufacturer", "system_model",
                     "system_serial", "system_uuid", "bios_version", "bios_vendor"):
            fingerprint.setdefault(key, "Unknown")

        # Set hostname from platform
        try:
            from vitia_invenire.platform import get_hostname
            fingerprint["hostname"] = get_hostname()
        except Exception:
            pass

        # Add TPM info if present
        for comp in all_components:
            if comp.component_type == "TPM":
                fingerprint["tpm_version"] = comp.properties.get("SpecVersion", "")
                fingerprint["tpm_manufacturer"] = comp.manufacturer

        self.context = {
            "fingerprint": fingerprint,
            "components": [comp.model_dump() for comp in all_components],
            "type_counts": dict(sorted(type_counts.items())),
        }

        summary_lines = [f"  {ctype}: {count}" for ctype, count in sorted(type_counts.items())]
        summary_text = "\n".join(summary_lines) if summary_lines else "  No components detected"

        # Serialize components list to JSON for evidence
        components_json = json.dumps(
            [comp.model_dump() for comp in all_components],
            indent=2,
            default=str,
        )

        findings.append(Finding(
            check_id=self.CHECK_ID,
            title="Hardware Inventory Collected",
            description=(
                f"Enumerated {len(all_components)} hardware components "
                f"across {len(type_counts)} categories."
            ),
            severity=Severity.INFO,
            category=self.CATEGORY,
            affected_item="All Hardware Components",
            evidence=f"Component summary:\n{summary_text}\n\nFull inventory:\n{components_json}",
            recommendation="Review hardware inventory for unexpected or unknown devices.",
            references=[
                "https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-processor",
                "https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-pnpentity",
            ],
        ))

        return findings
