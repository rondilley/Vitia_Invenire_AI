"""PCI-001: Enumerate all PCI devices and flag unknown vendor IDs.

Enumerates all PCI devices via Win32_PnPEntity with PCI\\ prefix.
Extracts VEN_ and DEV_ IDs from PNPDeviceID strings. Flags devices
with vendor IDs not in the hardcoded set of major known vendors as HIGH.
"""

from __future__ import annotations

import json
import re

from vitia_invenire.checks.base import BaseCheck
from vitia_invenire.collectors import wmi_collector
from vitia_invenire.models import Category, Finding, Severity

# Major known PCI vendor IDs (hex, uppercase) and their names
# Sources: https://pcisig.com/membership/member-companies,
#          https://pci-ids.ucw.cz/
_KNOWN_VENDORS: dict[str, str] = {
    "8086": "Intel Corporation",
    "1022": "Advanced Micro Devices (AMD)",
    "1002": "AMD/ATI Technologies",
    "10DE": "NVIDIA Corporation",
    "10EC": "Realtek Semiconductor",
    "14E4": "Broadcom Inc.",
    "168C": "Qualcomm Atheros",
    "1969": "Qualcomm Atheros (Attansic)",
    "17CB": "Qualcomm Technologies",
    "1AE0": "Google LLC",
    "8087": "Intel Corporation (Wireless)",
    "1B4B": "Marvell Technology Group",
    "1217": "O2 Micro International",
    "197B": "JMicron Technology",
    "104C": "Texas Instruments",
    "1180": "Ricoh Co., Ltd.",
    "1524": "ENE Technology Inc.",
    "11AB": "Marvell Semiconductor",
    "15AD": "VMware Inc.",
    "1AF4": "Red Hat / Virtio",
    "1AB8": "Parallels International",
    "1414": "Microsoft Corporation (Hyper-V)",
    "1D6B": "Linux Foundation (virtual)",
    "80EE": "Oracle VirtualBox",
    "5853": "XenSource / Citrix",
    "1B36": "QEMU Red Hat",
    "1013": "Cirrus Logic",
    "1039": "Silicon Integrated Systems (SiS)",
    "10B5": "PLX Technology / Broadcom",
    "10B7": "3Com Corporation",
    "1106": "VIA Technologies",
    "1166": "ServerWorks / Broadcom",
    "11C1": "Agere Systems / LSI",
    "1283": "Integrated Technology Express (ITE)",
    "12D8": "Pericom Semiconductor",
    "144D": "Samsung Electronics",
    "1462": "MSI (Micro-Star International)",
    "14C3": "MediaTek Inc.",
    "15B7": "Sandisk / Western Digital",
    "1C5C": "SK Hynix",
    "1C5F": "Beijing Memblaze Technology",
    "1CC1": "ADATA Technology",
    "1D97": "Shenzhen Longsys Electronics",
    "1E0F": "KIOXIA Corporation",
    "1344": "Micron Technology",
    "126F": "Silicon Motion Technology",
    "1179": "Toshiba Corporation",
    "1028": "Dell Inc.",
    "103C": "Hewlett-Packard",
    "17AA": "Lenovo",
    "1043": "ASUSTeK Computer",
    "1025": "Acer Incorporated",
    "19E5": "Huawei Technologies",
    "1D94": "Phison Electronics",
    "BEEF": "N/A (Testing placeholder VID)",
}

# Regex to extract VEN_ and DEV_ from PNPDeviceID like PCI\VEN_8086&DEV_A370&...
_PCI_ID_PATTERN = re.compile(
    r"VEN_([0-9A-Fa-f]{4})&DEV_([0-9A-Fa-f]{4})",
    re.IGNORECASE,
)


def _safe_str(value: object) -> str:
    if value is None:
        return "Unknown"
    return str(value)


class PciDeviceAuditCheck(BaseCheck):
    """Enumerate PCI devices and flag unknown vendor IDs."""

    CHECK_ID = "PCI-001"
    NAME = "PCI Device Audit"
    DESCRIPTION = (
        "Enumerate all PCI devices via Win32_PnPEntity. Extract vendor and "
        "device IDs. Flag devices with vendor IDs not in the known vendor list."
    )
    CATEGORY = Category.HARDWARE
    REQUIRES_ADMIN = False

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        all_devices: list[dict] = []
        unknown_vendor_devices: list[dict] = []

        # Query all PCI PnP entities
        rows = wmi_collector.query(
            "Win32_PnPEntity",
            properties=["Name", "PNPDeviceID", "Manufacturer",
                         "Description", "DeviceID", "Status",
                         "ClassGuid", "Service"],
            where="PNPDeviceID LIKE 'PCI\\\\%'",
        )

        for row in rows:
            pnp_id = _safe_str(row.get("PNPDeviceID") or row.get("DeviceID"))
            match = _PCI_ID_PATTERN.search(pnp_id)

            vendor_id = "Unknown"
            device_id = "Unknown"
            vendor_name = "Unknown"

            if match:
                vendor_id = match.group(1).upper()
                device_id = match.group(2).upper()
                vendor_name = _KNOWN_VENDORS.get(vendor_id, "Unknown Vendor")

            entry = {
                "name": _safe_str(row.get("Name")),
                "description": _safe_str(row.get("Description")),
                "manufacturer": _safe_str(row.get("Manufacturer")),
                "pnp_device_id": pnp_id,
                "vendor_id": vendor_id,
                "device_id": device_id,
                "vendor_name": vendor_name,
                "status": _safe_str(row.get("Status")),
                "service": _safe_str(row.get("Service")),
            }
            all_devices.append(entry)

            if vendor_name == "Unknown Vendor":
                unknown_vendor_devices.append(entry)

        # Informational finding with full PCI device inventory
        if all_devices:
            # Build summary by vendor
            vendor_counts: dict[str, int] = {}
            for dev in all_devices:
                vname = dev["vendor_name"]
                vendor_counts[vname] = vendor_counts.get(vname, 0) + 1

            summary_lines = [
                f"  {vname}: {count} device(s)"
                for vname, count in sorted(vendor_counts.items(), key=lambda x: -x[1])
            ]
            summary_text = "\n".join(summary_lines)

            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="PCI Device Inventory",
                description=f"Enumerated {len(all_devices)} PCI device(s) on the system.",
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="PCI Bus",
                evidence=f"Vendor summary:\n{summary_text}\n\nFull device list:\n{json.dumps(all_devices, indent=2)}",
                recommendation="Review PCI device inventory for unexpected hardware.",
                references=[
                    "https://pcisig.com/",
                    "https://pci-ids.ucw.cz/",
                ],
            ))

        # Flag unknown vendor devices
        if unknown_vendor_devices:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="PCI Devices With Unknown Vendor IDs",
                description=(
                    f"{len(unknown_vendor_devices)} PCI device(s) have vendor IDs not "
                    f"recognized as major hardware manufacturers. These could be "
                    f"legitimate niche hardware, or they could indicate rogue devices "
                    f"(hardware implants, debug tools, or malicious PCIe devices)."
                ),
                severity=Severity.HIGH,
                category=self.CATEGORY,
                affected_item="Unknown PCI Vendors",
                evidence=json.dumps(unknown_vendor_devices, indent=2),
                recommendation=(
                    "Investigate each unknown vendor ID against the PCI ID Database "
                    "(https://pci-ids.ucw.cz/). Physically inspect the system for "
                    "unauthorized PCIe/M.2/mPCIe devices if vendor cannot be identified. "
                    "Check for DMA attack devices such as PCILeech."
                ),
                references=[
                    "https://pci-ids.ucw.cz/",
                    "https://attack.mitre.org/techniques/T1200/",
                ],
            ))

        return findings
