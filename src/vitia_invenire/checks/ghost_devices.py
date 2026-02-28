"""GHOST-001: Detect ghost (previously connected) USB and PCI devices.

Enumerates USB and PCI device history from HKLM\\SYSTEM\\CurrentControlSet\\Enum.
Cross-references against currently connected devices. Flags disconnected devices,
especially known debug/attack tool VID/PIDs, as CRITICAL.
"""

from __future__ import annotations

import json
import re

from vitia_invenire.checks.base import BaseCheck
from vitia_invenire.collectors import registry, wmi_collector
from vitia_invenire.models import Category, Finding, Severity

# Known attack/debug tool USB VID:PID combinations
# Format: (VID, PID_or_None, tool_name, description)
_KNOWN_ATTACK_DEVICES: list[tuple[str, str | None, str, str]] = [
    ("0403", "6001", "FTDI FT232R", "Common USB-to-serial adapter used in debug/attack tools"),
    ("0403", "6010", "FTDI FT2232", "Dual USB-to-serial, used in JTAG debuggers"),
    ("0403", "6011", "FTDI FT4232", "Quad USB-to-serial, used in debug interfaces"),
    ("0403", "6014", "FTDI FT232H", "Multi-purpose USB-to-serial/SPI/I2C/JTAG"),
    ("0403", "6015", "FTDI FT-X Series", "USB-to-serial used in various debug tools"),
    ("1D50", None, "OpenMoko/Hak5", "Vendor ID used by Hak5 devices and open-source hardware"),
    ("1D50", "6089", "Great Scott Gadgets", "HackRF One SDR"),
    ("1D50", "60FC", "OpenVizsla", "USB protocol analyzer"),
    ("1FC9", "0083", "NXP LPC-Link2", "Debug probe for NXP microcontrollers"),
    ("2B3E", "ACE0", "Hak5 USB Rubber Ducky", "Keystroke injection attack tool"),
    ("2B3E", "C001", "Hak5 Bash Bunny", "Multi-function USB attack platform"),
    ("2B3E", "1337", "Hak5 Packet Squirrel", "Network implant tool"),
    ("2B3E", "ACE1", "Hak5 Key Croc", "Keylogger and keystroke injection tool"),
    ("2B3E", "ACE2", "Hak5 Screen Crab", "Screen capture implant"),
    ("2B3E", "ACE3", "Hak5 Shark Jack", "Network attack tool"),
    ("DEAD", "BEEF", "Facedancer", "USB emulation/attack framework"),
    ("1D6B", "0104", "BadUSB/Rubber Ducky clone", "Generic HID attack device"),
    ("16C0", "05DC", "V-USB", "Open-source USB for microcontrollers (common in DIY attack tools)"),
    ("16C0", "27DB", "Teensy HID", "Teensy USB development board (HID attack capable)"),
    ("16C0", "27DC", "Teensy MIDI", "Teensy USB development board"),
    ("16C0", "0486", "Teensy Rawhid", "Teensy raw HID mode"),
    ("2341", None, "Arduino", "Arduino boards (potential attack tool platform)"),
    ("1A86", "7523", "CH340 USB-Serial", "Common cheap USB-to-serial used in debug tools"),
    ("067B", "2303", "Prolific PL2303", "USB-to-serial adapter used in debug/attack tools"),
    ("10C4", "EA60", "Silicon Labs CP210x", "USB-to-serial used in embedded debug tools"),
    ("0FCE", None, "Sony Xperia", "USB debugging (ADB capable)"),
    ("04E8", "6860", "Samsung ADB", "Samsung Android Debug Bridge"),
    ("18D1", "4EE7", "Google Nexus ADB", "Google Android Debug Bridge"),
    ("2C97", None, "Ledger", "Hardware wallet (sensitive crypto device)"),
    ("1050", None, "Yubico YubiKey", "Hardware security key"),
    ("20A0", "4108", "Nitrokey", "Open-source hardware security key"),
    ("04D8", "003F", "Microchip PIC", "Microchip PIC USB device (debug)"),
    ("1366", None, "SEGGER J-Link", "JTAG/SWD debug probe"),
    ("C251", None, "Keil ULINK", "ARM debug probe"),
    ("0D28", "0204", "ARM CMSIS-DAP", "ARM debug access port"),
]

# Build lookup sets for quick matching
_ATTACK_VID_ONLY: set[str] = set()
_ATTACK_VID_PID: set[tuple[str, str]] = set()
_ATTACK_DEVICE_INFO: dict[str, str] = {}

for _vid, _pid, _name, _desc in _KNOWN_ATTACK_DEVICES:
    vid_upper = _vid.upper()
    if _pid is None:
        _ATTACK_VID_ONLY.add(vid_upper)
        _ATTACK_DEVICE_INFO[vid_upper] = f"{_name}: {_desc}"
    else:
        pid_upper = _pid.upper()
        _ATTACK_VID_PID.add((vid_upper, pid_upper))
        _ATTACK_DEVICE_INFO[f"{vid_upper}:{pid_upper}"] = f"{_name}: {_desc}"

# Regex to extract VID and PID from USB device instance IDs
# Format: USB\VID_XXXX&PID_XXXX\...  or  VID_XXXX&PID_XXXX
_USB_VID_PID_PATTERN = re.compile(
    r"VID_([0-9A-Fa-f]{4})&PID_([0-9A-Fa-f]{4})",
    re.IGNORECASE,
)


def _safe_str(value: object) -> str:
    if value is None:
        return "Unknown"
    return str(value)


def _is_attack_device(vid: str, pid: str) -> tuple[bool, str]:
    """Check if a VID:PID matches a known attack/debug device."""
    vid_upper = vid.upper()
    pid_upper = pid.upper()

    # Check exact VID:PID match first
    key = f"{vid_upper}:{pid_upper}"
    if (vid_upper, pid_upper) in _ATTACK_VID_PID:
        return True, _ATTACK_DEVICE_INFO.get(key, "Known attack/debug device")

    # Check VID-only match (all PIDs from this vendor are suspicious)
    if vid_upper in _ATTACK_VID_ONLY:
        return True, _ATTACK_DEVICE_INFO.get(vid_upper, "Known attack/debug vendor")

    return False, ""


class GhostDevicesCheck(BaseCheck):
    """Detect ghost (previously connected but now disconnected) devices."""

    CHECK_ID = "GHOST-001"
    NAME = "Ghost Device Detection"
    DESCRIPTION = (
        "Enumerate USB and PCI device history from registry. Cross-reference "
        "against currently connected devices. Flag disconnected devices, "
        "especially known debug/attack tool VID/PIDs."
    )
    CATEGORY = Category.HARDWARE
    REQUIRES_ADMIN = False

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        # Get currently connected PnP devices
        connected_device_ids: set[str] = set()
        connected_rows = wmi_collector.query(
            "Win32_PnPEntity",
            properties=["PNPDeviceID", "Status"],
        )
        for row in connected_rows:
            dev_id = row.get("PNPDeviceID")
            if dev_id:
                connected_device_ids.add(str(dev_id).upper())

        # Enumerate USB device history from registry
        usb_ghost_devices: list[dict] = []
        usb_attack_devices: list[dict] = []

        usb_subkeys = registry.enumerate_subkeys(
            registry.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Enum\USB",
        )

        for usb_dev in usb_subkeys:
            match = _USB_VID_PID_PATTERN.search(usb_dev)
            vid = ""
            pid = ""
            if match:
                vid = match.group(1).upper()
                pid = match.group(2).upper()

            # Enumerate serial number / instance subkeys
            instance_subkeys = registry.enumerate_subkeys(
                registry.HKEY_LOCAL_MACHINE,
                rf"SYSTEM\CurrentControlSet\Enum\USB\{usb_dev}",
            )

            for instance in instance_subkeys:
                full_id = f"USB\\{usb_dev}\\{instance}".upper()
                is_connected = full_id in connected_device_ids

                # Read device description from registry
                reg_path = rf"SYSTEM\CurrentControlSet\Enum\USB\{usb_dev}\{instance}"
                desc_val = registry.read_value(
                    registry.HKEY_LOCAL_MACHINE, reg_path, "DeviceDesc",
                )
                friendly_val = registry.read_value(
                    registry.HKEY_LOCAL_MACHINE, reg_path, "FriendlyName",
                )
                mfg_val = registry.read_value(
                    registry.HKEY_LOCAL_MACHINE, reg_path, "Mfg",
                )
                class_val = registry.read_value(
                    registry.HKEY_LOCAL_MACHINE, reg_path, "Class",
                )
                service_val = registry.read_value(
                    registry.HKEY_LOCAL_MACHINE, reg_path, "Service",
                )

                device_desc = ""
                if desc_val and desc_val.data:
                    # Device descriptions may have format: @provider.inf,%section%;Description
                    raw_desc = str(desc_val.data)
                    if ";" in raw_desc:
                        device_desc = raw_desc.split(";")[-1]
                    else:
                        device_desc = raw_desc

                entry = {
                    "device_id": full_id,
                    "vid": vid,
                    "pid": pid,
                    "instance": instance,
                    "description": device_desc or _safe_str(friendly_val.data if friendly_val else None),
                    "manufacturer": _safe_str(mfg_val.data if mfg_val else None),
                    "class": _safe_str(class_val.data if class_val else None),
                    "service": _safe_str(service_val.data if service_val else None),
                    "currently_connected": is_connected,
                }

                if not is_connected:
                    usb_ghost_devices.append(entry)

                    # Check if this is a known attack device
                    if vid and pid:
                        is_attack, attack_info = _is_attack_device(vid, pid)
                        if is_attack:
                            entry["attack_tool_info"] = attack_info
                            usb_attack_devices.append(entry)

        # Enumerate PCI device history from registry
        pci_ghost_devices: list[dict] = []

        pci_subkeys = registry.enumerate_subkeys(
            registry.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Enum\PCI",
        )

        for pci_dev in pci_subkeys:
            instance_subkeys = registry.enumerate_subkeys(
                registry.HKEY_LOCAL_MACHINE,
                rf"SYSTEM\CurrentControlSet\Enum\PCI\{pci_dev}",
            )

            for instance in instance_subkeys:
                full_id = f"PCI\\{pci_dev}\\{instance}".upper()
                is_connected = full_id in connected_device_ids

                if not is_connected:
                    reg_path = rf"SYSTEM\CurrentControlSet\Enum\PCI\{pci_dev}\{instance}"
                    desc_val = registry.read_value(
                        registry.HKEY_LOCAL_MACHINE, reg_path, "DeviceDesc",
                    )
                    friendly_val = registry.read_value(
                        registry.HKEY_LOCAL_MACHINE, reg_path, "FriendlyName",
                    )

                    device_desc = ""
                    if desc_val and desc_val.data:
                        raw_desc = str(desc_val.data)
                        if ";" in raw_desc:
                            device_desc = raw_desc.split(";")[-1]
                        else:
                            device_desc = raw_desc

                    pci_ghost_devices.append({
                        "device_id": full_id,
                        "instance": instance,
                        "description": device_desc or _safe_str(
                            friendly_val.data if friendly_val else None
                        ),
                        "currently_connected": False,
                    })

        # Report attack tool ghost devices as CRITICAL
        if usb_attack_devices:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Known Attack/Debug Tool USB Device Previously Connected",
                description=(
                    f"{len(usb_attack_devices)} previously connected USB device(s) "
                    f"match known attack or debug tool VID/PID combinations. "
                    f"These devices may have been used for keystroke injection, "
                    f"network sniffing, JTAG debugging, or other attack techniques."
                ),
                severity=Severity.CRITICAL,
                category=self.CATEGORY,
                affected_item="USB Device History",
                evidence=json.dumps(usb_attack_devices, indent=2),
                recommendation=(
                    "Investigate when and by whom these devices were connected. "
                    "Check for signs of compromise such as unauthorized scripts, "
                    "keylogger artifacts, or network configuration changes. "
                    "Consider forensic imaging if a Hak5 or similar attack tool "
                    "was detected."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1200/",
                    "https://attack.mitre.org/techniques/T1091/",
                ],
            ))

        # Report general ghost USB devices
        if usb_ghost_devices:
            # Filter out attack devices already reported
            attack_ids = {d["device_id"] for d in usb_attack_devices}
            non_attack_ghosts = [
                d for d in usb_ghost_devices if d["device_id"] not in attack_ids
            ]

            if non_attack_ghosts:
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title="Ghost USB Devices Detected",
                    description=(
                        f"{len(non_attack_ghosts)} previously connected USB device(s) "
                        f"were found in the registry but are no longer connected. "
                        f"These represent the USB device connection history."
                    ),
                    severity=Severity.INFO,
                    category=self.CATEGORY,
                    affected_item="USB Device History",
                    evidence=json.dumps(non_attack_ghosts, indent=2, default=str),
                    recommendation=(
                        "Review the USB device connection history for unexpected "
                        "devices. Unknown or unauthorized USB devices may indicate "
                        "data exfiltration or attack tool usage."
                    ),
                    references=[
                        "https://attack.mitre.org/techniques/T1200/",
                    ],
                ))

        # Report ghost PCI devices
        if pci_ghost_devices:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Ghost PCI Devices Detected",
                description=(
                    f"{len(pci_ghost_devices)} previously installed PCI device(s) "
                    f"were found in the registry but are no longer present. "
                    f"This may indicate hardware swaps, removed expansion cards, "
                    f"or previously inserted attack devices."
                ),
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="PCI Device History",
                evidence=json.dumps(pci_ghost_devices, indent=2, default=str),
                recommendation=(
                    "Review PCI device history for unexpected devices, especially "
                    "unknown vendor IDs that could indicate DMA attack hardware."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1200/",
                ],
            ))

        # Summary if no ghost devices found
        if not usb_ghost_devices and not pci_ghost_devices:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="No Ghost Devices Detected",
                description=(
                    "No disconnected USB or PCI devices were found in the "
                    "device registry history, or all historically registered "
                    "devices are currently connected."
                ),
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="Device History",
                evidence=(
                    f"Connected devices: {len(connected_device_ids)}, "
                    f"USB registry entries checked: {len(usb_subkeys)}, "
                    f"PCI registry entries checked: {len(pci_subkeys)}"
                ),
                recommendation="No action required.",
                references=[],
            ))

        return findings
