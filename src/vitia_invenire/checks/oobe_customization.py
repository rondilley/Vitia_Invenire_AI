"""OOBE-001: Check Unattend.xml for suspicious OOBE customizations.

Examines C:\\Windows\\Panther\\Unattend.xml and related locations
for RunSynchronousCommands and FirstLogonCommands. Non-Microsoft
binaries executed during OOBE are flagged as HIGH.
"""

from __future__ import annotations

import json
import os
import re
import xml.etree.ElementTree as ET
from pathlib import Path

from vitia_invenire.checks.base import BaseCheck
from vitia_invenire.models import Category, Finding, Severity

# Locations where Unattend.xml and related answer files may be found
_UNATTEND_LOCATIONS = [
    r"C:\Windows\Panther\Unattend.xml",
    r"C:\Windows\Panther\unattend.xml",
    r"C:\Windows\Panther\Unattend\Unattend.xml",
    r"C:\Windows\Panther\autounattend.xml",
    r"C:\Windows\System32\Sysprep\Unattend.xml",
    r"C:\Windows\System32\Sysprep\Panther\Unattend.xml",
]

# XML namespaces used in Unattend.xml
_UNATTEND_NS = {
    "u": "urn:schemas-microsoft-com:unattend",
    "wcm": "http://schemas.microsoft.com/WMIConfig/2002/State",
}

# Known Microsoft/Windows executables commonly seen in OOBE commands
_KNOWN_MICROSOFT_EXES = {
    "cmd.exe", "cmd", "powershell.exe", "powershell", "pwsh.exe", "pwsh",
    "cscript.exe", "cscript", "wscript.exe", "wscript",
    "msiexec.exe", "msiexec", "reg.exe", "reg",
    "net.exe", "net", "netsh.exe", "netsh",
    "schtasks.exe", "schtasks", "sc.exe", "sc",
    "bcdedit.exe", "bcdedit", "diskpart.exe", "diskpart",
    "dism.exe", "dism", "sfc.exe", "sfc",
    "regedit.exe", "regedit", "regsvr32.exe", "regsvr32",
    "rundll32.exe", "rundll32", "mshta.exe",
    "oobe.exe", "setupcomplete.cmd", "setupcomplete.bat",
    "w32tm.exe", "tzutil.exe", "systeminfo.exe",
    "compact.exe", "icacls.exe", "takeown.exe",
    "cleanmgr.exe", "defrag.exe",
    "explorer.exe", "taskkill.exe", "tasklist.exe",
}

# Suspicious command patterns
_SUSPICIOUS_PATTERNS = [
    (re.compile(r"invoke-webrequest|wget|curl|downloadfile|downloadstring|iwr\s", re.IGNORECASE),
     "Network download command"),
    (re.compile(r"bitsadmin.*transfer", re.IGNORECASE),
     "BITS file transfer"),
    (re.compile(r"-enc\s|encodedcommand|frombase64", re.IGNORECASE),
     "Encoded/obfuscated command"),
    (re.compile(r"new-service|sc\s+create", re.IGNORECASE),
     "Service creation during OOBE"),
    (re.compile(r"schtasks.*create|register-scheduledtask", re.IGNORECASE),
     "Scheduled task creation during OOBE"),
    (re.compile(r"add-mppreference.*exclusion", re.IGNORECASE),
     "Defender exclusion during OOBE"),
    (re.compile(r"set-mppreference.*disablerealtimemonitoring", re.IGNORECASE),
     "Disabling Defender during OOBE"),
    (re.compile(r"netsh\s+advfirewall\s+.*off", re.IGNORECASE),
     "Firewall disabled during OOBE"),
    (re.compile(r"net\s+user\s+.*\/add", re.IGNORECASE),
     "User account creation during OOBE"),
    (re.compile(r"certutil.*decode|certutil.*urlcache", re.IGNORECASE),
     "Certutil misuse (download/decode)"),
]


def _extract_command_from_text(text: str) -> str:
    """Extract the primary executable name from a command string."""
    text = text.strip()
    # Handle quoted paths
    if text.startswith('"'):
        end_quote = text.find('"', 1)
        if end_quote > 0:
            path = text[1:end_quote]
            return os.path.basename(path).lower()

    # Handle unquoted paths
    parts = text.split()
    if parts:
        return os.path.basename(parts[0]).lower()

    return text.lower()


def _is_non_microsoft_exe(command_text: str) -> tuple[bool, str]:
    """Determine if a command references a non-Microsoft executable."""
    exe_name = _extract_command_from_text(command_text)

    if exe_name in _KNOWN_MICROSOFT_EXES:
        return False, ""

    # Check if it is a Windows path to a Microsoft binary
    if "\\windows\\" in command_text.lower() and (
        "\\system32\\" in command_text.lower()
        or "\\syswow64\\" in command_text.lower()
    ):
        return False, ""

    # If the executable does not look like a known MS tool, flag it
    if exe_name and exe_name not in _KNOWN_MICROSOFT_EXES:
        return True, f"Non-Microsoft executable: {exe_name}"

    return False, ""


def _check_suspicious_patterns(command_text: str) -> list[str]:
    """Check a command string against suspicious patterns."""
    matches: list[str] = []
    for pattern, description in _SUSPICIOUS_PATTERNS:
        if pattern.search(command_text):
            matches.append(description)
    return matches


class OobeCustomizationCheck(BaseCheck):
    """Check Unattend.xml for suspicious OOBE customization commands."""

    CHECK_ID = "OOBE-001"
    NAME = "OOBE Customization Check"
    DESCRIPTION = (
        "Check Unattend.xml in C:\\Windows\\Panther\\ for "
        "RunSynchronousCommands and FirstLogonCommands. "
        "Non-Microsoft binaries referenced in OOBE = HIGH."
    )
    CATEGORY = Category.OEM_PREINSTALL
    REQUIRES_ADMIN = False

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        found_files: list[str] = []
        all_commands: list[dict] = []
        non_ms_commands: list[dict] = []
        suspicious_commands: list[dict] = []

        # Find all Unattend.xml files
        for location in _UNATTEND_LOCATIONS:
            if os.path.exists(location):
                found_files.append(location)

        if not found_files:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="No Unattend.xml Files Found",
                description=(
                    "No Unattend.xml or autounattend.xml files were found in "
                    "the standard Panther and Sysprep locations. This is normal "
                    "for retail installations without OEM customization."
                ),
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="Unattend.xml",
                evidence=f"Locations checked: {json.dumps(_UNATTEND_LOCATIONS)}",
                recommendation="No action needed.",
                references=[],
            ))
            return findings

        # Parse each Unattend.xml
        for xml_path in found_files:
            try:
                tree = ET.parse(xml_path)
                root = tree.getroot()
            except (ET.ParseError, OSError, PermissionError) as exc:
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title=f"Failed to Parse {os.path.basename(xml_path)}",
                    description=f"Could not parse {xml_path}: {exc}",
                    severity=Severity.LOW,
                    category=self.CATEGORY,
                    affected_item=xml_path,
                    evidence=str(exc),
                    recommendation="Manually inspect the file.",
                    references=[],
                ))
                continue

            # Extract commands from various sections
            commands = self._extract_commands(root, xml_path)
            all_commands.extend(commands)

            for cmd_info in commands:
                command_text = cmd_info.get("command", "")

                # Check for non-Microsoft executables
                is_non_ms, reason = _is_non_microsoft_exe(command_text)
                if is_non_ms:
                    cmd_info["reason"] = reason
                    non_ms_commands.append(cmd_info)

                # Check for suspicious patterns
                patterns = _check_suspicious_patterns(command_text)
                if patterns:
                    cmd_info["suspicious_patterns"] = patterns
                    suspicious_commands.append(cmd_info)

        # Report findings
        if all_commands:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="OOBE Customization Commands Found",
                description=(
                    f"Found {len(all_commands)} command(s) in {len(found_files)} "
                    f"Unattend.xml file(s). These commands execute during Windows "
                    f"setup or first logon."
                ),
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="Unattend.xml",
                evidence=json.dumps(all_commands, indent=2),
                recommendation="Review all OOBE commands for legitimacy.",
                references=[
                    "https://learn.microsoft.com/en-us/windows-hardware/customize/desktop/unattend/",
                ],
            ))

        if non_ms_commands:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Non-Microsoft Executables in OOBE Commands",
                description=(
                    f"{len(non_ms_commands)} OOBE command(s) reference executables "
                    f"that are not standard Microsoft/Windows tools. These may be "
                    f"OEM provisioning agents, bloatware installers, or potentially "
                    f"malicious implants inserted into the deployment image."
                ),
                severity=Severity.HIGH,
                category=self.CATEGORY,
                affected_item="OOBE Commands",
                evidence=json.dumps(non_ms_commands, indent=2),
                recommendation=(
                    "Investigate each non-Microsoft executable referenced in OOBE "
                    "commands. Verify they are legitimate OEM tools. Unknown "
                    "executables in Unattend.xml may indicate supply-chain "
                    "compromise of the deployment image."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1059/",
                    "https://learn.microsoft.com/en-us/windows-hardware/customize/desktop/unattend/",
                ],
            ))

        if suspicious_commands:
            # Deduplicate with non_ms_commands
            already_reported = {c.get("command", "") for c in non_ms_commands}
            new_suspicious = [
                c for c in suspicious_commands
                if c.get("command", "") not in already_reported
            ]
            if new_suspicious:
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title="Suspicious OOBE Command Patterns Detected",
                    description=(
                        f"{len(new_suspicious)} OOBE command(s) match suspicious "
                        f"patterns such as network downloads, encoded commands, "
                        f"or security feature modifications."
                    ),
                    severity=Severity.HIGH,
                    category=self.CATEGORY,
                    affected_item="OOBE Commands",
                    evidence=json.dumps(new_suspicious, indent=2),
                    recommendation=(
                        "Investigate suspicious OOBE commands. Commands that download "
                        "files, create services, or disable security features during "
                        "OOBE are common in supply-chain attacks."
                    ),
                    references=[
                        "https://attack.mitre.org/techniques/T1195/002/",
                    ],
                ))

        return findings

    def _extract_commands(self, root: ET.Element, xml_path: str) -> list[dict]:
        """Extract RunSynchronousCommand and FirstLogonCommands from XML."""
        commands: list[dict] = []

        # Handle both namespaced and non-namespaced XML
        # Try with namespace first
        for ns_prefix, ns_uri in [("u:", "urn:schemas-microsoft-com:unattend"), ("", "")]:
            if ns_uri:
                ns_map = {"u": ns_uri}
            else:
                ns_map = {}

            # RunSynchronousCommand entries
            for elem in root.iter():
                tag = elem.tag
                # Strip namespace for comparison
                local_tag = tag.split("}")[-1] if "}" in tag else tag

                if local_tag == "RunSynchronousCommand":
                    order = elem.get("{http://schemas.microsoft.com/WMIConfig/2002/State}action", "")
                    path_elem = elem.find(
                        f"{{{ns_uri}}}Path" if ns_uri else "Path"
                    )
                    desc_elem = elem.find(
                        f"{{{ns_uri}}}Description" if ns_uri else "Description"
                    )
                    order_elem = elem.find(
                        f"{{{ns_uri}}}Order" if ns_uri else "Order"
                    )

                    command_text = ""
                    if path_elem is not None and path_elem.text:
                        command_text = path_elem.text.strip()

                    commands.append({
                        "source_file": xml_path,
                        "type": "RunSynchronousCommand",
                        "command": command_text,
                        "description": desc_elem.text.strip() if desc_elem is not None and desc_elem.text else "",
                        "order": order_elem.text.strip() if order_elem is not None and order_elem.text else "",
                    })

                elif local_tag in ("SynchronousCommand", "AsynchronousCommand"):
                    # FirstLogonCommands and LogonCommands contain SynchronousCommand
                    parent = self._find_parent_tag(root, elem)
                    cmd_line_elem = elem.find(
                        f"{{{ns_uri}}}CommandLine" if ns_uri else "CommandLine"
                    )
                    desc_elem = elem.find(
                        f"{{{ns_uri}}}Description" if ns_uri else "Description"
                    )
                    order_elem = elem.find(
                        f"{{{ns_uri}}}Order" if ns_uri else "Order"
                    )

                    command_text = ""
                    if cmd_line_elem is not None and cmd_line_elem.text:
                        command_text = cmd_line_elem.text.strip()

                    commands.append({
                        "source_file": xml_path,
                        "type": f"{parent}/{local_tag}",
                        "command": command_text,
                        "description": desc_elem.text.strip() if desc_elem is not None and desc_elem.text else "",
                        "order": order_elem.text.strip() if order_elem is not None and order_elem.text else "",
                    })

        # Deduplicate commands (namespace iterations may find same elements)
        seen: set[str] = set()
        unique_commands: list[dict] = []
        for cmd in commands:
            key = f"{cmd['type']}:{cmd['command']}:{cmd['order']}"
            if key not in seen and cmd["command"]:
                seen.add(key)
                unique_commands.append(cmd)

        return unique_commands

    def _find_parent_tag(self, root: ET.Element, target: ET.Element) -> str:
        """Find the parent element tag name for a given element."""
        for parent in root.iter():
            for child in parent:
                if child is target:
                    tag = parent.tag
                    return tag.split("}")[-1] if "}" in tag else tag
        return "Unknown"
