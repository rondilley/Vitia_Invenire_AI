"""SOFT-001: Installed software inventory and risk analysis.

Enumerates installed software from the Uninstall registry keys
(HKLM, HKCU, and WOW6432Node). Flags known remote access tools
and reports the full software manifest.
"""

from __future__ import annotations

import re

from vitia_invenire.checks.base import BaseCheck
from vitia_invenire.collectors import registry
from vitia_invenire.models import Category, Finding, Severity

# Registry paths for installed software
_UNINSTALL_PATHS: list[tuple[int, str, bool]] = [
    (registry.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", False),
    (registry.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall", False),
    (registry.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", False),
]

# Known remote access tools with their detection patterns and descriptions
_REMOTE_ACCESS_TOOLS: list[tuple[str, str, str]] = [
    ("TeamViewer", "teamviewer", "Commercial remote access tool frequently abused for unauthorized access"),
    ("AnyDesk", "anydesk", "Remote desktop tool commonly used in social engineering attacks"),
    ("VNC", "vnc|realvnc|tightvnc|ultravnc|tigervnc", "Virtual Network Computing remote access"),
    ("LogMeIn", "logmein", "Cloud-based remote access and management"),
    ("ConnectWise", "connectwise|screenconnect", "Remote support and management tool"),
    ("Splashtop", "splashtop", "Remote access tool"),
    ("RemotePC", "remotepc", "Remote access application"),
    ("GoToMyPC", "gotomypc|gotoassist", "Citrix remote access tool"),
    ("DameWare", "dameware", "SolarWinds remote administration tool"),
    ("Radmin", "radmin", "Remote administrator tool"),
    ("NetSupport", "netsupport", "Remote control software often abused by threat actors"),
    ("Ammyy Admin", "ammyy", "Remote access tool frequently used in scam operations"),
    ("RustDesk", "rustdesk", "Open source remote desktop tool"),
    ("Supremo", "supremo", "Remote control application"),
    ("Chrome Remote Desktop", "chrome remote desktop|chromoting", "Google Chrome-based remote access"),
    ("MeshCentral", "meshcentral|meshagent", "Open source remote management server"),
    ("Action1", "action1", "Remote monitoring and management tool"),
    ("Atera", "atera", "Remote monitoring and management platform"),
    ("SimpleHelp", "simplehelp", "Remote support tool"),
    ("Bomgar", "bomgar|beyondtrust", "Privileged remote access tool"),
]


class SoftwareInventoryCheck(BaseCheck):
    """Enumerate installed software and flag remote access tools."""

    CHECK_ID = "SOFT-001"
    NAME = "Software Inventory Analysis"
    DESCRIPTION = (
        "Enumerates installed software from Uninstall registry keys "
        "(HKLM, HKCU, WOW6432Node) and flags known remote access tools "
        "that may represent unauthorized access channels."
    )
    CATEGORY = Category.CONFIGURATION
    REQUIRES_ADMIN = False

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        all_software: list[dict[str, str]] = []
        remote_access_found: list[tuple[str, str, dict[str, str]]] = []

        for hive, path, wow64 in _UNINSTALL_PATHS:
            subkeys = registry.enumerate_subkeys(hive, path, wow64_32=wow64)

            for subkey in subkeys:
                full_path = f"{path}\\{subkey}"
                values = registry.read_key(hive, full_path, wow64_32=wow64)

                sw_info: dict[str, str] = {"_subkey": subkey}
                for val in values:
                    if val.name in ("DisplayName", "DisplayVersion", "Publisher",
                                    "InstallLocation", "InstallDate", "UninstallString",
                                    "URLInfoAbout", "InstallSource"):
                        sw_info[val.name] = str(val.data) if val.data is not None else ""

                display_name = sw_info.get("DisplayName", "")
                if not display_name:
                    continue

                all_software.append(sw_info)

                # Check against remote access tool patterns
                name_lower = display_name.lower()
                publisher_lower = sw_info.get("Publisher", "").lower()
                combined = f"{name_lower} {publisher_lower}"

                for tool_name, pattern, tool_desc in _REMOTE_ACCESS_TOOLS:
                    if re.search(pattern, combined, re.IGNORECASE):
                        remote_access_found.append((tool_name, tool_desc, sw_info))
                        break

        # Report remote access tools
        for tool_name, tool_desc, sw_info in remote_access_found:
            display_name = sw_info.get("DisplayName", "Unknown")
            version = sw_info.get("DisplayVersion", "Unknown")
            publisher = sw_info.get("Publisher", "Unknown")
            install_loc = sw_info.get("InstallLocation", "Unknown")
            install_date = sw_info.get("InstallDate", "Unknown")

            findings.append(Finding(
                check_id=self.CHECK_ID,
                title=f"Remote access tool detected: {display_name}",
                description=(
                    f"Remote access software '{display_name}' ({tool_name}) is installed. "
                    f"{tool_desc}. Remote access tools can be used to maintain persistent "
                    "unauthorized access to the system."
                ),
                severity=Severity.HIGH,
                category=self.CATEGORY,
                affected_item=display_name,
                evidence=(
                    f"Software: {display_name}\n"
                    f"Version: {version}\n"
                    f"Publisher: {publisher}\n"
                    f"Install Location: {install_loc}\n"
                    f"Install Date: {install_date}\n"
                    f"Tool Category: {tool_name}"
                ),
                recommendation=(
                    f"Verify that '{display_name}' is authorized for use on this system. "
                    "If not authorized, uninstall immediately and investigate how it was installed."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1219/",
                ],
            ))

        # Build software manifest
        manifest_lines: list[str] = []
        for sw in sorted(all_software, key=lambda s: s.get("DisplayName", "").lower()):
            name = sw.get("DisplayName", "Unknown")
            version = sw.get("DisplayVersion", "")
            publisher = sw.get("Publisher", "")
            line = f"  {name}"
            if version:
                line += f" v{version}"
            if publisher:
                line += f" ({publisher})"
            manifest_lines.append(line)

        manifest_text = "\n".join(manifest_lines) if manifest_lines else "  No software found"

        findings.append(Finding(
            check_id=self.CHECK_ID,
            title="Installed software inventory",
            description=(
                f"Enumerated {len(all_software)} installed software packages. "
                f"Found {len(remote_access_found)} remote access tool(s)."
            ),
            severity=Severity.INFO,
            category=self.CATEGORY,
            affected_item="Software Inventory",
            evidence=f"Software manifest ({len(all_software)} items):\n{manifest_text}",
            recommendation="Review installed software periodically and remove unauthorized applications.",
        ))

        return findings
