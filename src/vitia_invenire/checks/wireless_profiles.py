"""WIFI-001: Wireless Network Profile Security Audit.

Enumerates WiFi profiles via netsh wlan show profiles and inspects
each profile for security configuration. Pre-configured networks on
new devices may indicate supply chain provisioning, and open
(no authentication) networks represent a security risk.
"""

from __future__ import annotations

import re

from vitia_invenire.checks.base import BaseCheck
from vitia_invenire.collectors.command import run_cmd
from vitia_invenire.models import Category, Finding, Severity


class WirelessProfilesCheck(BaseCheck):
    """Audit wireless network profiles for security risks."""

    CHECK_ID = "WIFI-001"
    NAME = "Wireless Profile Security Audit"
    DESCRIPTION = (
        "Enumerates WiFi profiles and inspects security settings. "
        "Flags open (unauthenticated) networks and pre-configured "
        "profiles on new devices."
    )
    CATEGORY = Category.NETWORK
    REQUIRES_ADMIN = False

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        # List all WiFi profiles
        list_result = run_cmd(
            ["netsh", "wlan", "show", "profiles"],
            timeout=15,
        )

        if not list_result.success:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Unable to Enumerate WiFi Profiles",
                description=(
                    "Failed to enumerate wireless profiles. The WLAN service "
                    "may not be available or no wireless adapter is present."
                ),
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="WiFi Profiles",
                evidence=f"Error: {list_result.stderr or 'netsh wlan show profiles failed'}",
                recommendation="No action required if wireless is not used.",
                references=[
                    "https://attack.mitre.org/techniques/T1557/",
                ],
            ))
            return findings

        # Parse profile names from output
        # Format: "    All User Profile     : ProfileName"
        profile_pattern = re.compile(
            r"(?:All User Profile|User Profile)\s*:\s*(.+)", re.IGNORECASE
        )
        profile_names: list[str] = []
        for line in list_result.stdout.splitlines():
            match = profile_pattern.search(line)
            if match:
                name = match.group(1).strip()
                if name:
                    profile_names.append(name)

        if not profile_names:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="No WiFi Profiles Found",
                description="No wireless network profiles are configured.",
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="WiFi Profiles",
                evidence="netsh wlan show profiles returned no profile entries.",
                recommendation="No action required.",
                references=[
                    "https://attack.mitre.org/techniques/T1557/",
                ],
            ))
            return findings

        # Get detailed info for each profile
        open_networks: list[dict[str, str]] = []
        weak_networks: list[dict[str, str]] = []
        all_profiles: list[dict[str, str]] = []

        for profile_name in profile_names:
            detail_result = run_cmd(
                ["netsh", "wlan", "show", "profile",
                 f"name={profile_name}", "key=clear"],
                timeout=10,
            )

            profile_info: dict[str, str] = {"name": profile_name}

            if detail_result.success and detail_result.stdout:
                output = detail_result.stdout

                # Extract authentication type
                auth_match = re.search(
                    r"Authentication\s*:\s*(.+)", output, re.IGNORECASE
                )
                if auth_match:
                    profile_info["authentication"] = auth_match.group(1).strip()

                # Extract cipher (encryption)
                cipher_match = re.search(
                    r"Cipher\s*:\s*(.+)", output, re.IGNORECASE
                )
                if cipher_match:
                    profile_info["cipher"] = cipher_match.group(1).strip()

                # Extract connection mode
                conn_match = re.search(
                    r"Connection mode\s*:\s*(.+)", output, re.IGNORECASE
                )
                if conn_match:
                    profile_info["connection_mode"] = conn_match.group(1).strip()

                # Extract SSID name
                ssid_match = re.search(
                    r"SSID name\s*:\s*\"?(.+?)\"?\s*$", output, re.MULTILINE | re.IGNORECASE
                )
                if ssid_match:
                    profile_info["ssid"] = ssid_match.group(1).strip().strip('"')

                # Extract network type
                net_type_match = re.search(
                    r"Network type\s*:\s*(.+)", output, re.IGNORECASE
                )
                if net_type_match:
                    profile_info["network_type"] = net_type_match.group(1).strip()

                # Extract security key presence
                key_match = re.search(
                    r"Security key\s*:\s*(.+)", output, re.IGNORECASE
                )
                if key_match:
                    profile_info["security_key"] = key_match.group(1).strip()

                # Check for open network (no authentication)
                auth_type = profile_info.get("authentication", "").lower()
                if auth_type in ("open", ""):
                    open_networks.append(profile_info)

                # Check for weak encryption
                if auth_type in ("wep", "shared"):
                    weak_networks.append(profile_info)

                # Check for WPA (not WPA2 or WPA3) which is also weak
                cipher_type = profile_info.get("cipher", "").lower()
                if auth_type == "wpapsk" and cipher_type == "tkip":
                    weak_networks.append(profile_info)

            all_profiles.append(profile_info)

        # Report open networks
        if open_networks:
            evidence_lines = []
            for net in open_networks:
                evidence_lines.append(
                    f"Profile: {net.get('name', 'Unknown')}\n"
                    f"  SSID: {net.get('ssid', 'Unknown')}\n"
                    f"  Authentication: {net.get('authentication', 'Open')}\n"
                    f"  Connection Mode: {net.get('connection_mode', 'Unknown')}"
                )
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Open (Unauthenticated) WiFi Networks Configured",
                description=(
                    f"{len(open_networks)} WiFi profile(s) are configured for "
                    f"open (unauthenticated) networks. Open networks provide "
                    f"no encryption or authentication, making all traffic "
                    f"visible to anyone in range and enabling easy "
                    f"man-in-the-middle attacks."
                ),
                severity=Severity.HIGH,
                category=self.CATEGORY,
                affected_item="WiFi Open Networks",
                evidence="\n\n".join(evidence_lines),
                recommendation=(
                    "Remove open WiFi profiles unless specifically required. "
                    "If connecting to open networks is necessary, always use "
                    "a VPN. Set profiles to not auto-connect: "
                    "'netsh wlan set profileparameter name=\"<profile>\" "
                    "connectionmode=manual'."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1557/",
                ],
            ))

        # Report weak encryption networks
        if weak_networks:
            evidence_lines = []
            for net in weak_networks:
                evidence_lines.append(
                    f"Profile: {net.get('name', 'Unknown')}\n"
                    f"  SSID: {net.get('ssid', 'Unknown')}\n"
                    f"  Authentication: {net.get('authentication', 'Unknown')}\n"
                    f"  Cipher: {net.get('cipher', 'Unknown')}"
                )
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="WiFi Profiles With Weak Encryption",
                description=(
                    f"{len(weak_networks)} WiFi profile(s) use weak or "
                    f"deprecated encryption (WEP, WPA-TKIP). These can be "
                    f"cracked in minutes to hours with widely available tools."
                ),
                severity=Severity.MEDIUM,
                category=self.CATEGORY,
                affected_item="WiFi Weak Encryption",
                evidence="\n\n".join(evidence_lines),
                recommendation=(
                    "Remove profiles using WEP or WPA-TKIP. Upgrade networks "
                    "to WPA2-AES or WPA3 where possible."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1557/",
                ],
            ))

        # Report on profile count (pre-configured networks on new device)
        if len(all_profiles) > 0:
            evidence_lines = []
            for prof in all_profiles:
                auth = prof.get("authentication", "Unknown")
                cipher = prof.get("cipher", "Unknown")
                mode = prof.get("connection_mode", "Unknown")
                evidence_lines.append(
                    f"  {prof['name']} - Auth: {auth}, "
                    f"Cipher: {cipher}, Mode: {mode}"
                )

            severity = Severity.INFO
            description = (
                f"Found {len(all_profiles)} WiFi profile(s) configured."
            )
            if len(all_profiles) > 10:
                severity = Severity.MEDIUM
                description += (
                    " A large number of pre-configured WiFi profiles on a "
                    "new device may indicate supply chain provisioning or "
                    "unauthorized configuration."
                )

            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="WiFi Profile Inventory",
                description=description,
                severity=severity,
                category=self.CATEGORY,
                affected_item="WiFi Profiles",
                evidence="\n".join(evidence_lines),
                recommendation="Review WiFi profiles and remove unnecessary ones.",
                references=[
                    "https://attack.mitre.org/techniques/T1557/",
                ],
            ))

        return findings
