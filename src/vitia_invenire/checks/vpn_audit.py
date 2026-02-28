"""VPN-001: VPN Configuration Security Audit.

Checks for built-in Windows VPN connections via Get-VpnConnection and
inspects for third-party VPN software in installed programs. Flags
pre-configured VPN connections to unknown servers and unauthorized
VPN client installations.
"""

from __future__ import annotations

import re

from vitia_invenire.checks.base import BaseCheck
from vitia_invenire.collectors.powershell import run_ps
from vitia_invenire.models import Category, Finding, Severity

# Known legitimate VPN providers for installed software checks
_KNOWN_VPN_SOFTWARE = [
    "cisco anyconnect",
    "cisco secure client",
    "globalprotect",
    "palo alto",
    "forticlient",
    "fortinet",
    "juniper pulse",
    "pulse secure",
    "ivanti secure access",
    "checkpoint endpoint",
    "zscaler",
    "netscaler",
    "citrix gateway",
    "openvpn",
    "wireguard",
    "tailscale",
    "cloudflare warp",
    "nordvpn",
    "expressvpn",
    "surfshark",
    "private internet access",
    "protonvpn",
    "mullvad",
    "windscribe",
    "cyberghost",
    "tunnelbear",
    "f5 access",
    "big-ip edge",
    "sonicwall",
    "barracuda",
    "aws vpn",
    "azure vpn",
    "google cloud vpn",
]

# Consumer VPN services that are unusual on enterprise machines
_CONSUMER_VPN_SOFTWARE = [
    "nordvpn",
    "expressvpn",
    "surfshark",
    "private internet access",
    "cyberghost",
    "tunnelbear",
    "windscribe",
    "hotspot shield",
    "hide.me",
    "ipvanish",
    "strongvpn",
    "torguard",
    "astrill",
]


class VPNAuditCheck(BaseCheck):
    """Audit VPN configuration and installed VPN software."""

    CHECK_ID = "VPN-001"
    NAME = "VPN Configuration Audit"
    DESCRIPTION = (
        "Checks Windows built-in VPN connections and scans for "
        "third-party VPN software. Flags pre-configured VPN connections "
        "to unknown servers and unauthorized VPN clients."
    )
    CATEGORY = Category.NETWORK
    REQUIRES_ADMIN = False

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        # Query built-in Windows VPN connections
        vpn_result = run_ps(
            "Get-VpnConnection -AllUserConnection -ErrorAction SilentlyContinue | "
            "Select-Object Name, ServerAddress, TunnelType, "
            "AuthenticationMethod, EncryptionLevel, SplitTunneling, "
            "ConnectionStatus, RememberCredential; "
            "Get-VpnConnection -ErrorAction SilentlyContinue | "
            "Select-Object Name, ServerAddress, TunnelType, "
            "AuthenticationMethod, EncryptionLevel, SplitTunneling, "
            "ConnectionStatus, RememberCredential",
            timeout=15,
            as_json=True,
        )

        vpn_connections: list[dict] = []
        if vpn_result.success and vpn_result.json_output:
            data = vpn_result.json_output
            if isinstance(data, dict):
                vpn_connections = [data]
            elif isinstance(data, list):
                vpn_connections = data

        if vpn_connections:
            # Deduplicate by name
            seen_names: set[str] = set()
            unique_vpns: list[dict] = []
            for vpn in vpn_connections:
                name = str(vpn.get("Name", ""))
                if name and name not in seen_names:
                    seen_names.add(name)
                    unique_vpns.append(vpn)

            evidence_lines = []
            suspicious_vpns: list[dict] = []

            for vpn in unique_vpns:
                name = str(vpn.get("Name", "Unknown"))
                server = str(vpn.get("ServerAddress", "Unknown"))
                tunnel = str(vpn.get("TunnelType", "Unknown"))
                auth = str(vpn.get("AuthenticationMethod", "Unknown"))
                enc = str(vpn.get("EncryptionLevel", "Unknown"))
                split = str(vpn.get("SplitTunneling", "Unknown"))
                status = str(vpn.get("ConnectionStatus", "Unknown"))
                remember = str(vpn.get("RememberCredential", "Unknown"))

                vpn_summary = (
                    f"VPN: {name}\n"
                    f"  Server: {server}\n"
                    f"  Tunnel Type: {tunnel}\n"
                    f"  Auth Method: {auth}\n"
                    f"  Encryption: {enc}\n"
                    f"  Split Tunnel: {split}\n"
                    f"  Status: {status}\n"
                    f"  Remember Credentials: {remember}"
                )
                evidence_lines.append(vpn_summary)

                # Check if server is an IP that could indicate suspicious VPN
                is_ip = re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", server)
                if is_ip:
                    suspicious_vpns.append(vpn)

            if suspicious_vpns:
                susp_lines = []
                for vpn in suspicious_vpns:
                    susp_lines.append(
                        f"VPN: {vpn.get('Name', 'Unknown')} -> "
                        f"{vpn.get('ServerAddress', 'Unknown')}"
                    )
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title="VPN Connection to IP Address Detected",
                    description=(
                        f"{len(suspicious_vpns)} VPN connection(s) are configured "
                        f"to connect to raw IP addresses instead of hostnames. "
                        f"This may indicate unauthorized or attacker-controlled "
                        f"VPN endpoints that bypass DNS-based monitoring."
                    ),
                    severity=Severity.HIGH,
                    category=self.CATEGORY,
                    affected_item="VPN Connections",
                    evidence="\n".join(susp_lines),
                    recommendation=(
                        "Verify each VPN connection endpoint. Remove any "
                        "unauthorized VPN configurations. VPN connections "
                        "should use FQDN hostnames for corporate endpoints."
                    ),
                    references=[
                        "https://attack.mitre.org/techniques/T1133/",
                    ],
                ))

            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Windows VPN Connections Inventory",
                description=(
                    f"Found {len(unique_vpns)} configured Windows VPN connection(s)."
                ),
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="VPN Connections",
                evidence="\n\n".join(evidence_lines),
                recommendation="Review all VPN connections for authorization.",
                references=[
                    "https://attack.mitre.org/techniques/T1133/",
                ],
            ))

        # Check for third-party VPN software in installed programs
        installed_result = run_ps(
            "Get-ItemProperty "
            "'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*', "
            "'HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*', "
            "'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*' "
            "-ErrorAction SilentlyContinue | "
            "Where-Object { $_.DisplayName -ne $null } | "
            "Select-Object DisplayName, DisplayVersion, Publisher, InstallDate",
            timeout=20,
            as_json=True,
        )

        if installed_result.success and installed_result.json_output:
            programs = installed_result.json_output
            if isinstance(programs, dict):
                programs = [programs]

            vpn_software_found: list[dict] = []
            consumer_vpn_found: list[dict] = []

            for prog in programs:
                display_name = str(prog.get("DisplayName", "")).lower()
                publisher = str(prog.get("Publisher", ""))

                # Check if it is VPN software
                is_vpn = (
                    "vpn" in display_name
                    or "tunnel" in display_name
                    or "wireguard" in display_name
                    or any(known in display_name for known in _KNOWN_VPN_SOFTWARE)
                )

                if is_vpn:
                    vpn_software_found.append(prog)

                    # Check if it is consumer VPN
                    if any(consumer in display_name for consumer in _CONSUMER_VPN_SOFTWARE):
                        consumer_vpn_found.append(prog)

            if consumer_vpn_found:
                evidence_lines = []
                for prog in consumer_vpn_found:
                    evidence_lines.append(
                        f"  {prog.get('DisplayName', 'Unknown')} "
                        f"v{prog.get('DisplayVersion', '?')} "
                        f"({prog.get('Publisher', 'Unknown')})"
                    )
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title="Consumer VPN Software Detected",
                    description=(
                        f"{len(consumer_vpn_found)} consumer VPN application(s) "
                        f"are installed. Consumer VPNs on enterprise machines "
                        f"can bypass corporate network monitoring and security "
                        f"controls, and may indicate policy violations or "
                        f"data exfiltration channels."
                    ),
                    severity=Severity.MEDIUM,
                    category=self.CATEGORY,
                    affected_item="Installed VPN Software",
                    evidence="\n".join(evidence_lines),
                    recommendation=(
                        "Verify consumer VPN software is authorized by "
                        "organizational policy. Remove unauthorized VPN "
                        "clients to prevent security control bypass."
                    ),
                    references=[
                        "https://attack.mitre.org/techniques/T1133/",
                    ],
                ))

            if vpn_software_found:
                evidence_lines = []
                for prog in vpn_software_found:
                    evidence_lines.append(
                        f"  {prog.get('DisplayName', 'Unknown')} "
                        f"v{prog.get('DisplayVersion', '?')} "
                        f"({prog.get('Publisher', 'Unknown')})"
                    )
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title="VPN Software Inventory",
                    description=(
                        f"Found {len(vpn_software_found)} VPN-related "
                        f"application(s) installed."
                    ),
                    severity=Severity.INFO,
                    category=self.CATEGORY,
                    affected_item="Installed VPN Software",
                    evidence="\n".join(evidence_lines),
                    recommendation="Review installed VPN software for authorization.",
                    references=[
                        "https://attack.mitre.org/techniques/T1133/",
                    ],
                ))

        return findings
