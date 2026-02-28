"""IPV6-001: IPv6 Configuration Security Audit.

Checks IPv6 addresses, DHCPv6, and SLAAC configuration. Inspects
IPv6 transition mechanisms (Teredo, ISATAP, 6to4) that can be used
to tunnel traffic past IPv4-only security controls.
"""

from __future__ import annotations

from vitia_invenire.checks.base import BaseCheck
from vitia_invenire.collectors import registry
from vitia_invenire.collectors.powershell import run_ps
from vitia_invenire.models import Category, Finding, Severity

# Registry paths for transition mechanism configuration
_TEREDO_PATH = "SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters"
_ISATAP_PATH = "SYSTEM\\CurrentControlSet\\Services\\tcpip6\\Parameters\\Interfaces"
_IPV6_COMPONENTS_PATH = "SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters"


class IPv6AuditCheck(BaseCheck):
    """Audit IPv6 configuration and transition mechanisms."""

    CHECK_ID = "IPV6-001"
    NAME = "IPv6 Configuration Audit"
    DESCRIPTION = (
        "Checks IPv6 address configuration, DHCPv6, SLAAC, and "
        "IPv6 transition mechanisms (Teredo, ISATAP, 6to4) that may "
        "create unmonitored network paths."
    )
    CATEGORY = Category.NETWORK
    REQUIRES_ADMIN = False

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        # Get IPv6 addresses on active interfaces
        ipv6_result = run_ps(
            "Get-NetIPAddress -AddressFamily IPv6 -ErrorAction SilentlyContinue | "
            "Where-Object { $_.AddressState -eq 'Preferred' } | "
            "Select-Object InterfaceAlias, IPAddress, PrefixLength, "
            "AddressState, Type, SuffixOrigin, PrefixOrigin",
            timeout=15,
            as_json=True,
        )

        ipv6_addresses: list[dict] = []
        if ipv6_result.success and ipv6_result.json_output:
            data = ipv6_result.json_output
            if isinstance(data, dict):
                ipv6_addresses = [data]
            elif isinstance(data, list):
                ipv6_addresses = data

        # Categorize IPv6 addresses
        link_local: list[dict] = []
        global_addrs: list[dict] = []
        teredo_addrs: list[dict] = []
        isatap_addrs: list[dict] = []
        sixto4_addrs: list[dict] = []
        other_addrs: list[dict] = []

        for addr in ipv6_addresses:
            ip = str(addr.get("IPAddress", ""))
            iface = str(addr.get("InterfaceAlias", ""))
            ip_lower = ip.lower()

            if ip_lower.startswith("fe80:"):
                link_local.append(addr)
            elif ip_lower.startswith("2001:0:") or ip_lower.startswith("2001:0000:"):
                teredo_addrs.append(addr)
            elif "isatap" in iface.lower() or ip_lower.startswith("fe80::5efe:"):
                isatap_addrs.append(addr)
            elif ip_lower.startswith("2002:"):
                sixto4_addrs.append(addr)
            elif ip_lower.startswith("::1"):
                # Loopback, skip
                continue
            elif ip_lower.startswith("2") or ip_lower.startswith("3"):
                global_addrs.append(addr)
            else:
                other_addrs.append(addr)

        # Report Teredo addresses
        if teredo_addrs:
            evidence_lines = []
            for addr in teredo_addrs:
                evidence_lines.append(
                    f"  Interface: {addr.get('InterfaceAlias', 'Unknown')}\n"
                    f"  Address: {addr.get('IPAddress', 'Unknown')}\n"
                    f"  Prefix Origin: {addr.get('PrefixOrigin', 'Unknown')}"
                )
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Teredo IPv6 Tunnel Active",
                description=(
                    f"{len(teredo_addrs)} Teredo tunnel address(es) detected. "
                    f"Teredo encapsulates IPv6 traffic within UDP/IPv4, which "
                    f"can bypass IPv4 firewalls and security monitoring. This "
                    f"is commonly disabled in enterprise environments."
                ),
                severity=Severity.MEDIUM,
                category=self.CATEGORY,
                affected_item="Teredo Tunnel",
                evidence="\n".join(evidence_lines),
                recommendation=(
                    "Disable Teredo unless specifically required: "
                    "'netsh interface teredo set state disabled'. "
                    "Block UDP port 3544 at the firewall."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1572/",
                ],
            ))

        # Report ISATAP addresses
        if isatap_addrs:
            evidence_lines = []
            for addr in isatap_addrs:
                evidence_lines.append(
                    f"  Interface: {addr.get('InterfaceAlias', 'Unknown')}\n"
                    f"  Address: {addr.get('IPAddress', 'Unknown')}"
                )
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="ISATAP IPv6 Tunnel Active",
                description=(
                    f"{len(isatap_addrs)} ISATAP tunnel address(es) detected. "
                    f"ISATAP tunnels IPv6 over IPv4, potentially bypassing "
                    f"security controls designed for IPv4 only."
                ),
                severity=Severity.MEDIUM,
                category=self.CATEGORY,
                affected_item="ISATAP Tunnel",
                evidence="\n".join(evidence_lines),
                recommendation=(
                    "Disable ISATAP unless specifically required: "
                    "'netsh interface isatap set state disabled'."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1572/",
                ],
            ))

        # Report 6to4 addresses
        if sixto4_addrs:
            evidence_lines = []
            for addr in sixto4_addrs:
                evidence_lines.append(
                    f"  Interface: {addr.get('InterfaceAlias', 'Unknown')}\n"
                    f"  Address: {addr.get('IPAddress', 'Unknown')}"
                )
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="6to4 IPv6 Tunnel Active",
                description=(
                    f"{len(sixto4_addrs)} 6to4 tunnel address(es) detected. "
                    f"6to4 automatically tunnels IPv6 over IPv4 using protocol "
                    f"41, which may bypass firewall rules."
                ),
                severity=Severity.MEDIUM,
                category=self.CATEGORY,
                affected_item="6to4 Tunnel",
                evidence="\n".join(evidence_lines),
                recommendation=(
                    "Disable 6to4 unless specifically required: "
                    "'netsh interface 6to4 set state disabled'."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1572/",
                ],
            ))

        # Check Teredo registry state directly
        teredo_state_result = run_ps(
            "netsh interface teredo show state 2>&1",
            timeout=10,
            as_json=False,
        )
        if teredo_state_result.success and teredo_state_result.output:
            output_lower = teredo_state_result.output.lower()
            if "client" in output_lower or "enterpriseclient" in output_lower:
                if not teredo_addrs:
                    findings.append(Finding(
                        check_id=self.CHECK_ID,
                        title="Teredo Client Enabled",
                        description=(
                            "The Teredo client is enabled even though no active "
                            "Teredo addresses were found. The client may activate "
                            "when IPv6 connectivity is needed."
                        ),
                        severity=Severity.LOW,
                        category=self.CATEGORY,
                        affected_item="Teredo Configuration",
                        evidence=teredo_state_result.output[:500],
                        recommendation="Disable Teredo if not required for operations.",
                        references=[
                            "https://attack.mitre.org/techniques/T1572/",
                        ],
                    ))

        # Check DHCPv6 configuration
        dhcpv6_result = run_ps(
            "Get-NetIPInterface -AddressFamily IPv6 -ErrorAction SilentlyContinue | "
            "Where-Object { $_.ConnectionState -eq 'Connected' } | "
            "Select-Object InterfaceAlias, Dhcp, "
            "RouterDiscovery, AdvertiseDefaultRoute",
            timeout=15,
            as_json=True,
        )

        if dhcpv6_result.success and dhcpv6_result.json_output:
            dhcp_data = dhcpv6_result.json_output
            if isinstance(dhcp_data, dict):
                dhcp_data = [dhcp_data]

            dhcpv6_enabled_ifaces: list[str] = []
            for iface in dhcp_data:
                alias = str(iface.get("InterfaceAlias", "Unknown"))
                dhcp_state = str(iface.get("Dhcp", "")).lower()
                if dhcp_state in ("enabled", "true"):
                    dhcpv6_enabled_ifaces.append(alias)

            if dhcpv6_enabled_ifaces:
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title="DHCPv6 Enabled on Active Interfaces",
                    description=(
                        f"DHCPv6 is enabled on {len(dhcpv6_enabled_ifaces)} "
                        f"interface(s). DHCPv6 can be exploited for "
                        f"man-in-the-middle attacks using rogue DHCPv6 servers "
                        f"(mitm6-style attacks)."
                    ),
                    severity=Severity.LOW,
                    category=self.CATEGORY,
                    affected_item="DHCPv6 Configuration",
                    evidence=(
                        "Interfaces with DHCPv6 enabled:\n"
                        + "\n".join(f"  - {i}" for i in dhcpv6_enabled_ifaces)
                    ),
                    recommendation=(
                        "If IPv6 is not used on the network, disable DHCPv6 "
                        "or configure IPv6 via static addresses. Consider "
                        "deploying DHCPv6 Guard on network switches."
                    ),
                    references=[
                        "https://attack.mitre.org/techniques/T1557/003/",
                    ],
                ))

        # Check DisabledComponents registry value
        disabled_components = registry.read_value(
            registry.HKEY_LOCAL_MACHINE, _IPV6_COMPONENTS_PATH,
            "DisabledComponents",
        )

        ipv6_status = "Fully enabled (default)"
        if disabled_components is not None:
            val = disabled_components.data
            if val == 0xFF:
                ipv6_status = "IPv6 fully disabled (0xFF)"
            elif val == 0x20:
                ipv6_status = "IPv6 preferred over IPv4 disabled (0x20)"
            elif val == 0x10:
                ipv6_status = "IPv6 disabled on non-tunnel interfaces (0x10)"
            elif val == 0x01:
                ipv6_status = "IPv6 disabled on all tunnel interfaces (0x01)"
            elif val == 0x11:
                ipv6_status = "IPv6 disabled except loopback (0x11)"
            else:
                ipv6_status = f"Custom setting (0x{val:02X})"

        # IPv6 summary
        total_addrs = (
            len(link_local) + len(global_addrs) + len(teredo_addrs)
            + len(isatap_addrs) + len(sixto4_addrs) + len(other_addrs)
        )

        findings.append(Finding(
            check_id=self.CHECK_ID,
            title="IPv6 Configuration Summary",
            description=f"IPv6 audit found {total_addrs} address(es) across all interfaces.",
            severity=Severity.INFO,
            category=self.CATEGORY,
            affected_item="IPv6 Configuration",
            evidence=(
                f"IPv6 Status: {ipv6_status}\n"
                f"Global addresses: {len(global_addrs)}\n"
                f"Link-local addresses: {len(link_local)}\n"
                f"Teredo addresses: {len(teredo_addrs)}\n"
                f"ISATAP addresses: {len(isatap_addrs)}\n"
                f"6to4 addresses: {len(sixto4_addrs)}\n"
                f"Other addresses: {len(other_addrs)}"
            ),
            recommendation=(
                "If IPv6 is not used in the network environment, consider "
                "disabling transition mechanisms. Do not fully disable IPv6 "
                "unless required, as Windows components may depend on it."
            ),
            references=[
                "https://attack.mitre.org/techniques/T1572/",
            ],
        ))

        return findings
