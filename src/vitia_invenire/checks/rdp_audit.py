"""RDP-001: Remote Desktop Protocol Security Audit.

Checks RDP configuration including the fDenyTSConnections registry value,
Network Level Authentication (NLA) enforcement, and RDP connection
history. RDP enabled on a workstation without NLA is a significant
security risk.
"""

from __future__ import annotations

from vitia_invenire.checks.base import BaseCheck
from vitia_invenire.collectors import registry
from vitia_invenire.collectors.powershell import run_ps
from vitia_invenire.models import Category, Finding, Severity

# Registry paths for RDP configuration
_RDP_DENY_PATH = "SYSTEM\\CurrentControlSet\\Control\\Terminal Server"
_RDP_NLA_PATH = (
    "SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp"
)
_RDP_SECURITY_LAYER_PATH = (
    "SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp"
)

# RDP connection history in the current user registry
_RDP_HISTORY_PATH = "Software\\Microsoft\\Terminal Server Client\\Default"
_RDP_SERVERS_PATH = "Software\\Microsoft\\Terminal Server Client\\Servers"

# Group Policy override paths
_GP_RDP_DENY_PATH = (
    "SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services"
)


class RDPAuditCheck(BaseCheck):
    """Audit RDP configuration and connection history."""

    CHECK_ID = "RDP-001"
    NAME = "RDP Security Audit"
    DESCRIPTION = (
        "Checks RDP enablement status (fDenyTSConnections), NLA "
        "enforcement, security layer settings, and RDP connection "
        "history to assess remote access security posture."
    )
    CATEGORY = Category.REMOTE_ACCESS
    REQUIRES_ADMIN = False

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        # Check fDenyTSConnections (0 = RDP enabled, 1 = RDP disabled)
        deny_val = registry.read_value(
            registry.HKEY_LOCAL_MACHINE, _RDP_DENY_PATH, "fDenyTSConnections"
        )

        # Also check Group Policy override
        gp_deny_val = registry.read_value(
            registry.HKEY_LOCAL_MACHINE, _GP_RDP_DENY_PATH, "fDenyTSConnections"
        )

        rdp_enabled = False
        rdp_evidence_parts: list[str] = []

        if gp_deny_val is not None:
            rdp_enabled = gp_deny_val.data == 0
            rdp_evidence_parts.append(
                f"Group Policy fDenyTSConnections: {gp_deny_val.data} "
                f"({'RDP Enabled' if rdp_enabled else 'RDP Disabled'})"
            )
        elif deny_val is not None:
            rdp_enabled = deny_val.data == 0
            rdp_evidence_parts.append(
                f"fDenyTSConnections: {deny_val.data} "
                f"({'RDP Enabled' if rdp_enabled else 'RDP Disabled'})"
            )
        else:
            rdp_evidence_parts.append(
                "fDenyTSConnections: Not found (default = RDP disabled)"
            )

        # Determine if this is a workstation or server
        os_type_result = run_ps(
            "(Get-CimInstance Win32_OperatingSystem).ProductType",
            timeout=10,
            as_json=False,
        )
        is_workstation = True
        if os_type_result.success and os_type_result.output:
            product_type = os_type_result.output.strip()
            # ProductType: 1 = Workstation, 2 = Domain Controller, 3 = Server
            is_workstation = product_type == "1"
            rdp_evidence_parts.append(f"ProductType: {product_type}")

        if rdp_enabled:
            severity = Severity.MEDIUM if is_workstation else Severity.INFO
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="RDP Is Enabled",
                description=(
                    f"Remote Desktop Protocol is enabled on this "
                    f"{'workstation' if is_workstation else 'server'}. "
                    f"{'RDP on workstations increases the attack surface for lateral movement.' if is_workstation else 'RDP on servers is common but should be scoped appropriately.'}"
                ),
                severity=severity,
                category=self.CATEGORY,
                affected_item="RDP Configuration",
                evidence="\n".join(rdp_evidence_parts),
                recommendation=(
                    "If RDP is not required, disable it by setting "
                    "fDenyTSConnections to 1. If required, ensure NLA is "
                    "enforced and access is restricted via firewall rules "
                    "and group membership."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1021/001/",
                ],
            ))
        else:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="RDP Is Disabled",
                description="Remote Desktop Protocol is disabled on this system.",
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="RDP Configuration",
                evidence="\n".join(rdp_evidence_parts),
                recommendation="No action required.",
                references=[
                    "https://attack.mitre.org/techniques/T1021/001/",
                ],
            ))

        # Check NLA enforcement
        nla_val = registry.read_value(
            registry.HKEY_LOCAL_MACHINE, _RDP_NLA_PATH, "UserAuthentication"
        )

        # Also check security layer
        sec_layer_val = registry.read_value(
            registry.HKEY_LOCAL_MACHINE, _RDP_SECURITY_LAYER_PATH, "SecurityLayer"
        )

        # Check minimum encryption level
        min_enc_val = registry.read_value(
            registry.HKEY_LOCAL_MACHINE, _RDP_SECURITY_LAYER_PATH,
            "MinEncryptionLevel",
        )

        nla_enabled = True  # Default assumption
        nla_evidence_parts: list[str] = []

        if nla_val is not None:
            nla_enabled = nla_val.data == 1
            nla_evidence_parts.append(
                f"UserAuthentication (NLA): {nla_val.data} "
                f"({'Enabled' if nla_enabled else 'Disabled'})"
            )
        else:
            nla_evidence_parts.append(
                "UserAuthentication (NLA): Not configured (OS default)"
            )

        if sec_layer_val is not None:
            # SecurityLayer: 0=RDP, 1=Negotiate, 2=TLS
            layer_names = {0: "RDP Security (Legacy)", 1: "Negotiate", 2: "TLS/SSL"}
            layer_name = layer_names.get(sec_layer_val.data, str(sec_layer_val.data))
            nla_evidence_parts.append(f"SecurityLayer: {sec_layer_val.data} ({layer_name})")

        if min_enc_val is not None:
            # MinEncryptionLevel: 1=Low, 2=Client Compatible, 3=High, 4=FIPS
            enc_names = {1: "Low", 2: "Client Compatible", 3: "High", 4: "FIPS Compliant"}
            enc_name = enc_names.get(min_enc_val.data, str(min_enc_val.data))
            nla_evidence_parts.append(f"MinEncryptionLevel: {min_enc_val.data} ({enc_name})")

        if rdp_enabled and not nla_enabled:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Network Level Authentication (NLA) Disabled",
                description=(
                    "NLA is disabled for RDP connections. Without NLA, the "
                    "RDP service is vulnerable to pre-authentication exploits "
                    "such as BlueKeep (CVE-2019-0708) and credential brute "
                    "force attacks."
                ),
                severity=Severity.HIGH,
                category=self.CATEGORY,
                affected_item="RDP NLA Configuration",
                evidence="\n".join(nla_evidence_parts),
                recommendation=(
                    "Enable NLA by setting UserAuthentication to 1 at "
                    f"HKLM\\{_RDP_NLA_PATH}. Set SecurityLayer to 2 (TLS) "
                    "for encrypted connections."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1021/001/",
                    "https://docs.microsoft.com/en-us/windows-server/remote/remote-desktop-services/clients/remote-desktop-allow-access",
                ],
            ))

        if sec_layer_val is not None and sec_layer_val.data == 0:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="RDP Using Legacy Security Layer",
                description=(
                    "RDP is configured to use the legacy RDP Security Layer "
                    "instead of TLS. This provides weaker encryption and "
                    "is susceptible to man-in-the-middle attacks."
                ),
                severity=Severity.MEDIUM,
                category=self.CATEGORY,
                affected_item="RDP Security Layer",
                evidence="\n".join(nla_evidence_parts),
                recommendation=(
                    "Set SecurityLayer to 2 (TLS/SSL) for RDP connections."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1021/001/",
                ],
            ))

        # Check RDP connection history
        # MRU server list from Default key
        mru_values = registry.read_key(
            registry.HKEY_CURRENT_USER, _RDP_HISTORY_PATH
        )

        # Detailed server connection history
        server_subkeys = registry.enumerate_subkeys(
            registry.HKEY_CURRENT_USER, _RDP_SERVERS_PATH
        )

        connection_history: list[dict[str, str]] = []

        for val in mru_values:
            if val.name and val.data:
                connection_history.append({
                    "source": "MRU",
                    "server": str(val.data),
                    "entry": val.name,
                })

        for server_name in server_subkeys:
            server_path = f"{_RDP_SERVERS_PATH}\\{server_name}"
            username_val = registry.read_value(
                registry.HKEY_CURRENT_USER, server_path, "UsernameHint"
            )
            connection_history.append({
                "source": "Servers",
                "server": server_name,
                "username_hint": str(username_val.data) if username_val else "Unknown",
            })

        if connection_history:
            evidence_lines = []
            unique_servers: set[str] = set()
            for entry in connection_history:
                server = entry.get("server", "Unknown")
                unique_servers.add(server)
                hint = entry.get("username_hint", "")
                line = f"  Server: {server}"
                if hint:
                    line += f" (User: {hint})"
                line += f" [Source: {entry['source']}]"
                evidence_lines.append(line)

            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="RDP Connection History Found",
                description=(
                    f"Found {len(unique_servers)} unique server(s) in the "
                    f"RDP connection history ({len(connection_history)} "
                    f"total entries). This reveals systems the user has "
                    f"connected to via RDP."
                ),
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="RDP Connection History",
                evidence="\n".join(evidence_lines),
                recommendation=(
                    "Review the RDP connection history for unexpected or "
                    "unauthorized servers. Investigate connections to "
                    "unknown systems."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1021/001/",
                ],
            ))

        # Check RDP port setting
        port_val = registry.read_value(
            registry.HKEY_LOCAL_MACHINE, _RDP_NLA_PATH, "PortNumber"
        )
        if port_val is not None and port_val.data != 3389:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Non-Standard RDP Port Configured",
                description=(
                    f"RDP is configured to listen on port {port_val.data} "
                    f"instead of the default port 3389. While not a security "
                    f"issue by itself, a changed port may indicate an attempt "
                    f"to hide RDP access."
                ),
                severity=Severity.LOW,
                category=self.CATEGORY,
                affected_item="RDP Port Configuration",
                evidence=f"RDP Port: {port_val.data} (default: 3389)",
                recommendation=(
                    "Verify the non-standard port is intentional and documented."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1021/001/",
                ],
            ))

        return findings
