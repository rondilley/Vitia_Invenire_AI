"""NET-CFG-001: Network configuration security assessment.

Reads the hosts file, checks DNS server configuration, proxy settings,
and NRPT (Name Resolution Policy Table) rules to detect potential
network-level supply chain attacks.
"""

from __future__ import annotations

import re

from vitia_invenire.checks.base import BaseCheck
from vitia_invenire.collectors import registry
from vitia_invenire.collectors.command import run_cmd
from vitia_invenire.collectors.powershell import run_ps
from vitia_invenire.models import Category, Finding, Severity

# Security-related domains that may be blocked in a tampered hosts file
_SECURITY_DOMAINS: list[str] = [
    "windowsupdate.com",
    "update.microsoft.com",
    "download.microsoft.com",
    "microsoft.com",
    "defender.microsoft.com",
    "malwareprotection.com",
    "virustotal.com",
    "symantec.com",
    "norton.com",
    "mcafee.com",
    "kaspersky.com",
    "bitdefender.com",
    "avast.com",
    "avg.com",
    "sophos.com",
    "crowdstrike.com",
    "sentinelone.com",
    "carbon.black",
    "trendmicro.com",
    "eset.com",
    "webroot.com",
    "malwarebytes.com",
    "paloaltonetworks.com",
    "fireeye.com",
    "mandiant.com",
    "clamav.net",
]

# Well-known legitimate DNS servers
_KNOWN_DNS_SERVERS: dict[str, str] = {
    "8.8.8.8": "Google Public DNS",
    "8.8.4.4": "Google Public DNS",
    "1.1.1.1": "Cloudflare DNS",
    "1.0.0.1": "Cloudflare DNS",
    "208.67.222.222": "OpenDNS",
    "208.67.220.220": "OpenDNS",
    "9.9.9.9": "Quad9 DNS",
    "149.112.112.112": "Quad9 DNS",
    "64.6.64.6": "Verisign DNS",
    "64.6.65.6": "Verisign DNS",
    "127.0.0.1": "Localhost",
    "::1": "Localhost IPv6",
}

# RFC 1918 / link-local ranges that indicate internal DNS
_INTERNAL_PREFIXES: list[str] = [
    "10.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
    "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
    "172.30.", "172.31.", "192.168.", "169.254.",
    "fe80:", "fd",
]


class NetworkConfigCheck(BaseCheck):
    """Analyze network configuration for supply chain security risks."""

    CHECK_ID = "NET-CFG-001"
    NAME = "Network Configuration Audit"
    DESCRIPTION = (
        "Checks the hosts file for blocking of security domains, DNS server "
        "configuration for non-standard servers, proxy settings, and NRPT "
        "rules that may redirect name resolution."
    )
    CATEGORY = Category.NETWORK
    REQUIRES_ADMIN = False

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        self._check_hosts_file(findings)
        self._check_dns_servers(findings)
        self._check_proxy_settings(findings)
        self._check_nrpt_rules(findings)

        return findings

    def _check_hosts_file(self, findings: list[Finding]) -> None:
        """Read and analyze the Windows hosts file for suspicious entries."""
        hosts_path = "C:\\Windows\\System32\\drivers\\etc\\hosts"
        result = run_cmd(["cmd", "/c", "type", hosts_path], timeout=10)

        if not result.success:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Unable to read hosts file",
                description=f"Could not read {hosts_path}: {result.stderr[:200] if result.stderr else 'unknown error'}",
                severity=Severity.MEDIUM,
                category=self.CATEGORY,
                affected_item=hosts_path,
                evidence=f"Error: {result.stderr[:300] if result.stderr else 'access denied or file not found'}",
                recommendation="Verify access to the hosts file.",
            ))
            return

        hosts_content = result.stdout
        blocked_domains: list[str] = []
        suspicious_entries: list[str] = []
        total_entries = 0

        for line in hosts_content.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            total_entries += 1

            # Parse the hosts entry: IP  hostname
            parts = stripped.split()
            if len(parts) < 2:
                continue

            ip_addr = parts[0]
            hostnames = parts[1:]

            # Check if redirecting to localhost (blocking)
            is_blocking = ip_addr in ("127.0.0.1", "0.0.0.0", "::1")

            for hostname in hostnames:
                hostname_lower = hostname.lower()
                if hostname_lower.startswith("#"):
                    break

                for sec_domain in _SECURITY_DOMAINS:
                    if sec_domain in hostname_lower:
                        blocked_domains.append(f"{ip_addr} -> {hostname}")
                        break

                # Check for non-blocking redirections to unexpected IPs
                if not is_blocking and ip_addr not in ("127.0.0.1", "0.0.0.0", "::1"):
                    suspicious_entries.append(f"{ip_addr} -> {hostname}")

        if blocked_domains:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Hosts file blocking security domains",
                description=(
                    f"The hosts file contains {len(blocked_domains)} entries that "
                    "redirect security-related domains (antivirus, Windows Update) "
                    "to localhost or null addresses. This is a common malware technique "
                    "to prevent security updates and AV definition downloads."
                ),
                severity=Severity.HIGH,
                category=self.CATEGORY,
                affected_item=hosts_path,
                evidence="Blocked security domains:\n" + "\n".join(f"  {d}" for d in blocked_domains[:20]),
                recommendation=(
                    "Remove the suspicious hosts file entries. "
                    "Restore the default hosts file content."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1562/001/",
                ],
            ))

        if suspicious_entries:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Suspicious hosts file redirections",
                description=(
                    f"Found {len(suspicious_entries)} hosts file entries redirecting "
                    "domains to non-standard IP addresses."
                ),
                severity=Severity.MEDIUM,
                category=self.CATEGORY,
                affected_item=hosts_path,
                evidence="Redirections:\n" + "\n".join(f"  {e}" for e in suspicious_entries[:20]),
                recommendation="Review all non-standard hosts file entries for legitimacy.",
            ))

        findings.append(Finding(
            check_id=self.CHECK_ID,
            title="Hosts file analysis complete",
            description=f"Parsed {total_entries} active entries in the hosts file.",
            severity=Severity.INFO,
            category=self.CATEGORY,
            affected_item=hosts_path,
            evidence=f"Total entries: {total_entries}, blocked: {len(blocked_domains)}, suspicious: {len(suspicious_entries)}",
            recommendation="Review the hosts file periodically.",
        ))

    def _check_dns_servers(self, findings: list[Finding]) -> None:
        """Check configured DNS servers via Get-DnsClientServerAddress."""
        result = run_ps(
            "Get-DnsClientServerAddress | Where-Object { $_.ServerAddresses.Count -gt 0 } | "
            "Select-Object InterfaceAlias, AddressFamily, "
            "@{N='Servers';E={$_.ServerAddresses -join ','}}",
            timeout=20,
            as_json=True,
        )

        if not result.success or result.json_output is None:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Unable to query DNS client configuration",
                description=f"Get-DnsClientServerAddress failed: {result.error or 'unknown'}",
                severity=Severity.MEDIUM,
                category=self.CATEGORY,
                affected_item="DNS Configuration",
                evidence=result.output[:500] if result.output else "No output",
                recommendation="Manually check DNS via ipconfig /all.",
            ))
            return

        dns_entries = result.json_output
        if isinstance(dns_entries, dict):
            dns_entries = [dns_entries]

        non_standard_dns: list[str] = []

        for entry in dns_entries:
            iface = str(entry.get("InterfaceAlias", "Unknown"))
            servers_str = str(entry.get("Servers", ""))
            servers = [s.strip() for s in servers_str.split(",") if s.strip()]

            for server in servers:
                is_known = server in _KNOWN_DNS_SERVERS
                is_internal = any(server.startswith(prefix) for prefix in _INTERNAL_PREFIXES)

                if not is_known and not is_internal:
                    non_standard_dns.append(f"{iface}: {server}")

        if non_standard_dns:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Non-standard DNS servers configured",
                description=(
                    f"Found {len(non_standard_dns)} DNS server(s) that are not well-known "
                    "public resolvers or internal network addresses. Non-standard DNS "
                    "servers may intercept and modify DNS responses."
                ),
                severity=Severity.MEDIUM,
                category=self.CATEGORY,
                affected_item="DNS Configuration",
                evidence="Non-standard DNS servers:\n" + "\n".join(f"  {d}" for d in non_standard_dns),
                recommendation=(
                    "Verify these DNS servers are authorized by your organization. "
                    "Consider using well-known DNS providers."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1557/",
                ],
            ))
        else:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="DNS servers appear standard",
                description="All configured DNS servers are well-known or internal addresses.",
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="DNS Configuration",
                evidence=f"Checked {len(dns_entries)} interface(s)",
                recommendation="No action needed.",
            ))

    def _check_proxy_settings(self, findings: list[Finding]) -> None:
        """Check system proxy settings via registry."""
        proxy_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings"

        proxy_enable = registry.read_value(
            registry.HKEY_CURRENT_USER, proxy_path, "ProxyEnable"
        )
        proxy_server = registry.read_value(
            registry.HKEY_CURRENT_USER, proxy_path, "ProxyServer"
        )
        proxy_override = registry.read_value(
            registry.HKEY_CURRENT_USER, proxy_path, "ProxyOverride"
        )
        auto_config = registry.read_value(
            registry.HKEY_CURRENT_USER, proxy_path, "AutoConfigURL"
        )

        evidence_lines: list[str] = []

        if proxy_enable is not None:
            evidence_lines.append(f"ProxyEnable: {proxy_enable.data}")
        if proxy_server is not None:
            evidence_lines.append(f"ProxyServer: {proxy_server.data}")
        if proxy_override is not None:
            evidence_lines.append(f"ProxyOverride: {proxy_override.data}")
        if auto_config is not None:
            evidence_lines.append(f"AutoConfigURL: {auto_config.data}")

        proxy_enabled = proxy_enable is not None and proxy_enable.data == 1

        if proxy_enabled and proxy_server is not None:
            server_val = str(proxy_server.data)
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title=f"System proxy configured: {server_val}",
                description=(
                    f"A system proxy is enabled pointing to '{server_val}'. "
                    "Malware may configure proxy settings to intercept traffic "
                    "or redirect connections through an attacker-controlled server."
                ),
                severity=Severity.MEDIUM,
                category=self.CATEGORY,
                affected_item="Proxy Settings",
                evidence="\n".join(evidence_lines),
                recommendation=(
                    "Verify the proxy configuration is authorized. "
                    "Check with IT whether a proxy is expected."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1090/",
                ],
            ))

        if auto_config is not None:
            auto_url = str(auto_config.data)
            if auto_url:
                # Check for suspicious PAC file URLs
                is_suspicious = not any(
                    auto_url.lower().startswith(prefix) for prefix in
                    ("http://wpad", "http://pac", "https://")
                )
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title=f"Proxy auto-configuration (PAC) URL set: {auto_url}",
                    description=(
                        f"A proxy auto-configuration URL is set to '{auto_url}'. "
                        "PAC files can selectively redirect traffic through proxies "
                        "based on the destination URL."
                    ),
                    severity=Severity.MEDIUM if is_suspicious else Severity.INFO,
                    category=self.CATEGORY,
                    affected_item="Proxy AutoConfig",
                    evidence="\n".join(evidence_lines),
                    recommendation="Verify the PAC URL is legitimate and controlled by your organization.",
                ))

        if not proxy_enabled and auto_config is None:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="No system proxy configured",
                description="No system-wide proxy or PAC file is configured.",
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="Proxy Settings",
                evidence="\n".join(evidence_lines) if evidence_lines else "No proxy settings found",
                recommendation="No action needed.",
            ))

    def _check_nrpt_rules(self, findings: list[Finding]) -> None:
        """Check Name Resolution Policy Table (NRPT) rules."""
        result = run_ps(
            "Get-DnsClientNrptRule -ErrorAction SilentlyContinue | "
            "Select-Object Namespace, NameServers, DnsSecEnable, "
            "DnsSecValidationRequired, DirectAccessDnsServers, "
            "DirectAccessEnabled, NameEncoding, DisplayName, Comment",
            timeout=20,
            as_json=True,
        )

        if not result.success or result.json_output is None:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="NRPT rules query completed",
                description="No NRPT rules found or cmdlet not available.",
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="NRPT Rules",
                evidence="Get-DnsClientNrptRule returned no results",
                recommendation="No action needed if NRPT is not in use.",
            ))
            return

        nrpt_rules = result.json_output
        if isinstance(nrpt_rules, dict):
            nrpt_rules = [nrpt_rules]

        if not nrpt_rules:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="No NRPT rules configured",
                description="No Name Resolution Policy Table rules are defined.",
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="NRPT Rules",
                evidence="Rule count: 0",
                recommendation="No action needed.",
            ))
            return

        for rule in nrpt_rules:
            namespace = str(rule.get("Namespace", "Unknown"))
            name_servers = rule.get("NameServers", [])
            da_servers = rule.get("DirectAccessDnsServers", [])
            da_enabled = rule.get("DirectAccessEnabled", False)
            display_name = str(rule.get("DisplayName", ""))
            comment = str(rule.get("Comment", ""))

            if name_servers is None:
                name_servers = []
            if da_servers is None:
                da_servers = []

            servers_str = ", ".join(str(s) for s in name_servers) if name_servers else "None"
            da_str = ", ".join(str(s) for s in da_servers) if da_servers else "None"

            # Check for catch-all rules or broad namespace redirections
            is_broad = namespace in (".", "*", "") or re.match(r"^\.\w{2,}$", namespace)

            findings.append(Finding(
                check_id=self.CHECK_ID,
                title=f"NRPT rule for namespace: {namespace}",
                description=(
                    f"NRPT rule redirecting DNS resolution for '{namespace}'. "
                    f"{'This is a broad catch-all rule that affects all DNS resolution.' if is_broad else ''}"
                ),
                severity=Severity.HIGH if is_broad else Severity.MEDIUM,
                category=self.CATEGORY,
                affected_item=f"NRPT: {namespace}",
                evidence=(
                    f"Namespace: {namespace}\n"
                    f"Name Servers: {servers_str}\n"
                    f"DirectAccess Servers: {da_str}\n"
                    f"DirectAccess Enabled: {da_enabled}\n"
                    f"Display Name: {display_name}\n"
                    f"Comment: {comment}"
                ),
                recommendation=(
                    "Review NRPT rules for legitimacy. Broad namespace rules "
                    "can redirect all DNS traffic through controlled servers."
                ),
                references=[
                    "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/dn593632(v=ws.11)",
                ],
            ))
