"""FW-RULE-001: Windows Firewall rule security assessment.

Enumerates enabled inbound allow rules via Get-NetFirewallRule and
flags rules that allow all profiles, use broad port ranges, or
allow any remote address.
"""

from __future__ import annotations

from vitia_invenire.checks.base import BaseCheck
from vitia_invenire.collectors.powershell import run_ps
from vitia_invenire.models import Category, Finding, Severity


class FirewallCheck(BaseCheck):
    """Analyze Windows Firewall rules for overly permissive configurations."""

    CHECK_ID = "FW-RULE-001"
    NAME = "Firewall Rule Audit"
    DESCRIPTION = (
        "Enumerates enabled inbound allow firewall rules and flags "
        "rules that allow all profiles, use broad port ranges, or "
        "permit connections from any remote address."
    )
    CATEGORY = Category.NETWORK
    REQUIRES_ADMIN = True

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        # Get firewall profile status first
        self._check_firewall_profiles(findings)

        # Enumerate inbound allow rules
        result = run_ps(
            "Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True "
            "-ErrorAction SilentlyContinue | ForEach-Object { "
            "$rule = $_; "
            "$port = $rule | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue; "
            "$addr = $rule | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue; "
            "$app = $rule | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue; "
            "@{ "
            "Name=$rule.Name; "
            "DisplayName=$rule.DisplayName; "
            "Description=$rule.Description; "
            "Profile=$rule.Profile.ToString(); "
            "LocalPort=if($port){$port.LocalPort}else{'Any'}; "
            "RemotePort=if($port){$port.RemotePort}else{'Any'}; "
            "Protocol=if($port){$port.Protocol}else{'Any'}; "
            "RemoteAddress=if($addr){$addr.RemoteAddress -join ','}else{'Any'}; "
            "LocalAddress=if($addr){$addr.LocalAddress -join ','}else{'Any'}; "
            "Program=if($app){$app.Program}else{'Any'}; "
            "Owner=$rule.Owner; "
            "Group=$rule.Group "
            "} }",
            timeout=60,
            as_json=True,
        )

        if not result.success or result.json_output is None:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Failed to enumerate firewall rules",
                description=f"Get-NetFirewallRule failed: {result.error or 'unknown error'}",
                severity=Severity.MEDIUM,
                category=self.CATEGORY,
                affected_item="Windows Firewall Rules",
                evidence=result.output[:500] if result.output else "No output",
                recommendation="Verify Windows Firewall service is running.",
            ))
            return findings

        rules = result.json_output
        if isinstance(rules, dict):
            rules = [rules]

        total_rules = len(rules)
        all_profiles_count = 0
        broad_port_count = 0
        any_address_count = 0

        for rule in rules:
            display_name = str(rule.get("DisplayName", rule.get("Name", "Unknown")))
            name = str(rule.get("Name", "Unknown"))
            description = str(rule.get("Description", ""))
            profile = str(rule.get("Profile", ""))
            local_port = str(rule.get("LocalPort", "Any"))
            remote_port = str(rule.get("RemotePort", "Any"))
            protocol = str(rule.get("Protocol", "Any"))
            remote_address = str(rule.get("RemoteAddress", "Any"))
            program = str(rule.get("Program", "Any"))
            group = str(rule.get("Group", ""))

            evidence_text = (
                f"Rule: {display_name}\n"
                f"Name: {name}\n"
                f"Profile: {profile}\n"
                f"Protocol: {protocol}\n"
                f"Local Port: {local_port}\n"
                f"Remote Port: {remote_port}\n"
                f"Remote Address: {remote_address}\n"
                f"Program: {program}\n"
                f"Group: {group}\n"
                f"Description: {description[:200] if description else 'None'}"
            )

            # Check for rules allowing all profiles
            profile_lower = profile.lower()
            allows_all = "any" in profile_lower or (
                "domain" in profile_lower and
                "private" in profile_lower and
                "public" in profile_lower
            )

            if allows_all and remote_address.lower() in ("any", "*"):
                all_profiles_count += 1
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title=f"Firewall rule allows all profiles and any address: {display_name}",
                    description=(
                        f"Inbound allow rule '{display_name}' applies to all firewall "
                        "profiles (Domain, Private, Public) and allows connections from "
                        "any remote address. This is an overly permissive configuration."
                    ),
                    severity=Severity.MEDIUM,
                    category=self.CATEGORY,
                    affected_item=f"Firewall Rule: {name}",
                    evidence=evidence_text,
                    recommendation=(
                        "Restrict this rule to specific profiles (e.g., Domain only) "
                        "and limit remote addresses where possible."
                    ),
                    references=[
                        "https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/",
                    ],
                ))

            # Check for broad port ranges or 'Any' ports
            if local_port.lower() == "any" and protocol.lower() in ("tcp", "udp"):
                broad_port_count += 1
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title=f"Firewall rule allows any port: {display_name}",
                    description=(
                        f"Inbound allow rule '{display_name}' allows {protocol} "
                        "connections on any local port. This effectively disables "
                        "the firewall for this protocol."
                    ),
                    severity=Severity.MEDIUM,
                    category=self.CATEGORY,
                    affected_item=f"Firewall Rule: {name}",
                    evidence=evidence_text,
                    recommendation=(
                        "Restrict the rule to specific port numbers. "
                        "Allowing all ports is rarely necessary."
                    ),
                ))
            elif "-" in local_port:
                # Check for broad port ranges like "1-65535" or "1024-65535"
                try:
                    port_parts = local_port.split("-")
                    if len(port_parts) == 2:
                        start_port = int(port_parts[0].strip())
                        end_port = int(port_parts[1].strip())
                        range_size = end_port - start_port
                        if range_size > 1000:
                            broad_port_count += 1
                            findings.append(Finding(
                                check_id=self.CHECK_ID,
                                title=f"Firewall rule with broad port range: {display_name}",
                                description=(
                                    f"Inbound allow rule '{display_name}' allows {protocol} "
                                    f"connections on port range {local_port} "
                                    f"({range_size} ports). Large port ranges significantly "
                                    "increase the attack surface."
                                ),
                                severity=Severity.MEDIUM,
                                category=self.CATEGORY,
                                affected_item=f"Firewall Rule: {name}",
                                evidence=evidence_text,
                                recommendation="Narrow the port range to specific required ports.",
                            ))
                except (ValueError, IndexError):
                    # Port range parsing failed, skip
                    findings.append(Finding(
                        check_id=self.CHECK_ID,
                        title=f"Unparseable firewall rule port range: {display_name}",
                        description=f"Could not parse port range '{local_port}' in rule '{display_name}'.",
                        severity=Severity.INFO,
                        category=self.CATEGORY,
                        affected_item=f"Firewall Rule: {name}",
                        evidence=evidence_text,
                        recommendation="Manually review this firewall rule.",
                    ))

            # Check for any remote address on public profile
            if "public" in profile_lower and remote_address.lower() in ("any", "*"):
                any_address_count += 1
                # Only flag if not already flagged by all-profiles check
                if not allows_all:
                    findings.append(Finding(
                        check_id=self.CHECK_ID,
                        title=f"Public profile rule allows any remote address: {display_name}",
                        description=(
                            f"Inbound allow rule '{display_name}' on the Public profile "
                            "allows connections from any remote address. The Public profile "
                            "applies to untrusted networks."
                        ),
                        severity=Severity.MEDIUM,
                        category=self.CATEGORY,
                        affected_item=f"Firewall Rule: {name}",
                        evidence=evidence_text,
                        recommendation="Restrict remote addresses or remove the Public profile from this rule.",
                    ))

        # Summary
        findings.append(Finding(
            check_id=self.CHECK_ID,
            title="Firewall rule audit summary",
            description=(
                f"Audited {total_rules} enabled inbound allow rules. "
                f"{all_profiles_count} allow all profiles with any address, "
                f"{broad_port_count} use broad port ranges."
            ),
            severity=Severity.INFO,
            category=self.CATEGORY,
            affected_item="Windows Firewall",
            evidence=(
                f"Total rules: {total_rules}\n"
                f"All profiles + any address: {all_profiles_count}\n"
                f"Broad port ranges: {broad_port_count}\n"
                f"Any remote on public: {any_address_count}"
            ),
            recommendation="Follow least-privilege principle for firewall rules.",
        ))

        return findings

    def _check_firewall_profiles(self, findings: list[Finding]) -> None:
        """Check if firewall profiles are enabled."""
        result = run_ps(
            "Get-NetFirewallProfile | Select-Object Name, Enabled, "
            "DefaultInboundAction, DefaultOutboundAction, "
            "LogAllowed, LogBlocked, LogFileName",
            timeout=15,
            as_json=True,
        )

        if not result.success or result.json_output is None:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Unable to query firewall profiles",
                description=f"Get-NetFirewallProfile failed: {result.error or 'unknown'}",
                severity=Severity.MEDIUM,
                category=self.CATEGORY,
                affected_item="Firewall Profiles",
                evidence=result.output[:500] if result.output else "No output",
                recommendation="Verify Windows Firewall service is running.",
            ))
            return

        profiles = result.json_output
        if isinstance(profiles, dict):
            profiles = [profiles]

        for profile in profiles:
            name = str(profile.get("Name", "Unknown"))
            enabled = profile.get("Enabled", False)
            default_in = str(profile.get("DefaultInboundAction", "Unknown"))
            default_out = str(profile.get("DefaultOutboundAction", "Unknown"))
            log_blocked = profile.get("LogBlocked", False)

            if not enabled:
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title=f"Firewall profile disabled: {name}",
                    description=(
                        f"The {name} firewall profile is disabled. "
                        "This leaves the system unprotected when connected to "
                        f"networks matching the {name} profile."
                    ),
                    severity=Severity.HIGH,
                    category=self.CATEGORY,
                    affected_item=f"Firewall Profile: {name}",
                    evidence=(
                        f"Profile: {name}\n"
                        f"Enabled: {enabled}\n"
                        f"Default Inbound: {default_in}\n"
                        f"Default Outbound: {default_out}"
                    ),
                    recommendation=f"Enable the {name} firewall profile: Set-NetFirewallProfile -Name {name} -Enabled True",
                    references=[
                        "https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/",
                    ],
                ))
