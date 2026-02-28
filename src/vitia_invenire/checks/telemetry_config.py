"""TELEM-001: Check for tampered or redirected Windows telemetry.

Checks DiagTrack service registry configuration, hosts file for
redirected telemetry domains, and WER CorporateWERServer settings.
Redirected telemetry endpoints are flagged as HIGH.
"""

from __future__ import annotations

import json
import os
import re

from vitia_invenire.checks.base import BaseCheck
from vitia_invenire.collectors import registry
from vitia_invenire.collectors.powershell import run_ps
from vitia_invenire.models import Category, Finding, Severity

# Microsoft telemetry domains that should resolve to Microsoft IPs
_TELEMETRY_DOMAINS = [
    "vortex.data.microsoft.com",
    "vortex-win.data.microsoft.com",
    "settings-win.data.microsoft.com",
    "watson.telemetry.microsoft.com",
    "watson.microsoft.com",
    "umwatsonc.events.data.microsoft.com",
    "ceuswatcab01.blob.core.windows.net",
    "ceuswatcab02.blob.core.windows.net",
    "eaus2watcab01.blob.core.windows.net",
    "eaus2watcab02.blob.core.windows.net",
    "weus2watcab01.blob.core.windows.net",
    "weus2watcab02.blob.core.windows.net",
    "v10.events.data.microsoft.com",
    "v10.vortex-win.data.microsoft.com",
    "v20.events.data.microsoft.com",
    "self.events.data.microsoft.com",
    "telecommand.telemetry.microsoft.com",
    "oca.telemetry.microsoft.com",
    "sqm.telemetry.microsoft.com",
    "telemetry.microsoft.com",
    "telemetry.urs.microsoft.com",
    "data.microsoft.com",
    "events.data.microsoft.com",
]

# Hosts file location
_HOSTS_FILE = r"C:\Windows\System32\drivers\etc\hosts"

# DiagTrack registry paths
_DIAGTRACK_SERVICE_PATH = r"SYSTEM\CurrentControlSet\Services\DiagTrack"
_DIAGTRACK_SETTINGS_PATH = r"SOFTWARE\Policies\Microsoft\Windows\DataCollection"
_DIAGTRACK_SETTINGS_PATH2 = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack"

# WER registry paths
_WER_POLICY_PATH = r"SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting"
_WER_SETTINGS_PATH = r"SOFTWARE\Microsoft\Windows\Windows Error Reporting"


class TelemetryConfigCheck(BaseCheck):
    """Check for tampered or redirected Windows telemetry configuration."""

    CHECK_ID = "TELEM-001"
    NAME = "Telemetry Configuration Check"
    DESCRIPTION = (
        "Check DiagTrack registry, hosts file for redirected telemetry "
        "domains, and WER CorporateWERServer settings."
    )
    CATEGORY = Category.OEM_PREINSTALL
    REQUIRES_ADMIN = False

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        # 1. Check DiagTrack service configuration
        diagtrack_findings = self._check_diagtrack()
        findings.extend(diagtrack_findings)

        # 2. Check hosts file for telemetry domain redirections
        hosts_findings = self._check_hosts_file()
        findings.extend(hosts_findings)

        # 3. Check WER (Windows Error Reporting) configuration
        wer_findings = self._check_wer_config()
        findings.extend(wer_findings)

        # 4. Check telemetry policy settings
        policy_findings = self._check_telemetry_policy()
        findings.extend(policy_findings)

        return findings

    def _check_diagtrack(self) -> list[Finding]:
        """Check DiagTrack (Connected User Experiences and Telemetry) service."""
        results: list[Finding] = []

        # Check service start type
        start_val = registry.read_value(
            registry.HKEY_LOCAL_MACHINE,
            _DIAGTRACK_SERVICE_PATH,
            "Start",
        )

        # Start types: 0=Boot, 1=System, 2=Auto, 3=Manual, 4=Disabled
        start_type_names = {
            0: "Boot", 1: "System", 2: "Automatic",
            3: "Manual", 4: "Disabled",
        }

        service_info: dict = {}
        if start_val:
            start_type = start_val.data
            service_info["start_type"] = start_type_names.get(start_type, f"Unknown ({start_type})")
            service_info["start_type_value"] = start_type

            # Also check ImagePath for tampering
            image_val = registry.read_value(
                registry.HKEY_LOCAL_MACHINE,
                _DIAGTRACK_SERVICE_PATH,
                "ImagePath",
            )
            if image_val:
                service_info["image_path"] = str(image_val.data)

                # Verify the service image path is the expected system path
                expected_path = r"%SystemRoot%\system32\svchost.exe"
                actual_lower = str(image_val.data).lower()
                if "svchost" not in actual_lower:
                    results.append(Finding(
                        check_id=self.CHECK_ID,
                        title="DiagTrack Service Image Path Modified",
                        description=(
                            "The DiagTrack service image path has been changed "
                            "from the default svchost.exe. This could indicate "
                            "service hijacking where telemetry data is being "
                            "intercepted or redirected."
                        ),
                        severity=Severity.HIGH,
                        category=self.CATEGORY,
                        affected_item="DiagTrack Service",
                        evidence=json.dumps(service_info, indent=2),
                        recommendation=(
                            "Restore the DiagTrack service to its default "
                            "configuration. Investigate what binary replaced the "
                            "original service executable."
                        ),
                        references=[
                            "https://attack.mitre.org/techniques/T1543/003/",
                        ],
                    ))

        # Check DiagTrack connection endpoints
        diagtrack_settings = registry.read_key(
            registry.HKEY_LOCAL_MACHINE,
            _DIAGTRACK_SETTINGS_PATH2,
        )
        endpoint_values: list[dict] = []
        for val in diagtrack_settings:
            if "endpoint" in val.name.lower() or "url" in val.name.lower():
                endpoint_values.append({
                    "name": val.name,
                    "data": str(val.data),
                })

        if endpoint_values:
            # Check if endpoints point to non-Microsoft domains
            suspicious_endpoints: list[dict] = []
            for ep in endpoint_values:
                data_lower = str(ep["data"]).lower()
                if data_lower and "microsoft.com" not in data_lower and "windows.com" not in data_lower:
                    suspicious_endpoints.append(ep)

            if suspicious_endpoints:
                results.append(Finding(
                    check_id=self.CHECK_ID,
                    title="DiagTrack Endpoints Redirected",
                    description=(
                        "DiagTrack telemetry endpoints have been configured to "
                        "point to non-Microsoft domains. This may indicate that "
                        "telemetry data is being exfiltrated to a third-party server."
                    ),
                    severity=Severity.HIGH,
                    category=self.CATEGORY,
                    affected_item="DiagTrack Endpoints",
                    evidence=json.dumps(suspicious_endpoints, indent=2),
                    recommendation=(
                        "Remove custom DiagTrack endpoint configurations. "
                        "Investigate where telemetry data has been sent."
                    ),
                    references=[
                        "https://attack.mitre.org/techniques/T1020/",
                    ],
                ))

        # Service summary
        if service_info:
            results.append(Finding(
                check_id=self.CHECK_ID,
                title="DiagTrack Service Configuration",
                description=f"DiagTrack service start type: {service_info.get('start_type', 'Unknown')}",
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="DiagTrack Service",
                evidence=json.dumps(service_info, indent=2),
                recommendation="Verify DiagTrack configuration matches organizational policy.",
                references=[],
            ))

        return results

    def _check_hosts_file(self) -> list[Finding]:
        """Check the hosts file for telemetry domain redirections."""
        results: list[Finding] = []

        if not os.path.exists(_HOSTS_FILE):
            return results

        try:
            with open(_HOSTS_FILE, "r", encoding="utf-8", errors="replace") as f:
                hosts_content = f.read()
        except (PermissionError, OSError):
            return results

        redirected_domains: list[dict] = []
        blocked_domains: list[dict] = []

        for line in hosts_content.splitlines():
            line = line.strip()
            # Skip comments and empty lines
            if not line or line.startswith("#"):
                continue

            parts = line.split()
            if len(parts) < 2:
                continue

            ip_addr = parts[0]
            hostname = parts[1].lower()

            # Check if this hostname is a known telemetry domain
            for telem_domain in _TELEMETRY_DOMAINS:
                if hostname == telem_domain or hostname.endswith("." + telem_domain):
                    if ip_addr in ("0.0.0.0", "127.0.0.1", "::0", "::1"):
                        blocked_domains.append({
                            "ip": ip_addr,
                            "domain": hostname,
                            "action": "blocked (loopback/null)",
                        })
                    else:
                        redirected_domains.append({
                            "ip": ip_addr,
                            "domain": hostname,
                            "action": "redirected to non-standard IP",
                        })

        if redirected_domains:
            results.append(Finding(
                check_id=self.CHECK_ID,
                title="Telemetry Domains Redirected in Hosts File",
                description=(
                    f"{len(redirected_domains)} Microsoft telemetry domain(s) "
                    f"are redirected to non-standard IP addresses in the hosts "
                    f"file. This may indicate that telemetry data is being "
                    f"intercepted and sent to an attacker-controlled server."
                ),
                severity=Severity.HIGH,
                category=self.CATEGORY,
                affected_item=_HOSTS_FILE,
                evidence=json.dumps(redirected_domains, indent=2),
                recommendation=(
                    "Investigate the IP addresses that telemetry domains are "
                    "redirected to. Remove unauthorized hosts file entries. "
                    "A compromised hosts file redirecting telemetry can be used "
                    "for data interception or as an indicator of malware activity."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1565/001/",
                ],
            ))

        if blocked_domains:
            results.append(Finding(
                check_id=self.CHECK_ID,
                title="Telemetry Domains Blocked in Hosts File",
                description=(
                    f"{len(blocked_domains)} Microsoft telemetry domain(s) are "
                    f"blocked via the hosts file (redirected to loopback/null). "
                    f"This is commonly done by privacy tools but may also be "
                    f"done by malware to prevent reporting."
                ),
                severity=Severity.MEDIUM,
                category=self.CATEGORY,
                affected_item=_HOSTS_FILE,
                evidence=json.dumps(blocked_domains, indent=2),
                recommendation=(
                    "Determine if the telemetry blocking is intentional. "
                    "If blocked by a privacy tool, this is expected. If "
                    "unexpected, investigate whether malware blocked telemetry "
                    "to avoid detection."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1562/001/",
                ],
            ))

        return results

    def _check_wer_config(self) -> list[Finding]:
        """Check Windows Error Reporting (WER) configuration."""
        results: list[Finding] = []
        wer_info: dict = {}

        # Check for CorporateWERServer
        corp_server = registry.read_value(
            registry.HKEY_LOCAL_MACHINE,
            _WER_POLICY_PATH,
            "CorporateWerServer",
        )
        if not corp_server:
            corp_server = registry.read_value(
                registry.HKEY_LOCAL_MACHINE,
                _WER_SETTINGS_PATH,
                "CorporateWerServer",
            )

        if corp_server and corp_server.data:
            server_url = str(corp_server.data)
            wer_info["corporate_wer_server"] = server_url

            # Check if the server is a Microsoft domain
            if "microsoft.com" not in server_url.lower():
                results.append(Finding(
                    check_id=self.CHECK_ID,
                    title="WER Corporate Server Configured (Non-Microsoft)",
                    description=(
                        f"Windows Error Reporting is configured to send crash "
                        f"reports to a corporate server: {server_url}. "
                        f"While this is normal in enterprise environments, "
                        f"a non-corporate WER redirect could be used to "
                        f"exfiltrate crash dump data containing sensitive "
                        f"information (memory contents, credentials, keys)."
                    ),
                    severity=Severity.HIGH,
                    category=self.CATEGORY,
                    affected_item="WER Configuration",
                    evidence=json.dumps(wer_info, indent=2),
                    recommendation=(
                        "Verify the CorporateWerServer is a legitimate "
                        "organization-owned server. Crash dumps may contain "
                        "sensitive data including credentials and encryption keys."
                    ),
                    references=[
                        "https://learn.microsoft.com/en-us/windows/win32/wer/collecting-user-mode-dumps",
                        "https://attack.mitre.org/techniques/T1005/",
                    ],
                ))

        # Check if WER is completely disabled
        disabled_val = registry.read_value(
            registry.HKEY_LOCAL_MACHINE,
            _WER_POLICY_PATH,
            "Disabled",
        )
        if disabled_val and disabled_val.data == 1:
            wer_info["disabled"] = True
            results.append(Finding(
                check_id=self.CHECK_ID,
                title="Windows Error Reporting Disabled",
                description=(
                    "WER is disabled via policy. While this may be an "
                    "intentional privacy measure, malware sometimes disables "
                    "WER to prevent crash reports that could reveal its presence."
                ),
                severity=Severity.LOW,
                category=self.CATEGORY,
                affected_item="WER Configuration",
                evidence=json.dumps(wer_info, indent=2),
                recommendation=(
                    "Determine if WER was intentionally disabled. If not, "
                    "re-enable it and investigate what may have changed the setting."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1562/001/",
                ],
            ))

        return results

    def _check_telemetry_policy(self) -> list[Finding]:
        """Check Windows telemetry level policy settings."""
        results: list[Finding] = []

        # AllowTelemetry value: 0=Security, 1=Basic, 2=Enhanced, 3=Full
        telemetry_level = registry.read_value(
            registry.HKEY_LOCAL_MACHINE,
            _DIAGTRACK_SETTINGS_PATH,
            "AllowTelemetry",
        )

        level_names = {
            0: "Security (Off/Enterprise only)",
            1: "Basic",
            2: "Enhanced",
            3: "Full",
        }

        if telemetry_level:
            level = telemetry_level.data
            level_name = level_names.get(level, f"Unknown ({level})")

            results.append(Finding(
                check_id=self.CHECK_ID,
                title="Windows Telemetry Level",
                description=f"Windows telemetry level is set to: {level_name}",
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="Telemetry Policy",
                evidence=f"AllowTelemetry: {level} ({level_name})",
                recommendation=(
                    "Set telemetry level according to organizational policy. "
                    "For maximum privacy, use level 0 (Security) on Enterprise editions."
                ),
                references=[
                    "https://learn.microsoft.com/en-us/windows/privacy/configure-windows-diagnostic-data-in-your-organization",
                ],
            ))

        return results
