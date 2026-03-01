"""SSH-001: OpenSSH Server Security Audit.

Checks the status of the sshd service, reads sshd_config for dangerous
settings (PermitRootLogin, PasswordAuthentication yes), detects the
presence of authorized_keys files, and inspects firewall rules scoping
SSH access.
"""

from __future__ import annotations

import os

from vitia_invenire.checks.base import BaseCheck
from vitia_invenire.collectors.powershell import run_ps
from vitia_invenire.collectors import registry
from vitia_invenire.models import Category, Finding, Severity

# Dangerous sshd_config settings and their descriptions
_DANGEROUS_SETTINGS: dict[str, dict[str, str]] = {
    "permitrootlogin": {
        "dangerous_value": "yes",
        "description": "Allows direct root/Administrator login via SSH",
        "severity": "HIGH",
    },
    "passwordauthentication": {
        "dangerous_value": "yes",
        "description": "Allows password-based authentication, vulnerable to brute force",
        "severity": "MEDIUM",
    },
    "permitemptypasswords": {
        "dangerous_value": "yes",
        "description": "Allows login with empty passwords",
        "severity": "HIGH",
    },
    "permittunel": {
        "dangerous_value": "yes",
        "description": "Allows SSH tunneling which can be used for lateral movement",
        "severity": "MEDIUM",
    },
    "x11forwarding": {
        "dangerous_value": "yes",
        "description": "Allows X11 forwarding which increases attack surface",
        "severity": "LOW",
    },
    "gatewayports": {
        "dangerous_value": "yes",
        "description": "Allows remote hosts to connect to forwarded ports",
        "severity": "MEDIUM",
    },
    "usepam": {
        "dangerous_value": "no",
        "description": "PAM authentication disabled, reducing security controls",
        "severity": "MEDIUM",
    },
    "allowtcpforwarding": {
        "dangerous_value": "yes",
        "description": "Allows TCP forwarding for tunneling and port forwarding",
        "severity": "LOW",
    },
}


def _parse_sshd_config(content: str) -> dict[str, str]:
    """Parse sshd_config content into a key-value dictionary.

    Returns lowercase keys mapped to their configured values.
    Ignores comments and blank lines.
    """
    config: dict[str, str] = {}
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split(None, 1)
        if len(parts) == 2:
            config[parts[0].lower()] = parts[1]
    return config


class OpenSSHAuditCheck(BaseCheck):
    """Audit OpenSSH server configuration and access controls."""

    CHECK_ID = "SSH-001"
    NAME = "OpenSSH Server Audit"
    DESCRIPTION = (
        "Checks the OpenSSH server (sshd) service status, inspects "
        "sshd_config for dangerous settings, detects authorized_keys "
        "files, and reviews firewall rule scope for SSH access."
    )
    CATEGORY = Category.REMOTE_ACCESS
    REQUIRES_ADMIN = True

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        self.context["state"] = {
            "service": [],
            "config": [],
            "authorized_keys": [],
        }

        # Check sshd service status
        svc_result = run_ps(
            "Get-Service -Name sshd -ErrorAction SilentlyContinue | "
            "Select-Object Name, Status, StartType, DisplayName",
            timeout=15,
            as_json=True,
        )

        sshd_running = False
        sshd_installed = False

        if svc_result.success and svc_result.json_output:
            svc_data = svc_result.json_output
            if isinstance(svc_data, list):
                svc_data = svc_data[0] if svc_data else {}
            status = str(svc_data.get("Status", "")).lower()
            start_type = str(svc_data.get("StartType", ""))
            sshd_installed = True

            # PowerShell Status enum: 1=Stopped, 4=Running
            sshd_running = status in ("running", "4")

            self.context["state"]["service"].append({
                "name": "sshd",
                "status": "Running" if sshd_running else "Stopped",
                "start_type": start_type,
            })

            severity = Severity.MEDIUM if sshd_running else Severity.INFO
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="OpenSSH Server Service Status",
                description=(
                    f"The OpenSSH Server (sshd) service is "
                    f"{'running' if sshd_running else 'installed but not running'}. "
                    f"Start type: {start_type}."
                ),
                severity=severity,
                category=self.CATEGORY,
                affected_item="sshd Service",
                evidence=(
                    f"Service Name: sshd\n"
                    f"Status: {'Running' if sshd_running else 'Stopped'}\n"
                    f"Start Type: {start_type}"
                ),
                recommendation=(
                    "If SSH remote access is not required, disable and stop the "
                    "sshd service. If required, ensure it is properly configured "
                    "and secured."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1021/004/",
                ],
            ))
        else:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="OpenSSH Server Not Installed",
                description="The OpenSSH Server (sshd) service is not installed.",
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="sshd Service",
                evidence="Get-Service -Name sshd returned no results.",
                recommendation="No action required if SSH access is not needed.",
                references=[
                    "https://attack.mitre.org/techniques/T1021/004/",
                ],
            ))
            return findings

        # Read sshd_config
        programdata = os.environ.get("ProgramData", "C:\\ProgramData")
        config_paths = [
            f"{programdata}\\ssh\\sshd_config",
            "C:\\ProgramData\\ssh\\sshd_config",
            "C:\\Windows\\System32\\OpenSSH\\sshd_config",
        ]

        config_content = ""
        config_path_used = ""
        for config_path in config_paths:
            read_result = run_ps(
                f"Get-Content '{config_path}' -Raw -ErrorAction SilentlyContinue",
                timeout=10,
                as_json=False,
            )
            if read_result.success and read_result.output:
                config_content = read_result.output
                config_path_used = config_path
                break

        if config_content:
            parsed_config = _parse_sshd_config(config_content)
            for k, v in parsed_config.items():
                self.context["state"]["config"].append({
                    "name": k,
                    "value": v,
                })
            dangerous_found: list[dict[str, str]] = []

            for setting_key, setting_info in _DANGEROUS_SETTINGS.items():
                configured_value = parsed_config.get(setting_key, "")
                if configured_value.lower() == setting_info["dangerous_value"].lower():
                    dangerous_found.append({
                        "setting": setting_key,
                        "value": configured_value,
                        "description": setting_info["description"],
                        "severity": setting_info["severity"],
                    })

            if dangerous_found:
                high_severity = any(d["severity"] == "HIGH" for d in dangerous_found)
                evidence_lines = []
                for d in dangerous_found:
                    evidence_lines.append(
                        f"  {d['setting']} = {d['value']}\n"
                        f"    Risk: {d['description']} (Severity: {d['severity']})"
                    )
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title="Dangerous sshd_config Settings Detected",
                    description=(
                        f"{len(dangerous_found)} dangerous setting(s) found in "
                        f"the OpenSSH server configuration at {config_path_used}."
                    ),
                    severity=Severity.HIGH if high_severity else Severity.MEDIUM,
                    category=self.CATEGORY,
                    affected_item=config_path_used,
                    evidence="\n".join(evidence_lines),
                    recommendation=(
                        "Update sshd_config to use secure settings: disable "
                        "PermitRootLogin, use key-based authentication only "
                        "(PasswordAuthentication no), and disable empty passwords."
                    ),
                    references=[
                        "https://attack.mitre.org/techniques/T1021/004/",
                        "https://docs.microsoft.com/en-us/windows-server/administration/openssh/openssh_server_configuration",
                    ],
                ))
        else:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="sshd_config Not Found",
                description=(
                    "Could not locate or read the sshd_config file. Default "
                    "settings may be in effect."
                ),
                severity=Severity.LOW,
                category=self.CATEGORY,
                affected_item="sshd_config",
                evidence="Searched paths: " + ", ".join(config_paths),
                recommendation=(
                    "Locate the sshd_config file and review settings manually."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1021/004/",
                ],
            ))

        # Check for authorized_keys files
        auth_keys_result = run_ps(
            "Get-ChildItem -Path 'C:\\Users' -Directory | "
            "ForEach-Object { "
            "  $akFile = Join-Path $_.FullName '.ssh\\authorized_keys'; "
            "  if (Test-Path $akFile) { "
            "    [PSCustomObject]@{ "
            "      User = $_.Name; "
            "      Path = $akFile; "
            "      Size = (Get-Item $akFile).Length; "
            "      LastWriteTime = (Get-Item $akFile).LastWriteTime.ToString('o'); "
            "      KeyCount = (Get-Content $akFile | Where-Object { $_.Trim() -and -not $_.StartsWith('#') }).Count "
            "    } "
            "  } "
            "} | Where-Object { $_ -ne $null }",
            timeout=15,
            as_json=True,
        )

        # Also check the ProgramData administrators authorized keys
        admin_ak_result = run_ps(
            f"$akPath = '{programdata}\\ssh\\administrators_authorized_keys'; "
            "if (Test-Path $akPath) { "
            "  [PSCustomObject]@{ "
            "    User = 'administrators'; "
            "    Path = $akPath; "
            "    Size = (Get-Item $akPath).Length; "
            "    LastWriteTime = (Get-Item $akPath).LastWriteTime.ToString('o'); "
            "    KeyCount = (Get-Content $akPath | Where-Object { $_.Trim() -and -not $_.StartsWith('#') }).Count "
            "  } "
            "}",
            timeout=10,
            as_json=True,
        )

        auth_keys_entries: list[dict] = []
        for ak_result in [auth_keys_result, admin_ak_result]:
            if ak_result.success and ak_result.json_output:
                data = ak_result.json_output
                if isinstance(data, dict):
                    auth_keys_entries.append(data)
                elif isinstance(data, list):
                    auth_keys_entries.extend(data)

        for entry in auth_keys_entries:
            self.context["state"]["authorized_keys"].append({
                "name": str(entry.get("User", "")),
                "path": str(entry.get("Path", "")),
                "key_count": entry.get("KeyCount", 0),
            })

        if auth_keys_entries:
            evidence_lines = []
            for entry in auth_keys_entries:
                evidence_lines.append(
                    f"User: {entry.get('User', 'Unknown')}\n"
                    f"  Path: {entry.get('Path', 'Unknown')}\n"
                    f"  Size: {entry.get('Size', 0)} bytes\n"
                    f"  Keys: {entry.get('KeyCount', 0)}\n"
                    f"  Last Modified: {entry.get('LastWriteTime', 'Unknown')}"
                )
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="SSH Authorized Keys Files Detected",
                description=(
                    f"{len(auth_keys_entries)} authorized_keys file(s) found. "
                    f"These files grant SSH access without password authentication "
                    f"and are a common persistence mechanism."
                ),
                severity=Severity.CRITICAL,
                category=self.CATEGORY,
                affected_item="SSH Authorized Keys",
                evidence="\n\n".join(evidence_lines),
                recommendation=(
                    "Review all authorized_keys files to ensure only legitimate, "
                    "authorized public keys are present. Remove any unknown keys. "
                    "Verify the file permissions are correctly restricted."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1098/004/",
                    "https://attack.mitre.org/techniques/T1021/004/",
                ],
            ))

        # Check firewall rules for SSH port
        fw_result = run_ps(
            "Get-NetFirewallRule -Direction Inbound -Enabled True -ErrorAction SilentlyContinue | "
            "Where-Object { $_.DisplayName -like '*SSH*' -or $_.DisplayName -like '*OpenSSH*' -or "
            "$_.DisplayName -like '*Secure Shell*' -or $_.DisplayName -like '*sshd*' } | "
            "ForEach-Object { "
            "  $portFilter = $_ | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue; "
            "  $addrFilter = $_ | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue; "
            "  [PSCustomObject]@{ "
            "    Name = $_.DisplayName; "
            "    Action = $_.Action.ToString(); "
            "    Profile = $_.Profile.ToString(); "
            "    LocalPort = $portFilter.LocalPort; "
            "    RemoteAddress = $addrFilter.RemoteAddress; "
            "    Protocol = $portFilter.Protocol "
            "  } "
            "}",
            timeout=15,
            as_json=True,
        )

        if fw_result.success and fw_result.json_output:
            fw_data = fw_result.json_output
            if isinstance(fw_data, dict):
                fw_data = [fw_data]

            any_open_to_all = False
            evidence_lines = []
            for rule in fw_data:
                remote_addr = str(rule.get("RemoteAddress", "Any"))
                action = str(rule.get("Action", ""))
                is_allow = action.lower() in ("allow", "2")
                is_open = remote_addr.lower() in ("any", "*", "{any}")

                if is_allow and is_open:
                    any_open_to_all = True

                evidence_lines.append(
                    f"Rule: {rule.get('Name', 'Unknown')}\n"
                    f"  Action: {action}\n"
                    f"  Profile: {rule.get('Profile', 'Unknown')}\n"
                    f"  Local Port: {rule.get('LocalPort', 'Unknown')}\n"
                    f"  Remote Address: {remote_addr}\n"
                    f"  Protocol: {rule.get('Protocol', 'Unknown')}"
                )

            if any_open_to_all:
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title="SSH Firewall Rule Open to All Addresses",
                    description=(
                        "One or more SSH firewall rules allow inbound connections "
                        "from any remote address. This exposes the SSH service to "
                        "the entire network."
                    ),
                    severity=Severity.MEDIUM,
                    category=self.CATEGORY,
                    affected_item="SSH Firewall Rules",
                    evidence="\n\n".join(evidence_lines),
                    recommendation=(
                        "Restrict SSH firewall rules to specific trusted IP "
                        "addresses or subnets. Avoid allowing SSH from 'Any' "
                        "remote address."
                    ),
                    references=[
                        "https://attack.mitre.org/techniques/T1021/004/",
                    ],
                ))
            elif evidence_lines:
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title="SSH Firewall Rules Inventory",
                    description=f"Found {len(fw_data)} SSH-related firewall rule(s).",
                    severity=Severity.INFO,
                    category=self.CATEGORY,
                    affected_item="SSH Firewall Rules",
                    evidence="\n\n".join(evidence_lines),
                    recommendation="Review SSH firewall rules for appropriate scoping.",
                    references=[
                        "https://attack.mitre.org/techniques/T1021/004/",
                    ],
                ))

        return findings
