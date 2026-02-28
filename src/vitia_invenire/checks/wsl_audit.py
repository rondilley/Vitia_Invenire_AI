"""WSL-001: Windows Subsystem for Linux Security Audit.

Checks whether WSL and VirtualMachinePlatform Windows features are
enabled. Lists installed WSL distributions and flags security-focused
distros (Kali, Parrot). Inspects bash configuration files for injected
commands and checks for the presence of known offensive security tools
within each distro.
"""

from __future__ import annotations

import json
import pathlib

from vitia_invenire.checks.base import BaseCheck
from vitia_invenire.collectors.powershell import run_ps
from vitia_invenire.collectors.command import run_cmd
from vitia_invenire.models import Category, Finding, Severity

_DATA_DIR = pathlib.Path(__file__).resolve().parent.parent / "data"

# Distro names that indicate offensive security purpose
_OFFENSIVE_DISTROS = [
    "kali",
    "parrot",
    "blackarch",
    "pentoo",
    "wifislax",
    "caine",
    "deft",
]

# Suspicious commands that may be injected into bash startup files
_SUSPICIOUS_BASH_PATTERNS = [
    "nc -",
    "ncat ",
    "netcat ",
    "/dev/tcp/",
    "/dev/udp/",
    "bash -i >& ",
    "reverse",
    "bind shell",
    "msfconsole",
    "msfvenom",
    "python -c 'import socket",
    "python3 -c 'import socket",
    "curl | bash",
    "wget -O - | bash",
    "curl | sh",
    "wget -O - | sh",
    "base64 -d",
    "eval $(base64",
    "powershell.exe",
    "cmd.exe",
    "certutil",
    "bitsadmin",
]


def _load_offensive_tools() -> list[str]:
    """Load the list of known offensive tools from data file."""
    data_file = _DATA_DIR / "offensive_tools.json"
    if not data_file.exists():
        return []
    with open(data_file, "r", encoding="utf-8") as fh:
        return json.load(fh)


class WSLAuditCheck(BaseCheck):
    """Audit WSL configuration and installed distros for security risks."""

    CHECK_ID = "WSL-001"
    NAME = "WSL Security Audit"
    DESCRIPTION = (
        "Checks WSL and VirtualMachinePlatform feature status, enumerates "
        "installed distributions, flags offensive security distros, and "
        "inspects for injected commands and offensive tooling."
    )
    CATEGORY = Category.CONFIGURATION
    REQUIRES_ADMIN = False

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        # Check if WSL feature is enabled
        wsl_feature_result = run_ps(
            "Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux "
            "| Select-Object FeatureName, State",
            timeout=30,
            as_json=True,
        )

        vmp_feature_result = run_ps(
            "Get-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform "
            "| Select-Object FeatureName, State",
            timeout=30,
            as_json=True,
        )

        wsl_enabled = False
        vmp_enabled = False

        if wsl_feature_result.success and wsl_feature_result.json_output:
            feature_data = wsl_feature_result.json_output
            if isinstance(feature_data, list):
                feature_data = feature_data[0] if feature_data else {}
            state = str(feature_data.get("State", "")).lower()
            wsl_enabled = state in ("enabled", "2")

        if vmp_feature_result.success and vmp_feature_result.json_output:
            feature_data = vmp_feature_result.json_output
            if isinstance(feature_data, list):
                feature_data = feature_data[0] if feature_data else {}
            state = str(feature_data.get("State", "")).lower()
            vmp_enabled = state in ("enabled", "2")

        if not wsl_enabled:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="WSL Feature Not Enabled",
                description="Windows Subsystem for Linux is not enabled on this system.",
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="WSL Feature",
                evidence="WSL feature state: Disabled",
                recommendation="No action required if WSL is not needed.",
                references=[
                    "https://attack.mitre.org/techniques/T1202/",
                ],
            ))
            return findings

        feature_evidence = (
            f"WSL Feature: {'Enabled' if wsl_enabled else 'Disabled'}\n"
            f"VirtualMachinePlatform: {'Enabled' if vmp_enabled else 'Disabled'}"
        )
        findings.append(Finding(
            check_id=self.CHECK_ID,
            title="WSL Feature Enabled",
            description=(
                "Windows Subsystem for Linux is enabled. WSL provides a "
                "Linux execution environment that can be used to bypass "
                "Windows security controls and host offensive tools."
            ),
            severity=Severity.MEDIUM,
            category=self.CATEGORY,
            affected_item="WSL Feature",
            evidence=feature_evidence,
            recommendation=(
                "Verify WSL is required for legitimate business purposes. "
                "If not needed, disable the feature via "
                "'Disable-WindowsOptionalFeature -Online -FeatureName "
                "Microsoft-Windows-Subsystem-Linux'."
            ),
            references=[
                "https://attack.mitre.org/techniques/T1202/",
            ],
        ))

        # List installed WSL distros
        distro_result = run_cmd(
            ["wsl", "--list", "--verbose"],
            timeout=15,
        )

        distros: list[dict[str, str]] = []
        if distro_result.success and distro_result.stdout:
            # Parse wsl --list --verbose output
            # Format:   NAME                   STATE           VERSION
            lines = distro_result.stdout.splitlines()
            for line in lines:
                # Remove null bytes that wsl.exe sometimes outputs
                cleaned = line.replace("\x00", "").strip()
                if not cleaned:
                    continue
                if cleaned.upper().startswith("NAME") or cleaned.startswith("---"):
                    continue
                # Handle the default marker asterisk
                if cleaned.startswith("*"):
                    cleaned = cleaned[1:].strip()

                parts = cleaned.split()
                if len(parts) >= 3:
                    distros.append({
                        "name": parts[0],
                        "state": parts[1],
                        "version": parts[2],
                    })
                elif len(parts) == 2:
                    distros.append({
                        "name": parts[0],
                        "state": parts[1],
                        "version": "Unknown",
                    })
                elif len(parts) == 1:
                    distros.append({
                        "name": parts[0],
                        "state": "Unknown",
                        "version": "Unknown",
                    })

        if not distros:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="No WSL Distributions Installed",
                description=(
                    "WSL is enabled but no distributions are installed."
                ),
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="WSL Distributions",
                evidence="wsl --list --verbose returned no distributions.",
                recommendation="No action required.",
                references=[
                    "https://attack.mitre.org/techniques/T1202/",
                ],
            ))
            return findings

        # Check for offensive security distros
        offensive_distros_found: list[dict[str, str]] = []
        for distro in distros:
            distro_lower = distro["name"].lower()
            for offensive_name in _OFFENSIVE_DISTROS:
                if offensive_name in distro_lower:
                    offensive_distros_found.append(distro)
                    break

        if offensive_distros_found:
            evidence_lines = []
            for d in offensive_distros_found:
                evidence_lines.append(
                    f"  {d['name']} - State: {d['state']}, Version: {d['version']}"
                )
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Offensive Security WSL Distribution Detected",
                description=(
                    f"{len(offensive_distros_found)} WSL distribution(s) are "
                    f"commonly associated with offensive security and penetration "
                    f"testing (e.g., Kali Linux, Parrot OS). Their presence on a "
                    f"non-security-team workstation is suspicious."
                ),
                severity=Severity.HIGH,
                category=self.CATEGORY,
                affected_item="WSL Distributions",
                evidence="\n".join(evidence_lines),
                recommendation=(
                    "Verify the offensive security distribution is authorized "
                    "for the user's role. If unauthorized, remove it via "
                    "'wsl --unregister <distro_name>'."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1202/",
                ],
            ))

        # Check for offensive tools and suspicious bash configs in each distro
        offensive_tools_list = _load_offensive_tools()

        for distro in distros:
            distro_name = distro["name"]

            if distro["state"].lower() != "running":
                continue

            # Check for offensive tools by looking for common binaries
            tools_found: list[str] = []
            if offensive_tools_list:
                # Build a PowerShell command to check for tool binaries
                # We check /usr/bin, /usr/local/bin, /usr/sbin, and dpkg/rpm
                check_bins = " ".join(
                    f"'{tool}'" for tool in offensive_tools_list[:40]
                )
                tool_check_cmd = (
                    f"wsl -d {distro_name} -- bash -c "
                    f"\"for tool in {check_bins}; do "
                    f"which $tool 2>/dev/null && echo FOUND:$tool; "
                    f"done\""
                )
                tool_result = run_cmd(
                    ["wsl", "-d", distro_name, "--", "bash", "-c",
                     f"for tool in {check_bins}; do "
                     f"which $tool 2>/dev/null || "
                     f"dpkg -l 2>/dev/null | grep -q \"ii  $tool\" && echo FOUND:$tool; "
                     f"done"],
                    timeout=30,
                )
                if tool_result.success and tool_result.stdout:
                    for line in tool_result.stdout.splitlines():
                        cleaned = line.strip()
                        if cleaned.startswith("FOUND:"):
                            tools_found.append(cleaned.replace("FOUND:", ""))
                        elif cleaned.startswith("/"):
                            # 'which' returns the path directly
                            tool_name = cleaned.rsplit("/", 1)[-1]
                            if tool_name in offensive_tools_list:
                                tools_found.append(tool_name)

            if tools_found:
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title=f"Offensive Tools Found in WSL Distro '{distro_name}'",
                    description=(
                        f"{len(tools_found)} known offensive security tool(s) "
                        f"detected in WSL distribution '{distro_name}'. These "
                        f"tools can be used for network reconnaissance, credential "
                        f"theft, and lateral movement."
                    ),
                    severity=Severity.HIGH,
                    category=self.CATEGORY,
                    affected_item=f"WSL:{distro_name}",
                    evidence=f"Offensive tools found:\n" + "\n".join(
                        f"  - {t}" for t in tools_found
                    ),
                    recommendation=(
                        "Verify the tools are authorized for the user's role. "
                        "Remove unauthorized offensive tools or the entire distro."
                    ),
                    references=[
                        "https://attack.mitre.org/techniques/T1202/",
                    ],
                ))

            # Check bash startup files for suspicious content
            bash_files = ["/etc/bash.bashrc", "~/.bashrc", "~/.bash_profile"]
            for bash_file in bash_files:
                file_result = run_cmd(
                    ["wsl", "-d", distro_name, "--", "cat", bash_file],
                    timeout=10,
                )
                if file_result.success and file_result.stdout:
                    content_lower = file_result.stdout.lower()
                    matched_patterns: list[str] = []
                    for pattern in _SUSPICIOUS_BASH_PATTERNS:
                        if pattern.lower() in content_lower:
                            matched_patterns.append(pattern)

                    if matched_patterns:
                        findings.append(Finding(
                            check_id=self.CHECK_ID,
                            title=f"Suspicious Commands in {bash_file} ({distro_name})",
                            description=(
                                f"The bash startup file {bash_file} in WSL "
                                f"distribution '{distro_name}' contains "
                                f"{len(matched_patterns)} suspicious pattern(s) "
                                f"that may indicate command injection or "
                                f"reverse shell establishment."
                            ),
                            severity=Severity.HIGH,
                            category=self.CATEGORY,
                            affected_item=f"WSL:{distro_name}:{bash_file}",
                            evidence=(
                                f"Suspicious patterns found:\n"
                                + "\n".join(f"  - {p}" for p in matched_patterns)
                                + f"\n\nFile content (first 2000 chars):\n"
                                + file_result.stdout[:2000]
                            ),
                            recommendation=(
                                "Review the bash startup file for unauthorized "
                                "modifications. Remove any injected commands. "
                                "Compare against a clean baseline."
                            ),
                            references=[
                                "https://attack.mitre.org/techniques/T1546/004/",
                            ],
                        ))

        # Distro inventory summary
        distro_lines = []
        for d in distros:
            distro_lines.append(
                f"  {d['name']} - State: {d['state']}, WSL Version: {d['version']}"
            )
        findings.append(Finding(
            check_id=self.CHECK_ID,
            title="WSL Distribution Inventory",
            description=f"Found {len(distros)} WSL distribution(s) installed.",
            severity=Severity.INFO,
            category=self.CATEGORY,
            affected_item="WSL Distributions",
            evidence="\n".join(distro_lines),
            recommendation="Review installed WSL distributions for business justification.",
            references=[
                "https://attack.mitre.org/techniques/T1202/",
            ],
        ))

        return findings
