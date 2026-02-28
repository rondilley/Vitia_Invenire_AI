"""REG-001: Registry autostart persistence detection.

Checks Run, RunOnce, and Winlogon registry keys in HKLM and HKCU
(including WOW6432Node) for suspicious autostart entries pointing
to TEMP/APPDATA directories or known Living-off-the-Land Binaries.
"""

from __future__ import annotations

import re

from vitia_invenire.checks.base import BaseCheck
from vitia_invenire.collectors import registry
from vitia_invenire.models import Category, Finding, Severity

# Registry locations to check for autostart entries
_AUTOSTART_KEYS: list[tuple[int, str, str]] = [
    (registry.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKLM Run"),
    (registry.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM RunOnce"),
    (registry.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "HKLM Run (WOW64)"),
    (registry.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM RunOnce (WOW64)"),
    (registry.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKCU Run"),
    (registry.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU RunOnce"),
    (registry.HKEY_CURRENT_USER, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "HKCU Run (WOW64)"),
    (registry.HKEY_CURRENT_USER, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU RunOnce (WOW64)"),
]

# Winlogon keys that control shell and user init
_WINLOGON_KEYS: list[tuple[int, str, str]] = [
    (registry.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "HKLM Winlogon"),
    (registry.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "HKCU Winlogon"),
]

# Suspicious directory patterns in autostart entries
_SUSPICIOUS_DIRS: list[str] = [
    "\\TEMP\\",
    "\\TMP\\",
    "\\APPDATA\\LOCAL\\TEMP\\",
    "\\APPDATA\\ROAMING\\",
    "\\APPDATA\\LOCAL\\",
    "\\USERS\\PUBLIC\\",
    "\\DOWNLOADS\\",
    "\\DESKTOP\\",
    "\\DOCUMENTS\\",
    "\\RECYCLER\\",
    "\\$RECYCLE.BIN\\",
    "\\PROGRAMDATA\\",
]

# LOLBins (Living-off-the-Land Binaries) commonly used for persistence
_LOLBINS: dict[str, str] = {
    "powershell": "PowerShell interpreter",
    "pwsh": "PowerShell Core",
    "cmd": "Command Prompt",
    "wscript": "Windows Script Host",
    "cscript": "Console Script Host",
    "mshta": "HTML Application Host",
    "rundll32": "Run DLL Host",
    "regsvr32": "Register Server",
    "msiexec": "Windows Installer",
    "certutil": "Certificate Utility",
    "bitsadmin": "BITS Admin",
    "wmic": "WMI Command-line",
    "msbuild": "MSBuild",
    "installutil": "Install Utility",
    "regasm": "Register Assembly",
    "regsvcs": "Register Services",
    "eventvwr": "Event Viewer (UAC bypass)",
    "fodhelper": "Features on Demand Helper (UAC bypass)",
    "computerdefaults": "Computer Defaults (UAC bypass)",
    "pcalua": "Program Compatibility Assistant",
    "forfiles": "ForFiles utility",
}

# Expected Winlogon Shell and Userinit values
_EXPECTED_SHELL = "explorer.exe"
_EXPECTED_USERINIT = "c:\\windows\\system32\\userinit.exe"


class RegistryAutostartCheck(BaseCheck):
    """Detect suspicious registry autostart persistence entries."""

    CHECK_ID = "REG-001"
    NAME = "Registry Autostart Persistence"
    DESCRIPTION = (
        "Checks Run/RunOnce in HKLM and HKCU (including WOW6432Node) "
        "and Winlogon Shell/Userinit for entries pointing to suspicious "
        "locations or Living-off-the-Land Binaries."
    )
    CATEGORY = Category.PERSISTENCE
    REQUIRES_ADMIN = False

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        self._check_autostart_keys(findings)
        self._check_winlogon(findings)

        return findings

    def _check_autostart_keys(self, findings: list[Finding]) -> None:
        """Check Run/RunOnce registry keys for suspicious entries."""
        total_entries = 0
        suspicious_count = 0

        for hive, path, key_label in _AUTOSTART_KEYS:
            values = registry.read_key(hive, path)

            for val in values:
                if val.data is None:
                    continue

                total_entries += 1
                entry_name = val.name
                entry_data = str(val.data)
                upper_data = entry_data.upper()

                is_suspicious = False
                reasons: list[str] = []

                # Check for suspicious directories
                for sus_dir in _SUSPICIOUS_DIRS:
                    if sus_dir in upper_data:
                        is_suspicious = True
                        reasons.append(f"Path contains suspicious directory: {sus_dir.strip(chr(92))}")
                        break

                # Check for LOLBins
                data_lower = entry_data.lower()
                for lolbin, lolbin_desc in _LOLBINS.items():
                    # Match the LOLBin as a standalone executable name
                    pattern = rf"(?:^|\\|/|\s){re.escape(lolbin)}(?:\.exe)?(?:\s|$|\")"
                    if re.search(pattern, data_lower):
                        is_suspicious = True
                        reasons.append(f"Uses LOLBin: {lolbin} ({lolbin_desc})")
                        break

                # Check for encoded commands
                if re.search(r"-[Ee]nc(?:oded)?[Cc]ommand", entry_data):
                    is_suspicious = True
                    reasons.append("Contains encoded PowerShell command")

                # Check for URLs in autostart
                if re.search(r"https?://|ftp://", data_lower):
                    is_suspicious = True
                    reasons.append("Contains URL reference")

                if is_suspicious:
                    suspicious_count += 1
                    findings.append(Finding(
                        check_id=self.CHECK_ID,
                        title=f"Suspicious autostart entry: {entry_name}",
                        description=(
                            f"Registry autostart entry '{entry_name}' in {key_label} "
                            f"is suspicious. Reasons: {'; '.join(reasons)}."
                        ),
                        severity=Severity.HIGH,
                        category=self.CATEGORY,
                        affected_item=f"{key_label}\\{entry_name}",
                        evidence=(
                            f"Key: {key_label}\n"
                            f"Value Name: {entry_name}\n"
                            f"Value Data: {entry_data}\n"
                            f"Reasons: {'; '.join(reasons)}"
                        ),
                        recommendation=(
                            f"Investigate autostart entry '{entry_name}'. If unauthorized, "
                            f"remove the value from the registry."
                        ),
                        references=[
                            "https://attack.mitre.org/techniques/T1547/001/",
                        ],
                    ))

        # Summary
        findings.append(Finding(
            check_id=self.CHECK_ID,
            title="Registry autostart enumeration summary",
            description=(
                f"Checked {len(_AUTOSTART_KEYS)} autostart registry locations. "
                f"Found {total_entries} entries total, {suspicious_count} suspicious."
            ),
            severity=Severity.INFO,
            category=self.CATEGORY,
            affected_item="Registry Autostart Keys",
            evidence=f"Total entries: {total_entries}, Suspicious: {suspicious_count}",
            recommendation="Review autostart entries periodically.",
        ))

    def _check_winlogon(self, findings: list[Finding]) -> None:
        """Check Winlogon Shell and Userinit values for hijacking."""
        for hive, path, key_label in _WINLOGON_KEYS:
            # Check Shell value
            shell_val = registry.read_value(hive, path, "Shell")
            if shell_val is not None:
                shell_data = str(shell_val.data).strip()
                shell_lower = shell_data.lower()

                # Expected: explorer.exe (possibly with full path)
                is_normal = (
                    shell_lower == _EXPECTED_SHELL or
                    shell_lower.endswith("\\explorer.exe") or
                    shell_lower == ""
                )

                if not is_normal:
                    # Check if explorer.exe is part of it but with additions
                    has_explorer = "explorer.exe" in shell_lower
                    if has_explorer:
                        # Shell is modified but still includes explorer
                        findings.append(Finding(
                            check_id=self.CHECK_ID,
                            title=f"Modified Winlogon Shell in {key_label}",
                            description=(
                                f"The Winlogon Shell value contains explorer.exe but "
                                f"also includes additional commands: '{shell_data}'. "
                                "This is a known persistence technique where the attacker "
                                "adds their payload alongside the legitimate shell."
                            ),
                            severity=Severity.HIGH,
                            category=self.CATEGORY,
                            affected_item=f"{key_label}\\Shell",
                            evidence=(
                                f"Key: {key_label}\n"
                                f"Value: Shell\n"
                                f"Data: {shell_data}\n"
                                f"Expected: {_EXPECTED_SHELL}"
                            ),
                            recommendation=(
                                f"Reset Winlogon Shell to '{_EXPECTED_SHELL}'. "
                                "Investigate the additional commands."
                            ),
                            references=[
                                "https://attack.mitre.org/techniques/T1547/004/",
                            ],
                        ))
                    else:
                        # Shell completely replaced
                        findings.append(Finding(
                            check_id=self.CHECK_ID,
                            title=f"Hijacked Winlogon Shell in {key_label}",
                            description=(
                                f"The Winlogon Shell value is set to '{shell_data}' "
                                f"instead of the expected '{_EXPECTED_SHELL}'. "
                                "This replaces the Windows shell at logon and is a "
                                "critical persistence mechanism."
                            ),
                            severity=Severity.HIGH,
                            category=self.CATEGORY,
                            affected_item=f"{key_label}\\Shell",
                            evidence=(
                                f"Key: {key_label}\n"
                                f"Value: Shell\n"
                                f"Data: {shell_data}\n"
                                f"Expected: {_EXPECTED_SHELL}"
                            ),
                            recommendation=(
                                f"Restore Winlogon Shell to '{_EXPECTED_SHELL}' immediately. "
                                "Investigate the replacement binary."
                            ),
                            references=[
                                "https://attack.mitre.org/techniques/T1547/004/",
                            ],
                        ))

            # Check Userinit value
            userinit_val = registry.read_value(hive, path, "Userinit")
            if userinit_val is not None:
                userinit_data = str(userinit_val.data).strip().rstrip(",")
                userinit_lower = userinit_data.lower().rstrip(",")

                expected_lower = _EXPECTED_USERINIT.rstrip(",")

                is_normal = (
                    userinit_lower == expected_lower or
                    userinit_lower.endswith("\\userinit.exe") or
                    userinit_lower == ""
                )

                if not is_normal:
                    has_userinit = "userinit.exe" in userinit_lower
                    if has_userinit and userinit_lower != expected_lower:
                        findings.append(Finding(
                            check_id=self.CHECK_ID,
                            title=f"Modified Winlogon Userinit in {key_label}",
                            description=(
                                f"The Winlogon Userinit value includes additional "
                                f"executables beyond the standard userinit.exe: '{userinit_data}'. "
                                "Additional entries execute at every user logon."
                            ),
                            severity=Severity.HIGH,
                            category=self.CATEGORY,
                            affected_item=f"{key_label}\\Userinit",
                            evidence=(
                                f"Key: {key_label}\n"
                                f"Value: Userinit\n"
                                f"Data: {userinit_data}\n"
                                f"Expected: {_EXPECTED_USERINIT}"
                            ),
                            recommendation=(
                                "Remove additional entries from Userinit. "
                                f"Expected value: {_EXPECTED_USERINIT},"
                            ),
                            references=[
                                "https://attack.mitre.org/techniques/T1547/004/",
                            ],
                        ))
                    elif not has_userinit:
                        findings.append(Finding(
                            check_id=self.CHECK_ID,
                            title=f"Hijacked Winlogon Userinit in {key_label}",
                            description=(
                                f"The Winlogon Userinit value is '{userinit_data}' "
                                f"which does not include the standard userinit.exe."
                            ),
                            severity=Severity.HIGH,
                            category=self.CATEGORY,
                            affected_item=f"{key_label}\\Userinit",
                            evidence=(
                                f"Key: {key_label}\n"
                                f"Value: Userinit\n"
                                f"Data: {userinit_data}\n"
                                f"Expected: {_EXPECTED_USERINIT}"
                            ),
                            recommendation=(
                                f"Restore Userinit to '{_EXPECTED_USERINIT},' immediately."
                            ),
                            references=[
                                "https://attack.mitre.org/techniques/T1547/004/",
                            ],
                        ))
