"""WER-001: Windows Error Reporting Configuration Audit.

Checks the CorporateWERServer registry value for unexpected WER
endpoints, inspects LocalDumps configuration for full memory dump
settings, and evaluates WER consent and queue settings. Full memory
dumps can leak sensitive data, and a rogue WER server can be used
for data exfiltration.
"""

from __future__ import annotations

from vitia_invenire.checks.base import BaseCheck
from vitia_invenire.collectors import registry
from vitia_invenire.models import Category, Finding, Severity

# WER registry paths
_WER_BASE_PATH = "SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting"
_WER_LOCAL_DUMPS_PATH = (
    "SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting\\LocalDumps"
)
_WER_CONSENT_PATH = (
    "SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting\\Consent"
)

# Known legitimate Microsoft WER endpoints
_KNOWN_WER_SERVERS = [
    "watson.microsoft.com",
    "watson.telemetry.microsoft.com",
    "ceuswatcab01.blob.core.windows.net",
    "ceuswatcab02.blob.core.windows.net",
    "eaus2watcab01.blob.core.windows.net",
    "eaus2watcab02.blob.core.windows.net",
    "weus2watcab01.blob.core.windows.net",
    "weus2watcab02.blob.core.windows.net",
]


class WERAuditCheck(BaseCheck):
    """Audit Windows Error Reporting configuration."""

    CHECK_ID = "WER-001"
    NAME = "Windows Error Reporting Audit"
    DESCRIPTION = (
        "Checks WER corporate server endpoint, local dump configuration, "
        "and consent settings. Flags unknown WER servers and full memory "
        "dump configurations that may leak sensitive data."
    )
    CATEGORY = Category.CONFIGURATION
    REQUIRES_ADMIN = False

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        # Check CorporateWerServer
        corp_server = registry.read_value(
            registry.HKEY_LOCAL_MACHINE, _WER_BASE_PATH, "CorporateWerServer"
        )

        if corp_server and corp_server.data:
            server_url = str(corp_server.data).lower()
            is_known = any(
                known in server_url for known in _KNOWN_WER_SERVERS
            )

            if not is_known:
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title="Unknown Corporate WER Server Configured",
                    description=(
                        "A CorporateWerServer registry value points to a "
                        "server that is not a recognized Microsoft WER "
                        "endpoint. This could be a legitimate enterprise "
                        "configuration, or it could be used to exfiltrate "
                        "crash dump data containing sensitive information "
                        "such as credentials, encryption keys, and memory "
                        "contents."
                    ),
                    severity=Severity.HIGH,
                    category=self.CATEGORY,
                    affected_item="CorporateWerServer",
                    evidence=(
                        f"Registry: HKLM\\{_WER_BASE_PATH}\\CorporateWerServer\n"
                        f"Value: {corp_server.data}"
                    ),
                    recommendation=(
                        "Verify the CorporateWerServer URL belongs to the "
                        "organization's legitimate error reporting "
                        "infrastructure. If unrecognized, remove the value "
                        "and investigate how it was configured."
                    ),
                    references=[
                        "https://docs.microsoft.com/en-us/windows/win32/wer/collecting-user-mode-dumps",
                        "https://attack.mitre.org/techniques/T1005/",
                    ],
                ))
            else:
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title="Corporate WER Server Points to Microsoft",
                    description=(
                        "CorporateWerServer is configured and points to a "
                        "recognized Microsoft endpoint."
                    ),
                    severity=Severity.INFO,
                    category=self.CATEGORY,
                    affected_item="CorporateWerServer",
                    evidence=f"Server: {corp_server.data}",
                    recommendation="No action required.",
                    references=[
                        "https://docs.microsoft.com/en-us/windows/win32/wer/collecting-user-mode-dumps",
                    ],
                ))

        # Check WER Disabled status
        wer_disabled = registry.read_value(
            registry.HKEY_LOCAL_MACHINE, _WER_BASE_PATH, "Disabled"
        )
        if wer_disabled and wer_disabled.data == 1:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Windows Error Reporting Disabled",
                description=(
                    "WER is disabled. While this prevents data from being "
                    "sent to Microsoft, it also prevents crash dump "
                    "collection that can be useful for debugging and "
                    "security incident analysis."
                ),
                severity=Severity.LOW,
                category=self.CATEGORY,
                affected_item="WER Service",
                evidence=(
                    f"HKLM\\{_WER_BASE_PATH}\\Disabled = 1"
                ),
                recommendation=(
                    "Consider enabling WER with appropriate privacy settings "
                    "for security incident investigation capability."
                ),
                references=[
                    "https://docs.microsoft.com/en-us/windows/win32/wer/wer-settings",
                ],
            ))

        # Check LocalDumps configuration
        # DumpType: 0=Custom, 1=MiniDump, 2=FullDump
        dump_type = registry.read_value(
            registry.HKEY_LOCAL_MACHINE, _WER_LOCAL_DUMPS_PATH, "DumpType"
        )
        dump_folder = registry.read_value(
            registry.HKEY_LOCAL_MACHINE, _WER_LOCAL_DUMPS_PATH, "DumpFolder"
        )
        dump_count = registry.read_value(
            registry.HKEY_LOCAL_MACHINE, _WER_LOCAL_DUMPS_PATH, "DumpCount"
        )

        dump_evidence_parts: list[str] = []

        if dump_type is not None:
            type_names = {0: "Custom", 1: "MiniDump", 2: "FullDump"}
            type_name = type_names.get(dump_type.data, str(dump_type.data))
            dump_evidence_parts.append(f"DumpType: {dump_type.data} ({type_name})")

            if dump_type.data == 2:
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title="Full Memory Dumps Enabled in WER",
                    description=(
                        "Windows Error Reporting is configured to create full "
                        "memory dumps on application crashes. Full dumps contain "
                        "the complete process memory including credentials, "
                        "encryption keys, authentication tokens, and other "
                        "sensitive data. This data could be exfiltrated if an "
                        "attacker gains access to the dump files."
                    ),
                    severity=Severity.MEDIUM,
                    category=self.CATEGORY,
                    affected_item="WER LocalDumps",
                    evidence="\n".join(dump_evidence_parts),
                    recommendation=(
                        "Change DumpType to 1 (MiniDump) unless full dumps "
                        "are specifically required for debugging. Restrict "
                        "access to the dump folder with appropriate ACLs."
                    ),
                    references=[
                        "https://docs.microsoft.com/en-us/windows/win32/wer/collecting-user-mode-dumps",
                        "https://attack.mitre.org/techniques/T1003/001/",
                    ],
                ))
        else:
            dump_evidence_parts.append("DumpType: Not configured (default: MiniDump)")

        if dump_folder is not None:
            dump_evidence_parts.append(f"DumpFolder: {dump_folder.data}")
        else:
            dump_evidence_parts.append(
                "DumpFolder: Not configured (default: %LOCALAPPDATA%\\CrashDumps)"
            )

        if dump_count is not None:
            dump_evidence_parts.append(f"DumpCount: {dump_count.data}")
        else:
            dump_evidence_parts.append("DumpCount: Not configured (default: 10)")

        # Check per-application LocalDumps overrides
        app_subkeys = registry.enumerate_subkeys(
            registry.HKEY_LOCAL_MACHINE, _WER_LOCAL_DUMPS_PATH
        )

        app_full_dumps: list[str] = []
        for app_name in app_subkeys:
            app_path = f"{_WER_LOCAL_DUMPS_PATH}\\{app_name}"
            app_dump_type = registry.read_value(
                registry.HKEY_LOCAL_MACHINE, app_path, "DumpType"
            )
            if app_dump_type and app_dump_type.data == 2:
                app_full_dumps.append(app_name)

        if app_full_dumps:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Per-Application Full Dumps Configured",
                description=(
                    f"{len(app_full_dumps)} application(s) have per-application "
                    f"full memory dump overrides configured. Full dumps for "
                    f"specific applications may be used to extract credentials "
                    f"from security-sensitive processes."
                ),
                severity=Severity.MEDIUM,
                category=self.CATEGORY,
                affected_item="WER Per-Application Dumps",
                evidence=(
                    "Applications with full dump overrides:\n"
                    + "\n".join(f"  - {app}" for app in app_full_dumps)
                ),
                recommendation=(
                    "Review per-application dump configurations. Remove full "
                    "dump settings for security-sensitive applications like "
                    "lsass.exe, credential providers, and web browsers."
                ),
                references=[
                    "https://docs.microsoft.com/en-us/windows/win32/wer/collecting-user-mode-dumps",
                    "https://attack.mitre.org/techniques/T1003/001/",
                ],
            ))

        # Check consent settings
        consent_default = registry.read_value(
            registry.HKEY_LOCAL_MACHINE, _WER_CONSENT_PATH, "DefaultConsent"
        )

        if consent_default is not None:
            # DefaultConsent: 1=Always Ask, 2=Parameters Only, 3=Parameters and Safe Data, 4=All Data
            consent_names = {
                1: "Always Ask",
                2: "Parameters Only",
                3: "Parameters and Safe Data",
                4: "All Data (including memory dumps)",
            }
            consent_name = consent_names.get(
                consent_default.data, str(consent_default.data)
            )
            dump_evidence_parts.append(
                f"Consent Level: {consent_default.data} ({consent_name})"
            )

            if consent_default.data == 4:
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title="WER Consent Set to Send All Data",
                    description=(
                        "WER consent is configured to send all data including "
                        "memory dumps without prompting. This may result in "
                        "sensitive information being transmitted to the WER "
                        "server endpoint."
                    ),
                    severity=Severity.LOW,
                    category=self.CATEGORY,
                    affected_item="WER Consent",
                    evidence=f"DefaultConsent: {consent_default.data} ({consent_name})",
                    recommendation=(
                        "Consider setting DefaultConsent to 1 (Always Ask) or "
                        "2 (Parameters Only) to limit data exposure."
                    ),
                    references=[
                        "https://docs.microsoft.com/en-us/windows/win32/wer/wer-settings",
                    ],
                ))

        # Summary finding
        findings.append(Finding(
            check_id=self.CHECK_ID,
            title="WER Configuration Summary",
            description="Windows Error Reporting configuration reviewed.",
            severity=Severity.INFO,
            category=self.CATEGORY,
            affected_item="WER Configuration",
            evidence="\n".join(dump_evidence_parts),
            recommendation="Review WER settings for appropriate privacy balance.",
            references=[
                "https://docs.microsoft.com/en-us/windows/win32/wer/wer-settings",
            ],
        ))

        return findings
