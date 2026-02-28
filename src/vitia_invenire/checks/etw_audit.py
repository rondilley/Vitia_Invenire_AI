"""ETW-001: Event Tracing for Windows (ETW) Session Audit.

Lists active ETW trace sessions via logman query -ets and checks for
missing critical sessions such as EventLog-Security and EventLog-System.
Verifies AutoLogger sessions in the registry for tamper detection.
Missing critical ETW sessions may indicate an attacker has disabled
logging to evade detection.
"""

from __future__ import annotations

from vitia_invenire.checks.base import BaseCheck
from vitia_invenire.collectors import registry
from vitia_invenire.collectors.command import run_cmd
from vitia_invenire.models import Category, Finding, Severity

# Critical ETW sessions that should always be running
_CRITICAL_SESSIONS = [
    "EventLog-Security",
    "EventLog-System",
    "EventLog-Application",
]

# Important but not critical sessions
_IMPORTANT_SESSIONS = [
    "EventLog-Microsoft-Windows-Sysmon/Operational",
    "EventLog-Microsoft-Windows-PowerShell/Operational",
    "Circular Kernel Context Logger",
    "DiagLog",
]

# AutoLogger registry path for session configurations
_AUTOLOGGER_BASE_PATH = "SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger"


class ETWAuditCheck(BaseCheck):
    """Audit ETW trace sessions for defense evasion detection."""

    CHECK_ID = "ETW-001"
    NAME = "ETW Session Audit"
    DESCRIPTION = (
        "Lists active ETW trace sessions and verifies that critical "
        "sessions (EventLog-Security, EventLog-System) are running. "
        "Checks AutoLogger registry configuration for tamper detection."
    )
    CATEGORY = Category.EVASION
    REQUIRES_ADMIN = True

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        # Query active ETW sessions via logman
        result = run_cmd(["logman", "query", "-ets"], timeout=30)

        active_sessions: list[str] = []
        raw_output = ""

        if result.success and result.stdout:
            raw_output = result.stdout
            # Parse logman output: session names are in lines that start
            # with a session name followed by status information.
            # Each data collection set line looks like:
            #   SessionName           Type     Status
            for line in result.stdout.splitlines():
                stripped = line.strip()
                if not stripped:
                    continue
                # Skip header lines and separator lines
                if stripped.startswith("Data Collector Set"):
                    continue
                if stripped.startswith("---"):
                    continue
                if stripped.startswith("The command completed"):
                    continue
                # Extract the session name (first column before whitespace)
                parts = stripped.split()
                if parts:
                    # Session names may contain spaces; but they appear
                    # before the Type column (Trace/Counter/Alert).
                    # We look for Trace type entries.
                    session_name_parts = []
                    for part in parts:
                        if part in ("Trace", "Counter", "Alert"):
                            break
                        session_name_parts.append(part)
                    if session_name_parts:
                        session_name = " ".join(session_name_parts)
                        active_sessions.append(session_name)
        else:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Unable to Query ETW Sessions",
                description=(
                    "The logman query -ets command failed. ETW session "
                    "auditing could not be performed."
                ),
                severity=Severity.MEDIUM,
                category=self.CATEGORY,
                affected_item="ETW Sessions",
                evidence=f"Error: {result.stderr or 'logman returned no output'}",
                recommendation=(
                    "Verify logman.exe is accessible and running with "
                    "administrator privileges."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1562/006/",
                ],
            ))
            return findings

        # Check for missing critical sessions
        active_lower = [s.lower() for s in active_sessions]
        missing_critical: list[str] = []
        for session in _CRITICAL_SESSIONS:
            if session.lower() not in active_lower:
                missing_critical.append(session)

        if missing_critical:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Critical ETW Session Missing",
                description=(
                    f"{len(missing_critical)} critical ETW session(s) are not "
                    f"running. This may indicate that an attacker has stopped "
                    f"event logging to evade detection, or the Windows Event "
                    f"Log service is malfunctioning."
                ),
                severity=Severity.HIGH,
                category=self.CATEGORY,
                affected_item="ETW Critical Sessions",
                evidence=(
                    f"Missing critical sessions: {', '.join(missing_critical)}\n\n"
                    f"Active sessions found: {', '.join(active_sessions[:50])}"
                ),
                recommendation=(
                    "Immediately investigate why critical ETW sessions are not "
                    "running. Restart the Windows Event Log service. Check for "
                    "signs of ETW tampering via EtwEventWrite patching or "
                    "provider disabling. Review for T1562.006 indicators."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1562/006/",
                    "https://docs.microsoft.com/en-us/windows/win32/etw/configuring-and-starting-an-autologger-session",
                ],
            ))

        # Check for missing important (but not critical) sessions
        missing_important: list[str] = []
        for session in _IMPORTANT_SESSIONS:
            if session.lower() not in active_lower:
                missing_important.append(session)

        if missing_important:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Important ETW Session Not Active",
                description=(
                    f"{len(missing_important)} recommended ETW session(s) are not "
                    f"running. These provide enhanced telemetry for security "
                    f"monitoring but are not always present on all systems."
                ),
                severity=Severity.LOW,
                category=self.CATEGORY,
                affected_item="ETW Important Sessions",
                evidence=f"Missing sessions: {', '.join(missing_important)}",
                recommendation=(
                    "Consider enabling these ETW sessions for improved security "
                    "visibility. Sysmon and PowerShell operational logging are "
                    "particularly valuable for threat detection."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1562/006/",
                ],
            ))

        # Verify AutoLogger registry configuration
        autologger_subkeys = registry.enumerate_subkeys(
            registry.HKEY_LOCAL_MACHINE, _AUTOLOGGER_BASE_PATH
        )

        disabled_autologgers: list[str] = []
        for subkey in autologger_subkeys:
            start_value = registry.read_value(
                registry.HKEY_LOCAL_MACHINE,
                f"{_AUTOLOGGER_BASE_PATH}\\{subkey}",
                "Start",
            )
            if start_value and start_value.data == 0:
                disabled_autologgers.append(subkey)

        # Check specifically for critical autologgers being disabled
        critical_disabled: list[str] = []
        for session_name in _CRITICAL_SESSIONS:
            if session_name in disabled_autologgers:
                critical_disabled.append(session_name)

        if critical_disabled:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Critical AutoLogger Session Disabled in Registry",
                description=(
                    f"{len(critical_disabled)} critical AutoLogger session(s) "
                    f"have their Start value set to 0 (disabled) in the registry. "
                    f"This prevents the session from starting automatically on boot, "
                    f"which is a defense evasion technique."
                ),
                severity=Severity.HIGH,
                category=self.CATEGORY,
                affected_item="AutoLogger Registry Configuration",
                evidence=(
                    f"Disabled critical AutoLoggers: {', '.join(critical_disabled)}\n"
                    f"Registry path: HKLM\\{_AUTOLOGGER_BASE_PATH}"
                ),
                recommendation=(
                    "Re-enable disabled critical AutoLogger sessions by setting "
                    "the Start DWORD value to 1 under "
                    f"HKLM\\{_AUTOLOGGER_BASE_PATH}\\<SessionName>. "
                    "Investigate the timeline of when the change occurred."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1562/006/",
                    "https://docs.microsoft.com/en-us/windows/win32/etw/configuring-and-starting-an-autologger-session",
                ],
            ))

        if disabled_autologgers and not critical_disabled:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Non-Critical AutoLogger Sessions Disabled",
                description=(
                    f"{len(disabled_autologgers)} AutoLogger session(s) are "
                    f"disabled in the registry. While these may not be critical, "
                    f"disabled sessions reduce telemetry coverage."
                ),
                severity=Severity.LOW,
                category=self.CATEGORY,
                affected_item="AutoLogger Registry Configuration",
                evidence=(
                    f"Disabled AutoLoggers: {', '.join(disabled_autologgers[:20])}"
                ),
                recommendation=(
                    "Review disabled AutoLogger sessions and re-enable any that "
                    "provide valuable security telemetry."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1562/006/",
                ],
            ))

        # Summary of active sessions
        findings.append(Finding(
            check_id=self.CHECK_ID,
            title="ETW Session Inventory",
            description=f"Found {len(active_sessions)} active ETW trace session(s).",
            severity=Severity.INFO,
            category=self.CATEGORY,
            affected_item="ETW Sessions",
            evidence=(
                f"Active sessions ({len(active_sessions)}):\n"
                + "\n".join(f"  - {s}" for s in active_sessions[:100])
                + (f"\n  ... and {len(active_sessions) - 100} more"
                   if len(active_sessions) > 100 else "")
                + f"\n\nAutoLogger entries: {len(autologger_subkeys)}"
                + f"\nDisabled AutoLoggers: {len(disabled_autologgers)}"
            ),
            recommendation="Review active ETW sessions for completeness.",
            references=[
                "https://attack.mitre.org/techniques/T1562/006/",
            ],
        ))

        return findings
