"""EVTLOG-001: Windows Event Log Configuration and Integrity Audit.

Checks the size, retention settings, and enabled status of critical
Windows event logs (Security, System, Application, PowerShell).
Analyzes event timestamps for gaps that may indicate log tampering
or service interruption.
"""

from __future__ import annotations

from vitia_invenire.checks.base import BaseCheck
from vitia_invenire.collectors.powershell import run_ps
from vitia_invenire.models import Category, Finding, Severity

# Minimum recommended log sizes in bytes
_MIN_LOG_SIZES: dict[str, int] = {
    "Security": 20 * 1024 * 1024,       # 20 MB
    "System": 10 * 1024 * 1024,          # 10 MB
    "Application": 10 * 1024 * 1024,     # 10 MB
    "Microsoft-Windows-PowerShell/Operational": 10 * 1024 * 1024,  # 10 MB
}

# Gap threshold in seconds (1 hour = 3600 seconds)
_GAP_THRESHOLD_SECONDS = 3600


class EventLogConfigCheck(BaseCheck):
    """Audit Windows Event Log configuration and integrity."""

    CHECK_ID = "EVTLOG-001"
    NAME = "Event Log Configuration Audit"
    DESCRIPTION = (
        "Checks size, retention, and enabled status of critical Windows "
        "event logs. Analyzes event timestamps for gaps exceeding 1 hour "
        "and backward time jumps that may indicate log tampering."
    )
    CATEGORY = Category.CONFIGURATION
    REQUIRES_ADMIN = False

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        # Query event log configurations
        log_config_cmd = (
            "Get-WinEvent -ListLog 'Security','System','Application',"
            "'Microsoft-Windows-PowerShell/Operational' "
            "-ErrorAction SilentlyContinue | "
            "Select-Object LogName, IsEnabled, MaximumSizeInBytes, "
            "LogMode, RecordCount, LastWriteTime, LogFilePath, "
            "@{Name='IsClassicLog';Expression={$_.IsClassicLog}}"
        )

        result = run_ps(log_config_cmd, timeout=15, as_json=True)

        if not result.success:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Unable to Query Event Log Configuration",
                description="Failed to query Windows Event Log configuration.",
                severity=Severity.MEDIUM,
                category=self.CATEGORY,
                affected_item="Event Logs",
                evidence=f"Error: {result.error or 'No output'}",
                recommendation="Verify access to Event Log configuration.",
                references=[
                    "https://attack.mitre.org/techniques/T1070/001/",
                ],
            ))
            return findings

        log_configs = result.json_output
        if log_configs is None:
            log_configs = []
        if isinstance(log_configs, dict):
            log_configs = [log_configs]

        disabled_logs: list[str] = []
        undersized_logs: list[dict[str, str]] = []
        config_evidence: list[str] = []

        for log in log_configs:
            log_name = str(log.get("LogName", "Unknown"))
            is_enabled = log.get("IsEnabled", True)
            max_size = log.get("MaximumSizeInBytes", 0)
            log_mode = str(log.get("LogMode", "Unknown"))
            record_count = log.get("RecordCount", 0)
            last_write = str(log.get("LastWriteTime", "Unknown"))
            log_path = str(log.get("LogFilePath", "Unknown"))

            if max_size is None:
                max_size = 0

            config_evidence.append(
                f"Log: {log_name}\n"
                f"  Enabled: {is_enabled}\n"
                f"  Max Size: {max_size} bytes ({max_size // (1024 * 1024)} MB)\n"
                f"  Mode: {log_mode}\n"
                f"  Records: {record_count}\n"
                f"  Last Write: {last_write}\n"
                f"  Path: {log_path}"
            )

            # Check if critical log is disabled
            if not is_enabled:
                disabled_logs.append(log_name)

            # Check if log size meets minimum recommendations
            min_size = _MIN_LOG_SIZES.get(log_name, 0)
            if min_size > 0 and max_size < min_size:
                undersized_logs.append({
                    "log_name": log_name,
                    "current_size_mb": str(max_size // (1024 * 1024)),
                    "recommended_size_mb": str(min_size // (1024 * 1024)),
                })

        # Report disabled critical logs
        if disabled_logs:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Critical Event Log Disabled",
                description=(
                    f"{len(disabled_logs)} critical event log(s) are disabled. "
                    f"This severely impacts forensic capability and may indicate "
                    f"an attacker has disabled logging to hide activity."
                ),
                severity=Severity.HIGH,
                category=self.CATEGORY,
                affected_item="Disabled Event Logs",
                evidence=f"Disabled logs: {', '.join(disabled_logs)}",
                recommendation=(
                    "Immediately re-enable all critical event logs. Investigate "
                    "when and how logging was disabled. Check for signs of "
                    "log clearing (Event ID 1102 in Security log)."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1562/002/",
                    "https://attack.mitre.org/techniques/T1070/001/",
                ],
            ))

        # Report undersized logs
        if undersized_logs:
            evidence_lines = []
            for entry in undersized_logs:
                evidence_lines.append(
                    f"  {entry['log_name']}: {entry['current_size_mb']} MB "
                    f"(recommended: {entry['recommended_size_mb']} MB)"
                )

            # Security log under 20 MB is MEDIUM; others are LOW
            has_small_security = any(
                e["log_name"] == "Security" for e in undersized_logs
            )
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Event Log Size Below Recommendation",
                description=(
                    f"{len(undersized_logs)} event log(s) have maximum sizes "
                    f"below recommended minimums. Small log sizes cause rapid "
                    f"rotation and loss of historical forensic data."
                ),
                severity=Severity.MEDIUM if has_small_security else Severity.LOW,
                category=self.CATEGORY,
                affected_item="Event Log Sizes",
                evidence="\n".join(evidence_lines),
                recommendation=(
                    "Increase event log maximum sizes to at least the "
                    "recommended minimums: Security >= 20 MB, "
                    "System/Application/PowerShell >= 10 MB. Consider "
                    "central log forwarding for long-term retention."
                ),
                references=[
                    "https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-log-management",
                ],
            ))

        # Configuration summary
        findings.append(Finding(
            check_id=self.CHECK_ID,
            title="Event Log Configuration Summary",
            description=f"Reviewed configuration for {len(log_configs)} event log(s).",
            severity=Severity.INFO,
            category=self.CATEGORY,
            affected_item="Event Logs",
            evidence="\n\n".join(config_evidence),
            recommendation="Review event log sizes and retention settings.",
            references=[
                "https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-log-management",
            ],
        ))

        # Analyze timestamps for gaps and anomalies in critical logs
        for log_name in ["Security", "System"]:
            gap_cmd = (
                f"try {{ "
                f"  $events = Get-WinEvent -LogName '{log_name}' -MaxEvents 5000 "
                f"    -ErrorAction Stop | "
                f"    Sort-Object TimeCreated | "
                f"    Select-Object -ExpandProperty TimeCreated; "
                f"  $gaps = @(); "
                f"  $backward = @(); "
                f"  for ($i = 1; $i -lt $events.Count; $i++) {{ "
                f"    $diff = ($events[$i] - $events[$i-1]).TotalSeconds; "
                f"    if ($diff -lt 0) {{ "
                f"      $backward += [PSCustomObject]@{{ "
                f"        Before = $events[$i-1].ToString('o'); "
                f"        After = $events[$i].ToString('o'); "
                f"        DiffSeconds = [math]::Round($diff, 0) "
                f"      }}; "
                f"    }} elseif ($diff -gt {_GAP_THRESHOLD_SECONDS}) {{ "
                f"      $gaps += [PSCustomObject]@{{ "
                f"        GapStart = $events[$i-1].ToString('o'); "
                f"        GapEnd = $events[$i].ToString('o'); "
                f"        DiffSeconds = [math]::Round($diff, 0) "
                f"      }}; "
                f"    }} "
                f"  }}; "
                f"  [PSCustomObject]@{{ "
                f"    LogName = '{log_name}'; "
                f"    EventCount = $events.Count; "
                f"    FirstEvent = $events[0].ToString('o'); "
                f"    LastEvent = $events[-1].ToString('o'); "
                f"    Gaps = $gaps; "
                f"    BackwardJumps = $backward "
                f"  }} "
                f"}} catch {{ "
                f"  [PSCustomObject]@{{ "
                f"    LogName = '{log_name}'; "
                f"    Error = $_.Exception.Message "
                f"  }} "
                f"}}"
            )

            gap_result = run_ps(gap_cmd, timeout=30, as_json=True)

            if not gap_result.success or not gap_result.json_output:
                continue

            gap_data = gap_result.json_output
            if isinstance(gap_data, list):
                gap_data = gap_data[0] if gap_data else {}

            if gap_data.get("Error"):
                continue

            gaps = gap_data.get("Gaps", [])
            backward_jumps = gap_data.get("BackwardJumps", [])
            event_count = gap_data.get("EventCount", 0)

            if isinstance(gaps, dict):
                gaps = [gaps]
            if isinstance(backward_jumps, dict):
                backward_jumps = [backward_jumps]

            # Report timestamp gaps
            if gaps:
                evidence_lines = []
                for gap in gaps[:20]:
                    diff_hours = int(gap.get("DiffSeconds", 0)) / 3600
                    evidence_lines.append(
                        f"  Gap: {gap.get('GapStart', '?')} to "
                        f"{gap.get('GapEnd', '?')} "
                        f"({diff_hours:.1f} hours)"
                    )
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title=f"Timestamp Gaps Detected in {log_name} Log",
                    description=(
                        f"{len(gaps)} gap(s) exceeding 1 hour detected in the "
                        f"{log_name} event log across {event_count} events. "
                        f"Large gaps may indicate the event log service was "
                        f"stopped, logs were cleared, or timestamps were "
                        f"manipulated."
                    ),
                    severity=Severity.MEDIUM,
                    category=self.CATEGORY,
                    affected_item=f"{log_name} Event Log",
                    evidence="\n".join(evidence_lines),
                    recommendation=(
                        "Investigate the cause of each gap. Check if the system "
                        "was powered off, the event log service was restarted, "
                        "or if logs were cleared. Correlate with Event ID 1102 "
                        "(audit log cleared) and Event ID 6005/6006 (service "
                        "start/stop)."
                    ),
                    references=[
                        "https://attack.mitre.org/techniques/T1070/001/",
                    ],
                ))

            # Report backward time jumps
            if backward_jumps:
                evidence_lines = []
                for jump in backward_jumps[:20]:
                    evidence_lines.append(
                        f"  Time went backward: {jump.get('Before', '?')} -> "
                        f"{jump.get('After', '?')} "
                        f"(delta: {jump.get('DiffSeconds', 0)} seconds)"
                    )
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title=f"Backward Time Jumps in {log_name} Log",
                    description=(
                        f"{len(backward_jumps)} backward time jump(s) detected "
                        f"in the {log_name} event log. Events appearing out of "
                        f"chronological order may indicate timestamp manipulation, "
                        f"log injection, or system clock tampering."
                    ),
                    severity=Severity.HIGH,
                    category=self.CATEGORY,
                    affected_item=f"{log_name} Event Log",
                    evidence="\n".join(evidence_lines),
                    recommendation=(
                        "Investigate each backward time jump. Check for NTP "
                        "clock sync events, time zone changes, or deliberate "
                        "timestamp manipulation. Cross-reference with other "
                        "log sources."
                    ),
                    references=[
                        "https://attack.mitre.org/techniques/T1070/006/",
                    ],
                ))

        return findings
