"""EVTLOG-002: Security Event Forensic Analysis.

Analyzes Security event log for indicators of compromise including
log clearing, suspicious account creation, brute force patterns,
and suspicious service installations. Also checks PowerShell script
block logging for known malicious patterns.
"""

from __future__ import annotations

import re
from collections import Counter

from vitia_invenire.checks.base import BaseCheck
from vitia_invenire.collectors.powershell import run_ps
from vitia_invenire.models import Category, Finding, Severity

# Suspicious service path patterns (case-insensitive)
_SUSPICIOUS_SERVICE_PATHS: list[str] = [
    r"\\temp\\",
    r"\\tmp\\",
    r"\\appdata\\",
    r"\\users\\[^\\]+\\downloads\\",
    r"\\users\\[^\\]+\\desktop\\",
    r"\\users\\[^\\]+\\documents\\",
    r"-enc\s",
    r"-encodedcommand\s",
    r"powershell.*-e\s+[A-Za-z0-9+/=]{20,}",
    r"cmd\.exe.*/c.*powershell",
]

# Suspicious PowerShell script block patterns (case-insensitive)
_SUSPICIOUS_PS_PATTERNS: list[str] = [
    r"-enc\b",
    r"FromBase64String",
    r"Invoke-Expression",
    r"\biex\b",
    r"downloadstring",
    r"Net\.WebClient",
    r"bypass",
    r"hidden",
]


class SecurityEventsCheck(BaseCheck):
    """Analyze Security event log for indicators of compromise."""

    CHECK_ID = "EVTLOG-002"
    NAME = "Security Event Forensic Analysis"
    DESCRIPTION = (
        "Analyzes Security event log for indicators of compromise including "
        "log clearing, suspicious account creation, brute force patterns, "
        "and suspicious service installations."
    )
    CATEGORY = Category.CONFIGURATION
    REQUIRES_ADMIN = True

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        summary_parts: list[str] = []

        self._check_log_cleared(findings, summary_parts)
        self._check_account_events(findings, summary_parts)
        self._check_brute_force(findings, summary_parts)
        self._check_suspicious_services(findings, summary_parts)
        self._check_suspicious_powershell(findings, summary_parts)

        # INFO summary finding
        findings.append(Finding(
            check_id=self.CHECK_ID,
            title="Security Event Forensic Analysis Summary",
            description=(
                "Completed forensic analysis of Security, System, and "
                "PowerShell event logs for indicators of compromise."
            ),
            severity=Severity.INFO,
            category=self.CATEGORY,
            affected_item="Security Event Logs",
            evidence="\n".join(summary_parts) if summary_parts else "No issues detected.",
            recommendation=(
                "Review any flagged events in detail. Correlate findings with "
                "other checks and external threat intelligence."
            ),
            references=[
                "https://attack.mitre.org/techniques/T1070/001/",
                "https://attack.mitre.org/techniques/T1110/",
                "https://attack.mitre.org/techniques/T1543/003/",
            ],
        ))

        return findings

    def _check_log_cleared(
        self,
        findings: list[Finding],
        summary_parts: list[str],
    ) -> None:
        """Check for Security audit log cleared events (Event ID 1102)."""
        result = run_ps(
            "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=1102} "
            "-MaxEvents 10 -ErrorAction SilentlyContinue | "
            "Select-Object TimeCreated, "
            "@{N='SubjectUserName';E={$_.Properties[1].Value}}, Message",
            timeout=30,
            as_json=True,
        )

        if not result.success:
            summary_parts.append("Log cleared check: unable to query (may require elevated access)")
            return

        events = result.json_output
        if events is None:
            summary_parts.append("Log cleared check: no Event ID 1102 events found")
            return

        if isinstance(events, dict):
            events = [events]

        if not events:
            summary_parts.append("Log cleared check: no Event ID 1102 events found")
            return

        evidence_lines: list[str] = []
        for event in events:
            time_created = str(event.get("TimeCreated", "Unknown"))
            subject_user = str(event.get("SubjectUserName", "Unknown"))
            evidence_lines.append(
                f"  Time: {time_created}, User: {subject_user}"
            )

        findings.append(Finding(
            check_id=self.CHECK_ID,
            title="Security audit log was cleared",
            description=(
                f"The Security event log was cleared {len(events)} time(s). "
                "Audit log clearing is a strong indicator of an attacker "
                "attempting to cover their tracks. Event ID 1102 records "
                "each instance of log clearing."
            ),
            severity=Severity.CRITICAL,
            category=self.CATEGORY,
            affected_item="Security Event Log",
            evidence=f"Event ID 1102 occurrences:\n" + "\n".join(evidence_lines),
            recommendation=(
                "Investigate who cleared the log and when. Review other log "
                "sources (System, Application, Sysmon) for activity around "
                "the clearing timestamps. Implement log forwarding to prevent "
                "local log destruction."
            ),
            references=[
                "https://attack.mitre.org/techniques/T1070/001/",
            ],
        ))

        summary_parts.append(
            f"Log cleared check: {len(events)} clearing event(s) detected (CRITICAL)"
        )

    def _check_account_events(
        self,
        findings: list[Finding],
        summary_parts: list[str],
    ) -> None:
        """Check for suspicious account creation and modification events."""
        result = run_ps(
            "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4720,4722,4732} "
            "-MaxEvents 50 -ErrorAction SilentlyContinue | "
            "Select-Object Id, TimeCreated, "
            "@{N='TargetUserName';E={$_.Properties[0].Value}}, "
            "@{N='SubjectUserName';E={$_.Properties[4].Value}}, Message",
            timeout=30,
            as_json=True,
        )

        if not result.success:
            summary_parts.append("Account events check: unable to query")
            return

        events = result.json_output
        if events is None:
            summary_parts.append("Account events check: no account modification events found")
            return

        if isinstance(events, dict):
            events = [events]

        if not events:
            summary_parts.append("Account events check: no account modification events found")
            return

        # Categorize events by type
        event_type_map = {
            4720: "Account Created",
            4722: "Account Enabled",
            4732: "Member Added to Security Group",
        }

        evidence_lines: list[str] = []
        type_counts: Counter[str] = Counter()
        for event in events:
            event_id = event.get("Id", 0)
            time_created = str(event.get("TimeCreated", "Unknown"))
            target_user = str(event.get("TargetUserName", "Unknown"))
            subject_user = str(event.get("SubjectUserName", "Unknown"))
            event_type = event_type_map.get(event_id, f"Event {event_id}")
            type_counts[event_type] += 1
            evidence_lines.append(
                f"  [{event_type}] Time: {time_created}, "
                f"Target: {target_user}, By: {subject_user}"
            )

        type_summary = ", ".join(
            f"{count} {etype}" for etype, count in type_counts.items()
        )

        findings.append(Finding(
            check_id=self.CHECK_ID,
            title="Account modification events detected",
            description=(
                f"Detected {len(events)} account modification event(s): "
                f"{type_summary}. These events may indicate unauthorized "
                "account creation, privilege escalation, or persistence "
                "establishment by an attacker."
            ),
            severity=Severity.HIGH,
            category=self.CATEGORY,
            affected_item="User Accounts",
            evidence="\n".join(evidence_lines),
            recommendation=(
                "Review each account modification event. Verify that all "
                "account creations and group membership changes were "
                "authorized. Check for accounts created outside of normal "
                "provisioning workflows."
            ),
            references=[
                "https://attack.mitre.org/techniques/T1136/001/",
                "https://attack.mitre.org/techniques/T1098/",
            ],
        ))

        summary_parts.append(
            f"Account events check: {len(events)} modification event(s) detected (HIGH)"
        )

    def _check_brute_force(
        self,
        findings: list[Finding],
        summary_parts: list[str],
    ) -> None:
        """Check for brute force patterns via failed logon events (4625)."""
        result = run_ps(
            "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} "
            "-MaxEvents 200 -ErrorAction SilentlyContinue | "
            "Select-Object TimeCreated, "
            "@{N='TargetUserName';E={$_.Properties[5].Value}}, "
            "@{N='LogonType';E={$_.Properties[10].Value}}, "
            "@{N='FailureReason';E={$_.Properties[8].Value}}, "
            "@{N='WorkstationName';E={$_.Properties[13].Value}}, "
            "@{N='SourceIP';E={$_.Properties[19].Value}}",
            timeout=30,
            as_json=True,
        )

        if not result.success:
            summary_parts.append("Brute force check: unable to query")
            return

        events = result.json_output
        if events is None:
            summary_parts.append("Brute force check: no failed logon events found")
            return

        if isinstance(events, dict):
            events = [events]

        if not events:
            summary_parts.append("Brute force check: no failed logon events found")
            return

        total_failures = len(events)

        if total_failures <= 20:
            summary_parts.append(
                f"Brute force check: {total_failures} failed logon(s) (below threshold)"
            )
            return

        # Count failures per user
        user_counts: Counter[str] = Counter()
        source_counts: Counter[str] = Counter()
        for event in events:
            target_user = str(event.get("TargetUserName", "Unknown"))
            source_ip = str(event.get("SourceIP", "Unknown"))
            user_counts[target_user] += 1
            if source_ip and source_ip not in ("Unknown", "-", ""):
                source_counts[source_ip] += 1

        evidence_lines: list[str] = [
            f"Total failed logon events: {total_failures}",
            "",
            "Failed logons by user:",
        ]
        for user, count in user_counts.most_common(10):
            evidence_lines.append(f"  {user}: {count} failure(s)")

        if source_counts:
            evidence_lines.append("")
            evidence_lines.append("Failed logons by source IP:")
            for ip, count in source_counts.most_common(10):
                evidence_lines.append(f"  {ip}: {count} failure(s)")

        # Show sample events
        evidence_lines.append("")
        evidence_lines.append("Sample events:")
        for event in events[:5]:
            time_created = str(event.get("TimeCreated", "Unknown"))
            target_user = str(event.get("TargetUserName", "Unknown"))
            logon_type = str(event.get("LogonType", "Unknown"))
            source_ip = str(event.get("SourceIP", "Unknown"))
            workstation = str(event.get("WorkstationName", "Unknown"))
            evidence_lines.append(
                f"  Time: {time_created}, User: {target_user}, "
                f"Type: {logon_type}, Source: {source_ip}, "
                f"Workstation: {workstation}"
            )

        findings.append(Finding(
            check_id=self.CHECK_ID,
            title="Potential brute force activity",
            description=(
                f"Detected {total_failures} failed logon events (Event ID 4625) "
                f"across {len(user_counts)} user account(s). More than 20 "
                "failed logons may indicate brute force password guessing, "
                "credential stuffing, or automated attack tools."
            ),
            severity=Severity.HIGH,
            category=self.CATEGORY,
            affected_item="Authentication",
            evidence="\n".join(evidence_lines),
            recommendation=(
                "Investigate the source of failed logon attempts. If from "
                "external IPs, consider blocking at the firewall. Enable "
                "account lockout policies. Review for compromised credentials."
            ),
            references=[
                "https://attack.mitre.org/techniques/T1110/",
            ],
        ))

        summary_parts.append(
            f"Brute force check: {total_failures} failed logon(s) detected (HIGH)"
        )

    def _check_suspicious_services(
        self,
        findings: list[Finding],
        summary_parts: list[str],
    ) -> None:
        """Check for suspicious service installations (Event ID 7045)."""
        result = run_ps(
            "Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045} "
            "-MaxEvents 50 -ErrorAction SilentlyContinue | "
            "Select-Object TimeCreated, "
            "@{N='ServiceName';E={$_.Properties[0].Value}}, "
            "@{N='ImagePath';E={$_.Properties[1].Value}}, "
            "@{N='ServiceType';E={$_.Properties[2].Value}}, "
            "@{N='StartType';E={$_.Properties[3].Value}}, "
            "@{N='AccountName';E={$_.Properties[4].Value}}",
            timeout=30,
            as_json=True,
        )

        if not result.success:
            summary_parts.append("Service installation check: unable to query")
            return

        events = result.json_output
        if events is None:
            summary_parts.append("Service installation check: no new service events found")
            return

        if isinstance(events, dict):
            events = [events]

        if not events:
            summary_parts.append("Service installation check: no new service events found")
            return

        suspicious_services: list[dict[str, str]] = []

        for event in events:
            service_name = str(event.get("ServiceName", "Unknown"))
            image_path = str(event.get("ImagePath", ""))
            time_created = str(event.get("TimeCreated", "Unknown"))
            account_name = str(event.get("AccountName", "Unknown"))
            start_type = str(event.get("StartType", "Unknown"))

            # Check for suspicious patterns in the image path
            is_suspicious = False
            matched_reason = ""
            image_path_lower = image_path.lower()

            for pattern in _SUSPICIOUS_SERVICE_PATHS:
                if re.search(pattern, image_path_lower):
                    is_suspicious = True
                    matched_reason = f"Path matches suspicious pattern: {pattern}"
                    break

            if is_suspicious:
                suspicious_services.append({
                    "service_name": service_name,
                    "image_path": image_path,
                    "time_created": time_created,
                    "account_name": account_name,
                    "start_type": start_type,
                    "reason": matched_reason,
                })

        if suspicious_services:
            evidence_lines: list[str] = []
            for svc in suspicious_services:
                evidence_lines.append(
                    f"  Service: {svc['service_name']}\n"
                    f"    Path: {svc['image_path']}\n"
                    f"    Time: {svc['time_created']}\n"
                    f"    Account: {svc['account_name']}\n"
                    f"    Start Type: {svc['start_type']}\n"
                    f"    Reason: {svc['reason']}"
                )

            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Suspicious service installations detected",
                description=(
                    f"Detected {len(suspicious_services)} service installation(s) "
                    "with suspicious image paths (temp directories, user profiles, "
                    "or encoded commands). Malicious services are a common "
                    "persistence mechanism in supply chain attacks."
                ),
                severity=Severity.HIGH,
                category=self.CATEGORY,
                affected_item="Service Installations",
                evidence="\n".join(evidence_lines),
                recommendation=(
                    "Investigate each flagged service. Verify the service binary "
                    "is legitimate. Remove unauthorized services and investigate "
                    "how they were installed."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1543/003/",
                    "https://attack.mitre.org/techniques/T1569/002/",
                ],
            ))

        summary_parts.append(
            f"Service installation check: {len(events)} total, "
            f"{len(suspicious_services)} suspicious"
            + (" (HIGH)" if suspicious_services else "")
        )

    def _check_suspicious_powershell(
        self,
        findings: list[Finding],
        summary_parts: list[str],
    ) -> None:
        """Check PowerShell script block logging for suspicious patterns."""
        result = run_ps(
            "Get-WinEvent -FilterHashtable "
            "@{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104} "
            "-MaxEvents 100 -ErrorAction SilentlyContinue | "
            "Select-Object TimeCreated, "
            "@{N='ScriptBlock';E={$_.Properties[2].Value}}",
            timeout=30,
            as_json=True,
        )

        if not result.success:
            summary_parts.append("PowerShell script block check: unable to query")
            return

        events = result.json_output
        if events is None:
            summary_parts.append(
                "PowerShell script block check: no script block events found"
            )
            return

        if isinstance(events, dict):
            events = [events]

        if not events:
            summary_parts.append(
                "PowerShell script block check: no script block events found"
            )
            return

        # Build combined regex pattern for suspicious indicators
        combined_pattern = "|".join(_SUSPICIOUS_PS_PATTERNS)

        suspicious_blocks: list[dict[str, str]] = []

        for event in events:
            script_block = str(event.get("ScriptBlock", ""))
            time_created = str(event.get("TimeCreated", "Unknown"))

            if not script_block.strip():
                continue

            matches = re.findall(combined_pattern, script_block, re.IGNORECASE)
            if matches:
                # Truncate long script blocks to 500 characters
                preview = script_block[:500]
                if len(script_block) > 500:
                    preview += "... (truncated)"

                suspicious_blocks.append({
                    "time_created": time_created,
                    "matched_patterns": ", ".join(sorted(set(matches))),
                    "script_preview": preview,
                })

        if suspicious_blocks:
            evidence_lines: list[str] = []
            for block in suspicious_blocks[:10]:
                evidence_lines.append(
                    f"  Time: {block['time_created']}\n"
                    f"    Matched: {block['matched_patterns']}\n"
                    f"    Script: {block['script_preview']}"
                )

            if len(suspicious_blocks) > 10:
                evidence_lines.append(
                    f"  ... and {len(suspicious_blocks) - 10} more suspicious block(s)"
                )

            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Suspicious PowerShell script blocks detected",
                description=(
                    f"Detected {len(suspicious_blocks)} PowerShell script block(s) "
                    "containing suspicious patterns such as encoded commands, "
                    "base64 decoding, dynamic execution, or download cradles. "
                    "These patterns are commonly used in attack toolkits."
                ),
                severity=Severity.HIGH,
                category=self.CATEGORY,
                affected_item="PowerShell Script Block Log",
                evidence="\n".join(evidence_lines),
                recommendation=(
                    "Review each flagged script block in detail. Determine if "
                    "the PowerShell activity was authorized. Investigate the "
                    "user context and parent process of suspicious executions."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1059/001/",
                    "https://attack.mitre.org/techniques/T1027/",
                ],
            ))

        summary_parts.append(
            f"PowerShell script block check: {len(events)} block(s) analyzed, "
            f"{len(suspicious_blocks)} suspicious"
            + (" (HIGH)" if suspicious_blocks else "")
        )
