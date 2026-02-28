"""TASK-001: Scheduled tasks security assessment.

Enumerates scheduled tasks via Get-ScheduledTask and flags tasks
that execute suspicious binaries (PowerShell, scripting engines,
LOLBins) or non-Microsoft network-related tasks.
"""

from __future__ import annotations

import re

from vitia_invenire.checks.base import BaseCheck
from vitia_invenire.collectors.powershell import run_ps
from vitia_invenire.models import Category, Finding, Severity

# Suspicious executables that are commonly abused in scheduled task persistence
_SUSPICIOUS_BINARIES: dict[str, str] = {
    "powershell": "PowerShell interpreter - commonly used for fileless malware",
    "pwsh": "PowerShell Core - cross-platform PowerShell",
    "wscript": "Windows Script Host - executes VBScript/JScript files",
    "cscript": "Windows Script Host (console) - executes VBScript/JScript files",
    "mshta": "Microsoft HTML Application Host - executes HTA files for code execution",
    "certutil": "Certificate utility - frequently abused for file download and encoding",
    "bitsadmin": "BITS Admin - abused for file download and persistence",
    "regsvr32": "Register Server - can load remote DLLs for code execution",
    "rundll32": "Run DLL - executes DLL exports, commonly abused by malware",
    "msiexec": "Windows Installer - can install packages from remote URLs",
    "cmd": "Command Prompt - can chain arbitrary commands",
    "cmd.exe": "Command Prompt - can chain arbitrary commands",
    "wmic": "WMI Command-line - can execute commands and queries remotely",
    "msbuild": "MSBuild - can compile and run inline C# code",
    "installutil": "Install Util - can execute code via custom installer classes",
    "regasm": "Register Assembly - can execute code during registration",
    "regsvcs": "Register Services - can execute code during registration",
}

# Suspicious command-line patterns in task actions
_SUSPICIOUS_PATTERNS: list[tuple[str, str]] = [
    (r"-[Ee]nc(?:oded)?[Cc]ommand", "Encoded PowerShell command - obfuscation technique"),
    (r"[Hh]idden[Ww]indow|[Ww]indow[Ss]tyle\s+[Hh]idden", "Hidden window execution"),
    (r"[Bb]ypass|-[Ee]xecutionpolicy\s+[Bb]ypass", "Execution policy bypass"),
    (r"[Ii]nvoke-[Ww]eb[Rr]equest|wget|curl|[Nn]et\.[Ww]eb[Cc]lient", "Network download activity"),
    (r"[Ss]tart-[Bb]its[Tt]ransfer", "BITS transfer - alternative download method"),
    (r"[Nn]ew-[Oo]bject\s+[Ss]ystem\.[Nn]et", "Network object creation"),
    (r"[Ff]rom[Bb]ase64", "Base64 decoding - common obfuscation"),
]


class ScheduledTasksCheck(BaseCheck):
    """Analyze scheduled tasks for persistence and malicious activity."""

    CHECK_ID = "TASK-001"
    NAME = "Scheduled Tasks Audit"
    DESCRIPTION = (
        "Enumerates scheduled tasks and flags tasks that execute "
        "suspicious binaries (PowerShell, scripting engines, LOLBins) "
        "or non-Microsoft tasks with network activity."
    )
    CATEGORY = Category.PERSISTENCE
    REQUIRES_ADMIN = False

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        result = run_ps(
            "Get-ScheduledTask | ForEach-Object { "
            "$task = $_; "
            "$actions = $task.Actions | ForEach-Object { "
            "@{ Execute=$_.Execute; Arguments=$_.Arguments; WorkingDirectory=$_.WorkingDirectory } "
            "}; "
            "@{ "
            "TaskName=$task.TaskName; "
            "TaskPath=$task.TaskPath; "
            "State=$task.State.ToString(); "
            "Author=$task.Author; "
            "Description=$task.Description; "
            "Actions=$actions; "
            "Source=$task.Source; "
            "Date=$task.Date "
            "} }",
            timeout=60,
            as_json=True,
        )

        if not result.success or result.json_output is None:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Failed to enumerate scheduled tasks",
                description=f"Get-ScheduledTask failed: {result.error or 'unknown error'}",
                severity=Severity.MEDIUM,
                category=self.CATEGORY,
                affected_item="Scheduled Tasks",
                evidence=result.output[:500] if result.output else "No output",
                recommendation="Run the assessment with appropriate privileges.",
            ))
            return findings

        tasks = result.json_output
        if isinstance(tasks, dict):
            tasks = [tasks]

        total_tasks = len(tasks)
        suspicious_count = 0
        non_ms_network_count = 0

        for task in tasks:
            task_name = str(task.get("TaskName", "Unknown"))
            task_path = str(task.get("TaskPath", ""))
            state = str(task.get("State", "Unknown"))
            author = str(task.get("Author", ""))
            description = str(task.get("Description", ""))
            actions = task.get("Actions", [])
            date = str(task.get("Date", ""))

            if actions is None:
                actions = []
            if isinstance(actions, dict):
                actions = [actions]

            is_microsoft = (
                "microsoft" in author.lower() or
                task_path.lower().startswith("\\microsoft\\")
            )

            full_task_id = f"{task_path}{task_name}"

            for action in actions:
                execute = str(action.get("Execute", ""))
                arguments = str(action.get("Arguments", ""))
                working_dir = str(action.get("WorkingDirectory", ""))

                exe_name = execute.rsplit("\\", 1)[-1].lower() if execute else ""
                exe_name_no_ext = exe_name.replace(".exe", "")

                # Check for suspicious binaries
                matched_binary = None
                for binary, binary_desc in _SUSPICIOUS_BINARIES.items():
                    if binary in exe_name_no_ext:
                        matched_binary = (binary, binary_desc)
                        break

                if matched_binary and not is_microsoft:
                    binary_name, binary_desc = matched_binary
                    suspicious_count += 1

                    # Check for additional suspicious patterns in arguments
                    pattern_matches: list[str] = []
                    for pattern, pattern_desc in _SUSPICIOUS_PATTERNS:
                        if re.search(pattern, arguments):
                            pattern_matches.append(pattern_desc)

                    severity = Severity.HIGH
                    if pattern_matches:
                        severity = Severity.HIGH

                    findings.append(Finding(
                        check_id=self.CHECK_ID,
                        title=f"Suspicious scheduled task: {task_name}",
                        description=(
                            f"Scheduled task '{task_name}' executes {binary_name} "
                            f"({binary_desc}). "
                            f"{'Additional suspicious patterns: ' + ', '.join(pattern_matches) + '. ' if pattern_matches else ''}"
                            f"Author: {author}."
                        ),
                        severity=severity,
                        category=self.CATEGORY,
                        affected_item=full_task_id,
                        evidence=(
                            f"Task: {full_task_id}\n"
                            f"State: {state}\n"
                            f"Author: {author}\n"
                            f"Execute: {execute}\n"
                            f"Arguments: {arguments[:500] if arguments else 'None'}\n"
                            f"Working Directory: {working_dir}\n"
                            f"Created: {date}\n"
                            f"Description: {description[:200] if description else 'None'}"
                        ),
                        recommendation=(
                            f"Investigate scheduled task '{task_name}'. "
                            "Verify the task author and purpose. If unauthorized: "
                            f"Unregister-ScheduledTask -TaskName '{task_name}' -Confirm:$false"
                        ),
                        references=[
                            "https://attack.mitre.org/techniques/T1053/005/",
                        ],
                    ))

                # Check for non-Microsoft tasks with network-related activities
                if not is_microsoft and not matched_binary:
                    full_cmd = f"{execute} {arguments}".lower()
                    has_network = any(
                        indicator in full_cmd for indicator in
                        ["http://", "https://", "ftp://", "net use",
                         "invoke-webrequest", "downloadfile", "webclient",
                         "bitstransfer", "curl", "wget"]
                    )
                    if has_network:
                        non_ms_network_count += 1
                        findings.append(Finding(
                            check_id=self.CHECK_ID,
                            title=f"Non-Microsoft task with network activity: {task_name}",
                            description=(
                                f"Non-Microsoft scheduled task '{task_name}' appears to "
                                "perform network operations. This may indicate data "
                                "exfiltration or command-and-control communication."
                            ),
                            severity=Severity.MEDIUM,
                            category=self.CATEGORY,
                            affected_item=full_task_id,
                            evidence=(
                                f"Task: {full_task_id}\n"
                                f"Author: {author}\n"
                                f"Execute: {execute}\n"
                                f"Arguments: {arguments[:500] if arguments else 'None'}\n"
                                f"State: {state}"
                            ),
                            recommendation=(
                                f"Review the network activity performed by task '{task_name}'."
                            ),
                            references=[
                                "https://attack.mitre.org/techniques/T1053/005/",
                            ],
                        ))

        # Summary
        findings.append(Finding(
            check_id=self.CHECK_ID,
            title="Scheduled tasks audit summary",
            description=(
                f"Audited {total_tasks} scheduled tasks. "
                f"{suspicious_count} suspicious (LOLBin execution), "
                f"{non_ms_network_count} non-Microsoft with network activity."
            ),
            severity=Severity.INFO,
            category=self.CATEGORY,
            affected_item="Scheduled Tasks",
            evidence=(
                f"Total tasks: {total_tasks}\n"
                f"Suspicious: {suspicious_count}\n"
                f"Non-MS Network: {non_ms_network_count}"
            ),
            recommendation="Regularly review scheduled tasks for unauthorized entries.",
        ))

        return findings
