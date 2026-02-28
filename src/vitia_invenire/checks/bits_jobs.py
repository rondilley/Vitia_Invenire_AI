"""BITS-001: BITS Transfer Job Abuse Detection.

Lists Background Intelligent Transfer Service (BITS) jobs via
Get-BitsTransfer -AllUsers and inspects them for indicators of abuse.
BITS jobs can be used for persistence and data exfiltration. Jobs with
NotifyCmdLine pointing to script interpreters are flagged as HIGH, and
jobs downloading from non-Microsoft URLs are flagged as MEDIUM.
"""

from __future__ import annotations

import re

from vitia_invenire.checks.base import BaseCheck
from vitia_invenire.collectors.powershell import run_ps
from vitia_invenire.models import Category, Finding, Severity

# Script interpreters that are suspicious when used as BITS notification commands
_SUSPICIOUS_INTERPRETERS = [
    "powershell",
    "pwsh",
    "cmd.exe",
    "cmd",
    "cscript",
    "wscript",
    "mshta",
    "rundll32",
    "regsvr32",
    "certutil",
    "bitsadmin",
    "msiexec",
    "bash",
    "python",
    "perl",
]

# Microsoft domains that are considered legitimate for BITS downloads
_MICROSOFT_DOMAINS = [
    "microsoft.com",
    "windowsupdate.com",
    "windows.com",
    "msn.com",
    "live.com",
    "office.com",
    "office365.com",
    "azure.com",
    "azure.net",
    "azureedge.net",
    "msecnd.net",
    "microsoftonline.com",
    "sharepoint.com",
    "skype.com",
    "visualstudio.com",
    "aka.ms",
    "download.microsoft.com",
    "update.microsoft.com",
    "delivery.mp.microsoft.com",
    "dl.delivery.mp.microsoft.com",
]

# Domain extraction pattern for URLs
_URL_DOMAIN_PATTERN = re.compile(r"https?://([^/:]+)", re.IGNORECASE)


def _is_microsoft_url(url: str) -> bool:
    """Return True if the URL belongs to a known Microsoft domain."""
    match = _URL_DOMAIN_PATTERN.search(url)
    if not match:
        return False
    domain = match.group(1).lower()
    return any(
        domain == ms_domain or domain.endswith("." + ms_domain)
        for ms_domain in _MICROSOFT_DOMAINS
    )


def _is_suspicious_interpreter(cmd_line: str) -> bool:
    """Return True if the command line invokes a suspicious script interpreter."""
    cmd_lower = cmd_line.lower().strip()
    for interp in _SUSPICIOUS_INTERPRETERS:
        if interp in cmd_lower:
            return True
    return False


class BITSJobsCheck(BaseCheck):
    """Detect BITS transfer job abuse for persistence and exfiltration."""

    CHECK_ID = "BITS-001"
    NAME = "BITS Transfer Job Audit"
    DESCRIPTION = (
        "Lists BITS transfer jobs across all users and checks for indicators "
        "of abuse including notification command lines pointing to script "
        "interpreters and downloads from non-Microsoft URLs."
    )
    CATEGORY = Category.PERSISTENCE
    REQUIRES_ADMIN = True

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        # Query all BITS transfer jobs with details
        ps_command = (
            "Get-BitsTransfer -AllUsers -ErrorAction SilentlyContinue | "
            "Select-Object JobId, DisplayName, TransferType, JobState, "
            "OwnerAccount, Priority, NotifyCmdLine, NotifyFlags, "
            "CreationTime, ModificationTime, "
            "@{Name='RemoteNames';Expression={($_.FileList | "
            "ForEach-Object { $_.RemoteName }) -join ';'}}, "
            "@{Name='LocalNames';Expression={($_.FileList | "
            "ForEach-Object { $_.LocalName }) -join ';'}}"
        )

        result = run_ps(ps_command, timeout=30, as_json=True)

        if not result.success:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="BITS Transfer Query Status",
                description=(
                    "Unable to query BITS transfer jobs. The BITS service may "
                    "not be running, or the Get-BitsTransfer cmdlet is unavailable."
                ),
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="BITS Service",
                evidence=f"Error: {result.error or 'No output from Get-BitsTransfer'}",
                recommendation=(
                    "Verify the BITS service is running and the BitsTransfer "
                    "PowerShell module is available."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1197/",
                ],
            ))
            return findings

        jobs = result.json_output
        if jobs is None:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="No BITS Transfer Jobs Found",
                description="No active BITS transfer jobs were found on the system.",
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="BITS Service",
                evidence="Get-BitsTransfer returned no jobs.",
                recommendation="No action required.",
                references=[
                    "https://attack.mitre.org/techniques/T1197/",
                ],
            ))
            return findings

        # Normalize to list
        if isinstance(jobs, dict):
            jobs = [jobs]

        suspicious_notify_jobs: list[dict] = []
        non_ms_download_jobs: list[dict] = []
        all_job_details: list[str] = []

        for job in jobs:
            job_id = str(job.get("JobId", "Unknown"))
            display_name = str(job.get("DisplayName", "Unknown"))
            transfer_type = str(job.get("TransferType", "Unknown"))
            job_state = str(job.get("JobState", "Unknown"))
            owner = str(job.get("OwnerAccount", "Unknown"))
            notify_cmd = job.get("NotifyCmdLine")
            remote_names = str(job.get("RemoteNames", ""))
            local_names = str(job.get("LocalNames", ""))
            creation_time = str(job.get("CreationTime", "Unknown"))

            job_summary = (
                f"Job ID: {job_id}\n"
                f"  Display Name: {display_name}\n"
                f"  Transfer Type: {transfer_type}\n"
                f"  State: {job_state}\n"
                f"  Owner: {owner}\n"
                f"  Created: {creation_time}\n"
                f"  Remote URLs: {remote_names}\n"
                f"  Local Paths: {local_names}"
            )

            if notify_cmd:
                # NotifyCmdLine can be a string or array
                notify_str = str(notify_cmd)
                job_summary += f"\n  NotifyCmdLine: {notify_str}"

                if _is_suspicious_interpreter(notify_str):
                    suspicious_notify_jobs.append({
                        "job_id": job_id,
                        "display_name": display_name,
                        "owner": owner,
                        "notify_cmd": notify_str,
                        "state": job_state,
                        "creation_time": creation_time,
                    })

            all_job_details.append(job_summary)

            # Check remote URLs against Microsoft domains
            if remote_names:
                urls = remote_names.split(";")
                for url in urls:
                    url = url.strip()
                    if url and not _is_microsoft_url(url):
                        non_ms_download_jobs.append({
                            "job_id": job_id,
                            "display_name": display_name,
                            "owner": owner,
                            "url": url,
                            "state": job_state,
                            "transfer_type": transfer_type,
                            "creation_time": creation_time,
                        })

        # Report suspicious NotifyCmdLine jobs
        if suspicious_notify_jobs:
            evidence_lines = []
            for entry in suspicious_notify_jobs:
                evidence_lines.append(
                    f"Job: {entry['display_name']} ({entry['job_id']})\n"
                    f"  Owner: {entry['owner']}\n"
                    f"  NotifyCmdLine: {entry['notify_cmd']}\n"
                    f"  State: {entry['state']}\n"
                    f"  Created: {entry['creation_time']}"
                )
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="BITS Job With Suspicious Notification Command",
                description=(
                    f"{len(suspicious_notify_jobs)} BITS job(s) have NotifyCmdLine "
                    f"values pointing to script interpreters. This is a known "
                    f"persistence technique where BITS triggers arbitrary command "
                    f"execution upon job completion."
                ),
                severity=Severity.HIGH,
                category=self.CATEGORY,
                affected_item="BITS Transfer Jobs",
                evidence="\n\n".join(evidence_lines),
                recommendation=(
                    "Investigate each flagged BITS job. Remove unauthorized jobs "
                    "using 'Remove-BitsTransfer'. Examine the notification command "
                    "for malicious payloads. Check the job owner account for "
                    "signs of compromise."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1197/",
                    "https://docs.microsoft.com/en-us/windows/win32/bits/bits-start-after-reboot",
                ],
            ))

        # Report non-Microsoft download URLs
        if non_ms_download_jobs:
            evidence_lines = []
            for entry in non_ms_download_jobs:
                evidence_lines.append(
                    f"Job: {entry['display_name']} ({entry['job_id']})\n"
                    f"  Owner: {entry['owner']}\n"
                    f"  URL: {entry['url']}\n"
                    f"  Transfer Type: {entry['transfer_type']}\n"
                    f"  State: {entry['state']}\n"
                    f"  Created: {entry['creation_time']}"
                )
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="BITS Job Downloading From Non-Microsoft URL",
                description=(
                    f"{len(non_ms_download_jobs)} BITS job(s) are configured to "
                    f"download from non-Microsoft URLs. While this can be "
                    f"legitimate (e.g., third-party updaters), it may also "
                    f"indicate malware using BITS for stealthy downloads."
                ),
                severity=Severity.MEDIUM,
                category=self.CATEGORY,
                affected_item="BITS Transfer Jobs",
                evidence="\n\n".join(evidence_lines),
                recommendation=(
                    "Verify that each download URL belongs to a known, trusted "
                    "vendor. Check if the downloading application is legitimate. "
                    "Remove any BITS jobs associated with unknown or suspicious URLs."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1197/",
                ],
            ))

        # Summary finding for all jobs
        if all_job_details:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="BITS Transfer Jobs Inventory",
                description=f"Found {len(all_job_details)} BITS transfer job(s) on the system.",
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="BITS Service",
                evidence="\n\n".join(all_job_details),
                recommendation="Review all active BITS jobs for legitimacy.",
                references=[
                    "https://attack.mitre.org/techniques/T1197/",
                ],
            ))

        return findings
