"""PATCH-001: Windows Update status and configuration assessment.

Queries the Windows Update service, update history via COM objects,
pending updates, WSUS configuration, and auto-update policy to detect
patch management gaps that may indicate supply chain compromise or
misconfiguration.
"""

from __future__ import annotations

from datetime import datetime, timezone

from vitia_invenire.checks.base import BaseCheck
from vitia_invenire.collectors import registry
from vitia_invenire.collectors.powershell import run_ps
from vitia_invenire.models import Category, Finding, Severity

# ResultCode values from IUpdateHistoryEntry
_RESULT_CODES: dict[int, str] = {
    0: "Not Started",
    1: "In Progress",
    2: "Succeeded",
    3: "Succeeded With Errors",
    4: "Failed",
    5: "Aborted",
}

# Operation values from IUpdateHistoryEntry
_OPERATION_CODES: dict[int, str] = {
    1: "Installation",
    2: "Uninstallation",
}

# AUOptions values for auto-update policy
_AU_OPTIONS: dict[int, str] = {
    1: "Keep my computer up to date is disabled in AU",
    2: "Notify for download and notify for install",
    3: "Auto download and notify for install",
    4: "Auto download and schedule the install",
    5: "AU is managed by local admin (default for standalone)",
}


class WindowsUpdateCheck(BaseCheck):
    """Assess Windows Update service status, patch history, and policy."""

    CHECK_ID = "PATCH-001"
    NAME = "Windows Update Status"
    DESCRIPTION = (
        "Queries the Windows Update service status, update installation "
        "history, pending updates, WSUS configuration, and auto-update "
        "policy to identify patch management gaps and misconfigurations "
        "that may leave the system vulnerable."
    )
    CATEGORY = Category.PATCHING
    REQUIRES_ADMIN = False

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        self._check_service_status(findings)
        self._check_update_history(findings)
        self._check_pending_updates(findings)
        self._check_wsus_config(findings)
        self._check_auto_update_policy(findings)

        # Summary finding
        issue_count = sum(
            1 for f in findings if f.severity != Severity.INFO
        )
        findings.append(Finding(
            check_id=self.CHECK_ID,
            title="Windows Update status assessment summary",
            description=(
                f"Completed Windows Update assessment. "
                f"Found {issue_count} issue(s) across service status, "
                f"update history, pending updates, and policy checks."
            ),
            severity=Severity.INFO,
            category=self.CATEGORY,
            affected_item="Windows Update",
            evidence=f"Total findings: {len(findings) + 1}, Issues: {issue_count}",
            recommendation="Review all findings and remediate as needed.",
        ))

        return findings

    def _check_service_status(self, findings: list[Finding]) -> None:
        """Query the Windows Update service (wuauserv) status."""
        result = run_ps(
            "Get-Service wuauserv -ErrorAction SilentlyContinue | "
            "Select-Object Name, Status, StartType, DisplayName",
            timeout=15,
            as_json=True,
        )

        if not result.success or result.json_output is None:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Unable to query Windows Update service",
                description=(
                    "Could not query the wuauserv service status: "
                    f"{result.error or 'unknown error'}. "
                    "The Windows Update service may not exist on this system."
                ),
                severity=Severity.HIGH,
                category=self.CATEGORY,
                affected_item="wuauserv",
                evidence=result.output[:500] if result.output else "No output",
                recommendation="Verify the Windows Update service exists and is accessible.",
            ))
            return

        svc = result.json_output
        if isinstance(svc, list):
            svc = svc[0] if svc else {}

        status = str(svc.get("Status", ""))
        start_type = str(svc.get("StartType", ""))
        display_name = str(svc.get("DisplayName", "Windows Update"))

        evidence_text = (
            f"Service: wuauserv\n"
            f"Display Name: {display_name}\n"
            f"Status: {status}\n"
            f"Start Type: {start_type}"
        )

        # PowerShell serializes the Status enum as an integer:
        # 1=Stopped, 4=Running. Also handle the string forms.
        status_lower = status.lower().strip()
        is_running = status_lower in ("running", "4")
        is_stopped = status_lower in ("stopped", "1")

        if is_stopped or (not is_running and status_lower not in ("", "none")):
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Windows Update service is not running",
                description=(
                    f"The Windows Update service (wuauserv) is currently "
                    f"'{status}'. Without this service running, the system "
                    "cannot check for or install security updates. A stopped "
                    "WU service on a production system may indicate tampering."
                ),
                severity=Severity.CRITICAL,
                category=self.CATEGORY,
                affected_item="wuauserv",
                evidence=evidence_text,
                recommendation=(
                    "Start the Windows Update service: "
                    "Start-Service wuauserv; Set-Service wuauserv -StartupType Manual"
                ),
                references=[
                    "https://learn.microsoft.com/en-us/windows/deployment/update/how-windows-update-works",
                ],
            ))
        else:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Windows Update service is running",
                description=f"The wuauserv service is in '{status}' state.",
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="wuauserv",
                evidence=evidence_text,
                recommendation="No action needed.",
            ))

    def _check_update_history(self, findings: list[Finding]) -> None:
        """Query update installation history via the COM Update Session."""
        ps_command = (
            "try {"
            "  $session = New-Object -ComObject Microsoft.Update.Session;"
            "  $searcher = $session.CreateUpdateSearcher();"
            "  $count = $searcher.GetTotalHistoryCount();"
            "  if ($count -eq 0) {"
            "    @{TotalCount=0; Entries=@()} | Select-Object TotalCount, Entries"
            "  } else {"
            "    $limit = [Math]::Min($count, 50);"
            "    $history = $searcher.QueryHistory(0, $limit);"
            "    $entries = @();"
            "    foreach ($entry in $history) {"
            "      $entries += @{"
            "        Title = $entry.Title;"
            "        Date = $entry.Date.ToString('o');"
            "        ResultCode = [int]$entry.ResultCode;"
            "        Operation = [int]$entry.Operation"
            "      }"
            "    };"
            "    @{TotalCount=$count; Entries=$entries} | Select-Object TotalCount, Entries"
            "  }"
            "} catch {"
            "  @{Error=$_.Exception.Message; TotalCount=-1; Entries=@()}"
            "    | Select-Object Error, TotalCount, Entries"
            "}"
        )

        result = run_ps(ps_command, timeout=30, as_json=True)

        if not result.success or result.json_output is None:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Unable to query update history",
                description=(
                    "Could not retrieve Windows Update history via COM: "
                    f"{result.error or 'unknown error'}. "
                    "The Update Session COM object may not be available."
                ),
                severity=Severity.MEDIUM,
                category=self.CATEGORY,
                affected_item="Update History",
                evidence=result.output[:500] if result.output else "No output",
                recommendation="Manually check update history via Settings > Update > Update history.",
            ))
            return

        data = result.json_output
        if isinstance(data, list) and len(data) > 0:
            data = data[0]

        com_error = data.get("Error")
        if com_error:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Update history COM query failed",
                description=(
                    f"The Microsoft.Update.Session COM object returned an error: "
                    f"{com_error}"
                ),
                severity=Severity.MEDIUM,
                category=self.CATEGORY,
                affected_item="Update History",
                evidence=f"COM Error: {com_error}",
                recommendation=(
                    "Verify Windows Update components are intact. "
                    "Run: sfc /scannow"
                ),
            ))
            return

        total_count = 0
        try:
            total_count = int(data.get("TotalCount", 0))
        except (ValueError, TypeError):
            total_count = 0

        entries = data.get("Entries", [])
        if entries is None:
            entries = []
        if isinstance(entries, dict):
            entries = [entries]

        if total_count == 0 or not entries:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="No update history found",
                description=(
                    "Windows Update reports no installation history. "
                    "This may indicate a fresh installation or that update "
                    "history has been cleared."
                ),
                severity=Severity.HIGH,
                category=self.CATEGORY,
                affected_item="Update History",
                evidence=f"Total history entries: {total_count}",
                recommendation=(
                    "Verify Windows Update is configured and functional. "
                    "Run: UsoClient StartInteractiveScan"
                ),
            ))
            return

        # Parse dates and find the most recent successful update
        now_utc = datetime.now(timezone.utc)
        most_recent_date: datetime | None = None
        successful_count = 0
        failed_count = 0
        evidence_lines: list[str] = [f"Total history entries: {total_count}"]

        for entry in entries:
            title = str(entry.get("Title", "Unknown"))
            date_str = str(entry.get("Date", ""))
            result_code = 0
            operation_code = 0

            try:
                result_code = int(entry.get("ResultCode", 0))
            except (ValueError, TypeError):
                result_code = 0

            try:
                operation_code = int(entry.get("Operation", 0))
            except (ValueError, TypeError):
                operation_code = 0

            result_text = _RESULT_CODES.get(result_code, f"Unknown ({result_code})")
            operation_text = _OPERATION_CODES.get(operation_code, f"Unknown ({operation_code})")

            # Parse the ISO 8601 date
            entry_date: datetime | None = None
            if date_str:
                try:
                    # Handle ISO format with and without timezone
                    cleaned = date_str.replace("Z", "+00:00")
                    entry_date = datetime.fromisoformat(cleaned)
                    if entry_date.tzinfo is None:
                        entry_date = entry_date.replace(tzinfo=timezone.utc)
                except ValueError:
                    entry_date = None

            if result_code == 2:
                successful_count += 1
                if entry_date is not None:
                    if most_recent_date is None or entry_date > most_recent_date:
                        most_recent_date = entry_date
            elif result_code in (4, 5):
                failed_count += 1

            if len(evidence_lines) <= 15:
                date_display = entry_date.strftime("%Y-%m-%d %H:%M") if entry_date else date_str
                evidence_lines.append(
                    f"  [{result_text}] {date_display} - {operation_text}: "
                    f"{title[:80]}"
                )

        evidence_lines.insert(1, f"Successful: {successful_count}, Failed: {failed_count}")
        evidence_text = "\n".join(evidence_lines)

        # Evaluate days since last successful update
        if most_recent_date is not None:
            days_since = (now_utc - most_recent_date).days

            if days_since >= 90:
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title=f"No successful update in {days_since} days",
                    description=(
                        f"The most recent successful Windows Update was "
                        f"{days_since} days ago ({most_recent_date.strftime('%Y-%m-%d')}). "
                        "A system more than 90 days behind on updates is critically "
                        "exposed to known vulnerabilities and may indicate the update "
                        "mechanism has been tampered with."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.CATEGORY,
                    affected_item="Update History",
                    evidence=evidence_text,
                    recommendation=(
                        "Immediately run Windows Update. Investigate why updates "
                        "have not been installed. Check for Group Policy or WSUS "
                        "misconfigurations."
                    ),
                    references=[
                        "https://learn.microsoft.com/en-us/windows/deployment/update/best-practices-for-update-management",
                    ],
                ))
            elif days_since >= 30:
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title=f"No successful update in {days_since} days",
                    description=(
                        f"The most recent successful Windows Update was "
                        f"{days_since} days ago ({most_recent_date.strftime('%Y-%m-%d')}). "
                        "Systems should receive security updates at least monthly "
                        "per Patch Tuesday cadence."
                    ),
                    severity=Severity.HIGH,
                    category=self.CATEGORY,
                    affected_item="Update History",
                    evidence=evidence_text,
                    recommendation=(
                        "Run Windows Update to install available patches. "
                        "Review update logs for installation failures."
                    ),
                    references=[
                        "https://learn.microsoft.com/en-us/windows/deployment/update/best-practices-for-update-management",
                    ],
                ))
            else:
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title=f"Last successful update {days_since} days ago",
                    description=(
                        f"Most recent successful update: "
                        f"{most_recent_date.strftime('%Y-%m-%d')}. "
                        f"System is within normal Patch Tuesday cadence."
                    ),
                    severity=Severity.INFO,
                    category=self.CATEGORY,
                    affected_item="Update History",
                    evidence=evidence_text,
                    recommendation="Continue regular update schedule.",
                ))
        else:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="No successful updates found in history",
                description=(
                    "Could not find any successfully installed updates in the "
                    "update history. All recorded updates may have failed or "
                    "the history may be incomplete."
                ),
                severity=Severity.HIGH,
                category=self.CATEGORY,
                affected_item="Update History",
                evidence=evidence_text,
                recommendation=(
                    "Investigate update failures. Run Windows Update troubleshooter: "
                    "msdt.exe /id WindowsUpdateDiagnostic"
                ),
            ))

        # Report high failure rate
        total_recorded = successful_count + failed_count
        if total_recorded > 0 and failed_count > 0:
            failure_rate = (failed_count / total_recorded) * 100
            if failure_rate > 30:
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title=f"High update failure rate: {failure_rate:.0f}%",
                    description=(
                        f"Of {total_recorded} recorded update operations, "
                        f"{failed_count} failed ({failure_rate:.0f}%). "
                        "A high failure rate may indicate disk space issues, "
                        "corrupted update components, or interference."
                    ),
                    severity=Severity.MEDIUM,
                    category=self.CATEGORY,
                    affected_item="Update History",
                    evidence=evidence_text,
                    recommendation=(
                        "Run the Windows Update troubleshooter. "
                        "Check disk space and run: DISM /Online /Cleanup-Image /RestoreHealth"
                    ),
                ))

    def _check_pending_updates(self, findings: list[Finding]) -> None:
        """Query for pending (not installed) updates via COM."""
        ps_command = (
            "try {"
            "  $searcher = (New-Object -ComObject Microsoft.Update.Session)"
            "    .CreateUpdateSearcher();"
            "  $result = $searcher.Search('IsInstalled=0');"
            "  $updates = @();"
            "  foreach ($update in $result.Updates) {"
            "    $updates += @{"
            "      Title = $update.Title;"
            "      MsrcSeverity = $update.MsrcSeverity;"
            "      IsDownloaded = $update.IsDownloaded"
            "    }"
            "  };"
            "  @{Count=$result.Updates.Count; Updates=$updates}"
            "    | Select-Object Count, Updates"
            "} catch {"
            "  @{Error=$_.Exception.Message; Count=-1; Updates=@()}"
            "    | Select-Object Error, Count, Updates"
            "}"
        )

        result = run_ps(ps_command, timeout=120, as_json=True)

        if not result.success or result.json_output is None:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Unable to query pending updates",
                description=(
                    "Could not search for pending updates: "
                    f"{result.error or 'unknown error'}. "
                    "This query requires network access to the update source."
                ),
                severity=Severity.MEDIUM,
                category=self.CATEGORY,
                affected_item="Pending Updates",
                evidence=result.output[:500] if result.output else "No output",
                recommendation="Manually check for updates via Settings > Update.",
            ))
            return

        data = result.json_output
        if isinstance(data, list) and len(data) > 0:
            data = data[0]

        com_error = data.get("Error")
        if com_error:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Pending updates query failed",
                description=(
                    f"Update search returned an error: {com_error}. "
                    "This may occur if the system cannot reach the update source."
                ),
                severity=Severity.MEDIUM,
                category=self.CATEGORY,
                affected_item="Pending Updates",
                evidence=f"COM Error: {com_error}",
                recommendation="Verify network connectivity and update source availability.",
            ))
            return

        pending_count = 0
        try:
            pending_count = int(data.get("Count", 0))
        except (ValueError, TypeError):
            pending_count = 0

        updates = data.get("Updates", [])
        if updates is None:
            updates = []
        if isinstance(updates, dict):
            updates = [updates]

        if pending_count == 0:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="No pending updates found",
                description="The system reports no updates waiting to be installed.",
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="Pending Updates",
                evidence=f"Pending update count: 0",
                recommendation="No action needed. System is up to date.",
            ))
            return

        # Categorize pending updates by severity
        critical_updates: list[str] = []
        important_updates: list[str] = []
        other_updates: list[str] = []

        for update in updates:
            title = str(update.get("Title", "Unknown"))
            msrc_severity = str(update.get("MsrcSeverity", "") or "")
            is_downloaded = update.get("IsDownloaded", False)
            download_status = "Downloaded" if is_downloaded else "Not downloaded"

            entry_text = f"{title} [{download_status}]"

            severity_lower = msrc_severity.lower().strip()
            if severity_lower == "critical":
                critical_updates.append(entry_text)
            elif severity_lower in ("important", "moderate"):
                important_updates.append(entry_text)
            else:
                other_updates.append(entry_text)

        evidence_lines = [f"Total pending: {pending_count}"]
        if critical_updates:
            evidence_lines.append(f"Critical ({len(critical_updates)}):")
            for u in critical_updates[:10]:
                evidence_lines.append(f"  {u[:100]}")
        if important_updates:
            evidence_lines.append(f"Important ({len(important_updates)}):")
            for u in important_updates[:10]:
                evidence_lines.append(f"  {u[:100]}")
        if other_updates:
            evidence_lines.append(f"Other ({len(other_updates)}):")
            for u in other_updates[:10]:
                evidence_lines.append(f"  {u[:100]}")

        evidence_text = "\n".join(evidence_lines)

        if critical_updates or important_updates:
            combined_count = len(critical_updates) + len(important_updates)
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title=(
                    f"{combined_count} critical/important update(s) pending"
                ),
                description=(
                    f"There are {len(critical_updates)} critical and "
                    f"{len(important_updates)} important updates pending "
                    f"installation. Unpatched critical vulnerabilities expose "
                    f"the system to known exploits."
                ),
                severity=Severity.HIGH,
                category=self.CATEGORY,
                affected_item="Pending Updates",
                evidence=evidence_text,
                recommendation=(
                    "Install pending critical and important updates immediately. "
                    "Run: UsoClient StartInstall"
                ),
                references=[
                    "https://learn.microsoft.com/en-us/windows/deployment/update/windows-update-overview",
                ],
            ))

        if other_updates and not critical_updates and not important_updates:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title=f"{len(other_updates)} pending update(s) available",
                description=(
                    f"There are {len(other_updates)} updates pending "
                    "installation. None are rated critical or important."
                ),
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="Pending Updates",
                evidence=evidence_text,
                recommendation="Install pending updates at next maintenance window.",
            ))

    def _check_wsus_config(self, findings: list[Finding]) -> None:
        """Check WSUS configuration from registry."""
        wu_path = r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"

        wu_server = registry.read_value(
            registry.HKEY_LOCAL_MACHINE, wu_path, "WUServer"
        )
        wu_status_server = registry.read_value(
            registry.HKEY_LOCAL_MACHINE, wu_path, "WUStatusServer"
        )

        if wu_server is None and wu_status_server is None:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="No WSUS server configured",
                description=(
                    "The system is not configured to use a WSUS server. "
                    "Updates are sourced directly from Microsoft Update."
                ),
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="WSUS Configuration",
                evidence="Registry key not present or WUServer value not set",
                recommendation="No action needed for standalone systems.",
            ))
            return

        wu_server_val = str(wu_server.data) if wu_server else "Not set"
        wu_status_val = str(wu_status_server.data) if wu_status_server else "Not set"

        evidence_text = (
            f"WUServer: {wu_server_val}\n"
            f"WUStatusServer: {wu_status_val}"
        )

        findings.append(Finding(
            check_id=self.CHECK_ID,
            title=f"WSUS server configured: {wu_server_val}",
            description=(
                f"Updates are directed to a WSUS server at '{wu_server_val}' "
                f"with status reporting to '{wu_status_val}'. A compromised "
                "or rogue WSUS server can serve malicious updates or suppress "
                "critical patches. Verify this server is authorized by your "
                "organization."
            ),
            severity=Severity.MEDIUM,
            category=self.CATEGORY,
            affected_item="WSUS Configuration",
            evidence=evidence_text,
            recommendation=(
                "Verify the WSUS server URL is authorized and expected. "
                "Confirm the WSUS server is using HTTPS to prevent MITM attacks."
            ),
            references=[
                "https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus",
            ],
        ))

        # Flag if WSUS is using HTTP (not HTTPS)
        if wu_server and str(wu_server.data).lower().startswith("http://"):
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="WSUS server uses unencrypted HTTP",
                description=(
                    f"The WSUS server URL '{wu_server_val}' uses HTTP "
                    "instead of HTTPS. An attacker on the network path can "
                    "intercept update traffic and inject malicious content."
                ),
                severity=Severity.HIGH,
                category=self.CATEGORY,
                affected_item="WSUS Configuration",
                evidence=evidence_text,
                recommendation=(
                    "Configure WSUS to use HTTPS. Update the WUServer "
                    "registry value to use https:// protocol."
                ),
                references=[
                    "https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus",
                ],
            ))

    def _check_auto_update_policy(self, findings: list[Finding]) -> None:
        """Check auto-update policy from registry."""
        au_path = r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"

        no_auto_update = registry.read_value(
            registry.HKEY_LOCAL_MACHINE, au_path, "NoAutoUpdate"
        )
        au_options = registry.read_value(
            registry.HKEY_LOCAL_MACHINE, au_path, "AUOptions"
        )

        evidence_lines: list[str] = []

        if no_auto_update is not None:
            evidence_lines.append(f"NoAutoUpdate: {no_auto_update.data}")
        else:
            evidence_lines.append("NoAutoUpdate: Not configured")

        if au_options is not None:
            au_val = au_options.data
            au_desc = _AU_OPTIONS.get(au_val, f"Unknown ({au_val})") if isinstance(au_val, int) else str(au_val)
            evidence_lines.append(f"AUOptions: {au_val} ({au_desc})")
        else:
            evidence_lines.append("AUOptions: Not configured")

        evidence_text = "\n".join(evidence_lines)

        # Neither policy value exists -- default Windows behavior
        if no_auto_update is None and au_options is None:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Auto-update policy uses default settings",
                description=(
                    "No explicit auto-update Group Policy is configured. "
                    "Windows will use its default automatic update behavior."
                ),
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="Auto-Update Policy",
                evidence=evidence_text,
                recommendation="No action needed for default configuration.",
            ))
            return

        # Check if auto-updates are explicitly disabled
        if no_auto_update is not None:
            try:
                disabled = int(no_auto_update.data) == 1
            except (ValueError, TypeError):
                disabled = False

            if disabled:
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title="Automatic updates are disabled by policy",
                    description=(
                        "The NoAutoUpdate registry value is set to 1, which "
                        "disables automatic updates via Group Policy. The system "
                        "will not automatically check for, download, or install "
                        "updates. This significantly increases exposure to known "
                        "vulnerabilities."
                    ),
                    severity=Severity.HIGH,
                    category=self.CATEGORY,
                    affected_item="Auto-Update Policy",
                    evidence=evidence_text,
                    recommendation=(
                        "Enable automatic updates. Remove the NoAutoUpdate "
                        "policy or set it to 0. Verify with your organization "
                        "whether this is intentional."
                    ),
                    references=[
                        "https://learn.microsoft.com/en-us/windows/deployment/update/waas-wu-settings",
                    ],
                ))
                return

        # Report AUOptions if configured
        if au_options is not None:
            try:
                au_val = int(au_options.data)
            except (ValueError, TypeError):
                au_val = -1

            au_desc = _AU_OPTIONS.get(au_val, f"Unknown ({au_val})")
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title=f"Auto-update policy: {au_desc}",
                description=(
                    f"AUOptions is set to {au_val}: {au_desc}. "
                    "This controls how updates are downloaded and installed."
                ),
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="Auto-Update Policy",
                evidence=evidence_text,
                recommendation=(
                    "Verify the auto-update policy aligns with organizational "
                    "patch management requirements."
                ),
            ))
