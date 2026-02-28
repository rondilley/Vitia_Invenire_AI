"""DEF-001: Windows Defender status and configuration assessment.

Queries Get-MpPreference and Get-MpComputerStatus to check real-time
protection, cloud protection, tamper protection, exclusions, and
scan history.
"""

from __future__ import annotations

from vitia_invenire.checks.base import BaseCheck
from vitia_invenire.collectors.powershell import run_ps
from vitia_invenire.models import Category, Finding, Severity


class DefenderStatusCheck(BaseCheck):
    """Assess Windows Defender configuration and protection status."""

    CHECK_ID = "DEF-001"
    NAME = "Windows Defender Status"
    DESCRIPTION = (
        "Queries Windows Defender configuration including real-time "
        "protection, cloud protection, tamper protection, exclusions, "
        "and scan history to assess endpoint security posture."
    )
    CATEGORY = Category.HARDENING
    REQUIRES_ADMIN = False

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        self._check_defender_status(findings)
        self._check_defender_preferences(findings)
        self._check_exclusions(findings)
        self._check_scan_history(findings)

        return findings

    def _check_defender_status(self, findings: list[Finding]) -> None:
        """Query Get-MpComputerStatus for current protection state."""
        result = run_ps(
            "Get-MpComputerStatus -ErrorAction SilentlyContinue | "
            "Select-Object AMServiceEnabled, AntispywareEnabled, "
            "AntivirusEnabled, BehaviorMonitorEnabled, IoavProtectionEnabled, "
            "NISEnabled, OnAccessProtectionEnabled, RealTimeProtectionEnabled, "
            "AMRunningMode, AMServiceVersion, AntispywareSignatureVersion, "
            "AntivirusSignatureVersion, AntispywareSignatureLastUpdated, "
            "AntivirusSignatureLastUpdated, FullScanAge, QuickScanAge, "
            "RealTimeScanDirection, IsTamperProtected, "
            "AntispywareSignatureAge, AntivirusSignatureAge",
            timeout=20,
            as_json=True,
        )

        if not result.success or result.json_output is None:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Windows Defender status unavailable",
                description=(
                    f"Could not query Defender status: {result.error or 'unknown'}. "
                    "Windows Defender may not be installed or another AV is active."
                ),
                severity=Severity.MEDIUM,
                category=self.CATEGORY,
                affected_item="Windows Defender",
                evidence=result.output[:500] if result.output else "No output",
                recommendation="Verify antivirus protection is active on this system.",
            ))
            return

        status = result.json_output
        if isinstance(status, list) and len(status) > 0:
            status = status[0]

        realtime = status.get("RealTimeProtectionEnabled", False)
        antivirus = status.get("AntivirusEnabled", False)
        antispyware = status.get("AntispywareEnabled", False)
        behavior = status.get("BehaviorMonitorEnabled", False)
        ioav = status.get("IoavProtectionEnabled", False)
        nis = status.get("NISEnabled", False)
        tamper = status.get("IsTamperProtected", False)
        running_mode = str(status.get("AMRunningMode", "Unknown"))
        av_sig_age = status.get("AntivirusSignatureAge", 0)
        as_sig_age = status.get("AntispywareSignatureAge", 0)
        full_scan_age = status.get("FullScanAge", -1)
        quick_scan_age = status.get("QuickScanAge", -1)

        evidence_lines = [
            f"RealTimeProtection: {realtime}",
            f"AntivirusEnabled: {antivirus}",
            f"AntispywareEnabled: {antispyware}",
            f"BehaviorMonitor: {behavior}",
            f"IOAVProtection: {ioav}",
            f"NetworkInspection: {nis}",
            f"TamperProtected: {tamper}",
            f"RunningMode: {running_mode}",
            f"AV Signature Age: {av_sig_age} days",
            f"AS Signature Age: {as_sig_age} days",
            f"Full Scan Age: {full_scan_age} days",
            f"Quick Scan Age: {quick_scan_age} days",
        ]
        evidence_text = "\n".join(evidence_lines)

        # Check real-time protection
        if not realtime:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Real-time protection is disabled",
                description=(
                    "Windows Defender real-time protection is turned off. "
                    "The system is not actively scanning for malware during file access, "
                    "downloads, or program execution."
                ),
                severity=Severity.HIGH,
                category=self.CATEGORY,
                affected_item="Real-Time Protection",
                evidence=evidence_text,
                recommendation=(
                    "Enable real-time protection: "
                    "Set-MpPreference -DisableRealtimeMonitoring $false"
                ),
                references=[
                    "https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/configure-real-time-protection-microsoft-defender-antivirus",
                ],
            ))

        if not antivirus:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Antivirus component is disabled",
                description="The Windows Defender antivirus engine is not enabled.",
                severity=Severity.HIGH,
                category=self.CATEGORY,
                affected_item="Antivirus Engine",
                evidence=evidence_text,
                recommendation="Enable antivirus protection through Windows Security settings.",
            ))

        if not behavior:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Behavior monitoring is disabled",
                description=(
                    "Behavior monitoring is turned off. This feature detects "
                    "suspicious process behavior patterns indicative of malware."
                ),
                severity=Severity.MEDIUM,
                category=self.CATEGORY,
                affected_item="Behavior Monitoring",
                evidence=evidence_text,
                recommendation="Enable behavior monitoring: Set-MpPreference -DisableBehaviorMonitoring $false",
            ))

        if not tamper:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Tamper protection is not active",
                description=(
                    "Tamper protection is not enabled. Without tamper protection, "
                    "malware can disable Defender protections programmatically."
                ),
                severity=Severity.MEDIUM,
                category=self.CATEGORY,
                affected_item="Tamper Protection",
                evidence=evidence_text,
                recommendation=(
                    "Enable tamper protection through Windows Security app. "
                    "This cannot be set via PowerShell for security reasons."
                ),
                references=[
                    "https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/prevent-changes-to-security-settings-with-tamper-protection",
                ],
            ))

        # Check signature age
        try:
            sig_age = int(av_sig_age) if av_sig_age is not None else 0
            if sig_age > 7:
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title=f"Antivirus signatures are {sig_age} days old",
                    description=(
                        f"Defender antivirus signatures have not been updated in "
                        f"{sig_age} days. Outdated signatures miss recently discovered malware."
                    ),
                    severity=Severity.MEDIUM if sig_age < 14 else Severity.HIGH,
                    category=self.CATEGORY,
                    affected_item="Signature Updates",
                    evidence=evidence_text,
                    recommendation=(
                        "Update Defender signatures: Update-MpSignature. "
                        "Verify Windows Update is functioning."
                    ),
                ))
        except (ValueError, TypeError):
            # Unable to parse signature age
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Unable to determine signature age",
                description="Could not parse the antivirus signature age.",
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="Signature Updates",
                evidence=evidence_text,
                recommendation="Manually check signature currency.",
            ))

        # Report if all major protections are on
        if realtime and antivirus and antispyware and behavior:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Core Defender protections are enabled",
                description="Real-time, antivirus, antispyware, and behavior monitoring are all active.",
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="Windows Defender",
                evidence=evidence_text,
                recommendation="No action needed. Continue monitoring.",
            ))

    def _check_defender_preferences(self, findings: list[Finding]) -> None:
        """Query Get-MpPreference for configuration settings."""
        result = run_ps(
            "Get-MpPreference -ErrorAction SilentlyContinue | "
            "Select-Object CloudBlockLevel, CloudExtendedTimeout, "
            "DisableArchiveScanning, DisableAutoExclusions, "
            "DisableBlockAtFirstSeen, DisableCatchupFullScan, "
            "DisableEmailScanning, DisableIOAVProtection, "
            "DisablePrivacyMode, DisableRealtimeMonitoring, "
            "DisableRemovableDriveScanning, DisableScanningMappedNetworkDrivesForFullScan, "
            "DisableScanningNetworkFiles, DisableScriptScanning, "
            "EnableControlledFolderAccess, EnableNetworkProtection, "
            "MAPSReporting, PUAProtection, SubmitSamplesConsent, "
            "AttackSurfaceReductionRules_Actions, AttackSurfaceReductionRules_Ids",
            timeout=20,
            as_json=True,
        )

        if not result.success or result.json_output is None:
            return

        prefs = result.json_output
        if isinstance(prefs, list) and len(prefs) > 0:
            prefs = prefs[0]

        # Check cloud protection
        cloud_level = prefs.get("CloudBlockLevel", 0)
        if cloud_level is not None:
            try:
                cloud_int = int(cloud_level)
                if cloud_int == 0:
                    findings.append(Finding(
                        check_id=self.CHECK_ID,
                        title="Cloud-delivered protection is at default level",
                        description=(
                            "Cloud block level is at default (0). Higher levels provide "
                            "stronger cloud-based detection. Level 2 (High) or higher "
                            "is recommended for enterprise environments."
                        ),
                        severity=Severity.INFO,
                        category=self.CATEGORY,
                        affected_item="Cloud Block Level",
                        evidence=f"CloudBlockLevel: {cloud_int}",
                        recommendation="Consider increasing: Set-MpPreference -CloudBlockLevel 2",
                    ))
            except (ValueError, TypeError):
                # Skip if not parseable
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title="Cloud block level could not be parsed",
                    description="Unable to determine cloud block level.",
                    severity=Severity.INFO,
                    category=self.CATEGORY,
                    affected_item="Cloud Block Level",
                    evidence=f"CloudBlockLevel: {cloud_level}",
                    recommendation="Manually verify cloud block level.",
                ))

        # Check MAPS reporting
        maps = prefs.get("MAPSReporting", 0)
        if maps is not None:
            try:
                maps_int = int(maps)
                if maps_int == 0:
                    findings.append(Finding(
                        check_id=self.CHECK_ID,
                        title="Microsoft MAPS (cloud protection) is disabled",
                        description=(
                            "MAPS reporting is disabled. Cloud-delivered protection "
                            "provides faster detection of new threats using cloud intelligence."
                        ),
                        severity=Severity.MEDIUM,
                        category=self.CATEGORY,
                        affected_item="MAPS Reporting",
                        evidence=f"MAPSReporting: {maps_int} (0=Disabled, 1=Basic, 2=Advanced)",
                        recommendation="Enable MAPS: Set-MpPreference -MAPSReporting 2",
                    ))
            except (ValueError, TypeError):
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title="MAPS reporting level could not be parsed",
                    description="Unable to determine MAPS reporting status.",
                    severity=Severity.INFO,
                    category=self.CATEGORY,
                    affected_item="MAPS Reporting",
                    evidence=f"MAPSReporting: {maps}",
                    recommendation="Manually verify MAPS reporting status.",
                ))

        # Check script scanning
        script_scanning_disabled = prefs.get("DisableScriptScanning", False)
        if script_scanning_disabled:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Script scanning is disabled",
                description=(
                    "Defender script scanning is turned off. This reduces detection "
                    "of malicious scripts (PowerShell, VBScript, JavaScript)."
                ),
                severity=Severity.MEDIUM,
                category=self.CATEGORY,
                affected_item="Script Scanning",
                evidence=f"DisableScriptScanning: {script_scanning_disabled}",
                recommendation="Enable: Set-MpPreference -DisableScriptScanning $false",
            ))

        # Check network protection
        net_protection = prefs.get("EnableNetworkProtection", 0)
        if net_protection is not None:
            try:
                net_int = int(net_protection)
                if net_int == 0:
                    findings.append(Finding(
                        check_id=self.CHECK_ID,
                        title="Network protection is not enabled",
                        description=(
                            "Network protection is disabled. This feature blocks "
                            "connections to known malicious domains and IP addresses."
                        ),
                        severity=Severity.MEDIUM,
                        category=self.CATEGORY,
                        affected_item="Network Protection",
                        evidence=f"EnableNetworkProtection: {net_int} (0=Disabled, 1=Enabled, 2=Audit)",
                        recommendation="Enable: Set-MpPreference -EnableNetworkProtection 1",
                    ))
            except (ValueError, TypeError):
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title="Network protection status could not be parsed",
                    description="Unable to determine network protection status.",
                    severity=Severity.INFO,
                    category=self.CATEGORY,
                    affected_item="Network Protection",
                    evidence=f"EnableNetworkProtection: {net_protection}",
                    recommendation="Manually verify network protection status.",
                ))

        # Check PUA protection
        pua = prefs.get("PUAProtection", 0)
        if pua is not None:
            try:
                pua_int = int(pua)
                if pua_int == 0:
                    findings.append(Finding(
                        check_id=self.CHECK_ID,
                        title="Potentially Unwanted App protection is disabled",
                        description=(
                            "PUA protection is not enabled. This allows potentially "
                            "unwanted applications (adware, bundleware) to install."
                        ),
                        severity=Severity.LOW,
                        category=self.CATEGORY,
                        affected_item="PUA Protection",
                        evidence=f"PUAProtection: {pua_int} (0=Disabled, 1=Enabled, 2=Audit)",
                        recommendation="Enable: Set-MpPreference -PUAProtection 1",
                    ))
            except (ValueError, TypeError):
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title="PUA protection status could not be parsed",
                    description="Unable to determine PUA protection status.",
                    severity=Severity.INFO,
                    category=self.CATEGORY,
                    affected_item="PUA Protection",
                    evidence=f"PUAProtection: {pua}",
                    recommendation="Manually verify PUA protection status.",
                ))

    def _check_exclusions(self, findings: list[Finding]) -> None:
        """Check Defender exclusions for suspicious entries."""
        result = run_ps(
            "Get-MpPreference -ErrorAction SilentlyContinue | "
            "Select-Object ExclusionPath, ExclusionExtension, "
            "ExclusionProcess, ExclusionIpAddress",
            timeout=20,
            as_json=True,
        )

        if not result.success or result.json_output is None:
            return

        prefs = result.json_output
        if isinstance(prefs, list) and len(prefs) > 0:
            prefs = prefs[0]

        exclusion_paths = prefs.get("ExclusionPath", []) or []
        exclusion_exts = prefs.get("ExclusionExtension", []) or []
        exclusion_procs = prefs.get("ExclusionProcess", []) or []
        exclusion_ips = prefs.get("ExclusionIpAddress", []) or []

        if isinstance(exclusion_paths, str):
            exclusion_paths = [exclusion_paths]
        if isinstance(exclusion_exts, str):
            exclusion_exts = [exclusion_exts]
        if isinstance(exclusion_procs, str):
            exclusion_procs = [exclusion_procs]
        if isinstance(exclusion_ips, str):
            exclusion_ips = [exclusion_ips]

        total_exclusions = len(exclusion_paths) + len(exclusion_exts) + len(exclusion_procs) + len(exclusion_ips)

        # Suspicious exclusion patterns
        suspicious_path_patterns = [
            "\\temp\\", "\\tmp\\", "\\appdata\\", "\\downloads\\",
            "\\users\\public\\", "\\desktop\\",
            "c:\\", "d:\\", "e:\\",  # Whole drive exclusions
        ]

        suspicious_ext_patterns = [
            ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js",
            ".hta", ".scr", ".pif", ".com",
        ]

        suspicious_proc_patterns = [
            "powershell", "cmd.exe", "wscript", "cscript",
            "mshta", "rundll32", "regsvr32", "certutil",
        ]

        for path in exclusion_paths:
            path_str = str(path)
            path_lower = path_str.lower()
            is_suspicious = any(p in path_lower for p in suspicious_path_patterns)

            # Check for whole-drive exclusions
            is_whole_drive = len(path_str.rstrip("\\")) <= 3 and ":" in path_str

            if is_suspicious or is_whole_drive:
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title=f"Suspicious Defender path exclusion: {path_str}",
                    description=(
                        f"Defender path exclusion '{path_str}' is suspicious. "
                        f"{'This excludes an entire drive.' if is_whole_drive else 'This excludes a common malware staging directory.'} "
                        "Attackers add exclusions to prevent detection of their tools."
                    ),
                    severity=Severity.HIGH,
                    category=self.CATEGORY,
                    affected_item=f"Exclusion: {path_str}",
                    evidence=f"Excluded Path: {path_str}",
                    recommendation=(
                        f"Remove suspicious exclusion: "
                        f"Remove-MpPreference -ExclusionPath '{path_str}'"
                    ),
                    references=[
                        "https://attack.mitre.org/techniques/T1562/001/",
                    ],
                ))

        for ext in exclusion_exts:
            ext_str = str(ext).lower()
            if ext_str in suspicious_ext_patterns:
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title=f"Suspicious Defender extension exclusion: {ext_str}",
                    description=(
                        f"Defender extension exclusion '{ext_str}' is suspicious. "
                        "Excluding executable file types prevents detection of malware "
                        "with that extension."
                    ),
                    severity=Severity.HIGH,
                    category=self.CATEGORY,
                    affected_item=f"Exclusion: {ext_str}",
                    evidence=f"Excluded Extension: {ext_str}",
                    recommendation=f"Remove: Remove-MpPreference -ExclusionExtension '{ext_str}'",
                    references=[
                        "https://attack.mitre.org/techniques/T1562/001/",
                    ],
                ))

        for proc in exclusion_procs:
            proc_str = str(proc)
            proc_lower = proc_str.lower()
            if any(p in proc_lower for p in suspicious_proc_patterns):
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title=f"Suspicious Defender process exclusion: {proc_str}",
                    description=(
                        f"Defender process exclusion '{proc_str}' excludes a commonly "
                        "abused system binary from scanning. This allows the process "
                        "to execute malicious content without detection."
                    ),
                    severity=Severity.HIGH,
                    category=self.CATEGORY,
                    affected_item=f"Exclusion: {proc_str}",
                    evidence=f"Excluded Process: {proc_str}",
                    recommendation=f"Remove: Remove-MpPreference -ExclusionProcess '{proc_str}'",
                    references=[
                        "https://attack.mitre.org/techniques/T1562/001/",
                    ],
                ))

        # Summary of exclusions
        if total_exclusions > 0:
            evidence_lines = []
            if exclusion_paths:
                evidence_lines.append(f"Path exclusions ({len(exclusion_paths)}):")
                for p in exclusion_paths:
                    evidence_lines.append(f"  {p}")
            if exclusion_exts:
                evidence_lines.append(f"Extension exclusions ({len(exclusion_exts)}):")
                for e in exclusion_exts:
                    evidence_lines.append(f"  {e}")
            if exclusion_procs:
                evidence_lines.append(f"Process exclusions ({len(exclusion_procs)}):")
                for pr in exclusion_procs:
                    evidence_lines.append(f"  {pr}")
            if exclusion_ips:
                evidence_lines.append(f"IP exclusions ({len(exclusion_ips)}):")
                for ip in exclusion_ips:
                    evidence_lines.append(f"  {ip}")

            findings.append(Finding(
                check_id=self.CHECK_ID,
                title=f"Defender exclusions summary ({total_exclusions} total)",
                description=(
                    f"Found {total_exclusions} Defender exclusions: "
                    f"{len(exclusion_paths)} paths, {len(exclusion_exts)} extensions, "
                    f"{len(exclusion_procs)} processes, {len(exclusion_ips)} IPs."
                ),
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="Defender Exclusions",
                evidence="\n".join(evidence_lines),
                recommendation="Review all exclusions and remove unnecessary ones.",
            ))

    def _check_scan_history(self, findings: list[Finding]) -> None:
        """Check recent scan history and threat detections."""
        result = run_ps(
            "Get-MpThreatDetection -ErrorAction SilentlyContinue | "
            "Select-Object -First 20 ThreatID, "
            "@{N='ThreatName';E={(Get-MpThreat -ThreatID $_.ThreatID -ErrorAction SilentlyContinue).ThreatName}}, "
            "ProcessName, "
            "@{N='DomainUser';E={$_.DomainUser}}, "
            "InitialDetectionTime, "
            "@{N='CleaningAction';E={$_.CleaningAction.ToString()}}, "
            "@{N='Resources';E={($_.Resources | Select-Object -First 3) -join '; '}}",
            timeout=30,
            as_json=True,
        )

        if not result.success or result.json_output is None:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Threat detection history",
                description="No recent threat detections found or query failed.",
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="Threat History",
                evidence="Get-MpThreatDetection returned no results",
                recommendation="No action needed if no threats were detected.",
            ))
            return

        threats = result.json_output
        if isinstance(threats, dict):
            threats = [threats]

        if threats:
            threat_lines: list[str] = []
            for threat in threats:
                threat_name = str(threat.get("ThreatName", "Unknown"))
                process = str(threat.get("ProcessName", "Unknown"))
                detection_time = str(threat.get("InitialDetectionTime", "Unknown"))
                action = str(threat.get("CleaningAction", "Unknown"))
                resources = str(threat.get("Resources", ""))

                threat_lines.append(
                    f"  {threat_name} - Process: {process}, "
                    f"Time: {detection_time}, Action: {action}"
                )

            findings.append(Finding(
                check_id=self.CHECK_ID,
                title=f"Recent threat detections ({len(threats)})",
                description=(
                    f"Windows Defender has detected {len(threats)} threat(s) recently. "
                    "Review detections to ensure all were properly remediated."
                ),
                severity=Severity.MEDIUM,
                category=self.CATEGORY,
                affected_item="Threat History",
                evidence="Recent detections:\n" + "\n".join(threat_lines),
                recommendation="Review all threat detections and verify remediation.",
            ))
