"""POL-002: Application Control Policy Assessment.

Checks AppLocker policy configuration and enforcement, WDAC
(Windows Defender Application Control) policy status, AppIDSvc
service state, and Smart App Control configuration to evaluate
application whitelisting posture.
"""

from __future__ import annotations

from vitia_invenire.checks.base import BaseCheck
from vitia_invenire.collectors import registry
from vitia_invenire.collectors.powershell import run_ps
from vitia_invenire.models import Category, Finding, Severity

# Smart App Control registry path
_SAC_POLICY_PATH = r"SYSTEM\CurrentControlSet\Control\CI\Policy"

# WDAC enforcement status values
_WDAC_ENFORCEMENT_NAMES: dict[int, str] = {
    0: "Off",
    1: "Audit mode",
    2: "Enforced",
}


class AppControlPolicyCheck(BaseCheck):
    """Assess application control policy configuration and enforcement."""

    CHECK_ID = "POL-002"
    NAME = "Application Control Policy"
    DESCRIPTION = (
        "Checks AppLocker policy rules and enforcement, WDAC policy status "
        "via DeviceGuard WMI, AppIDSvc service state, and Smart App Control "
        "registry configuration to evaluate application whitelisting posture."
    )
    CATEGORY = Category.POLICY
    REQUIRES_ADMIN = True

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        applocker_configured = self._check_applocker(findings)
        wdac_active = self._check_wdac(findings)
        self._check_appidsvc(findings, applocker_configured)
        self._check_smart_app_control(findings)
        self._assess_overall(findings, applocker_configured, wdac_active)

        return findings

    def _check_applocker(self, findings: list[Finding]) -> bool:
        """Query AppLocker effective policy and return True if rules exist."""
        result = run_ps(
            "Get-AppLockerPolicy -Effective -ErrorAction SilentlyContinue "
            "| Select-Object -ExpandProperty RuleCollections",
            timeout=20,
            as_json=True,
        )

        if not result.success or result.json_output is None:
            # AppLocker query failed or returned nothing -- not configured
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="AppLocker policy not available",
                description=(
                    "Could not retrieve AppLocker effective policy. "
                    "AppLocker may not be configured on this system. "
                    f"Error: {result.error or 'no data returned'}"
                ),
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="AppLocker",
                evidence=result.output[:500] if result.output else "No output",
                recommendation=(
                    "Consider deploying AppLocker or WDAC policies to control "
                    "which applications are allowed to execute."
                ),
            ))
            return False

        rules = result.json_output
        if isinstance(rules, dict):
            rules = [rules]

        if not rules:
            return False

        # Count rules by collection type
        collection_counts: dict[str, int] = {}
        enforcement_modes: dict[str, str] = {}
        rule_evidence: list[str] = []

        for rule_collection in rules:
            if not isinstance(rule_collection, dict):
                continue
            rule_type = str(rule_collection.get("RuleCollectionType", "Unknown"))
            count = rule_collection.get("Count", 0)
            if count is None:
                count = 0
            try:
                count = int(count)
            except (ValueError, TypeError):
                count = 0
            enforcement = str(rule_collection.get("EnforcementMode", "NotConfigured"))

            collection_counts[rule_type] = count
            enforcement_modes[rule_type] = enforcement
            rule_evidence.append(
                f"  {rule_type}: {count} rule(s), enforcement={enforcement}"
            )

        total_rules = sum(collection_counts.values())

        if total_rules > 0:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title=f"AppLocker configured with {total_rules} rule(s)",
                description=(
                    f"AppLocker has {total_rules} rule(s) across "
                    f"{len(collection_counts)} collection(s). "
                    "Review enforcement modes to ensure policies are enforced "
                    "rather than running in audit-only mode."
                ),
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="AppLocker Policy",
                evidence="\n".join(rule_evidence),
                recommendation=(
                    "Review AppLocker rules for completeness and verify "
                    "enforcement mode is not set to AuditOnly for production."
                ),
                references=[
                    "https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/applocker/applocker-overview",
                ],
            ))

            # Check for audit-only collections
            audit_collections = [
                name for name, mode in enforcement_modes.items()
                if mode.lower() == "auditonly"
            ]
            if audit_collections:
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title="AppLocker collections in audit-only mode",
                    description=(
                        f"{len(audit_collections)} AppLocker rule collection(s) "
                        f"are in AuditOnly mode: {', '.join(audit_collections)}. "
                        "Audit-only mode logs policy violations but does not "
                        "block execution of unauthorized applications."
                    ),
                    severity=Severity.LOW,
                    category=self.CATEGORY,
                    affected_item="AppLocker Enforcement",
                    evidence="\n".join(rule_evidence),
                    recommendation=(
                        "Transition AppLocker rules from AuditOnly to Enforce "
                        "mode after validating that legitimate applications are "
                        "covered by the rules."
                    ),
                    references=[
                        "https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/applocker/configure-an-applocker-policy-for-enforce-rules",
                    ],
                ))

            return True

        return False

    def _check_wdac(self, findings: list[Finding]) -> bool:
        """Query WDAC status via DeviceGuard WMI and return True if active."""
        result = run_ps(
            "Get-CimInstance -ClassName Win32_DeviceGuard "
            "-Namespace root\\Microsoft\\Windows\\DeviceGuard "
            "-ErrorAction SilentlyContinue "
            "| Select-Object CodeIntegrityPolicyEnforcementStatus, "
            "UsermodeCodeIntegrityPolicyEnforcementStatus",
            timeout=15,
            as_json=True,
        )

        if not result.success or result.json_output is None:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="WDAC status unavailable",
                description=(
                    "Could not query Windows Defender Application Control status "
                    f"via DeviceGuard WMI. Error: {result.error or 'no data returned'}"
                ),
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="WDAC",
                evidence=result.output[:500] if result.output else "No output",
                recommendation="Verify DeviceGuard WMI namespace is accessible.",
            ))
            return False

        wdac_data = result.json_output
        if isinstance(wdac_data, list) and len(wdac_data) > 0:
            wdac_data = wdac_data[0]

        ci_status = wdac_data.get("CodeIntegrityPolicyEnforcementStatus")
        um_status = wdac_data.get("UsermodeCodeIntegrityPolicyEnforcementStatus")

        ci_name = _WDAC_ENFORCEMENT_NAMES.get(ci_status, f"Unknown ({ci_status})")
        um_name = _WDAC_ENFORCEMENT_NAMES.get(um_status, f"Unknown ({um_status})")

        evidence_text = (
            f"CodeIntegrityPolicyEnforcementStatus: {ci_status} ({ci_name})\n"
            f"UsermodeCodeIntegrityPolicyEnforcementStatus: {um_status} ({um_name})"
        )

        wdac_active = False

        if ci_status is not None and ci_status == 2:
            wdac_active = True
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="WDAC kernel-mode policy is enforced",
                description=(
                    "Windows Defender Application Control code integrity policy "
                    "is actively enforced for kernel-mode drivers and code."
                ),
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="WDAC Kernel Policy",
                evidence=evidence_text,
                recommendation="No action needed. Continue monitoring policy.",
            ))
        elif ci_status is not None and ci_status == 1:
            wdac_active = True
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="WDAC kernel-mode policy in audit mode",
                description=(
                    "WDAC code integrity policy is in audit mode for "
                    "kernel-mode code. Violations are logged but not blocked."
                ),
                severity=Severity.LOW,
                category=self.CATEGORY,
                affected_item="WDAC Kernel Policy",
                evidence=evidence_text,
                recommendation=(
                    "Transition WDAC policy from audit to enforced mode "
                    "once all legitimate drivers are accounted for."
                ),
                references=[
                    "https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/deployment/audit-wdac-policies",
                ],
            ))

        if um_status is not None and um_status == 1:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="WDAC user-mode policy in audit mode",
                description=(
                    "WDAC user-mode code integrity policy is in audit mode. "
                    "Unauthorized user-mode applications are logged but not "
                    "blocked from executing."
                ),
                severity=Severity.LOW,
                category=self.CATEGORY,
                affected_item="WDAC User-Mode Policy",
                evidence=evidence_text,
                recommendation=(
                    "Transition user-mode WDAC policy from audit to enforced "
                    "mode after validating application compatibility."
                ),
            ))

        return wdac_active

    def _check_appidsvc(
        self, findings: list[Finding], applocker_configured: bool
    ) -> None:
        """Check the AppIDSvc service status required for AppLocker."""
        result = run_ps(
            "Get-Service AppIDSvc -ErrorAction SilentlyContinue "
            "| Select-Object Status, StartType",
            timeout=10,
            as_json=True,
        )

        if not result.success or result.json_output is None:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="AppIDSvc service status unavailable",
                description=(
                    "Could not query the Application Identity (AppIDSvc) "
                    f"service. Error: {result.error or 'no data returned'}"
                ),
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="AppIDSvc",
                evidence=result.output[:500] if result.output else "No output",
                recommendation="Verify the AppIDSvc service exists on this system.",
            ))
            return

        svc_data = result.json_output
        if isinstance(svc_data, list) and len(svc_data) > 0:
            svc_data = svc_data[0]

        status = str(svc_data.get("Status", "Unknown"))
        start_type = str(svc_data.get("StartType", "Unknown"))

        # PowerShell returns numeric status values in some versions
        status_names = {
            "1": "Stopped", "2": "StartPending", "3": "StopPending",
            "4": "Running", "5": "ContinuePending", "6": "PausePending",
            "7": "Paused",
        }
        display_status = status_names.get(status, status)

        evidence_text = f"AppIDSvc Status: {display_status}\nStartType: {start_type}"

        svc_running = display_status.lower() == "running" or status == "4"

        if applocker_configured and not svc_running:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="AppIDSvc not running with AppLocker configured",
                description=(
                    "The Application Identity service (AppIDSvc) is not running "
                    "but AppLocker rules are configured. AppLocker requires "
                    "AppIDSvc to enforce application control rules. Without this "
                    "service running, AppLocker rules are not enforced."
                ),
                severity=Severity.MEDIUM,
                category=self.CATEGORY,
                affected_item="AppIDSvc",
                evidence=evidence_text,
                recommendation=(
                    "Start the AppIDSvc service and set its start type to "
                    "Automatic: Set-Service AppIDSvc -StartupType Automatic; "
                    "Start-Service AppIDSvc"
                ),
                references=[
                    "https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/applocker/configure-the-application-identity-service",
                ],
            ))
        else:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="AppIDSvc service status",
                description=(
                    f"Application Identity service is {display_status} "
                    f"with start type {start_type}."
                ),
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="AppIDSvc",
                evidence=evidence_text,
                recommendation="No action needed." if svc_running else (
                    "Consider starting AppIDSvc if AppLocker policies are planned."
                ),
            ))

    def _check_smart_app_control(self, findings: list[Finding]) -> None:
        """Check Smart App Control configuration via registry."""
        sac_val = registry.read_value(
            registry.HKEY_LOCAL_MACHINE,
            _SAC_POLICY_PATH,
            "VerifiedAndReputablePolicyState",
        )

        if sac_val is None:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Smart App Control state not found",
                description=(
                    "The VerifiedAndReputablePolicyState registry value was "
                    "not found. Smart App Control may not be available on "
                    "this version of Windows or was never enabled."
                ),
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="Smart App Control",
                evidence="Registry value not present at "
                         "HKLM\\SYSTEM\\CurrentControlSet\\Control\\CI\\Policy"
                         "\\VerifiedAndReputablePolicyState",
                recommendation=(
                    "Smart App Control is available on Windows 11 22H2 and "
                    "later. It can only be enabled during a clean OS install."
                ),
            ))
            return

        try:
            sac_state = int(sac_val.data)
        except (ValueError, TypeError):
            sac_state = -1

        # States: 0=Off, 1=Evaluation, 2=Enforced
        sac_state_names: dict[int, str] = {
            0: "Off",
            1: "Evaluation",
            2: "Enforced",
        }
        state_name = sac_state_names.get(sac_state, f"Unknown ({sac_state})")
        evidence_text = f"VerifiedAndReputablePolicyState: {sac_state} ({state_name})"

        if sac_state == 2:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Smart App Control is enforced",
                description=(
                    "Smart App Control is actively enforced. Applications must "
                    "be verified and reputable to execute."
                ),
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="Smart App Control",
                evidence=evidence_text,
                recommendation="No action needed. Smart App Control is active.",
            ))
        elif sac_state == 1:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Smart App Control is in evaluation mode",
                description=(
                    "Smart App Control is in evaluation mode. It is learning "
                    "application patterns but not yet blocking untrusted apps."
                ),
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="Smart App Control",
                evidence=evidence_text,
                recommendation=(
                    "Allow evaluation to complete. Smart App Control will "
                    "automatically transition to enforced mode if the system "
                    "is a good candidate."
                ),
            ))
        elif sac_state == 0:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Smart App Control is off",
                description=(
                    "Smart App Control is turned off. Once turned off, it can "
                    "only be re-enabled by resetting or reinstalling Windows."
                ),
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="Smart App Control",
                evidence=evidence_text,
                recommendation=(
                    "Smart App Control cannot be re-enabled without a clean "
                    "Windows install. Consider deploying WDAC or AppLocker "
                    "as alternative application control measures."
                ),
            ))

    def _assess_overall(
        self,
        findings: list[Finding],
        applocker_configured: bool,
        wdac_active: bool,
    ) -> None:
        """Produce a summary finding based on the overall posture."""
        controls: list[str] = []
        if applocker_configured:
            controls.append("AppLocker")
        if wdac_active:
            controls.append("WDAC")

        if not controls:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="No application control policy active",
                description=(
                    "Neither AppLocker nor WDAC application control policies "
                    "are configured on this system. Without application "
                    "whitelisting, any executable can run, including malware "
                    "and unauthorized tools introduced during supply chain "
                    "handling."
                ),
                severity=Severity.MEDIUM,
                category=self.CATEGORY,
                affected_item="Application Control",
                evidence="AppLocker: not configured\nWDAC: not active",
                recommendation=(
                    "Deploy either AppLocker or WDAC policies to restrict "
                    "which applications are permitted to execute. WDAC is "
                    "recommended for new deployments as it provides stronger "
                    "protections than AppLocker."
                ),
                references=[
                    "https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/wdac-and-applocker-overview",
                ],
            ))

        # Summary
        findings.append(Finding(
            check_id=self.CHECK_ID,
            title="Application control policy assessment complete",
            description=(
                f"Assessed AppLocker, WDAC, AppIDSvc, and Smart App Control. "
                f"Active controls: {', '.join(controls) if controls else 'none'}."
            ),
            severity=Severity.INFO,
            category=self.CATEGORY,
            affected_item="Application Control Policy",
            evidence=f"Active application control mechanisms: {', '.join(controls) if controls else 'none'}",
            recommendation="Review application control configuration against organizational policy.",
            references=[
                "https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/wdac-and-applocker-overview",
            ],
        ))
