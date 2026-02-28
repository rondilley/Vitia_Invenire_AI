"""POL-006: PowerShell security configuration assessment.

Checks script block logging, module logging, transcription, execution
policy, language mode, and PowerShell v2 availability to assess the
PowerShell security posture of the system.
"""

from __future__ import annotations

from vitia_invenire.checks.base import BaseCheck
from vitia_invenire.collectors import registry
from vitia_invenire.collectors.powershell import run_ps
from vitia_invenire.models import Category, Finding, Severity

# Registry paths for PowerShell logging policies
_PS_POLICY_BASE = r"SOFTWARE\Policies\Microsoft\Windows\PowerShell"
_SCRIPT_BLOCK_LOGGING_PATH = _PS_POLICY_BASE + r"\ScriptBlockLogging"
_MODULE_LOGGING_PATH = _PS_POLICY_BASE + r"\ModuleLogging"
_TRANSCRIPTION_PATH = _PS_POLICY_BASE + r"\Transcription"


class PowerShellSecurityCheck(BaseCheck):
    """Assess PowerShell security configuration and logging policies."""

    CHECK_ID = "POL-006"
    NAME = "PowerShell Security Configuration"
    DESCRIPTION = (
        "Checks PowerShell script block logging, module logging, "
        "transcription, execution policy, language mode, and "
        "PowerShell v2 availability to assess hardening posture."
    )
    CATEGORY = Category.POLICY
    REQUIRES_ADMIN = False

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        issues_found = 0

        issues_found += self._check_script_block_logging(findings)
        issues_found += self._check_module_logging(findings)
        issues_found += self._check_transcription(findings)
        issues_found += self._check_execution_policy(findings)
        issues_found += self._check_language_mode(findings)
        issues_found += self._check_powershell_v2(findings)

        # Summary finding
        findings.append(Finding(
            check_id=self.CHECK_ID,
            title="PowerShell security configuration summary",
            description=(
                f"Assessed 6 PowerShell security controls. "
                f"{issues_found} issue(s) identified."
            ),
            severity=Severity.INFO,
            category=self.CATEGORY,
            affected_item="PowerShell Configuration",
            evidence=(
                f"Controls checked: script block logging, module logging, "
                f"transcription, execution policy, language mode, PS v2\n"
                f"Issues found: {issues_found}"
            ),
            recommendation=(
                "Enable all PowerShell logging mechanisms, enforce "
                "restricted execution policies, and disable PowerShell v2."
            ),
        ))

        return findings

    def _check_script_block_logging(self, findings: list[Finding]) -> int:
        """Check if PowerShell script block logging is enabled via GPO."""
        val = registry.read_value(
            registry.HKEY_LOCAL_MACHINE,
            _SCRIPT_BLOCK_LOGGING_PATH,
            "EnableScriptBlockLogging",
        )

        if val is None or val.data != 1:
            current = "not configured" if val is None else str(val.data)
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="PowerShell script block logging is not enabled",
                description=(
                    "Script block logging records the content of all PowerShell "
                    "script blocks that are processed, providing visibility into "
                    "obfuscated and dynamically generated code. Without this, "
                    "attacker PowerShell activity may go undetected."
                ),
                severity=Severity.MEDIUM,
                category=self.CATEGORY,
                affected_item="ScriptBlockLogging",
                evidence=(
                    f"Registry: HKLM\\{_SCRIPT_BLOCK_LOGGING_PATH}\n"
                    f"Value: EnableScriptBlockLogging\n"
                    f"Current: {current}\n"
                    f"Expected: 1"
                ),
                recommendation=(
                    "Enable script block logging via Group Policy: "
                    "Computer Configuration > Administrative Templates > "
                    "Windows Components > Windows PowerShell > "
                    "Turn on PowerShell Script Block Logging. "
                    "Or set registry value EnableScriptBlockLogging = 1 (DWORD) "
                    f"at HKLM\\{_SCRIPT_BLOCK_LOGGING_PATH}."
                ),
                references=[
                    "https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows",
                    "https://attack.mitre.org/techniques/T1059/001/",
                ],
            ))
            return 1

        findings.append(Finding(
            check_id=self.CHECK_ID,
            title="PowerShell script block logging is enabled",
            description="Script block logging is configured and active.",
            severity=Severity.INFO,
            category=self.CATEGORY,
            affected_item="ScriptBlockLogging",
            evidence=(
                f"Registry: HKLM\\{_SCRIPT_BLOCK_LOGGING_PATH}\n"
                f"Value: EnableScriptBlockLogging = {val.data}"
            ),
            recommendation="No action needed.",
        ))
        return 0

    def _check_module_logging(self, findings: list[Finding]) -> int:
        """Check if PowerShell module logging is enabled via GPO."""
        val = registry.read_value(
            registry.HKEY_LOCAL_MACHINE,
            _MODULE_LOGGING_PATH,
            "EnableModuleLogging",
        )

        if val is None or val.data != 1:
            current = "not configured" if val is None else str(val.data)
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="PowerShell module logging is not enabled",
                description=(
                    "Module logging records pipeline execution details for "
                    "specified PowerShell modules. Without module logging, "
                    "there is limited visibility into which cmdlets and "
                    "functions attackers invoke."
                ),
                severity=Severity.LOW,
                category=self.CATEGORY,
                affected_item="ModuleLogging",
                evidence=(
                    f"Registry: HKLM\\{_MODULE_LOGGING_PATH}\n"
                    f"Value: EnableModuleLogging\n"
                    f"Current: {current}\n"
                    f"Expected: 1"
                ),
                recommendation=(
                    "Enable module logging via Group Policy: "
                    "Computer Configuration > Administrative Templates > "
                    "Windows Components > Windows PowerShell > "
                    "Turn on Module Logging. Configure module names to log "
                    "(use '*' for all modules)."
                ),
                references=[
                    "https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows",
                ],
            ))
            return 1

        findings.append(Finding(
            check_id=self.CHECK_ID,
            title="PowerShell module logging is enabled",
            description="Module logging is configured and active.",
            severity=Severity.INFO,
            category=self.CATEGORY,
            affected_item="ModuleLogging",
            evidence=(
                f"Registry: HKLM\\{_MODULE_LOGGING_PATH}\n"
                f"Value: EnableModuleLogging = {val.data}"
            ),
            recommendation="No action needed.",
        ))
        return 0

    def _check_transcription(self, findings: list[Finding]) -> int:
        """Check if PowerShell transcription is enabled via GPO."""
        val = registry.read_value(
            registry.HKEY_LOCAL_MACHINE,
            _TRANSCRIPTION_PATH,
            "EnableTranscripting",
        )

        if val is None or val.data != 1:
            current = "not configured" if val is None else str(val.data)
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="PowerShell transcription is not enabled",
                description=(
                    "PowerShell transcription creates a text record of every "
                    "PowerShell session including all input and output. This "
                    "provides a complete audit trail of PowerShell activity "
                    "that is independent of the Windows event log."
                ),
                severity=Severity.LOW,
                category=self.CATEGORY,
                affected_item="Transcription",
                evidence=(
                    f"Registry: HKLM\\{_TRANSCRIPTION_PATH}\n"
                    f"Value: EnableTranscripting\n"
                    f"Current: {current}\n"
                    f"Expected: 1"
                ),
                recommendation=(
                    "Enable transcription via Group Policy: "
                    "Computer Configuration > Administrative Templates > "
                    "Windows Components > Windows PowerShell > "
                    "Turn on PowerShell Transcription. Configure an output "
                    "directory with appropriate access controls."
                ),
                references=[
                    "https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows",
                ],
            ))
            return 1

        findings.append(Finding(
            check_id=self.CHECK_ID,
            title="PowerShell transcription is enabled",
            description="PowerShell transcription is configured and active.",
            severity=Severity.INFO,
            category=self.CATEGORY,
            affected_item="Transcription",
            evidence=(
                f"Registry: HKLM\\{_TRANSCRIPTION_PATH}\n"
                f"Value: EnableTranscripting = {val.data}"
            ),
            recommendation="No action needed.",
        ))
        return 0

    def _check_execution_policy(self, findings: list[Finding]) -> int:
        """Check PowerShell execution policy across all scopes."""
        result = run_ps(
            "Get-ExecutionPolicy -List | Select-Object Scope, ExecutionPolicy",
            timeout=15,
            as_json=True,
        )

        if not result.success or result.json_output is None:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Failed to query PowerShell execution policy",
                description=(
                    f"Could not retrieve execution policy: "
                    f"{result.error or 'unknown error'}"
                ),
                severity=Severity.MEDIUM,
                category=self.CATEGORY,
                affected_item="ExecutionPolicy",
                evidence=result.output[:500] if result.output else "No output",
                recommendation="Manually check: Get-ExecutionPolicy -List",
            ))
            return 1

        policies = result.json_output
        if isinstance(policies, dict):
            policies = [policies]

        issues = 0
        evidence_lines: list[str] = []
        for policy in policies:
            scope = str(policy.get("Scope", "Unknown"))
            ep = str(policy.get("ExecutionPolicy", "Undefined"))
            evidence_lines.append(f"  {scope}: {ep}")

            if ep.lower() == "unrestricted":
                issues += 1
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title=f"Execution policy is Unrestricted at {scope} scope",
                    description=(
                        f"The PowerShell execution policy at the {scope} scope "
                        f"is set to Unrestricted, which allows all scripts to "
                        f"run without any restrictions or warnings. This removes "
                        f"a defense-in-depth layer against malicious scripts."
                    ),
                    severity=Severity.MEDIUM,
                    category=self.CATEGORY,
                    affected_item=f"ExecutionPolicy ({scope})",
                    evidence="\n".join(evidence_lines),
                    recommendation=(
                        f"Set a more restrictive execution policy: "
                        f"Set-ExecutionPolicy -Scope {scope} -ExecutionPolicy "
                        f"RemoteSigned. For maximum security, use AllSigned."
                    ),
                    references=[
                        "https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies",
                    ],
                ))

        if issues == 0:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="PowerShell execution policy configuration",
                description="No Unrestricted execution policies found across scopes.",
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="ExecutionPolicy",
                evidence="\n".join(evidence_lines),
                recommendation="No action needed.",
            ))

        return issues

    def _check_language_mode(self, findings: list[Finding]) -> int:
        """Check the current PowerShell language mode."""
        result = run_ps(
            "$ExecutionContext.SessionState.LanguageMode",
            timeout=10,
            as_json=False,
        )

        if not result.success:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Failed to query PowerShell language mode",
                description=(
                    f"Could not determine language mode: "
                    f"{result.error or 'unknown error'}"
                ),
                severity=Severity.MEDIUM,
                category=self.CATEGORY,
                affected_item="LanguageMode",
                evidence=result.output[:500] if result.output else "No output",
                recommendation="Manually check: $ExecutionContext.SessionState.LanguageMode",
            ))
            return 1

        mode = result.output.strip()
        self.context["ps_language_mode"] = mode

        if mode.lower() == "constrainedlanguage":
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="PowerShell is running in Constrained Language mode",
                description=(
                    "PowerShell Constrained Language mode is active. This "
                    "restricts access to sensitive .NET types, COM objects, "
                    "and other features commonly abused by attackers. This is "
                    "a positive security configuration."
                ),
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="LanguageMode",
                evidence=f"Current language mode: {mode}",
                recommendation="No action needed. This is a recommended configuration.",
            ))
            return 0

        if mode.lower() == "fulllanguage":
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="PowerShell is running in Full Language mode",
                description=(
                    "PowerShell is running in Full Language mode, which "
                    "provides unrestricted access to all language features "
                    "including .NET types, COM objects, and reflection. "
                    "Consider enabling Constrained Language mode via "
                    "AppLocker or WDAC for additional protection."
                ),
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="LanguageMode",
                evidence=f"Current language mode: {mode}",
                recommendation=(
                    "Consider deploying AppLocker or Windows Defender "
                    "Application Control (WDAC) policies to enforce "
                    "Constrained Language mode for non-admin users."
                ),
            ))
            return 0

        # Unexpected mode
        findings.append(Finding(
            check_id=self.CHECK_ID,
            title=f"PowerShell language mode: {mode}",
            description=f"PowerShell is running in {mode} mode.",
            severity=Severity.INFO,
            category=self.CATEGORY,
            affected_item="LanguageMode",
            evidence=f"Current language mode: {mode}",
            recommendation="Review language mode configuration.",
        ))
        return 0

    def _check_powershell_v2(self, findings: list[Finding]) -> int:
        """Check if PowerShell v2 engine is enabled (downgrade attack vector)."""
        result = run_ps(
            "Get-WindowsOptionalFeature -Online "
            "-FeatureName MicrosoftWindowsPowerShellV2 "
            "-ErrorAction SilentlyContinue | "
            "Select-Object FeatureName, State",
            timeout=30,
            as_json=True,
        )

        if not result.success or result.json_output is None:
            # This command requires admin on some systems; report inability
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Could not determine PowerShell v2 status",
                description=(
                    f"Failed to query PowerShell v2 feature state: "
                    f"{result.error or 'unknown error'}. "
                    "This command may require administrator privileges."
                ),
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="PowerShell v2",
                evidence=result.output[:500] if result.output else "No output",
                recommendation=(
                    "Manually check: Get-WindowsOptionalFeature -Online "
                    "-FeatureName MicrosoftWindowsPowerShellV2"
                ),
            ))
            return 0

        feature = result.json_output
        if isinstance(feature, list) and len(feature) > 0:
            feature = feature[0]

        state = str(feature.get("State", "Unknown"))
        feature_name = str(feature.get("FeatureName", "MicrosoftWindowsPowerShellV2"))

        if state.lower() in ("enabled", "2"):
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="PowerShell v2 engine is enabled",
                description=(
                    "The PowerShell v2 engine is installed and enabled. "
                    "Attackers use PowerShell v2 for downgrade attacks to "
                    "bypass script block logging, AMSI (Antimalware Scan "
                    "Interface), and Constrained Language mode, as v2 does "
                    "not support these security features."
                ),
                severity=Severity.HIGH,
                category=self.CATEGORY,
                affected_item=feature_name,
                evidence=(
                    f"Feature: {feature_name}\n"
                    f"State: {state}"
                ),
                recommendation=(
                    "Disable PowerShell v2: "
                    "Disable-WindowsOptionalFeature -Online "
                    "-FeatureName MicrosoftWindowsPowerShellV2Root. "
                    "Also disable MicrosoftWindowsPowerShellV2 if listed separately."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1059/001/",
                    "https://www.leeholmes.com/powershell-constrained-language-mode/",
                ],
            ))
            return 1

        findings.append(Finding(
            check_id=self.CHECK_ID,
            title="PowerShell v2 engine is disabled",
            description=(
                f"The PowerShell v2 feature is in state: {state}. "
                "This prevents downgrade attacks that bypass modern "
                "PowerShell security controls."
            ),
            severity=Severity.INFO,
            category=self.CATEGORY,
            affected_item=feature_name,
            evidence=(
                f"Feature: {feature_name}\n"
                f"State: {state}"
            ),
            recommendation="No action needed.",
        ))
        return 0
