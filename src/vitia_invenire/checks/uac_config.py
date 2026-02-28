"""POL-001: User Account Control (UAC) Configuration Assessment.

Reads UAC-related registry values under
HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System
to verify that UAC is enabled, prompting is configured securely,
Secure Desktop is active, and the built-in Administrator account
is filtered by UAC.
"""

from __future__ import annotations

from vitia_invenire.checks.base import BaseCheck
from vitia_invenire.collectors import registry
from vitia_invenire.models import Category, Finding, Severity

# UAC registry key path
_UAC_POLICY_PATH = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"

# ConsentPromptBehaviorAdmin values
_CONSENT_PROMPT_NAMES: dict[int, str] = {
    0: "Elevate without prompting",
    1: "Prompt for credentials on secure desktop",
    2: "Prompt for consent on secure desktop",
    3: "Prompt for credentials",
    4: "Prompt for consent",
    5: "Prompt for consent for non-Windows binaries",
}


class UACConfigCheck(BaseCheck):
    """Assess User Account Control configuration for security weaknesses."""

    CHECK_ID = "POL-001"
    NAME = "UAC Configuration"
    DESCRIPTION = (
        "Reads UAC registry values to verify that User Account Control is "
        "enabled, consent prompting is securely configured, Secure Desktop "
        "is active for elevation prompts, and the built-in Administrator "
        "account is filtered by UAC."
    )
    CATEGORY = Category.POLICY
    REQUIRES_ADMIN = False

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        evidence_lines: list[str] = []

        # -- EnableLUA --
        enable_lua_val = registry.read_value(
            registry.HKEY_LOCAL_MACHINE, _UAC_POLICY_PATH, "EnableLUA"
        )
        enable_lua: int | None = None
        if enable_lua_val is not None:
            try:
                enable_lua = int(enable_lua_val.data)
            except (ValueError, TypeError):
                enable_lua = None
            evidence_lines.append(f"EnableLUA: {enable_lua_val.data}")
        else:
            evidence_lines.append("EnableLUA: not found (default: 1)")

        # -- ConsentPromptBehaviorAdmin --
        consent_val = registry.read_value(
            registry.HKEY_LOCAL_MACHINE, _UAC_POLICY_PATH, "ConsentPromptBehaviorAdmin"
        )
        consent_behavior: int | None = None
        if consent_val is not None:
            try:
                consent_behavior = int(consent_val.data)
            except (ValueError, TypeError):
                consent_behavior = None
            consent_name = _CONSENT_PROMPT_NAMES.get(
                consent_behavior if consent_behavior is not None else -1,
                f"Unknown ({consent_val.data})",
            )
            evidence_lines.append(
                f"ConsentPromptBehaviorAdmin: {consent_val.data} ({consent_name})"
            )
        else:
            evidence_lines.append(
                "ConsentPromptBehaviorAdmin: not found (default: 5)"
            )

        # -- PromptOnSecureDesktop --
        secure_desktop_val = registry.read_value(
            registry.HKEY_LOCAL_MACHINE, _UAC_POLICY_PATH, "PromptOnSecureDesktop"
        )
        prompt_secure_desktop: int | None = None
        if secure_desktop_val is not None:
            try:
                prompt_secure_desktop = int(secure_desktop_val.data)
            except (ValueError, TypeError):
                prompt_secure_desktop = None
            evidence_lines.append(
                f"PromptOnSecureDesktop: {secure_desktop_val.data}"
            )
        else:
            evidence_lines.append("PromptOnSecureDesktop: not found (default: 1)")

        # -- FilterAdministratorToken --
        filter_admin_val = registry.read_value(
            registry.HKEY_LOCAL_MACHINE, _UAC_POLICY_PATH, "FilterAdministratorToken"
        )
        filter_admin: int | None = None
        if filter_admin_val is not None:
            try:
                filter_admin = int(filter_admin_val.data)
            except (ValueError, TypeError):
                filter_admin = None
            evidence_lines.append(
                f"FilterAdministratorToken: {filter_admin_val.data}"
            )
        else:
            evidence_lines.append(
                "FilterAdministratorToken: not found (default: 0)"
            )

        evidence_text = "\n".join(evidence_lines)

        # -- Findings --

        # EnableLUA = 0 means UAC is completely disabled
        if enable_lua is not None and enable_lua == 0:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="UAC is disabled",
                description=(
                    "User Account Control is completely disabled (EnableLUA=0). "
                    "All applications run with full administrative privileges "
                    "without any elevation prompt. This removes a critical "
                    "security boundary and allows malware to execute with "
                    "unrestricted access immediately."
                ),
                severity=Severity.CRITICAL,
                category=self.CATEGORY,
                affected_item="EnableLUA",
                evidence=evidence_text,
                recommendation=(
                    "Re-enable UAC immediately by setting EnableLUA to 1 under "
                    "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System. "
                    "A reboot is required for the change to take effect."
                ),
                references=[
                    "https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/",
                    "https://attack.mitre.org/techniques/T1548/002/",
                ],
            ))

        # ConsentPromptBehaviorAdmin = 0 means elevate without prompting
        if consent_behavior is not None and consent_behavior == 0:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="UAC set to never prompt",
                description=(
                    "ConsentPromptBehaviorAdmin is set to 0 (Elevate without "
                    "prompting). Administrative users are never prompted when "
                    "an application requests elevation. Malware can silently "
                    "elevate to administrative privileges without user awareness."
                ),
                severity=Severity.HIGH,
                category=self.CATEGORY,
                affected_item="ConsentPromptBehaviorAdmin",
                evidence=evidence_text,
                recommendation=(
                    "Set ConsentPromptBehaviorAdmin to 2 (Prompt for consent "
                    "on secure desktop) for maximum security, or 5 (Prompt for "
                    "consent for non-Windows binaries) for balanced usability."
                ),
                references=[
                    "https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/settings-and-configuration",
                    "https://attack.mitre.org/techniques/T1548/002/",
                ],
            ))

        # PromptOnSecureDesktop = 0 means Secure Desktop is off
        if prompt_secure_desktop is not None and prompt_secure_desktop == 0:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Secure Desktop disabled for UAC",
                description=(
                    "PromptOnSecureDesktop is set to 0. UAC elevation prompts "
                    "are displayed on the interactive user desktop instead of "
                    "the isolated Secure Desktop. Malware running in the user "
                    "session can spoof or interact with the elevation dialog "
                    "to trick users into approving malicious elevation requests."
                ),
                severity=Severity.MEDIUM,
                category=self.CATEGORY,
                affected_item="PromptOnSecureDesktop",
                evidence=evidence_text,
                recommendation=(
                    "Set PromptOnSecureDesktop to 1 to ensure elevation prompts "
                    "appear on the Secure Desktop where other applications "
                    "cannot interact with the dialog."
                ),
                references=[
                    "https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/settings-and-configuration",
                ],
            ))

        # FilterAdministratorToken = 0 means built-in admin is not filtered
        if filter_admin is not None and filter_admin == 0:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Built-in admin not filtered",
                description=(
                    "FilterAdministratorToken is set to 0. The built-in "
                    "Administrator account (RID 500) runs all applications "
                    "with full administrative privileges without UAC filtering. "
                    "If this account is enabled, any process running under it "
                    "has unrestricted access."
                ),
                severity=Severity.MEDIUM,
                category=self.CATEGORY,
                affected_item="FilterAdministratorToken",
                evidence=evidence_text,
                recommendation=(
                    "Set FilterAdministratorToken to 1 to apply UAC token "
                    "filtering to the built-in Administrator account. "
                    "Alternatively, ensure the built-in Administrator account "
                    "is disabled if not needed."
                ),
                references=[
                    "https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/settings-and-configuration",
                ],
            ))

        # Additional read: ValidateAdminCodeSignatures
        validate_sig_val = registry.read_value(
            registry.HKEY_LOCAL_MACHINE, _UAC_POLICY_PATH,
            "ValidateAdminCodeSignatures"
        )
        if validate_sig_val is not None:
            try:
                validate_sig = int(validate_sig_val.data)
            except (ValueError, TypeError):
                validate_sig = None
            evidence_lines.append(
                f"ValidateAdminCodeSignatures: {validate_sig_val.data}"
            )
            if validate_sig is not None and validate_sig == 0:
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title="UAC does not require signed executables for elevation",
                    description=(
                        "ValidateAdminCodeSignatures is set to 0. UAC does not "
                        "require that executables requesting elevation are signed "
                        "and validated. Unsigned or tampered binaries can request "
                        "administrative privileges."
                    ),
                    severity=Severity.LOW,
                    category=self.CATEGORY,
                    affected_item="ValidateAdminCodeSignatures",
                    evidence=evidence_text,
                    recommendation=(
                        "Set ValidateAdminCodeSignatures to 1 to require PKI "
                        "certificate chain validation for any interactive "
                        "application that requests elevation."
                    ),
                    references=[
                        "https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/settings-and-configuration",
                    ],
                ))

        # Additional read: EnableInstallerDetection
        installer_detect_val = registry.read_value(
            registry.HKEY_LOCAL_MACHINE, _UAC_POLICY_PATH,
            "EnableInstallerDetection"
        )
        if installer_detect_val is not None:
            try:
                installer_detect = int(installer_detect_val.data)
            except (ValueError, TypeError):
                installer_detect = None
            evidence_lines.append(
                f"EnableInstallerDetection: {installer_detect_val.data}"
            )

        # Rebuild evidence with any additional values read
        evidence_text = "\n".join(evidence_lines)

        # INFO summary finding
        findings.append(Finding(
            check_id=self.CHECK_ID,
            title="UAC configuration assessment complete",
            description=(
                "Assessed User Account Control registry configuration "
                "including EnableLUA, ConsentPromptBehaviorAdmin, "
                "PromptOnSecureDesktop, and FilterAdministratorToken."
            ),
            severity=Severity.INFO,
            category=self.CATEGORY,
            affected_item="UAC Policy",
            evidence=evidence_text,
            recommendation="Review UAC settings against organizational security policy.",
            references=[
                "https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/",
            ],
        ))

        return findings
