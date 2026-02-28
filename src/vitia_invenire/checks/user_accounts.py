"""ACCT-001: Local user account security assessment.

Enumerates local users via Get-LocalUser, detects hidden accounts
(names ending in $), and audits the Administrators group membership
for unexpected entries.
"""

from __future__ import annotations

from vitia_invenire.checks.base import BaseCheck
from vitia_invenire.collectors.powershell import run_ps
from vitia_invenire.models import Category, Finding, Severity

# Built-in Windows accounts that are expected in the Administrators group
_EXPECTED_ADMIN_ACCOUNTS: set[str] = {
    "ADMINISTRATOR",
    "DOMAIN ADMINS",
}

# Built-in Windows user accounts that always exist
_BUILTIN_ACCOUNTS: set[str] = {
    "ADMINISTRATOR",
    "GUEST",
    "DEFAULTACCOUNT",
    "WDAGUTILITYACCOUNT",
}


class UserAccountsCheck(BaseCheck):
    """Audit local user accounts and administrator group membership."""

    CHECK_ID = "ACCT-001"
    NAME = "User Account Audit"
    DESCRIPTION = (
        "Enumerates local user accounts, detects hidden accounts "
        "(names ending in $), and audits the local Administrators "
        "group for unexpected members."
    )
    CATEGORY = Category.ACCOUNTS
    REQUIRES_ADMIN = False

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        self._enumerate_local_users(findings)
        self._check_admin_group(findings)

        return findings

    def _enumerate_local_users(self, findings: list[Finding]) -> None:
        """Enumerate all local users and detect hidden or suspicious accounts."""
        result = run_ps(
            "Get-LocalUser | Select-Object Name, Enabled, "
            "PasswordRequired, PasswordLastSet, LastLogon, "
            "Description, SID, UserMayChangePassword, "
            "PasswordExpires, AccountExpires",
            timeout=20,
            as_json=True,
        )

        if not result.success or result.json_output is None:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Failed to enumerate local users",
                description=f"Get-LocalUser failed: {result.error or 'unknown error'}",
                severity=Severity.MEDIUM,
                category=self.CATEGORY,
                affected_item="Local User Accounts",
                evidence=result.output[:500] if result.output else "No output",
                recommendation="Verify PowerShell can access local user management cmdlets.",
            ))
            return

        users = result.json_output
        if isinstance(users, dict):
            users = [users]

        total_users = len(users)
        hidden_users: list[str] = []
        enabled_users: list[str] = []
        no_password_users: list[str] = []

        user_summary_lines: list[str] = []

        for user in users:
            name = str(user.get("Name", "Unknown"))
            enabled = user.get("Enabled", False)
            pwd_required = user.get("PasswordRequired", True)
            pwd_last_set = str(user.get("PasswordLastSet", "Never"))
            last_logon = str(user.get("LastLogon", "Never"))
            description = str(user.get("Description", ""))
            sid = str(user.get("SID", {}).get("Value", "")) if isinstance(user.get("SID"), dict) else str(user.get("SID", ""))

            user_summary_lines.append(
                f"  {name}: Enabled={enabled}, PwdRequired={pwd_required}, LastLogon={last_logon}"
            )

            if enabled:
                enabled_users.append(name)

            # Check for hidden accounts (name ending in $)
            if name.endswith("$"):
                hidden_users.append(name)
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title=f"Hidden user account detected: {name}",
                    description=(
                        f"A user account ending in '$' was found: '{name}'. "
                        "Accounts with names ending in '$' are hidden from default "
                        "user enumeration tools and may indicate a backdoor account "
                        "created by an attacker."
                    ),
                    severity=Severity.HIGH,
                    category=self.CATEGORY,
                    affected_item=f"User: {name}",
                    evidence=(
                        f"Name: {name}\n"
                        f"Enabled: {enabled}\n"
                        f"SID: {sid}\n"
                        f"Description: {description}\n"
                        f"Password Last Set: {pwd_last_set}\n"
                        f"Last Logon: {last_logon}"
                    ),
                    recommendation=(
                        f"Investigate user account '{name}'. If unauthorized, "
                        f"disable and remove: Remove-LocalUser -Name '{name}'"
                    ),
                    references=[
                        "https://attack.mitre.org/techniques/T1136/001/",
                    ],
                ))

            # Check for enabled accounts without password requirement
            if enabled and not pwd_required:
                name_upper = name.upper()
                if name_upper not in _BUILTIN_ACCOUNTS:
                    no_password_users.append(name)
                    findings.append(Finding(
                        check_id=self.CHECK_ID,
                        title=f"Account without password requirement: {name}",
                        description=(
                            f"User account '{name}' is enabled but does not require "
                            "a password. This allows anyone to log in as this user."
                        ),
                        severity=Severity.HIGH,
                        category=self.CATEGORY,
                        affected_item=f"User: {name}",
                        evidence=(
                            f"Name: {name}\n"
                            f"Enabled: {enabled}\n"
                            f"PasswordRequired: {pwd_required}\n"
                            f"SID: {sid}"
                        ),
                        recommendation=(
                            f"Set a strong password for '{name}': "
                            f"Set-LocalUser -Name '{name}' -PasswordNeverExpires $false"
                        ),
                    ))

            # Check if the Guest account is enabled
            if name.upper() == "GUEST" and enabled:
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title="Guest account is enabled",
                    description=(
                        "The built-in Guest account is enabled. This provides "
                        "anonymous access to the system and should be disabled."
                    ),
                    severity=Severity.HIGH,
                    category=self.CATEGORY,
                    affected_item="User: Guest",
                    evidence=(
                        f"Name: Guest\n"
                        f"Enabled: True\n"
                        f"SID: {sid}"
                    ),
                    recommendation="Disable the Guest account: Disable-LocalUser -Name Guest",
                    references=[
                        "https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/accounts-guest-account-status",
                    ],
                ))

        # Summary finding
        findings.append(Finding(
            check_id=self.CHECK_ID,
            title="Local user account enumeration summary",
            description=(
                f"Found {total_users} local user accounts. "
                f"{len(enabled_users)} enabled, {len(hidden_users)} hidden, "
                f"{len(no_password_users)} without password requirements."
            ),
            severity=Severity.INFO,
            category=self.CATEGORY,
            affected_item="Local User Accounts",
            evidence="\n".join(user_summary_lines) if user_summary_lines else "No users found",
            recommendation="Review user accounts periodically and remove unused accounts.",
        ))

    def _check_admin_group(self, findings: list[Finding]) -> None:
        """Enumerate members of the local Administrators group."""
        result = run_ps(
            "Get-LocalGroupMember -Group 'Administrators' | "
            "Select-Object Name, ObjectClass, PrincipalSource, "
            "@{N='SIDValue';E={$_.SID.Value}}",
            timeout=20,
            as_json=True,
        )

        if not result.success or result.json_output is None:
            # Try with localized name
            result = run_ps(
                "$adminGroup = (Get-LocalGroup | Where-Object { "
                "$_.SID.Value -eq 'S-1-5-32-544' }).Name; "
                "Get-LocalGroupMember -Group $adminGroup | "
                "Select-Object Name, ObjectClass, PrincipalSource, "
                "@{N='SIDValue';E={$_.SID.Value}}",
                timeout=20,
                as_json=True,
            )

        if not result.success or result.json_output is None:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Failed to enumerate Administrators group",
                description=f"Get-LocalGroupMember failed: {result.error or 'unknown error'}",
                severity=Severity.MEDIUM,
                category=self.CATEGORY,
                affected_item="Administrators Group",
                evidence=result.output[:500] if result.output else "No output",
                recommendation="Manually verify Administrators group: net localgroup Administrators",
            ))
            return

        members = result.json_output
        if isinstance(members, dict):
            members = [members]

        unexpected_admins: list[str] = []
        hidden_admins: list[str] = []
        member_lines: list[str] = []

        for member in members:
            name = str(member.get("Name", "Unknown"))
            obj_class = str(member.get("ObjectClass", "Unknown"))
            source = str(member.get("PrincipalSource", "Unknown"))
            sid = str(member.get("SIDValue", ""))

            member_lines.append(f"  {name} ({obj_class}, Source: {source}, SID: {sid})")

            # Extract the account name portion (DOMAIN\Username or Username)
            account_name = name.split("\\")[-1].upper() if "\\" in name else name.upper()

            # Check for hidden admin accounts
            if account_name.endswith("$"):
                hidden_admins.append(name)
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title=f"Hidden account in Administrators group: {name}",
                    description=(
                        f"A hidden account (ending in '$') was found in the local "
                        f"Administrators group: '{name}'. This is a strong indicator "
                        "of a backdoor account with full system privileges."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.CATEGORY,
                    affected_item=f"Admin: {name}",
                    evidence=(
                        f"Name: {name}\n"
                        f"Type: {obj_class}\n"
                        f"Source: {source}\n"
                        f"SID: {sid}"
                    ),
                    recommendation=(
                        f"Immediately investigate and remove: "
                        f"Remove-LocalGroupMember -Group 'Administrators' -Member '{name}'"
                    ),
                    references=[
                        "https://attack.mitre.org/techniques/T1098/",
                    ],
                ))
                continue

            # Check for unexpected admins (not in expected list)
            if account_name not in _EXPECTED_ADMIN_ACCOUNTS:
                unexpected_admins.append(name)
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title=f"Unexpected Administrators group member: {name}",
                    description=(
                        f"User '{name}' is a member of the local Administrators group "
                        "but is not in the expected administrators list. Non-default "
                        "administrator accounts increase the attack surface."
                    ),
                    severity=Severity.HIGH,
                    category=self.CATEGORY,
                    affected_item=f"Admin: {name}",
                    evidence=(
                        f"Name: {name}\n"
                        f"Type: {obj_class}\n"
                        f"Source: {source}\n"
                        f"SID: {sid}"
                    ),
                    recommendation=(
                        f"Verify that '{name}' requires administrator privileges. "
                        "Remove from Administrators group if not needed. "
                        "Follow least-privilege principle."
                    ),
                    references=[
                        "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/implementing-least-privilege-administrative-models",
                    ],
                ))

        # Summary finding
        findings.append(Finding(
            check_id=self.CHECK_ID,
            title="Administrators group membership summary",
            description=(
                f"Found {len(members)} members in the Administrators group. "
                f"{len(unexpected_admins)} unexpected, {len(hidden_admins)} hidden."
            ),
            severity=Severity.INFO,
            category=self.CATEGORY,
            affected_item="Administrators Group",
            evidence="\n".join(member_lines) if member_lines else "No members found",
            recommendation="Minimize Administrators group membership.",
        ))
