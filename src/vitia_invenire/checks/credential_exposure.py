"""CRED-001: Credential exposure detection.

Checks WDigest clear-text credential storage, NTLM compatibility level,
LM hash storage, cached logon count, credential delegation, and stored
credentials to identify credential exposure risks.
"""

from __future__ import annotations

from vitia_invenire.checks.base import BaseCheck
from vitia_invenire.collectors import registry
from vitia_invenire.collectors.powershell import run_ps
from vitia_invenire.models import Category, Finding, Severity

# Registry paths
_WDIGEST_PATH = r"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
_LSA_PATH = r"SYSTEM\CurrentControlSet\Control\Lsa"
_WINLOGON_PATH = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
_CRED_DELEGATION_PATH = r"SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation"

# LmCompatibilityLevel descriptions
_LM_COMPAT_LEVELS: dict[int, tuple[str, Severity]] = {
    0: ("Send LM and NTLM responses", Severity.HIGH),
    1: ("Send LM and NTLM, use NTLMv2 session security if negotiated", Severity.HIGH),
    2: ("Send NTLM response only", Severity.HIGH),
    3: ("Send NTLMv2 response only", Severity.MEDIUM),
    4: ("Send NTLMv2 response only, refuse LM", Severity.LOW),
    5: ("Send NTLMv2 response only, refuse LM and NTLM", Severity.INFO),
}


class CredentialExposureCheck(BaseCheck):
    """Detect credential exposure risks in Windows configuration."""

    CHECK_ID = "CRED-001"
    NAME = "Credential Exposure Detection"
    DESCRIPTION = (
        "Checks WDigest clear-text credential storage, NTLM compatibility "
        "level, LM hash storage, cached logon count, credential delegation, "
        "and stored credentials to identify credential exposure risks."
    )
    CATEGORY = Category.ACCOUNTS
    REQUIRES_ADMIN = True

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        issues_found = 0

        issues_found += self._check_wdigest(findings)
        issues_found += self._check_lm_compatibility(findings)
        issues_found += self._check_no_lm_hash(findings)
        issues_found += self._check_cached_logons(findings)
        issues_found += self._check_credential_delegation(findings)
        issues_found += self._check_stored_credentials(findings)

        # Summary finding
        findings.append(Finding(
            check_id=self.CHECK_ID,
            title="Credential exposure assessment summary",
            description=(
                f"Assessed 6 credential security controls. "
                f"{issues_found} issue(s) identified."
            ),
            severity=Severity.INFO,
            category=self.CATEGORY,
            affected_item="Credential Security",
            evidence=(
                f"Controls checked: WDigest, LmCompatibilityLevel, "
                f"NoLMHash, CachedLogonsCount, CredentialsDelegation, "
                f"stored credentials\n"
                f"Issues found: {issues_found}"
            ),
            recommendation=(
                "Disable WDigest clear-text storage, enforce NTLMv2-only "
                "authentication, disable LM hash storage, reduce cached "
                "logons, restrict credential delegation, and audit stored "
                "credentials."
            ),
        ))

        return findings

    def _check_wdigest(self, findings: list[Finding]) -> int:
        """Check WDigest UseLogonCredential for clear-text password storage."""
        val = registry.read_value(
            registry.HKEY_LOCAL_MACHINE,
            _WDIGEST_PATH,
            "UseLogonCredential",
        )

        if val is not None:
            try:
                current = int(val.data)
            except (ValueError, TypeError):
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title="WDigest UseLogonCredential has unexpected value",
                    description=(
                        f"UseLogonCredential is set to '{val.data}' which "
                        "could not be parsed as an integer."
                    ),
                    severity=Severity.MEDIUM,
                    category=self.CATEGORY,
                    affected_item="WDigest UseLogonCredential",
                    evidence=(
                        f"Registry: HKLM\\{_WDIGEST_PATH}\n"
                        f"Value: UseLogonCredential = {val.data} (type: {val.type})"
                    ),
                    recommendation="Verify and set UseLogonCredential to 0.",
                ))
                return 1

            if current == 1:
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title="WDigest stores clear-text passwords in memory",
                    description=(
                        "WDigest UseLogonCredential is set to 1, which causes "
                        "Windows to store clear-text copies of user passwords "
                        "in LSASS process memory. Credential dumping tools such "
                        "as Mimikatz can extract these passwords directly. This "
                        "is a critical security vulnerability."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.CATEGORY,
                    affected_item="WDigest UseLogonCredential",
                    evidence=(
                        f"Registry: HKLM\\{_WDIGEST_PATH}\n"
                        f"Value: UseLogonCredential = 1\n"
                        f"Expected: 0 (or not configured)"
                    ),
                    recommendation=(
                        "Set UseLogonCredential to 0: "
                        "reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\"
                        "SecurityProviders\\WDigest /v UseLogonCredential "
                        "/t REG_DWORD /d 0 /f. "
                        "Reboot is required for the change to take effect."
                    ),
                    references=[
                        "https://attack.mitre.org/techniques/T1003/001/",
                        "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/dn785092(v=ws.11)",
                    ],
                ))
                return 1

        # UseLogonCredential is 0 or not configured (safe default on Win 8.1+)
        current_display = str(val.data) if val is not None else "not configured (default: 0)"
        findings.append(Finding(
            check_id=self.CHECK_ID,
            title="WDigest clear-text password storage is disabled",
            description=(
                "WDigest UseLogonCredential is not set to 1. Clear-text "
                "passwords are not stored in LSASS memory by WDigest."
            ),
            severity=Severity.INFO,
            category=self.CATEGORY,
            affected_item="WDigest UseLogonCredential",
            evidence=(
                f"Registry: HKLM\\{_WDIGEST_PATH}\n"
                f"Value: UseLogonCredential = {current_display}"
            ),
            recommendation="No action needed.",
        ))
        return 0

    def _check_lm_compatibility(self, findings: list[Finding]) -> int:
        """Check LmCompatibilityLevel for NTLM authentication strength."""
        val = registry.read_value(
            registry.HKEY_LOCAL_MACHINE,
            _LSA_PATH,
            "LmCompatibilityLevel",
        )

        if val is None:
            # Default is typically 3 on modern Windows, but not explicitly set
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="LmCompatibilityLevel is not explicitly configured",
                description=(
                    "The LmCompatibilityLevel registry value is not set. "
                    "Modern Windows defaults to level 3 (send NTLMv2 only), "
                    "but the effective level depends on domain policy. "
                    "Explicitly setting this value ensures the expected "
                    "NTLM behavior regardless of domain configuration."
                ),
                severity=Severity.LOW,
                category=self.CATEGORY,
                affected_item="LmCompatibilityLevel",
                evidence=(
                    f"Registry: HKLM\\{_LSA_PATH}\n"
                    f"Value: LmCompatibilityLevel\n"
                    f"Current: not configured\n"
                    f"Recommended: 5 (send NTLMv2 only, refuse LM and NTLM)"
                ),
                recommendation=(
                    "Set LmCompatibilityLevel to 5 via Group Policy: "
                    "Computer Configuration > Windows Settings > "
                    "Security Settings > Local Policies > Security Options > "
                    "Network security: LAN Manager authentication level."
                ),
                references=[
                    "https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-lan-manager-authentication-level",
                ],
            ))
            return 1

        try:
            level = int(val.data)
        except (ValueError, TypeError):
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="LmCompatibilityLevel has unexpected value",
                description=(
                    f"LmCompatibilityLevel is set to '{val.data}' which "
                    "could not be parsed as an integer."
                ),
                severity=Severity.MEDIUM,
                category=self.CATEGORY,
                affected_item="LmCompatibilityLevel",
                evidence=(
                    f"Registry: HKLM\\{_LSA_PATH}\n"
                    f"Value: LmCompatibilityLevel = {val.data} (type: {val.type})"
                ),
                recommendation="Verify and set LmCompatibilityLevel to 5.",
            ))
            return 1

        if level < 3:
            level_desc, severity = _LM_COMPAT_LEVELS.get(
                level, (f"Unknown level {level}", Severity.HIGH)
            )
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title=f"Weak NTLM authentication level ({level})",
                description=(
                    f"LmCompatibilityLevel is set to {level}: '{level_desc}'. "
                    "Levels below 3 allow NTLMv1 or LM authentication, which "
                    "are cryptographically weak and vulnerable to offline "
                    "cracking attacks. Attackers can intercept and crack "
                    "NTLMv1/LM hashes rapidly."
                ),
                severity=Severity.HIGH,
                category=self.CATEGORY,
                affected_item="LmCompatibilityLevel",
                evidence=(
                    f"Registry: HKLM\\{_LSA_PATH}\n"
                    f"Value: LmCompatibilityLevel = {level}\n"
                    f"Description: {level_desc}\n"
                    f"Recommended: 5 (send NTLMv2 only, refuse LM and NTLM)"
                ),
                recommendation=(
                    "Set LmCompatibilityLevel to at least 3 (NTLMv2 only), "
                    "ideally 5 (refuse LM and NTLMv1). Test in your "
                    "environment first to ensure legacy system compatibility."
                ),
                references=[
                    "https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-lan-manager-authentication-level",
                    "https://attack.mitre.org/techniques/T1557/001/",
                ],
            ))
            return 1

        level_desc = _LM_COMPAT_LEVELS.get(level, (f"Level {level}", Severity.INFO))[0]
        findings.append(Finding(
            check_id=self.CHECK_ID,
            title=f"NTLM authentication level is {level}",
            description=(
                f"LmCompatibilityLevel is set to {level}: '{level_desc}'. "
                "NTLMv1 and LM authentication are restricted."
            ),
            severity=Severity.INFO,
            category=self.CATEGORY,
            affected_item="LmCompatibilityLevel",
            evidence=(
                f"Registry: HKLM\\{_LSA_PATH}\n"
                f"Value: LmCompatibilityLevel = {level}\n"
                f"Description: {level_desc}"
            ),
            recommendation=(
                "Consider increasing to level 5 for maximum security "
                "if legacy compatibility is not required."
                if level < 5 else "No action needed."
            ),
        ))
        return 0

    def _check_no_lm_hash(self, findings: list[Finding]) -> int:
        """Check if LM hash storage is disabled."""
        val = registry.read_value(
            registry.HKEY_LOCAL_MACHINE,
            _LSA_PATH,
            "NoLMHash",
        )

        if val is None:
            # Default on Vista+ is to not store LM hashes, but not explicit
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="NoLMHash not explicitly configured",
                description=(
                    "The NoLMHash registry value is not explicitly set. "
                    "Windows Vista and later default to not storing LM hashes, "
                    "but explicitly setting this value provides defense in depth."
                ),
                severity=Severity.LOW,
                category=self.CATEGORY,
                affected_item="NoLMHash",
                evidence=(
                    f"Registry: HKLM\\{_LSA_PATH}\n"
                    f"Value: NoLMHash\n"
                    f"Current: not configured\n"
                    f"Expected: 1"
                ),
                recommendation=(
                    "Set NoLMHash to 1 via Group Policy: "
                    "Computer Configuration > Windows Settings > "
                    "Security Settings > Local Policies > Security Options > "
                    "Network security: Do not store LAN Manager hash value "
                    "on next password change."
                ),
            ))
            return 0

        try:
            current = int(val.data)
        except (ValueError, TypeError):
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="NoLMHash has unexpected value",
                description=(
                    f"NoLMHash is set to '{val.data}' which could not be "
                    "parsed as an integer."
                ),
                severity=Severity.MEDIUM,
                category=self.CATEGORY,
                affected_item="NoLMHash",
                evidence=(
                    f"Registry: HKLM\\{_LSA_PATH}\n"
                    f"Value: NoLMHash = {val.data} (type: {val.type})"
                ),
                recommendation="Verify and set NoLMHash to 1.",
            ))
            return 1

        if current == 0:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="LM hash storage is enabled",
                description=(
                    "NoLMHash is set to 0, meaning Windows will store "
                    "LAN Manager hash values for passwords. LM hashes are "
                    "cryptographically weak (DES-based, case-insensitive, "
                    "split into 7-character blocks) and can be cracked almost "
                    "instantly with modern hardware."
                ),
                severity=Severity.HIGH,
                category=self.CATEGORY,
                affected_item="NoLMHash",
                evidence=(
                    f"Registry: HKLM\\{_LSA_PATH}\n"
                    f"Value: NoLMHash = 0\n"
                    f"Expected: 1 (disable LM hash storage)"
                ),
                recommendation=(
                    "Set NoLMHash to 1 and force all users to change "
                    "passwords to remove existing stored LM hashes."
                ),
                references=[
                    "https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-do-not-store-lan-manager-hash-value-on-next-password-change",
                    "https://attack.mitre.org/techniques/T1003/",
                ],
            ))
            return 1

        findings.append(Finding(
            check_id=self.CHECK_ID,
            title="LM hash storage is disabled",
            description="NoLMHash is set to 1. LM hashes are not stored.",
            severity=Severity.INFO,
            category=self.CATEGORY,
            affected_item="NoLMHash",
            evidence=(
                f"Registry: HKLM\\{_LSA_PATH}\n"
                f"Value: NoLMHash = {current}"
            ),
            recommendation="No action needed.",
        ))
        return 0

    def _check_cached_logons(self, findings: list[Finding]) -> int:
        """Check the number of cached domain logon credentials."""
        val = registry.read_value(
            registry.HKEY_LOCAL_MACHINE,
            _WINLOGON_PATH,
            "CachedLogonsCount",
        )

        if val is None:
            # Default is 10 on Windows
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="CachedLogonsCount not explicitly configured (default: 10)",
                description=(
                    "CachedLogonsCount is not explicitly set. Windows defaults "
                    "to caching 10 domain logon credentials. Cached credentials "
                    "can be extracted and cracked offline by attackers with "
                    "local administrator access."
                ),
                severity=Severity.LOW,
                category=self.CATEGORY,
                affected_item="CachedLogonsCount",
                evidence=(
                    f"Registry: HKLM\\{_WINLOGON_PATH}\n"
                    f"Value: CachedLogonsCount\n"
                    f"Current: not configured (default: 10)\n"
                    f"Recommended: 4 or less for sensitive systems, "
                    f"0 for high-security environments"
                ),
                recommendation=(
                    "Reduce CachedLogonsCount via Group Policy: "
                    "Computer Configuration > Windows Settings > "
                    "Security Settings > Local Policies > Security Options > "
                    "Interactive logon: Number of previous logons to cache."
                ),
            ))
            return 0

        try:
            count = int(val.data)
        except (ValueError, TypeError):
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="CachedLogonsCount has unexpected value",
                description=(
                    f"CachedLogonsCount is set to '{val.data}' which could "
                    "not be parsed as an integer."
                ),
                severity=Severity.MEDIUM,
                category=self.CATEGORY,
                affected_item="CachedLogonsCount",
                evidence=(
                    f"Registry: HKLM\\{_WINLOGON_PATH}\n"
                    f"Value: CachedLogonsCount = {val.data} (type: {val.type})"
                ),
                recommendation="Verify and correct the CachedLogonsCount value.",
            ))
            return 1

        if count > 10:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title=f"Excessive cached logon credentials ({count})",
                description=(
                    f"CachedLogonsCount is set to {count}, which is above "
                    f"the default of 10. Each cached credential represents "
                    f"a domain account whose password hash is stored locally "
                    f"and can be targeted for offline cracking by an attacker "
                    f"with local administrator access."
                ),
                severity=Severity.MEDIUM,
                category=self.CATEGORY,
                affected_item="CachedLogonsCount",
                evidence=(
                    f"Registry: HKLM\\{_WINLOGON_PATH}\n"
                    f"Value: CachedLogonsCount = {count}\n"
                    f"Recommended: 4 or less"
                ),
                recommendation=(
                    f"Reduce CachedLogonsCount to 4 or less. Set to 0 for "
                    f"systems that always have network connectivity to domain "
                    f"controllers."
                ),
                references=[
                    "https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/interactive-logon-number-of-previous-logons-to-cache-in-case-domain-controller-is-not-available",
                    "https://attack.mitre.org/techniques/T1003/005/",
                ],
            ))
            return 1

        findings.append(Finding(
            check_id=self.CHECK_ID,
            title=f"Cached logon count is {count}",
            description=(
                f"CachedLogonsCount is set to {count}."
                + (
                    " This is within the acceptable range."
                    if count <= 4
                    else " Consider reducing to 4 or less for sensitive systems."
                )
            ),
            severity=Severity.INFO,
            category=self.CATEGORY,
            affected_item="CachedLogonsCount",
            evidence=(
                f"Registry: HKLM\\{_WINLOGON_PATH}\n"
                f"Value: CachedLogonsCount = {count}"
            ),
            recommendation=(
                "No action needed."
                if count <= 4
                else "Consider reducing to 4 or less for high-security environments."
            ),
        ))
        return 0

    def _check_credential_delegation(self, findings: list[Finding]) -> int:
        """Check if credential delegation (CredSSP) is enabled."""
        val = registry.read_value(
            registry.HKEY_LOCAL_MACHINE,
            _CRED_DELEGATION_PATH,
            "AllowDefaultCredentials",
        )

        if val is None:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Credential delegation policy not configured",
                description=(
                    "AllowDefaultCredentials is not configured. Default "
                    "credential delegation may be controlled by other "
                    "policies or application settings."
                ),
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="CredentialsDelegation",
                evidence=(
                    f"Registry: HKLM\\{_CRED_DELEGATION_PATH}\n"
                    f"Value: AllowDefaultCredentials\n"
                    f"Current: not configured"
                ),
                recommendation=(
                    "Review credential delegation policies to ensure "
                    "credentials are not forwarded to untrusted servers."
                ),
            ))
            return 0

        try:
            enabled = int(val.data)
        except (ValueError, TypeError):
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="AllowDefaultCredentials has unexpected value",
                description=(
                    f"AllowDefaultCredentials is set to '{val.data}' which "
                    "could not be parsed as an integer."
                ),
                severity=Severity.MEDIUM,
                category=self.CATEGORY,
                affected_item="CredentialsDelegation",
                evidence=(
                    f"Registry: HKLM\\{_CRED_DELEGATION_PATH}\n"
                    f"Value: AllowDefaultCredentials = {val.data} (type: {val.type})"
                ),
                recommendation="Verify the credential delegation configuration.",
            ))
            return 1

        if enabled == 1:
            # Check what servers are allowed
            subkeys = registry.enumerate_subkeys(
                registry.HKEY_LOCAL_MACHINE,
                _CRED_DELEGATION_PATH,
            )
            server_list_values = registry.read_key(
                registry.HKEY_LOCAL_MACHINE,
                _CRED_DELEGATION_PATH + r"\AllowDefaultCredentials",
            )
            server_list = [str(v.data) for v in server_list_values if v.data]

            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Credential delegation is enabled",
                description=(
                    "AllowDefaultCredentials is set to 1, enabling CredSSP "
                    "credential delegation. This allows the system to forward "
                    "user credentials to remote servers, which increases the "
                    "risk of credential theft if a delegated server is "
                    "compromised."
                ),
                severity=Severity.MEDIUM,
                category=self.CATEGORY,
                affected_item="CredentialsDelegation",
                evidence=(
                    f"Registry: HKLM\\{_CRED_DELEGATION_PATH}\n"
                    f"Value: AllowDefaultCredentials = 1\n"
                    f"Delegation targets: {', '.join(server_list) if server_list else 'none specified'}"
                ),
                recommendation=(
                    "Disable credential delegation unless specifically "
                    "required. If needed, restrict delegation targets to "
                    "specific trusted servers using AllowDefaultCredentials "
                    "server list. Consider using Remote Credential Guard "
                    "instead of CredSSP."
                ),
                references=[
                    "https://learn.microsoft.com/en-us/windows/security/identity-protection/remote-credential-guard",
                    "https://attack.mitre.org/techniques/T1556/",
                ],
            ))
            return 1

        findings.append(Finding(
            check_id=self.CHECK_ID,
            title="Credential delegation is not enabled",
            description=(
                f"AllowDefaultCredentials is set to {enabled}. Default "
                "credential delegation is not active."
            ),
            severity=Severity.INFO,
            category=self.CATEGORY,
            affected_item="CredentialsDelegation",
            evidence=(
                f"Registry: HKLM\\{_CRED_DELEGATION_PATH}\n"
                f"Value: AllowDefaultCredentials = {enabled}"
            ),
            recommendation="No action needed.",
        ))
        return 0

    def _check_stored_credentials(self, findings: list[Finding]) -> int:
        """Check for stored credentials using cmdkey."""
        result = run_ps(
            "cmdkey /list",
            timeout=15,
            as_json=False,
        )

        if not result.success:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Failed to enumerate stored credentials",
                description=(
                    f"Could not run cmdkey /list: "
                    f"{result.error or 'unknown error'}"
                ),
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="Stored Credentials",
                evidence=result.output[:500] if result.output else "No output",
                recommendation="Manually check stored credentials: cmdkey /list",
            ))
            return 0

        output = result.output.strip()
        if not output:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="No stored credentials found",
                description="cmdkey /list returned no stored credentials.",
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="Stored Credentials",
                evidence="cmdkey /list: no output",
                recommendation="No action needed.",
            ))
            return 0

        # Parse cmdkey output to count credential entries
        # Each credential block starts with "Target:" or "* Target:"
        credential_count = 0
        credential_targets: list[str] = []
        for line in output.splitlines():
            stripped = line.strip()
            if stripped.lower().startswith("target:") or stripped.lower().startswith("* target:"):
                credential_count += 1
                # Extract target name
                target = stripped.split(":", 1)[1].strip() if ":" in stripped else stripped
                credential_targets.append(target)

        if credential_count == 0:
            # Check for "no entries" type messages
            if "currently stored credentials" in output.lower() and "none" in output.lower():
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title="No stored credentials found",
                    description="The Windows Credential Manager has no stored credentials.",
                    severity=Severity.INFO,
                    category=self.CATEGORY,
                    affected_item="Stored Credentials",
                    evidence=output[:500],
                    recommendation="No action needed.",
                ))
                return 0

            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Stored credentials query completed",
                description="cmdkey completed but no credential entries were parsed.",
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="Stored Credentials",
                evidence=output[:500],
                recommendation="Manually review cmdkey /list output.",
            ))
            return 0

        # Stored credentials found
        target_evidence = "\n".join(f"  {t}" for t in credential_targets[:20])
        if len(credential_targets) > 20:
            target_evidence += f"\n  ... and {len(credential_targets) - 20} more"

        findings.append(Finding(
            check_id=self.CHECK_ID,
            title=f"Stored credentials found ({credential_count})",
            description=(
                f"Found {credential_count} stored credential(s) in the "
                f"Windows Credential Manager. Stored credentials can be "
                f"extracted by attackers with local administrator access "
                f"using tools such as Mimikatz or by accessing the DPAPI "
                f"credential store directly."
            ),
            severity=Severity.MEDIUM,
            category=self.CATEGORY,
            affected_item="Stored Credentials",
            evidence=(
                f"Stored credentials: {credential_count}\n"
                f"Targets:\n{target_evidence}"
            ),
            recommendation=(
                "Review stored credentials and remove any that are no "
                "longer needed: cmdkey /delete:targetname. Avoid storing "
                "domain administrator or service account credentials "
                "on workstations."
            ),
            references=[
                "https://attack.mitre.org/techniques/T1555/004/",
            ],
        ))
        return 1
