"""DPAPI-001: DPAPI and Credential Manager Audit.

Lists Credential Manager entries via cmdkey /list and checks for
unexpected stored credentials. Stored credentials for unusual hosts
or services may indicate credential harvesting, persistence, or
lateral movement preparation.
"""

from __future__ import annotations

import re

from vitia_invenire.checks.base import BaseCheck
from vitia_invenire.collectors.command import run_cmd
from vitia_invenire.models import Category, Finding, Severity

# Common legitimate credential targets that are generally expected
_COMMON_TARGETS = [
    "microsoftonline.com",
    "login.live.com",
    "login.microsoft.com",
    "office365.com",
    "outlook.office365.com",
    "teams.microsoft.com",
    "sharepoint.com",
    "visualstudio.com",
    "azure.com",
    "windows.net",
    "windowsazure.com",
    "virtualapp/didlogical",
    "sso_prt",
    "windowslive:",
    "microsoftaccount:",
    "msteams:",
]

# Patterns that suggest suspicious credential storage
_SUSPICIOUS_PATTERNS = [
    r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",  # IP addresses
    r"admin",
    r"root",
    r"ftp://",
    r"ssh://",
    r"rdp://",
    r"vnc://",
    r"smb://",
    r"\\\\[a-zA-Z0-9]",  # UNC paths
    r"domain:",
    r"termsrv/",
]


def _is_common_target(target: str) -> bool:
    """Return True if the credential target is a known common/legitimate entry."""
    target_lower = target.lower()
    return any(common in target_lower for common in _COMMON_TARGETS)


def _is_suspicious_target(target: str) -> bool:
    """Return True if the credential target matches suspicious patterns."""
    target_lower = target.lower()
    for pattern in _SUSPICIOUS_PATTERNS:
        if re.search(pattern, target_lower):
            return True
    return False


class DPAPIAuditCheck(BaseCheck):
    """Audit DPAPI Credential Manager stored credentials."""

    CHECK_ID = "DPAPI-001"
    NAME = "DPAPI Credential Manager Audit"
    DESCRIPTION = (
        "Lists Credential Manager entries via cmdkey /list and inspects "
        "them for unexpected stored credentials that may indicate "
        "credential harvesting or lateral movement preparation."
    )
    CATEGORY = Category.CONFIGURATION
    REQUIRES_ADMIN = False

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        # Run cmdkey /list to enumerate stored credentials
        result = run_cmd(["cmdkey", "/list"], timeout=15)

        if not result.success:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Unable to Query Credential Manager",
                description="Failed to enumerate Credential Manager entries.",
                severity=Severity.LOW,
                category=self.CATEGORY,
                affected_item="Credential Manager",
                evidence=f"Error: {result.stderr or 'cmdkey /list failed'}",
                recommendation="Run cmdkey /list manually to verify access.",
                references=[
                    "https://attack.mitre.org/techniques/T1555/004/",
                ],
            ))
            return findings

        # Parse cmdkey output
        # Format:
        #   Target: <target_name>
        #   Type: <type>
        #   User: <username>
        credentials: list[dict[str, str]] = []
        current_cred: dict[str, str] = {}

        for line in result.stdout.splitlines():
            stripped = line.strip()

            if stripped.lower().startswith("target:"):
                if current_cred:
                    credentials.append(current_cred)
                current_cred = {"target": stripped.split(":", 1)[1].strip()}
            elif stripped.lower().startswith("type:"):
                current_cred["type"] = stripped.split(":", 1)[1].strip()
            elif stripped.lower().startswith("user:"):
                current_cred["user"] = stripped.split(":", 1)[1].strip()
            elif stripped.lower().startswith("local machine persistence"):
                current_cred["persistence"] = "Local Machine"
            elif stripped.lower().startswith("enterprise persistence"):
                current_cred["persistence"] = "Enterprise"

        if current_cred:
            credentials.append(current_cred)

        if not credentials:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="No Credential Manager Entries Found",
                description="Credential Manager contains no stored credentials.",
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="Credential Manager",
                evidence="cmdkey /list returned no credential entries.",
                recommendation="No action required.",
                references=[
                    "https://attack.mitre.org/techniques/T1555/004/",
                ],
            ))
            return findings

        # Categorize credentials
        suspicious_creds: list[dict[str, str]] = []
        unusual_creds: list[dict[str, str]] = []
        normal_creds: list[dict[str, str]] = []

        for cred in credentials:
            target = cred.get("target", "")
            if _is_suspicious_target(target):
                suspicious_creds.append(cred)
            elif not _is_common_target(target):
                unusual_creds.append(cred)
            else:
                normal_creds.append(cred)

        # Report suspicious credentials
        if suspicious_creds:
            evidence_lines = []
            for cred in suspicious_creds:
                evidence_lines.append(
                    f"Target: {cred.get('target', 'Unknown')}\n"
                    f"  Type: {cred.get('type', 'Unknown')}\n"
                    f"  User: {cred.get('user', 'Unknown')}\n"
                    f"  Persistence: {cred.get('persistence', 'Unknown')}"
                )
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Suspicious Stored Credentials Detected",
                description=(
                    f"{len(suspicious_creds)} stored credential(s) target "
                    f"suspicious destinations such as IP addresses, UNC paths, "
                    f"admin accounts, or remote access protocols. This may "
                    f"indicate lateral movement preparation or credential "
                    f"harvesting by an attacker."
                ),
                severity=Severity.HIGH,
                category=self.CATEGORY,
                affected_item="Credential Manager",
                evidence="\n\n".join(evidence_lines),
                recommendation=(
                    "Review each suspicious credential entry. Remove any "
                    "unauthorized stored credentials using 'cmdkey /delete:<target>'. "
                    "Investigate how the credentials were stored and whether "
                    "they are being actively used."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1555/004/",
                    "https://attack.mitre.org/techniques/T1078/",
                ],
            ))

        # Report unusual (non-common) credentials
        if unusual_creds:
            evidence_lines = []
            for cred in unusual_creds:
                evidence_lines.append(
                    f"Target: {cred.get('target', 'Unknown')}\n"
                    f"  Type: {cred.get('type', 'Unknown')}\n"
                    f"  User: {cred.get('user', 'Unknown')}\n"
                    f"  Persistence: {cred.get('persistence', 'Unknown')}"
                )
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Unusual Stored Credentials Found",
                description=(
                    f"{len(unusual_creds)} stored credential(s) target "
                    f"destinations that are not among common Microsoft services. "
                    f"These should be reviewed for legitimacy."
                ),
                severity=Severity.MEDIUM,
                category=self.CATEGORY,
                affected_item="Credential Manager",
                evidence="\n\n".join(evidence_lines),
                recommendation=(
                    "Verify each credential entry belongs to authorized, "
                    "known services. Remove any that are unrecognized."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1555/004/",
                ],
            ))

        # Summary
        findings.append(Finding(
            check_id=self.CHECK_ID,
            title="Credential Manager Inventory",
            description=(
                f"Found {len(credentials)} total Credential Manager "
                f"entries: {len(normal_creds)} common, "
                f"{len(unusual_creds)} unusual, "
                f"{len(suspicious_creds)} suspicious."
            ),
            severity=Severity.INFO,
            category=self.CATEGORY,
            affected_item="Credential Manager",
            evidence=(
                f"Total entries: {len(credentials)}\n"
                f"Common/Expected: {len(normal_creds)}\n"
                f"Unusual: {len(unusual_creds)}\n"
                f"Suspicious: {len(suspicious_creds)}"
            ),
            recommendation="Review stored credentials periodically.",
            references=[
                "https://attack.mitre.org/techniques/T1555/004/",
            ],
        ))

        return findings
