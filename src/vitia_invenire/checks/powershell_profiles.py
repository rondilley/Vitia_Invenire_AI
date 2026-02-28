"""PS-001: PowerShell profile persistence detection.

Checks all four standard PowerShell profile paths for suspicious
content including network activity, file downloads, encoded commands,
and obfuscated scripts.
"""

from __future__ import annotations

import re

from vitia_invenire.checks.base import BaseCheck
from vitia_invenire.collectors.powershell import run_ps
from vitia_invenire.models import Category, Finding, Severity

# Suspicious patterns in PowerShell profiles
_SUSPICIOUS_PATTERNS: list[tuple[str, str, str]] = [
    (
        r"[Ii]nvoke-[Ww]eb[Rr]equest|[Ii]wr\s|wget\s|curl\s",
        "Network download (Invoke-WebRequest)",
        "Profile downloads content from the internet at every PowerShell session start",
    ),
    (
        r"[Nn]et\.[Ww]eb[Cc]lient|[Dd]ownload[Ff]ile|[Dd]ownload[Ss]tring|[Dd]ownload[Dd]ata",
        "Network download (.NET WebClient)",
        "Profile uses .NET WebClient for file downloads",
    ),
    (
        r"[Ss]tart-[Bb]its[Tt]ransfer",
        "BITS transfer download",
        "Profile uses BITS for file transfer",
    ),
    (
        r"-[Ee]nc(?:oded)?[Cc]ommand\s",
        "Encoded command execution",
        "Profile executes base64-encoded PowerShell commands",
    ),
    (
        r"[Ff]rom[Bb]ase64[Ss]tring|[Cc]onvert.*[Bb]ase64",
        "Base64 decoding",
        "Profile decodes base64-encoded content",
    ),
    (
        r"[Nn]ew-[Oo]bject\s+[Ss]ystem\.[Nn]et\.[Ss]ockets",
        "Raw socket creation",
        "Profile creates raw network sockets - possible reverse shell",
    ),
    (
        r"[Ss]ystem\.[Nn]et\.[Ss]ockets\.[Tt]cp[Cc]lient",
        "TCP client creation",
        "Profile creates TCP connections - possible C2 communication",
    ),
    (
        r"[Ss]tream[Rr]eader|[Ss]tream[Ww]riter",
        "Stream I/O",
        "Profile uses stream readers/writers - common in reverse shells",
    ),
    (
        r"[Ii]nvoke-[Ee]xpression|[Ii]ex\s|\|\s*[Ii]ex\b",
        "Dynamic code execution (IEX)",
        "Profile uses Invoke-Expression to execute dynamic code",
    ),
    (
        r"\[System\.Reflection\.Assembly\]::Load|Add-Type.*-TypeDefinition",
        "Assembly loading / inline compilation",
        "Profile loads .NET assemblies or compiles code at runtime",
    ),
    (
        r"[Ss]et-[Mm]p[Pp]reference|[Dd]isable.*[Rr]eal[Tt]ime|[Ee]xclusion[Pp]ath",
        "Defender tampering",
        "Profile modifies Windows Defender settings",
    ),
    (
        r"[Nn]ew-[Ss]cheduled[Tt]ask|[Rr]egister-[Ss]cheduled[Tt]ask",
        "Scheduled task creation",
        "Profile creates scheduled tasks for persistence",
    ),
    (
        r"[Ss]et-[Ii]tem[Pp]roperty.*[Rr]un\b|[Nn]ew-[Ii]tem[Pp]roperty.*[Rr]un\b",
        "Registry Run key modification",
        "Profile modifies autostart registry keys",
    ),
    (
        r"[Hh]idden[Ww]indow|[Ww]indow[Ss]tyle\s+[Hh]idden",
        "Hidden window execution",
        "Profile launches processes with hidden windows",
    ),
    (
        r"https?://\d+\.\d+\.\d+\.\d+",
        "Hardcoded IP address URL",
        "Profile contacts a hardcoded IP address",
    ),
]


class PowerShellProfilesCheck(BaseCheck):
    """Detect suspicious content in PowerShell profile scripts."""

    CHECK_ID = "PS-001"
    NAME = "PowerShell Profile Persistence"
    DESCRIPTION = (
        "Checks all standard PowerShell profile paths for suspicious "
        "content including network downloads, encoded commands, "
        "obfuscation, and persistence mechanisms."
    )
    CATEGORY = Category.PERSISTENCE
    REQUIRES_ADMIN = False

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        # Get all four profile paths
        profile_result = run_ps(
            "@{ "
            "AllUsersAllHosts=$PROFILE.AllUsersAllHosts; "
            "AllUsersCurrentHost=$PROFILE.AllUsersCurrentHost; "
            "CurrentUserAllHosts=$PROFILE.CurrentUserAllHosts; "
            "CurrentUserCurrentHost=$PROFILE.CurrentUserCurrentHost "
            "}",
            timeout=10,
            as_json=True,
        )

        if not profile_result.success or profile_result.json_output is None:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Failed to determine PowerShell profile paths",
                description=f"Could not query $PROFILE paths: {profile_result.error or 'unknown'}",
                severity=Severity.MEDIUM,
                category=self.CATEGORY,
                affected_item="PowerShell Profiles",
                evidence=profile_result.output[:500] if profile_result.output else "No output",
                recommendation="Manually check PowerShell profile locations.",
            ))
            return findings

        profiles = profile_result.json_output
        if isinstance(profiles, list) and len(profiles) > 0:
            profiles = profiles[0]

        profile_paths: dict[str, str] = {
            "AllUsersAllHosts": str(profiles.get("AllUsersAllHosts", "")),
            "AllUsersCurrentHost": str(profiles.get("AllUsersCurrentHost", "")),
            "CurrentUserAllHosts": str(profiles.get("CurrentUserAllHosts", "")),
            "CurrentUserCurrentHost": str(profiles.get("CurrentUserCurrentHost", "")),
        }

        profiles_found = 0
        suspicious_profiles = 0

        for profile_name, profile_path in profile_paths.items():
            if not profile_path:
                continue

            # Check if the profile file exists and read its contents
            read_result = run_ps(
                f"if (Test-Path '{profile_path}') {{ "
                f"@{{ Exists=$true; Content=(Get-Content '{profile_path}' -Raw -ErrorAction SilentlyContinue); "
                f"Length=(Get-Item '{profile_path}').Length; "
                f"LastWriteTime=(Get-Item '{profile_path}').LastWriteTime.ToString('o') }} "
                f"}} else {{ @{{ Exists=$false; Content=''; Length=0; LastWriteTime='' }} }}",
                timeout=10,
                as_json=True,
            )

            if not read_result.success or read_result.json_output is None:
                continue

            data = read_result.json_output
            if isinstance(data, list) and len(data) > 0:
                data = data[0]

            exists = data.get("Exists", False)
            if not exists:
                continue

            profiles_found += 1
            content = str(data.get("Content", ""))
            file_size = data.get("Length", 0)
            last_write = str(data.get("LastWriteTime", ""))

            if not content.strip():
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title=f"PowerShell profile exists but is empty: {profile_name}",
                    description=f"Profile at '{profile_path}' exists but contains no code.",
                    severity=Severity.INFO,
                    category=self.CATEGORY,
                    affected_item=profile_path,
                    evidence=f"Path: {profile_path}\nSize: {file_size} bytes\nLast Modified: {last_write}",
                    recommendation="No action needed.",
                ))
                continue

            # Check for suspicious patterns
            matched_patterns: list[tuple[str, str]] = []
            for pattern, pattern_name, pattern_desc in _SUSPICIOUS_PATTERNS:
                if re.search(pattern, content):
                    matched_patterns.append((pattern_name, pattern_desc))

            if matched_patterns:
                suspicious_profiles += 1
                pattern_evidence = "\n".join(
                    f"  [{name}]: {desc}" for name, desc in matched_patterns
                )

                # Show first 1000 chars of the profile
                content_preview = content[:1000]
                if len(content) > 1000:
                    content_preview += "\n... (truncated)"

                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title=f"Suspicious PowerShell profile: {profile_name}",
                    description=(
                        f"PowerShell profile '{profile_name}' at '{profile_path}' "
                        f"contains {len(matched_patterns)} suspicious pattern(s). "
                        "PowerShell profiles execute automatically at every session start."
                    ),
                    severity=Severity.HIGH,
                    category=self.CATEGORY,
                    affected_item=profile_path,
                    evidence=(
                        f"Profile: {profile_name}\n"
                        f"Path: {profile_path}\n"
                        f"Size: {file_size} bytes\n"
                        f"Last Modified: {last_write}\n\n"
                        f"Suspicious patterns found:\n{pattern_evidence}\n\n"
                        f"Profile content preview:\n{content_preview}"
                    ),
                    recommendation=(
                        f"Review the content of '{profile_path}' carefully. "
                        "If unauthorized, remove the file or its suspicious contents. "
                        "PowerShell profiles should only contain legitimate customizations."
                    ),
                    references=[
                        "https://attack.mitre.org/techniques/T1546/013/",
                    ],
                ))
            else:
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title=f"PowerShell profile found: {profile_name}",
                    description=(
                        f"Profile at '{profile_path}' exists with {file_size} bytes. "
                        "No suspicious patterns were detected."
                    ),
                    severity=Severity.INFO,
                    category=self.CATEGORY,
                    affected_item=profile_path,
                    evidence=f"Path: {profile_path}\nSize: {file_size} bytes\nLast Modified: {last_write}",
                    recommendation="Review profile content periodically.",
                ))

        # Summary
        findings.append(Finding(
            check_id=self.CHECK_ID,
            title="PowerShell profile audit summary",
            description=(
                f"Checked {len(profile_paths)} profile locations. "
                f"{profiles_found} profiles exist, "
                f"{suspicious_profiles} contain suspicious patterns."
            ),
            severity=Severity.INFO,
            category=self.CATEGORY,
            affected_item="PowerShell Profiles",
            evidence=(
                f"Profile locations checked: {len(profile_paths)}\n"
                f"Profiles found: {profiles_found}\n"
                f"Suspicious: {suspicious_profiles}"
            ),
            recommendation="Monitor PowerShell profiles for unauthorized changes.",
        ))

        return findings
