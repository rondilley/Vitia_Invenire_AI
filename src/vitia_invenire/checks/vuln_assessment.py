"""VULN-001: Software Vulnerability Assessment.

Enumerates installed software from Uninstall registry keys (HKLM, HKCU,
WOW6432Node) and cross-references versions against a known vulnerable
software database. Also checks .NET Framework version for known issues.
"""

from __future__ import annotations

import importlib.resources
import json
import re

from vitia_invenire.checks.base import BaseCheck
from vitia_invenire.collectors import registry
from vitia_invenire.models import Category, Finding, Severity

# Registry paths for installed software
_UNINSTALL_PATHS: list[tuple[int, str, bool]] = [
    (registry.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", False),
    (registry.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall", False),
    (registry.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", False),
]

# .NET Framework 4.x release number to version string mapping
# See: https://learn.microsoft.com/en-us/dotnet/framework/migration-guide/how-to-determine-which-versions-are-installed
_DOTNET_RELEASE_MAP: list[tuple[int, str]] = [
    (533320, "4.8.1"),
    (528040, "4.8"),
    (461808, "4.7.2"),
    (461308, "4.7.1"),
    (460798, "4.7"),
    (394802, "4.6.2"),
    (394254, "4.6.1"),
    (393295, "4.6"),
    (379893, "4.5.2"),
    (378675, "4.5.1"),
    (378389, "4.5"),
]

# Minimum recommended .NET Framework release number (4.8.1 = 533320)
_DOTNET_MIN_RECOMMENDED_RELEASE = 528040
_DOTNET_MIN_RECOMMENDED_VERSION = "4.8"


def _parse_version(version_str: str) -> tuple[int, ...]:
    """Parse a version string into a tuple of integers for comparison.

    Splits on dots and converts each segment to an integer. Non-numeric
    segments are treated as zero. Returns an empty tuple if the string
    cannot be parsed at all.

    Args:
        version_str: A version string like "121.0.6167.160" or "3.12.3".

    Returns:
        Tuple of integers, e.g. (121, 0, 6167, 160).
    """
    if not version_str or not version_str.strip():
        return ()

    # Strip common prefixes like "v" or "V"
    cleaned = version_str.strip().lstrip("vV").strip()
    if not cleaned:
        return ()

    parts: list[int] = []
    for segment in cleaned.split("."):
        # Extract leading digits from each segment (handles "160-rc1" -> 160)
        match = re.match(r"(\d+)", segment.strip())
        if match:
            parts.append(int(match.group(1)))
        else:
            parts.append(0)

    return tuple(parts)


def _version_lte(installed: tuple[int, ...], max_safe: tuple[int, ...]) -> bool:
    """Return True if installed version is less than or equal to max_safe.

    Pads the shorter tuple with zeros for comparison.

    Args:
        installed: Parsed installed version tuple.
        max_safe: Parsed maximum safe (still-vulnerable) version tuple.

    Returns:
        True if installed <= max_safe, meaning the software is vulnerable.
    """
    max_len = max(len(installed), len(max_safe))
    padded_installed = installed + (0,) * (max_len - len(installed))
    padded_safe = max_safe + (0,) * (max_len - len(max_safe))
    return padded_installed <= padded_safe


class VulnAssessmentCheck(BaseCheck):
    """Cross-reference installed software versions against known vulnerabilities."""

    CHECK_ID = "VULN-001"
    NAME = "Software Vulnerability Assessment"
    DESCRIPTION = (
        "Enumerates installed software from Uninstall registry keys "
        "and cross-references versions against a database of known "
        "vulnerable software with associated CVEs."
    )
    CATEGORY = Category.PATCHING
    REQUIRES_ADMIN = False

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        software_list = self._enumerate_software()
        vuln_data = self._load_vuln_data()

        vulnerable_count = 0
        if vuln_data is not None:
            vulnerable_count = self._check_vulnerabilities(software_list, vuln_data, findings)
        else:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Vulnerability reference data unavailable",
                description=(
                    "Could not load known_vulnerable_software.json reference data. "
                    "Vulnerability cross-referencing has been skipped. Software inventory "
                    "is still reported below."
                ),
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="known_vulnerable_software.json",
                evidence="Reference data file missing or malformed",
                recommendation=(
                    "Run 'vitia-invenire update-data' to refresh reference data, "
                    "or verify that known_vulnerable_software.json exists in the data directory."
                ),
            ))

        # Check .NET Framework version
        self._check_dotnet_version(findings)

        # Summary finding
        findings.append(Finding(
            check_id=self.CHECK_ID,
            title="Software vulnerability assessment summary",
            description=(
                f"Enumerated {len(software_list)} installed software packages. "
                f"Found {vulnerable_count} package(s) matching known vulnerabilities."
            ),
            severity=Severity.INFO,
            category=self.CATEGORY,
            affected_item="Software Vulnerability Assessment",
            evidence=(
                f"Total software enumerated: {len(software_list)}\n"
                f"Vulnerable packages found: {vulnerable_count}\n"
                f"Reference data loaded: {'Yes' if vuln_data is not None else 'No'}"
            ),
            recommendation=(
                "Update all software to the latest available versions. "
                "Prioritize patching CRITICAL and HIGH severity vulnerabilities."
            ),
        ))

        return findings

    def _enumerate_software(self) -> list[dict[str, str]]:
        """Enumerate installed software from Windows Uninstall registry keys.

        Returns:
            List of dicts, each containing 'name', 'version', and 'publisher' keys.
        """
        all_software: list[dict[str, str]] = []
        seen_names: set[str] = set()

        for hive, path, wow64 in _UNINSTALL_PATHS:
            try:
                subkeys = registry.enumerate_subkeys(hive, path, wow64_32=wow64)
            except OSError:
                continue

            for subkey in subkeys:
                full_path = f"{path}\\{subkey}"
                try:
                    values = registry.read_key(hive, full_path, wow64_32=wow64)
                except OSError:
                    continue

                sw_info: dict[str, str] = {}
                for val in values:
                    if val.name == "DisplayName" and val.data is not None:
                        sw_info["name"] = str(val.data).strip()
                    elif val.name == "DisplayVersion" and val.data is not None:
                        sw_info["version"] = str(val.data).strip()
                    elif val.name == "Publisher" and val.data is not None:
                        sw_info["publisher"] = str(val.data).strip()

                name = sw_info.get("name", "")
                if not name:
                    continue

                # Deduplicate by name (same software in HKLM and WOW6432Node)
                dedup_key = name.lower()
                if dedup_key in seen_names:
                    continue
                seen_names.add(dedup_key)

                sw_info.setdefault("version", "")
                sw_info.setdefault("publisher", "")
                all_software.append(sw_info)

        return all_software

    def _load_vuln_data(self) -> list[dict] | None:
        """Load the known vulnerable software reference data.

        Returns:
            List of vulnerability entries from the JSON file, or None
            if the file cannot be loaded.
        """
        try:
            ref = importlib.resources.files("vitia_invenire.data").joinpath(
                "known_vulnerable_software.json"
            )
            raw = ref.read_text(encoding="utf-8")
            data = json.loads(raw)
            if not isinstance(data, dict):
                return None
            entries = data.get("software")
            if not isinstance(entries, list):
                return None
            return entries
        except FileNotFoundError:
            return None
        except json.JSONDecodeError:
            return None
        except TypeError:
            return None
        except AttributeError:
            return None

    def _check_vulnerabilities(
        self,
        software_list: list[dict[str, str]],
        vuln_data: list[dict],
        findings: list[Finding],
    ) -> int:
        """Cross-reference installed software against known vulnerabilities.

        For each installed software package, checks whether its name and
        optional vendor match any entry in the vulnerability database. If
        the installed version is less than or equal to the max_safe_version,
        the software is considered vulnerable.

        Args:
            software_list: Installed software from _enumerate_software().
            vuln_data: Vulnerability entries from _load_vuln_data().
            findings: List to append Finding objects to.

        Returns:
            Number of vulnerable software packages found.
        """
        vulnerable_count = 0

        for sw in software_list:
            sw_name = sw.get("name", "")
            sw_version = sw.get("version", "")
            sw_publisher = sw.get("publisher", "")

            if not sw_version:
                continue

            installed_ver = _parse_version(sw_version)
            if not installed_ver:
                continue

            for vuln in vuln_data:
                name_pattern = vuln.get("name_pattern", "")
                vendor_pattern = vuln.get("vendor_pattern", "")
                max_safe_str = vuln.get("max_safe_version", "")
                cve = vuln.get("cve", "Unknown CVE")
                vuln_severity = vuln.get("severity", "HIGH")
                vuln_desc = vuln.get("description", "")

                if not name_pattern or not max_safe_str:
                    continue

                # Match software name (case-insensitive substring)
                if name_pattern.lower() not in sw_name.lower():
                    continue

                # Match vendor if specified (case-insensitive substring)
                if vendor_pattern and vendor_pattern.lower() not in sw_publisher.lower():
                    continue

                max_safe_ver = _parse_version(max_safe_str)
                if not max_safe_ver:
                    continue

                if _version_lte(installed_ver, max_safe_ver):
                    # Map severity string to Severity enum
                    try:
                        sev = Severity(vuln_severity)
                    except ValueError:
                        sev = Severity.HIGH

                    vulnerable_count += 1
                    findings.append(Finding(
                        check_id=self.CHECK_ID,
                        title=f"Vulnerable software: {sw_name} ({cve})",
                        description=(
                            f"Installed software '{sw_name}' version {sw_version} is "
                            f"at or below the maximum affected version {max_safe_str} "
                            f"for {cve}. {vuln_desc}"
                        ),
                        severity=sev,
                        category=self.CATEGORY,
                        affected_item=sw_name,
                        evidence=(
                            f"Software: {sw_name}\n"
                            f"Installed version: {sw_version}\n"
                            f"Max affected version: {max_safe_str}\n"
                            f"Publisher: {sw_publisher}\n"
                            f"CVE: {cve}\n"
                            f"Vulnerability: {vuln_desc}"
                        ),
                        recommendation=(
                            f"Update '{sw_name}' to a version newer than {max_safe_str} "
                            f"to remediate {cve}. Check the vendor website for the latest "
                            "security release."
                        ),
                        references=[
                            f"https://nvd.nist.gov/vuln/detail/{cve}",
                        ],
                    ))

        return vulnerable_count

    def _check_dotnet_version(self, findings: list[Finding]) -> None:
        """Check .NET Framework version from the registry.

        Reads the Release DWORD from the .NET Framework 4.x registry key
        and maps it to a version string. Reports if the installed version
        is below the recommended minimum.

        Args:
            findings: List to append Finding objects to.
        """
        dotnet_path = r"SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full"
        release_val = registry.read_value(
            registry.HKEY_LOCAL_MACHINE, dotnet_path, "Release"
        )

        if release_val is None or release_val.data is None:
            # .NET Framework 4.x not installed or not detectable
            return

        try:
            release_num = int(release_val.data)
        except (ValueError, TypeError):
            return

        # Map release number to version string
        dotnet_version = "Unknown"
        for min_release, ver_str in _DOTNET_RELEASE_MAP:
            if release_num >= min_release:
                dotnet_version = ver_str
                break

        if release_num < _DOTNET_MIN_RECOMMENDED_RELEASE:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title=f".NET Framework version {dotnet_version} is outdated",
                description=(
                    f".NET Framework version {dotnet_version} (release {release_num}) "
                    f"is installed but version {_DOTNET_MIN_RECOMMENDED_VERSION} or later "
                    "is recommended. Older .NET Framework versions may contain unpatched "
                    "security vulnerabilities."
                ),
                severity=Severity.HIGH,
                category=self.CATEGORY,
                affected_item=".NET Framework",
                evidence=(
                    f".NET Framework version: {dotnet_version}\n"
                    f"Release number: {release_num}\n"
                    f"Minimum recommended release: {_DOTNET_MIN_RECOMMENDED_RELEASE} "
                    f"({_DOTNET_MIN_RECOMMENDED_VERSION})"
                ),
                recommendation=(
                    f"Update .NET Framework to version {_DOTNET_MIN_RECOMMENDED_VERSION} "
                    "or later via Windows Update or the Microsoft Download Center."
                ),
                references=[
                    "https://learn.microsoft.com/en-us/dotnet/framework/install/",
                    "https://dotnet.microsoft.com/en-us/download/dotnet-framework",
                ],
            ))
