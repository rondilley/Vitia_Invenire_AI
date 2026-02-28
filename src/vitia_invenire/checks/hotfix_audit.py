"""PATCH-002: Installed Hotfix Audit.

Enumerates installed Windows hotfixes via Get-HotFix, retrieves the
current OS build number, and cross-references against a curated list
of critical KBs to identify missing security patches that address
known exploited vulnerabilities.
"""

from __future__ import annotations

import importlib.resources
import json

from vitia_invenire.checks.base import BaseCheck
from vitia_invenire.collectors.powershell import run_ps
from vitia_invenire.models import Category, Finding, Severity


class HotfixAuditCheck(BaseCheck):
    """Audit installed hotfixes against critical KB requirements."""

    CHECK_ID = "PATCH-002"
    NAME = "Installed Hotfix Audit"
    DESCRIPTION = (
        "Enumerates installed Windows hotfixes, retrieves the current OS "
        "build number, and cross-references against a curated database of "
        "critical KBs addressing known exploited vulnerabilities."
    )
    CATEGORY = Category.PATCHING
    REQUIRES_ADMIN = False

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        installed_hotfixes = self._get_installed_hotfixes(findings)
        if installed_hotfixes is None:
            return findings

        installed_kb_ids = {
            hf.get("HotFixID", "").upper().strip()
            for hf in installed_hotfixes
            if hf.get("HotFixID")
        }

        # Retrieve OS build number for context
        build_result = run_ps(
            "(Get-ItemProperty "
            "'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion')"
            ".CurrentBuildNumber",
            timeout=15,
            as_json=False,
        )
        os_build = "Unknown"
        if build_result.success and build_result.output:
            os_build = build_result.output.strip()
        self.context["os_build"] = os_build

        # Flag suspiciously low hotfix count
        total_hotfixes = len(installed_hotfixes)
        if total_hotfixes < 5:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Unusually low hotfix count detected",
                description=(
                    f"Only {total_hotfixes} hotfixes are installed. A healthy "
                    "Windows 11 system typically has many more. This may "
                    "indicate a system image that was reset, wiped, or never "
                    "received cumulative updates."
                ),
                severity=Severity.HIGH,
                category=self.CATEGORY,
                affected_item="Installed Hotfixes",
                evidence=(
                    f"Total installed hotfixes: {total_hotfixes}\n"
                    f"OS Build: {os_build}"
                ),
                recommendation=(
                    "Verify the system update history. Run Windows Update "
                    "and ensure all cumulative and security updates are "
                    "applied before deployment."
                ),
                references=[
                    "https://learn.microsoft.com/en-us/windows/deployment/update/windows-update-overview",
                ],
            ))

        # Cross-reference against critical KBs
        critical_kbs = self._load_critical_kbs(findings)
        if critical_kbs is not None:
            self._check_missing_kbs(findings, installed_kb_ids, critical_kbs)

        # Build summary listing
        installed_list = sorted(installed_kb_ids)
        missing_critical = []
        if critical_kbs is not None:
            for entry in critical_kbs:
                kb_id = entry.get("kb", "").upper().strip()
                if kb_id and kb_id not in installed_kb_ids:
                    missing_critical.append(
                        f"{kb_id} ({entry.get('cve', 'N/A')})"
                    )

        missing_summary = (
            f" Missing critical KBs: {', '.join(missing_critical)}."
            if missing_critical
            else " No missing critical KBs detected."
        )

        findings.append(Finding(
            check_id=self.CHECK_ID,
            title="Hotfix audit summary",
            description=(
                f"Enumerated {total_hotfixes} installed hotfixes on OS build "
                f"{os_build}.{missing_summary}"
            ),
            severity=Severity.INFO,
            category=self.CATEGORY,
            affected_item="Installed Hotfixes",
            evidence=(
                f"Total installed: {total_hotfixes}\n"
                f"OS Build: {os_build}\n"
                f"Installed KBs: {', '.join(installed_list) if installed_list else 'None'}"
            ),
            recommendation=(
                "Ensure all critical and cumulative updates are applied "
                "before deploying the system."
            ),
        ))

        return findings

    def _get_installed_hotfixes(
        self, findings: list[Finding]
    ) -> list[dict] | None:
        """Query installed hotfixes via Get-HotFix.

        Returns a list of hotfix dicts on success, or None if the query
        fails (after appending an error finding).
        """
        result = run_ps(
            "Get-HotFix | Select-Object HotFixID, Description, "
            "InstalledOn, InstalledBy",
            timeout=30,
            as_json=True,
        )

        if not result.success:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Failed to enumerate installed hotfixes",
                description=(
                    f"PowerShell Get-HotFix query failed: "
                    f"{result.error or 'unknown error'}"
                ),
                severity=Severity.MEDIUM,
                category=self.CATEGORY,
                affected_item="Get-HotFix",
                evidence=result.output[:500] if result.output else "No output",
                recommendation=(
                    "Verify PowerShell access and WMI subsystem health. "
                    "Run Get-HotFix manually to diagnose."
                ),
            ))
            return None

        if result.json_output is None:
            # No hotfixes at all -- return empty list rather than None
            return []

        hotfixes = result.json_output
        if isinstance(hotfixes, dict):
            hotfixes = [hotfixes]

        return hotfixes

    def _load_critical_kbs(
        self, findings: list[Finding]
    ) -> list[dict] | None:
        """Load the critical KB reference data from package data.

        Returns the list of KB entries on success, or None if loading
        fails (after appending an informational finding).
        """
        try:
            ref = importlib.resources.files("vitia_invenire.data").joinpath(
                "critical_kbs.json"
            )
            raw = ref.read_text(encoding="utf-8")
            data = json.loads(raw)
            kbs = data.get("kbs", [])
            if not isinstance(kbs, list):
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title="Critical KB reference data has unexpected format",
                    description=(
                        "The critical_kbs.json file was loaded but the 'kbs' "
                        "field is not a list. Critical KB cross-referencing "
                        "will be skipped."
                    ),
                    severity=Severity.INFO,
                    category=self.CATEGORY,
                    affected_item="critical_kbs.json",
                    evidence=f"Type of 'kbs' field: {type(kbs).__name__}",
                    recommendation=(
                        "Run the update-data command to refresh reference data."
                    ),
                ))
                return None
            return kbs
        except FileNotFoundError:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Critical KB reference data unavailable",
                description=(
                    "The critical_kbs.json reference data file was not found. "
                    "Critical KB cross-referencing will be skipped."
                ),
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="critical_kbs.json",
                evidence="File not found in vitia_invenire.data package",
                recommendation=(
                    "Run the update-data command to fetch the latest "
                    "reference data files."
                ),
            ))
            return None
        except json.JSONDecodeError as exc:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Critical KB reference data is malformed",
                description=(
                    f"Failed to parse critical_kbs.json: {exc}. "
                    "Critical KB cross-referencing will be skipped."
                ),
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="critical_kbs.json",
                evidence=f"JSONDecodeError: {exc}",
                recommendation=(
                    "Run the update-data command to refresh reference data."
                ),
            ))
            return None
        except (TypeError, AttributeError) as exc:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Critical KB reference data could not be loaded",
                description=(
                    f"Unexpected error loading critical_kbs.json: {exc}. "
                    "Critical KB cross-referencing will be skipped."
                ),
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="critical_kbs.json",
                evidence=f"{type(exc).__name__}: {exc}",
                recommendation=(
                    "Run the update-data command to refresh reference data."
                ),
            ))
            return None

    def _check_missing_kbs(
        self,
        findings: list[Finding],
        installed_kb_ids: set[str],
        critical_kbs: list[dict],
    ) -> None:
        """Check for missing critical KBs and emit findings.

        Compares the set of installed KB IDs against the critical KB list.
        Missing KBs with severity CRITICAL generate CRITICAL findings;
        missing KBs with severity HIGH generate HIGH findings.
        """
        severity_map = {
            "CRITICAL": Severity.CRITICAL,
            "HIGH": Severity.HIGH,
        }

        for entry in critical_kbs:
            kb_id = entry.get("kb", "").upper().strip()
            if not kb_id:
                continue

            if kb_id in installed_kb_ids:
                continue

            entry_severity_str = entry.get("severity", "HIGH").upper()
            finding_severity = severity_map.get(
                entry_severity_str, Severity.HIGH
            )
            cve = entry.get("cve", "N/A")
            description = entry.get("description", "No description available")

            findings.append(Finding(
                check_id=self.CHECK_ID,
                title=f"Missing critical hotfix: {kb_id} ({cve})",
                description=(
                    f"The critical security update {kb_id} addressing {cve} "
                    f"is not installed. Vulnerability: {description}."
                ),
                severity=finding_severity,
                category=self.CATEGORY,
                affected_item=kb_id,
                evidence=(
                    f"KB: {kb_id}\n"
                    f"CVE: {cve}\n"
                    f"Reference severity: {entry_severity_str}\n"
                    f"Description: {description}"
                ),
                recommendation=(
                    f"Install {kb_id} via Windows Update or download from "
                    f"the Microsoft Update Catalog. This patch addresses "
                    f"{cve}: {description}."
                ),
                references=[
                    f"https://support.microsoft.com/help/{kb_id.lstrip('KB')}",
                    f"https://msrc.microsoft.com/update-guide/vulnerability/{cve}"
                    if cve != "N/A" else "",
                ],
            ))
