"""HK-001: HardeningKitty PowerShell module integration."""

from __future__ import annotations

import csv
import io
import tempfile

from vitia_invenire.checks.base import BaseCheck
from vitia_invenire.collectors.powershell import run_ps
from vitia_invenire.models import Category, Finding, Severity


class HardeningKittyCheck(BaseCheck):
    CHECK_ID = "HK-001"
    NAME = "HardeningKitty Audit"
    DESCRIPTION = "Run HardeningKitty PowerShell module in audit mode for Windows hardening assessment"
    CATEGORY = Category.HARDENING
    REQUIRES_ADMIN = True

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        # Check if HardeningKitty module is available
        check_cmd = "Get-Module -ListAvailable -Name HardeningKitty"
        result = run_ps(check_cmd, timeout=30, as_json=True)
        if not result.success or not result.json_output:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="HardeningKitty module not installed",
                description="The HardeningKitty PowerShell module is not available on this system.",
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="PowerShell Module: HardeningKitty",
                evidence="Module not found via Get-Module -ListAvailable",
                recommendation="Install HardeningKitty: Install-Module -Name HardeningKitty -Scope CurrentUser",
                references=["https://github.com/scipag/HardeningKitty"],
            ))
            return findings

        # Run HardeningKitty in audit mode with CSV output
        csv_path = tempfile.mktemp(suffix=".csv")
        audit_cmd = (
            f"Import-Module HardeningKitty; "
            f"Invoke-HardeningKitty -Mode Audit -Report -ReportFile '{csv_path}' -SkipRestorePoint"
        )
        result = run_ps(audit_cmd, timeout=600, as_json=False)

        if not result.success:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="HardeningKitty audit failed",
                description=f"HardeningKitty execution failed: {result.error}",
                severity=Severity.LOW,
                category=self.CATEGORY,
                affected_item="HardeningKitty execution",
                evidence=result.error or "Unknown error",
                recommendation="Check HardeningKitty module installation and permissions",
            ))
            return findings

        # Parse CSV results
        try:
            with open(csv_path, encoding="utf-8-sig") as f:
                csv_content = f.read()
        except FileNotFoundError:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="HardeningKitty report file not found",
                description="The CSV report file was not generated.",
                severity=Severity.LOW,
                category=self.CATEGORY,
                affected_item=csv_path,
                evidence="Report file missing after execution",
                recommendation="Run HardeningKitty manually to diagnose",
            ))
            return findings

        reader = csv.DictReader(io.StringIO(csv_content))
        fail_count = 0
        for row in reader:
            status = row.get("Status", "").strip()
            if status.lower() in ("failed", "false"):
                fail_count += 1
                setting_name = row.get("Name", row.get("ID", "Unknown"))
                expected = row.get("Recommended", row.get("Expected", "N/A"))
                actual = row.get("Current", row.get("Value", "N/A"))
                severity_str = row.get("Severity", "Medium").strip()

                if severity_str.lower() in ("critical", "high"):
                    sev = Severity.HIGH
                elif severity_str.lower() == "medium":
                    sev = Severity.MEDIUM
                else:
                    sev = Severity.LOW

                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title=f"Hardening check failed: {setting_name}",
                    description=f"HardeningKitty setting '{setting_name}' does not match recommended value.",
                    severity=sev,
                    category=self.CATEGORY,
                    affected_item=setting_name,
                    evidence=f"Expected: {expected}, Actual: {actual}",
                    recommendation=f"Set '{setting_name}' to recommended value: {expected}",
                    references=["https://github.com/scipag/HardeningKitty"],
                ))

        if fail_count == 0:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="HardeningKitty audit passed",
                description="All HardeningKitty hardening checks passed.",
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="System hardening configuration",
                evidence=f"All checks passed. CSV report: {csv_path}",
                recommendation="No action needed",
            ))

        return findings
