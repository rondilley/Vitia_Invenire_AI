"""CIS-001: CIS-CAT Pro CLI integration."""

from __future__ import annotations

import csv
import io
import os
import tempfile

from vitia_invenire.checks.base import BaseCheck
from vitia_invenire.collectors.command import run_cmd
from vitia_invenire.models import Category, Finding, Severity


class CISCATScanCheck(BaseCheck):
    CHECK_ID = "CIS-001"
    NAME = "CIS-CAT Benchmark Assessment"
    DESCRIPTION = "CIS-CAT Pro CLI Windows 11 Enterprise benchmark assessment"
    CATEGORY = Category.HARDENING
    REQUIRES_ADMIN = True

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        # Load CIS-CAT configuration
        from vitia_invenire.config import Config
        config = Config.from_defaults()
        ciscat_config = config.get_check_config("CIS-001")

        ciscat_path = ciscat_config.get("ciscat_path")
        benchmark = ciscat_config.get("benchmark", "CIS_Microsoft_Windows_11_Enterprise")

        if not ciscat_path:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="CIS-CAT path not configured",
                description="CIS-CAT Assessor CLI path must be set in the configuration file.",
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="Configuration: CIS-001.ciscat_path",
                evidence="ciscat_path is null in config",
                recommendation="Set ciscat_path in check_config.yaml to the CIS-CAT Assessor CLI location",
                references=["https://www.cisecurity.org/cybersecurity-tools/cis-cat-pro"],
            ))
            return findings

        if not os.path.exists(ciscat_path):
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="CIS-CAT Assessor not found",
                description=f"CIS-CAT Assessor CLI not found at configured path: {ciscat_path}",
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item=ciscat_path,
                evidence=f"File not found: {ciscat_path}",
                recommendation="Verify CIS-CAT Assessor CLI installation path",
            ))
            return findings

        # Run CIS-CAT assessment
        report_dir = tempfile.mkdtemp(prefix="ciscat_")
        ciscat_args = [
            ciscat_path,
            "-b", benchmark,
            "-rd", report_dir,
            "-rf", "csv",
            "-nts",  # no timestamp in report filename
        ]

        result = run_cmd(ciscat_args, timeout=600)

        if not result.success:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="CIS-CAT assessment failed",
                description=f"CIS-CAT execution failed with return code {result.return_code}",
                severity=Severity.LOW,
                category=self.CATEGORY,
                affected_item="CIS-CAT execution",
                evidence=result.stderr[:500] if result.stderr else "Unknown error",
                recommendation="Run CIS-CAT manually to diagnose execution issues",
            ))
            return findings

        # Find and parse CSV report
        csv_files = [f for f in os.listdir(report_dir) if f.endswith(".csv")]
        if not csv_files:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="CIS-CAT report not generated",
                description="No CSV report file was found after CIS-CAT execution.",
                severity=Severity.LOW,
                category=self.CATEGORY,
                affected_item=report_dir,
                evidence=f"No .csv files found in {report_dir}",
                recommendation="Check CIS-CAT output directory and execution logs",
            ))
            return findings

        csv_path = os.path.join(report_dir, csv_files[0])
        try:
            with open(csv_path, encoding="utf-8-sig") as f:
                csv_content = f.read()
        except OSError as exc:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Cannot read CIS-CAT report",
                description=f"Failed to read CSV report: {exc}",
                severity=Severity.LOW,
                category=self.CATEGORY,
                affected_item=csv_path,
                evidence=str(exc),
                recommendation="Check file permissions on CIS-CAT report directory",
            ))
            return findings

        reader = csv.DictReader(io.StringIO(csv_content))
        pass_count = 0
        fail_count = 0

        for row in reader:
            result_val = row.get("Result", row.get("result", "")).strip().lower()

            if result_val == "pass":
                pass_count += 1
                continue
            elif result_val in ("fail", "error"):
                fail_count += 1
                rule_id = row.get("Rule ID", row.get("rule_id", "Unknown"))
                rule_title = row.get("Rule Title", row.get("rule_title", row.get("Description", "Unknown")))
                expected = row.get("Expected", row.get("expected", "N/A"))
                actual = row.get("Actual", row.get("actual", "N/A"))

                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title=f"CIS benchmark fail: {rule_title[:80]}",
                    description=f"CIS benchmark rule '{rule_id}' failed compliance check.",
                    severity=Severity.MEDIUM,
                    category=self.CATEGORY,
                    affected_item=rule_id,
                    evidence=f"Rule: {rule_title}\nExpected: {expected}\nActual: {actual}",
                    recommendation=f"Configure system to meet CIS benchmark rule {rule_id}",
                    references=[f"https://www.cisecurity.org/benchmark/{benchmark.lower()}"],
                ))

        findings.append(Finding(
            check_id=self.CHECK_ID,
            title=f"CIS-CAT assessment complete: {pass_count} passed, {fail_count} failed",
            description=f"CIS-CAT benchmark '{benchmark}' assessment completed.",
            severity=Severity.INFO,
            category=self.CATEGORY,
            affected_item=benchmark,
            evidence=f"Passed: {pass_count}, Failed: {fail_count}, Report: {csv_path}",
            recommendation="Review failed rules and apply CIS hardening recommendations",
        ))

        return findings
