"""DATA-001: Reference Data Staleness Check.

Checks the age of all reference data JSON files in the data directory.
Stale data files may contain outdated threat intelligence, missing
new indicators, or obsolete vendor mappings that reduce detection
effectiveness.
"""

from __future__ import annotations

import pathlib
import time

from vitia_invenire.checks.base import BaseCheck
from vitia_invenire.models import Category, Finding, Severity

_DATA_DIR = pathlib.Path(__file__).resolve().parent.parent / "data"

# Staleness threshold in days
_STALENESS_THRESHOLD_DAYS = 30
_STALENESS_THRESHOLD_SECONDS = _STALENESS_THRESHOLD_DAYS * 24 * 3600


class DataStalenessCheck(BaseCheck):
    """Check age of reference data JSON files."""

    CHECK_ID = "DATA-001"
    NAME = "Reference Data Staleness Check"
    DESCRIPTION = (
        "Checks the age of all reference data JSON files in the data "
        "directory. Flags files older than 30 days as they may contain "
        "outdated threat intelligence or vendor mappings."
    )
    CATEGORY = Category.META
    REQUIRES_ADMIN = False

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        if not _DATA_DIR.exists():
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Data Directory Not Found",
                description=(
                    f"The reference data directory at {_DATA_DIR} does not "
                    f"exist. No data files can be validated."
                ),
                severity=Severity.MEDIUM,
                category=self.CATEGORY,
                affected_item=str(_DATA_DIR),
                evidence=f"Directory not found: {_DATA_DIR}",
                recommendation="Verify the installation includes the data directory.",
                references=[],
            ))
            return findings

        # Enumerate all JSON files in the data directory
        json_files = list(_DATA_DIR.glob("*.json"))

        if not json_files:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="No Data Files Found",
                description="No JSON data files were found in the data directory.",
                severity=Severity.MEDIUM,
                category=self.CATEGORY,
                affected_item=str(_DATA_DIR),
                evidence=f"No .json files in {_DATA_DIR}",
                recommendation="Populate the data directory with reference data files.",
                references=[],
            ))
            return findings

        now = time.time()
        stale_files: list[dict[str, str]] = []
        fresh_files: list[dict[str, str]] = []

        for json_file in sorted(json_files):
            mtime = json_file.stat().st_mtime
            age_seconds = now - mtime
            age_days = age_seconds / 86400

            file_info = {
                "name": json_file.name,
                "path": str(json_file),
                "age_days": f"{age_days:.1f}",
                "size_bytes": str(json_file.stat().st_size),
            }

            if age_seconds > _STALENESS_THRESHOLD_SECONDS:
                stale_files.append(file_info)
            else:
                fresh_files.append(file_info)

        if stale_files:
            evidence_lines = []
            for f in stale_files:
                evidence_lines.append(
                    f"  {f['name']}: {f['age_days']} days old "
                    f"({f['size_bytes']} bytes)"
                )
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Stale Reference Data Files Detected",
                description=(
                    f"{len(stale_files)} reference data file(s) are older "
                    f"than {_STALENESS_THRESHOLD_DAYS} days. Outdated data "
                    f"files may miss newly identified threats, C2 pipe "
                    f"patterns, debug devices, or vendor information."
                ),
                severity=Severity.LOW,
                category=self.CATEGORY,
                affected_item="Reference Data Files",
                evidence="\n".join(evidence_lines),
                recommendation=(
                    "Update reference data files to the latest versions. "
                    "Consider automating data file updates as part of the "
                    "tool maintenance process."
                ),
                references=[],
            ))

        # Summary of all data files
        all_evidence = []
        for f in sorted(stale_files + fresh_files, key=lambda x: x["name"]):
            status = "STALE" if f in stale_files else "Current"
            all_evidence.append(
                f"  [{status}] {f['name']}: {f['age_days']} days, "
                f"{f['size_bytes']} bytes"
            )

        findings.append(Finding(
            check_id=self.CHECK_ID,
            title="Reference Data Inventory",
            description=(
                f"Found {len(json_files)} data file(s): "
                f"{len(fresh_files)} current, {len(stale_files)} stale."
            ),
            severity=Severity.INFO,
            category=self.CATEGORY,
            affected_item="Reference Data Files",
            evidence="\n".join(all_evidence),
            recommendation="Keep reference data files updated.",
            references=[],
        ))

        return findings
