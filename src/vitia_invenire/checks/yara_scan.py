"""YARA-001: YARA Rule-Based Malware Scan.

Scans key user and system directories for malware indicators using
YARA rules and the external yara64.exe binary. Rules are loaded from
a package-bundled index that maps rule files to severity levels.
"""

from __future__ import annotations

import json
import os
from importlib import resources
from pathlib import Path

from vitia_invenire.checks.base import BaseCheck
from vitia_invenire.collectors.command import run_cmd
from vitia_invenire.models import Category, Finding, Severity

_DEFAULT_SCAN_DIRS = [
    os.path.expandvars("%TEMP%"),
    os.path.expandvars("%SYSTEMDRIVE%\\ProgramData"),
    os.path.expandvars("%USERPROFILE%\\Downloads"),
    os.path.expandvars("%USERPROFILE%\\Desktop"),
]

_SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "INFO": Severity.INFO,
}

_MAX_EVIDENCE_LENGTH = 2000


def _load_rule_index(rules_dir: Path) -> list[dict]:
    """Load the YARA rule index from the rules directory.

    Returns:
        List of rule entry dicts with file, category, and severity keys.
        Empty list if the index cannot be loaded.
    """
    index_path = rules_dir / "yara_rule_index.json"
    try:
        raw = index_path.read_text(encoding="utf-8")
        data = json.loads(raw)
        if isinstance(data, dict) and "rules" in data:
            rules = data["rules"]
            if isinstance(rules, list):
                return rules
    except (FileNotFoundError, json.JSONDecodeError, TypeError, AttributeError,
            OSError, ValueError):
        return []
    return []


def _parse_yara_output(stdout: str) -> list[dict]:
    """Parse yara64 output into structured match records.

    Each match block starts with a line of the form 'RuleName FilePath'
    followed by zero or more string match lines starting with '0x'.

    Returns:
        List of dicts with keys: rule, file, strings.
    """
    matches: list[dict] = []
    current_match: dict | None = None

    for line in stdout.splitlines():
        stripped = line.strip()
        if not stripped:
            continue

        if stripped.startswith("0x"):
            # String match detail line belonging to the current match
            if current_match is not None:
                current_match["strings"].append(stripped)
        else:
            # New match line: "RuleName FilePath"
            parts = stripped.split(" ", 1)
            if len(parts) == 2:
                current_match = {
                    "rule": parts[0],
                    "file": parts[1],
                    "strings": [],
                }
                matches.append(current_match)

    return matches


class YaraScanCheck(BaseCheck):
    """Scan directories for malware using YARA rules and yara64.exe."""

    CHECK_ID = "YARA-001"
    NAME = "YARA Malware Scan"
    DESCRIPTION = (
        "Scans user and system directories for malware indicators using "
        "YARA signature rules loaded from the package rule set. Uses the "
        "external yara64.exe binary for scanning."
    )
    CATEGORY = Category.MALWARE
    REQUIRES_ADMIN = False
    REQUIRES_TOOLS = ["yara64"]

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        # Locate the bundled YARA rules directory
        try:
            rules_dir_ref = resources.files("vitia_invenire.data").joinpath("yara_rules")
            rules_dir = Path(str(rules_dir_ref))
        except (TypeError, AttributeError, FileNotFoundError) as exc:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="YARA rules directory not accessible",
                description=(
                    f"Could not resolve the YARA rules package data directory: "
                    f"{type(exc).__name__}: {exc}"
                ),
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="vitia_invenire.data/yara_rules",
                evidence=str(exc),
                recommendation=(
                    "Verify the vitia_invenire package is installed correctly "
                    "and the data/yara_rules directory is present."
                ),
            ))
            return findings

        # Load the rule index
        rule_entries = _load_rule_index(rules_dir)
        if not rule_entries:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="YARA rule index could not be loaded",
                description=(
                    "The YARA rule index file (yara_rule_index.json) could not "
                    "be loaded or contains no rule entries. No scanning will be "
                    "performed."
                ),
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item=str(rules_dir / "yara_rule_index.json"),
                evidence="Rule index missing, empty, or malformed",
                recommendation=(
                    "Ensure yara_rules/yara_rule_index.json exists in the "
                    "package data directory and contains a valid rules array."
                ),
            ))
            return findings

        # Validate and resolve rule file paths, mapping each to its severity
        rule_files: list[tuple[str, Severity, str]] = []
        for entry in rule_entries:
            rule_filename = entry.get("file", "")
            severity_str = entry.get("severity", "MEDIUM").upper()
            rule_category = entry.get("category", "unknown")
            severity = _SEVERITY_MAP.get(severity_str, Severity.MEDIUM)

            rule_path = rules_dir / rule_filename
            if not rule_path.exists():
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title=f"YARA rule file missing: {rule_filename}",
                    description=(
                        f"Rule file '{rule_filename}' listed in the index "
                        f"was not found on disk."
                    ),
                    severity=Severity.LOW,
                    category=self.CATEGORY,
                    affected_item=str(rule_path),
                    evidence=f"Expected path: {rule_path}",
                    recommendation="Verify the rule file is included in the package.",
                ))
                continue

            rule_files.append((str(rule_path), severity, rule_category))

        if not rule_files:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="No valid YARA rule files found",
                description=(
                    "All rule files listed in the index are missing. "
                    "No scanning will be performed."
                ),
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item=str(rules_dir),
                evidence="Zero valid rule files after resolving index entries",
                recommendation="Add YARA rule files to the yara_rules directory.",
            ))
            return findings

        # Determine scan directories (skip those that do not exist)
        scan_dirs: list[str] = []
        skipped_dirs: list[str] = []
        for scan_dir in _DEFAULT_SCAN_DIRS:
            if os.path.isdir(scan_dir):
                scan_dirs.append(scan_dir)
            else:
                skipped_dirs.append(scan_dir)

        if not scan_dirs:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="No scan directories available",
                description="None of the default scan directories exist on this system.",
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="Scan directories",
                evidence=f"Missing directories: {', '.join(skipped_dirs)}",
                recommendation="Verify expected directory paths for this system.",
            ))
            return findings

        # Execute scans: for each rule file against each directory
        total_matches = 0
        timeout_dirs: list[str] = []
        dir_match_counts: dict[str, int] = {d: 0 for d in scan_dirs}

        for rule_path, rule_severity, rule_category in rule_files:
            rule_name = Path(rule_path).name

            for scan_dir in scan_dirs:
                cmd = [
                    "yara64", "-r", "-s", "-w",
                    "-p", "4",
                    rule_path,
                    scan_dir,
                ]

                result = run_cmd(cmd, timeout=120)

                # Handle timeout
                if not result.success and "timed out" in result.stderr.lower():
                    timeout_key = f"{rule_name} -> {scan_dir}"
                    if timeout_key not in timeout_dirs:
                        timeout_dirs.append(timeout_key)
                        findings.append(Finding(
                            check_id=self.CHECK_ID,
                            title=f"YARA scan timed out: {scan_dir}",
                            description=(
                                f"YARA scan with rule '{rule_name}' timed out "
                                f"after 120 seconds on directory '{scan_dir}'. "
                                f"The directory may contain too many files or "
                                f"very large files."
                            ),
                            severity=Severity.MEDIUM,
                            category=self.CATEGORY,
                            affected_item=scan_dir,
                            evidence=f"Rule: {rule_name}, Directory: {scan_dir}, Timeout: 120s",
                            recommendation=(
                                "Consider scanning this directory with fewer "
                                "rules or increasing the timeout. Large temporary "
                                "file caches should be cleaned periodically."
                            ),
                        ))
                    continue

                # Non-timeout failures: yara64 returns non-zero for errors,
                # but also returns non-zero when there are warnings we suppress.
                # We still parse stdout for any matches that were produced.
                stdout = result.stdout
                if not stdout.strip():
                    continue

                matches = _parse_yara_output(stdout)
                if not matches:
                    continue

                dir_match_counts[scan_dir] += len(matches)
                total_matches += len(matches)

                for match in matches:
                    matched_rule = match["rule"]
                    matched_file = match["file"]
                    matched_strings = match["strings"]

                    evidence_parts = [
                        f"Rule: {matched_rule}",
                        f"Rule file: {rule_name}",
                        f"Rule category: {rule_category}",
                        f"Matched file: {matched_file}",
                    ]
                    if matched_strings:
                        evidence_parts.append("Matched strings:")
                        for s in matched_strings:
                            evidence_parts.append(f"  {s}")

                    evidence = "\n".join(evidence_parts)
                    if len(evidence) > _MAX_EVIDENCE_LENGTH:
                        evidence = evidence[:_MAX_EVIDENCE_LENGTH - 20] + "\n[truncated]"

                    findings.append(Finding(
                        check_id=self.CHECK_ID,
                        title=f"YARA match: {matched_rule} in {Path(matched_file).name}",
                        description=(
                            f"YARA rule '{matched_rule}' from the "
                            f"'{rule_category}' rule set matched file "
                            f"'{matched_file}'. This may indicate the "
                            f"presence of malware, suspicious code patterns, "
                            f"or packing/encryption tools."
                        ),
                        severity=rule_severity,
                        category=self.CATEGORY,
                        affected_item=matched_file,
                        evidence=evidence,
                        recommendation=(
                            "Quarantine and investigate the matched file. "
                            "Verify whether it is a known legitimate tool or "
                            "a true positive detection. Submit to a malware "
                            "analysis sandbox if uncertain."
                        ),
                        references=[
                            "https://yara.readthedocs.io/",
                        ],
                    ))

        # Summary finding
        summary_parts = [
            f"Directories scanned: {len(scan_dirs)}",
        ]
        for scan_dir in scan_dirs:
            count = dir_match_counts[scan_dir]
            summary_parts.append(f"  {scan_dir}: {count} match(es)")
        if skipped_dirs:
            summary_parts.append(f"Directories skipped (not found): {len(skipped_dirs)}")
            for d in skipped_dirs:
                summary_parts.append(f"  {d}")
        if timeout_dirs:
            summary_parts.append(f"Scan timeouts: {len(timeout_dirs)}")
            for t in timeout_dirs:
                summary_parts.append(f"  {t}")
        summary_parts.append(f"Total YARA matches: {total_matches}")
        summary_parts.append(f"Rule files used: {len(rule_files)}")

        summary_evidence = "\n".join(summary_parts)

        findings.append(Finding(
            check_id=self.CHECK_ID,
            title="YARA scan summary",
            description=(
                f"Scanned {len(scan_dirs)} directory(ies) with "
                f"{len(rule_files)} rule file(s). "
                f"Found {total_matches} total match(es)."
            ),
            severity=Severity.INFO,
            category=self.CATEGORY,
            affected_item="YARA scan",
            evidence=summary_evidence,
            recommendation=(
                "Review all matches above. No matches indicates a clean scan "
                "for the loaded rule set."
            ),
        ))

        return findings
