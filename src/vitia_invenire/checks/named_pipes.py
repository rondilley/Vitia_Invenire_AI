"""PIPE-001: Named Pipe Enumeration for C2 Detection.

Enumerates named pipes on the system via PowerShell and cross-references
them against known command-and-control (C2) framework pipe name patterns.
Named pipes are commonly used by C2 implants (Cobalt Strike, Metasploit,
etc.) for inter-process communication and lateral movement.
"""

from __future__ import annotations

import json
import pathlib
import re

from vitia_invenire.checks.base import BaseCheck
from vitia_invenire.collectors.powershell import run_ps
from vitia_invenire.models import Category, Finding, Severity

_DATA_DIR = pathlib.Path(__file__).resolve().parent.parent / "data"


def _load_suspicious_pipes() -> list[dict]:
    """Load suspicious pipe patterns from the data file."""
    data_file = _DATA_DIR / "suspicious_pipes.json"
    if not data_file.exists():
        return []
    with open(data_file, "r", encoding="utf-8") as fh:
        return json.load(fh)


class NamedPipesCheck(BaseCheck):
    """Enumerate named pipes and detect known C2 pipe patterns."""

    CHECK_ID = "PIPE-001"
    NAME = "Named Pipe C2 Detection"
    DESCRIPTION = (
        "Enumerates all named pipes on the system and cross-references "
        "against known C2 framework named pipe patterns including Cobalt "
        "Strike, Metasploit, PsExec, and other offensive toolkits."
    )
    CATEGORY = Category.EVASION
    REQUIRES_ADMIN = False

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        # Enumerate named pipes via PowerShell
        ps_command = (
            "[System.IO.Directory]::GetFiles('\\\\.\\pipe\\') | "
            "ForEach-Object { $_.Replace('\\\\.\\pipe\\', '') }"
        )
        result = run_ps(ps_command, timeout=30, as_json=False)

        if not result.success:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Unable to Enumerate Named Pipes",
                description="Failed to enumerate named pipes on the system.",
                severity=Severity.MEDIUM,
                category=self.CATEGORY,
                affected_item="Named Pipes",
                evidence=f"Error: {result.error or 'No output'}",
                recommendation=(
                    "Verify PowerShell access to the named pipe filesystem "
                    "at \\\\.\\pipe\\."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1570/",
                ],
            ))
            return findings

        pipe_names: list[str] = []
        if result.output:
            pipe_names = [
                line.strip()
                for line in result.output.splitlines()
                if line.strip()
            ]

        if not pipe_names:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="No Named Pipes Found",
                description="Named pipe enumeration returned zero results.",
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="Named Pipes",
                evidence="No named pipes were enumerated.",
                recommendation="No action required.",
                references=[
                    "https://attack.mitre.org/techniques/T1570/",
                ],
            ))
            return findings

        # Load suspicious pipe patterns
        suspicious_patterns = _load_suspicious_pipes()

        # Build compiled regex patterns for matching
        compiled_patterns: list[tuple[re.Pattern, dict]] = []
        for entry in suspicious_patterns:
            pattern_str = entry.get("pattern", "")
            if pattern_str:
                try:
                    compiled = re.compile(re.escape(pattern_str), re.IGNORECASE)
                    compiled_patterns.append((compiled, entry))
                except re.error:
                    continue

        # Check each pipe against known C2 patterns
        c2_matches: list[dict[str, str]] = []
        matched_pipe_names: set[str] = set()

        for pipe_name in pipe_names:
            for pattern, entry in compiled_patterns:
                if pattern.search(pipe_name):
                    if pipe_name not in matched_pipe_names:
                        c2_matches.append({
                            "pipe_name": pipe_name,
                            "matched_pattern": entry.get("pattern", ""),
                            "tool_name": entry.get("name", "Unknown"),
                            "framework": entry.get("framework", "Unknown"),
                            "description": entry.get("description", ""),
                        })
                        matched_pipe_names.add(pipe_name)

        # Report C2 pipe matches
        if c2_matches:
            evidence_lines = []
            for match in c2_matches:
                evidence_lines.append(
                    f"Pipe: {match['pipe_name']}\n"
                    f"  Matched Pattern: {match['matched_pattern']}\n"
                    f"  Framework: {match['framework']}\n"
                    f"  Tool: {match['tool_name']}\n"
                    f"  Description: {match['description']}"
                )
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Known C2 Named Pipe Detected",
                description=(
                    f"{len(c2_matches)} named pipe(s) match known command-and-control "
                    f"framework patterns. This is a strong indicator of an active "
                    f"C2 implant or lateral movement tool on the system."
                ),
                severity=Severity.CRITICAL,
                category=self.CATEGORY,
                affected_item="Named Pipes",
                evidence="\n\n".join(evidence_lines),
                recommendation=(
                    "IMMEDIATE ACTION REQUIRED: Investigate each flagged named pipe. "
                    "Identify the process owning the pipe using "
                    "'Get-Process | ForEach-Object { $h = Get-NetTCPConnection "
                    "-OwningProcess $_.Id -ErrorAction SilentlyContinue }'. "
                    "Isolate the system from the network. Collect forensic evidence "
                    "before remediation. Engage incident response procedures."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1570/",
                    "https://attack.mitre.org/techniques/T1071/",
                    "https://labs.withsecure.com/publications/detecting-cobalt-strike-default-named-pipes",
                ],
            ))

        # Summary of all pipes
        # Group pipes by common prefixes for readability
        pipe_sample = pipe_names[:200]
        findings.append(Finding(
            check_id=self.CHECK_ID,
            title="Named Pipe Inventory",
            description=(
                f"Enumerated {len(pipe_names)} named pipe(s) on the system. "
                f"{len(c2_matches)} matched known C2 patterns."
            ),
            severity=Severity.INFO,
            category=self.CATEGORY,
            affected_item="Named Pipes",
            evidence=(
                f"Total pipes: {len(pipe_names)}\n"
                f"C2 pattern matches: {len(c2_matches)}\n\n"
                f"Pipe listing (first {len(pipe_sample)}):\n"
                + "\n".join(f"  - {p}" for p in pipe_sample)
                + (f"\n  ... and {len(pipe_names) - 200} more"
                   if len(pipe_names) > 200 else "")
            ),
            recommendation=(
                "Review the named pipe inventory for any unusual or unexpected pipes."
            ),
            references=[
                "https://attack.mitre.org/techniques/T1570/",
            ],
        ))

        return findings
