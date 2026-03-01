"""Rich console report output."""

from __future__ import annotations

from rich.console import Console
from rich.table import Table

from vitia_invenire.models import AssessmentReport, Severity

SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}


def generate(report: AssessmentReport, output_dir: str) -> str:
    """Display the report on the console using Rich.

    Args:
        report: The assessment report to display.
        output_dir: Unused for console output, kept for interface consistency.

    Returns:
        Empty string (console output has no file path).
    """
    con = Console()

    con.print()
    con.print("[bold]Vitia Invenire - Assessment Report[/bold]")
    con.print(f"Host: {report.hostname}")
    con.print(f"OS: {report.os_version}")
    con.print(f"Scan: {report.scan_start.isoformat()} to {report.scan_end.isoformat()}")
    con.print()

    # Summary table
    summary_table = Table(title="Summary by Severity")
    summary_table.add_column("Severity", style="bold")
    summary_table.add_column("Count", justify="right")

    for sev in Severity:
        count = report.summary.get(sev.value, 0)
        style = SEVERITY_COLORS.get(sev, "")
        summary_table.add_row(sev.value, str(count), style=style)

    con.print(summary_table)
    con.print()

    # Check results
    results_table = Table(title="Check Results")
    results_table.add_column("ID", style="cyan", width=18)
    results_table.add_column("Name", width=35)
    results_table.add_column("Category", width=20)
    results_table.add_column("Status", width=10)
    results_table.add_column("Findings", justify="right", width=10)
    results_table.add_column("Time (s)", justify="right", width=10)

    status_styles = {
        "passed": "green",
        "medium": "yellow",
        "high": "red",
        "critical": "bold red",
        "error": "bold magenta",
        "skipped": "dim",
    }

    for result in report.results:
        status_style = status_styles.get(result.status, "")
        results_table.add_row(
            result.check_id,
            result.check_name,
            result.category.value,
            f"[{status_style}]{result.status}[/{status_style}]",
            str(len(result.findings)),
            f"{result.duration_seconds:.1f}",
        )

    con.print(results_table)
    con.print()

    # Findings detail (non-INFO only)
    findings_shown = False
    for result in report.results:
        for finding in result.findings:
            if finding.severity == Severity.INFO:
                continue
            if not findings_shown:
                con.print("[bold]Findings Detail[/bold]")
                con.print()
                findings_shown = True

            sev_style = SEVERITY_COLORS.get(finding.severity, "")
            con.print(f"  [{sev_style}][{finding.severity.value}][/{sev_style}] {finding.title}")
            con.print(f"    Check: {finding.check_id}")
            con.print(f"    Affected: {finding.affected_item}")
            con.print(f"    Evidence: {finding.evidence[:200]}")
            con.print(f"    Recommendation: {finding.recommendation}")
            if finding.references:
                con.print(f"    References: {', '.join(finding.references)}")
            con.print()

    # Skipped checks
    skipped = [r for r in report.results if r.status == "skipped"]
    if skipped:
        con.print(f"[dim]{len(skipped)} checks skipped (use --verbose to see reasons)[/dim]")
        con.print()

    return ""
