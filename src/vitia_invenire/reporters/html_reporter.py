"""HTML report output via Jinja2 templating."""

from __future__ import annotations

import os
from importlib import resources
from pathlib import Path

from jinja2 import Environment, BaseLoader

from vitia_invenire.models import AssessmentReport, Severity

SEVERITY_COLORS = {
    "CRITICAL": "#dc3545",
    "HIGH": "#e74c3c",
    "MEDIUM": "#f39c12",
    "LOW": "#3498db",
    "INFO": "#95a5a6",
}


def _load_template() -> str:
    """Load the HTML template from package data."""
    ref = resources.files("vitia_invenire.templates").joinpath("report.html.j2")
    return ref.read_text(encoding="utf-8")


def generate(report: AssessmentReport, output_dir: str) -> str:
    """Render the assessment report as a self-contained HTML file.

    Args:
        report: The assessment report to render.
        output_dir: Directory to write the HTML file.

    Returns:
        Path to the generated HTML file.
    """
    os.makedirs(output_dir, exist_ok=True)

    template_str = _load_template()
    env = Environment(loader=BaseLoader(), autoescape=True)
    template = env.from_string(template_str)

    # Prepare template data
    total_findings = sum(len(r.findings) for r in report.results)
    passed = sum(1 for r in report.results if r.status == "passed")
    failed = sum(1 for r in report.results if r.status == "failed")
    errored = sum(1 for r in report.results if r.status == "error")
    skipped = sum(1 for r in report.results if r.status == "skipped")

    # All findings sorted by severity
    all_findings = []
    for result in report.results:
        for finding in result.findings:
            all_findings.append(finding)
    all_findings.sort(key=lambda f: list(Severity).index(f.severity))

    # Category summary
    category_counts: dict[str, dict[str, int]] = {}
    for result in report.results:
        cat = result.category.value
        if cat not in category_counts:
            category_counts[cat] = {s.value: 0 for s in Severity}
        for finding in result.findings:
            category_counts[cat][finding.severity.value] += 1

    duration = (report.scan_end - report.scan_start).total_seconds()

    html = template.render(
        report=report,
        total_findings=total_findings,
        passed=passed,
        failed=failed,
        errored=errored,
        skipped=skipped,
        all_findings=all_findings,
        category_counts=category_counts,
        severity_colors=SEVERITY_COLORS,
        severities=[s.value for s in Severity],
        duration=f"{duration:.1f}",
    )

    timestamp = report.scan_start.strftime("%Y%m%d_%H%M%S")
    filename = f"{report.hostname}_{timestamp}.html"
    filepath = Path(output_dir) / filename
    filepath.write_text(html, encoding="utf-8")

    return str(filepath)
