"""HTML report output via Jinja2 templating."""

from __future__ import annotations

import os
from collections import OrderedDict
from importlib import resources
from pathlib import Path

from jinja2 import Environment, BaseLoader

from vitia_invenire.models import CATEGORY_ORDER, AssessmentReport, Category, Severity

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


def _build_category_data(report: AssessmentReport) -> tuple[OrderedDict, dict]:
    """Group results by category and compute per-category stats.

    Returns:
        (category_results, category_stats) where:
        - category_results: OrderedDict mapping category name -> list of CheckResult
        - category_stats: dict mapping category name -> stat dict
    """
    # Group results by category
    groups: dict[str, list] = {}
    for result in report.results:
        cat = result.category.value
        groups.setdefault(cat, []).append(result)

    # Sort categories by canonical order
    sorted_cats = sorted(
        groups.keys(),
        key=lambda c: CATEGORY_ORDER.get(Category(c), 999) if c in [e.value for e in Category] else 999,
    )
    category_results: OrderedDict = OrderedDict()
    for cat in sorted_cats:
        category_results[cat] = groups[cat]

    # Compute per-category stats
    category_stats: dict[str, dict] = {}
    for cat, results in category_results.items():
        check_count = len(results)
        passed = sum(1 for r in results if r.status == "passed")
        medium = sum(1 for r in results if r.status == "medium")
        high = sum(1 for r in results if r.status == "high")
        critical = sum(1 for r in results if r.status == "critical")
        errored = sum(1 for r in results if r.status == "error")
        skipped = sum(1 for r in results if r.status == "skipped")
        finding_count = sum(len(r.findings) for r in results)
        severity_breakdown = {s.value: 0 for s in Severity}
        for r in results:
            for f in r.findings:
                severity_breakdown[f.severity.value] += 1

        category_stats[cat] = {
            "check_count": check_count,
            "passed": passed,
            "medium": medium,
            "high": high,
            "critical": critical,
            "errored": errored,
            "skipped": skipped,
            "finding_count": finding_count,
            "severity_breakdown": severity_breakdown,
        }

    return category_results, category_stats


def _extract_check_context(report: AssessmentReport) -> tuple[dict, dict]:
    """Extract binary analysis and network context dicts from check results.

    Returns:
        (binary_context, network_context) dicts.
    """
    binary_context: dict = {}
    network_context: dict = {}

    for result in report.results:
        if result.check_id == "BIN-001" and result.context:
            binary_context["hashing"] = result.context
        elif result.check_id == "HASH-001" and result.context:
            binary_context["hash_lookup"] = result.context
        elif result.check_id == "SIG-001" and result.context:
            binary_context["signatures"] = result.context
        elif result.check_id == "CATALOG-001" and result.context:
            binary_context["catalog"] = result.context
        elif result.check_id == "NET-CONN-001" and result.context:
            network_context["connections"] = result.context
        elif result.check_id == "NET-PROC-001" and result.context:
            network_context["listeners"] = result.context

    return binary_context, network_context


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
    medium = sum(1 for r in report.results if r.status == "medium")
    high = sum(1 for r in report.results if r.status == "high")
    critical = sum(1 for r in report.results if r.status == "critical")
    errored = sum(1 for r in report.results if r.status == "error")
    skipped = sum(1 for r in report.results if r.status == "skipped")

    # All findings sorted by severity
    all_findings = []
    for result in report.results:
        for finding in result.findings:
            all_findings.append(finding)
    all_findings.sort(key=lambda f: list(Severity).index(f.severity))

    # Category data
    category_results, category_stats = _build_category_data(report)

    # Extract context data for dashboards
    binary_context, network_context = _extract_check_context(report)

    duration = (report.scan_end - report.scan_start).total_seconds()

    html = template.render(
        report=report,
        total_findings=total_findings,
        passed=passed,
        medium=medium,
        high=high,
        critical=critical,
        errored=errored,
        skipped=skipped,
        all_findings=all_findings,
        category_results=category_results,
        category_stats=category_stats,
        binary_context=binary_context,
        network_context=network_context,
        severity_colors=SEVERITY_COLORS,
        severities=[s.value for s in Severity],
        duration=f"{duration:.1f}",
    )

    timestamp = report.scan_start.strftime("%Y%m%d_%H%M%S")
    filename = f"{report.hostname}_{timestamp}.html"
    filepath = Path(output_dir) / filename
    filepath.write_text(html, encoding="utf-8")

    return str(filepath)
