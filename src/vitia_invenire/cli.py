"""Click CLI interface for Vitia Invenire."""

from __future__ import annotations

import sys

import click
from rich.console import Console
from rich.table import Table

from vitia_invenire import __version__
from vitia_invenire.config import Config
from vitia_invenire.engine import Engine
from vitia_invenire.platform import is_admin, is_windows
from vitia_invenire.reporters import console_reporter, json_reporter

console = Console()


@click.group()
@click.version_option(version=__version__, prog_name="vitia-invenire")
def main():
    """Vitia Invenire - Windows Supply Chain Security Assessment Tool."""


@main.command()
@click.option("--categories", default=None, help="Comma-separated categories to run (default: all)")
@click.option("--severity", default=None, help="Minimum severity to report (default: INFO)")
@click.option("--output-dir", default=None, help="Output directory for reports (default: ./reports)")
@click.option("--format", "formats", default=None, help="Output formats: json,html,console (default: console,json)")
@click.option("--config", "config_path", default=None, type=click.Path(exists=True), help="Path to config YAML")
@click.option("--skip-admin-checks", is_flag=True, help="Skip checks requiring admin privileges")
@click.option("--require-admin", is_flag=True, help="Exit with error if not running as admin")
@click.option("--randomize-order", is_flag=True, help="Randomize check execution order (anti-evasion)")
@click.option("--list-checks", is_flag=True, help="List all available checks and exit")
@click.option("--verbose", is_flag=True, help="Verbose output during scanning")
def scan(
    categories: str | None,
    severity: str | None,
    output_dir: str | None,
    formats: str | None,
    config_path: str | None,
    skip_admin_checks: bool,
    require_admin: bool,
    randomize_order: bool,
    list_checks: bool,
    verbose: bool,
):
    """Run security assessment checks on this system."""
    # Load config
    if config_path:
        config = Config.from_yaml(config_path)
    else:
        config = Config.from_defaults()

    config.apply_overrides(
        categories=categories,
        severity=severity,
        output_dir=output_dir,
        formats=formats,
        skip_admin=skip_admin_checks,
        require_admin=require_admin,
        randomize_order=randomize_order,
        verbose=verbose,
    )

    engine = Engine(config)

    # List checks mode
    if list_checks:
        checks = engine.list_checks()
        table = Table(title=f"Available Checks ({len(checks)} total)")
        table.add_column("ID", style="cyan", width=18)
        table.add_column("Name", width=35)
        table.add_column("Category", width=20)
        table.add_column("Admin", width=6)
        table.add_column("Tools", width=15)
        table.add_column("Description", width=60)

        for check in checks:
            table.add_row(
                check["check_id"],
                check["name"],
                check["category"],
                "Yes" if check["requires_admin"] else "No",
                ", ".join(check["requires_tools"]) if check["requires_tools"] else "",
                check["description"][:60],
            )

        console.print(table)
        return

    # Admin requirement check
    if config.require_admin and is_windows() and not is_admin():
        console.print("[bold red]ERROR: --require-admin specified but not running as administrator.[/bold red]")
        console.print("Re-run from an elevated command prompt or PowerShell.")
        sys.exit(1)

    # Admin warning
    if is_windows() and not is_admin() and not config.skip_admin_checks:
        console.print(
            "[yellow]WARNING: Running without administrator privileges. "
            "Critical firmware, Secure Boot, and EFI partition checks require elevation. "
            "Results will be incomplete.[/yellow]"
        )
        console.print()

    # Run assessment
    console.print(f"[bold]Vitia Invenire v{__version__}[/bold]")
    console.print()

    engine.discover_checks()
    console.print(f"Discovered {len(engine.checks)} checks")
    console.print()

    report = engine.run()

    # Generate reports
    output_files: list[str] = []
    for fmt in config.output_formats:
        if fmt == "console":
            console_reporter.generate(report, config.output_directory)
        elif fmt == "json":
            path = json_reporter.generate(report, config.output_directory)
            output_files.append(path)
        elif fmt == "html":
            try:
                from vitia_invenire.reporters import html_reporter
                path = html_reporter.generate(report, config.output_directory)
                output_files.append(path)
            except ImportError:
                console.print("[yellow]HTML reporter not available[/yellow]")

    if output_files:
        console.print("[bold]Reports written:[/bold]")
        for path in output_files:
            console.print(f"  {path}")

    # Exit code
    if report.has_critical_findings():
        sys.exit(2)


@main.command()
@click.argument("action", type=click.Choice(["create", "compare"]))
@click.option("--output", default="baseline.json", help="Output file for baseline (create mode)")
@click.option("--baseline", default=None, type=click.Path(exists=True), help="Baseline file to compare against")
@click.option("--config", "config_path", default=None, type=click.Path(exists=True), help="Path to config YAML")
def baseline(action: str, output: str, baseline_path: str | None, config_path: str | None):
    """Golden image baseline management.

    Create a baseline from a trusted reference device, or compare
    the current system against an existing baseline.
    """
    if config_path:
        config = Config.from_yaml(config_path)
    else:
        config = Config.from_defaults()

    if action == "create":
        console.print("[bold]Creating golden image baseline...[/bold]")
        engine = Engine(config)
        engine.discover_checks()
        report = engine.run()
        json_str = report.model_dump_json(indent=2)
        with open(output, "w", encoding="utf-8") as f:
            f.write(json_str)
        console.print(f"Baseline written to: {output}")

    elif action == "compare":
        if not baseline_path:
            console.print("[bold red]ERROR: --baseline path required for compare mode[/bold red]")
            sys.exit(1)

        import json
        from vitia_invenire.models import AssessmentReport as AR

        console.print(f"[bold]Comparing against baseline: {baseline_path}[/bold]")

        with open(baseline_path, encoding="utf-8") as f:
            baseline_data = json.load(f)
        baseline_report = AR.model_validate(baseline_data)

        engine = Engine(config)
        engine.discover_checks()
        current_report = engine.run()

        _compare_reports(baseline_report, current_report)


def _compare_reports(baseline: "AssessmentReport", current: "AssessmentReport"):
    """Compare two reports and display differences."""
    from vitia_invenire.models import AssessmentReport  # noqa: F811

    con = Console()
    con.print()
    con.print("[bold]Baseline Comparison Results[/bold]")
    con.print(f"  Baseline host: {baseline.hostname}")
    con.print(f"  Current host:  {current.hostname}")
    con.print()

    differences = 0

    # Compare hardware fingerprints
    if baseline.hardware_fingerprint and current.hardware_fingerprint:
        bf = baseline.hardware_fingerprint
        cf = current.hardware_fingerprint
        hw_fields = [
            ("System Manufacturer", bf.system_manufacturer, cf.system_manufacturer),
            ("System Model", bf.system_model, cf.system_model),
            ("BIOS Version", bf.bios_version, cf.bios_version),
            ("BIOS Vendor", bf.bios_vendor, cf.bios_vendor),
            ("EC Version", bf.ec_version, cf.ec_version),
            ("Secure Boot", bf.secure_boot_enabled, cf.secure_boot_enabled),
            ("TPM Version", bf.tpm_version, cf.tpm_version),
        ]
        for field_name, bval, cval in hw_fields:
            if bval != cval:
                con.print(f"  [yellow]DIFF[/yellow] {field_name}: baseline={bval}, current={cval}")
                differences += 1

        # Component count differences
        baseline_types = {}
        for comp in bf.components:
            baseline_types.setdefault(comp.component_type, []).append(comp)
        current_types = {}
        for comp in cf.components:
            current_types.setdefault(comp.component_type, []).append(comp)

        all_types = set(baseline_types.keys()) | set(current_types.keys())
        for ctype in sorted(all_types):
            b_count = len(baseline_types.get(ctype, []))
            c_count = len(current_types.get(ctype, []))
            if b_count != c_count:
                con.print(f"  [yellow]DIFF[/yellow] {ctype} count: baseline={b_count}, current={c_count}")
                differences += 1

    # Compare check results
    baseline_checks = {r.check_id: r for r in baseline.results}
    current_checks = {r.check_id: r for r in current.results}

    for check_id, current_result in current_checks.items():
        baseline_result = baseline_checks.get(check_id)
        if baseline_result is None:
            continue

        # New findings not in baseline
        baseline_titles = {f.title for f in baseline_result.findings}
        for finding in current_result.findings:
            if finding.title not in baseline_titles:
                sev = finding.severity.value
                con.print(f"  [red]NEW FINDING[/red] [{sev}] {finding.title}")
                con.print(f"    Check: {check_id}, Affected: {finding.affected_item}")
                differences += 1

    con.print()
    if differences == 0:
        con.print("[green]No differences found -- system matches baseline.[/green]")
    else:
        con.print(f"[yellow]{differences} difference(s) found between baseline and current system.[/yellow]")


@main.command(name="update-data")
@click.option("--catalog-export", "catalog_export_path", default=None, type=click.Path(),
              help="Export catalog verification results to JSON file")
def update_data(catalog_export_path: str | None):
    """Fetch latest reference data from trusted sources.

    Run this on a TRUSTED machine, not on the device under assessment.
    Copy the updated data files to the assessment USB drive.

    Use --catalog-export to run CATALOG-001 and export all file verification
    results as a JSON baseline for comparison across devices.
    """
    if catalog_export_path:
        _export_catalog(catalog_export_path)
        return

    console.print("[bold]Reference data update[/bold]")
    console.print()
    console.print("This command will fetch updated reference data from:")
    console.print("  - Microsoft Trusted Root Program (certificates)")
    console.print("  - LOLDrivers project (vulnerable driver hashes)")
    console.print("  - NIST NSRL (known file hashes)")
    console.print()
    console.print("[yellow]Not yet implemented. Reference data files must be updated manually.[/yellow]")
    console.print("See README.md for data file format documentation.")


def _export_catalog(output_path: str) -> None:
    """Run CATALOG-001 and export all results as JSON."""
    import json
    from datetime import datetime, timezone

    from vitia_invenire.checks.catalog_integrity import CatalogIntegrityCheck
    from vitia_invenire.platform import get_hostname, get_os_version

    console.print("[bold]Catalog verification export[/bold]")
    console.print()

    check = CatalogIntegrityCheck()
    console.print("Running catalog integrity verification...")
    result = check.execute()

    if result.status == "skipped":
        console.print(f"[yellow]Skipped: {result.error_message}[/yellow]")
        return

    if result.status == "error":
        console.print(f"[red]Error: {result.error_message}[/red]")
        return

    all_results = result.context.get("_all_results", [])
    summary = {
        "total_files": result.context.get("total_files", 0),
        "catalog_verified": result.context.get("catalog_verified", 0),
        "third_party_signed": result.context.get("third_party_signed", 0),
        "hash_mismatch": result.context.get("hash_mismatch", 0),
        "not_signed": result.context.get("not_signed", 0),
        "errors": result.context.get("errors", 0),
        "verification_rate_pct": result.context.get("verification_rate_pct", 0.0),
    }

    export_data = {
        "export_type": "catalog_verification",
        "export_version": "1.0",
        "hostname": get_hostname(),
        "os_version": get_os_version(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "summary": summary,
        "files": all_results,
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(export_data, f, indent=2)

    console.print(f"Exported {len(all_results)} file verification results")
    console.print(f"  Catalog verified: {summary['catalog_verified']}")
    console.print(f"  Third-party signed: {summary['third_party_signed']}")
    console.print(f"  Hash mismatch: {summary['hash_mismatch']}")
    console.print(f"  Unsigned: {summary['not_signed']}")
    console.print(f"  Errors: {summary['errors']}")
    console.print()
    console.print(f"Written to: {output_path}")


@main.command()
@click.option("--duration", default=300, help="Monitoring duration in seconds (default: 300)")
@click.option("--output-dir", default="./reports", help="Output directory for monitor results")
def monitor(duration: int, output_dir: str):
    """Passive network beaconing monitor.

    Monitors outbound network connections for the specified duration
    to detect beaconing behavior (periodic C2 callbacks).
    """
    if not is_windows():
        console.print("[yellow]Network monitoring requires Windows. Exiting.[/yellow]")
        return

    console.print(f"[bold]Passive network monitor -- listening for {duration} seconds[/bold]")
    console.print()
    console.print("[yellow]Not yet implemented. This will be added in Phase 8.[/yellow]")
