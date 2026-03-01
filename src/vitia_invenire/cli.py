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
@click.option("--baseline", "baseline_path", default=None, type=click.Path(exists=True), help="Baseline file to compare against")
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


def _compare_reports(baseline_report: "AssessmentReport", current_report: "AssessmentReport"):
    """Compare two reports and display differences with deep state diffing."""
    con = Console()
    con.print()
    con.print("[bold]Baseline Comparison Results[/bold]")
    con.print(f"  Baseline host: {baseline_report.hostname}")
    con.print(f"  Current host:  {current_report.hostname}")
    con.print()

    differences = 0

    # Compare hardware fingerprints
    if baseline_report.hardware_fingerprint and current_report.hardware_fingerprint:
        bf = baseline_report.hardware_fingerprint
        cf = current_report.hardware_fingerprint
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
        baseline_types: dict[str, list] = {}
        for comp in bf.components:
            baseline_types.setdefault(comp.component_type, []).append(comp)
        current_types: dict[str, list] = {}
        for comp in cf.components:
            current_types.setdefault(comp.component_type, []).append(comp)

        all_types = set(baseline_types.keys()) | set(current_types.keys())
        for ctype in sorted(all_types):
            b_count = len(baseline_types.get(ctype, []))
            c_count = len(current_types.get(ctype, []))
            if b_count != c_count:
                con.print(f"  [yellow]DIFF[/yellow] {ctype} count: baseline={b_count}, current={c_count}")
                differences += 1

    # Per-check key fields for state diffing.
    # Maps check_id -> (context_key, identity_field_or_tuple).
    # For ACCT-001, special handling is used since state is a dict with two sub-lists.
    _STATE_KEYS: dict[str, tuple[str, str | tuple[str, ...]]] = {
        "SVC-001": ("state", "name"),
        "TASK-001": ("state", "task_path"),
        "DRV-001": ("state", "path"),
        "CERT-001": ("state", "thumbprint"),
        "FW-RULE-001": ("state", "name"),
        "SOFT-001": ("state", "name"),
        "REG-001": ("state", ("key", "name")),
        "PROC-001": ("state", "exe"),
        "COM-001": ("state", "clsid"),
        "EXT-001": ("state", ("browser", "extension_id")),
        "BITS-001": ("state", "job_id"),
        "FILE-001": ("state", "filename"),
        "BIN-001": ("state", "path"),
        "NET-PROC-001": ("listeners", "address"),
    }

    # Checks with dict-of-sub-lists state (like ACCT-001).
    # Maps check_id -> list of (sub_key, id_field, label).
    _MULTI_STATE_KEYS: dict[str, list[tuple[str, str, str]]] = {
        "ACCT-001": [
            ("users", "name", "users"),
            ("admin_members", "name", "admin members"),
        ],
        "WMI-001": [
            ("filters", "name", "WMI filters"),
            ("consumers", "name", "WMI consumers"),
            ("bindings", "name", "WMI bindings"),
        ],
        "SSH-001": [
            ("service", "name", "SSH service"),
            ("config", "name", "SSH config"),
            ("authorized_keys", "name", "authorized keys"),
        ],
        "RDP-001": [
            ("config", "name", "RDP config"),
            ("connections", "name", "RDP connections"),
        ],
    }

    baseline_checks = {r.check_id: r for r in baseline_report.results}
    current_checks = {r.check_id: r for r in current_report.results}

    for check_id in sorted(set(baseline_checks.keys()) | set(current_checks.keys())):
        baseline_result = baseline_checks.get(check_id)
        current_result = current_checks.get(check_id)
        check_diffs: list[str] = []

        # New check not in baseline
        if baseline_result is None and current_result is not None:
            check_diffs.append("  [cyan]NEW CHECK[/cyan] (not in baseline)")

        # Check disappeared
        if baseline_result is not None and current_result is None:
            check_diffs.append("  [cyan]REMOVED CHECK[/cyan] (was in baseline)")

        if baseline_result and current_result:
            # Deep state diffing
            if check_id in _MULTI_STATE_KEYS:
                # Checks with dict-of-sub-lists state
                b_state = baseline_result.context.get("state", {})
                c_state = current_result.context.get("state", {})
                if isinstance(b_state, dict) and isinstance(c_state, dict):
                    for sub_key, id_field, label in _MULTI_STATE_KEYS[check_id]:
                        b_items = b_state.get(sub_key, [])
                        c_items = c_state.get(sub_key, [])
                        if isinstance(b_items, list) and isinstance(c_items, list):
                            sub_diffs = _diff_state_lists(b_items, c_items, id_field)
                            for kind, item in sub_diffs:
                                if kind == "added":
                                    check_diffs.append(f"  [red]ADDED[/red] {label}: {_fmt_item(item)}")
                                elif kind == "removed":
                                    check_diffs.append(f"  [green]REMOVED[/green] {label}: {_fmt_item(item)}")
                                elif kind == "changed":
                                    check_diffs.append(f"  [yellow]CHANGED[/yellow] {label}: {_fmt_item(item)}")

            elif check_id in _STATE_KEYS:
                ctx_key, id_field = _STATE_KEYS[check_id]
                b_items = baseline_result.context.get(ctx_key, [])
                c_items = current_result.context.get(ctx_key, [])
                if isinstance(b_items, list) and isinstance(c_items, list):
                    sub_diffs = _diff_state_lists(b_items, c_items, id_field)
                    for kind, item in sub_diffs:
                        if kind == "added":
                            check_diffs.append(f"  [red]ADDED[/red] {_fmt_item(item)}")
                        elif kind == "removed":
                            check_diffs.append(f"  [green]REMOVED[/green] {_fmt_item(item)}")
                        elif kind == "changed":
                            check_diffs.append(f"  [yellow]CHANGED[/yellow] {_fmt_item(item)}")

            # Finding diffing: new and resolved findings
            baseline_titles = {f.title for f in baseline_result.findings}
            current_titles = {f.title for f in current_result.findings}

            for finding in current_result.findings:
                if finding.title not in baseline_titles:
                    sev = finding.severity.value
                    check_diffs.append(
                        f"  [red]NEW FINDING[/red] [{sev}] {finding.title}"
                    )

            for finding in baseline_result.findings:
                if finding.title not in current_titles:
                    sev = finding.severity.value
                    check_diffs.append(
                        f"  [green]RESOLVED[/green] [{sev}] {finding.title}"
                    )

        if check_diffs:
            check_name = ""
            if current_result:
                check_name = current_result.check_name
            elif baseline_result:
                check_name = baseline_result.check_name
            con.print(f"[bold]{check_id}[/bold] ({check_name})")
            for line in check_diffs:
                con.print(line)
            con.print()
            differences += len(check_diffs)

    con.print()
    if differences == 0:
        con.print("[green]No differences found -- system matches baseline.[/green]")
    else:
        con.print(f"[yellow]{differences} difference(s) found between baseline and current system.[/yellow]")


def _get_item_key(item: dict, id_field: str | tuple[str, ...]) -> str:
    """Extract a hashable identity key from a state item."""
    if isinstance(id_field, tuple):
        return "|".join(str(item.get(f, "")) for f in id_field)
    return str(item.get(id_field, ""))


def _diff_state_lists(
    baseline_items: list[dict],
    current_items: list[dict],
    id_field: str | tuple[str, ...],
) -> list[tuple[str, dict]]:
    """Diff two lists of state dicts by identity field.

    Returns list of (kind, item) where kind is 'added', 'removed', or 'changed'.
    For 'changed', item includes the key fields plus a '_changes' key describing
    the differing fields.
    """
    diffs: list[tuple[str, dict]] = []

    b_map: dict[str, dict] = {}
    for item in baseline_items:
        key = _get_item_key(item, id_field)
        if key:
            b_map[key] = item

    c_map: dict[str, dict] = {}
    for item in current_items:
        key = _get_item_key(item, id_field)
        if key:
            c_map[key] = item

    # Added items (in current but not baseline)
    for key in sorted(c_map.keys()):
        if key not in b_map:
            diffs.append(("added", c_map[key]))

    # Removed items (in baseline but not current)
    for key in sorted(b_map.keys()):
        if key not in c_map:
            diffs.append(("removed", b_map[key]))

    # Changed items (same key, different values)
    for key in sorted(b_map.keys()):
        if key in c_map:
            b_item = b_map[key]
            c_item = c_map[key]
            changes: dict[str, tuple] = {}
            all_fields = set(b_item.keys()) | set(c_item.keys())
            for field in all_fields:
                if field.startswith("_"):
                    continue
                bval = b_item.get(field)
                cval = c_item.get(field)
                if bval != cval:
                    changes[field] = (bval, cval)
            if changes:
                changed_item = dict(c_item)
                changed_item["_changes"] = changes
                diffs.append(("changed", changed_item))

    return diffs


def _fmt_item(item: dict) -> str:
    """Format a state item dict for display."""
    changes = item.pop("_changes", None)
    # Build a concise representation
    parts = []
    for k, v in item.items():
        if k.startswith("_"):
            continue
        sv = str(v)
        if len(sv) > 80:
            sv = sv[:77] + "..."
        parts.append(f"{k}={sv}")
    result = ", ".join(parts)
    if changes:
        change_parts = []
        for field, (old, new) in changes.items():
            change_parts.append(f"{field}: {old} -> {new}")
        result += " | Changes: " + "; ".join(change_parts)
    return result


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
