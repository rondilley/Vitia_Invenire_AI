"""Check discovery, orchestration, and report assembly."""

from __future__ import annotations

import importlib
import inspect
import pkgutil
import random
from datetime import datetime, timezone

from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

import vitia_invenire.checks as checks_package
from vitia_invenire.checks.base import BaseCheck
from vitia_invenire.config import Config
from vitia_invenire.models import (
    CATEGORY_ORDER,
    AssessmentReport,
    CheckResult,
)
from vitia_invenire.platform import get_hostname, get_os_version

console = Console()


class Engine:
    """Discovers and runs security checks, producing an AssessmentReport."""

    def __init__(self, config: Config):
        self.config = config
        self.checks: list[BaseCheck] = []

    def discover_checks(self) -> list[BaseCheck]:
        """Walk the checks package and find all BaseCheck subclasses.

        Returns:
            List of instantiated BaseCheck subclasses, filtered by config.
        """
        check_classes: list[type[BaseCheck]] = []

        for module_info in pkgutil.walk_packages(
            checks_package.__path__,
            prefix=checks_package.__name__ + ".",
        ):
            try:
                module = importlib.import_module(module_info.name)
            except Exception as exc:
                if self.config.verbose:
                    console.print(f"[yellow]Warning: Failed to import {module_info.name}: {exc}[/yellow]")
                continue

            for _name, obj in inspect.getmembers(module, inspect.isclass):
                if (
                    issubclass(obj, BaseCheck)
                    and obj is not BaseCheck
                    and obj.CHECK_ID  # skip classes without CHECK_ID
                ):
                    check_classes.append(obj)

        # Deduplicate by CHECK_ID (in case of re-imports)
        seen: set[str] = set()
        unique_classes: list[type[BaseCheck]] = []
        for cls in check_classes:
            if cls.CHECK_ID not in seen:
                seen.add(cls.CHECK_ID)
                unique_classes.append(cls)

        # Filter by config
        filtered: list[type[BaseCheck]] = []
        for cls in unique_classes:
            if self.config.is_check_disabled(cls.CHECK_ID):
                continue
            if not self.config.is_category_enabled(cls.CATEGORY.value):
                continue
            if self.config.skip_admin_checks and cls.REQUIRES_ADMIN:
                continue
            filtered.append(cls)

        # Sort by category order, then by CHECK_ID for stable ordering
        filtered.sort(key=lambda c: (CATEGORY_ORDER.get(c.CATEGORY, 999), c.CHECK_ID))

        # Randomize if requested (anti-evasion measure)
        if self.config.randomize_order:
            random.shuffle(filtered)

        # Instantiate
        self.checks = [cls() for cls in filtered]
        return self.checks

    def list_checks(self) -> list[dict]:
        """Return metadata for all discovered checks (for --list-checks)."""
        self.discover_checks()
        return [
            {
                "check_id": check.CHECK_ID,
                "name": check.NAME,
                "category": check.CATEGORY.value,
                "requires_admin": check.REQUIRES_ADMIN,
                "requires_tools": check.REQUIRES_TOOLS,
                "description": check.DESCRIPTION,
            }
            for check in self.checks
        ]

    def run(self) -> AssessmentReport:
        """Execute all discovered checks and assemble the report.

        Returns:
            AssessmentReport with all check results and summary.
        """
        if not self.checks:
            self.discover_checks()

        scan_start = datetime.now(timezone.utc)
        results: list[CheckResult] = []

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("Running security checks...", total=len(self.checks))

            for check in self.checks:
                progress.update(task, description=f"[cyan]{check.CHECK_ID}[/cyan] {check.NAME}")
                result = check.execute()
                results.append(result)
                progress.advance(task)

        scan_end = datetime.now(timezone.utc)

        report = AssessmentReport(
            hostname=get_hostname(),
            os_version=get_os_version(),
            scan_start=scan_start,
            scan_end=scan_end,
            results=results,
        )
        report.compute_summary()

        return report
