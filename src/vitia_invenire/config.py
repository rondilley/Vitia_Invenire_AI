"""YAML configuration loader with defaults."""

from __future__ import annotations

from importlib import resources
from pathlib import Path
from typing import Any

import yaml

from vitia_invenire.models import Severity

_DEFAULT_CONFIG_RESOURCE = "vitia_invenire.data"
_DEFAULT_CONFIG_FILE = "check_config.yaml"


class Config:
    """Application configuration loaded from YAML with CLI overrides."""

    def __init__(
        self,
        enabled_categories: list[str] | None = None,
        disabled_checks: list[str] | None = None,
        check_configs: dict[str, dict] | None = None,
        minimum_severity: Severity = Severity.INFO,
        output_formats: list[str] | None = None,
        output_directory: str = "./reports",
        skip_admin_checks: bool = False,
        require_admin: bool = False,
        randomize_order: bool = False,
        verbose: bool = False,
    ):
        self.enabled_categories = enabled_categories or ["all"]
        self.disabled_checks = disabled_checks or []
        self.check_configs = check_configs or {}
        self.minimum_severity = minimum_severity
        self.output_formats = output_formats or ["console", "json"]
        self.output_directory = output_directory
        self.skip_admin_checks = skip_admin_checks
        self.require_admin = require_admin
        self.randomize_order = randomize_order
        self.verbose = verbose

    def get_check_config(self, check_id: str) -> dict[str, Any]:
        """Return per-check configuration dict, empty if not configured."""
        return self.check_configs.get(check_id, {})

    def is_category_enabled(self, category_name: str) -> bool:
        """Check if a category is enabled in config."""
        if "all" in self.enabled_categories:
            return True
        return category_name in self.enabled_categories

    def is_check_disabled(self, check_id: str) -> bool:
        """Check if a specific check is disabled."""
        return check_id in self.disabled_checks

    @classmethod
    def from_yaml(cls, path: str | Path) -> Config:
        """Load configuration from a YAML file."""
        with open(path) as f:
            raw = yaml.safe_load(f) or {}
        return cls._from_dict(raw)

    @classmethod
    def from_defaults(cls) -> Config:
        """Load built-in default configuration."""
        try:
            ref = resources.files(_DEFAULT_CONFIG_RESOURCE).joinpath(_DEFAULT_CONFIG_FILE)
            raw = yaml.safe_load(ref.read_text(encoding="utf-8")) or {}
            return cls._from_dict(raw)
        except (FileNotFoundError, TypeError):
            return cls()

    @classmethod
    def _from_dict(cls, raw: dict) -> Config:
        """Parse a raw dict into Config."""
        categories = raw.get("categories", {})
        checks = raw.get("checks", {})
        severity_section = raw.get("severity", {})
        output_section = raw.get("output", {})

        disabled = checks.pop("disabled", []) if isinstance(checks.get("disabled"), list) else []

        min_sev_str = severity_section.get("minimum", "INFO")
        try:
            min_severity = Severity(min_sev_str.upper())
        except ValueError:
            min_severity = Severity.INFO

        return cls(
            enabled_categories=categories.get("enabled", ["all"]),
            disabled_checks=disabled,
            check_configs=checks,
            minimum_severity=min_severity,
            output_formats=output_section.get("formats", ["console", "json"]),
            output_directory=output_section.get("directory", "./reports"),
        )

    def apply_overrides(
        self,
        categories: str | None = None,
        severity: str | None = None,
        output_dir: str | None = None,
        formats: str | None = None,
        skip_admin: bool = False,
        require_admin: bool = False,
        randomize_order: bool = False,
        verbose: bool = False,
    ) -> None:
        """Apply CLI flag overrides to this config."""
        if categories:
            self.enabled_categories = [c.strip() for c in categories.split(",")]
        if severity:
            try:
                self.minimum_severity = Severity(severity.upper())
            except ValueError:
                pass  # keep existing
        if output_dir:
            self.output_directory = output_dir
        if formats:
            self.output_formats = [f.strip() for f in formats.split(",")]
        if skip_admin:
            self.skip_admin_checks = True
        if require_admin:
            self.require_admin = True
        if randomize_order:
            self.randomize_order = True
        if verbose:
            self.verbose = True
