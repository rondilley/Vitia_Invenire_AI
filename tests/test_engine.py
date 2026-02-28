"""Tests for the check discovery engine."""

from __future__ import annotations

from vitia_invenire.config import Config
from vitia_invenire.engine import Engine
from vitia_invenire.models import Category


class TestEngineDiscovery:
    def test_discover_finds_checks(self):
        """Engine should discover all check modules in the checks package."""
        config = Config()
        engine = Engine(config)
        checks = engine.discover_checks()
        # We should have at least some checks discovered
        # (exact count depends on which check files exist)
        assert isinstance(checks, list)

    def test_discover_deduplicates_by_check_id(self):
        """Each CHECK_ID should appear at most once."""
        config = Config()
        engine = Engine(config)
        checks = engine.discover_checks()
        ids = [c.CHECK_ID for c in checks]
        assert len(ids) == len(set(ids)), f"Duplicate CHECK_IDs found: {ids}"

    def test_discover_filters_disabled_checks(self):
        """Disabled checks should not be discovered."""
        config = Config(disabled_checks=["CERT-001"])
        engine = Engine(config)
        checks = engine.discover_checks()
        ids = [c.CHECK_ID for c in checks]
        assert "CERT-001" not in ids

    def test_discover_filters_by_category(self):
        """Only enabled categories should be discovered."""
        config = Config(enabled_categories=["Certificates"])
        engine = Engine(config)
        checks = engine.discover_checks()
        for check in checks:
            assert check.CATEGORY == Category.CERTIFICATES

    def test_discover_skips_admin_checks(self):
        """With skip_admin_checks, admin-requiring checks should be excluded."""
        config = Config(skip_admin_checks=True)
        engine = Engine(config)
        checks = engine.discover_checks()
        for check in checks:
            assert not check.REQUIRES_ADMIN, f"{check.CHECK_ID} requires admin but was not skipped"

    def test_list_checks_returns_metadata(self):
        """list_checks should return dicts with check metadata."""
        config = Config()
        engine = Engine(config)
        checks_info = engine.list_checks()
        assert isinstance(checks_info, list)
        if checks_info:
            first = checks_info[0]
            assert "check_id" in first
            assert "name" in first
            assert "category" in first
            assert "requires_admin" in first
            assert "description" in first

    def test_run_produces_report(self):
        """Engine.run() should produce a valid AssessmentReport."""
        config = Config()
        engine = Engine(config)
        engine.discover_checks()
        report = engine.run()
        assert report.hostname
        assert report.os_version
        assert report.scan_start <= report.scan_end
        assert isinstance(report.results, list)
        assert isinstance(report.summary, dict)


class TestEngineConfig:
    def test_config_from_defaults(self):
        config = Config.from_defaults()
        assert config.enabled_categories == ["all"]
        assert config.minimum_severity.value == "INFO"

    def test_config_apply_overrides(self):
        config = Config()
        config.apply_overrides(
            categories="Firmware,Certificates",
            severity="HIGH",
            output_dir="/tmp/test",
            formats="json,html",
            skip_admin=True,
            verbose=True,
        )
        assert config.enabled_categories == ["Firmware", "Certificates"]
        assert config.minimum_severity.value == "HIGH"
        assert config.output_directory == "/tmp/test"
        assert config.output_formats == ["json", "html"]
        assert config.skip_admin_checks is True
        assert config.verbose is True

    def test_config_check_config(self):
        config = Config(check_configs={"CERT-001": {"threshold": 2048}})
        cert_config = config.get_check_config("CERT-001")
        assert cert_config["threshold"] == 2048

    def test_config_missing_check_config(self):
        config = Config()
        result = config.get_check_config("NONEXISTENT-001")
        assert result == {}
