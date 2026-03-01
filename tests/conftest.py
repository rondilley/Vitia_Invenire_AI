"""Shared test fixtures and platform-conditional helpers."""

from __future__ import annotations

import sys

import pytest

from vitia_invenire.config import Config
from vitia_invenire.models import (
    AssessmentReport,
    Category,
    CheckResult,
    Finding,
    HardwareComponent,
    HardwareFingerprint,
    Severity,
)

# Platform skip markers
windows_only = pytest.mark.skipif(
    sys.platform != "win32",
    reason="Test requires Windows",
)


@pytest.fixture
def default_config() -> Config:
    """Return a default Config instance."""
    return Config()


@pytest.fixture
def sample_finding() -> Finding:
    """Return a sample Finding for testing."""
    return Finding(
        check_id="TEST-001",
        title="Test Finding",
        description="A test finding for unit tests",
        severity=Severity.HIGH,
        category=Category.CONFIGURATION,
        affected_item="test_item",
        evidence="test evidence data",
        recommendation="Fix the test issue",
        references=["https://example.com/test"],
    )


@pytest.fixture
def sample_check_result(sample_finding: Finding) -> CheckResult:
    """Return a sample CheckResult for testing."""
    return CheckResult(
        check_id="TEST-001",
        check_name="Test Check",
        category=Category.CONFIGURATION,
        status="high",
        duration_seconds=1.5,
        findings=[sample_finding],
    )


@pytest.fixture
def sample_hardware_fingerprint() -> HardwareFingerprint:
    """Return a sample HardwareFingerprint for testing."""
    return HardwareFingerprint(
        hostname="TEST-LAPTOP",
        system_manufacturer="Dell Inc.",
        system_model="Latitude 5540",
        system_serial="ABC1234",
        system_uuid="12345678-1234-1234-1234-123456789012",
        bios_version="1.15.0",
        bios_vendor="Dell Inc.",
        ec_version="1.5.0",
        secure_boot_enabled=True,
        tpm_version="2.0",
        tpm_manufacturer="Infineon",
        components=[
            HardwareComponent(
                component_type="CPU",
                manufacturer="Intel",
                model="Core i7-1365U",
                properties={"cores": 10, "threads": 12},
            ),
            HardwareComponent(
                component_type="RAM",
                manufacturer="Samsung",
                model="M471A2G43BB2-CWE",
                serial_number="12345678",
                properties={"capacity_gb": 16, "speed_mhz": 3200, "type": "DDR4"},
            ),
        ],
    )
