"""Tests for Pydantic models -- validation, serialization, deserialization."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from vitia_invenire.models import (
    AssessmentReport,
    BinaryAnalysis,
    Category,
    CheckResult,
    Finding,
    HardwareComponent,
    HardwareFingerprint,
    Severity,
    SEVERITY_ORDER,
)


class TestSeverity:
    def test_severity_values(self):
        assert Severity.CRITICAL.value == "CRITICAL"
        assert Severity.HIGH.value == "HIGH"
        assert Severity.MEDIUM.value == "MEDIUM"
        assert Severity.LOW.value == "LOW"
        assert Severity.INFO.value == "INFO"

    def test_severity_ordering(self):
        assert SEVERITY_ORDER[Severity.CRITICAL] < SEVERITY_ORDER[Severity.HIGH]
        assert SEVERITY_ORDER[Severity.HIGH] < SEVERITY_ORDER[Severity.MEDIUM]
        assert SEVERITY_ORDER[Severity.MEDIUM] < SEVERITY_ORDER[Severity.LOW]
        assert SEVERITY_ORDER[Severity.LOW] < SEVERITY_ORDER[Severity.INFO]


class TestCategory:
    def test_category_values(self):
        assert Category.HARDWARE.value == "Hardware"
        assert Category.FIRMWARE.value == "Firmware"
        assert Category.CERTIFICATES.value == "Certificates"
        assert Category.META.value == "Meta"

    def test_all_categories_present(self):
        expected = {
            "Hardware", "Firmware", "Binary Integrity", "OEM Pre-Installation",
            "Certificates", "Persistence", "Network", "Drivers", "Services",
            "Accounts", "Configuration", "Malware", "Hardening", "Defense Evasion",
            "Remote Access", "Meta",
        }
        actual = {cat.value for cat in Category}
        assert actual == expected


class TestFinding:
    def test_finding_creation(self, sample_finding):
        assert sample_finding.check_id == "TEST-001"
        assert sample_finding.severity == Severity.HIGH
        assert sample_finding.false_positive is False
        assert sample_finding.id  # UUID should be auto-generated
        assert sample_finding.timestamp  # should be auto-set

    def test_finding_json_roundtrip(self, sample_finding):
        json_str = sample_finding.model_dump_json()
        data = json.loads(json_str)
        restored = Finding.model_validate(data)
        assert restored.check_id == sample_finding.check_id
        assert restored.severity == sample_finding.severity
        assert restored.title == sample_finding.title

    def test_finding_with_cvss(self):
        finding = Finding(
            check_id="CVE-001",
            title="CVE Finding",
            description="A finding with CVSS",
            severity=Severity.CRITICAL,
            category=Category.FIRMWARE,
            affected_item="BIOS",
            evidence="CVE-2023-12345",
            recommendation="Update firmware",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            cvss_score=9.8,
        )
        assert finding.cvss_score == 9.8
        assert finding.cvss_vector is not None


class TestCheckResult:
    def test_check_result_passed(self):
        result = CheckResult(
            check_id="TEST-001",
            check_name="Test Check",
            category=Category.CONFIGURATION,
            status="passed",
            duration_seconds=0.5,
        )
        assert result.status == "passed"
        assert len(result.findings) == 0
        assert result.error_message is None

    def test_check_result_failed_with_findings(self, sample_check_result):
        assert sample_check_result.status == "failed"
        assert len(sample_check_result.findings) == 1

    def test_check_result_skipped(self):
        result = CheckResult(
            check_id="TEST-002",
            check_name="Skipped Check",
            category=Category.FIRMWARE,
            status="skipped",
            error_message="Not running on Windows",
        )
        assert result.status == "skipped"
        assert result.error_message == "Not running on Windows"

    def test_check_result_json_roundtrip(self, sample_check_result):
        json_str = sample_check_result.model_dump_json()
        data = json.loads(json_str)
        restored = CheckResult.model_validate(data)
        assert restored.check_id == sample_check_result.check_id
        assert len(restored.findings) == len(sample_check_result.findings)


class TestHardwareModels:
    def test_hardware_component(self):
        comp = HardwareComponent(
            component_type="NIC",
            manufacturer="Intel",
            model="I219-V",
            firmware_version="0.8-4",
            driver_version="12.19.1.37",
            pnp_device_id="PCI\\VEN_8086&DEV_15BC",
            properties={"mac_address": "AA:BB:CC:DD:EE:FF"},
        )
        assert comp.component_type == "NIC"
        assert comp.properties["mac_address"] == "AA:BB:CC:DD:EE:FF"

    def test_hardware_fingerprint(self, sample_hardware_fingerprint):
        fp = sample_hardware_fingerprint
        assert fp.hostname == "TEST-LAPTOP"
        assert len(fp.components) == 2
        assert fp.components[0].component_type == "CPU"
        assert fp.secure_boot_enabled is True

    def test_hardware_fingerprint_json_roundtrip(self, sample_hardware_fingerprint):
        json_str = sample_hardware_fingerprint.model_dump_json()
        data = json.loads(json_str)
        restored = HardwareFingerprint.model_validate(data)
        assert restored.hostname == sample_hardware_fingerprint.hostname
        assert len(restored.components) == len(sample_hardware_fingerprint.components)


class TestBinaryAnalysis:
    def test_binary_analysis(self):
        ba = BinaryAnalysis(
            file_path="C:\\Windows\\System32\\ntoskrnl.exe",
            file_size=12345678,
            sha256="abcdef1234567890" * 4,
            is_signed=True,
            signature_valid=True,
            signer="Microsoft Windows",
            max_entropy=6.5,
            is_packed=False,
        )
        assert ba.is_signed is True
        assert ba.max_entropy == 6.5
        assert ba.is_packed is False


class TestAssessmentReport:
    def test_report_creation(self, sample_check_result):
        now = datetime.now(timezone.utc)
        report = AssessmentReport(
            hostname="TEST-HOST",
            os_version="Windows 11 Pro 23H2",
            scan_start=now,
            scan_end=now,
            results=[sample_check_result],
        )
        assert report.hostname == "TEST-HOST"
        assert len(report.results) == 1

    def test_compute_summary(self, sample_check_result):
        now = datetime.now(timezone.utc)
        report = AssessmentReport(
            hostname="TEST-HOST",
            os_version="Windows 11",
            scan_start=now,
            scan_end=now,
            results=[sample_check_result],
        )
        summary = report.compute_summary()
        assert summary["HIGH"] == 1
        assert summary["CRITICAL"] == 0
        assert summary["INFO"] == 0

    def test_has_critical_findings(self):
        now = datetime.now(timezone.utc)
        critical_finding = Finding(
            check_id="CRIT-001",
            title="Critical issue",
            description="Critical",
            severity=Severity.CRITICAL,
            category=Category.CERTIFICATES,
            affected_item="cert",
            evidence="bad cert",
            recommendation="Remove it",
        )
        result = CheckResult(
            check_id="CRIT-001",
            check_name="Critical Check",
            category=Category.CERTIFICATES,
            status="failed",
            findings=[critical_finding],
        )
        report = AssessmentReport(
            hostname="TEST",
            os_version="Win11",
            scan_start=now,
            scan_end=now,
            results=[result],
        )
        report.compute_summary()
        assert report.has_critical_findings() is True

    def test_full_json_roundtrip(self, sample_check_result, sample_hardware_fingerprint):
        now = datetime.now(timezone.utc)
        report = AssessmentReport(
            hostname="TEST-HOST",
            os_version="Windows 11 Pro 23H2",
            scan_start=now,
            scan_end=now,
            hardware_fingerprint=sample_hardware_fingerprint,
            results=[sample_check_result],
        )
        report.compute_summary()

        json_str = report.model_dump_json(indent=2)
        data = json.loads(json_str)
        restored = AssessmentReport.model_validate(data)

        assert restored.hostname == report.hostname
        assert restored.hardware_fingerprint is not None
        assert restored.hardware_fingerprint.hostname == "TEST-LAPTOP"
        assert len(restored.results) == 1
        assert restored.summary["HIGH"] == 1
