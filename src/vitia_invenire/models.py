"""Core Pydantic models for Vitia Invenire."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


class Category(str, Enum):
    HARDWARE = "Hardware"
    FIRMWARE = "Firmware"
    BINARY_INTEGRITY = "Binary Integrity"
    OEM_PREINSTALL = "OEM Pre-Installation"
    CERTIFICATES = "Certificates"
    PERSISTENCE = "Persistence"
    NETWORK = "Network"
    DRIVERS = "Drivers"
    SERVICES = "Services"
    ACCOUNTS = "Accounts"
    CONFIGURATION = "Configuration"
    MALWARE = "Malware"
    HARDENING = "Hardening"
    EVASION = "Defense Evasion"
    REMOTE_ACCESS = "Remote Access"
    PATCHING = "Patch Management"
    POLICY = "Security Policy"
    META = "Meta"


CATEGORY_ORDER = {cat: i for i, cat in enumerate(Category)}


class SystemInfo(BaseModel):
    """System information matching Windows Settings > System > About."""
    hostname: str = ""
    os_product_name: str = ""  # e.g. "Windows 11 Pro"
    os_display_version: str = ""  # e.g. "25H2"
    os_build: str = ""  # e.g. "26200.7840"
    os_edition_id: str = ""
    system_type: str = ""  # e.g. "x64-based PC"
    device_id: str = ""
    product_id: str = ""
    processor_name: str = ""
    processor_cores: int = 0
    processor_logical: int = 0
    installed_ram_gb: float = 0.0
    experience_pack: str = ""


class Finding(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    check_id: str
    title: str
    description: str
    severity: Severity
    category: Category
    affected_item: str
    evidence: str
    recommendation: str
    references: list[str] = Field(default_factory=list)
    cvss_vector: str | None = None
    cvss_score: float | None = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    false_positive: bool = False


class CheckResult(BaseModel):
    check_id: str
    check_name: str
    category: Category
    status: str  # "passed", "failed", "error", "skipped"
    duration_seconds: float = 0.0
    findings: list[Finding] = Field(default_factory=list)
    context: dict = Field(default_factory=dict)
    error_message: str | None = None


class HardwareComponent(BaseModel):
    component_type: str
    manufacturer: str
    model: str
    serial_number: str | None = None
    firmware_version: str | None = None
    driver_version: str | None = None
    driver_signer: str | None = None
    pnp_device_id: str | None = None
    properties: dict = Field(default_factory=dict)


class HardwareFingerprint(BaseModel):
    hostname: str
    system_manufacturer: str
    system_model: str
    system_serial: str
    system_uuid: str
    bios_version: str
    bios_vendor: str
    ec_version: str | None = None
    secure_boot_enabled: bool | None = None
    tpm_version: str | None = None
    tpm_manufacturer: str | None = None
    components: list[HardwareComponent] = Field(default_factory=list)
    smbios_raw: dict | None = None


class BinaryAnalysis(BaseModel):
    file_path: str
    file_size: int
    sha256: str
    sha1: str | None = None
    md5: str | None = None
    imphash: str | None = None
    is_signed: bool
    signature_valid: bool | None = None
    signer: str | None = None
    signature_timestamp: str | None = None
    max_entropy: float = 0.0
    suspicious_imports: list[str] = Field(default_factory=list)
    is_packed: bool = False
    nsrl_known: bool | None = None
    vt_detections: int | None = None


class AssessmentReport(BaseModel):
    report_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    hostname: str
    os_version: str
    scan_start: datetime
    scan_end: datetime
    system_info: SystemInfo | None = None
    hardware_fingerprint: HardwareFingerprint | None = None
    binary_analysis_summary: dict | None = None
    results: list[CheckResult] = Field(default_factory=list)
    summary: dict = Field(default_factory=dict)

    def compute_summary(self) -> dict:
        """Compute finding counts by severity."""
        counts: dict[str, int] = {s.value: 0 for s in Severity}
        for result in self.results:
            for finding in result.findings:
                counts[finding.severity.value] += 1
        self.summary = counts
        return counts

    def has_critical_findings(self) -> bool:
        return self.summary.get(Severity.CRITICAL.value, 0) > 0
