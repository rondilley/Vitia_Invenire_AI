"""OEM-001: Query OEM activation and licensing method.

Queries OA3 product key from SoftwareLicensingService, checks
the activation method via slmgr. KMS activation pointed at a
non-corporate server is flagged as HIGH.
"""

from __future__ import annotations

import json
import re

from vitia_invenire.checks.base import BaseCheck
from vitia_invenire.collectors import registry, wmi_collector
from vitia_invenire.collectors.powershell import run_ps
from vitia_invenire.models import Category, Finding, Severity

# Well-known Microsoft KMS server FQDNs and internal naming patterns
_KNOWN_KMS_PATTERNS = [
    "kms.core.windows.net",
    "_vlmcs._tcp",
    "kms.domain",
    "kms.local",
    "kms.corp",
    "kms.internal",
]

# Known legitimate KMS port
_KMS_PORT = 1688


def _safe_str(value: object) -> str:
    if value is None:
        return "Unknown"
    return str(value)


class OemActivationCheck(BaseCheck):
    """Query OEM activation and licensing method."""

    CHECK_ID = "OEM-001"
    NAME = "OEM Activation and Licensing"
    DESCRIPTION = (
        "Query OA3 product key from SoftwareLicensingService, check "
        "activation method. Flag KMS activation to non-corporate "
        "server as HIGH."
    )
    CATEGORY = Category.OEM_PREINSTALL
    REQUIRES_ADMIN = False

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        # Query SoftwareLicensingService for licensing details
        license_info = self._query_licensing_service()
        activation_info = self._query_activation_status()
        oem_key_info = self._query_oem_product_key()

        # Combine evidence
        all_evidence: dict = {}
        all_evidence.update(license_info)
        all_evidence.update(activation_info)
        all_evidence.update(oem_key_info)

        # Determine activation method
        activation_method = license_info.get("activation_method", "Unknown")
        kms_server = license_info.get("kms_server", "")
        kms_port = license_info.get("kms_port", "")

        # Report OEM product key info
        oem_key = oem_key_info.get("oem_product_key", "")
        oem_desc = oem_key_info.get("oem_description", "")

        if oem_key:
            # Mask most of the key for security
            masked_key = oem_key[:5] + "-*****-*****-*****-" + oem_key[-5:] if len(oem_key) > 10 else "***masked***"
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="OA3 OEM Product Key Detected",
                description=(
                    f"An OEM Activation 3.0 (OA3) product key is embedded in "
                    f"the firmware/BIOS. Description: {oem_desc}"
                ),
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="OEM Product Key",
                evidence=f"Key (masked): {masked_key}\nDescription: {oem_desc}",
                recommendation=(
                    "OA3 keys are normal for OEM-installed Windows. Verify the "
                    "key matches the expected license type for this hardware."
                ),
                references=[
                    "https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/oem-activation-3",
                ],
            ))

        # Check KMS activation
        if "kms" in activation_method.lower():
            is_suspicious_kms = False
            kms_concern = ""

            if kms_server:
                kms_lower = kms_server.lower()

                # Check if the KMS server is a known/expected pattern
                is_known_pattern = False
                for pattern in _KNOWN_KMS_PATTERNS:
                    if pattern in kms_lower:
                        is_known_pattern = True
                        break

                # Check for obvious piracy indicators
                # Public IP addresses or suspicious domain names
                ip_pattern = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
                if ip_pattern.match(kms_server):
                    # External IP being used as KMS - suspicious
                    is_suspicious_kms = True
                    kms_concern = (
                        f"KMS server is a raw IP address ({kms_server}), not a "
                        f"corporate FQDN. This may indicate use of an unauthorized "
                        f"KMS emulator."
                    )
                elif not is_known_pattern:
                    # Check for suspicious domain indicators
                    suspicious_keywords = [
                        "crack", "pirat", "hack", "free", "activ",
                        "kmspico", "kmsauto", "vlmcsd",
                    ]
                    for keyword in suspicious_keywords:
                        if keyword in kms_lower:
                            is_suspicious_kms = True
                            kms_concern = (
                                f"KMS server name '{kms_server}' contains suspicious "
                                f"keyword '{keyword}', suggesting an unauthorized activator."
                            )
                            break

                    if not is_suspicious_kms and not is_known_pattern:
                        # Non-standard KMS server - worth noting
                        kms_concern = (
                            f"KMS server '{kms_server}' does not match common "
                            f"corporate KMS patterns. Verify this is a legitimate "
                            f"enterprise KMS server."
                        )

            if is_suspicious_kms:
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title="Suspicious KMS Activation Server",
                    description=(
                        f"Windows is activated via KMS using a suspicious server. "
                        f"{kms_concern} Unauthorized KMS emulators (KMSpico, "
                        f"KMSAuto, vlmcsd) are a common vector for malware "
                        f"distribution."
                    ),
                    severity=Severity.HIGH,
                    category=self.CATEGORY,
                    affected_item="Windows Activation",
                    evidence=json.dumps(all_evidence, indent=2, default=str),
                    recommendation=(
                        "Verify the KMS server is a legitimate corporate server. "
                        "If this is not an enterprise environment, the activation "
                        "may be pirated. KMS emulators often bundle trojans, "
                        "cryptocurrency miners, or other malware. Re-image the "
                        "system with a genuine Windows license."
                    ),
                    references=[
                        "https://attack.mitre.org/techniques/T1204/002/",
                        "https://learn.microsoft.com/en-us/windows-server/get-started/kms-create-host",
                    ],
                ))
            elif kms_concern:
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title="KMS Activation - Non-Standard Server",
                    description=kms_concern,
                    severity=Severity.MEDIUM,
                    category=self.CATEGORY,
                    affected_item="Windows Activation",
                    evidence=json.dumps(all_evidence, indent=2, default=str),
                    recommendation=(
                        "Confirm the KMS server is operated by your organization. "
                        "Document the KMS infrastructure for audit purposes."
                    ),
                    references=[
                        "https://learn.microsoft.com/en-us/windows-server/get-started/kms-create-host",
                    ],
                ))

        # General activation summary
        findings.append(Finding(
            check_id=self.CHECK_ID,
            title="Windows Activation Summary",
            description=(
                f"Activation method: {activation_method}. "
                f"License status collected from SoftwareLicensingService."
            ),
            severity=Severity.INFO,
            category=self.CATEGORY,
            affected_item="Windows License",
            evidence=json.dumps(all_evidence, indent=2, default=str),
            recommendation="Verify Windows activation matches expected licensing model.",
            references=[],
        ))

        return findings

    def _query_licensing_service(self) -> dict:
        """Query SoftwareLicensingService for activation details."""
        result: dict = {}

        rows = wmi_collector.query(
            "SoftwareLicensingService",
            properties=[
                "Version", "KeyManagementServiceMachine",
                "KeyManagementServicePort",
                "IsKeyManagementServiceMachine",
                "DiscoveredKeyManagementServiceMachineName",
                "DiscoveredKeyManagementServiceMachinePort",
                "KeyManagementServiceLookupDomain",
                "PolicyCacheRefreshRequired",
                "ClientMachineID",
                "OA3xOriginalProductKey",
            ],
        )

        for row in rows:
            kms_machine = row.get("KeyManagementServiceMachine") or row.get(
                "DiscoveredKeyManagementServiceMachineName"
            )
            kms_port = row.get("KeyManagementServicePort") or row.get(
                "DiscoveredKeyManagementServiceMachinePort"
            )

            if kms_machine:
                result["activation_method"] = "KMS"
                result["kms_server"] = _safe_str(kms_machine)
                result["kms_port"] = _safe_str(kms_port)
            else:
                result["activation_method"] = "Retail/OEM/Digital"

            result["service_version"] = _safe_str(row.get("Version"))
            result["is_kms_host"] = row.get("IsKeyManagementServiceMachine", False)
            result["client_machine_id"] = _safe_str(row.get("ClientMachineID"))

        return result

    def _query_activation_status(self) -> dict:
        """Query activation status via SoftwareLicensingProduct."""
        result: dict = {}

        rows = wmi_collector.query(
            "SoftwareLicensingProduct",
            properties=[
                "Name", "Description", "LicenseStatus",
                "GracePeriodRemaining", "PartialProductKey",
                "ProductKeyChannel",
            ],
            where="PartialProductKey IS NOT NULL",
        )

        for row in rows:
            license_status = row.get("LicenseStatus", -1)
            status_map = {
                0: "Unlicensed",
                1: "Licensed",
                2: "Out-Of-Box Grace Period",
                3: "Out-Of-Tolerance Grace Period",
                4: "Non-Genuine Grace Period",
                5: "Notification",
                6: "Extended Grace",
            }
            result["license_status"] = status_map.get(license_status, f"Unknown ({license_status})")
            result["license_status_code"] = license_status
            result["product_name"] = _safe_str(row.get("Name"))
            result["description"] = _safe_str(row.get("Description"))
            result["partial_key"] = _safe_str(row.get("PartialProductKey"))
            result["channel"] = _safe_str(row.get("ProductKeyChannel"))
            result["grace_remaining"] = row.get("GracePeriodRemaining", 0)

        return result

    def _query_oem_product_key(self) -> dict:
        """Query OA3 OEM product key from firmware."""
        result: dict = {}

        # Query via SoftwareLicensingService
        rows = wmi_collector.query(
            "SoftwareLicensingService",
            properties=["OA3xOriginalProductKey", "OA3xOriginalProductKeyDescription"],
        )

        for row in rows:
            key = row.get("OA3xOriginalProductKey")
            desc = row.get("OA3xOriginalProductKeyDescription")
            if key:
                result["oem_product_key"] = str(key)
                result["oem_description"] = _safe_str(desc)

        # Also check registry for product key
        reg_val = registry.read_value(
            registry.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform",
            "BackupProductKeyDefault",
        )
        if reg_val and reg_val.data:
            result["registry_backup_key"] = "present"

        return result
