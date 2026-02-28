"""AMT-001: Intel AMT and Management Engine assessment.

Queries Intel Management Engine version via Win32_PnPSignedDriver,
checks AMT provisioning status via registry, and identifies known
vulnerable ME firmware versions.
"""

from __future__ import annotations

import re

from vitia_invenire.checks.base import BaseCheck
from vitia_invenire.collectors import registry, wmi_collector
from vitia_invenire.collectors.powershell import run_ps
from vitia_invenire.models import Category, Finding, Severity

# Known vulnerable Intel ME firmware version ranges.
# Format: list of (description, affected_versions_pattern, CVE references)
_VULNERABLE_ME_VERSIONS: list[tuple[str, list[str], list[str]]] = [
    (
        "SA-00086 - Multiple buffer overflows in ME/SPS/TXE",
        [
            "11.0.", "11.5.", "11.6.", "11.7.", "11.8.",
            "11.10.", "11.11.", "11.20.",
        ],
        [
            "CVE-2017-5705", "CVE-2017-5706", "CVE-2017-5707",
            "https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00086.html",
        ],
    ),
    (
        "SA-00112 - ME 11.x buffer overflow allowing local code execution",
        ["11.0.", "11.5.", "11.6.", "11.7.", "11.8.50"],
        [
            "CVE-2018-3627",
            "https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00112.html",
        ],
    ),
    (
        "SA-00125 - ME 11.x/12.x logic vulnerability",
        ["11.8.", "11.11.", "11.22.", "12.0."],
        [
            "CVE-2018-3628", "CVE-2018-3629", "CVE-2018-3632",
            "https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00125.html",
        ],
    ),
    (
        "SA-00213 - ME/CSME multiple vulnerabilities",
        ["11.8.", "11.11.", "11.22.", "12.0.", "13.0.", "14.0."],
        [
            "CVE-2019-11086", "CVE-2019-11087", "CVE-2019-11100",
            "https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00213.html",
        ],
    ),
    (
        "SA-00391 - CSME/SPS/TXE/AMT privilege escalation",
        ["11.8.", "11.12.", "11.22.", "12.0.", "13.0.", "13.30.", "14.0.", "14.5."],
        [
            "CVE-2020-8745", "CVE-2020-8744", "CVE-2020-8705",
            "https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00391.html",
        ],
    ),
]

# AMT provisioning states from Intel documentation
_PROVISIONING_STATES = {
    0: "Pre-provisioning",
    1: "In provisioning",
    2: "Post-provisioning (fully provisioned)",
}


class IntelAmtCheck(BaseCheck):
    """Assess Intel AMT and Management Engine security risks."""

    CHECK_ID = "AMT-001"
    NAME = "Intel AMT/ME Assessment"
    DESCRIPTION = (
        "Queries Intel Management Engine firmware version, checks AMT "
        "provisioning status, and identifies known vulnerable ME versions "
        "that could allow remote code execution or privilege escalation."
    )
    CATEGORY = Category.REMOTE_ACCESS
    REQUIRES_ADMIN = True

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        me_version = self._check_me_version(findings)
        self._check_amt_provisioning(findings)
        if me_version:
            self._check_vulnerable_versions(findings, me_version)

        return findings

    def _check_me_version(self, findings: list[Finding]) -> str | None:
        """Query Intel ME version via PnP signed driver enumeration."""
        me_rows = wmi_collector.query(
            "Win32_PnPSignedDriver",
            properties=[
                "DeviceName", "DriverVersion", "Manufacturer",
                "DeviceID", "DriverDate", "InfName", "IsSigned",
            ],
            where="DeviceName LIKE '%Management Engine%'",
        )

        if not me_rows:
            # Also try looking for "Intel(R) Management Engine" with the registered mark
            me_rows = wmi_collector.query(
                "Win32_PnPSignedDriver",
                properties=[
                    "DeviceName", "DriverVersion", "Manufacturer",
                    "DeviceID", "DriverDate", "InfName", "IsSigned",
                ],
                where="DeviceName LIKE '%ME Interface%'",
            )

        if not me_rows:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Intel Management Engine not detected",
                description=(
                    "No Intel Management Engine driver was found via WMI. "
                    "This system may use an AMD processor or ME may be disabled."
                ),
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="Intel Management Engine",
                evidence="No PnP signed driver matching 'Management Engine' or 'ME Interface' found",
                recommendation="If this is an Intel system, verify ME driver is properly installed.",
            ))
            return None

        me_version = None
        for row in me_rows:
            device_name = str(row.get("DeviceName", "Unknown"))
            driver_version = str(row.get("DriverVersion", "Unknown"))
            manufacturer = str(row.get("Manufacturer", "Unknown"))
            device_id = str(row.get("DeviceID", ""))
            is_signed = row.get("IsSigned", False)

            # Try to extract firmware version from driver version
            version_match = re.search(r"(\d+\.\d+\.\d+[\.\d]*)", driver_version)
            if version_match:
                me_version = version_match.group(1)

            findings.append(Finding(
                check_id=self.CHECK_ID,
                title=f"Intel Management Engine detected: {device_name}",
                description=(
                    f"Intel ME driver found. Driver version: {driver_version}, "
                    f"Manufacturer: {manufacturer}"
                ),
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item=device_name,
                evidence=(
                    f"Device: {device_name}\n"
                    f"Driver Version: {driver_version}\n"
                    f"Manufacturer: {manufacturer}\n"
                    f"Device ID: {device_id}\n"
                    f"Driver Signed: {is_signed}"
                ),
                recommendation="Keep Intel ME firmware and drivers up to date.",
                references=[
                    "https://www.intel.com/content/www/us/en/security-center/default.html",
                ],
            ))

        # Also try to get the actual firmware version via MEI
        fw_result = run_ps(
            "(Get-CimInstance -Namespace root\\Intel\\ME -ClassName ME_System "
            "-ErrorAction SilentlyContinue).FWVersion",
            timeout=15,
            as_json=False,
        )
        if fw_result.success and fw_result.output.strip():
            fw_ver = fw_result.output.strip()
            version_match = re.search(r"(\d+\.\d+\.\d+[\.\d]*)", fw_ver)
            if version_match:
                me_version = version_match.group(1)
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title=f"Intel ME firmware version: {me_version}",
                    description=f"ME firmware version obtained from CIM namespace: {fw_ver}",
                    severity=Severity.INFO,
                    category=self.CATEGORY,
                    affected_item="Intel ME Firmware",
                    evidence=f"FWVersion from root\\Intel\\ME: {fw_ver}",
                    recommendation="Compare against Intel security advisories.",
                ))

        return me_version

    def _check_amt_provisioning(self, findings: list[Finding]) -> None:
        """Check Intel AMT provisioning status via registry."""
        amt_path = r"SOFTWARE\Intel\AMT"

        # Check provisioning state
        prov_val = registry.read_value(
            registry.HKEY_LOCAL_MACHINE, amt_path, "ProvisioningState"
        )

        # Check if AMT is enabled
        enabled_val = registry.read_value(
            registry.HKEY_LOCAL_MACHINE, amt_path, "AMTEnabled"
        )

        # Check provisioning mode
        mode_val = registry.read_value(
            registry.HKEY_LOCAL_MACHINE, amt_path, "ProvisioningMode"
        )

        # Get all AMT registry values for evidence
        all_amt_values = registry.read_key(registry.HKEY_LOCAL_MACHINE, amt_path)

        if not all_amt_values and prov_val is None and enabled_val is None:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Intel AMT registry keys not found",
                description=(
                    "No Intel AMT configuration found in the registry. "
                    "AMT may not be configured on this system."
                ),
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item=f"HKLM\\{amt_path}",
                evidence="Registry key does not exist or is empty",
                recommendation="No action needed if AMT is not required.",
            ))
            return

        evidence_lines: list[str] = []
        for val in all_amt_values:
            evidence_lines.append(f"{val.name} = {val.data} (type {val.type})")

        evidence_text = "\n".join(evidence_lines) if evidence_lines else "No values"

        amt_enabled = False
        if enabled_val is not None:
            amt_enabled = bool(enabled_val.data)

        prov_state = -1
        if prov_val is not None:
            try:
                prov_state = int(prov_val.data)
            except (ValueError, TypeError):
                prov_state = -1

        prov_state_text = _PROVISIONING_STATES.get(prov_state, f"Unknown ({prov_state})")

        if amt_enabled and prov_state == 2:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Intel AMT is fully provisioned and enabled",
                description=(
                    "Intel Active Management Technology is enabled and fully provisioned. "
                    "AMT provides out-of-band remote management capabilities that operate "
                    "independently of the operating system. If not properly secured, this "
                    "represents a significant attack surface."
                ),
                severity=Severity.HIGH,
                category=self.CATEGORY,
                affected_item=f"HKLM\\{amt_path}",
                evidence=f"Provisioning State: {prov_state_text}\n{evidence_text}",
                recommendation=(
                    "Verify AMT is configured with strong credentials and TLS. "
                    "Disable AMT if not required for enterprise management. "
                    "Check that default credentials have been changed."
                ),
                references=[
                    "https://www.intel.com/content/www/us/en/architecture-and-technology/intel-active-management-technology.html",
                ],
            ))

            # Check for default credentials (port 16992/16993 AMT web interface)
            cred_result = run_ps(
                "try { "
                "$tcp = New-Object System.Net.Sockets.TcpClient; "
                "$tcp.Connect('127.0.0.1', 16992); "
                "$connected = $tcp.Connected; "
                "$tcp.Close(); "
                "@{Port=16992; Accessible=$connected} "
                "} catch { @{Port=16992; Accessible=$false} }",
                timeout=10,
                as_json=True,
            )
            if cred_result.success and cred_result.json_output:
                cred_data = cred_result.json_output
                if isinstance(cred_data, list):
                    cred_data = cred_data[0] if cred_data else {}
                if cred_data.get("Accessible"):
                    findings.append(Finding(
                        check_id=self.CHECK_ID,
                        title="AMT web interface accessible on port 16992",
                        description=(
                            "The Intel AMT web management interface is accessible on "
                            "port 16992. This port may accept default credentials (admin/admin) "
                            "if AMT was not properly provisioned."
                        ),
                        severity=Severity.CRITICAL,
                        category=self.CATEGORY,
                        affected_item="Intel AMT Web Interface (port 16992)",
                        evidence="TCP connection to 127.0.0.1:16992 succeeded",
                        recommendation=(
                            "Immediately change AMT credentials from defaults. "
                            "Configure TLS on AMT. If AMT is not needed, disable it in BIOS."
                        ),
                        references=[
                            "https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00075.html",
                        ],
                    ))
        elif amt_enabled:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title=f"Intel AMT is enabled (provisioning state: {prov_state_text})",
                description=(
                    f"Intel AMT is enabled but provisioning state is '{prov_state_text}'. "
                    "Review configuration to ensure proper security controls."
                ),
                severity=Severity.MEDIUM,
                category=self.CATEGORY,
                affected_item=f"HKLM\\{amt_path}",
                evidence=evidence_text,
                recommendation="Configure AMT with strong credentials or disable if not needed.",
            ))
        else:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Intel AMT is not enabled",
                description="Intel AMT registry keys exist but AMT is not enabled.",
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item=f"HKLM\\{amt_path}",
                evidence=evidence_text,
                recommendation="No action needed.",
            ))

    def _check_vulnerable_versions(self, findings: list[Finding], me_version: str) -> None:
        """Check the ME firmware version against known vulnerabilities."""
        for vuln_desc, affected_prefixes, references in _VULNERABLE_ME_VERSIONS:
            for prefix in affected_prefixes:
                if me_version.startswith(prefix):
                    findings.append(Finding(
                        check_id=self.CHECK_ID,
                        title=f"Intel ME version {me_version} affected by {vuln_desc}",
                        description=(
                            f"Intel Management Engine firmware version {me_version} is "
                            f"in the affected range for: {vuln_desc}. "
                            "These vulnerabilities may allow local or remote code execution "
                            "at the ME firmware level, which operates below the OS."
                        ),
                        severity=Severity.HIGH,
                        category=self.CATEGORY,
                        affected_item=f"Intel ME {me_version}",
                        evidence=f"ME Version: {me_version}, matched prefix: {prefix}",
                        recommendation=(
                            "Update Intel ME firmware to the latest version available from "
                            "your system manufacturer. Check Intel security advisories "
                            "for the specific patched version."
                        ),
                        references=references,
                    ))
                    break
