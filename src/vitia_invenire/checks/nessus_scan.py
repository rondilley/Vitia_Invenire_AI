"""NESSUS-001: Nessus REST API integration via pyTenable."""

from __future__ import annotations

import time

from vitia_invenire.checks.base import BaseCheck
from vitia_invenire.models import Category, Finding, Severity


class NessusScanCheck(BaseCheck):
    CHECK_ID = "NESSUS-001"
    NAME = "Nessus Vulnerability Scan"
    DESCRIPTION = "Nessus credentialed local scan via pyTenable REST API"
    CATEGORY = Category.HARDENING
    REQUIRES_ADMIN = True

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        # Try to import pyTenable
        try:
            from tenable.nessus import Nessus
        except ImportError:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="pyTenable not installed",
                description="The pyTenable library is required for Nessus integration.",
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="Python package: pyTenable",
                evidence="ImportError: tenable.nessus",
                recommendation="Install pyTenable: pip install pyTenable",
                references=["https://pytenable.readthedocs.io/"],
            ))
            return findings

        # Load Nessus configuration
        from vitia_invenire.config import Config
        config = Config.from_defaults()
        nessus_config = config.get_check_config("NESSUS-001")

        host = nessus_config.get("host", "localhost")
        port = nessus_config.get("port", 8834)
        access_key = nessus_config.get("access_key")
        secret_key = nessus_config.get("secret_key")
        scan_timeout = nessus_config.get("scan_timeout", 3600)

        if not access_key or not secret_key:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Nessus API credentials not configured",
                description="Nessus access_key and secret_key must be set in the configuration file.",
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="Configuration: NESSUS-001",
                evidence="access_key or secret_key is null in config",
                recommendation="Add Nessus API credentials to check_config.yaml under NESSUS-001",
            ))
            return findings

        # Connect to Nessus
        try:
            nessus = Nessus(
                host=host,
                port=port,
                access_key=access_key,
                secret_key=secret_key,
                ssl_verify=False,
            )
        except Exception as exc:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Cannot connect to Nessus",
                description=f"Failed to connect to Nessus at {host}:{port}",
                severity=Severity.LOW,
                category=self.CATEGORY,
                affected_item=f"Nessus at {host}:{port}",
                evidence=f"{type(exc).__name__}: {exc}",
                recommendation="Verify Nessus is running and API credentials are correct",
            ))
            return findings

        # Create and launch scan
        try:
            scan = nessus.scans.create(
                name="Vitia Invenire Local Assessment",
                targets="127.0.0.1",
                template="advanced",
            )
            scan_id = scan["id"]
            nessus.scans.launch(scan_id)
        except Exception as exc:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Failed to create Nessus scan",
                description=f"Could not create or launch Nessus scan: {exc}",
                severity=Severity.LOW,
                category=self.CATEGORY,
                affected_item="Nessus scan creation",
                evidence=f"{type(exc).__name__}: {exc}",
                recommendation="Check Nessus license, scan policies, and API permissions",
            ))
            return findings

        # Wait for scan completion
        start_wait = time.monotonic()
        scan_complete = False
        while time.monotonic() - start_wait < scan_timeout:
            try:
                status_info = nessus.scans.status(scan_id)
                if hasattr(status_info, "status"):
                    scan_status = status_info.status
                else:
                    scan_status = str(status_info)
                if scan_status in ("completed", "imported"):
                    scan_complete = True
                    break
                if scan_status in ("canceled", "aborted"):
                    break
            except Exception:
                break
            time.sleep(15)

        if not scan_complete:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Nessus scan did not complete",
                description=f"Scan timed out after {scan_timeout}s or was aborted.",
                severity=Severity.LOW,
                category=self.CATEGORY,
                affected_item=f"Nessus scan ID: {scan_id}",
                evidence=f"Scan did not reach 'completed' status within {scan_timeout}s",
                recommendation="Check Nessus web interface for scan status and errors",
            ))
            return findings

        # Retrieve and convert results
        try:
            vulns = nessus.scans.results(scan_id)
            if hasattr(vulns, "vulnerabilities"):
                vuln_list = vulns.vulnerabilities
            else:
                vuln_list = vulns if isinstance(vulns, list) else []

            for vuln in vuln_list:
                plugin_name = getattr(vuln, "plugin_name", str(vuln.get("plugin_name", "Unknown"))) if isinstance(vuln, dict) else getattr(vuln, "plugin_name", "Unknown")
                nessus_severity = getattr(vuln, "severity", vuln.get("severity", 0) if isinstance(vuln, dict) else 0)
                plugin_id = getattr(vuln, "plugin_id", vuln.get("plugin_id", "N/A") if isinstance(vuln, dict) else "N/A")

                # Map Nessus severity (0-4) to our severity
                sev_map = {0: Severity.INFO, 1: Severity.LOW, 2: Severity.MEDIUM, 3: Severity.HIGH, 4: Severity.CRITICAL}
                severity = sev_map.get(int(nessus_severity), Severity.INFO)

                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title=f"Nessus: {plugin_name}",
                    description=f"Nessus plugin {plugin_id} detected a vulnerability.",
                    severity=severity,
                    category=self.CATEGORY,
                    affected_item="127.0.0.1",
                    evidence=f"Plugin: {plugin_id}, Name: {plugin_name}, Severity: {nessus_severity}",
                    recommendation="See Nessus plugin details for remediation guidance",
                    references=[f"https://www.tenable.com/plugins/nessus/{plugin_id}"],
                ))
        except Exception as exc:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Failed to retrieve Nessus results",
                description=f"Error retrieving scan results: {exc}",
                severity=Severity.LOW,
                category=self.CATEGORY,
                affected_item=f"Nessus scan ID: {scan_id}",
                evidence=f"{type(exc).__name__}: {exc}",
                recommendation="Retrieve results manually from Nessus web interface",
            ))

        return findings
