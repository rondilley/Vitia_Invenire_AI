"""NMAP-001: Local port scan with service detection and vulnerability scripts."""

from __future__ import annotations

from vitia_invenire.checks.base import BaseCheck
from vitia_invenire.collectors.command import run_cmd
from vitia_invenire.models import Category, Finding, Severity


class NmapScanCheck(BaseCheck):
    CHECK_ID = "NMAP-001"
    NAME = "Nmap Local Scan"
    DESCRIPTION = "Local port scan with service detection and vulnerability NSE scripts"
    CATEGORY = Category.HARDENING
    REQUIRES_TOOLS = ["nmap"]

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        # Run nmap with service detection and key vulnerability scripts
        nmap_args = [
            "nmap", "-sV", "-sC",
            "--script", "smb-vuln-ms17-010,smb-security-mode,ssl-cert,smb2-security-mode",
            "-oN", "-",  # normal output to stdout
            "--open",  # only show open ports
            "-T4",  # aggressive timing
            "127.0.0.1",
        ]

        result = run_cmd(nmap_args, timeout=300)

        if not result.success:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Nmap scan failed",
                description=f"Nmap execution failed: {result.stderr}",
                severity=Severity.LOW,
                category=self.CATEGORY,
                affected_item="nmap localhost scan",
                evidence=result.stderr[:500],
                recommendation="Verify nmap is installed and accessible",
            ))
            return findings

        output = result.stdout
        open_ports: list[str] = []
        vuln_findings: list[str] = []

        for line in output.splitlines():
            stripped = line.strip()

            # Parse open port lines (format: "PORT/PROTO STATE SERVICE VERSION")
            if "/tcp" in stripped and "open" in stripped:
                open_ports.append(stripped)
            elif "/udp" in stripped and "open" in stripped:
                open_ports.append(stripped)

            # Parse vulnerability script results
            if "VULNERABLE" in stripped.upper():
                vuln_findings.append(stripped)
            elif "smb-vuln-ms17-010" in stripped and "State:" in stripped:
                vuln_findings.append(stripped)

        # Report open ports
        if open_ports:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title=f"Open ports detected: {len(open_ports)} port(s)",
                description="Nmap detected open listening ports on the local system.",
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="127.0.0.1",
                evidence="\n".join(open_ports),
                recommendation="Review open ports and disable unnecessary services",
            ))

            # Flag specific high-risk ports
            high_risk_ports = {"445", "139", "3389", "5985", "5986", "22"}
            for port_line in open_ports:
                port_num = port_line.split("/")[0].strip()
                if port_num in high_risk_ports:
                    findings.append(Finding(
                        check_id=self.CHECK_ID,
                        title=f"High-risk port open: {port_num}",
                        description=f"Port {port_num} is open and represents an elevated attack surface.",
                        severity=Severity.MEDIUM,
                        category=self.CATEGORY,
                        affected_item=f"127.0.0.1:{port_num}",
                        evidence=port_line,
                        recommendation=f"Evaluate if port {port_num} needs to be open. Disable the associated service if not required.",
                    ))

        # Report vulnerabilities
        for vuln in vuln_findings:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Nmap vulnerability detected",
                description="Nmap NSE script detected a potential vulnerability.",
                severity=Severity.HIGH,
                category=self.CATEGORY,
                affected_item="127.0.0.1",
                evidence=vuln,
                recommendation="Investigate and remediate the identified vulnerability. Apply relevant patches.",
                references=["https://nmap.org/nsedoc/"],
            ))

        if not open_ports and not vuln_findings:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="No open ports detected",
                description="Nmap found no open ports on the local system.",
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="127.0.0.1",
                evidence="Nmap scan completed with no open ports found",
                recommendation="No action needed",
            ))

        return findings
