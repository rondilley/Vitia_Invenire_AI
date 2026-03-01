"""CERT-001: Certificate store analysis.

Enumerates all root CAs in Cert:\\LocalMachine\\Root via PowerShell,
compares thumbprints against known-good and known-bad certificate
databases, and checks for weak key sizes.
"""

from __future__ import annotations

import importlib.resources
import json

from vitia_invenire.checks.base import BaseCheck
from vitia_invenire.collectors.powershell import run_ps
from vitia_invenire.models import Category, Finding, Severity


def _load_json_data(filename: str) -> list[dict]:
    """Load a JSON data file from the vitia_invenire.data package."""
    try:
        ref = importlib.resources.files("vitia_invenire.data").joinpath(filename)
        raw = ref.read_text(encoding="utf-8")
        data = json.loads(raw)
        if isinstance(data, list):
            return data
    except (FileNotFoundError, json.JSONDecodeError, TypeError, AttributeError):
        return []
    return []


def _build_known_good_set(entries: list[dict]) -> set[str]:
    """Build a set of uppercase thumbprints from known-good cert entries."""
    thumbprints: set[str] = set()
    for entry in entries:
        tp = entry.get("thumbprint", "")
        if tp:
            thumbprints.add(tp.upper().strip())
    return thumbprints


def _build_known_bad_map(entries: list[dict]) -> dict[str, dict]:
    """Build a map of uppercase thumbprint to bad cert metadata."""
    bad_map: dict[str, dict] = {}
    for entry in entries:
        tp = entry.get("thumbprint", "")
        if tp:
            bad_map[tp.upper().strip()] = entry
    return bad_map


class CertificateStoreCheck(BaseCheck):
    """Analyze the Windows certificate root store for supply chain risks."""

    CHECK_ID = "CERT-001"
    NAME = "Certificate Store Analysis"
    DESCRIPTION = (
        "Enumerates root CAs in the local machine certificate store, "
        "compares against known-good and known-bad certificate databases, "
        "and checks for weak cryptographic key sizes."
    )
    CATEGORY = Category.CERTIFICATES
    REQUIRES_ADMIN = False

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        known_good = _build_known_good_set(_load_json_data("known_good_certs.json"))
        known_bad = _build_known_bad_map(_load_json_data("known_bad_certs.json"))

        ps_command = (
            "Get-ChildItem Cert:\\LocalMachine\\Root | "
            "Select-Object Thumbprint, Subject, Issuer, NotBefore, NotAfter, "
            "@{N='KeyLength';E={$_.PublicKey.Key.KeySize}}, "
            "@{N='Algorithm';E={$_.PublicKey.Oid.FriendlyName}}"
        )
        result = run_ps(ps_command, timeout=30, as_json=True)

        if not result.success or result.json_output is None:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Failed to enumerate certificate store",
                description=f"PowerShell certificate enumeration failed: {result.error or 'unknown error'}",
                severity=Severity.MEDIUM,
                category=self.CATEGORY,
                affected_item="Cert:\\LocalMachine\\Root",
                evidence=result.output[:500] if result.output else "No output",
                recommendation="Verify PowerShell access to the certificate store.",
            ))
            return findings

        certs = result.json_output
        if isinstance(certs, dict):
            certs = [certs]

        # Capture full certificate state for baseline comparison
        self.context["state"] = [
            {
                "thumbprint": str(c.get("Thumbprint", "")).upper().strip(),
                "subject": str(c.get("Subject", "")),
                "algorithm": str(c.get("Algorithm", "")),
                "key_length": c.get("KeyLength"),
                "not_after": str(c.get("NotAfter", "")),
            }
            for c in certs
        ]

        total_certs = len(certs)
        unknown_count = 0
        bad_count = 0
        weak_count = 0

        for cert in certs:
            thumbprint = str(cert.get("Thumbprint", "")).upper().strip()
            subject = str(cert.get("Subject", "Unknown"))
            issuer = str(cert.get("Issuer", "Unknown"))
            key_length = cert.get("KeyLength")
            algorithm = str(cert.get("Algorithm", "Unknown"))
            not_before = str(cert.get("NotBefore", ""))
            not_after = str(cert.get("NotAfter", ""))

            cert_desc = f"Subject: {subject}, Issuer: {issuer}, Thumbprint: {thumbprint}"

            if thumbprint in known_bad:
                bad_info = known_bad[thumbprint]
                bad_count += 1
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title=f"Known-bad certificate detected: {bad_info.get('name', 'Unknown')}",
                    description=(
                        f"A certificate known to be malicious or compromised was found in the "
                        f"trusted root store. {bad_info.get('description', '')}"
                    ),
                    severity=Severity.CRITICAL,
                    category=self.CATEGORY,
                    affected_item=f"Cert:\\LocalMachine\\Root\\{thumbprint}",
                    evidence=(
                        f"{cert_desc}\n"
                        f"Known-bad name: {bad_info.get('name', 'N/A')}\n"
                        f"Valid: {not_before} to {not_after}"
                    ),
                    recommendation=(
                        "Remove this certificate immediately. Run: "
                        f"Remove-Item 'Cert:\\LocalMachine\\Root\\{thumbprint}' in an elevated PowerShell."
                    ),
                    references=[bad_info.get("reference", "")],
                ))
                continue

            if thumbprint and thumbprint not in known_good:
                unknown_count += 1
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title=f"Untrusted root CA not in known-good list",
                    description=(
                        "A root certificate authority was found that is not in the "
                        "Microsoft Trusted Root Program known-good list. This may indicate "
                        "a third-party or enterprise CA, or a supply chain compromise."
                    ),
                    severity=Severity.HIGH,
                    category=self.CATEGORY,
                    affected_item=f"Cert:\\LocalMachine\\Root\\{thumbprint}",
                    evidence=(
                        f"{cert_desc}\n"
                        f"Algorithm: {algorithm}, Key Length: {key_length}\n"
                        f"Valid: {not_before} to {not_after}"
                    ),
                    recommendation=(
                        "Investigate whether this certificate was intentionally installed. "
                        "Verify with IT/security whether this is an enterprise or partner CA. "
                        "If unknown, consider removal."
                    ),
                    references=[
                        "https://learn.microsoft.com/en-us/security/trusted-root/program-requirements",
                    ],
                ))

            if key_length is not None:
                try:
                    key_len_int = int(key_length)
                    if key_len_int > 0 and key_len_int < 2048:
                        weak_count += 1
                        findings.append(Finding(
                            check_id=self.CHECK_ID,
                            title=f"Root CA with weak key size ({key_len_int} bits)",
                            description=(
                                f"A root certificate authority has a {algorithm} key of only "
                                f"{key_len_int} bits, which is below the recommended minimum "
                                f"of 2048 bits for RSA keys."
                            ),
                            severity=Severity.MEDIUM,
                            category=self.CATEGORY,
                            affected_item=f"Cert:\\LocalMachine\\Root\\{thumbprint}",
                            evidence=(
                                f"{cert_desc}\n"
                                f"Algorithm: {algorithm}, Key Length: {key_len_int} bits\n"
                                f"Valid: {not_before} to {not_after}"
                            ),
                            recommendation=(
                                "Certificates with key sizes below 2048 bits are considered "
                                "cryptographically weak. Replace or remove if not required."
                            ),
                            references=[
                                "https://www.keylength.com/en/4/",
                            ],
                        ))
                except (ValueError, TypeError):
                    # Key length not parseable, skip weak key check for this cert
                    continue

        findings.append(Finding(
            check_id=self.CHECK_ID,
            title="Certificate store enumeration summary",
            description=(
                f"Enumerated {total_certs} root certificates. "
                f"Found {bad_count} known-bad, {unknown_count} unknown/untrusted, "
                f"and {weak_count} with weak key sizes."
            ),
            severity=Severity.INFO,
            category=self.CATEGORY,
            affected_item="Cert:\\LocalMachine\\Root",
            evidence=f"Total certificates: {total_certs}",
            recommendation="Review all non-standard root CAs periodically.",
        ))

        return findings
