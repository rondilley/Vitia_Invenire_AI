"""BOOT-001: Boot configuration security assessment.

Runs bcdedit /enum to parse boot configuration entries and detect
dangerous settings like test signing, debug mode, disabled integrity
checks, and hypervisor launch type configuration.
"""

from __future__ import annotations

import re

from vitia_invenire.checks.base import BaseCheck
from vitia_invenire.collectors.command import run_cmd
from vitia_invenire.models import Category, Finding, Severity

# Boot configuration flags that indicate security risks
_DANGEROUS_SETTINGS: dict[str, tuple[str, str, Severity]] = {
    "testsigning": (
        "Test signing mode allows loading of unsigned or test-signed drivers. "
        "This bypasses driver signature enforcement and is commonly abused "
        "by rootkits and malicious drivers.",
        "Disable test signing: bcdedit /set testsigning off",
        Severity.HIGH,
    ),
    "debug": (
        "Kernel debugging mode enables low-level system debugging. "
        "An attacker with debug access can read and write arbitrary kernel "
        "memory, bypass security controls, and install rootkits.",
        "Disable debug mode: bcdedit /set debug off",
        Severity.HIGH,
    ),
    "nointegritychecks": (
        "Integrity checks are disabled. This allows loading of unsigned "
        "code and drivers, bypassing Code Integrity enforcement. "
        "Malware can load arbitrary kernel-mode code.",
        "Re-enable integrity checks: bcdedit /set nointegritychecks off",
        Severity.HIGH,
    ),
    "loadoptions": (
        "Custom boot load options are set. While not inherently dangerous, "
        "non-standard load options should be reviewed for potential abuse.",
        "Review load options and remove if not needed: bcdedit /deletevalue loadoptions",
        Severity.MEDIUM,
    ),
    "bootdebug": (
        "Boot debugger is enabled. This enables debugging of the boot process "
        "before the kernel loads, which can be used to tamper with early boot.",
        "Disable boot debug: bcdedit /set bootdebug off",
        Severity.HIGH,
    ),
}


def _parse_bcdedit_output(output: str) -> list[dict[str, str]]:
    """Parse bcdedit /enum output into a list of entry dictionaries.

    Each entry is separated by a line of dashes. Within an entry,
    each line has a key-value pair separated by whitespace.
    """
    entries: list[dict[str, str]] = []
    current: dict[str, str] = {}

    for line in output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue

        # Separator line between entries
        if re.match(r"^-{3,}$", stripped):
            if current:
                entries.append(current)
                current = {}
            continue

        # Key-value pair with at least two space separation
        match = re.match(r"^(\S+)\s{2,}(.+)$", stripped)
        if match:
            key = match.group(1).lower()
            value = match.group(2).strip()
            current[key] = value

    if current:
        entries.append(current)

    return entries


class BootConfigCheck(BaseCheck):
    """Analyze Windows boot configuration for security weaknesses."""

    CHECK_ID = "BOOT-001"
    NAME = "Boot Configuration Security"
    DESCRIPTION = (
        "Parses bcdedit output to detect dangerous boot settings including "
        "test signing, debug mode, disabled integrity checks, and "
        "hypervisor launch type configuration."
    )
    CATEGORY = Category.CONFIGURATION
    REQUIRES_ADMIN = True

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        result = run_cmd(["bcdedit", "/enum", "all"], timeout=30)

        if not result.success:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Failed to query boot configuration",
                description=(
                    f"bcdedit command failed. Error: {result.stderr[:500] if result.stderr else 'unknown'}. "
                    "This check requires administrator privileges."
                ),
                severity=Severity.MEDIUM,
                category=self.CATEGORY,
                affected_item="bcdedit",
                evidence=f"Return code: {result.return_code}, stderr: {result.stderr[:500] if result.stderr else 'none'}",
                recommendation="Run this assessment as Administrator.",
            ))
            return findings

        entries = _parse_bcdedit_output(result.stdout)

        if not entries:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="No boot configuration entries found",
                description="bcdedit returned no parseable entries.",
                severity=Severity.MEDIUM,
                category=self.CATEGORY,
                affected_item="bcdedit",
                evidence=f"Raw output length: {len(result.stdout)} characters",
                recommendation="Manually verify boot configuration via bcdedit /enum.",
            ))
            return findings

        # Process each BCD entry
        for entry in entries:
            identifier = entry.get("identifier", "unknown")
            description = entry.get("description", identifier)

            # Check for test signing
            testsigning = entry.get("testsigning", "").lower()
            if testsigning == "yes":
                desc_text, rec_text, sev = _DANGEROUS_SETTINGS["testsigning"]
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title=f"Test signing enabled in '{description}'",
                    description=desc_text,
                    severity=sev,
                    category=self.CATEGORY,
                    affected_item=f"BCD Entry: {identifier}",
                    evidence=f"testsigning = Yes\nEntry: {description}\nIdentifier: {identifier}",
                    recommendation=rec_text,
                    references=[
                        "https://learn.microsoft.com/en-us/windows-hardware/drivers/install/the-testsigning-boot-configuration-option",
                    ],
                ))

            # Check for debug mode
            debug_val = entry.get("debug", "").lower()
            if debug_val == "yes":
                desc_text, rec_text, sev = _DANGEROUS_SETTINGS["debug"]
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title=f"Debug mode enabled in '{description}'",
                    description=desc_text,
                    severity=sev,
                    category=self.CATEGORY,
                    affected_item=f"BCD Entry: {identifier}",
                    evidence=f"debug = Yes\nEntry: {description}\nIdentifier: {identifier}",
                    recommendation=rec_text,
                    references=[
                        "https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/bcdedit--debug",
                    ],
                ))

            # Check for boot debug
            bootdebug_val = entry.get("bootdebug", "").lower()
            if bootdebug_val == "yes":
                desc_text, rec_text, sev = _DANGEROUS_SETTINGS["bootdebug"]
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title=f"Boot debugger enabled in '{description}'",
                    description=desc_text,
                    severity=sev,
                    category=self.CATEGORY,
                    affected_item=f"BCD Entry: {identifier}",
                    evidence=f"bootdebug = Yes\nEntry: {description}\nIdentifier: {identifier}",
                    recommendation=rec_text,
                ))

            # Check for nointegritychecks
            nointegrity = entry.get("nointegritychecks", "").lower()
            if nointegrity == "yes":
                desc_text, rec_text, sev = _DANGEROUS_SETTINGS["nointegritychecks"]
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title=f"Integrity checks disabled in '{description}'",
                    description=desc_text,
                    severity=sev,
                    category=self.CATEGORY,
                    affected_item=f"BCD Entry: {identifier}",
                    evidence=f"nointegritychecks = Yes\nEntry: {description}\nIdentifier: {identifier}",
                    recommendation=rec_text,
                    references=[
                        "https://learn.microsoft.com/en-us/windows-hardware/drivers/install/kernel-mode-code-signing-policy--windows-vista-and-later-",
                    ],
                ))

            # Check hypervisor launch type
            hvl = entry.get("hypervisorlaunchtype", "").lower()
            if hvl:
                if hvl == "off":
                    findings.append(Finding(
                        check_id=self.CHECK_ID,
                        title=f"Hypervisor launch type is OFF in '{description}'",
                        description=(
                            "The hypervisor is configured not to launch. This disables "
                            "Hyper-V, Credential Guard, Device Guard, and other "
                            "virtualization-based security features."
                        ),
                        severity=Severity.MEDIUM,
                        category=self.CATEGORY,
                        affected_item=f"BCD Entry: {identifier}",
                        evidence=f"hypervisorlaunchtype = {hvl}\nEntry: {description}",
                        recommendation=(
                            "Enable the hypervisor if VBS/Credential Guard is needed: "
                            "bcdedit /set hypervisorlaunchtype auto"
                        ),
                    ))
                elif hvl == "auto":
                    findings.append(Finding(
                        check_id=self.CHECK_ID,
                        title=f"Hypervisor launch type is Auto in '{description}'",
                        description="The hypervisor is configured to launch automatically, enabling VBS.",
                        severity=Severity.INFO,
                        category=self.CATEGORY,
                        affected_item=f"BCD Entry: {identifier}",
                        evidence=f"hypervisorlaunchtype = {hvl}\nEntry: {description}",
                        recommendation="No action needed. Hypervisor is properly configured.",
                    ))

            # Check for custom load options
            loadoptions = entry.get("loadoptions", "")
            if loadoptions:
                # Check for known suspicious load options
                suspicious_opts = ["DISABLE_INTEGRITY_CHECKS", "DDISABLE_INTEGRITY_CHECKS",
                                   "ENABLE_KERNEL_DEBUGGING", "TESTSIGNING"]
                is_suspicious = any(
                    opt.upper() in loadoptions.upper() for opt in suspicious_opts
                )
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title=f"Custom load options found in '{description}'",
                    description=(
                        "Custom boot load options are configured. "
                        f"{'Suspicious options detected.' if is_suspicious else 'Review for legitimacy.'}"
                    ),
                    severity=Severity.HIGH if is_suspicious else Severity.MEDIUM,
                    category=self.CATEGORY,
                    affected_item=f"BCD Entry: {identifier}",
                    evidence=f"loadoptions = {loadoptions}\nEntry: {description}",
                    recommendation="Remove custom load options if not required: bcdedit /deletevalue loadoptions",
                ))

        # Summary finding
        findings.append(Finding(
            check_id=self.CHECK_ID,
            title="Boot configuration enumeration complete",
            description=f"Parsed {len(entries)} BCD entries from bcdedit output.",
            severity=Severity.INFO,
            category=self.CATEGORY,
            affected_item="bcdedit",
            evidence=f"Total BCD entries: {len(entries)}",
            recommendation="Regularly review boot configuration for unauthorized changes.",
        ))

        return findings
