"""BROWSER-001: Browser Security Configuration Audit.

Checks the default browser setting and inspects Group Policy registry
entries for forced browser extensions in Chrome, Edge, Firefox, and
Brave. Force-installed extensions can be used for credential theft,
data exfiltration, and browser-based persistence.
"""

from __future__ import annotations

from vitia_invenire.checks.base import BaseCheck
from vitia_invenire.collectors import registry
from vitia_invenire.collectors.powershell import run_ps
from vitia_invenire.models import Category, Finding, Severity

# Extension force-install registry paths for each browser
_EXTENSION_POLICIES: dict[str, list[str]] = {
    "Google Chrome": [
        "SOFTWARE\\Policies\\Google\\Chrome\\ExtensionInstallForcelist",
        "SOFTWARE\\Policies\\Google\\Chrome\\ExtensionInstallAllowlist",
    ],
    "Microsoft Edge": [
        "SOFTWARE\\Policies\\Microsoft\\Edge\\ExtensionInstallForcelist",
        "SOFTWARE\\Policies\\Microsoft\\Edge\\ExtensionInstallAllowlist",
    ],
    "Mozilla Firefox": [
        "SOFTWARE\\Policies\\Mozilla\\Firefox\\Extensions\\Install",
    ],
    "Brave": [
        "SOFTWARE\\Policies\\BraveSoftware\\Brave\\ExtensionInstallForcelist",
    ],
}

# Known legitimate extension IDs (Chrome Web Store format)
_KNOWN_EXTENSIONS: dict[str, str] = {
    "ghbmnnjooekpmoecnnnilnnbdlolhkhi": "Google Docs Offline",
    "nmmhkkegccagdldgiimedpiccmgmieda": "Chrome Web Store Payments",
    "aohghmighlieiainnegkcijnfilokake": "Google Docs",
    "aapocclcgogkmnckokdopfmhonfmgoek": "Google Slides",
    "felcaaldnbdncclmgdcncolpebgiejap": "Google Sheets",
    "cjpalhdlnbpafiamejdnhcphjbkeiagm": "uBlock Origin",
    "cfhdojbkjhnklbpkdaibdccddilifddb": "Adblock Plus",
    "gighmmpiobklfepjocnamgkkbiglidom": "AdBlock",
    "hdokiejnpimakedhajhdlcegeplioahd": "LastPass",
    "nngceckbapebfimnlniiiahkandclblb": "Bitwarden",
    "oboonakemofpalcgghocfoadofidjkkk": "KeePassXC-Browser",
    "bkdgflcldnnnapblkhphbgpggdiikppg": "DuckDuckGo Privacy Essentials",
    "gcbommkclmhbdlidjoijfklkkkgfpppp": "Microsoft Outlook",
}


class BrowserAuditCheck(BaseCheck):
    """Audit browser configuration and forced extensions."""

    CHECK_ID = "BROWSER-001"
    NAME = "Browser Security Audit"
    DESCRIPTION = (
        "Checks default browser configuration and inspects Group Policy "
        "registry entries for force-installed browser extensions in Chrome, "
        "Edge, Firefox, and Brave."
    )
    CATEGORY = Category.CONFIGURATION
    REQUIRES_ADMIN = False

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        # Get default browser
        default_browser_result = run_ps(
            "(Get-ItemProperty 'HKCU:\\SOFTWARE\\Microsoft\\Windows\\Shell\\Associations\\UrlAssociations\\https\\UserChoice' "
            "-ErrorAction SilentlyContinue).ProgId",
            timeout=10,
            as_json=False,
        )

        default_browser = "Unknown"
        if default_browser_result.success and default_browser_result.output:
            prog_id = default_browser_result.output.strip()
            browser_map = {
                "ChromeHTML": "Google Chrome",
                "MSEdgeHTM": "Microsoft Edge",
                "FirefoxURL": "Mozilla Firefox",
                "BraveHTML": "Brave Browser",
                "IE.HTTP": "Internet Explorer",
                "OperaStable": "Opera",
                "SafariHTML": "Safari",
                "AppXq0fevzme2pys62n3e0fbqa7peapykr8v": "Microsoft Edge (UWP)",
            }
            default_browser = browser_map.get(prog_id, prog_id)

        findings.append(Finding(
            check_id=self.CHECK_ID,
            title="Default Browser Identified",
            description=f"The default browser is set to {default_browser}.",
            severity=Severity.INFO,
            category=self.CATEGORY,
            affected_item="Default Browser",
            evidence=f"Default browser: {default_browser}",
            recommendation="Ensure the default browser is an up-to-date, supported browser.",
            references=[
                "https://attack.mitre.org/techniques/T1176/",
            ],
        ))

        # Check force-installed extensions for each browser
        total_unknown_extensions: list[dict[str, str]] = []
        all_forced_extensions: list[dict[str, str]] = []

        for browser_name, reg_paths in _EXTENSION_POLICIES.items():
            for reg_path in reg_paths:
                # Try HKLM first (machine-level policy)
                values = registry.read_key(
                    registry.HKEY_LOCAL_MACHINE, reg_path
                )

                # Also check HKCU for user-level policy
                hkcu_values = registry.read_key(
                    registry.HKEY_CURRENT_USER, reg_path
                )
                values.extend(hkcu_values)

                if not values:
                    continue

                for val in values:
                    if val.data is None:
                        continue

                    ext_data = str(val.data)
                    # Chrome/Edge force-install format: extensionid;update_url
                    # or just extensionid
                    ext_id = ext_data.split(";")[0].strip()
                    update_url = ""
                    if ";" in ext_data:
                        update_url = ext_data.split(";", 1)[1].strip()

                    is_known = ext_id.lower() in _KNOWN_EXTENSIONS
                    ext_name = _KNOWN_EXTENSIONS.get(ext_id.lower(), "Unknown Extension")

                    entry = {
                        "browser": browser_name,
                        "extension_id": ext_id,
                        "extension_name": ext_name,
                        "update_url": update_url,
                        "registry_path": reg_path,
                        "registry_name": val.name,
                    }

                    all_forced_extensions.append(entry)
                    if not is_known:
                        total_unknown_extensions.append(entry)

        # Report unknown forced extensions
        if total_unknown_extensions:
            evidence_lines = []
            for ext in total_unknown_extensions:
                evidence_lines.append(
                    f"Browser: {ext['browser']}\n"
                    f"  Extension ID: {ext['extension_id']}\n"
                    f"  Update URL: {ext['update_url'] or 'Default'}\n"
                    f"  Registry: HKLM\\{ext['registry_path']}"
                )
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Unknown Force-Installed Browser Extensions Detected",
                description=(
                    f"{len(total_unknown_extensions)} force-installed browser "
                    f"extension(s) are not in the known-legitimate extension "
                    f"list. Force-installed extensions can intercept web "
                    f"traffic, steal credentials, exfiltrate data, and "
                    f"establish persistence."
                ),
                severity=Severity.MEDIUM,
                category=self.CATEGORY,
                affected_item="Browser Extensions",
                evidence="\n\n".join(evidence_lines),
                recommendation=(
                    "Verify each forced extension is authorized and serves a "
                    "legitimate business purpose. Check the extension ID "
                    "against the Chrome Web Store or Edge Add-ons store. "
                    "Remove any unauthorized extensions from Group Policy."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1176/",
                ],
            ))

        # Summary of all forced extensions
        if all_forced_extensions:
            evidence_lines = []
            for ext in all_forced_extensions:
                status = "Known" if ext["extension_name"] != "Unknown Extension" else "UNKNOWN"
                evidence_lines.append(
                    f"  [{status}] {ext['browser']}: "
                    f"{ext['extension_name']} ({ext['extension_id']})"
                )
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Force-Installed Extensions Inventory",
                description=(
                    f"Found {len(all_forced_extensions)} force-installed "
                    f"extension(s) across all browsers via Group Policy."
                ),
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="Browser Extensions",
                evidence="\n".join(evidence_lines),
                recommendation="Review all forced extensions for legitimacy.",
                references=[
                    "https://attack.mitre.org/techniques/T1176/",
                ],
            ))

        # Check for extension developer mode
        chrome_dev_result = registry.read_value(
            registry.HKEY_LOCAL_MACHINE,
            "SOFTWARE\\Policies\\Google\\Chrome",
            "DeveloperToolsAvailability",
        )
        if chrome_dev_result and chrome_dev_result.data == 1:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Chrome Developer Tools Unrestricted",
                description=(
                    "Chrome Developer Tools are set to be available everywhere "
                    "including on force-installed extensions. This allows "
                    "inspection and potential manipulation of extension behavior."
                ),
                severity=Severity.LOW,
                category=self.CATEGORY,
                affected_item="Chrome Developer Tools Policy",
                evidence=f"DeveloperToolsAvailability: {chrome_dev_result.data}",
                recommendation=(
                    "Consider restricting developer tools availability in "
                    "production environments."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1176/",
                ],
            ))

        return findings
