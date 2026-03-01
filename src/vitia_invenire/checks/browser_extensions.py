"""EXT-001: Browser Extension Audit.

Enumerates installed browser extensions for Chrome, Edge, and Firefox across
all user profiles on the system. Cross-references extension IDs against a
known-malicious extensions database, flags sideloaded extensions not from
official web stores, and analyzes extension permissions for excessive access.
"""

from __future__ import annotations

import json
import os
from importlib import resources
from pathlib import Path

from vitia_invenire.checks.base import BaseCheck
from vitia_invenire.models import Category, Finding, Severity

# Chrome/Edge permissions considered dangerous for supply chain risk
_DANGEROUS_PERMISSIONS: set[str] = {
    "<all_urls>",
    "*://*/*",
    "webRequest",
    "webRequestBlocking",
    "cookies",
    "tabs",
    "management",
    "nativeMessaging",
    "debugger",
    "proxy",
}

# Threshold for excessive permissions finding
_EXCESSIVE_PERMISSION_THRESHOLD = 3

# Official web store update URLs
_OFFICIAL_UPDATE_URLS: list[str] = [
    "chrome.google.com/webstore",
    "clients2.google.com/service/update2/crx",
    "edge.microsoft.com",
    "microsoftedge.microsoft.com",
]


def _load_known_malicious() -> dict[str, dict]:
    """Load known malicious extensions from package data.

    Returns a dict mapping extension ID to its metadata entry.
    """
    try:
        ref = resources.files("vitia_invenire.data").joinpath(
            "known_malicious_extensions.json"
        )
        raw = ref.read_text(encoding="utf-8")
        data = json.loads(raw)
    except (FileNotFoundError, json.JSONDecodeError, TypeError, AttributeError):
        return {}

    result: dict[str, dict] = {}
    extensions = data.get("extensions", [])
    if not isinstance(extensions, list):
        return result
    for entry in extensions:
        ext_id = entry.get("id", "")
        if ext_id:
            result[ext_id.lower().strip()] = entry
    return result


def _get_users_dir() -> str:
    """Return the path to the Users directory."""
    system_drive = os.path.expandvars("%SYSTEMDRIVE%")
    if system_drive and system_drive != "%SYSTEMDRIVE%":
        return os.path.join(system_drive, "Users")
    return "C:\\Users"


def _enumerate_user_profiles(users_dir: str) -> list[str]:
    """Enumerate user profile directories, skipping system profiles."""
    skip_dirs = {"Public", "Default", "Default User", "All Users", "desktop.ini"}
    profiles: list[str] = []
    try:
        entries = os.listdir(users_dir)
    except OSError:
        return profiles
    for entry in entries:
        if entry in skip_dirs:
            continue
        full_path = os.path.join(users_dir, entry)
        try:
            if os.path.isdir(full_path):
                profiles.append(full_path)
        except OSError:
            continue
    return profiles


def _find_highest_version_dir(ext_dir: str) -> str | None:
    """Find the highest version subdirectory inside a Chrome/Edge extension directory.

    Extension directories contain one or more version subdirectories (e.g., 1.0.0_0).
    Returns the path to the subdirectory that sorts highest alphabetically,
    which approximates the latest version.
    """
    try:
        subdirs = [
            d for d in os.listdir(ext_dir)
            if os.path.isdir(os.path.join(ext_dir, d))
        ]
    except OSError:
        return None
    if not subdirs:
        return None
    # Sort version directories and take the last (highest) one
    subdirs.sort()
    return os.path.join(ext_dir, subdirs[-1])


def _read_manifest(manifest_path: str) -> dict | None:
    """Read and parse a Chrome/Edge extension manifest.json file."""
    try:
        with open(manifest_path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return None


def _collect_chromium_extensions(
    profile_path: str, browser_name: str, browser_data_dir: str
) -> list[dict]:
    """Collect extensions from a Chromium-based browser (Chrome or Edge).

    Scans both the Default profile and numbered Profile directories.
    """
    extensions: list[dict] = []
    user_data_path = os.path.join(profile_path, browser_data_dir)

    # Determine which browser profile directories to scan
    profile_dirs: list[str] = []

    default_path = os.path.join(user_data_path, "Default", "Extensions")
    if os.path.isdir(default_path):
        profile_dirs.append(default_path)

    # Check for additional numbered profiles (Profile 1, Profile 2, etc.)
    try:
        if os.path.isdir(user_data_path):
            for entry in os.listdir(user_data_path):
                if entry.startswith("Profile "):
                    numbered_ext_path = os.path.join(
                        user_data_path, entry, "Extensions"
                    )
                    if os.path.isdir(numbered_ext_path):
                        profile_dirs.append(numbered_ext_path)
    except OSError:
        pass

    for ext_root in profile_dirs:
        try:
            ext_ids = os.listdir(ext_root)
        except OSError:
            continue

        for ext_id in ext_ids:
            ext_dir = os.path.join(ext_root, ext_id)
            try:
                if not os.path.isdir(ext_dir):
                    continue
            except OSError:
                continue

            version_dir = _find_highest_version_dir(ext_dir)
            if version_dir is None:
                continue

            manifest_path = os.path.join(version_dir, "manifest.json")
            manifest = _read_manifest(manifest_path)
            if manifest is None:
                continue

            # Extract permissions from both manifest v2 and v3 formats
            permissions: list[str] = []
            raw_permissions = manifest.get("permissions", [])
            if isinstance(raw_permissions, list):
                permissions.extend(str(p) for p in raw_permissions)
            optional_perms = manifest.get("optional_permissions", [])
            if isinstance(optional_perms, list):
                permissions.extend(str(p) for p in optional_perms)
            # Manifest v3 host_permissions
            host_perms = manifest.get("host_permissions", [])
            if isinstance(host_perms, list):
                permissions.extend(str(p) for p in host_perms)

            update_url = manifest.get("update_url", "")
            if not isinstance(update_url, str):
                update_url = ""

            extensions.append({
                "browser": browser_name,
                "extension_id": ext_id,
                "name": str(manifest.get("name", "Unknown")),
                "version": str(manifest.get("version", "Unknown")),
                "description": str(manifest.get("description", "")),
                "permissions": permissions,
                "update_url": update_url,
                "manifest_path": manifest_path,
                "user_profile": profile_path,
            })

    return extensions


def _collect_firefox_extensions(profile_path: str) -> list[dict]:
    """Collect extensions from Firefox browser profiles.

    Firefox stores extension metadata in a single extensions.json file
    per browser profile.
    """
    extensions: list[dict] = []
    firefox_profiles_dir = os.path.join(
        profile_path, "AppData", "Roaming", "Mozilla", "Firefox", "Profiles"
    )

    try:
        if not os.path.isdir(firefox_profiles_dir):
            return extensions
    except OSError:
        return extensions

    try:
        ff_profiles = os.listdir(firefox_profiles_dir)
    except OSError:
        return extensions

    for ff_profile in ff_profiles:
        extensions_json_path = os.path.join(
            firefox_profiles_dir, ff_profile, "extensions.json"
        )

        try:
            if not os.path.isfile(extensions_json_path):
                continue
        except OSError:
            continue

        try:
            with open(extensions_json_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError, UnicodeDecodeError):
            continue

        addons = data.get("addons", [])
        if not isinstance(addons, list):
            continue

        for addon in addons:
            addon_id = str(addon.get("id", ""))
            if not addon_id:
                continue

            # Extract permissions from Firefox addon data
            permissions: list[str] = []
            raw_perms = addon.get("permissions", [])
            if isinstance(raw_perms, list):
                permissions.extend(str(p) for p in raw_perms)
            user_perms = addon.get("userPermissions", {})
            if isinstance(user_perms, dict):
                perm_list = user_perms.get("permissions", [])
                if isinstance(perm_list, list):
                    permissions.extend(str(p) for p in perm_list)
                origin_list = user_perms.get("origins", [])
                if isinstance(origin_list, list):
                    permissions.extend(str(p) for p in origin_list)

            extensions.append({
                "browser": "Firefox",
                "extension_id": addon_id,
                "name": str(addon.get("name", "Unknown")),
                "version": str(addon.get("version", "Unknown")),
                "description": str(addon.get("description", "")),
                "permissions": permissions,
                "type": str(addon.get("type", "")),
                "update_url": "",
                "manifest_path": extensions_json_path,
                "user_profile": profile_path,
            })

    return extensions


def _is_sideloaded(extension: dict) -> bool:
    """Determine if a Chrome/Edge extension is sideloaded (not from official web store).

    An extension is considered sideloaded if its update_url does not reference
    a known official web store URL.
    """
    update_url = extension.get("update_url", "")
    if not update_url:
        # No update_url at all means it was loaded outside the store
        return True
    update_url_lower = update_url.lower()
    for official_url in _OFFICIAL_UPDATE_URLS:
        if official_url in update_url_lower:
            return False
    return True


def _count_dangerous_permissions(permissions: list[str]) -> list[str]:
    """Return the list of dangerous permissions found in the given permission set."""
    found: list[str] = []
    for perm in permissions:
        if perm in _DANGEROUS_PERMISSIONS:
            found.append(perm)
    return found


def _has_traffic_interception(permissions: list[str]) -> bool:
    """Check if extension has full traffic interception capability.

    This requires webRequest + webRequestBlocking + <all_urls> or *://*/*.
    """
    perm_set = set(permissions)
    has_web_request = "webRequest" in perm_set
    has_blocking = "webRequestBlocking" in perm_set
    has_all_urls = "<all_urls>" in perm_set or "*://*/*" in perm_set
    return has_web_request and has_blocking and has_all_urls


class BrowserExtensionAuditCheck(BaseCheck):
    """Audit installed browser extensions across all user profiles."""

    CHECK_ID = "EXT-001"
    NAME = "Browser Extension Audit"
    DESCRIPTION = (
        "Enumerates browser extensions installed in Chrome, Edge, and Firefox "
        "across all user profiles. Cross-references against known malicious "
        "extension databases, detects sideloaded extensions, and analyzes "
        "extension permissions for excessive access."
    )
    CATEGORY = Category.CONFIGURATION
    REQUIRES_ADMIN = False

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        # Load known malicious extensions database
        known_malicious = _load_known_malicious()

        # Find all user profiles
        users_dir = _get_users_dir()
        user_profiles = _enumerate_user_profiles(users_dir)

        if not user_profiles:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="No user profiles found for extension audit",
                description=(
                    f"Unable to enumerate user profiles under {users_dir}. "
                    "Browser extension audit could not be performed."
                ),
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item=users_dir,
                evidence=f"Users directory: {users_dir}",
                recommendation=(
                    "Verify the Users directory path and access permissions."
                ),
            ))
            return findings

        # Collect all extensions across browsers and user profiles
        all_extensions: list[dict] = []
        browser_counts: dict[str, int] = {"Chrome": 0, "Edge": 0, "Firefox": 0}

        for profile_path in user_profiles:
            # Chrome extensions
            chrome_exts = _collect_chromium_extensions(
                profile_path,
                "Chrome",
                os.path.join("AppData", "Local", "Google", "Chrome", "User Data"),
            )
            all_extensions.extend(chrome_exts)
            browser_counts["Chrome"] += len(chrome_exts)

            # Edge extensions
            edge_exts = _collect_chromium_extensions(
                profile_path,
                "Edge",
                os.path.join("AppData", "Local", "Microsoft", "Edge", "User Data"),
            )
            all_extensions.extend(edge_exts)
            browser_counts["Edge"] += len(edge_exts)

            # Firefox extensions
            firefox_exts = _collect_firefox_extensions(profile_path)
            all_extensions.extend(firefox_exts)
            browser_counts["Firefox"] += len(firefox_exts)

        # Capture full extension state for baseline comparison
        self.context["state"] = [
            {
                "browser": ext["browser"],
                "extension_id": ext["extension_id"],
                "name": ext["name"],
                "version": ext.get("version", ""),
                "user_profile": os.path.basename(ext.get("user_profile", "")),
            }
            for ext in all_extensions
        ]

        # Analyze each extension
        malicious_count = 0
        sideloaded_count = 0
        excessive_perm_count = 0
        traffic_intercept_count = 0

        for ext in all_extensions:
            ext_id = ext["extension_id"].lower().strip()
            ext_name = ext["name"]
            ext_browser = ext["browser"]
            ext_user = os.path.basename(ext["user_profile"])
            affected_item = f"{ext_browser} extension: {ext_name} ({ext_id})"

            # Check 1: Known malicious extension
            if ext_id in known_malicious:
                malicious_entry = known_malicious[ext_id]
                malicious_count += 1
                mal_severity_str = malicious_entry.get("severity", "CRITICAL")
                try:
                    mal_severity = Severity(mal_severity_str)
                except ValueError:
                    mal_severity = Severity.CRITICAL

                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title=f"Known malicious extension: {malicious_entry.get('name', ext_name)}",
                    description=(
                        f"Extension {ext_id} in {ext_browser} for user {ext_user} "
                        f"is in the known malicious extensions database. "
                        f"{malicious_entry.get('description', '')}"
                    ),
                    severity=mal_severity,
                    category=self.CATEGORY,
                    affected_item=affected_item,
                    evidence=(
                        f"Browser: {ext_browser}\n"
                        f"User profile: {ext_user}\n"
                        f"Extension ID: {ext_id}\n"
                        f"Extension name: {ext_name}\n"
                        f"Version: {ext.get('version', 'Unknown')}\n"
                        f"Known malicious name: {malicious_entry.get('name', 'N/A')}\n"
                        f"Manifest: {ext.get('manifest_path', 'N/A')}"
                    ),
                    recommendation=(
                        "Remove this extension immediately. Uninstall from "
                        "the browser extensions page and delete the extension "
                        "directory. Investigate the user account for signs of "
                        "compromise. Review browser history and saved credentials."
                    ),
                    references=[
                        "https://attack.mitre.org/techniques/T1176/",
                    ],
                ))
                continue

            permissions = ext.get("permissions", [])

            # Check 2: Full traffic interception capability
            if _has_traffic_interception(permissions):
                traffic_intercept_count += 1
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title=f"Extension has full traffic interception: {ext_name}",
                    description=(
                        f"Extension {ext_id} in {ext_browser} for user {ext_user} "
                        f"has webRequest, webRequestBlocking, and broad URL access "
                        f"permissions. This combination allows the extension to "
                        f"intercept, modify, or block all web traffic including "
                        f"HTTPS requests, enabling credential theft, data "
                        f"exfiltration, and man-in-the-browser attacks."
                    ),
                    severity=Severity.HIGH,
                    category=self.CATEGORY,
                    affected_item=affected_item,
                    evidence=(
                        f"Browser: {ext_browser}\n"
                        f"User profile: {ext_user}\n"
                        f"Extension ID: {ext_id}\n"
                        f"Extension name: {ext_name}\n"
                        f"Version: {ext.get('version', 'Unknown')}\n"
                        f"Permissions: {', '.join(permissions)}\n"
                        f"Manifest: {ext.get('manifest_path', 'N/A')}"
                    ),
                    recommendation=(
                        "Review this extension to confirm it is legitimate and "
                        "required. Extensions with full traffic interception "
                        "capability should be limited to trusted security or "
                        "privacy tools. Remove if not authorized."
                    ),
                    references=[
                        "https://attack.mitre.org/techniques/T1176/",
                        "https://attack.mitre.org/techniques/T1557/",
                    ],
                ))
                continue

            # Check 3: Excessive dangerous permissions
            dangerous = _count_dangerous_permissions(permissions)
            if len(dangerous) >= _EXCESSIVE_PERMISSION_THRESHOLD:
                excessive_perm_count += 1
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title=f"Extension has excessive permissions: {ext_name}",
                    description=(
                        f"Extension {ext_id} in {ext_browser} for user {ext_user} "
                        f"requests {len(dangerous)} dangerous permissions. "
                        f"Extensions with broad permissions can access sensitive "
                        f"browser data, modify web requests, and interact with "
                        f"native applications."
                    ),
                    severity=Severity.HIGH,
                    category=self.CATEGORY,
                    affected_item=affected_item,
                    evidence=(
                        f"Browser: {ext_browser}\n"
                        f"User profile: {ext_user}\n"
                        f"Extension ID: {ext_id}\n"
                        f"Extension name: {ext_name}\n"
                        f"Version: {ext.get('version', 'Unknown')}\n"
                        f"Dangerous permissions ({len(dangerous)}): "
                        f"{', '.join(dangerous)}\n"
                        f"All permissions: {', '.join(permissions)}\n"
                        f"Manifest: {ext.get('manifest_path', 'N/A')}"
                    ),
                    recommendation=(
                        "Review this extension and verify it is authorized. "
                        "Determine whether the requested permissions are "
                        "proportional to the extension's stated functionality. "
                        "Remove if the permissions are not justified."
                    ),
                    references=[
                        "https://attack.mitre.org/techniques/T1176/",
                    ],
                ))

            # Check 4: Sideloaded extension (Chrome/Edge only)
            if ext_browser in ("Chrome", "Edge") and _is_sideloaded(ext):
                sideloaded_count += 1
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title=f"Sideloaded extension detected: {ext_name}",
                    description=(
                        f"Extension {ext_id} in {ext_browser} for user {ext_user} "
                        f"does not reference an official web store update URL. "
                        f"Sideloaded extensions bypass web store review processes "
                        f"and may contain unvetted or malicious code."
                    ),
                    severity=Severity.MEDIUM,
                    category=self.CATEGORY,
                    affected_item=affected_item,
                    evidence=(
                        f"Browser: {ext_browser}\n"
                        f"User profile: {ext_user}\n"
                        f"Extension ID: {ext_id}\n"
                        f"Extension name: {ext_name}\n"
                        f"Version: {ext.get('version', 'Unknown')}\n"
                        f"Update URL: {ext.get('update_url', 'None')}\n"
                        f"Manifest: {ext.get('manifest_path', 'N/A')}"
                    ),
                    recommendation=(
                        "Verify this extension was intentionally sideloaded. "
                        "Sideloaded extensions should be approved by IT/security "
                        "policy. If unauthorized, remove the extension and "
                        "investigate how it was installed."
                    ),
                    references=[
                        "https://attack.mitre.org/techniques/T1176/",
                    ],
                ))

        # Summary finding
        findings.append(Finding(
            check_id=self.CHECK_ID,
            title="Browser extension audit summary",
            description=(
                f"Scanned {len(user_profiles)} user profile(s) and found "
                f"{len(all_extensions)} total extension(s). "
                f"Chrome: {browser_counts['Chrome']}, "
                f"Edge: {browser_counts['Edge']}, "
                f"Firefox: {browser_counts['Firefox']}. "
                f"Malicious: {malicious_count}, "
                f"traffic interception: {traffic_intercept_count}, "
                f"excessive permissions: {excessive_perm_count}, "
                f"sideloaded: {sideloaded_count}."
            ),
            severity=Severity.INFO,
            category=self.CATEGORY,
            affected_item="Browser Extensions",
            evidence=(
                f"User profiles scanned: {len(user_profiles)}\n"
                f"Total extensions: {len(all_extensions)}\n"
                f"  Chrome: {browser_counts['Chrome']}\n"
                f"  Edge: {browser_counts['Edge']}\n"
                f"  Firefox: {browser_counts['Firefox']}\n"
                f"Known malicious: {malicious_count}\n"
                f"Traffic interception: {traffic_intercept_count}\n"
                f"Excessive permissions: {excessive_perm_count}\n"
                f"Sideloaded: {sideloaded_count}\n"
                f"Known malicious DB entries: {len(known_malicious)}"
            ),
            recommendation=(
                "Regularly audit browser extensions across all user profiles. "
                "Maintain an allowlist of approved extensions and enforce via "
                "Group Policy."
            ),
            references=[
                "https://attack.mitre.org/techniques/T1176/",
            ],
        ))

        return findings
