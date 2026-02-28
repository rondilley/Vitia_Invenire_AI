"""COM-001: COM Object Hijacking Detection.

Enumerates HKCU\\Software\\Classes\\CLSID entries via the registry collector
and cross-references them against HKLM equivalents. A user-level CLSID
override that shadows a machine-level entry is a classic COM hijacking
persistence technique. CLSIDs pointing to TEMP or APPDATA paths are
flagged as HIGH severity, and entries matching known-hijacked CLSIDs
are called out explicitly.
"""

from __future__ import annotations

import os

from vitia_invenire.checks.base import BaseCheck
from vitia_invenire.collectors import registry
from vitia_invenire.models import Category, Finding, Severity

# CLSIDs that are frequently targeted for COM hijacking persistence
_KNOWN_HIJACKED_CLSIDS: dict[str, str] = {
    "{b5f8350b-0548-48b1-a6ee-88bd00b4a5e7}": "CLSID used by explorer.exe CAccPropServicesClass",
    "{BCDE0395-E52F-467C-8E3D-C4579291692E}": "MMDeviceEnumerator - audio subsystem COM object",
    "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}": "Thumbnail Cache COM object",
    "{CF4CC405-E2C5-4DDD-B3CE-5E7582D8C9FA}": "Shell Folder View Host COM object",
    "{42aedc87-2188-41fd-b9a3-0c966feab5f8}": "New Taskbar COM handler",
    "{fbeb8a05-beee-4442-804e-409d6c4515e9}": "Shell Folder Band COM handler",
    "{b6073a68-959d-4a3c-b498-c2a719cc4c55}": "IE New Window Manager COM object",
    "{ceff45ee-c862-41de-aee2-a022c81eda92}": "AutoPlay Event Handler COM object",
    "{9B1F122C-2982-4e91-AA8B-E071D54F2A4D}": "TaskBand COM handler",
    "{C08AFD90-F2A1-11D1-8455-00A0C91F3880}": "Shell Automation InProcServer",
    "{E6F15661-568D-11D1-A7F7-00C04FC2DCD2}": "CortanaUI COM handler",
}

# Suspicious path fragments that may indicate COM hijack payloads
_SUSPICIOUS_PATH_FRAGMENTS = [
    "\\temp\\",
    "\\tmp\\",
    "\\appdata\\local\\temp\\",
    "\\appdata\\roaming\\",
    "\\downloads\\",
    "\\public\\",
    "\\users\\public\\",
    "\\programdata\\",
]


class COMHijackingCheck(BaseCheck):
    """Detect COM object hijacking via HKCU CLSID overrides."""

    CHECK_ID = "COM-001"
    NAME = "COM Object Hijacking Detection"
    DESCRIPTION = (
        "Enumerates user-level CLSID entries in HKCU\\Software\\Classes\\CLSID "
        "and cross-references against HKLM equivalents to detect COM hijacking "
        "persistence. Flags CLSIDs pointing to suspicious paths and known "
        "hijacking targets."
    )
    CATEGORY = Category.PERSISTENCE
    REQUIRES_ADMIN = False

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        hkcu_clsid_path = "Software\\Classes\\CLSID"
        hklm_clsid_path = "Software\\Classes\\CLSID"

        # Enumerate all user-level CLSID subkeys
        hkcu_clsids = registry.enumerate_subkeys(
            registry.HKEY_CURRENT_USER, hkcu_clsid_path
        )

        if not hkcu_clsids:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="No User-Level CLSID Overrides Found",
                description="No CLSID entries found under HKCU\\Software\\Classes\\CLSID.",
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="HKCU\\Software\\Classes\\CLSID",
                evidence="HKCU CLSID subkey enumeration returned zero entries.",
                recommendation="No action required. This is the expected state for a clean system.",
                references=[
                    "https://attack.mitre.org/techniques/T1546/015/",
                ],
            ))
            return findings

        override_count = 0
        suspicious_path_entries: list[dict[str, str]] = []
        known_hijack_entries: list[dict[str, str]] = []
        general_override_entries: list[dict[str, str]] = []

        for clsid in hkcu_clsids:
            # Read InprocServer32 or LocalServer32 from the user CLSID
            hkcu_inproc_path = f"{hkcu_clsid_path}\\{clsid}\\InprocServer32"
            hkcu_local_path = f"{hkcu_clsid_path}\\{clsid}\\LocalServer32"

            hkcu_inproc = registry.read_value(
                registry.HKEY_CURRENT_USER, hkcu_inproc_path, ""
            )
            hkcu_local = registry.read_value(
                registry.HKEY_CURRENT_USER, hkcu_local_path, ""
            )

            user_dll_path = None
            server_type = "Unknown"
            if hkcu_inproc and hkcu_inproc.data:
                user_dll_path = str(hkcu_inproc.data)
                server_type = "InprocServer32"
            elif hkcu_local and hkcu_local.data:
                user_dll_path = str(hkcu_local.data)
                server_type = "LocalServer32"

            if user_dll_path is None:
                continue

            # Check if HKLM has the same CLSID (this makes it an override)
            hklm_inproc_path = f"{hklm_clsid_path}\\{clsid}\\InprocServer32"
            hklm_local_path = f"{hklm_clsid_path}\\{clsid}\\LocalServer32"

            hklm_inproc = registry.read_value(
                registry.HKEY_LOCAL_MACHINE, hklm_inproc_path, ""
            )
            hklm_local = registry.read_value(
                registry.HKEY_LOCAL_MACHINE, hklm_local_path, ""
            )

            hklm_dll_path = None
            if hklm_inproc and hklm_inproc.data:
                hklm_dll_path = str(hklm_inproc.data)
            elif hklm_local and hklm_local.data:
                hklm_dll_path = str(hklm_local.data)

            is_override = hklm_dll_path is not None
            if is_override:
                override_count += 1

            entry_info = {
                "clsid": clsid,
                "server_type": server_type,
                "user_path": user_dll_path,
                "machine_path": hklm_dll_path or "N/A (no HKLM equivalent)",
                "is_override": str(is_override),
            }

            # Check if the path points to a suspicious location
            normalized_path = user_dll_path.lower()
            path_is_suspicious = any(
                frag in normalized_path for frag in _SUSPICIOUS_PATH_FRAGMENTS
            )

            # Expand environment variables for additional checks
            temp_dir = os.environ.get("TEMP", "").lower()
            appdata_dir = os.environ.get("APPDATA", "").lower()
            localappdata_dir = os.environ.get("LOCALAPPDATA", "").lower()

            if temp_dir and temp_dir in normalized_path:
                path_is_suspicious = True
            if appdata_dir and appdata_dir in normalized_path:
                path_is_suspicious = True
            if localappdata_dir and "\\temp\\" in normalized_path:
                path_is_suspicious = True

            clsid_lower = clsid.lower()
            is_known_hijack = clsid_lower in _KNOWN_HIJACKED_CLSIDS

            if is_known_hijack:
                known_hijack_entries.append(entry_info)
            elif path_is_suspicious:
                suspicious_path_entries.append(entry_info)
            elif is_override:
                general_override_entries.append(entry_info)

        # Report known hijacked CLSIDs
        if known_hijack_entries:
            evidence_lines = []
            for entry in known_hijack_entries:
                clsid_desc = _KNOWN_HIJACKED_CLSIDS.get(
                    entry["clsid"].lower(), "Known hijacking target"
                )
                evidence_lines.append(
                    f"CLSID: {entry['clsid']}\n"
                    f"  Description: {clsid_desc}\n"
                    f"  Server Type: {entry['server_type']}\n"
                    f"  User Path: {entry['user_path']}\n"
                    f"  Machine Path: {entry['machine_path']}"
                )
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Known Hijacked CLSID Detected",
                description=(
                    f"{len(known_hijack_entries)} user-level CLSID override(s) "
                    f"match known COM hijacking targets. These CLSIDs are commonly "
                    f"abused for persistence by malware and red team tools."
                ),
                severity=Severity.HIGH,
                category=self.CATEGORY,
                affected_item="HKCU\\Software\\Classes\\CLSID",
                evidence="\n\n".join(evidence_lines),
                recommendation=(
                    "Investigate each flagged CLSID override. Verify the DLL or "
                    "executable pointed to by the user-level entry is legitimate. "
                    "Remove unauthorized HKCU CLSID overrides. Check the binary "
                    "for digital signatures and scan with antimalware tools."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1546/015/",
                    "https://bohops.com/2018/08/18/abusing-the-com-registry-structure-clsid-localserver32-inprocserver32/",
                ],
            ))

        # Report CLSIDs pointing to suspicious paths
        if suspicious_path_entries:
            evidence_lines = []
            for entry in suspicious_path_entries:
                evidence_lines.append(
                    f"CLSID: {entry['clsid']}\n"
                    f"  Server Type: {entry['server_type']}\n"
                    f"  User Path: {entry['user_path']}\n"
                    f"  Machine Path: {entry['machine_path']}"
                )
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="CLSID Override Pointing to Suspicious Path",
                description=(
                    f"{len(suspicious_path_entries)} user-level CLSID override(s) "
                    f"point to binaries in TEMP, APPDATA, Downloads, or other "
                    f"suspicious directories. This pattern is commonly used by "
                    f"malware for COM hijacking persistence."
                ),
                severity=Severity.HIGH,
                category=self.CATEGORY,
                affected_item="HKCU\\Software\\Classes\\CLSID",
                evidence="\n\n".join(evidence_lines),
                recommendation=(
                    "Verify each DLL or executable referenced by these CLSID "
                    "entries. Legitimate software rarely stores COM server binaries "
                    "in TEMP or user profile directories. Remove suspicious entries "
                    "and scan the referenced binaries for malware."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1546/015/",
                ],
            ))

        # Report general overrides that shadow HKLM entries
        if general_override_entries:
            evidence_lines = []
            for entry in general_override_entries:
                evidence_lines.append(
                    f"CLSID: {entry['clsid']}\n"
                    f"  Server Type: {entry['server_type']}\n"
                    f"  User Path: {entry['user_path']}\n"
                    f"  Machine Path: {entry['machine_path']}"
                )
            severity = Severity.MEDIUM if len(general_override_entries) > 5 else Severity.LOW
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="User-Level CLSID Overrides Detected",
                description=(
                    f"{len(general_override_entries)} user-level CLSID override(s) "
                    f"shadow machine-level HKLM entries. While some are legitimate "
                    f"(e.g., shell extensions), unexpected overrides may indicate "
                    f"COM hijacking."
                ),
                severity=severity,
                category=self.CATEGORY,
                affected_item="HKCU\\Software\\Classes\\CLSID",
                evidence="\n\n".join(evidence_lines),
                recommendation=(
                    "Review each override to confirm it belongs to known, "
                    "legitimate software. Investigate any entries that cannot be "
                    "attributed to installed applications."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1546/015/",
                ],
            ))

        # If nothing suspicious was found, report clean
        if not known_hijack_entries and not suspicious_path_entries and not general_override_entries:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="COM Hijacking Check Passed",
                description=(
                    f"Examined {len(hkcu_clsids)} HKCU CLSID entries. "
                    f"No suspicious overrides detected."
                ),
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="HKCU\\Software\\Classes\\CLSID",
                evidence=f"Total HKCU CLSIDs examined: {len(hkcu_clsids)}",
                recommendation="No action required.",
                references=[
                    "https://attack.mitre.org/techniques/T1546/015/",
                ],
            ))

        return findings
