"""PE-001: Analyze PE headers of system binaries.

Uses pefile to compute per-section entropy, flag sections with
entropy > 7.0 as packed (CRITICAL for system binaries), and check
imports against a list of suspicious API functions commonly used in
malware and implants.
"""

from __future__ import annotations

import json
import math
import os
from collections import Counter
from pathlib import Path

from vitia_invenire.checks.base import BaseCheck
from vitia_invenire.models import Category, Finding, Severity

# Directories containing system binaries to analyze
_SYSTEM_DIRS = [
    r"C:\Windows\System32",
    r"C:\Windows\System32\drivers",
]

# Extensions to analyze
_TARGET_EXTENSIONS = {".exe", ".dll", ".sys"}

# Maximum number of files to analyze (PE parsing is expensive)
_MAX_FILES_TO_ANALYZE = 500

# Entropy threshold for packed/encrypted sections
_ENTROPY_THRESHOLD = 7.0

# Suspicious import function names organized by technique
_SUSPICIOUS_IMPORTS: dict[str, list[str]] = {
    "process_injection": [
        "VirtualAllocEx",
        "WriteProcessMemory",
        "CreateRemoteThread",
        "NtCreateThreadEx",
        "QueueUserAPC",
        "NtQueueApcThread",
        "RtlCreateUserThread",
        "NtMapViewOfSection",
        "NtUnmapViewOfSection",
        "SetThreadContext",
        "NtSetContextThread",
        "ResumeThread",
        "SuspendThread",
    ],
    "code_execution": [
        "CreateProcessA",
        "CreateProcessW",
        "CreateProcessAsUserA",
        "CreateProcessAsUserW",
        "CreateProcessWithLogonW",
        "CreateProcessWithTokenW",
        "WinExec",
        "ShellExecuteA",
        "ShellExecuteW",
        "ShellExecuteExA",
        "ShellExecuteExW",
    ],
    "memory_manipulation": [
        "VirtualAlloc",
        "VirtualAllocEx",
        "VirtualProtect",
        "VirtualProtectEx",
        "HeapCreate",
        "RtlMoveMemory",
        "RtlCopyMemory",
        "NtAllocateVirtualMemory",
        "NtProtectVirtualMemory",
        "NtWriteVirtualMemory",
        "NtReadVirtualMemory",
    ],
    "credential_access": [
        "CredEnumerateA",
        "CredEnumerateW",
        "CredReadA",
        "CredReadW",
        "LsaEnumerateLogonSessions",
        "LsaGetLogonSessionData",
        "SamIConnect",
        "SamrQueryInformationUser",
        "LsaRetrievePrivateData",
    ],
    "token_manipulation": [
        "OpenProcessToken",
        "AdjustTokenPrivileges",
        "DuplicateToken",
        "DuplicateTokenEx",
        "ImpersonateLoggedOnUser",
        "ImpersonateNamedPipeClient",
        "SetThreadToken",
        "CreateProcessWithTokenW",
        "NtSetInformationToken",
    ],
    "dll_injection": [
        "LoadLibraryA",
        "LoadLibraryW",
        "LoadLibraryExA",
        "LoadLibraryExW",
        "GetProcAddress",
        "LdrLoadDll",
        "LdrGetProcedureAddress",
    ],
    "defense_evasion": [
        "NtSetInformationProcess",
        "NtSetInformationThread",
        "IsDebuggerPresent",
        "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess",
        "OutputDebugStringA",
        "OutputDebugStringW",
        "GetTickCount",
        "QueryPerformanceCounter",
    ],
    "keylogging": [
        "SetWindowsHookExA",
        "SetWindowsHookExW",
        "GetAsyncKeyState",
        "GetKeyState",
        "GetKeyboardState",
        "MapVirtualKeyA",
        "MapVirtualKeyW",
        "RegisterRawInputDevices",
        "GetRawInputData",
    ],
    "screen_capture": [
        "BitBlt",
        "GetDC",
        "GetWindowDC",
        "CreateCompatibleDC",
        "CreateCompatibleBitmap",
        "GetDIBits",
        "PrintWindow",
    ],
    "network": [
        "InternetOpenA",
        "InternetOpenW",
        "InternetOpenUrlA",
        "InternetOpenUrlW",
        "HttpOpenRequestA",
        "HttpOpenRequestW",
        "HttpSendRequestA",
        "HttpSendRequestW",
        "URLDownloadToFileA",
        "URLDownloadToFileW",
        "URLDownloadToCacheFileA",
        "URLDownloadToCacheFileW",
        "WinHttpOpen",
        "WinHttpConnect",
        "WinHttpOpenRequest",
        "WinHttpSendRequest",
    ],
    "registry_manipulation": [
        "RegCreateKeyExA",
        "RegCreateKeyExW",
        "RegSetValueExA",
        "RegSetValueExW",
        "RegDeleteKeyA",
        "RegDeleteKeyW",
        "RegDeleteValueA",
        "RegDeleteValueW",
        "NtSetValueKey",
        "NtDeleteKey",
    ],
    "service_manipulation": [
        "CreateServiceA",
        "CreateServiceW",
        "ChangeServiceConfigA",
        "ChangeServiceConfigW",
        "StartServiceA",
        "StartServiceW",
        "ControlService",
        "DeleteService",
    ],
    "crypto": [
        "CryptEncrypt",
        "CryptDecrypt",
        "CryptAcquireContextA",
        "CryptAcquireContextW",
        "CryptGenKey",
        "CryptDeriveKey",
        "CryptImportKey",
        "CryptExportKey",
        "BCryptEncrypt",
        "BCryptDecrypt",
    ],
}

# Flatten for quick lookup
_ALL_SUSPICIOUS_IMPORTS: set[str] = set()
_IMPORT_TO_TECHNIQUE: dict[str, str] = {}
for _technique, _imports in _SUSPICIOUS_IMPORTS.items():
    for _imp in _imports:
        _ALL_SUSPICIOUS_IMPORTS.add(_imp.lower())
        _IMPORT_TO_TECHNIQUE[_imp.lower()] = _technique


def _compute_entropy(data: bytes) -> float:
    """Compute Shannon entropy of a byte sequence."""
    if not data:
        return 0.0
    length = len(data)
    freq = Counter(data)
    entropy = 0.0
    for count in freq.values():
        probability = count / length
        if probability > 0:
            entropy -= probability * math.log2(probability)
    return entropy


class PeAnalysisCheck(BaseCheck):
    """Analyze PE headers of system binaries for packing and suspicious imports."""

    CHECK_ID = "PE-001"
    NAME = "PE Binary Analysis"
    DESCRIPTION = (
        "Analyze PE headers of system binaries in System32 and drivers. "
        "Compute per-section entropy to detect packed binaries. "
        "Check imports against suspicious API function list."
    )
    CATEGORY = Category.BINARY_INTEGRITY
    REQUIRES_ADMIN = False

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        # Try to import pefile
        try:
            import pefile as pe_module
        except ImportError:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="PE Analysis Skipped - pefile Not Available",
                description=(
                    "The pefile Python module is not installed. PE header "
                    "analysis cannot be performed without it."
                ),
                severity=Severity.LOW,
                category=self.CATEGORY,
                affected_item="PE Analysis",
                evidence="ImportError: pefile module not found",
                recommendation="Install pefile: pip install pefile",
                references=["https://github.com/erocarrera/pefile"],
            ))
            return findings

        # Enumerate target files
        target_files = self._enumerate_files()
        if not target_files:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="No PE Files Found for Analysis",
                description="No target PE files were found in the system directories.",
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="System Binaries",
                evidence=f"Directories searched: {json.dumps(_SYSTEM_DIRS)}",
                recommendation="Verify scan paths and file permissions.",
                references=[],
            ))
            return findings

        packed_binaries: list[dict] = []
        suspicious_import_binaries: list[dict] = []
        analysis_errors: list[dict] = []
        total_analyzed = 0

        for file_path in target_files[:_MAX_FILES_TO_ANALYZE]:
            try:
                pe = pe_module.PE(file_path, fast_load=False)
            except (pe_module.PEFormatError, OSError, PermissionError) as exc:
                analysis_errors.append({"file": file_path, "error": str(exc)})
                continue

            total_analyzed += 1
            file_name = os.path.basename(file_path)

            # Analyze section entropy
            max_entropy = 0.0
            high_entropy_sections: list[dict] = []
            try:
                for section in pe.sections:
                    section_data = section.get_data()
                    entropy = _compute_entropy(section_data)
                    section_name = section.Name.decode("utf-8", errors="replace").rstrip("\x00")
                    if entropy > max_entropy:
                        max_entropy = entropy
                    if entropy > _ENTROPY_THRESHOLD:
                        high_entropy_sections.append({
                            "section": section_name,
                            "entropy": round(entropy, 4),
                            "virtual_size": section.Misc_VirtualSize,
                            "raw_size": section.SizeOfRawData,
                        })
            except (AttributeError, OSError):
                high_entropy_sections = []

            if high_entropy_sections:
                packed_binaries.append({
                    "file": file_path,
                    "max_entropy": round(max_entropy, 4),
                    "high_entropy_sections": high_entropy_sections,
                })

            # Analyze imports for suspicious functions
            suspicious_found: list[dict] = []
            try:
                pe.parse_data_directories(
                    directories=[
                        pe_module.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
                    ]
                )
                if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                    for entry in pe.DIRECTORY_ENTRY_IMPORT:
                        dll_name = entry.dll.decode("utf-8", errors="replace") if entry.dll else "Unknown"
                        for imp in entry.imports:
                            if imp.name:
                                func_name = imp.name.decode("utf-8", errors="replace")
                                if func_name.lower() in _ALL_SUSPICIOUS_IMPORTS:
                                    technique = _IMPORT_TO_TECHNIQUE.get(func_name.lower(), "unknown")
                                    suspicious_found.append({
                                        "function": func_name,
                                        "dll": dll_name,
                                        "technique": technique,
                                    })
            except (AttributeError, OSError, pe_module.PEFormatError):
                suspicious_found = []

            if suspicious_found:
                # Group by technique
                techniques_used: dict[str, list[str]] = {}
                for sf in suspicious_found:
                    tech = sf["technique"]
                    if tech not in techniques_used:
                        techniques_used[tech] = []
                    techniques_used[tech].append(sf["function"])

                suspicious_import_binaries.append({
                    "file": file_path,
                    "suspicious_import_count": len(suspicious_found),
                    "techniques": techniques_used,
                    "imports": suspicious_found,
                })

            try:
                pe.close()
            except (AttributeError, OSError):
                pass  # close() failures are non-fatal

        # Report packed binaries
        if packed_binaries:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Potentially Packed System Binaries Detected",
                description=(
                    f"{len(packed_binaries)} system binary(ies) have sections with "
                    f"entropy exceeding {_ENTROPY_THRESHOLD}, which suggests "
                    f"packing, encryption, or compression. Packed system binaries "
                    f"in System32/drivers are highly unusual and may indicate "
                    f"tampering or implant insertion."
                ),
                severity=Severity.CRITICAL,
                category=self.CATEGORY,
                affected_item="Packed System Binaries",
                evidence=json.dumps(packed_binaries, indent=2),
                recommendation=(
                    "Investigate each packed binary. Compare SHA256 hashes against "
                    "the Microsoft Update Catalog or NSRL database. Packed system "
                    "binaries that do not match known-good hashes should be treated "
                    "as potential rootkits or implants."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1027/002/",
                    "https://attack.mitre.org/techniques/T1014/",
                ],
            ))

        # Report binaries with many suspicious imports
        # Filter to only report binaries with multiple technique categories
        high_risk_imports = [
            b for b in suspicious_import_binaries
            if len(b.get("techniques", {})) >= 3
        ]
        if high_risk_imports:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="System Binaries With Suspicious Import Combinations",
                description=(
                    f"{len(high_risk_imports)} system binary(ies) import functions "
                    f"associated with 3 or more suspicious technique categories "
                    f"(process injection, credential access, defense evasion, etc.). "
                    f"While some legitimate system binaries use these APIs, the "
                    f"combination warrants investigation."
                ),
                severity=Severity.HIGH,
                category=self.CATEGORY,
                affected_item="System Binaries (Suspicious Imports)",
                evidence=json.dumps(high_risk_imports[:50], indent=2),
                recommendation=(
                    "Review each flagged binary and its import table. Compare against "
                    "known-good versions from Microsoft. Focus on binaries that combine "
                    "injection + network + evasion technique APIs."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1055/",
                    "https://attack.mitre.org/techniques/T1027/",
                ],
            ))

        # Summary finding
        findings.append(Finding(
            check_id=self.CHECK_ID,
            title="PE Analysis Summary",
            description=(
                f"Analyzed {total_analyzed} PE files. Found {len(packed_binaries)} "
                f"potentially packed, {len(suspicious_import_binaries)} with "
                f"suspicious imports. {len(analysis_errors)} files had parse errors."
            ),
            severity=Severity.INFO,
            category=self.CATEGORY,
            affected_item="System Binaries",
            evidence=(
                f"Files analyzed: {total_analyzed}\n"
                f"Packed binaries: {len(packed_binaries)}\n"
                f"Suspicious imports: {len(suspicious_import_binaries)}\n"
                f"Parse errors: {len(analysis_errors)}"
            ),
            recommendation="Review PE analysis results for anomalies.",
            references=[],
        ))

        return findings

    def _enumerate_files(self) -> list[str]:
        """Enumerate PE files in system directories."""
        target_files: list[str] = []
        seen: set[str] = set()

        for scan_dir in _SYSTEM_DIRS:
            dir_path = Path(scan_dir)
            if not dir_path.exists() or not dir_path.is_dir():
                continue
            try:
                for entry in dir_path.iterdir():
                    try:
                        if (
                            entry.is_file()
                            and entry.suffix.lower() in _TARGET_EXTENSIONS
                        ):
                            resolved = str(entry.resolve())
                            if resolved not in seen:
                                seen.add(resolved)
                                target_files.append(resolved)
                    except (PermissionError, OSError):
                        continue
            except (PermissionError, OSError):
                continue

        return target_files
