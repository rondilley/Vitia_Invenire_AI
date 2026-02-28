"""HASH-001: Compare file hashes against NSRL and VirusTotal.

Compares SHA256 hashes of system binaries against the NSRL SQLite
database (if configured) and the VirusTotal API (if API key configured).
Reports unknown files, and any VT detection > 0 on a system binary
is flagged as CRITICAL.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import time
from pathlib import Path

from vitia_invenire.checks.base import BaseCheck
from vitia_invenire.models import Category, Finding, Severity

# Default system directories to scan
_DEFAULT_SCAN_DIRS = [
    r"C:\Windows\System32",
    r"C:\Windows\System32\drivers",
]

# Extensions to check
_TARGET_EXTENSIONS = {".exe", ".dll", ".sys"}

# Maximum files to hash and look up
_MAX_FILES = 500

# Read buffer for hashing
_READ_BUFFER_SIZE = 65536

# Default VT rate limit (requests per minute)
_VT_DEFAULT_RATE_LIMIT = 4

# Default VT daily limit
_VT_DEFAULT_DAILY_LIMIT = 500

# VirusTotal API v3 base URL
_VT_API_BASE = "https://www.virustotal.com/api/v3"


def _compute_sha256(file_path: str) -> str | None:
    """Compute SHA256 of a file."""
    try:
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            while True:
                chunk = f.read(_READ_BUFFER_SIZE)
                if not chunk:
                    break
                sha256.update(chunk)
        return sha256.hexdigest()
    except (PermissionError, OSError, FileNotFoundError):
        return None


def _enumerate_files(scan_dirs: list[str], extensions: set[str], max_files: int) -> list[str]:
    """Enumerate target files in scan directories."""
    target_files: list[str] = []
    seen: set[str] = set()

    for scan_dir in scan_dirs:
        dir_path = Path(scan_dir)
        if not dir_path.exists() or not dir_path.is_dir():
            continue
        try:
            for entry in dir_path.iterdir():
                try:
                    if entry.is_file() and entry.suffix.lower() in extensions:
                        resolved = str(entry.resolve())
                        if resolved not in seen:
                            seen.add(resolved)
                            target_files.append(resolved)
                            if len(target_files) >= max_files:
                                return target_files
                except (PermissionError, OSError):
                    continue
        except (PermissionError, OSError):
            continue

    return target_files


_VT_KEY_FILENAME = "virustotal.key.txt"

# NSRL database filename (RDS Modern SQLite)
_NSRL_DB_FILENAME = "NSRLFile.db"

# Standard subdirectory under install root
_NSRL_SUBDIR = "nsrl"


def _find_nsrl_db() -> str:
    """Locate the NSRL RDS Modern SQLite database.

    Searches for NSRLFile.db in these locations (first match wins):
      1. VITIA_NSRL_DB_PATH environment variable (explicit override)
      2. %LOCALAPPDATA%/VitiaInvenire/nsrl/NSRLFile.db (standard install)
      3. %LOCALAPPDATA%/VitiaInvenire/nsrl/*.db (any .db in nsrl dir)
      4. Current working directory

    Returns the path string or empty string if not found.
    """
    # Explicit environment variable takes priority
    env_path = os.environ.get("VITIA_NSRL_DB_PATH", "")
    if env_path and Path(env_path).exists():
        return env_path

    search_dirs: list[str] = []

    # Standard install location
    local_app_data = os.environ.get("LOCALAPPDATA", "")
    if local_app_data:
        search_dirs.append(
            os.path.join(local_app_data, "VitiaInvenire", _NSRL_SUBDIR)
        )

    # Current working directory
    search_dirs.append(os.getcwd())

    for directory in search_dirs:
        # Check for the standard filename first
        db_path = os.path.join(directory, _NSRL_DB_FILENAME)
        if Path(db_path).exists():
            return db_path

        # Fall back to any .db file in the directory
        try:
            for entry in os.listdir(directory):
                if entry.lower().endswith(".db"):
                    candidate = os.path.join(directory, entry)
                    if Path(candidate).is_file():
                        return candidate
        except (OSError, PermissionError):
            continue

    return ""


def _load_vt_key_from_file() -> str:
    """Attempt to load a VirusTotal API key from a key file.

    Searches for virustotal.key.txt in these locations (first match wins):
      1. The Vitia Invenire install directory (%LOCALAPPDATA%/VitiaInvenire)
      2. The current working directory
      3. The user's home directory

    Returns the key string (stripped) or empty string if not found.
    """
    search_dirs: list[str] = []

    # Install directory (standard install location)
    local_app_data = os.environ.get("LOCALAPPDATA", "")
    if local_app_data:
        search_dirs.append(os.path.join(local_app_data, "VitiaInvenire"))

    # Current working directory
    search_dirs.append(os.getcwd())

    # User home directory
    home = os.path.expanduser("~")
    if home:
        search_dirs.append(home)

    for directory in search_dirs:
        key_path = os.path.join(directory, _VT_KEY_FILENAME)
        try:
            with open(key_path, encoding="utf-8") as f:
                key = f.read().strip()
                if key:
                    return key
        except (OSError, FileNotFoundError, PermissionError):
            continue

    return ""


class HashLookupCheck(BaseCheck):
    """Compare system binary hashes against NSRL and VirusTotal."""

    CHECK_ID = "HASH-001"
    NAME = "Hash Lookup (NSRL + VirusTotal)"
    DESCRIPTION = (
        "Compare SHA256 hashes of system binaries against the NSRL "
        "database and VirusTotal API. Unknown files and VT detections "
        "on system binaries are flagged."
    )
    CATEGORY = Category.BINARY_INTEGRITY
    REQUIRES_ADMIN = False

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        # Read configuration -- auto-detect NSRL database and VT API key
        nsrl_db_path = _find_nsrl_db()
        vt_api_key = os.environ.get("VITIA_VT_API_KEY", "")
        vt_rate_limit = _VT_DEFAULT_RATE_LIMIT
        vt_daily_limit = _VT_DEFAULT_DAILY_LIMIT

        # Load VT API key from key file if not set via environment variable
        if not vt_api_key:
            vt_api_key = _load_vt_key_from_file()

        nsrl_available = bool(nsrl_db_path) and Path(nsrl_db_path).exists()
        vt_available = bool(vt_api_key)

        if not nsrl_available and not vt_available:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Hash Lookup Not Available",
                description=(
                    "Neither the NSRL database nor a VirusTotal API key was "
                    "found. The installer should have downloaded the NSRL "
                    "database automatically. Re-run the installer or set "
                    "VITIA_NSRL_DB_PATH to the database file."
                ),
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="Hash Lookup Configuration",
                evidence=(
                    f"NSRL DB: {'found at ' + nsrl_db_path if nsrl_db_path else 'not found'}\n"
                    f"VT API key: {'configured' if vt_api_key else 'not found'}\n"
                    f"Searched for: {_NSRL_DB_FILENAME} in install dir, CWD\n"
                    f"Searched for: {_VT_KEY_FILENAME} in install dir, CWD, home"
                ),
                recommendation=(
                    "Re-run the installer to download the NSRL database. "
                    "Optionally register for a free VirusTotal API key at "
                    "https://www.virustotal.com/ and save it to "
                    "virustotal.key.txt in the install directory."
                ),
                references=[
                    "https://www.nist.gov/itl/ssd/software-quality-group/national-software-reference-library-nsrl",
                    "https://www.virustotal.com/",
                ],
            ))
            return findings

        # Enumerate and hash files
        target_files = _enumerate_files(
            _DEFAULT_SCAN_DIRS, _TARGET_EXTENSIONS, _MAX_FILES
        )

        file_hashes: dict[str, str] = {}
        for fp in target_files:
            sha256 = _compute_sha256(fp)
            if sha256:
                file_hashes[fp] = sha256

        if not file_hashes:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="No Files Hashed for Lookup",
                description="Could not hash any target files for lookup.",
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="System Binaries",
                evidence=f"Target files found: {len(target_files)}, hashed: 0",
                recommendation="Check file permissions in system directories.",
                references=[],
            ))
            return findings

        # NSRL lookup
        nsrl_known: set[str] = set()
        nsrl_unknown: set[str] = set()

        if nsrl_available:
            nsrl_known, nsrl_unknown = self._nsrl_lookup(
                nsrl_db_path, set(file_hashes.values())
            )

            nsrl_unknown_files = [
                {"file": fp, "sha256": h}
                for fp, h in file_hashes.items()
                if h in nsrl_unknown
            ]

            if nsrl_unknown_files:
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title="System Binaries Not Found in NSRL",
                    description=(
                        f"{len(nsrl_unknown_files)} system binary hash(es) were not "
                        f"found in the NSRL database. These files are not part of "
                        f"known software distributions and should be investigated."
                    ),
                    severity=Severity.MEDIUM,
                    category=self.CATEGORY,
                    affected_item="NSRL Unknown Files",
                    evidence=json.dumps(nsrl_unknown_files[:100], indent=2),
                    recommendation=(
                        "Investigate files not in NSRL. They may be legitimate "
                        "vendor-specific files, or they could indicate tampering."
                    ),
                    references=[
                        "https://www.nist.gov/itl/ssd/software-quality-group/national-software-reference-library-nsrl",
                    ],
                ))

            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="NSRL Lookup Summary",
                description=(
                    f"Checked {len(file_hashes)} hashes against NSRL. "
                    f"{len(nsrl_known)} known, {len(nsrl_unknown)} unknown."
                ),
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="NSRL Database",
                evidence=(
                    f"Total hashes: {len(file_hashes)}\n"
                    f"NSRL known: {len(nsrl_known)}\n"
                    f"NSRL unknown: {len(nsrl_unknown)}"
                ),
                recommendation="Keep NSRL database updated.",
                references=[],
            ))

        self.context = {
            "total_hashed": len(file_hashes),
            "nsrl_available": nsrl_available,
            "nsrl_known": len(nsrl_known),
            "nsrl_unknown": len(nsrl_unknown),
            "vt_available": vt_available,
        }

        # VirusTotal lookup
        if vt_available:
            # Only submit unknown hashes to VT (or all if NSRL not available)
            hashes_for_vt: dict[str, str] = {}
            if nsrl_available:
                hashes_for_vt = {
                    fp: h for fp, h in file_hashes.items()
                    if h in nsrl_unknown
                }
            else:
                hashes_for_vt = dict(file_hashes)

            # Limit to daily quota
            vt_batch = dict(list(hashes_for_vt.items())[:vt_daily_limit])

            vt_detections = self._vt_lookup(
                vt_api_key, vt_batch, vt_rate_limit
            )

            detected_files: list[dict] = []
            clean_count = 0
            error_count = 0

            for fp, result in vt_detections.items():
                if result.get("error"):
                    error_count += 1
                    continue

                detections = result.get("detections", 0)
                total_engines = result.get("total", 0)

                if detections > 0:
                    detected_files.append({
                        "file": fp,
                        "sha256": vt_batch.get(fp, ""),
                        "detections": detections,
                        "total_engines": total_engines,
                        "detection_ratio": f"{detections}/{total_engines}",
                        "vt_link": f"https://www.virustotal.com/gui/file/{vt_batch.get(fp, '')}",
                    })
                else:
                    clean_count += 1

            if detected_files:
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title="VirusTotal Detections on System Binaries",
                    description=(
                        f"{len(detected_files)} system binary(ies) have VirusTotal "
                        f"detections. Any positive detection on a file in System32 "
                        f"or the drivers directory is a critical finding that "
                        f"requires immediate investigation."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.CATEGORY,
                    affected_item="VT Detected Files",
                    evidence=json.dumps(detected_files, indent=2),
                    recommendation=(
                        "Immediately investigate each detected file. Isolate the "
                        "system from the network if detections confirm malware. "
                        "Perform full forensic analysis."
                    ),
                    references=[
                        "https://www.virustotal.com/",
                        "https://attack.mitre.org/techniques/T1036/005/",
                    ],
                ))

            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="VirusTotal Lookup Summary",
                description=(
                    f"Submitted {len(vt_batch)} hashes to VirusTotal. "
                    f"{clean_count} clean, {len(detected_files)} detected, "
                    f"{error_count} errors."
                ),
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="VirusTotal API",
                evidence=(
                    f"Total submitted: {len(vt_batch)}\n"
                    f"Clean: {clean_count}\n"
                    f"Detected: {len(detected_files)}\n"
                    f"Errors: {error_count}"
                ),
                recommendation="Regularly check system binary hashes against VT.",
                references=[],
            ))

            self.context["vt_submitted"] = len(vt_batch)
            self.context["vt_detected"] = len(detected_files)
            self.context["vt_clean"] = clean_count
            self.context["vt_errors"] = error_count

        return findings

    def _nsrl_lookup(
        self, db_path: str, hashes: set[str]
    ) -> tuple[set[str], set[str]]:
        """Look up SHA256 hashes in NSRL SQLite database.

        Uses batch queries for performance. The NSRL RDS v3 Modern Minimal
        database uses views (FILE, MFG, OS, PKG) backed by a METADATA table.
        We try FILE view first, then METADATA table, then DISTINCT_HASH view.

        Returns (known_hashes, unknown_hashes) tuple.
        """
        known: set[str] = set()

        if not hashes:
            return known, set()

        # Uppercase all hashes for NSRL comparison (NSRL stores uppercase hex)
        hash_list = [h.upper() for h in hashes]
        # Map uppercase -> original for result mapping
        upper_to_orig = {h.upper(): h for h in hashes}

        try:
            conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
            cursor = conn.cursor()

            # Detect which table/view contains sha256 hashes (try once)
            query_source = None
            for candidate in ("FILE", "METADATA", "DISTINCT_HASH"):
                try:
                    cursor.execute(
                        f"SELECT sha256 FROM {candidate} LIMIT 1"  # noqa: S608
                    )
                    query_source = candidate
                    break
                except sqlite3.OperationalError:
                    continue

            if not query_source:
                conn.close()
                return set(), set(hashes)

            # Batch lookup in chunks of 500 (SQLite variable limit is 999)
            batch_size = 500
            for i in range(0, len(hash_list), batch_size):
                batch = hash_list[i : i + batch_size]
                placeholders = ",".join("?" for _ in batch)
                try:
                    cursor.execute(
                        f"SELECT DISTINCT sha256 FROM {query_source} "  # noqa: S608
                        f"WHERE sha256 IN ({placeholders})",
                        batch,
                    )
                    for row in cursor.fetchall():
                        found_hash = row[0]
                        orig = upper_to_orig.get(found_hash)
                        if orig:
                            known.add(orig)
                except sqlite3.OperationalError:
                    break

            conn.close()
        except (sqlite3.Error, OSError):
            # If database access fails, treat all as unknown
            return set(), set(hashes)

        unknown = set(hashes) - known
        return known, unknown

    def _vt_lookup(
        self,
        api_key: str,
        file_hashes: dict[str, str],
        rate_limit: int,
    ) -> dict[str, dict]:
        """Look up file hashes on VirusTotal API v3.

        Returns dict mapping file_path to VT result dict.
        """
        results: dict[str, dict] = {}

        try:
            import urllib.request
            import urllib.error
        except ImportError:
            for fp in file_hashes:
                results[fp] = {"error": "urllib not available"}
            return results

        interval = 60.0 / rate_limit if rate_limit > 0 else 15.0

        for fp, sha256 in file_hashes.items():
            url = f"{_VT_API_BASE}/files/{sha256}"
            req = urllib.request.Request(url)
            req.add_header("x-apikey", api_key)
            req.add_header("Accept", "application/json")

            try:
                with urllib.request.urlopen(req, timeout=30) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                    attrs = data.get("data", {}).get("attributes", {})
                    stats = attrs.get("last_analysis_stats", {})
                    detections = stats.get("malicious", 0) + stats.get("suspicious", 0)
                    total = sum(stats.values()) if stats else 0
                    results[fp] = {
                        "detections": detections,
                        "total": total,
                        "error": None,
                    }
            except urllib.error.HTTPError as exc:
                if exc.code == 404:
                    # File not found on VT - not necessarily bad
                    results[fp] = {"detections": 0, "total": 0, "error": None, "not_found": True}
                elif exc.code == 429:
                    results[fp] = {"error": "VT rate limit exceeded"}
                    break
                else:
                    results[fp] = {"error": f"HTTP {exc.code}: {exc.reason}"}
            except (urllib.error.URLError, OSError) as exc:
                results[fp] = {"error": str(exc)}
            except json.JSONDecodeError:
                results[fp] = {"error": "Invalid JSON response from VT"}

            # Rate limiting
            time.sleep(interval)

        return results
