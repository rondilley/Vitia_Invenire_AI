"""BIN-001: SHA256 hash system executables using ThreadPoolExecutor.

Hashes all .exe/.dll/.sys/.ocx files in System32, SysWOW64, and
drivers directories. Reports total files, total size, and timing
as an INFO finding.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from vitia_invenire.checks.base import BaseCheck
from vitia_invenire.models import Category, Finding, Severity

# Default directories to scan
_DEFAULT_SCAN_DIRS = [
    r"C:\Windows\System32",
    r"C:\Windows\SysWOW64",
    r"C:\Windows\System32\drivers",
]

# File extensions to hash
_TARGET_EXTENSIONS = {".exe", ".dll", ".sys", ".ocx"}

# Maximum number of worker threads
_DEFAULT_MAX_THREADS = 4

# Maximum file size to hash (512 MB) to avoid excessive memory/time
_MAX_FILE_SIZE = 512 * 1024 * 1024

# Read buffer size for streaming hash computation
_READ_BUFFER_SIZE = 65536


def _compute_sha256(file_path: str) -> tuple[str, str, int, str | None]:
    """Compute SHA256 hash of a single file.

    Returns:
        Tuple of (file_path, sha256_hex, file_size, error_or_none).
    """
    try:
        file_size = os.path.getsize(file_path)
        if file_size > _MAX_FILE_SIZE:
            return (file_path, "", file_size, f"Skipped: file exceeds {_MAX_FILE_SIZE} bytes")
        if file_size == 0:
            return (file_path, hashlib.sha256(b"").hexdigest(), 0, None)

        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            while True:
                chunk = f.read(_READ_BUFFER_SIZE)
                if not chunk:
                    break
                sha256.update(chunk)
        return (file_path, sha256.hexdigest(), file_size, None)
    except PermissionError:
        return (file_path, "", 0, "Permission denied")
    except OSError as exc:
        return (file_path, "", 0, f"OS error: {exc}")


def _enumerate_target_files(scan_dirs: list[str], extensions: set[str]) -> list[str]:
    """Enumerate all files with target extensions in scan directories."""
    target_files: list[str] = []
    seen_paths: set[str] = set()

    for scan_dir in scan_dirs:
        dir_path = Path(scan_dir)
        if not dir_path.exists() or not dir_path.is_dir():
            continue

        try:
            for entry in dir_path.iterdir():
                try:
                    if entry.is_file() and entry.suffix.lower() in extensions:
                        resolved = str(entry.resolve())
                        if resolved not in seen_paths:
                            seen_paths.add(resolved)
                            target_files.append(resolved)
                except (PermissionError, OSError):
                    continue
        except (PermissionError, OSError):
            continue

    return target_files


class ExecutableHashingCheck(BaseCheck):
    """SHA256 hash all system executables using parallel threads."""

    CHECK_ID = "BIN-001"
    NAME = "System Executable Hashing"
    DESCRIPTION = (
        "SHA256 hash all .exe, .dll, .sys, and .ocx files in System32, "
        "SysWOW64, and drivers directories using ThreadPoolExecutor."
    )
    CATEGORY = Category.BINARY_INTEGRITY
    REQUIRES_ADMIN = False

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        scan_dirs = list(_DEFAULT_SCAN_DIRS)
        extensions = set(_TARGET_EXTENSIONS)
        max_threads = _DEFAULT_MAX_THREADS

        # Enumerate target files
        target_files = _enumerate_target_files(scan_dirs, extensions)

        if not target_files:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="No System Executables Found",
                description=(
                    "No target executable files were found in the configured "
                    "scan directories. This may indicate a non-standard Windows "
                    "installation or permission issues."
                ),
                severity=Severity.LOW,
                category=self.CATEGORY,
                affected_item="System Executables",
                evidence=f"Scan directories: {json.dumps(scan_dirs)}",
                recommendation="Verify scan directory paths and permissions.",
                references=[],
            ))
            return findings

        # Hash files in parallel
        start_time = time.monotonic()
        hashed_count = 0
        error_count = 0
        total_bytes: int = 0
        errors: list[dict] = []
        extension_counts: dict[str, int] = {}
        dir_counts: dict[str, int] = {}

        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            future_map = {
                executor.submit(_compute_sha256, fp): fp
                for fp in target_files
            }

            for future in as_completed(future_map):
                file_path, sha256_hex, file_size, error = future.result()
                if error:
                    error_count += 1
                    errors.append({"file": file_path, "error": error})
                else:
                    hashed_count += 1
                    total_bytes += file_size

                # Count by extension
                ext = Path(file_path).suffix.lower()
                extension_counts[ext] = extension_counts.get(ext, 0) + 1

                # Count by directory
                parent_dir = str(Path(file_path).parent)
                dir_counts[parent_dir] = dir_counts.get(parent_dir, 0) + 1

        elapsed = time.monotonic() - start_time
        total_mb = total_bytes / (1024 * 1024)
        throughput_mb = total_mb / elapsed if elapsed > 0 else 0

        self.context = {
            "files_enumerated": len(target_files),
            "files_hashed": hashed_count,
            "files_errored": error_count,
            "total_mb": round(total_mb, 1),
            "elapsed_seconds": round(elapsed, 2),
            "throughput_mb_s": round(throughput_mb, 1),
            "by_extension": dict(sorted(extension_counts.items(), key=lambda x: -x[1])),
            "by_directory": dict(sorted(dir_counts.items(), key=lambda x: -x[1])),
        }

        # Build evidence summary
        ext_summary = "\n".join(
            f"  {ext}: {count} files"
            for ext, count in sorted(extension_counts.items(), key=lambda x: -x[1])
        )
        dir_summary = "\n".join(
            f"  {d}: {count} files"
            for d, count in sorted(dir_counts.items(), key=lambda x: -x[1])
        )
        error_summary = ""
        if errors:
            # Show first 20 errors
            shown_errors = errors[:20]
            error_lines = [f"  {e['file']}: {e['error']}" for e in shown_errors]
            error_summary = (
                f"\n\nErrors ({error_count} total, showing first {len(shown_errors)}):\n"
                + "\n".join(error_lines)
            )

        evidence = (
            f"Files enumerated: {len(target_files)}\n"
            f"Files hashed: {hashed_count}\n"
            f"Files with errors: {error_count}\n"
            f"Total size: {total_mb:.1f} MB\n"
            f"Elapsed time: {elapsed:.2f} seconds\n"
            f"Throughput: {throughput_mb:.1f} MB/s\n"
            f"Worker threads: {max_threads}\n"
            f"\nBy extension:\n{ext_summary}\n"
            f"\nBy directory:\n{dir_summary}"
            f"{error_summary}"
        )

        findings.append(Finding(
            check_id=self.CHECK_ID,
            title="System Executable Hashing Complete",
            description=(
                f"Hashed {hashed_count} executable files ({total_mb:.1f} MB) "
                f"in {elapsed:.2f} seconds across {len(scan_dirs)} directories."
            ),
            severity=Severity.INFO,
            category=self.CATEGORY,
            affected_item="System Executables",
            evidence=evidence,
            recommendation=(
                "Use the generated hashes to compare against known-good baselines "
                "(NSRL, vendor manifests) or submit to threat intelligence services."
            ),
            references=[
                "https://www.nist.gov/itl/ssd/software-quality-group/national-software-reference-library-nsrl",
            ],
        ))

        return findings
