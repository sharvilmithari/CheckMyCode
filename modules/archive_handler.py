"""Archive Handling Module for OpenGuard.

Safely inspects, validates, and extracts uploaded ZIP project archives with
defenses against ZIP slip (path traversal), ZIP bombs, and symlink attacks.
"""

from __future__ import annotations

import io
import logging
import os
from pathlib import Path
import shutil
import stat
from typing import Any, Dict, List, Optional, Tuple
import zipfile

logger = logging.getLogger(__name__)

# Mandatory Security & Resource Constraints
MAX_ZIP_SIZE = 50 * 1024 * 1024          # 50 MB compressed
MAX_TOTAL_UNCOMPRESSED = 150 * 1024 * 1024 # 150 MB uncompressed limit
MAX_FILE_COUNT = 1500                     # Max files extracted
MAX_SINGLE_FILE_SIZE = 10 * 1024 * 1024   # 10 MB per individual file


class ArchiveSecurityError(Exception):
    """Raised when an archive contains potentially dangerous or malicious entries."""
    pass


def is_path_safe(base_dir: Path, target_path: Path) -> bool:
    """Ensure target path resolves strictly within the base destination directory."""
    try:
        resolved_base = base_dir.resolve()
        resolved_target = target_path.resolve()
        return str(resolved_target).startswith(str(resolved_base))
    except Exception:
        return False


def validate_zip_safety(zf: zipfile.ZipFile) -> Tuple[bool, str, int, int]:
    """Inspect archive entries for traversal, symlinks, and bomb patterns.

    Returns:
        (is_safe, error_message, total_file_count, total_uncompressed_bytes)
    """
    total_uncompressed = 0
    file_count = 0

    for info in zf.infolist():
        file_count += 1
        if file_count > MAX_FILE_COUNT:
            return False, f"Archive exceeds maximum allowed file count ({MAX_FILE_COUNT} files).", file_count, total_uncompressed

        # Path traversal checks (ZIP Slip prevention)
        filename = info.filename
        if (
            "../" in filename
            or "..\\" in filename
            or filename.startswith("/")
            or filename.startswith("\\")
            or (len(filename) > 2 and filename[1] == ":")
        ):
            return False, f"Path traversal detected in archive entry: '{filename}'.", file_count, total_uncompressed

        # Check for symlink flags in external attributes
        mode = info.external_attr >> 16
        if stat.S_ISLNK(mode):
            return False, f"Symlink entry rejected for security: '{filename}'.", file_count, total_uncompressed

        # Size checks
        if info.file_size > MAX_SINGLE_FILE_SIZE:
            return (
                False,
                f"File '{filename}' exceeds single file size limit ({MAX_SINGLE_FILE_SIZE // (1024*1024)} MB).",
                file_count,
                total_uncompressed,
            )

        total_uncompressed += info.file_size
        if total_uncompressed > MAX_TOTAL_UNCOMPRESSED:
            return (
                False,
                f"Archive uncompressed size exceeds limit ({MAX_TOTAL_UNCOMPRESSED // (1024*1024)} MB).",
                file_count,
                total_uncompressed,
            )

    return True, "", file_count, total_uncompressed


def extract_archive_safely(
    archive_source: io.BytesIO | Path | str,
    destination_dir: Path,
) -> Tuple[bool, str, Dict[str, Any]]:
    """Validate and extract an untrusted ZIP archive into an isolated destination directory.

    Guarantees:
    - Never extracts outside destination_dir
    - Rejects path traversal and symlinks
    - Enforces size and file count bounds
    - Skips executable permissions on extracted files
    """
    dest_path = Path(destination_dir).resolve()
    dest_path.mkdir(parents=True, exist_ok=True)

    metadata: Dict[str, Any] = {
        "files_extracted": 0,
        "total_uncompressed_bytes": 0,
        "skipped_entries": 0,
    }

    try:
        if isinstance(archive_source, (Path, str)):
            if not Path(archive_source).exists():
                return False, f"Archive file '{archive_source}' does not exist.", metadata
            zf = zipfile.ZipFile(archive_source, "r")
        else:
            archive_source.seek(0)
            zf = zipfile.ZipFile(archive_source, "r")

        with zf:
            is_safe, error_msg, file_count, total_bytes = validate_zip_safety(zf)
            if not is_safe:
                return False, error_msg, metadata

            metadata["total_uncompressed_bytes"] = total_bytes

            for member in zf.infolist():
                # Normalize and verify target path
                member_path = (dest_path / member.filename).resolve()
                if not is_path_safe(dest_path, member_path):
                    return False, f"Security violation: path escape detected for '{member.filename}'.", metadata

                if member.is_dir():
                    member_path.mkdir(parents=True, exist_ok=True)
                    continue

                # Ensure parent directories exist
                member_path.parent.mkdir(parents=True, exist_ok=True)

                # Write out file with stripped executable bit
                with zf.open(member) as source_file, open(member_path, "wb") as target_file:
                    shutil.copyfileobj(source_file, target_file)

                # Remove executable permission where applicable
                try:
                    os.chmod(member_path, 0o644)
                except Exception:
                    pass

                metadata["files_extracted"] += 1

        return True, "", metadata

    except zipfile.BadZipFile:
        return False, "Uploaded file is corrupted or not a valid ZIP archive.", metadata
    except Exception as e:
        logger.error("Archive extraction failed: %s", e)
        return False, f"Failed to extract archive safely: {e}", metadata


def cleanup_directory(target_dir: Path | str) -> None:
    """Safely remove a temporary directory tree."""
    try:
        p = Path(target_dir)
        if p.exists() and p.is_dir():
            shutil.rmtree(p, ignore_errors=True)
    except Exception as e:
        logger.warning("Error cleaning temporary directory %s: %s", target_dir, e)

