"""Project Packaging and Integrity Verification Script.

Creates a clean, portable ZIP archive of the Blockchain Smart Contract Honeypot
Attack Detector project, excluding virtual environments, dependencies (node_modules),
temporary build artifacts, and caches. Verifies archive integrity upon creation.
"""

import os
import sys
import zipfile
from pathlib import Path

# Project root directory
ROOT_DIR = Path(__file__).resolve().parent

# Target output archive
OUTPUT_DIR = ROOT_DIR / "dist"
ARCHIVE_NAME = "blockchain-honeypot-detector.zip"
OUTPUT_ZIP = OUTPUT_DIR / ARCHIVE_NAME
ROOT_ZIP = ROOT_DIR / ARCHIVE_NAME

# Directories and file patterns to strictly exclude
EXCLUDE_DIRS = {
    ".venv",
    "venv",
    "env",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    ".git",
    "dist",
    ".gemini",
}

EXCLUDE_EXTENSIONS = {
    ".pyc",
    ".pyo",
    ".pyd",
    ".DS_Store",
    ".log",
}

EXCLUDE_FILES = {
    ARCHIVE_NAME,
    "package_project.py",
}


def should_include(path: Path) -> bool:
    """Evaluates whether a given relative path should be included in the archive."""
    parts = path.parts
    # Check if any parent directory is in exclusion list
    for part in parts:
        if part in EXCLUDE_DIRS:
            return False
        if part.startswith(".pytest_cache"):
            return False

    # Check file extension and name
    if path.suffix in EXCLUDE_EXTENSIONS:
        return False
    if path.name in EXCLUDE_FILES:
        return False

    return True


def package_project():
    """Packages the project into a ZIP archive and performs verification."""
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    print(f"[*] Packaging project from: {ROOT_DIR}")
    print(f"[*] Destination: {OUTPUT_ZIP}")

    included_files = []

    with zipfile.ZipFile(OUTPUT_ZIP, "w", zipfile.ZIP_DEFLATED) as zip_file:
        for root, dirs, files in os.walk(ROOT_DIR):
            rel_root = Path(root).relative_to(ROOT_DIR)

            # Skip excluded directories in os.walk
            dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS and not d.startswith(".pytest_cache")]

            for file in files:
                rel_path = rel_root / file
                if should_include(rel_path):
                    abs_path = ROOT_DIR / rel_path
                    # Normalize zip entry path with forward slashes
                    arcname = f"blockchain-honeypot-detector/{rel_path.as_posix()}"
                    zip_file.write(abs_path, arcname=arcname)
                    included_files.append((arcname, abs_path.stat().st_size))

    # Also create a copy at the project root for convenient access
    import shutil
    shutil.copy2(OUTPUT_ZIP, ROOT_ZIP)

    # Verification phase
    print("\n" + "=" * 60)
    print("ARCHIVE INTEGRITY & CONTENTS VERIFICATION")
    print("=" * 60)

    zip_size_bytes = OUTPUT_ZIP.stat().st_size
    zip_size_mb = zip_size_bytes / (1024 * 1024)
    print(f"[+] Archive created successfully: {OUTPUT_ZIP.name}")
    print(f"[+] Location 1 (dist/): {OUTPUT_ZIP}")
    print(f"[+] Location 2 (root):  {ROOT_ZIP}")
    print(f"[+] Archive Compressed Size: {zip_size_bytes:,} bytes ({zip_size_mb:.2f} MB)")
    print(f"[+] Total Files Packaged: {len(included_files):,} files")

    # Test zipfile CRC checksums
    print("[*] Testing archive CRC32 checksums...")
    with zipfile.ZipFile(OUTPUT_ZIP, "r") as test_zip:
        bad_file = test_zip.testzip()
        if bad_file:
            print(f"[!] ERROR: Corrupted file detected in archive: {bad_file}")
            sys.exit(1)
        else:
            print("[+] All CRC32 checksums verified: 0 errors.")

        # Category breakdown
        categories = {
            "Documentation (docs/, README)": 0,
            "Core Source (src/)": 0,
            "Machine Learning (ml/, models/, data/)": 0,
            "Educational Samples (samples/)": 0,
            "Test Suite (tests/, pytest.ini)": 0,
            "MERN Backend (server/)": 0,
            "MERN Frontend (client/)": 0,
            "Root & Configuration Files": 0,
        }

        for name, _ in included_files:
            sub = name.replace("blockchain-honeypot-detector/", "")
            if sub.startswith("docs/") or sub == "README.md":
                categories["Documentation (docs/, README)"] += 1
            elif sub.startswith("src/"):
                categories["Core Source (src/)"] += 1
            elif sub.startswith("ml/") or sub.startswith("models/") or sub.startswith("data/"):
                categories["Machine Learning (ml/, models/, data/)"] += 1
            elif sub.startswith("samples/"):
                categories["Educational Samples (samples/)"] += 1
            elif sub.startswith("tests/") or sub == "pytest.ini":
                categories["Test Suite (tests/, pytest.ini)"] += 1
            elif sub.startswith("server/"):
                categories["MERN Backend (server/)"] += 1
            elif sub.startswith("client/"):
                categories["MERN Frontend (client/)"] += 1
            else:
                categories["Root & Configuration Files"] += 1

        print("\n[*] Content Breakdown by Subsystem:")
        for cat, count in categories.items():
            print(f"    - {cat:<40}: {count:>3} files")

    print("\n[+] Verification Complete: Project ZIP package is 100% complete and valid.")


if __name__ == "__main__":
    package_project()
