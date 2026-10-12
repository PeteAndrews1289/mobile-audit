from __future__ import annotations

import os
import shutil
import stat
import zipfile
from pathlib import Path, PurePosixPath
from typing import Iterator


MAX_ZIP_ENTRIES = 20_000
MAX_ZIP_UNCOMPRESSED = 1_500_000_000
MAX_CONFIG_BYTES = 2_000_000
MAX_SOURCE_BYTES = 1_000_000
MAX_SOURCE_FILES = 25_000

SKIP_DIRS = {
    ".git", ".build", ".swiftpm", ".gradle", ".idea", ".vscode",
    ".claude", ".codex", ".codex_home", ".venv", "venv",
    "node_modules", "Pods", "Carthage", "DerivedData", "build", "dist",
    "vendor", "coverage", "__pycache__", "Tests", "UITests", "test", "tests",
}


def project_files(root: Path) -> Iterator[Path]:
    count = 0
    for base, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = sorted(
            d for d in dirs
            if d not in SKIP_DIRS and not d.endswith("Tests") and not d.endswith("UITests")
            and not d.endswith(".xcassets")
        )
        for name in sorted(files):
            path = Path(base) / name
            if path.is_symlink() or not path.is_file():
                continue
            count += 1
            if count > MAX_SOURCE_FILES:
                raise ValueError(f"Source tree exceeds {MAX_SOURCE_FILES:,} files")
            yield path


def read_small(path: Path, limit: int = MAX_CONFIG_BYTES) -> bytes | None:
    try:
        if path.stat().st_size > limit:
            return None
        return path.read_bytes()
    except OSError:
        return None


def checked_zip_entries(archive: zipfile.ZipFile) -> list[zipfile.ZipInfo]:
    entries = archive.infolist()
    if len(entries) > MAX_ZIP_ENTRIES:
        raise ValueError(f"Archive exceeds {MAX_ZIP_ENTRIES:,} entries")
    if len({str(PurePosixPath(item.filename)) for item in entries}) != len(entries):
        raise ValueError("Archive contains duplicate member paths")
    if sum(item.file_size for item in entries) > MAX_ZIP_UNCOMPRESSED:
        raise ValueError("Archive exceeds the 1.5 GB uncompressed safety limit")
    for item in entries:
        member = PurePosixPath(item.filename)
        if member.is_absolute() or ".." in member.parts or "\\" in item.filename:
            raise ValueError(f"Unsafe archive member path: {item.filename!r}")
        if not member.parts:
            raise ValueError("Archive has an empty member name")
        mode = (item.external_attr >> 16) & 0xFFFF
        if stat.S_ISLNK(mode):
            raise ValueError(f"Archive contains a symbolic link: {item.filename!r}")
    return entries


def read_zip_member(archive: zipfile.ZipFile, item: zipfile.ZipInfo, limit: int = MAX_CONFIG_BYTES) -> bytes | None:
    if item.file_size > limit:
        return None
    with archive.open(item) as stream:
        data = stream.read(limit + 1)
    return data if len(data) <= limit else None


def extract_checked_zip(archive: zipfile.ZipFile, entries: list[zipfile.ZipInfo], destination: Path) -> None:
    for item in entries:
        out = destination.joinpath(*PurePosixPath(item.filename).parts)
        if item.is_dir():
            out.mkdir(parents=True, exist_ok=True)
            continue
        out.parent.mkdir(parents=True, exist_ok=True)
        with archive.open(item) as source, out.open("wb") as target:
            shutil.copyfileobj(source, target, 1024 * 1024)
