"""Extract package-shipped plaintext code assets without touching encrypted code."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import BinaryIO

from .utils import checked_zip_entries


SOURCE_LIKE_SUFFIXES = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".jsbundle", ".html", ".htm", ".map", ".wasm"}
MAX_ASSET_BYTES = 50 * 1024 * 1024
MAX_TOTAL_BYTES = 300 * 1024 * 1024
MAX_ASSETS = 3000
_RECOVERED_SUFFIXES = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".html", ".htm", ".css", ".json", ".vue", ".svelte"}


def _copy_asset(source: BinaryIO, destination: Path) -> tuple[int, str]:
    destination.parent.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256()
    count = 0
    with destination.open("wb") as output:
        while block := source.read(1024 * 1024):
            count += len(block)
            if count > MAX_ASSET_BYTES:
                raise ValueError("An extracted asset exceeded the 50 MB limit")
            digest.update(block)
            output.write(block)
    return count, digest.hexdigest()


def _embedded_sources(document: object, depth: int = 0):
    """Yield source text shipped inside a version 3 source map, including indexed maps."""
    if depth > 4 or not isinstance(document, dict) or document.get("version") != 3:
        return
    sources = document.get("sources")
    contents = document.get("sourcesContent")
    if isinstance(sources, list) and isinstance(contents, list):
        if len(sources) > MAX_ASSETS or len(contents) > MAX_ASSETS:
            raise ValueError(f"A source map lists more than {MAX_ASSETS:,} source files")
        for index, (name, content) in enumerate(zip(sources, contents)):
            if isinstance(name, str) and isinstance(content, str):
                yield index, name, content
    sections = document.get("sections")
    if isinstance(sections, list):
        if len(sections) > MAX_ASSETS:
            raise ValueError(f"A source map has more than {MAX_ASSETS:,} sections")
        for section in sections:
            if isinstance(section, dict):
                yield from _embedded_sources(section.get("map"), depth + 1)


def _recover_map_sources(map_file: Path, source_map_path: str, output: Path,
                         recovered: list[dict[str, object]], total: int) -> int:
    try:
        document = json.loads(map_file.read_bytes())
    except (OSError, ValueError, UnicodeDecodeError, RecursionError):
        return total
    for source_index, source_name, content in _embedded_sources(document):
        if len(recovered) >= MAX_ASSETS:
            raise ValueError(f"Source maps contain more than {MAX_ASSETS:,} embedded source files")
        data = content.encode("utf-8")
        if len(data) > MAX_ASSET_BYTES:
            raise ValueError("An embedded source file exceeded the 50 MB limit")
        if total + len(data) > MAX_TOTAL_BYTES:
            raise ValueError("Source-like assets and embedded sources exceed the 300 MB extraction limit")
        suffix = PurePosixPath(source_name.replace("\\", "/").split("?", 1)[0].split("#", 1)[0]).suffix.lower()
        if suffix not in _RECOVERED_SUFFIXES:
            suffix = ".txt"
        relative = Path("_recovered_source_maps") / f"source-{len(recovered) + 1:05d}{suffix}"
        destination = output / relative
        if destination.exists():
            raise ValueError("Recovered source output collides with a packaged asset")
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
        recovered.append({
            "path": relative.as_posix(),
            "source_map": source_map_path,
            "source_index": source_index,
            "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        })
        total += len(data)
    return total


def extract_ios_assets(target: Path, destination: Path) -> dict[str, object]:
    """Write packaged JavaScript, HTML, source maps, and WASM to a new directory.

    The output manifest records package-relative paths, sizes, and hashes. It
    does not contain the extracted source itself.
    """
    target = target.expanduser().resolve()
    destination = destination.expanduser().resolve()
    if not target.exists():
        raise FileNotFoundError(target)
    if destination.exists():
        raise ValueError("Choose an output directory that does not already exist")
    if target.is_dir() and target.suffix != ".app":
        raise ValueError("Asset extraction requires an .app bundle or .ipa file")
    if target.is_file() and target.suffix.lower() != ".ipa":
        raise ValueError("Asset extraction requires an .app bundle or .ipa file")
    if target.is_dir() and destination.is_relative_to(target):
        raise ValueError("Output directory cannot be inside the app bundle")
    destination.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".mobile-audit-assets-", dir=destination.parent))
    manifest: list[dict[str, object]] = []
    map_paths: list[tuple[Path, str]] = []
    recovered: list[dict[str, object]] = []
    skipped_large = 0
    total = 0
    try:
        if target.is_file():
            with zipfile.ZipFile(target) as archive:
                entries = checked_zip_entries(archive)
                selected = [item for item in entries if item.filename.startswith("Payload/")
                            and any(part.endswith((".app", ".appex")) for part in PurePosixPath(item.filename).parts)
                            and not item.is_dir()
                            and PurePosixPath(item.filename).suffix.lower() in SOURCE_LIKE_SUFFIXES]
                if len(selected) > MAX_ASSETS:
                    raise ValueError(f"Archive has more than {MAX_ASSETS:,} source-like assets")
                for item in selected:
                    if item.file_size > MAX_ASSET_BYTES:
                        skipped_large += 1
                        continue
                    if total + item.file_size > MAX_TOTAL_BYTES:
                        raise ValueError("Source-like assets exceed the 300 MB extraction limit")
                    relative = PurePosixPath(item.filename)
                    with archive.open(item) as stream:
                        count, digest = _copy_asset(stream, staging.joinpath(*relative.parts))
                    total += count
                    manifest.append({"path": item.filename, "bytes": count, "sha256": digest})
                    if relative.suffix.lower() == ".map":
                        map_paths.append((staging.joinpath(*relative.parts), item.filename))
        else:
            selected = [path for path in target.rglob("*") if path.is_file() and not path.is_symlink()
                        and path.suffix.lower() in SOURCE_LIKE_SUFFIXES]
            if len(selected) > MAX_ASSETS:
                raise ValueError(f"App bundle has more than {MAX_ASSETS:,} source-like assets")
            for path in sorted(selected):
                size = path.stat().st_size
                if size > MAX_ASSET_BYTES:
                    skipped_large += 1
                    continue
                if total + size > MAX_TOTAL_BYTES:
                    raise ValueError("Source-like assets exceed the 300 MB extraction limit")
                relative = path.relative_to(target)
                with path.open("rb") as stream:
                    count, digest = _copy_asset(stream, staging / relative)
                total += count
                manifest.append({"path": relative.as_posix(), "bytes": count, "sha256": digest})
                if relative.suffix.lower() == ".map":
                    map_paths.append((staging / relative, relative.as_posix()))
        for map_file, source_map_path in map_paths:
            total = _recover_map_sources(map_file, source_map_path, staging, recovered, total)
        result: dict[str, object] = {
            "source_type": "ipa" if target.is_file() else "app_bundle",
            "asset_count": len(manifest),
            "total_bytes": total,
            "skipped_oversize_assets": skipped_large,
            "assets": manifest,
            "recovered_source_count": len(recovered),
            "recovered_sources": recovered,
            "note": "Embedded JavaScript/TypeScript source is recovered only when shipped in a source map. Other assets may be minified or bytecode; native Swift/Objective-C source is not recovered.",
        }
        (staging / "manifest.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        os.replace(staging, destination)
        return result
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise
