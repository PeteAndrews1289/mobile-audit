"""Bounded dependency inventory and opt-in OSV advisory lookup."""

from __future__ import annotations

import json
import os
import re
import urllib.request
from pathlib import Path
from typing import Callable

from .utils import SKIP_DIRS


MAX_LOCKFILES = 30
MAX_LOCK_BYTES = 12 * 1024 * 1024
MAX_DEPENDENCIES = 3000
MAX_OSV_QUERIES = 200
_POD = re.compile(r"^  - ([A-Za-z0-9_.+/-]+) \(([^()\s]+)\)(?::)?$")


def _lockfiles(root: Path):
    count = 0
    for base, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = sorted(name for name in dirs if name not in SKIP_DIRS)
        for name in sorted(files):
            if name not in {"Package.resolved", "package-lock.json", "Podfile.lock"}:
                continue
            path = Path(base) / name
            if path.is_symlink() or not path.is_file():
                continue
            count += 1
            if count > MAX_LOCKFILES:
                raise ValueError(f"Source contains more than {MAX_LOCKFILES} dependency lockfiles")
            yield path


def _swift_lock(data: dict, location: str) -> list[dict[str, object]]:
    pins = data.get("pins")
    if not isinstance(pins, list):
        pins = data.get("object", {}).get("pins") if isinstance(data.get("object"), dict) else []
    if not isinstance(pins, list):
        return []
    result = []
    for pin in pins[:MAX_DEPENDENCIES]:
        if not isinstance(pin, dict):
            continue
        state = pin.get("state")
        if not isinstance(state, dict):
            continue
        version = state.get("version")
        repo = pin.get("location") or pin.get("repositoryURL")
        if not isinstance(version, str) or not version or not isinstance(repo, str) or not repo.startswith(("https://", "http://")):
            continue
        name = pin.get("identity") or pin.get("package") or repo.rstrip("/").split("/")[-1].removesuffix(".git")
        if not isinstance(name, str) or not name:
            continue
        result.append({"ecosystem": "SwiftURL", "name": repo, "display_name": name[:120],
                       "version": version[:80], "manifest": location,
                       "use_status": "declared_in_lockfile_not_verified_in_binary"})
    return result


def _npm_lock(data: dict, location: str) -> list[dict[str, object]]:
    packages = data.get("packages")
    if not isinstance(packages, dict):
        return []
    result = []
    for path, item in packages.items():
        if len(result) >= MAX_DEPENDENCIES:
            break
        if not isinstance(path, str) or not path.startswith("node_modules/") or not isinstance(item, dict):
            continue
        if item.get("dev") is True or item.get("optional") is True:
            continue
        version = item.get("version")
        if not isinstance(version, str) or not version or len(version) > 80:
            continue
        name = path.split("node_modules/")[-1]
        if not name or len(name) > 200:
            continue
        result.append({"ecosystem": "npm", "name": name, "display_name": name,
                       "version": version, "manifest": location,
                       "use_status": "declared_runtime_dependency_not_verified_in_ios_build"})
    return result


def _pod_lock(text: str, location: str) -> list[dict[str, object]]:
    in_pods = False
    result = []
    for line in text.splitlines():
        if line == "PODS:":
            in_pods = True
            continue
        if in_pods and line and not line.startswith(" "):
            break
        if not in_pods:
            continue
        match = _POD.fullmatch(line)
        if match:
            result.append({"ecosystem": "CocoaPods", "name": match.group(1),
                           "display_name": match.group(1), "version": match.group(2),
                           "manifest": location, "use_status": "declared_in_lockfile_not_verified_in_binary"})
            if len(result) >= MAX_DEPENDENCIES:
                break
    return result


def collect_dependencies(root: Path) -> tuple[list[dict[str, object]], list[str]]:
    """Read exact versions from source lockfiles; never infer versions from library names."""
    root = root.expanduser().resolve()
    if not root.is_dir():
        raise ValueError("Dependency inventory requires a source directory")
    dependencies: list[dict[str, object]] = []
    warnings: list[str] = []
    seen: set[tuple[str, str, str]] = set()
    for path in _lockfiles(root):
        location = path.relative_to(root).as_posix()
        if path.stat().st_size > MAX_LOCK_BYTES:
            warnings.append(f"Skipped oversized lockfile: {location}")
            continue
        try:
            if path.name == "Podfile.lock":
                found = _pod_lock(path.read_text(encoding="utf-8"), location)
            else:
                document = json.loads(path.read_bytes())
                if not isinstance(document, dict):
                    raise ValueError("lockfile root is not an object")
                found = _swift_lock(document, location) if path.name == "Package.resolved" else _npm_lock(document, location)
        except (OSError, ValueError, UnicodeDecodeError, RecursionError):
            warnings.append(f"Could not parse dependency lockfile: {location}")
            continue
        for item in found:
            key = (str(item["ecosystem"]), str(item["name"]), str(item["version"]))
            if key not in seen:
                seen.add(key)
                dependencies.append(item)
                if len(dependencies) >= MAX_DEPENDENCIES:
                    warnings.append(f"Dependency inventory stopped at {MAX_DEPENDENCIES} entries")
                    return dependencies, warnings
    return sorted(dependencies, key=lambda item: (str(item["ecosystem"]), str(item["name"]), str(item["version"]))), warnings


def _post_osv(payload: bytes) -> bytes:
    request = urllib.request.Request(
        "https://api.osv.dev/v1/querybatch", data=payload,
        headers={"Content-Type": "application/json", "User-Agent": "mobile-audit/0.5"}, method="POST",
    )
    with urllib.request.urlopen(request, timeout=20) as response:
        body = response.read(4 * 1024 * 1024 + 1)
    if len(body) > 4 * 1024 * 1024:
        raise ValueError("OSV response exceeded the 4 MB limit")
    return body


def lookup_known_advisories(dependencies: list[dict[str, object]],
                            post: Callable[[bytes], bytes] = _post_osv) -> tuple[list[dict[str, object]], list[str]]:
    """Send only exact package coordinates to OSV when the caller explicitly opts in."""
    eligible = [item for item in dependencies if item.get("ecosystem") in {"SwiftURL", "npm"}
                and isinstance(item.get("version"), str) and item["version"]]
    if not eligible:
        return [], ["No SwiftURL or npm exact-version coordinates were available for OSV lookup"]
    if len(eligible) > MAX_OSV_QUERIES:
        eligible = eligible[:MAX_OSV_QUERIES]
        notes = [f"Only the first {MAX_OSV_QUERIES} versioned dependencies were checked with OSV"]
    else:
        notes = []
    matches = []
    for offset in range(0, len(eligible), 50):
        group = eligible[offset:offset + 50]
        payload = json.dumps({"queries": [{"package": {"ecosystem": item["ecosystem"], "name": item["name"]},
                                           "version": item["version"]} for item in group]}).encode("utf-8")
        response = json.loads(post(payload))
        results = response.get("results") if isinstance(response, dict) else None
        if not isinstance(results, list) or len(results) != len(group):
            raise ValueError("OSV returned an unexpected result count")
        for dependency, result in zip(group, results):
            if not isinstance(result, dict):
                raise ValueError("OSV returned an invalid result")
            if result.get("next_page_token"):
                notes.append(f"OSV results were paginated for {dependency['display_name']}; additional matches were not fetched")
            vulns = result.get("vulns", [])
            if not isinstance(vulns, list):
                raise ValueError("OSV returned invalid vulnerability data")
            for vuln in vulns[:100]:
                identifier = vuln.get("id") if isinstance(vuln, dict) else None
                if isinstance(identifier, str) and re.fullmatch(r"[A-Za-z0-9_.-]{4,100}", identifier):
                    matches.append({"id": identifier, "url": f"https://osv.dev/vulnerability/{identifier}",
                                    "ecosystem": dependency["ecosystem"], "name": dependency["name"],
                                    "version": dependency["version"],
                                    "status": "known_advisory_version_match_usage_unverified"})
    return matches, notes
