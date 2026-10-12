from __future__ import annotations

import json
import hashlib
import plistlib
import re
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import BinaryIO, Callable

from .code_text import without_code_comments
from .macho import MAX_HEADER_BYTES, MAX_REFERENCE_BYTES, inspect_macho, scan_api_references
from .sensitive_names import sensitive_storage_key
from .package_assets import SOURCE_LIKE_SUFFIXES, _embedded_sources
from .models import Finding, Report
from .webcode import scan_web_code
from .utils import (
    MAX_CONFIG_BYTES,
    MAX_ZIP_ENTRIES,
    checked_zip_entries,
    read_small,
    read_zip_member,
)


MAX_IOS_BUNDLES = 1024
MAX_IOS_BINARIES = 1024
MAX_IOS_SIGNATURES = 256


def _executable_priority(location: str) -> tuple[int, str]:
    parts = PurePosixPath(location).parts
    if len(parts) == 3 and parts[0] == "Payload" and parts[1].endswith(".app"):
        return (0, location)
    if any(part.endswith(".appex") for part in parts):
        return (1, location)
    return (2, location)


def _package_file_info(path: Path, report: Report, *, entries: list[zipfile.ZipInfo] | None = None) -> None:
    if entries is not None:
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            while block := stream.read(1024 * 1024):
                digest.update(block)
        report.inventory["ios_package_file"] = {
            "name": path.name, "format": "ipa", "size_bytes": path.stat().st_size,
            "sha256": digest.hexdigest(),
            "file_count": sum(not item.is_dir() for item in entries),
            "uncompressed_bytes": sum(item.file_size for item in entries),
        }
    else:
        count = total = 0
        for candidate in path.rglob("*"):
            if candidate.is_file() and not candidate.is_symlink():
                count += 1
                total += candidate.stat().st_size
                if count > MAX_ZIP_ENTRIES:
                    report.warnings.append("App bundle file inventory exceeded the 20,000-file limit")
                    break
        report.inventory["ios_package_file"] = {
            "name": path.name, "format": "app_bundle", "size_bytes": total,
            "sha256": None, "file_count": count,
            "hash_note": "A directory has no single-file SHA-256; hash the distributed IPA for artifact provenance.",
        }
    report.coverage.append("iOS package identity, size, and file inventory")


def _bundle_kind(location: str) -> str:
    parent = PurePosixPath(location).parent.name.lower()
    if parent.endswith(".appex"):
        return "extension"
    if parent.endswith(".framework"):
        return "framework"
    if parent.endswith(".bundle"):
        return "resource_bundle"
    return "app"


def _is_bundle_info_plist(location: str) -> bool:
    member = PurePosixPath(location)
    return member.name == "Info.plist" and member.parent.name.lower().endswith(
        (".app", ".appex", ".framework", ".bundle")
    )


def _scan_privacy_manifest(data: bytes, location: str, report: Report) -> None:
    try:
        manifest = plistlib.loads(data)
    except (ValueError, TypeError, OverflowError):
        report.warnings.append(f"Could not parse privacy manifest: {location}")
        return
    if not isinstance(manifest, dict):
        report.warnings.append(f"Unexpected privacy manifest structure: {location}")
        return
    collected = manifest.get("NSPrivacyCollectedDataTypes")
    accessed = manifest.get("NSPrivacyAccessedAPITypes")
    domains = manifest.get("NSPrivacyTrackingDomains")
    record = {
        "location": location,
        "tracking_declared": manifest.get("NSPrivacyTracking") is True,
        "tracking_domains": sorted({item for item in domains[:100] if isinstance(item, str) and len(item) <= 200})
        if isinstance(domains, list) else [],
        "collected_data_types": sorted({item.get("NSPrivacyCollectedDataType") for item in collected[:200]
                                        if isinstance(item, dict) and isinstance(item.get("NSPrivacyCollectedDataType"), str)})
        if isinstance(collected, list) else [],
        "accessed_api_types": sorted({item.get("NSPrivacyAccessedAPIType") for item in accessed[:200]
                                      if isinstance(item, dict) and isinstance(item.get("NSPrivacyAccessedAPIType"), str)})
        if isinstance(accessed, list) else [],
    }
    manifests = report.inventory.setdefault("ios_privacy_manifests", [])
    if isinstance(manifests, list) and len(manifests) < 300:
        manifests.append(record)
    report.coverage.append("iOS privacy manifest declarations")


def _code_signature_metadata(path: Path, location: str, *, verify_bundle: bool) -> dict[str, object]:
    result: dict[str, object] = {"location": location, "metadata_status": "unavailable",
                                 "verification": "not_performed"}
    if not shutil.which("codesign"):
        result["note"] = "codesign is unavailable on this Mac"
        return result
    try:
        display = subprocess.run(["codesign", "-dv", "--verbose=4", str(path)],
                                 capture_output=True, text=True, timeout=20, check=False)
        if display.returncode == 0:
            values: dict[str, str] = {}
            authorities: list[str] = []
            for line in display.stderr.splitlines():
                key, sep, value = line.partition("=")
                if not sep or len(value) > 250:
                    continue
                if key in {"Identifier", "TeamIdentifier", "Format", "Signature"}:
                    values[key] = value
                elif key == "Authority" and len(authorities) < 5:
                    authorities.append(value)
            result.update({"metadata_status": "available", "identifier": values.get("Identifier"),
                           "team_id": values.get("TeamIdentifier"), "format": values.get("Format"),
                           "signature": values.get("Signature"), "authorities": authorities})
        else:
            result["note"] = "codesign did not provide signature metadata"
        if verify_bundle:
            verified = subprocess.run(["codesign", "--verify", "--deep", "--strict", str(path)],
                                      capture_output=True, timeout=30, check=False)
            result["verification"] = "verified" if verified.returncode == 0 else "failed"
        else:
            result["note"] = (str(result.get("note", "")) + " Executable only; IPA bundle resources were not verified.").strip()
    except (OSError, subprocess.TimeoutExpired):
        result["note"] = "Code-signature inspection was unavailable or timed out"
    return result


def _entry_point(report: Report, kind: str, value: str, location: str, next_test: str) -> None:
    if not value or len(value) > 200:
        return
    items = report.inventory.setdefault("ios_entry_points", [])
    if isinstance(items, list) and len(items) < 200:
        item = {"kind": kind, "value": value, "location": location, "next_test": next_test}
        if item not in items:
            items.append(item)


def _inspect_binary(open_binary: Callable[[], BinaryIO], size: int, location: str,
                    report: Report) -> None:
    with open_binary() as stream:
        prefix = stream.read(min(size, MAX_HEADER_BYTES))
    inspection = inspect_macho(prefix, size)
    inspection["location"] = location
    if inspection["encryption"] == "not_encrypted":
        if size <= MAX_REFERENCE_BYTES:
            with open_binary() as stream:
                inspection["api_reference_categories"] = scan_api_references(stream, size)
        else:
            inspection["api_reference_categories"] = []
            inspection["reference_scan_note"] = "Binary exceeds the 256 MB reference scan limit"
    else:
        inspection["api_reference_categories"] = []
    binaries = report.inventory.setdefault("ios_binaries", [])
    if isinstance(binaries, list):
        binaries.append(inspection)


def _finish_binary_inventory(report: Report) -> None:
    binaries = report.inventory.get("ios_binaries", [])
    if not isinstance(binaries, list) or not binaries:
        report.warnings.append("No iOS executable was available for Mach-O inspection")
        return
    counts = {
        "not_encrypted": sum(item.get("encryption") == "not_encrypted" for item in binaries),
        "encrypted": sum(item.get("encryption") in {"encrypted", "mixed"} for item in binaries),
        "unknown": sum(item.get("encryption") == "unknown" for item in binaries),
        "uninspected": max(0, report.inventory.get("ios_binary_candidates", len(binaries)) - len(binaries)),
    }
    report.inventory["ios_binary_visibility"] = counts
    app_bundles = [item for item in report.inventory.get("ios_bundles", [])
                   if isinstance(item, dict) and item.get("kind") == "app"
                   and isinstance(item.get("executable"), str)]
    if app_bundles:
        main = min(app_bundles, key=lambda item: (str(item.get("location", "")).count("/"),
                                                  len(str(item.get("location", "")))))
        parent = PurePosixPath(str(main.get("location", ""))).parent
        location = str(parent / main["executable"]) if str(parent) != "." else main["executable"]
        inspected = next((item for item in binaries if item.get("location") == location), None)
        report.inventory["ios_main_executable"] = {
            "location": location,
            "encryption": inspected.get("encryption", "unknown") if inspected else "uninspected",
        }
    report.coverage.append("iOS Mach-O load commands and encryption state")
    if counts["not_encrypted"]:
        report.coverage.append("Readable iOS binary API-name references")
    if counts["encrypted"]:
        report.warnings.append(
            "Encrypted iOS executable code was not inspected; load commands and bundled resources remain available"
        )


def scan_info_plist(data: bytes, location: str, report: Report) -> None:
    try:
        plist = plistlib.loads(data)
    except (ValueError, TypeError, OverflowError) as exc:
        report.warnings.append(f"Could not parse {location}: {exc}")
        return
    if not isinstance(plist, dict):
        report.warnings.append(f"Unexpected plist structure in {location}")
        return

    bundle = plist.get("CFBundleIdentifier")
    if isinstance(bundle, str):
        bundles = report.inventory.setdefault("ios_bundles", [])
        if isinstance(bundles, list) and len(bundles) < MAX_IOS_BUNDLES:
            bundles.append({
                "location": location, "kind": _bundle_kind(location), "bundle_id": bundle,
                "display_name": next((plist[key] for key in ("CFBundleDisplayName", "CFBundleName")
                                      if isinstance(plist.get(key), str)), None),
                "version": plist.get("CFBundleShortVersionString") if isinstance(plist.get("CFBundleShortVersionString"), str) else None,
                "build": plist.get("CFBundleVersion") if isinstance(plist.get("CFBundleVersion"), str) else None,
                "minimum_ios": plist.get("MinimumOSVersion") if isinstance(plist.get("MinimumOSVersion"), str) else None,
                "executable": plist.get("CFBundleExecutable") if isinstance(plist.get("CFBundleExecutable"), str) else None,
                "background_modes": sorted(item for item in plist.get("UIBackgroundModes", [])[:50]
                                           if isinstance(item, str)) if isinstance(plist.get("UIBackgroundModes"), list) else [],
            })
    permissions = report.inventory.setdefault("ios_privacy_permissions", [])
    if isinstance(permissions, list):
        for key in sorted(plist):
            if isinstance(key, str) and key.startswith("NS") and key.endswith("UsageDescription") and len(permissions) < 300:
                purpose = plist[key]
                permissions.append({"location": location, "key": key,
                                    "purpose_provided": isinstance(purpose, str) and bool(purpose.strip())})
    url_types = plist.get("CFBundleURLTypes")
    if isinstance(url_types, list):
        for group in url_types[:50]:
            if isinstance(group, dict) and isinstance(group.get("CFBundleURLSchemes"), list):
                for scheme in group["CFBundleURLSchemes"][:50]:
                    if isinstance(scheme, str) and re.fullmatch(r"[A-Za-z][A-Za-z0-9+.-]{0,99}", scheme):
                        _entry_point(report, "custom_url_scheme", scheme, location,
                                     "Open a controlled link while signed out and as a second test account; check authorization and input handling.")
    document_types = plist.get("CFBundleDocumentTypes")
    if isinstance(document_types, list):
        for group in document_types[:50]:
            if isinstance(group, dict) and isinstance(group.get("LSItemContentTypes"), list):
                for content_type in group["LSItemContentTypes"][:50]:
                    if isinstance(content_type, str):
                        _entry_point(report, "document_type", content_type, location,
                                     "Open a benign test document of this type and inspect import validation and file access.")
    ats = plist.get("NSAppTransportSecurity", {})
    if not isinstance(ats, dict):
        ats = {}
    exceptions = ats.get("NSExceptionDomains", {})
    if not isinstance(exceptions, dict):
        exceptions = {}
    nested_ats = ats.get("NSAppTransportSecurity")
    nested_ats_keys = {"NSExceptionDomains", "NSAllowsArbitraryLoads", "NSAllowsArbitraryLoadsForMedia",
                       "NSAllowsArbitraryLoadsInWebContent", "NSAllowsLocalNetworking"}
    malformed_nesting = isinstance(nested_ats, dict) and bool(nested_ats_keys.intersection(nested_ats))
    transports = report.inventory.setdefault("ios_transport_security", [])
    if isinstance(transports, list) and len(transports) < 300:
        transports.append({
            "location": location,
            "global_arbitrary_loads": ats.get("NSAllowsArbitraryLoads") is True,
            "web_arbitrary_loads": ats.get("NSAllowsArbitraryLoadsInWebContent") is True,
            "media_arbitrary_loads": ats.get("NSAllowsArbitraryLoadsForMedia") is True,
            "local_networking": ats.get("NSAllowsLocalNetworking") is True,
            "exception_domains": sorted(str(domain) for domain in exceptions)[:100],
            "nested_ats_configuration": malformed_nesting,
        })

    if malformed_nesting:
        report.add(Finding(
            "IOS-ATS-NESTED-CONFIG", "ATS settings nested at the wrong level", "ios", "medium", "high",
            location, "NSAppTransportSecurity.NSAppTransportSecurity contains ATS settings",
            "Place supported ATS keys directly in the documented NSAppTransportSecurity dictionary and verify the effective policy.",
            "MASVS-NETWORK-1", None,
        ))

    # Apple ignores the global key when any of these scoped exception keys are present.
    scoped_keys = {"NSAllowsArbitraryLoadsForMedia", "NSAllowsArbitraryLoadsInWebContent", "NSAllowsLocalNetworking"}
    if ats.get("NSAllowsArbitraryLoads") is True and not scoped_keys.intersection(ats):
        report.add(Finding(
            "IOS-ATS-GLOBAL", "App Transport Security disabled globally", "ios", "high", "high",
            location, "NSAppTransportSecurity.NSAllowsArbitraryLoads = true",
            "Use HTTPS and remove the global exception; scope any necessary exception to a specific domain.",
            "MASVS-NETWORK-1", "MASWE-0026",
        ))
    if ats.get("NSAllowsArbitraryLoadsInWebContent") is True:
        report.add(Finding(
            "IOS-ATS-WEB", "Web content may load insecure resources", "ios", "medium", "high",
            location, "NSAllowsArbitraryLoadsInWebContent = true",
            "Review WebView destinations and use HTTPS wherever possible.",
            "MASVS-NETWORK-1", "MASWE-0026",
        ))
    for domain, settings in sorted(exceptions.items()):
        if isinstance(settings, dict) and settings.get("NSExceptionAllowsInsecureHTTPLoads") is True:
            report.add(Finding(
                "IOS-ATS-DOMAIN", "Domain permits insecure HTTP loads", "ios", "medium", "high",
                location, f"NSExceptionDomains[{domain!r}].NSExceptionAllowsInsecureHTTPLoads = true",
                "Verify the exception is needed and restrict it to the smallest possible domain and duration.",
                "MASVS-NETWORK-1", "MASWE-0026",
            ))

    if plist.get("UIFileSharingEnabled") is True:
        report.add(Finding(
            "IOS-FILE-SHARING", "App Documents are exposed through file sharing", "ios", "low", "high",
            location, "UIFileSharingEnabled = true",
            "Confirm the Documents directory contains only files users are intended to access; store private data elsewhere.",
            "MASVS-STORAGE-1", "MASWE-0002",
        ))
    report.coverage.append("iOS Info.plist and ATS configuration")


def scan_entitlements(data: bytes, location: str, report: Report, *, signed: bool) -> None:
    try:
        entitlements = plistlib.loads(data)
    except (ValueError, TypeError, OverflowError):
        return
    if not isinstance(entitlements, dict):
        return
    report.inventory.setdefault("ios_entitlements", []).append({
        "location": location,
        "signed": signed,
        "keys": sorted(entitlements.keys()),
    })
    domains = entitlements.get("com.apple.developer.associated-domains")
    if isinstance(domains, list):
        for domain in domains[:100]:
            if isinstance(domain, str) and domain.startswith("applinks:"):
                _entry_point(report, "universal_link_domain", domain, location,
                             "Open a controlled universal link as a signed-out user and as a second test account.")
    if entitlements.get("get-task-allow") is True or entitlements.get("com.apple.security.get-task-allow") is True:
        report.add(Finding(
            "IOS-DEBUG-ENTITLEMENT", "Debug entitlement enabled", "ios",
            "high" if signed else "low", "high" if signed else "medium",
            location, "get-task-allow = true" + (" in signed app" if signed else " in source entitlement file"),
            "Ensure release signing removes the debugging entitlement.",
            "MASVS-RESILIENCE-2", "MASWE-0063",
        ))
    report.coverage.append("iOS entitlement configuration")


def _signed_entitlements(bundle: Path) -> bytes | None:
    if not shutil.which("codesign"):
        return None
    try:
        result = subprocess.run(
            ["codesign", "-d", "--entitlements", ":-", str(bundle)],
            capture_output=True, check=False, timeout=20,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    data = result.stdout.strip()
    if data.startswith((b"<?xml", b"<plist", b"bplist")):
        return data
    return None


def scan_app_bundle(path: Path, report: Report) -> None:
    _package_file_info(path, report)
    candidates = [p for p in path.rglob("Info.plist")
                  if p.is_file() and p.stat().st_size <= MAX_CONFIG_BYTES
                  and (p.parent == path or p.parent.suffix.lower() in {".appex", ".framework", ".bundle"})]
    binaries: set[Path] = set()
    for plist_path in sorted(candidates):
        data = read_small(plist_path)
        if data is not None:
            scan_info_plist(data, plist_path.relative_to(path).as_posix(), report)
            try:
                info = plistlib.loads(data)
            except (ValueError, TypeError, OverflowError):
                info = None
            if isinstance(info, dict):
                executable = info.get("CFBundleExecutable")
                if isinstance(executable, str) and executable == Path(executable).name:
                    candidate = plist_path.parent / executable
                    if candidate.is_file() and not candidate.is_symlink():
                        binaries.add(candidate)
    for candidate in path.rglob("*.dylib"):
        if candidate.is_file() and not candidate.is_symlink():
            binaries.add(candidate)
    for framework in path.rglob("*.framework"):
        candidate = framework / framework.stem
        if candidate.is_file() and not candidate.is_symlink():
            binaries.add(candidate)
    report.inventory["ios_binary_candidates"] = len(binaries)
    for candidate in sorted(binaries, key=lambda item: (0 if item.parent == path else
                            1 if any(part.endswith(".appex") for part in item.relative_to(path).parts) else 2,
                            str(item)))[:MAX_IOS_BINARIES]:
        try:
            _inspect_binary(lambda candidate=candidate: candidate.open("rb"), candidate.stat().st_size,
                            candidate.relative_to(path).as_posix(), report)
        except OSError as exc:
            report.warnings.append(f"Could not inspect {candidate.name}: {exc}")
    if len(binaries) > MAX_IOS_BINARIES:
        report.warnings.append(f"Only the first {MAX_IOS_BINARIES} prioritized iOS executables were inspected")
    assets = [candidate for candidate in path.rglob("*")
              if candidate.is_file() and not candidate.is_symlink()
              and candidate.suffix.lower() in SOURCE_LIKE_SUFFIXES]
    report.inventory["ios_plaintext_code_assets"] = [
        {"location": candidate.relative_to(path).as_posix(), "size": candidate.stat().st_size}
        for candidate in sorted(assets)[:300]
    ]
    if len(assets) > 300:
        report.warnings.append("Only the first 300 plaintext code assets were listed")
    for candidate in sorted(assets)[:300]:
        data = read_small(candidate, 1024 * 1024)
        if data is not None:
            _scan_code_asset(data, candidate.relative_to(path).as_posix(), report)
    for manifest in sorted(path.rglob("*.xcprivacy"))[:300]:
        if manifest.is_file() and not manifest.is_symlink():
            data = read_small(manifest)
            if data is not None:
                _scan_privacy_manifest(data, manifest.relative_to(path).as_posix(), report)
    _finish_binary_inventory(report)
    if not candidates:
        report.warnings.append("No Info.plist found in app bundle")
    signed = _signed_entitlements(path)
    if signed:
        scan_entitlements(signed, f"{path.name} (signed entitlements)", report, signed=True)
    else:
        report.warnings.append("Signed entitlements could not be read from the app bundle")
    report.inventory["ios_signatures"] = [_code_signature_metadata(path, path.name, verify_bundle=True)]
    report.coverage.append("iOS code-signature metadata and bundle verification")


def scan_ipa(path: Path, report: Report) -> None:
    with zipfile.ZipFile(path) as archive:
        entries = checked_zip_entries(archive)
        _package_file_info(path, report, entries=entries)
        by_name = {item.filename: item for item in entries}
        plists = [
            item for item in entries
            if item.filename.startswith("Payload/") and _is_bundle_info_plist(item.filename)
        ]
        plists.sort(key=lambda item: _executable_priority(item.filename))
        if len(plists) > MAX_IOS_BUNDLES:
            report.warnings.append(f"Only the first {MAX_IOS_BUNDLES} prioritized iOS bundle declarations were retained")
        binary_names: set[str] = set()
        signed_executables: list[tuple[str, zipfile.ZipInfo]] = []
        for item in plists:
            data = read_zip_member(archive, item)
            if data is not None:
                scan_info_plist(data, item.filename, report)
                try:
                    info = plistlib.loads(data)
                except (ValueError, TypeError, OverflowError):
                    info = None
                if isinstance(info, dict):
                    executable = info.get("CFBundleExecutable")
                    if isinstance(executable, str) and executable == PurePosixPath(executable).name:
                        name = str(PurePosixPath(item.filename).parent / executable)
                        if name in by_name:
                            binary_names.add(name)
                            signed_executables.append((name, by_name[name]))
                        else:
                            report.warnings.append(f"Declared iOS executable was not found: {name}")
        assets: list[dict[str, object]] = []
        asset_count = 0
        for item in entries:
            if not item.filename.startswith("Payload/") or item.is_dir():
                continue
            member = PurePosixPath(item.filename)
            if not any(part.endswith((".app", ".appex")) for part in member.parts):
                continue
            if member.suffix.lower() in SOURCE_LIKE_SUFFIXES:
                asset_count += 1
                if len(assets) < 300:
                    assets.append({"location": item.filename, "size": item.file_size})
            parts = member.parts
            is_framework_executable = any(
                part.endswith(".framework") and index + 2 == len(parts)
                and parts[index + 1] == part.removesuffix(".framework")
                for index, part in enumerate(parts)
            )
            if member.suffix.lower() == ".dylib" or is_framework_executable:
                binary_names.add(item.filename)
        report.inventory["ios_plaintext_code_assets"] = assets
        if asset_count > 300:
            report.warnings.append("Only the first 300 plaintext code assets were listed")
        for asset in assets:
            item = by_name[asset["location"]]
            data = read_zip_member(archive, item, 1024 * 1024)
            if data is not None:
                _scan_code_asset(data, item.filename, report)
        manifests = [item for item in entries if item.filename.startswith("Payload/")
                     and item.filename.endswith(".xcprivacy") and not item.is_dir()]
        if len(manifests) > 300:
            report.warnings.append("Only the first 300 iOS privacy manifests were inspected")
        for item in manifests[:300]:
            data = read_zip_member(archive, item)
            if data is not None:
                _scan_privacy_manifest(data, item.filename, report)
        report.inventory["ios_binary_candidates"] = len(binary_names)
        for name in sorted(binary_names, key=_executable_priority)[:MAX_IOS_BINARIES]:
            item = by_name[name]
            try:
                _inspect_binary(lambda item=item: archive.open(item), item.file_size, name, report)
            except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
                report.warnings.append(f"Could not inspect {name}: {exc}")
        if len(binary_names) > MAX_IOS_BINARIES:
            report.warnings.append(f"Only the first {MAX_IOS_BINARIES} prioritized iOS executables were inspected")
        _finish_binary_inventory(report)
        if not plists:
            report.warnings.append("IPA has no Payload/*.app/Info.plist")

        # Entitlements live in each signed Mach-O; the full IPA need not be unpacked.
        report.inventory["ios_signatures"] = []
        signed_executables.sort(key=lambda item: _executable_priority(item[0]))
        report.inventory["ios_signature_candidates"] = len(signed_executables)
        if len(signed_executables) > MAX_IOS_SIGNATURES:
            report.warnings.append(f"Only the first {MAX_IOS_SIGNATURES} prioritized executable signatures were inspected")
        if signed_executables and shutil.which("codesign"):
            with tempfile.TemporaryDirectory(prefix="mobile-audit-ipa-") as temp:
                signed_count = 0
                signatures: list[dict[str, object]] = []
                for index, (name, item) in enumerate(signed_executables[:MAX_IOS_SIGNATURES]):
                    if item.file_size > 512 * 1024 * 1024:
                        report.warnings.append(f"Skipped signed entitlements in oversized executable: {name}")
                        continue
                    executable = Path(temp) / f"executable-{index}"
                    with archive.open(item) as source, executable.open("wb") as output:
                        copied = 0
                        while block := source.read(1024 * 1024):
                            copied += len(block)
                            if copied > 512 * 1024 * 1024:
                                raise ValueError("iOS executable exceeds the 512 MB entitlement inspection limit")
                            output.write(block)
                    signatures.append(_code_signature_metadata(executable, name, verify_bundle=False))
                    data = _signed_entitlements(executable)
                    executable.unlink(missing_ok=True)
                    if data:
                        scan_entitlements(data, f"{name} (signed entitlements)", report, signed=True)
                        signed_count += 1
                if signed_count == 0:
                    report.warnings.append("Signed entitlements could not be read from the IPA")
                report.inventory["ios_signatures"] = signatures
                report.coverage.append("iOS executable code-signature metadata (bundle verification unavailable)")
        elif signed_executables:
            report.inventory["ios_signatures"] = [
                {"location": name, "metadata_status": "unavailable", "verification": "not_performed",
                 "note": "codesign is unavailable on this host"}
                for name, _ in signed_executables[:MAX_IOS_SIGNATURES]
            ]
            report.warnings.append("Code-signature metadata and signed entitlements could not be read: codesign is unavailable")
        else:
            report.warnings.append("No declared app or extension executable was available for code-signature inspection")


def _scan_code_asset(data: bytes, location: str, report: Report) -> None:
    suffix = PurePosixPath(location).suffix.lower()
    if suffix == ".map":
        try:
            document = json.loads(data)
            for index, (_, _, content) in enumerate(_embedded_sources(document)):
                if index >= 50:
                    report.warnings.append(f"Only the first 50 embedded sources were checked in {location}")
                    break
                if len(content) <= 1024 * 1024:
                    scan_web_code(content, f"{location}#source-{index + 1}", report)
        except (ValueError, UnicodeDecodeError, RecursionError):
            return
    elif suffix in {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".html", ".htm"}:
        try:
            scan_web_code(data.decode("utf-8"), location, report)
        except UnicodeDecodeError:
            return


_WEAK_KEYCHAIN = re.compile(r"\bkSecAttrAccessibleAlways(?:ThisDeviceOnly)?\b")
_WEAK_CRYPTO = re.compile(r"\b(?:CC_MD5|CC_SHA1|Insecure\.MD5|Insecure\.SHA1|kCCAlgorithmDES|kCCAlgorithmRC4)\b")
_USER_DEFAULTS = re.compile(r"\b(?:UserDefaults(?:\.standard)?|NSUserDefaults)\b")
_SENSITIVE_NAME = re.compile(r"(?i)\b(?:access.?token|refresh.?token|auth.?token|password|secret|credential|private.?key|chat.?history)\b")
_USER_DEFAULTS_KEY = re.compile(r"\bforKey\s*:\s*(['\"])([^'\"]{1,100})\1")
_TRUST_EXCEPTION = re.compile(r"\b(?:SecTrustSetExceptions\b|URLCredential\s*\(\s*trust\s*:)")
_SWIFT_LITERAL = re.compile(
    r"""\b(?:let|var)\s+(?P<name>[A-Za-z_]\w*)\s*(?::\s*String)?\s*=\s*(?P<quote>["'])(?P<value>[^"'\\\r\n]{8,128})(?P=quote)"""
)
_CRYPTO_USE = re.compile(r"\b(?:CCCrypt|CryptoKit|AESCrypto|SymmetricKey|kCCAlgorithm\w*|kCCKeySize\w*)\b")
_CRYPTO_KEY_NAME = re.compile(r"(?i)(?:^key$|(?:aes|crypto|cipher|encrypt|decrypt|symmetric|secret)\w*key$)")
_CRYPTO_IV_NAME = re.compile(r"(?i)^(?:iv|nonce|initializationVector)$")
_HTTP_URL = re.compile(
    r"""\b(?:NS)?URL\s*\(\s*string\s*:\s*(["'])http://(?!localhost(?:[:/]|$)|127\.0\.0\.1(?:[:/]|$)|10\.0\.2\.2(?:[:/]|$))[^"'\r\n]{1,200}\1""",
    re.IGNORECASE,
)
_KEY_PLACEHOLDER = re.compile(r"(?i)^(?:example|placeholder|changeme|your[_ -]|test[_ -]|dummy|xxxx|0000|<|\$\{|\{\{)")


def scan_ios_code(text: str, location: str, report: Report) -> None:
    lines = []
    in_block_comment = False
    for original in text.splitlines():
        code, in_block_comment = without_code_comments(original, in_block_comment)
        lines.append(code)
    has_crypto_use = bool(_CRYPTO_USE.search("\n".join(lines)))
    for number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        where = f"{location}:{number}"
        if has_crypto_use:
            literal = _SWIFT_LITERAL.search(line)
            if literal:
                name, value = literal.group("name"), literal.group("value")
                if not _KEY_PLACEHOLDER.search(value) and len(set(value)) > 2 and "\\(" not in value:
                    if _CRYPTO_KEY_NAME.search(name):
                        report.add(Finding(
                            "IOS-STATIC-CRYPTO-KEY", "Cryptographic key literal in iOS source",
                            "ios", "medium", "high", where,
                            f"{name} is assigned a fixed literal in code using cryptography (value redacted)",
                            "Confirm how the key is used; generate and protect device-specific keys in Keychain where appropriate.",
                            "MASVS-STORAGE-1", "MASWE-0004",
                        ))
                    elif _CRYPTO_IV_NAME.fullmatch(name):
                        report.add(Finding(
                            "IOS-STATIC-CRYPTO-IV", "Fixed cryptographic IV or nonce in iOS source",
                            "ios", "medium", "medium", where,
                            f"{name} is assigned a fixed literal in code using cryptography (value redacted)",
                            "Confirm this value reaches encryption; use a fresh IV or nonce for each operation as required by the mode.",
                            "MASVS-CRYPTO-1", "MASWE-0007",
                        ))
        if _HTTP_URL.search(line):
            report.add(Finding(
                "IOS-CLEARTEXT-URL", "HTTP URL constructed in iOS source",
                "ios", "medium", "low", where,
                "URL(string:) contains an HTTP endpoint (destination redacted); no network connection was observed",
                "Trace the URL to a reachable request and check ATS behavior; use HTTPS for network traffic.",
                "MASVS-NETWORK-1", "MASWE-0026",
            ))
        match = _WEAK_KEYCHAIN.search(line)
        if match:
            report.add(Finding(
                "IOS-KEYCHAIN-ACCESS", "Deprecated Keychain accessibility class", "ios", "medium", "high",
                f"{location}:{number}", f"Uses {match.group(0)}",
                "Choose a current Keychain accessibility class appropriate for when the data must be available.",
            "MASVS-STORAGE-1", None,
            ))
        match = _WEAK_CRYPTO.search(line)
        if match:
            is_hash = match.group(0) in {"CC_MD5", "CC_SHA1", "Insecure.MD5", "Insecure.SHA1"}
            report.add(Finding(
                "IOS-WEAK-CRYPTO", "Weak cryptographic API needs review", "ios", "medium", "medium",
                f"{location}:{number}", f"Uses {match.group(0)}; context determines security impact",
                "Use a modern algorithm for security-sensitive hashing or encryption; check whether this use is only a checksum.",
                "MASVS-CRYPTO-1", "MASWE-0008" if is_hash else "MASWE-0007",
            ))
        context = "\n".join(lines[max(0, number - 10):number])
        write = re.search(r"\b(?:set|setObject|setValue)\s*\(\s*([^,)]*)", line)
        key = _USER_DEFAULTS_KEY.search(line)
        sensitive = sensitive_storage_key(key.group(2)) if key else None
        if not sensitive and write:
            match = _SENSITIVE_NAME.search(write.group(1))
            sensitive = match.group(0) if match else None
        if not sensitive and not key:
            match = _SENSITIVE_NAME.search(context)
            sensitive = match.group(0) if match else None
        if _USER_DEFAULTS.search(line) and sensitive and write:
            report.add(Finding(
                "IOS-USERDEFAULTS-SENSITIVE", "Possible sensitive value stored in UserDefaults", "ios", "medium", "medium",
                f"{location}:{number}", f"UserDefaults write near {sensitive} (value redacted)",
                "Confirm the stored value; use Keychain for secrets and protected file storage for larger personal data.",
                "MASVS-STORAGE-1", "MASWE-0001",
            ))
        match = _TRUST_EXCEPTION.search(line)
        if match:
            report.add(Finding(
                "IOS-CUSTOM-TRUST", "Custom server trust handling needs review", "ios", "medium", "low",
                f"{location}:{number}", f"Uses {match.group(0).strip()}",
                "Review the full trust validation path; do not accept a server certificate without proper validation.",
                "MASVS-NETWORK-1", "MASWE-0027",
            ))
    report.coverage.append("iOS Swift and Objective-C source patterns")
