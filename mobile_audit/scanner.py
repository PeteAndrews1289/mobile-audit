from __future__ import annotations

import plistlib
import re
import zipfile
from pathlib import Path

from .android import scan_android_code, scan_apk, scan_manifest, scan_network_config
from .code_text import without_code_comments
from .flutter import scan_dart_code
from .ios import scan_app_bundle, scan_entitlements, scan_info_plist, scan_ios_code, scan_ipa
from .webcode import scan_web_code
from .models import Finding, Report, relative_location
from .utils import (
    MAX_CONFIG_BYTES, MAX_SOURCE_BYTES, checked_zip_entries, project_files,
    read_small, read_zip_member,
)


_SOURCE_CODE = {".swift", ".m", ".mm", ".h", ".kt", ".java", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".dart"}
_SECRET_TEXT = _SOURCE_CODE | {".xml", ".json", ".properties", ".gradle", ".xcconfig", ".env", ".txt"}
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(client[_-]?secret|private[_-]?key|secret[_-]?key|api[_-]?secret|"
    r"access[_-]?token|refresh[_-]?token|auth[_-]?token|password)\b"
    r"[\"']?\s*[=:]\s*[\"']([^\"'\r\n]{8,})[\"']"
)
_AUTH_NAME = re.compile(r"(?i)(?:[A-Za-z_]\w*)?(?:password|passcode|pin|otp|auth_?token|access_?token)\Z")
_CODE_TOKEN = re.compile(r"[A-Za-z_]\w*|==|\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'")
_INLINE_SECRET_VALUE = re.compile(
    r"(?i)\b(?P<name>client[_-]?secret|private[_-]?key|secret[_-]?key|api[_-]?secret|"
    r"access[_-]?token|refresh[_-]?token|auth[_-]?token|password)\s*[:=]\s*"
    r"(?P<value>[A-Za-z0-9_!@#$%^&*?./+-]{8,})"
)
_PLACEHOLDER = re.compile(r"(?i)^(?:example|placeholder|changeme|your[_ -]|test[_ -]|dummy|xxxx|0000|<|\$\{|\{\{)")
_PRIVATE_KEY = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")
_SECRET_KEY = re.compile(r"(?i)^(?:client[_-]?secret|private[_-]?key|secret[_-]?key|api[_-]?secret|access[_-]?token|refresh[_-]?token|auth[_-]?token|password)$")


def _scan_secrets(text: str, location: str, platform: str, report: Report) -> None:
    if _PRIVATE_KEY.search(text):
        report.add(Finding(
            "MOBILE-PRIVATE-KEY", "Private key embedded in application source", platform,
            "high", "high", location, "PEM private-key block present (key redacted)",
            "Remove the key from the client and rotate it if it has been distributed.",
            "MASVS-STORAGE-1", "MASWE-0004",
        ))
    in_block = False
    is_code = Path(location).suffix.lower() in _SOURCE_CODE
    for number, line in enumerate(text.splitlines(), 1):
        for match in _SECRET_ASSIGNMENT.finditer(line):
            value = match.group(2).strip()
            if _PLACEHOLDER.search(value) or len(set(value)) <= 2:
                continue
            report.add(Finding(
                "MOBILE-HARDCODED-SECRET", "Possible hardcoded credential", platform,
                "medium", "medium", f"{location}:{number}",
                f"Literal assigned to {match.group(1)} (value redacted)",
                "Confirm whether this is a real credential; keep server secrets off the client and rotate exposed values.",
                "MASVS-STORAGE-1", "MASWE-0004",
            ))
        if not is_code:
            continue
        code, in_block = without_code_comments(line, in_block)
        tokens = [match.group(0) for match in _CODE_TOKEN.finditer(code)]
        for index in range(len(tokens) - 2):
            name, operator, literal = tokens[index:index + 3]
            if not _AUTH_NAME.fullmatch(name) or operator != "==" or not literal.startswith(("'", '"')):
                continue
            value = literal[1:-1].strip()
            if not 4 <= len(value) <= 128:
                continue
            if _PLACEHOLDER.search(value) or len(set(value)) <= 2:
                continue
            report.add(Finding(
                "MOBILE-AUTH-LITERAL-CHECK", "Fixed literal in authentication-related comparison", platform,
                "medium", "low", f"{location}:{number}",
                f"{name} compared to a fixed literal (value redacted)",
                "Trace the branch to learn whether it grants or denies access; enforce authentication on a trusted server.",
                "MASVS-AUTH-1", None,
            ))


def _scan_plist_secrets(data: bytes, location: str, platform: str, report: Report) -> None:
    try:
        plist = plistlib.loads(data)
    except (ValueError, TypeError, OverflowError):
        return

    def visit(value: object, trail: str = "") -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                name = str(key)
                path = f"{trail}.{name}" if trail else name
                if _SECRET_KEY.fullmatch(name) and isinstance(item, str) and len(item) >= 8 and not _PLACEHOLDER.search(item):
                    report.add(Finding(
                        "MOBILE-HARDCODED-SECRET", "Possible hardcoded credential", platform,
                        "medium", "medium", location, f"Literal at plist key {path} (value redacted)",
                        "Confirm whether this is a real credential; keep server secrets off the client and rotate exposed values.",
                        "MASVS-STORAGE-1", "MASWE-0004",
                    ))
                elif isinstance(item, str):
                    match = _INLINE_SECRET_VALUE.search(item)
                    if match and not _PLACEHOLDER.search(match.group("value")):
                        report.add(Finding(
                            "MOBILE-HARDCODED-SECRET", "Possible hardcoded credential", platform,
                            "medium", "low", location,
                            f"Credential-like assignment inside plist key {path} (value redacted)",
                            "Confirm whether the value is a real credential; keep server secrets out of app resources and rotate exposed values.",
                            "MASVS-STORAGE-1", "MASWE-0004",
                        ))
                visit(item, path)
        elif isinstance(value, list):
            for index, item in enumerate(value):
                visit(item, f"{trail}[{index}]")

    visit(plist)


def _scan_package_resources(path: Path, platform: str, report: Report) -> None:
    with zipfile.ZipFile(path) as archive:
        entries = checked_zip_entries(archive)
        for item in entries:
            if item.is_dir():
                continue
            suffix = Path(item.filename).suffix.lower()
            if suffix not in {".plist", ".json", ".pem", ".key", ".txt", ".properties"}:
                continue
            data = read_zip_member(archive, item, MAX_CONFIG_BYTES)
            if data is None:
                continue
            if suffix == ".plist":
                _scan_plist_secrets(data, item.filename, platform, report)
            try:
                text = data.decode("utf-8")
            except UnicodeDecodeError:
                continue
            _scan_secrets(text, item.filename, platform, report)
    report.coverage.append("Package resource credential patterns")


def scan_source(root: Path, report: Report) -> None:
    scanned = 0
    for path in project_files(root):
        location = relative_location(path, root)
        suffix = path.suffix.lower()
        if path.name == "Info.plist" or path.name.endswith("-Info.plist"):
            data = read_small(path)
            if data is not None:
                scan_info_plist(data, location, report)
                _scan_plist_secrets(data, location, "ios", report)
                scanned += 1
            continue
        if suffix == ".plist":
            data = read_small(path)
            if data is not None:
                _scan_plist_secrets(data, location, "ios", report)
                scanned += 1
            continue
        if suffix == ".entitlements":
            data = read_small(path)
            if data is not None:
                scan_entitlements(data, location, report, signed=False)
                scanned += 1
            continue
        if path.name == "AndroidManifest.xml":
            data = read_small(path)
            if data is not None:
                scan_manifest(data, location, report)
                scanned += 1
            continue
        if suffix == ".xml" and "network_security" in path.name:
            data = read_small(path)
            if data is not None:
                scan_network_config(data, location, report)
                scanned += 1
            continue
        if suffix not in _SECRET_TEXT or path.stat().st_size > MAX_SOURCE_BYTES:
            continue
        data = read_small(path, MAX_SOURCE_BYTES)
        if data is None:
            continue
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if suffix in {".swift", ".m", ".mm", ".h"}:
            scan_ios_code(text, location, report)
            platform = "ios"
        elif suffix in {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx"}:
            scan_web_code(text, location, report)
            platform = "ios"
        elif suffix in {".kt", ".java"}:
            scan_android_code(text, location, report)
            platform = "android"
        elif suffix == ".dart":
            scan_dart_code(text, location, report)
            platform = "mobile"
        else:
            platform = "mobile"
        _scan_secrets(text, location, platform, report)
        scanned += 1
    report.inventory["source_files_checked"] = scanned
    report.coverage.append("Source configuration and embedded credential patterns")


def scan(target: Path, source: Path | None = None) -> Report:
    target = target.expanduser().resolve()
    if not target.exists():
        raise FileNotFoundError(target)
    if source is not None:
        source = source.expanduser().resolve()
        if not source.is_dir():
            raise ValueError("--source must point to a source directory")
    report = Report(target=str(target))
    if target.is_dir() and target.suffix == ".app":
        report.inventory["input_type"] = "app_bundle"
        scan_app_bundle(target, report)
    elif target.is_dir():
        report.inventory["input_type"] = "source"
        scan_source(target, report)
    elif target.suffix.lower() == ".ipa":
        report.inventory["input_type"] = "ipa"
        scan_ipa(target, report)
        _scan_package_resources(target, "ios", report)
    elif target.suffix.lower() == ".apk":
        report.inventory["input_type"] = "apk"
        scan_apk(target, report)
        _scan_package_resources(target, "android", report)
    else:
        raise ValueError("Target must be a source directory, .app bundle, .ipa, or .apk")
    if source and source != target:
        scan_source(source, report)
        report.inventory["source_root"] = str(source)
    return report
