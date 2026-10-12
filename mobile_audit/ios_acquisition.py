"""Mac-side App Store IPA acquisition and evidence-preserving intake.

ipatool handles App Store authentication and transport. Mobile Audit never
accepts Apple Account credentials or reads ipatool's session files.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path

from .evidence import utc_now
from .research import build_research_scan
from .research_reporting import write_research_bundle
from .utils import checked_zip_entries


_BUNDLE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$")
_MAX_IPA_BYTES = 2_000_000_000


def find_ipatool(backend: str | None = None) -> str:
    located = shutil.which(backend or "ipatool")
    if not located:
        raise RuntimeError("ipatool is unavailable; run 'mobile-audit acquire-ios setup' on this Mac")
    return located


def ipatool_version(backend: str) -> str:
    try:
        completed = subprocess.run([backend, "--version"], capture_output=True, text=True,
                                   stdin=subprocess.DEVNULL, timeout=10, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return "unknown"
    version = (completed.stdout or completed.stderr).strip()
    return version[:100] if completed.returncode == 0 and version else "unknown"


def run_ipatool_interactive(args: list[str], *, backend: str | None = None) -> int:
    """Pass terminal input and output directly to ipatool, without recording it."""
    executable = find_ipatool(backend)
    try:
        return subprocess.run([executable, *args], check=False).returncode
    except OSError as exc:
        raise RuntimeError("Could not start ipatool") from exc


def _check_archive(path: Path) -> None:
    if not path.is_file() or path.stat().st_size == 0:
        raise ValueError("ipatool did not produce an IPA file")
    if path.stat().st_size > _MAX_IPA_BYTES:
        raise ValueError("Downloaded IPA exceeds the 2 GB intake limit")
    with zipfile.ZipFile(path) as archive:
        entries = checked_zip_entries(archive)
        main_plists = [item for item in entries if
                       len(item.filename.split("/")) == 3 and
                       item.filename.startswith("Payload/") and
                       item.filename.split("/")[1].endswith(".app") and
                       item.filename.endswith("/Info.plist")]
        if len(main_plists) != 1:
            raise ValueError("IPA must contain exactly one main Payload/*.app/Info.plist")
        if archive.testzip() is not None:
            raise ValueError("Downloaded IPA failed ZIP integrity verification")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def _main_bundle(report: dict[str, object]) -> dict[str, object]:
    profile = report.get("package_profile", {})
    bundles = profile.get("ios_bundles", []) if isinstance(profile, dict) else []
    main = [item for item in bundles if isinstance(item, dict) and
            len(str(item.get("location", "")).split("/")) == 3 and
            str(item.get("location", "")).startswith("Payload/") and
            str(item.get("location", "")).endswith(".app/Info.plist")]
    if len(main) != 1 or not isinstance(main[0].get("bundle_id"), str) or not _BUNDLE_ID.fullmatch(main[0]["bundle_id"]):
        raise ValueError("Downloaded IPA has no identifiable main app bundle")
    return main[0]


def acquire_ios_app(*, output: Path, bundle_id: str | None = None,
                    app_id: int | None = None, phone_version: str | None = None,
                    name: str | None = None, privacy_report: Path | None = None,
                    iphone_report: Path | None = None, ios_version: str | None = None,
                    backend: str | None = None) -> dict[str, object]:
    """Download, verify, and scan one licensed iPhone app into a new directory."""
    if (bundle_id is None) == (app_id is None):
        raise ValueError("Choose exactly one of --bundle-id or --app-id")
    if bundle_id is not None and not _BUNDLE_ID.fullmatch(bundle_id):
        raise ValueError("--bundle-id is not a valid bundle identifier")
    if app_id is not None and app_id <= 0:
        raise ValueError("--app-id must be a positive App Store identifier")
    if phone_version is not None and (not phone_version.strip() or len(phone_version) > 100):
        raise ValueError("--phone-version must be a short nonempty version")
    if privacy_report and iphone_report:
        raise ValueError("Choose either --privacy-report or --iphone-report")
    executable = find_ipatool(backend)
    output = output.expanduser().resolve()
    if output.exists():
        raise ValueError("Choose a new output directory; an existing acquisition will not be overwritten")
    output.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".mobile-audit-acquire-", dir=output.parent))
    try:
        package = staging / "package.ipa"
        command = [executable, "--non-interactive", "download", "--platform", "iphone", "--output", str(package)]
        command.extend(["--bundle-identifier", bundle_id] if bundle_id else ["--app-id", str(app_id)])
        try:
            completed = subprocess.run(command, check=False, timeout=1800)
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError("App Store download timed out") from exc
        except OSError as exc:
            raise RuntimeError("Could not start ipatool download") from exc
        if completed.returncode != 0:
            raise RuntimeError("App Store download failed; sign in with 'mobile-audit acquire-ios auth' and ensure the Apple Account owns the app")
        _check_archive(package)
        report = build_research_scan(package=package, privacy_report=privacy_report,
                                     iphone_report=iphone_report, app=bundle_id, name=name,
                                     app_version=phone_version, ios_version=ios_version)
        main = _main_bundle(report)
        actual_bundle = main["bundle_id"]
        if bundle_id and actual_bundle != bundle_id:
            raise ValueError("Downloaded package bundle identifier differs from the requested app")
        actual_version = main.get("version")
        version_match = ("unknown" if not phone_version or not actual_version else
                         "match" if phone_version == actual_version else "mismatch")
        profile = report["package_profile"]
        visibility = profile.get("ios_binary_visibility", {})
        acquisition = {
            "schema_version": "ios-acquisition-1.0",
            "method": "app_store_download",
            "retrieved_at": utc_now(),
            "backend": {"name": "ipatool", "version": ipatool_version(executable)},
            "requested": {"bundle_id": bundle_id, "app_id": app_id, "platform": "iphone",
                          "phone_version": phone_version},
            "package": {"file": "package.ipa", "sha256": _sha256(package),
                        "size_bytes": package.stat().st_size, "bundle_id": actual_bundle,
                        "version": actual_version, "build": main.get("build"),
                        "binary_visibility": visibility,
                        "main_executable": profile.get("ios_main_executable")},
            "version_match": version_match,
            "report": "scan/report.html",
        }
        profile["acquisition"] = {key: value for key, value in acquisition.items()
                                  if key not in {"schema_version", "report"}}
        for item in report["inputs"]:
            if item.get("kind") == "ios_package":
                item["name"] = "App Store IPA downloaded by Mobile Audit"
        if version_match == "mismatch":
            report["notes"].append("The App Store package version differs from the phone version; do not combine code and behavior as one build.")
        report["notes"].append("Package downloaded through ipatool; Apple Account credentials and session files are excluded from this report.")
        write_research_bundle(report, staging / "scan")
        (staging / "acquisition.json").write_text(json.dumps(acquisition, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        if output.exists():
            raise ValueError("Output directory appeared during acquisition; leaving it untouched")
        os.replace(staging, output)
        return acquisition
    finally:
        shutil.rmtree(staging, ignore_errors=True)
