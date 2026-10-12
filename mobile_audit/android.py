from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path

from .models import Finding, Report


ANDROID_NS = "http://schemas.android.com/apk/res/android"


def attr(element: ET.Element, name: str) -> str | None:
    return element.get(f"{{{ANDROID_NS}}}{name}")


def scan_manifest(data: bytes | ET.Element, location: str, report: Report) -> None:
    try:
        root = ET.fromstring(data) if isinstance(data, bytes) else data
    except ET.ParseError as exc:
        report.warnings.append(f"Could not parse {location}: {exc}")
        return
    if root.tag != "manifest":
        report.warnings.append(f"Unexpected Android manifest root in {location}")
        return
    package = root.get("package")
    uses_sdk = root.find("uses-sdk")
    target_sdk = attr(uses_sdk, "targetSdkVersion") if uses_sdk is not None else None
    report.inventory.setdefault("android_manifests", []).append({
        "location": location, "package": package, "target_sdk": target_sdk,
        "permissions": sorted({attr(p, "name") for p in root.findall("uses-permission") if attr(p, "name")}),
    })
    application = root.find("application")
    if application is None:
        return
    if attr(application, "debuggable") == "true":
        report.add(Finding(
            "ANDROID-DEBUGGABLE", "Application is debuggable", "android", "high", "high",
            location, "application android:debuggable=true",
            "Disable debugging in release builds.",
            "MASVS-RESILIENCE-2", "MASWE-0063",
        ))
    network_config = attr(application, "networkSecurityConfig")
    if attr(application, "usesCleartextTraffic") == "true" and not network_config:
        report.add(Finding(
            "ANDROID-CLEARTEXT", "Application allows cleartext traffic", "android", "medium", "high",
            location, "application android:usesCleartextTraffic=true",
            "Use HTTPS and disable cleartext traffic, or scope an exception to an essential domain.",
            "MASVS-NETWORK-1", "MASWE-0026",
        ))
    if attr(application, "allowBackup") == "true" and not attr(application, "dataExtractionRules"):
        report.add(Finding(
            "ANDROID-BACKUP", "App data backup needs review", "android", "low", "medium",
            location, "application android:allowBackup=true; no dataExtractionRules declared",
            "Review backup contents and exclude sensitive keys and temporary data.",
            "MASVS-STORAGE-1", "MASWE-0006",
        ))

    for kind in ("provider", "service", "receiver"):
        for component in application.findall(kind):
            if attr(component, "exported") != "true":
                continue
            permission = (
                attr(component, "permission") or attr(application, "permission")
                or attr(component, "readPermission") or attr(component, "writePermission")
            )
            if permission:
                continue
            name = attr(component, "name") or "(unnamed)"
            report.add(Finding(
                "ANDROID-EXPORTED-COMPONENT", f"Exported {kind} lacks a declared permission", "android",
                "medium", "medium", location,
                f"{kind} {name}: android:exported=true without a declared permission",
                "Confirm external callers are intended, validate all input, and require an appropriate permission or authentication.",
                "MASVS-PLATFORM-1", "MASWE-0018",
            ))
    if network_config:
        report.inventory.setdefault("android_network_configs", []).append({"manifest": location, "reference": network_config})
    report.coverage.append("Android manifest permissions and component exposure")


def scan_network_config(data: bytes | ET.Element, location: str, report: Report) -> None:
    try:
        root = ET.fromstring(data) if isinstance(data, bytes) else data
    except ET.ParseError as exc:
        report.warnings.append(f"Could not parse {location}: {exc}")
        return
    if root.tag != "network-security-config":
        return
    for config in root.iter():
        if config.tag not in {"base-config", "domain-config"}:
            continue
        if config.get("cleartextTrafficPermitted") == "true":
            domains = [e.text for e in config.findall("domain") if e.text]
            scope = ", ".join(domains) if domains else config.tag
            report.add(Finding(
                "ANDROID-NETWORK-CLEARTEXT", "Network configuration permits cleartext traffic", "android",
                "medium", "high", location, f"cleartextTrafficPermitted=true for {scope}",
                "Require HTTPS, or narrow the exception to a domain that cannot yet support it.",
                "MASVS-NETWORK-1", "MASWE-0026",
            ))
        for anchor in config.findall("./trust-anchors/certificates"):
            if anchor.get("src") == "user":
                report.add(Finding(
                    "ANDROID-USER-CA", "Release trust configuration accepts user CAs", "android",
                    "low", "medium", location, f"{config.tag} trust-anchors certificates src=user",
                    "Confirm user-installed CAs are required for this app's threat model.",
                    "MASVS-NETWORK-1", "MASWE-0027",
                ))
    report.coverage.append("Android network security configuration")


_TRUST_ALL = re.compile(r"(?s)checkServerTrusted\s*\([^)]*\)\s*(?:throws\s+[^\{]+)?\{\s*\}")
_HOSTNAME_ALL = re.compile(r"(?s)HostnameVerifier\s*\{[^}]{0,400}\breturn\s+true\b")


def scan_android_code(text: str, location: str, report: Report) -> None:
    for rule, pattern, title in (
        ("ANDROID-TRUST-ALL", _TRUST_ALL, "Empty server certificate validation"),
        ("ANDROID-HOSTNAME-ALL", _HOSTNAME_ALL, "Hostname verifier appears to accept any host"),
    ):
        for match in pattern.finditer(text):
            line = text.count("\n", 0, match.start()) + 1
            report.add(Finding(
                rule, title, "android", "high", "medium", f"{location}:{line}",
                "Certificate or hostname validation bypass pattern (code excerpt omitted)",
                "Use platform TLS validation and remove unconditional acceptance of certificates or hostnames.",
                "MASVS-NETWORK-1", "MASWE-0027",
            ))
    report.coverage.append("Android Java and Kotlin source patterns")


def scan_apk(path: Path, report: Report) -> None:
    try:
        from loguru import logger
        from androguard.core.apk import APK
        from androguard.core.axml import AXMLPrinter
    except ImportError as exc:
        raise RuntimeError("APK scanning requires the Android extra: pip install -e '.[android]'") from exc
    logger.disable("androguard")
    apk = APK(str(path))
    manifest = apk.get_android_manifest_xml()
    if manifest is None:
        raise ValueError("AndroidManifest.xml could not be decoded")
    scan_manifest(manifest, "AndroidManifest.xml", report)
    files = set(apk.get_files())
    network_paths = sorted(name for name in files if name.startswith("res/xml/") and "network_security" in name and name.endswith(".xml"))
    for name in network_paths:
        try:
            decoded = AXMLPrinter(apk.get_file(name)).get_xml_obj()
            if decoded is not None:
                scan_network_config(decoded, name, report)
        except Exception as exc:
            report.warnings.append(f"Could not decode {name}: {exc}")
    if report.inventory.get("android_network_configs") and not network_paths:
        report.warnings.append("Manifest references a network security configuration that was not decoded from the APK")
