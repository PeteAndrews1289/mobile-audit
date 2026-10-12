from __future__ import annotations

import io
import hashlib
import json
import plistlib
import struct
import tempfile
import unittest
import warnings
import zipfile
from pathlib import Path

from mobile_audit.ios import scan_entitlements
from mobile_audit.macho import inspect_macho, scan_api_references
from mobile_audit.models import Report
from mobile_audit.package_assets import extract_ios_assets
from mobile_audit.reporting import write_html
from mobile_audit.scanner import scan
from mobile_audit.static_adapter import adapt_static_report


def synthetic_macho(*, encrypted: bool) -> bytes:
    name = b"/System/Library/Frameworks/WebKit.framework/WebKit\0"
    size = (24 + len(name) + 7) & ~7
    dylib = struct.pack("<6I", 0x0C, size, 24, 0, 0, 0) + name.ljust(size - 24, b"\0")
    crypt = struct.pack("<6I", 0x2C, 24, 0x1000, 0x200, int(encrypted), 0)
    commands = dylib + crypt
    header = struct.pack("<8I", 0xFEEDFACF, 0x0100000C, 0, 2, 2, len(commands), 0, 0)
    return header + commands + b"\0" * 200 + b"SecTrustSetExceptions\0application:openURL:options:\0"


class MachOInspectionTests(unittest.TestCase):
    def test_main_app_executable_is_inspected_before_large_framework_set(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            ipa = Path(temp) / "ManyFrameworks.ipa"
            binary = synthetic_macho(encrypted=True)
            with zipfile.ZipFile(ipa, "w") as archive:
                archive.writestr("Payload/Priority.app/Info.plist", plistlib.dumps({
                    "CFBundleIdentifier": "example.priority", "CFBundleExecutable": "Priority",
                }))
                archive.writestr("Payload/Priority.app/Priority", binary)
                for index in range(1024):
                    name = f"F{index:04d}"
                    archive.writestr(f"Payload/Priority.app/Frameworks/{name}.framework/{name}", binary)
            profile = scan(ipa).inventory
            self.assertEqual(1025, profile["ios_binary_candidates"])
            self.assertEqual(1024, len(profile["ios_binaries"]))
            self.assertEqual(1, profile["ios_binary_visibility"]["uninspected"])
            self.assertEqual("Payload/Priority.app/Priority", profile["ios_binaries"][0]["location"])

    def test_macho_reports_build_and_hardening_header_metadata(self) -> None:
        version = lambda major, minor, patch: (major << 16) | (minor << 8) | patch
        build = struct.pack("<6I", 0x32, 24, 2, version(15, 2, 0), version(17, 4, 1), 0)
        signature = struct.pack("<4I", 0x1D, 16, 128, 32)
        commands = build + signature
        binary = struct.pack("<8I", 0xFEEDFACF, 0x0100000C, 0, 2, 2,
                             len(commands), 0x200000, 0) + commands
        arch = inspect_macho(binary, len(binary))["architectures"][0]
        self.assertEqual(arch["build_platform"], "ios")
        self.assertEqual(arch["minimum_os"], "15.2.0")
        self.assertEqual(arch["sdk_version"], "17.4.1")
        self.assertTrue(arch["pie_flag"])
        self.assertTrue(arch["code_signature_command"])

    def test_ipa_profile_records_bundles_privacy_and_artifact_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            ipa = Path(temp) / "Profile.ipa"
            with zipfile.ZipFile(ipa, "w") as archive:
                archive.writestr("Payload/Profile.app/Info.plist", plistlib.dumps({
                    "CFBundleIdentifier": "example.profile",
                    "CFBundleDisplayName": "Profile <test>",
                    "CFBundleExecutable": "Profile",
                    "CFBundleShortVersionString": "3.2",
                    "CFBundleVersion": "42",
                    "MinimumOSVersion": "16.0",
                    "NSCameraUsageDescription": "Scan a document",
                    "NSAppTransportSecurity": {"NSExceptionDomains": {
                        "example.test": {"NSExceptionAllowsInsecureHTTPLoads": True}}},
                }))
                archive.writestr("Payload/Profile.app/Profile", synthetic_macho(encrypted=False))
                archive.writestr("Payload/Profile.app/PlugIns/Share.appex/Info.plist", plistlib.dumps({
                    "CFBundleIdentifier": "example.profile.share",
                    "CFBundleExecutable": "Share",
                    "CFBundleShortVersionString": "1.0",
                }))
                archive.writestr("Payload/Profile.app/PlugIns/Share.appex/Share", synthetic_macho(encrypted=True))
                archive.writestr("Payload/Profile.app/PrivacyInfo.xcprivacy", plistlib.dumps({
                    "NSPrivacyTracking": True,
                    "NSPrivacyTrackingDomains": ["tracker.example"],
                    "NSPrivacyCollectedDataTypes": [{"NSPrivacyCollectedDataType": "NSPrivacyCollectedDataTypeEmailAddress"}],
                    "NSPrivacyAccessedAPITypes": [{"NSPrivacyAccessedAPIType": "NSPrivacyAccessedAPICategoryFileTimestamp"}],
                }))
                archive.writestr("Payload/Profile.app/Assets.bundle/Info.plist", plistlib.dumps({
                    "CFBundleIdentifier": "example.profile.assets",
                }))
            report = scan(ipa)
            inv = report.inventory
            self.assertEqual(inv["ios_package_file"]["sha256"], hashlib.sha256(ipa.read_bytes()).hexdigest())
            self.assertEqual(inv["ios_package_file"]["file_count"], 6)
            self.assertEqual({item["kind"] for item in inv["ios_bundles"]},
                             {"app", "extension", "resource_bundle"})
            app = next(item for item in inv["ios_bundles"] if item["kind"] == "app")
            self.assertEqual((app["version"], app["build"], app["minimum_ios"]), ("3.2", "42", "16.0"))
            self.assertEqual(inv["ios_privacy_permissions"][0]["key"], "NSCameraUsageDescription")
            self.assertEqual(inv["ios_transport_security"][0]["exception_domains"], ["example.test"])
            self.assertEqual(inv["ios_privacy_manifests"][0]["tracking_domains"], ["tracker.example"])
            self.assertEqual(len(inv["ios_signatures"]), 2)
            self.assertTrue(all(item["verification"] == "not_performed" for item in inv["ios_signatures"]))
            html = Path(temp) / "profile.html"
            write_html(report, html)
            page = html.read_text()
            self.assertIn("Declared bundles", page)
            self.assertIn("Privacy manifests", page)
            self.assertIn("Profile &lt;test&gt;", page)
            self.assertNotIn("Profile <test>", page)
            self.assertIn("No A-F grade is assigned", page)

    def test_encrypted_ipa_reports_visible_surfaces_and_code_limit(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            ipa = Path(temp) / "Synthetic.ipa"
            with zipfile.ZipFile(ipa, "w") as archive:
                archive.writestr("Payload/Synthetic.app/Info.plist", plistlib.dumps({
                    "CFBundleIdentifier": "example.synthetic",
                    "CFBundleExecutable": "Synthetic",
                    "CFBundleShortVersionString": "2.0",
                    "CFBundleURLTypes": [{"CFBundleURLSchemes": ["syntheticapp"]}],
                    "CFBundleDocumentTypes": [{"LSItemContentTypes": ["public.json"]}],
                }))
                archive.writestr("Payload/Synthetic.app/Synthetic", synthetic_macho(encrypted=True))
                archive.writestr("Payload/Synthetic.app/assets/main.js", "console.log('synthetic');")
                archive.writestr("Payload/Synthetic.app/assets/main.js.map", json.dumps({
                    "version": 3,
                    "sources": ["../../../private.ts", "missing.ts"],
                    "sourcesContent": ["export const value = 7;", None],
                }))
                archive.writestr("Payload/Synthetic.app/PlugIns/Share.appex/main.jsbundle", "globalThis.share = true;")
            report = scan(ipa)
            self.assertEqual(report.inventory["ios_binary_visibility"]["encrypted"], 1)
            binary = report.inventory["ios_binaries"][0]
            self.assertEqual(binary["encryption"], "encrypted")
            self.assertEqual(binary["api_reference_categories"], [])
            self.assertIn("WebKit.framework/WebKit", binary["architectures"][0]["linked_libraries"][0])
            self.assertEqual({entry["kind"] for entry in report.inventory["ios_entry_points"]},
                             {"custom_url_scheme", "document_type"})
            self.assertEqual({item["location"] for item in report.inventory["ios_plaintext_code_assets"]}, {
                "Payload/Synthetic.app/assets/main.js",
                "Payload/Synthetic.app/assets/main.js.map",
                "Payload/Synthetic.app/PlugIns/Share.appex/main.jsbundle",
            })
            self.assertIn("encrypted", " ".join(report.warnings).lower())
            self.assertNotIn("SecTrustSetExceptions", json.dumps(report.to_dict()))
            evidence = adapt_static_report(report)
            self.assertIn("Encrypted iOS executable code was not inspected", " ".join(evidence.notes))
            self.assertEqual(next(item.status for item in evidence.coverage
                                  if item.area == "ios_executable_code_references"), "unavailable")
            html = Path(temp) / "report.html"
            write_html(report, html)
            self.assertIn("Entry points to test", html.read_text())
            self.assertIn("1 encrypted executable(s)", html.read_text())
            output = Path(temp) / "extracted"
            manifest = extract_ios_assets(ipa, output)
            self.assertEqual(manifest["asset_count"], 3)
            self.assertEqual(manifest["recovered_source_count"], 1)
            self.assertEqual((output / "_recovered_source_maps/source-00001.ts").read_text(),
                             "export const value = 7;")
            self.assertEqual(manifest["recovered_sources"][0]["source_index"], 0)
            self.assertEqual((output / "Payload/Synthetic.app/assets/main.js").read_text(),
                             "console.log('synthetic');")
            self.assertEqual((output / "Payload/Synthetic.app/PlugIns/Share.appex/main.jsbundle").read_text(),
                             "globalThis.share = true;")
            self.assertIn("sha256", json.loads((output / "manifest.json").read_text())["assets"][0])
            with self.assertRaises(ValueError):
                extract_ios_assets(ipa, output)

    def test_unencrypted_app_bundle_scans_bounded_api_names(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            app = Path(temp) / "Synthetic.app"
            app.mkdir()
            (app / "Info.plist").write_bytes(plistlib.dumps({
                "CFBundleIdentifier": "example.synthetic",
                "CFBundleExecutable": "Synthetic",
            }))
            (app / "Synthetic").write_bytes(synthetic_macho(encrypted=False))
            report = scan(app)
            self.assertEqual(report.inventory["ios_binary_visibility"]["not_encrypted"], 1)
            self.assertEqual(report.inventory["ios_binaries"][0]["api_reference_categories"],
                             ["custom_server_trust", "external_url_handler"])
            self.assertNotIn("SecTrustSetExceptions", json.dumps(report.to_dict()))

    def test_malformed_and_fat_headers_are_bounded(self) -> None:
        invalid = struct.pack("<8I", 0xFEEDFACF, 0x0100000C, 0, 2, 5000, 0, 0, 0)
        self.assertEqual(inspect_macho(invalid, len(invalid))["encryption"], "unknown")
        thin = synthetic_macho(encrypted=False)
        fat = struct.pack(">2I", 0xCAFEBABE, 1) + struct.pack(">5I", 0x0100000C, 0, 0x1000, len(thin), 12)
        fat = fat.ljust(0x1000, b"\0") + thin
        self.assertEqual(inspect_macho(fat, len(fat))["encryption"], "not_encrypted")
        stream = io.BytesIO(b"x" * (1024 * 1024 - 10) + b"SecTrustSetExceptions")
        self.assertEqual(scan_api_references(stream, 1024 * 1024 + 11), ["custom_server_trust"])
        bounded = io.BytesIO(b"abcdSecTrustSetExceptions")
        self.assertEqual(scan_api_references(bounded, 4), [])
        self.assertEqual(bounded.tell(), 4)

    def test_associated_domain_entitlement_adds_test_entry_point(self) -> None:
        report = Report(target="synthetic")
        scan_entitlements(plistlib.dumps({
            "com.apple.developer.associated-domains": ["applinks:example.test", "webcredentials:example.test"],
        }), "signed entitlements", report, signed=True)
        self.assertEqual(report.inventory["ios_entry_points"][0]["kind"], "universal_link_domain")
        self.assertEqual(len(report.inventory["ios_entry_points"]), 1)

    def test_duplicate_archive_member_is_rejected_before_extraction(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            ipa = Path(temp) / "Duplicate.ipa"
            with zipfile.ZipFile(ipa, "w") as archive:
                archive.writestr("Payload/Example.app/main.js", "first")
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", UserWarning)
                    archive.writestr("Payload/Example.app/main.js", "second")
            with self.assertRaises(ValueError):
                extract_ios_assets(ipa, Path(temp) / "extracted")
            self.assertFalse((Path(temp) / "extracted").exists())

    def test_normalized_duplicate_archive_member_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            ipa = Path(temp) / "Duplicate.ipa"
            with zipfile.ZipFile(ipa, "w") as archive:
                archive.writestr("Payload/Example.app/assets/main.js", "first")
                archive.writestr("Payload/Example.app/assets//main.js", "second")
            with self.assertRaises(ValueError):
                extract_ios_assets(ipa, Path(temp) / "extracted")


if __name__ == "__main__":
    unittest.main()
