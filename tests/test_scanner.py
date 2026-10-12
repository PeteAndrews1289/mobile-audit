from __future__ import annotations

import json
import plistlib
import tempfile
import unittest
import zipfile
from pathlib import Path

from mobile_audit.reporting import write_html
from mobile_audit.scanner import scan
from mobile_audit.models import Report
from mobile_audit.webcode import scan_web_code


class ScannerTests(unittest.TestCase):
    def test_web_capability_uri_does_not_hide_real_http_endpoint(self) -> None:
        code = "systeminfo.getCapability('http://tizen.org/system/model_name')\n"
        report = Report("example")
        scan_web_code(code, "bundle.js", report)
        self.assertNotIn("IOS-WEB-CLEARTEXT-URL", {f.rule_id for f in report.findings})

        scan_web_code(code + "fetch('http://example.test/resource')\n", "bundle.js", report)
        cleartext = [f for f in report.findings if f.rule_id == "IOS-WEB-CLEARTEXT-URL"]
        self.assertEqual(["bundle.js:2"], [f.location for f in cleartext])

    def test_ios_source_reports_configuration_and_redacts_secret(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Info.plist").write_bytes(plistlib.dumps({
                "NSAppTransportSecurity": {"NSAllowsArbitraryLoads": True},
            }))
            (root / "Example.swift").write_text(
                'let client_secret = "very-secret-value-123"\n'
                'let key = AccountScopedStorageKey.make(prefix: "chatHistory", userID: userID)\n'
                'UserDefaults.standard.set(encoded, forKey: key)\n'
                'let level = kSecAttrAccessibleAlways\n', encoding="utf-8",
            )
            report = scan(root)
            ids = {finding.rule_id for finding in report.findings}
            self.assertTrue({
                "IOS-ATS-GLOBAL", "IOS-KEYCHAIN-ACCESS", "IOS-USERDEFAULTS-SENSITIVE",
                "MOBILE-HARDCODED-SECRET",
            }.issubset(ids))
            serialized = json.dumps(report.to_dict())
            self.assertNotIn("very-secret-value-123", serialized)
            keychain = next(item for item in report.findings if item.rule_id == "IOS-KEYCHAIN-ACCESS")
            self.assertIsNone(keychain.maswe)

    def test_ios_weak_crypto_maps_hashing_and_encryption_separately(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Crypto.swift").write_text(
                "let digest = CC_MD5(input, length, output)\n"
                "let algorithm = kCCAlgorithmDES\n", encoding="utf-8",
            )
            findings = [item for item in scan(root).findings if item.rule_id == "IOS-WEAK-CRYPTO"]
        self.assertEqual(2, len(findings))
        self.assertEqual({"MASWE-0008", "MASWE-0007"}, {item.maswe for item in findings})

    def test_scoped_ats_key_suppresses_ineffective_global_setting(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Info.plist").write_bytes(plistlib.dumps({
                "NSAppTransportSecurity": {
                    "NSAllowsArbitraryLoads": True,
                    "NSAllowsLocalNetworking": True,
                },
            }))
            report = scan(root)
            self.assertNotIn("IOS-ATS-GLOBAL", {f.rule_id for f in report.findings})

    def test_nested_ats_configuration_is_not_treated_as_domain_exception(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Info.plist").write_bytes(plistlib.dumps({
                "NSAppTransportSecurity": {
                    "NSAllowsArbitraryLoads": True,
                    "NSAppTransportSecurity": {
                        "NSExceptionDomains": {"example.test": {"NSIncludesSubdomains": True}},
                    },
                },
            }))
            report = scan(root)
            self.assertTrue({"IOS-ATS-GLOBAL", "IOS-ATS-NESTED-CONFIG"}.issubset(
                {f.rule_id for f in report.findings}))
            transport = report.inventory["ios_transport_security"][0]
            self.assertEqual([], transport["exception_domains"])
            self.assertTrue(transport["nested_ats_configuration"])

    def test_ipa_parses_plist_and_rejects_unsafe_archive(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ipa = root / "Example.ipa"
            with zipfile.ZipFile(ipa, "w") as archive:
                archive.writestr("Payload/Example.app/Info.plist", plistlib.dumps({
                    "CFBundleIdentifier": "example.app",
                    "NSAppTransportSecurity": {"NSExceptionDomains": {
                        "example.test": {"NSExceptionAllowsInsecureHTTPLoads": True},
                    }},
                }))
                archive.writestr("Payload/Example.app/config.plist", plistlib.dumps({
                    "client_secret": "real-example-secret-123",
                }))
            report = scan(ipa)
            self.assertIn("IOS-ATS-DOMAIN", {f.rule_id for f in report.findings})
            self.assertIn("MOBILE-HARDCODED-SECRET", {f.rule_id for f in report.findings})
            self.assertNotIn("real-example-secret-123", json.dumps(report.to_dict()))
            self.assertEqual("example.app", report.inventory["ios_bundles"][0]["bundle_id"])
            unsafe = root / "Unsafe.ipa"
            with zipfile.ZipFile(unsafe, "w") as archive:
                archive.writestr("../outside.txt", "bad")
            with self.assertRaises(ValueError):
                scan(unsafe)

    def test_android_source_components_and_network_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "AndroidManifest.xml").write_text(
                '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="example.app">'
                '<application android:debuggable="true"><provider android:name=".Data" android:exported="true" />'
                '</application></manifest>', encoding="utf-8",
            )
            (root / "network_security_config.xml").write_text(
                '<network-security-config><base-config cleartextTrafficPermitted="true" />'
                '</network-security-config>', encoding="utf-8",
            )
            report = scan(root)
            self.assertTrue({
                "ANDROID-DEBUGGABLE", "ANDROID-EXPORTED-COMPONENT", "ANDROID-NETWORK-CLEARTEXT",
            }.issubset({f.rule_id for f in report.findings}))

    def test_html_escapes_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Info.plist").write_bytes(plistlib.dumps({
                "NSAppTransportSecurity": {"NSExceptionDomains": {
                    "<script>alert(1)</script>": {"NSExceptionAllowsInsecureHTTPLoads": True},
                }},
            }))
            report = scan(root)
            output = root / "report.html"
            write_html(report, output)
            content = output.read_text(encoding="utf-8")
            self.assertNotIn("<script>alert(1)</script>", content)
            self.assertIn("&lt;script&gt;", content)


if __name__ == "__main__":
    unittest.main()
