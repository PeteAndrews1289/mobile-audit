from __future__ import annotations

import unittest
import tempfile
import plistlib
from pathlib import Path

from mobile_audit.benchmark import evaluate_benchmark
from mobile_audit.scanner import scan


ROOT = Path(__file__).resolve().parents[1]


class BaselineBenchmarkTests(unittest.TestCase):
    def test_bundled_controls_and_canary_run_without_upstream_apps(self) -> None:
        result = evaluate_benchmark(ROOT / "baselines/benchmark.json", ROOT)
        summary = result["summary"]
        self.assertEqual((3, 3), (summary["selected_positive_detected"], summary["selected_positive_total"]))
        self.assertEqual((14, 14), (summary["negative_controls_clear"], summary["negative_controls_total"]))
        self.assertEqual(6, sum(app["status"] == "source_missing" for app in result["apps"]))
        self.assertEqual("manual_pending", next(case["status"] for case in result["cases"] if case["id"] == "CB-04"))

    def test_flutter_patterns_report_locations_without_secret_values(self) -> None:
        report = scan(ROOT / "baselines/FlutterControls/Clean")
        self.assertEqual([], report.findings)
        self.assertIn("Flutter Dart source patterns", report.coverage)

        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "app.dart"
            source.write_text("""
import 'package:shared_preferences/shared_preferences.dart';
// Uri.parse('http://comment.invalid/');
// Key.fromUtf8('comment-only-key');
Future<void> work() async {
  final prefs = await SharedPreferences.getInstance();
  prefs.setString('auth_token', 'topsecretvalue');
  final uri = Uri.parse('http://example.invalid/account');
  final key = Key.fromUtf8('literal-key-123456');
  print('PIN: $pin');
  final cipher = AES(key, mode: AESMode.ecb);
}
""", encoding="utf-8")
            unsafe = scan(Path(temp))
        self.assertEqual({"MOBILE-FLUTTER-PREFS-SENSITIVE", "MOBILE-FLUTTER-CLEARTEXT-URL",
                          "MOBILE-FLUTTER-STATIC-CRYPTO-KEY", "MOBILE-FLUTTER-SENSITIVE-LOG",
                          "MOBILE-FLUTTER-WEAK-CRYPTO"},
                         {item.rule_id for item in unsafe.findings})
        self.assertNotIn("topsecretvalue", str(unsafe.to_dict()))
        self.assertNotIn("literal-key-123456", str(unsafe.to_dict()))
        mappings = {item.rule_id: item.maswe for item in unsafe.findings}
        self.assertEqual("MASWE-0007", mappings["MOBILE-FLUTTER-WEAK-CRYPTO"])
        self.assertEqual("MASWE-0005", mappings["MOBILE-FLUTTER-SENSITIVE-LOG"])
        self.assertEqual("MASWE-0004", mappings["MOBILE-FLUTTER-STATIC-CRYPTO-KEY"])

    def test_auth_comparison_storage_and_plist_leads_are_qualified(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "Example.swift").write_text("""
let message = "password == 'Admin' is example text"
let count = 1 // password == "Admin" is a comment
/* password == "Admin" is also a comment */
if password == "ActualDemoValue" { print("demo") }
UserDefaults.standard.set("1234", forKey: "PIN")
UserDefaults.standard.set("draft", forKey: "cardNote")
UserDefaults.standard.set(3, forKey: "tokenCount")
""", encoding="utf-8")
            (root / "config.plist").write_bytes(plistlib.dumps({
                "api": "secret_key=XyZ_12345678AbCd",
                "password": "example-placeholder-value",
            }))
            report = scan(root)
        by_rule = {}
        for finding in report.findings:
            by_rule.setdefault(finding.rule_id, []).append(finding)
        self.assertEqual(1, len(by_rule["MOBILE-AUTH-LITERAL-CHECK"]))
        self.assertEqual(1, len(by_rule["IOS-USERDEFAULTS-SENSITIVE"]))
        self.assertEqual(1, len(by_rule["MOBILE-HARDCODED-SECRET"]))
        self.assertIsNone(by_rule["MOBILE-AUTH-LITERAL-CHECK"][0].maswe)
        self.assertNotIn("XyZ_12345678AbCd", str(report.to_dict()))
        self.assertNotIn("ActualDemoValue", str(report.to_dict()))

    def test_native_crypto_and_http_leads_redact_literals_and_ignore_comments(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "Crypto.swift"
            source.write_text("""
import CommonCrypto
// let aesKey = "CommentOnlyKey12"
/* let iv = "CommentOnlyIV1234" */
let aesKey = "FixedDemoKey1234"
let iv = "FixedDemoIV12345"
let description = "URL(string: \\"http://text.invalid\\")"
let local = URL(string: "http://localhost:8080/health")
let endpoint = URL(string: "http://example.test/account")
func encrypt() { _ = CCCrypt }
""", encoding="utf-8")
            report = scan(Path(temp))
        rules = {item.rule_id: item for item in report.findings}
        self.assertEqual({"IOS-STATIC-CRYPTO-KEY", "IOS-STATIC-CRYPTO-IV", "IOS-CLEARTEXT-URL"}, set(rules))
        self.assertEqual("MASWE-0004", rules["IOS-STATIC-CRYPTO-KEY"].maswe)
        self.assertEqual("MASWE-0007", rules["IOS-STATIC-CRYPTO-IV"].maswe)
        self.assertEqual("MASWE-0026", rules["IOS-CLEARTEXT-URL"].maswe)
        self.assertNotIn("FixedDemoKey1234", str(report.to_dict()))
        self.assertNotIn("FixedDemoIV12345", str(report.to_dict()))
        self.assertNotIn("example.test", str(report.to_dict()))


if __name__ == "__main__":
    unittest.main()
