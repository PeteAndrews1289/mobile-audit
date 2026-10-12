from __future__ import annotations

import json
import plistlib
import struct
import tempfile
import unittest
import zipfile
from pathlib import Path

from mobile_audit.ai_review import import_ai_review
from mobile_audit.cli import main
from mobile_audit.dependencies import collect_dependencies
from mobile_audit.research import _validate_report, build_research_scan
from mobile_audit.research_reporting import ai_review_data, write_research_bundle


def macho(encrypted: bool) -> bytes:
    command = struct.pack("<6I", 0x2C, 24, 0x1000, 0x200, int(encrypted), 0)
    header = struct.pack("<8I", 0xFEEDFACF, 0x0100000C, 0, 2, 1, len(command), 0, 0)
    return header + command + b"\0" * 64 + b"SecTrustSetExceptions\0application:openURL:options:\0"


class ResearchScanTests(unittest.TestCase):
    def make_package(self, root: Path) -> Path:
        package = root / "Example.ipa"
        with zipfile.ZipFile(package, "w") as archive:
            archive.writestr("Payload/Example.app/Info.plist", plistlib.dumps({
                "CFBundleIdentifier": "com.example.app", "CFBundleExecutable": "Example",
                "CFBundleShortVersionString": "1.0",
                "CFBundleURLTypes": [{"CFBundleURLSchemes": ["exampleapp"]}],
            }))
            archive.writestr("Payload/Example.app/Example", macho(True))
            archive.writestr("Payload/Example.app/Frameworks/Helper.dylib", macho(False))
            archive.writestr("Payload/Example.app/main.js.map", json.dumps({
                "version": 3, "sources": ["../../src/bridge.ts"],
                "sourcesContent": ["const sink = eval(userInput);"],
            }))
        return package

    def make_source(self, root: Path) -> Path:
        source = root / "source"
        source.mkdir()
        (source / "Review.swift").write_text("SecTrustSetExceptions(trust, data)\n", encoding="utf-8")
        (source / "Package.resolved").write_text(json.dumps({
            "version": 2, "pins": [{"identity": "example-lib", "kind": "remoteSourceControl",
                                    "location": "https://github.com/example/example-lib.git",
                                    "state": {"version": "1.2.3", "revision": "a" * 40}}],
        }), encoding="utf-8")
        return source

    def test_unified_package_source_and_activity_report(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            package = self.make_package(root)
            source = self.make_source(root)
            apr = root / "activity.ndjson"
            apr.write_text(
                json.dumps({"type": "networkActivity", "bundleID": "com.example.app",
                            "domain": "private.example.test", "firstTimeStamp": "2026-10-01T00:00:00Z",
                            "timeStamp": "2026-10-01T00:01:00Z", "hits": 1}) + "\n" +
                json.dumps({"type": "networkActivity", "bundleID": "com.other.app",
                            "domain": "unrelated.example.test", "firstTimeStamp": "2026-10-01T00:00:00Z",
                            "timeStamp": "2026-10-01T00:01:00Z", "hits": 1}) + "\n", encoding="utf-8")
            report = build_research_scan(package=package, source=source, privacy_report=apr)
            self.assertEqual("com.example.app", report["target"]["identifier"])
            self.assertEqual("1.0", report["target"]["version"])
            self.assertEqual("incomplete", report["assessment"]["status"])
            self.assertEqual("com.example.app", report["package_profile"]["ios_bundles"][0]["bundle_id"])
            self.assertEqual("ipa", report["package_profile"]["ios_package_file"]["format"])
            self.assertEqual(1, len(report["dependencies"]))
            self.assertEqual(1, report["visibility"]["package_binaries"]["encrypted"])
            kinds = {item["kind"] for item in report["leads"]}
            self.assertIn("IOS-WEB-DYNAMIC-CODE", kinds)
            self.assertIn("custom_url_scheme", kinds)
            self.assertIn("custom_server_trust", kinds)
            self.assertIn("sender", next(item for item in report["leads"]
                                         if item["kind"] == "custom_url_scheme")["attack_scenario"])
            linked = next(item for item in report["leads"] if item["kind"] == "external_link_web_sink_review")
            self.assertEqual(2, len(linked["evidence_ids"]))
            self.assertEqual("low", linked["confidence"])
            self.assertEqual("hypothesis", linked["state"])
            self.assertEqual("co_presence_only", linked["path_analysis"]["basis"])
            self.assertEqual({"external_link_entry", "web_code_sink"},
                             {item["role"] for item in linked["path_analysis"]["clues"]})
            self.assertEqual(set(linked["evidence_ids"]),
                             {identifier for clue in linked["path_analysis"]["clues"]
                              for identifier in clue["evidence_ids"]})
            trust = next(item for item in report["evidence"]
                         if item["details"].get("rule_id") == "IOS-CUSTOM-TRUST")
            self.assertEqual("MASVS-NETWORK-1", trust["details"]["masvs"])
            self.assertEqual("MASWE-0027", trust["details"]["maswe"])
            handed_off = next(item for item in ai_review_data(report)["evidence"] if item["id"] == trust["id"])
            self.assertEqual("MASWE-0027", handed_off["details"]["maswe"])
            self.assertNotIn("unrelated.example.test", json.dumps(report))
            output = root / "research-output"
            write_research_bundle(report, output)
            self.assertTrue((output / "report.html").exists())
            self.assertIn("Attack path hypotheses", (output / "report.html").read_text())
            self.assertIn("Package overview", (output / "report.html").read_text())
            self.assertIn("Missing connection", (output / "report.html").read_text())
            self.assertIn("private.example.test", (output / "report.json").read_text())
            self.assertNotIn("private.example.test", (output / "ai-review.json").read_text())
            self.assertNotIn(str(root), (output / "report.json").read_text())
            with self.assertRaises(ValueError):
                write_research_bundle(report, output)

    def test_link_auth_and_http_exception_paths_require_both_clues(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "source"
            source.mkdir()
            (source / "Info.plist").write_bytes(plistlib.dumps({
                "CFBundleIdentifier": "com.example.paths",
                "CFBundleURLTypes": [{"CFBundleURLSchemes": ["examplepaths"]}],
                "NSAppTransportSecurity": {"NSAllowsArbitraryLoads": True},
            }))
            secret = "PrivateTestValue6723"
            endpoint = "http://secret-endpoint.example.test/path"
            (source / "Flow.swift").write_text(
                f'if password == "{secret}" {{ allowAccess() }}\n'
                f'let endpoint = URL(string: "{endpoint}")\n', encoding="utf-8")
            report = build_research_scan(source=source, app="com.example.paths")
            paths = {item["kind"]: item for item in report["leads"] if item.get("path_analysis")}
            for kind in ("external_link_auth_boundary_review", "http_exception_request_review"):
                self.assertIn(kind, paths)
                self.assertEqual("hypothesis", paths[kind]["state"])
                self.assertEqual("low", paths[kind]["confidence"])
                self.assertTrue(paths[kind]["path_analysis"]["missing_link"])
                self.assertTrue(paths[kind]["disconfirming_result"])
            brief = ai_review_data(report)
            self.assertIn("path_analysis", next(item for item in brief["leads"]
                                                if item["kind"] == "external_link_auth_boundary_review"))
            for serialized in (json.dumps(report), json.dumps(brief)):
                self.assertNotIn(secret, serialized)
                self.assertNotIn(endpoint, serialized)

            altered = json.loads(json.dumps(report))
            next(item for item in altered["leads"] if item.get("path_analysis"))["path_analysis"]["clues"][0]["evidence_ids"] = ["missing"]
            with self.assertRaisesRegex(ValueError, "uncited clues"):
                _validate_report(altered)
            promoted = json.loads(json.dumps(report))
            next(item for item in promoted["leads"] if item.get("path_analysis"))["confidence"] = "high"
            with self.assertRaisesRegex(ValueError, "low-confidence hypothesis"):
                _validate_report(promoted)

            (source / "Info.plist").write_bytes(plistlib.dumps({"CFBundleIdentifier": "com.example.paths"}))
            no_entry_or_exception = build_research_scan(source=source, app="com.example.paths")
            no_path_kinds = {item["kind"] for item in no_entry_or_exception["leads"]}
            self.assertNotIn("external_link_auth_boundary_review", no_path_kinds)
            self.assertNotIn("http_exception_request_review", no_path_kinds)

    def test_web_sink_and_native_bridge_path_requires_both_clues(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "source"
            source.mkdir()
            (source / "Info.plist").write_bytes(plistlib.dumps({
                "CFBundleIdentifier": "com.example.paths",
                "CFBundleDocumentTypes": [{"LSItemContentTypes": ["public.json"]}],
            }))
            (source / "Web.js").write_text("eval(userInput)\n", encoding="utf-8")
            binary = root / "ExampleBinary"
            binary.write_bytes(macho(False) + b"WKScriptMessageHandler\0NSKeyedUnarchiver\0")
            report = build_research_scan(source=source, readable_binary=binary, app="com.example.paths")
            path = next(item for item in report["leads"] if item["kind"] == "web_content_native_bridge_review")
            self.assertIn("same WebView", path["path_analysis"]["missing_link"])
            self.assertEqual("co_presence_only", path["path_analysis"]["basis"])
            self.assertIn("origin", path["next_test"])
            document_path = next(item for item in report["leads"] if item["kind"] == "document_deserializer_review")
            self.assertIn("document import", document_path["path_analysis"]["missing_link"])
            without_binary = build_research_scan(source=source, app="com.example.paths")
            self.assertNotIn("web_content_native_bridge_review", {item["kind"] for item in without_binary["leads"]})
            self.assertNotIn("document_deserializer_review", {item["kind"] for item in without_binary["leads"]})

    def test_static_leads_have_discriminating_plans_without_source_literals(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "source"
            source.mkdir()
            secret = "LiveLookingValue8274"
            endpoint = "http://private-endpoint.example.test/path"
            (source / "Review.swift").write_text(
                f'let password = "{secret}"\n'
                f'if password == "{secret}" {{ allowAccess() }}\n'
                f'let endpoint = URL(string: "{endpoint}")\n'
                'SecTrustSetExceptions(trust, data)\n', encoding="utf-8")
            report = build_research_scan(source=source, app="com.example.app")
            leads = {item["kind"]: item for item in report["leads"]}
            self.assertIn("both branches", leads["MOBILE-AUTH-LITERAL-CHECK"]["next_test"])
            self.assertIn("server authorization", leads["MOBILE-AUTH-LITERAL-CHECK"]["disconfirming_result"])
            self.assertIn("ATS blocks", leads["IOS-CLEARTEXT-URL"]["next_test"])
            self.assertIn("invalid certificate", leads["IOS-CUSTOM-TRUST"]["disconfirming_result"])
            self.assertIn("network path", leads["IOS-CUSTOM-TRUST"]["attack_scenario"])
            self.assertIn("server check", leads["MOBILE-AUTH-LITERAL-CHECK"]["attack_scenario"])
            self.assertEqual("static_lead", leads["IOS-CUSTOM-TRUST"]["state"])
            self.assertEqual("incomplete", report["assessment"]["status"])
            ai = ai_review_data(report)
            self.assertEqual(leads["IOS-CLEARTEXT-URL"]["disconfirming_result"],
                             next(item for item in ai["leads"] if item["kind"] == "IOS-CLEARTEXT-URL")["disconfirming_result"])
            self.assertEqual(leads["IOS-CLEARTEXT-URL"]["attack_scenario"],
                             next(item for item in ai["leads"] if item["kind"] == "IOS-CLEARTEXT-URL")["attack_scenario"])
            output = root / "output"
            write_research_bundle(report, output)
            self.assertIn("Disconfirming result", (output / "report.html").read_text())
            self.assertIn("Possible attack path", (output / "report.html").read_text())
            for name in ("report.json", "ai-review.json", "report.html"):
                content = (output / name).read_text()
                self.assertNotIn(secret, content)
                self.assertNotIn(endpoint, content)

    def test_known_advisory_is_version_match_not_app_vulnerability(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            source = self.make_source(Path(temp))
            def fake_osv(payload: bytes) -> bytes:
                query = json.loads(payload)["queries"][0]
                self.assertEqual("SwiftURL", query["package"]["ecosystem"])
                self.assertEqual("1.2.3", query["version"])
                return json.dumps({"results": [{"vulns": [{"id": "GHSA-abcd-1234-5678"}]}]}).encode()
            report = build_research_scan(source=source, app="com.example.app",
                                         check_known_vulns=True, osv_post=fake_osv)
            self.assertEqual("known_advisory_version_match_usage_unverified", report["known_advisories"][0]["status"])
            self.assertEqual("known_version_match", next(item for item in report["leads"] if item["kind"] == "known_advisory")["state"])
            self.assertEqual("observed", next(item for item in report["coverage"] if item["area"] == "known_advisories")["status"])
            self.assertTrue(all(item["source_id"] in {source["id"] for source in report["inputs"]} for item in report["evidence"]))

    def test_source_framework_identity_is_not_used_as_app_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "source"
            framework = source / "ThirdParty" / "Example.framework"
            framework.mkdir(parents=True)
            (source / "Info.plist").write_bytes(plistlib.dumps({
                "CFBundleIdentifier": "$(PRODUCT_BUNDLE_IDENTIFIER)",
            }))
            (framework / "Info.plist").write_bytes(plistlib.dumps({
                "CFBundleIdentifier": "com.example.library",
                "CFBundleShortVersionString": "9.9",
            }))
            unlabelled = build_research_scan(source=source)
            self.assertIsNone(unlabelled["target"]["identifier"])
            self.assertIsNone(unlabelled["target"]["version"])
            labelled = build_research_scan(source=source, app="com.example.actual", app_version="1.2")
            self.assertEqual("com.example.actual", labelled["target"]["identifier"])
            self.assertEqual("1.2", labelled["target"]["version"])

    def test_ios_research_scan_omits_android_only_findings(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "mixed-source"
            source.mkdir()
            (source / "Network.java").write_text(
                "class Network { void test() { javax.net.ssl.TrustManager[] trustAllCerts = null; } }",
                encoding="utf-8",
            )
            (source / "Review.swift").write_text("SecTrustSetExceptions(trust, data)\n", encoding="utf-8")
            report = build_research_scan(source=source, app="com.example.app")
            self.assertNotIn("android", {item["details"].get("platform") for item in report["evidence"]})
            self.assertIn("IOS-CUSTOM-TRUST", {item["kind"] for item in report["leads"]})

    def test_static_evidence_ids_are_stable_across_repeated_scans(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            source = self.make_source(Path(temp))
            first = build_research_scan(source=source, app="com.example.app")
            second = build_research_scan(source=source, app="com.example.app")
            self.assertEqual([item["id"] for item in first["evidence"]],
                             [item["id"] for item in second["evidence"]])
            self.assertEqual([item["id"] for item in first["inputs"]],
                             [item["id"] for item in second["inputs"]])

    def test_readable_binary_and_encrypted_binary_are_distinguished(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            readable = root / "readable"
            readable.write_bytes(macho(False))
            report = build_research_scan(readable_binary=readable, app="com.example.app")
            self.assertEqual("not_encrypted", report["visibility"]["supplied_binary"]["encryption"])
            self.assertIn("custom_server_trust", {item["kind"] for item in report["leads"]})
            encrypted = root / "encrypted"
            encrypted.write_bytes(macho(True))
            report = build_research_scan(readable_binary=encrypted, app="com.example.app")
            self.assertEqual("encrypted", report["visibility"]["supplied_binary"]["encryption"])
            self.assertEqual([], report["leads"])

    def test_iphone_report_preserves_provisional_grade_as_researcher_recorded(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            exported = root / "iphone.json"
            exported.write_text(json.dumps({
                "schema_version": "2.1", "target": {"platform": "ios", "identifier": "com.example.app", "version": "1.0"},
                "artifacts": [{"id": "artifact-1", "sha256": "a" * 64}],
                "observations": [{"id": "observation-1", "kind": "network_contact",
                                  "details": {"domain": "app.example.test", "reported_contacts": 2},
                                  "provenance": {"artifact_id": "artifact-1", "locator": {"line_numbers": [1]}}}],
                "test_results": [{"evidence_ids": ["observation-1"]}],
                "assessment": {"status": "provisional", "grade": "C", "coverage_percent": 85,
                               "evidence_integrity_status": "verified"},
                "attack_vectors": [{"title": "Cross-account access", "state": "confirmed",
                                    "attacker_control": "A second test account", "impact": "Private content read",
                                    "attack_scenario": "If ownership checks fail, account B could read account A's item."}],
            }), encoding="utf-8")
            report = build_research_scan(iphone_report=exported)
            self.assertEqual("C", report["assessment"]["grade"])
            self.assertEqual("researcher_reported_impact", report["leads"][0]["state"])
            self.assertIn("account B", report["leads"][0]["attack_scenario"])
            self.assertEqual("unavailable", next(item for item in report["coverage"] if item["area"] == "backend_authorization")["status"])
            exported.write_text(exported.read_text().replace("observation-1", "missing", 1), encoding="utf-8")
            with self.assertRaises(ValueError):
                build_research_scan(iphone_report=exported)

    def test_cli_rejects_mismatched_app_and_creates_new_output(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            package = self.make_package(root)
            output = root / "out"
            self.assertEqual(1, main(["research-scan", "--package", str(package),
                                      "--app", "com.other.app", "--output", str(output)]))
            self.assertFalse(output.exists())
            self.assertEqual(0, main(["research-scan", "--package", str(package),
                                      "--output", str(output)]))
            self.assertTrue((output / "ai-review.md").exists())

    def test_ai_review_import_keeps_grade_and_marks_suggestions_unreviewed(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            report = build_research_scan(package=self.make_package(root))
            evidence_id = report["evidence"][0]["id"]
            response = root / "response.json"
            response.write_text(json.dumps({
                "format": "mobile-audit-ai-response-1.0",
                "hypotheses": [{
                    "hypothesis": "Try <script>alert(1)</script> through the declared URL scheme",
                    "priority": "medium", "priority_reason": "A link parameter is controllable",
                    "supporting_evidence_ids": [evidence_id],
                    "attacker_control": "A controlled link", "possible_impact": "Unintended in-app action",
                    "attack_scenario": "If the link reaches a protected action, its sender might invoke it.",
                    "test_plan": "Open a benign link under two controlled accounts",
                    "disconfirming_result": "Both accounts reject the unauthorized action",
                    "missing_evidence": "Handler behavior and authorization result", "confidence": "low",
                }],
            }), encoding="utf-8")
            original_assessment = report["assessment"].copy()
            updated = import_ai_review(report, response)
            self.assertEqual(original_assessment, updated["assessment"])
            self.assertEqual(0, len(report["llm_reviews"]))
            suggestion = next(item for item in updated["leads"] if item["state"] == "llm_suggestion")
            self.assertEqual([evidence_id], suggestion["evidence_ids"])
            self.assertIn("protected action", suggestion["attack_scenario"])
            self.assertEqual("unreviewed", updated["llm_reviews"][0]["status"])
            self.assertEqual(len(report["leads"]), len(ai_review_data(updated)["leads"]))
            output = root / "reviewed"
            write_research_bundle(updated, output)
            html = (output / "report.html").read_text()
            self.assertNotIn("<script>", html)
            self.assertIn("&lt;script&gt;", html)
            self.assertIn("Disconfirming result", html)
            with self.assertRaisesRegex(ValueError, "already been imported"):
                import_ai_review(updated, response)

    def test_ai_review_rejects_uncited_claim_and_cli_imports_valid_response(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            report_dir = root / "scan"
            self.assertEqual(0, main(["research-scan", "--package", str(self.make_package(root)),
                                      "--output", str(report_dir)]))
            response = root / "response.json"
            hypothesis = {
                "hypothesis": "Check link authorization", "priority": "medium",
                "priority_reason": "A link entry point was observed", "supporting_evidence_ids": ["missing"],
                "attacker_control": "A link", "possible_impact": "Unintended action",
                "test_plan": "Use a controlled account and link", "disconfirming_result": "Unauthorized action is rejected",
                "missing_evidence": "Handler trace", "confidence": "low",
            }
            response.write_text(json.dumps({"format": "mobile-audit-ai-response-1.0",
                                            "hypotheses": [hypothesis]}), encoding="utf-8")
            imported_dir = root / "imported"
            self.assertEqual(1, main(["import-ai-review", "--report", str(report_dir / "report.json"),
                                      "--response", str(response), "--output", str(imported_dir)]))
            self.assertFalse(imported_dir.exists())
            hypothesis["supporting_evidence_ids"] = [json.loads((report_dir / "report.json").read_text())["evidence"][0]["id"]]
            response.write_text(json.dumps({"format": "mobile-audit-ai-response-1.0",
                                            "hypotheses": [hypothesis]}), encoding="utf-8")
            self.assertEqual(0, main(["import-ai-review", "--report", str(report_dir / "report.json"),
                                      "--response", str(response), "--output", str(imported_dir)]))
            imported = json.loads((imported_dir / "report.json").read_text())
            self.assertEqual(1, len(imported["llm_reviews"]))
            self.assertEqual(1, sum(item["state"] == "llm_suggestion" for item in imported["leads"]))


if __name__ == "__main__":
    unittest.main()
