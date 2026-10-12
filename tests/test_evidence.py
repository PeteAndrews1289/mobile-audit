from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from mobile_audit.cli import main
from mobile_audit.evidence_reporting import write_evidence_html, write_evidence_json
from mobile_audit.models import Finding, Report
from mobile_audit.privacy_report import import_privacy_report, list_apps
from mobile_audit.static_adapter import adapt_static_report


FIXTURE = Path(__file__).parent / "fixtures" / "app_privacy_report.ndjson"


class EvidenceTests(unittest.TestCase):
    def test_import_isolates_one_app_and_pairs_access_events(self) -> None:
        self.assertEqual(["com.example.maps", "com.other.bank"], list_apps(FIXTURE))
        report = import_privacy_report(FIXTURE, "com.example.maps")
        data = report.to_dict()
        serialized = json.dumps(data)
        self.assertEqual("2.0", data["schema_version"])
        self.assertEqual("com.example.maps", data["target"]["identifier"])
        self.assertEqual([], data["sessions"])
        self.assertIsNone(data["environment"]["permissions"])
        self.assertNotIn("com.other.bank", serialized)
        self.assertNotIn("private.bank.example", serialized)
        self.assertNotIn("private-account-page", serialized)
        self.assertNotIn("/private/account", serialized)
        self.assertNotIn("domainClassification", serialized)
        self.assertNotIn("contextVerificationType", serialized)
        self.assertEqual([], data["findings"])
        accesses = [item for item in data["observations"] if item["kind"] == "resource_access"]
        networks = [item for item in data["observations"] if item["kind"] == "network_contact"]
        self.assertEqual(2, len(accesses))
        self.assertEqual(2, len(networks))
        location = next(item for item in accesses if item["details"]["category"] == "location")
        self.assertEqual("complete", location["details"]["interval_status"])
        self.assertEqual([1, 3], location["provenance"]["locator"]["line_numbers"])
        microphone = next(item for item in accesses if item["details"]["category"] == "microphone")
        self.assertEqual("incomplete", microphone["details"]["interval_status"])
        self.assertEqual(3, next(item for item in networks if item["details"]["domain"] == "api.example.test")["details"]["reported_contacts"])
        self.assertTrue(any(item["status"] == "unavailable" for item in data["coverage"]))

    def test_invalid_target_record_is_skipped_without_exposing_it(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "input.ndjson"
            path.write_text(
                '{"type":"networkActivity","bundleID":"app.one","domain":"valid.example","firstTimeStamp":"2026-10-01T00:00:00Z","timeStamp":"2026-10-01T00:01:00Z","hits":1}\n'
                '{"type":"networkActivity","bundleID":"app.one","domain":"bad.example","hits":"secret-value"}\n',
                encoding="utf-8",
            )
            report = import_privacy_report(path, "app.one")
            self.assertEqual(1, len(report.observations))
            self.assertIn("1 selected-app record", " ".join(report.notes))
            self.assertNotIn("secret-value", json.dumps(report.to_dict()))

    def test_malformed_json_fails_with_line_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.ndjson"
            path.write_text("{secret-value\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "line 1") as error:
                import_privacy_report(path, "app.one")
            self.assertNotIn("secret-value", str(error.exception))

    def test_fractional_timestamps_keep_network_range_order(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "fractional.ndjson"
            path.write_text(json.dumps({
                "type": "networkActivity", "bundleID": "app.one", "domain": "api.example",
                "firstTimeStamp": "2026-10-01T00:00:00Z",
                "timeStamp": "2026-10-01T00:00:00.001Z", "hits": 1,
            }) + "\n", encoding="utf-8")
            report = import_privacy_report(path, "app.one")
            self.assertEqual(1, len(report.observations))
            self.assertLess(
                report.observations[0].details["first_seen_at"],
                report.observations[0].details["last_seen_at"],
            )

    def test_html_escapes_imported_values(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "input.ndjson"
            path.write_text(json.dumps({
                "type": "networkActivity", "bundleID": "app.one", "domain": "<script>alert(1)</script>",
                "firstTimeStamp": "2026-10-01T00:00:00Z", "timeStamp": "2026-10-01T00:01:00Z", "hits": 1,
            }) + "\n", encoding="utf-8")
            report = import_privacy_report(path, "app.one")
            html_path = root / "report.html"
            write_evidence_html(report, html_path)
            content = html_path.read_text(encoding="utf-8")
            self.assertNotIn("<script>alert(1)</script>", content)
            self.assertIn("&lt;script&gt;", content)

    def test_static_adapter_links_leads_to_observations(self) -> None:
        legacy = Report(target="/Users/alice/private/MyApp")
        legacy.inventory["input_type"] = "source"
        legacy.coverage.append("Source configuration")
        legacy.add(Finding(
            "IOS-TEST", "Potential weak configuration", "ios", "medium", "medium",
            "Info.plist:3", "Flag enabled", "Review the flag", "MASVS-NETWORK-1",
        ))
        evidence = adapt_static_report(legacy).to_dict()
        self.assertEqual("security_lead", evidence["findings"][0]["state"])
        self.assertEqual("inconclusive", evidence["test_results"][0]["status"])
        self.assertEqual(
            evidence["findings"][0]["evidence_ids"],
            [evidence["observations"][0]["id"]],
        )
        self.assertEqual(["static_rules"], evidence["findings"][0]["coverage_areas"])
        self.assertNotIn("/Users/alice/private", json.dumps(evidence))

    def test_cli_writes_schema_and_legacy_scan_still_works(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            json_path = root / "privacy.json"
            html_path = root / "privacy.html"
            self.assertEqual(0, main(["privacy-report", str(FIXTURE), "--app", "com.example.maps", "--json", str(json_path), "--html", str(html_path)]))
            self.assertEqual("2.0", json.loads(json_path.read_text())["schema_version"])
            self.assertTrue(html_path.exists())
            source = root / "source"
            source.mkdir()
            (source / "Example.swift").write_text("let a = 1\n", encoding="utf-8")
            evidence_path = root / "static-evidence.json"
            self.assertEqual(0, main([str(source), "--evidence-json", str(evidence_path)]))
            self.assertEqual("static_scan", json.loads(evidence_path.read_text())["mode"])


if __name__ == "__main__":
    unittest.main()
