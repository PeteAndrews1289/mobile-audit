from __future__ import annotations

import json
import plistlib
import tempfile
import unittest
from pathlib import Path

from mobile_audit.cli import main
from mobile_audit.research import build_research_scan
from mobile_audit.research_reporting import write_research_bundle
from mobile_audit.watch import build_watch_report
from mobile_audit.watch_reporting import watch_html


def privacy_export(path: Path, domains: list[str], hits: int = 1) -> Path:
    records = [
        {"type": "networkActivity", "bundleID": "com.example.watch", "domain": domain,
         "firstTimeStamp": "2026-10-01T00:00:00Z", "timeStamp": "2026-10-01T00:01:00Z", "hits": hits}
        for domain in domains
    ]
    path.write_text("\n".join(json.dumps(item) for item in records) + "\n", encoding="utf-8")
    return path


class WatchTests(unittest.TestCase):
    def test_first_scan_triages_lead_without_intrusion_alert(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "source"
            source.mkdir()
            (source / "Trust.swift").write_text("SecTrustSetExceptions(trust, data)\n", encoding="utf-8")
            current = build_research_scan(source=source, app="com.example.watch")
            watch = build_watch_report(current)
            self.assertEqual([], watch["alerts"])
            self.assertEqual("test_lead_only", watch["candidate_triage"][0]["stage"])
            self.assertEqual("not_demonstrated", watch["candidate_triage"][0]["cve_readiness"])
            self.assertIn("network path", watch["candidate_triage"][0]["attack_scenario"])
            self.assertIn("Possible attack path", watch_html(watch))
            output = Path(temp) / "research"
            write_research_bundle(current, output)
            self.assertTrue((output / "watch.html").exists())
            self.assertTrue((output / "watch.json").exists())

    def test_new_domain_is_change_alert_not_intrusion_detection(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            previous = build_research_scan(privacy_report=privacy_export(root / "before.ndjson", ["api.example.test"]),
                                           app="com.example.watch")
            current = build_research_scan(privacy_report=privacy_export(root / "after.ndjson", ["api.example.test", "cdn.example.test"]),
                                          app="com.example.watch")
            watch = build_watch_report(current, previous)
            new_domains = [item for item in watch["alerts"] if item["kind"] == "new_network_domain"]
            self.assertEqual(1, len(new_domains))
            self.assertIn("cdn.example.test", new_domains[0]["summary"])
            self.assertIn("not evidence of intrusion", new_domains[0]["explanation"])
            same_domains = build_research_scan(privacy_report=privacy_export(root / "counts.ndjson", ["api.example.test"], hits=9),
                                               app="com.example.watch")
            self.assertEqual([], build_watch_report(same_domains, previous)["alerts"])

    def test_new_lead_and_reduced_coverage_are_distinguished(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "source"
            source.mkdir()
            previous = build_research_scan(source=source, app="com.example.watch")
            (source / "Trust.swift").write_text("SecTrustSetExceptions(trust, data)\n", encoding="utf-8")
            current = build_research_scan(source=source, app="com.example.watch")
            watch = build_watch_report(current, previous)
            self.assertEqual(1, watch["comparison"]["newly_observed_lead_count"])
            self.assertIn("new_test_lead", {item["kind"] for item in watch["alerts"]})
            without_source = build_research_scan(privacy_report=privacy_export(root / "activity.ndjson", ["api.example.test"]),
                                                 app="com.example.watch")
            reduced = build_watch_report(without_source, current)
            self.assertIn("coverage_reduced", {item["kind"] for item in reduced["alerts"]})
            self.assertGreater(reduced["comparison"]["no_longer_observed_lead_count"], 0)
            self.assertTrue(any("not a verified fix" in note for note in reduced["notes"]))

    def test_second_web_sink_does_not_rediscover_existing_correlation(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "source"
            source.mkdir()
            (source / "Info.plist").write_bytes(plistlib.dumps({
                "CFBundleIdentifier": "com.example.watch",
                "CFBundleURLTypes": [{"CFBundleURLSchemes": ["sample"]}],
            }))
            (source / "b.ts").write_text("eval(userInput)\n", encoding="utf-8")
            before = build_research_scan(source=source, app="com.example.watch")
            (source / "a.ts").write_text("eval(otherInput)\n", encoding="utf-8")
            after = build_research_scan(source=source, app="com.example.watch")
            watch = build_watch_report(after, before)
            new_leads = [item for item in watch["alerts"] if item["kind"] == "new_test_lead"]
            self.assertEqual(1, len(new_leads))
            self.assertEqual("low", new_leads[0]["severity"])

    def test_paired_path_triage_names_missing_connection_and_stays_stable(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "source"
            source.mkdir()
            (source / "Info.plist").write_bytes(plistlib.dumps({
                "CFBundleIdentifier": "com.example.watch",
                "CFBundleURLTypes": [{"CFBundleURLSchemes": ["sample"]}],
            }))
            (source / "Auth.swift").write_text('if password == "FixedValue" { allowAccess() }\n', encoding="utf-8")
            before = build_research_scan(source=source, app="com.example.watch")
            path = next(item for item in before["leads"] if item["kind"] == "external_link_auth_boundary_review")
            candidate = next(item for item in build_watch_report(before)["candidate_triage"]
                             if item["lead_id"] == path["id"])
            self.assertEqual("multiple_clues_no_path_verified", candidate["stage"])
            self.assertEqual("not_demonstrated", candidate["cve_readiness"])
            self.assertTrue(any(path["path_analysis"]["missing_link"] in step
                                for step in candidate["missing_steps"]))
            (source / "OtherAuth.swift").write_text('if password == "OtherValue" { allowAccess() }\n', encoding="utf-8")
            after = build_research_scan(source=source, app="com.example.watch")
            watch = build_watch_report(after, before)
            self.assertFalse(any(item["kind"] == "new_test_lead" and
                                 any(lead["kind"] == "external_link_auth_boundary_review" and lead["id"] in item["lead_ids"]
                                     for lead in after["leads"]) for item in watch["alerts"]))

    def test_reported_impact_requires_review_and_known_match_is_separate(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            iphone = root / "iphone.json"
            iphone.write_text(json.dumps({
                "schema_version": "2.1", "target": {"platform": "ios", "identifier": "com.example.watch", "version": "1.0"},
                "artifacts": [{"id": "artifact-1", "sha256": "a" * 64}],
                "observations": [{"id": "observation-1", "kind": "network_contact",
                                  "details": {"domain": "api.example.test"},
                                  "provenance": {"artifact_id": "artifact-1", "locator": {"line_numbers": [1]}}}],
                "test_results": [{"evidence_ids": ["observation-1"]}],
                "attack_vectors": [{"title": "Controlled cross-account access", "state": "confirmed",
                                    "attacker_control": "Second test account", "impact": "Private object read"}],
            }), encoding="utf-8")
            impact_report = build_research_scan(iphone_report=iphone)
            candidate = build_watch_report(impact_report)["candidate_triage"][0]
            self.assertEqual("reported_impact_needs_independent_review", candidate["stage"])
            self.assertEqual("independent_review_required", candidate["cve_readiness"])
            source = root / "source"
            source.mkdir()
            (source / "Package.resolved").write_text(json.dumps({
                "version": 2, "pins": [{"identity": "example-lib", "location": "https://github.com/example/example-lib.git",
                                        "state": {"version": "1.2.3", "revision": "a" * 40}}],
            }), encoding="utf-8")
            def fake_osv(_: bytes) -> bytes:
                return json.dumps({"results": [{"vulns": [{"id": "GHSA-abcd-1234-5678"}]}]}).encode()
            before = build_research_scan(source=source, app="com.example.watch")
            after = build_research_scan(source=source, app="com.example.watch",
                                        check_known_vulns=True, osv_post=fake_osv)
            watch = build_watch_report(after, before)
            self.assertIn("new_known_advisory_match", {item["kind"] for item in watch["alerts"]})
            self.assertEqual([], watch["candidate_triage"])

    def test_mismatched_apps_are_rejected_and_html_escapes_values(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            previous = build_research_scan(source=Path(temp), app="com.example.one")
            current = build_research_scan(source=Path(temp), app="com.example.two")
            with self.assertRaisesRegex(ValueError, "same nonempty"):
                build_watch_report(current, previous)
            current["target"]["name"] = '<script>alert("x")</script>'
            html = watch_html(build_watch_report(current))
            self.assertNotIn("<script>", html)
            self.assertIn("&lt;script&gt;", html)

    def test_watch_cli_alert_exit_code(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "source"
            source.mkdir()
            before = build_research_scan(source=source, app="com.example.watch")
            (source / "Trust.swift").write_text("SecTrustSetExceptions(trust, data)\n", encoding="utf-8")
            after = build_research_scan(source=source, app="com.example.watch")
            before_path, after_path = root / "before.json", root / "after.json"
            before_path.write_text(json.dumps(before), encoding="utf-8")
            after_path.write_text(json.dumps(after), encoding="utf-8")
            output = root / "watch-output"
            self.assertEqual(2, main(["watch-report", "--previous", str(before_path),
                                      "--current", str(after_path), "--output", str(output),
                                      "--fail-on", "medium"]))
            self.assertTrue((output / "watch.html").exists())
            self.assertEqual(1, len(json.loads((output / "watch.json").read_text())["alerts"]))


if __name__ == "__main__":
    unittest.main()
