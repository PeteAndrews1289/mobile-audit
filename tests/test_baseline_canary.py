from __future__ import annotations

import unittest
from pathlib import Path

from mobile_audit.research import build_research_scan
from mobile_audit.watch import build_watch_report


CANARY = Path(__file__).resolve().parents[1] / "baselines" / "CanaryApp"
APP_ID = "org.mobileaudit.baseline.canary"


class CanaryBaselineTests(unittest.TestCase):
    def test_known_changes_are_detected_without_rediscovering_unchanged_link(self) -> None:
        fixed = build_research_scan(source=CANARY / "Fixed", app=APP_ID, app_version="1.0")
        vulnerable = build_research_scan(source=CANARY / "Vulnerable", app=APP_ID, app_version="1.1")
        fixed_kinds = {lead["kind"] for lead in fixed["leads"]}
        vulnerable_kinds = {lead["kind"] for lead in vulnerable["leads"]}

        self.assertEqual({"custom_url_scheme"}, fixed_kinds)
        self.assertEqual({"custom_url_scheme", "IOS-ATS-GLOBAL", "IOS-CUSTOM-TRUST",
                          "IOS-USERDEFAULTS-SENSITIVE"}, vulnerable_kinds)
        watch = build_watch_report(vulnerable, fixed)
        self.assertEqual(3, watch["comparison"]["newly_observed_lead_count"])
        self.assertEqual(0, watch["comparison"]["no_longer_observed_lead_count"])
        self.assertEqual(3, sum(item["kind"] == "new_test_lead" for item in watch["alerts"]))
        self.assertFalse(any(item["kind"] == "new_entry_point" for item in watch["alerts"]))
        self.assertEqual("incomplete", vulnerable["assessment"]["status"])


if __name__ == "__main__":
    unittest.main()
