# Baseline Canary

This is a small SwiftUI training app with two **separate** Xcode projects. Both use `org.mobileaudit.baseline.canary`; install only one variant at a time. `Fixed` is version 1.0 and `Vulnerable` is version 1.1. The versions have the same simple UI and only invented account notes and token values.

| Case | Corrected 1.0 | Vulnerable 1.1 | Expected Mobile Audit result |
| --- | --- | --- | --- |
| `CB-01` Transport configuration | Default App Transport Security policy. | Global `NSAllowsArbitraryLoads` exemption. | New `IOS-ATS-GLOBAL` lead. The exemption alone does not prove traffic exposure. |
| `CB-02` Local storage | Invented token saved in Keychain. | Same token saved in UserDefaults. | New `IOS-USERDEFAULTS-SENSITIVE` lead. |
| `CB-03` Server trust | Default `URLSession` trust handling. | Delegate accepts any server certificate. | New `IOS-CUSTOM-TRUST` lead. A controlled HTTPS endpoint is needed for a runtime check. |
| `CB-04` Incoming link | Blocks a note requested for an account other than `alice`. | Displays `bob`'s invented note while signed in as `alice`. | Both versions declare the same custom URL scheme. A static entry-point lead is expected in both; the missing account check requires manual validation and is a current scanner blind spot. |

## Scan and compare without a simulator

From the `mobile-audit` directory after installing the CLI (`pip install -e .`):

```sh
mobile-audit research-scan --source baselines/CanaryApp/Fixed \
  --app org.mobileaudit.baseline.canary --app-version 1.0 \
  --name 'Baseline Canary' --output /path/to/canary-fixed-report

mobile-audit research-scan --source baselines/CanaryApp/Vulnerable \
  --app org.mobileaudit.baseline.canary --app-version 1.1 \
  --name 'Baseline Canary' \
  --previous-report /path/to/canary-fixed-report/report.json \
  --output /path/to/canary-vulnerable-report
```

The current scanner produces **one** fixed-version lead (the unchanged URL scheme), **four** vulnerable-version leads, and **three** new test-lead alerts plus an informational version-change alert. The [example watch report](../../examples/canary-watch.html) shows that result. Static-only assessments remain incomplete; no grade or CVE is implied.

## Build for a physical iPhone later

Open either `BaselineCanary.xcodeproj` in Xcode, choose your signing team and a connected iPhone, then build and run. Both projects also passed unsigned `xcodebuild` builds for `generic/platform=iOS` with Xcode 26.5. A signed device run has not yet been performed.

For the link check, while `alice` is shown as the active demo account, open `mobileauditcanary://note?owner=bob` from another app. The corrected app should show a blocked message; the vulnerable app should display Bob's invented note. The user must initiate this test; the app does not open links or make network requests by itself. For transport testing, a controlled HTTP endpoint can distinguish the ATS settings; a controlled HTTPS endpoint with a known invalid certificate can distinguish trust handling. Those observed outcomes should be recorded as guided-test evidence, separate from scanner pattern matches.
