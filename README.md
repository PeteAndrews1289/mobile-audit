# Mobile Audit

Mobile Audit is an iOS-first, local evidence tool for mobile app security and privacy research. Its primary target is a third-party app running on a standard iPhone; an IPA, Mac-compatible copy, or developer source is optional. The iPhone app can start a private research case for any app you name, even without an App Privacy Report. It can also import an Apple App Privacy Report, save selected-app snapshots, compare exports across labeled test sessions, and create shareable HTML and evidence JSON reports from those snapshots. Guided checks on a physical iPhone can add structured potential attack vectors and a provisional, evidence-linked A–F security grade. The Mac CLI can acquire a licensed App Store IPA, validate it, and combine it with iPhone activity or supplied source in one research report. The first live third-party package acquisition has been validated; a new researcher signs in locally before downloading apps associated with their Apple Account.

**Current status:** research prototype. The CLI, report generation, synthetic baseline, and package acquisition have been exercised; the complete guided assessment and export flow has not yet been verified on a signed physical iPhone. Static matches are test leads, not confirmed vulnerabilities. See the [project brief](docs/PROJECT_BRIEF.md) for a quick capability and validation summary, the [roadmap](ROADMAP.md) for the next gates, and [contributing](CONTRIBUTING.md) for development and data-handling rules.

| Surface | What it does | What it cannot establish alone |
| --- | --- | --- |
| iPhone app | Imports App Privacy Report data, saves selected-app observations, guides manual checks, and prepares evidence-linked reports | Request contents, other apps' private files, or exploitability from an export |
| Python CLI | Scans source and supplied IPA/APK packages, validates a licensed iOS acquisition, and combines available evidence | Original source from encrypted App Store code or runtime behavior from a static match |
| Research workflow | Compares versions, records conditional attack paths, prepares a minimized AI handoff, and separates known advisory matches | Automatic intrusion detection, a verified vulnerability, or a CVE assignment |

**Start with the iPhone app:** [ios/README.md](ios/README.md) · [Xcode project](ios/MobileAudit.xcodeproj)

A [synthetic assessment report](examples/sample-assessment.html) shows the provisional grade, the reasons for it, the guided-check coverage table, and attack-vector layout. Its app and finding are invented test data.

For a possible new vulnerability, the iPhone app keeps exact reproduction steps, expected and observed behavior, attacker control, and possible prior reports in a separate private case. A [synthetic private case draft](examples/sample-private-case.txt) shows the format. It is researcher-recorded working material for independent review, not a CVE assignment or proof that the target has a vulnerability.

The product and research design is in [DESIGN.md](DESIGN.md); the [near-term roadmap](ROADMAP.md) lists the next test gates. The [iOS package acquisition guide](docs/IOS_PACKAGE_ACQUISITION.md) explains how to get an App Store IPA on a Mac and what remains encrypted. The iPhone's machine-readable report contract is [schema 2.1](schema/evidence-report.schema.json); [schema 2.0](schema/evidence-report-2.0.schema.json) remains available for Mac CLI output.

## Acquire and scan an App Store app on the Mac

Mobile Audit now offers one local command family for backend setup, Apple Account sign-in, App Store search, IPA download, verification, and scanning. `ipatool` is the MIT-licensed acquisition backend; setup installs it with Homebrew when needed. Sign-in happens in its interactive terminal flow, and Mobile Audit does not ask for or write an Apple Account password or two-factor code. The account must already have a license for the app, including free apps. Run these commands in a terminal from this project directory:

```sh
python3 -m mobile_audit acquire-ios setup
python3 -m mobile_audit acquire-ios auth
python3 -m mobile_audit acquire-ios search "App Name"
python3 -m mobile_audit acquire-ios download \
  --bundle-id BUNDLE.ID.FROM.SEARCH \
  --phone-version VERSION.ON.PHONE \
  --output /path/to/new-acquisition
```

The output directory contains `package.ipa`, `acquisition.json`, and `scan/report.html` with companion JSON, change-triage, and AI-review files. Add `--privacy-report /path/to/export.ndjson` or `--iphone-report /path/to/evidence.json` to combine phone evidence during acquisition. The command checks ZIP integrity, the main app identity, package hash, version/build, and native-code encryption. A version mismatch is shown prominently; it must be resolved before linking package code to phone behavior. Downloading the IPA does not decrypt its native executable. One licensed third-party App Store package was acquired and scanned locally in October 2026; the IPA and its app-specific report remain under ignored `reports/` rather than in the source release.

## Run one iOS research scan

The Mac companion can begin with any available input. An App Privacy Report needs a selected bundle identifier; package-only and source-only scans work without an iPhone export. For a third-party iPhone app, start with its privacy export:

```sh
.venv/bin/mobile-audit research-scan \
  --privacy-report /path/to/AppPrivacyReport.ndjson \
  --app com.example.app --name "Example App" \
  --output /path/to/new-phone-report
```

Add package or source evidence later when available. Here is a combined scan:

```sh
.venv/bin/mobile-audit research-scan \
  --package /path/to/App.ipa \
  --source /path/to/ios/project \
  --privacy-report /path/to/AppPrivacyReport.ndjson \
  --app com.example.app --name "Example App" \
  --output /path/to/new-research-report
```

Use `--iphone-report /path/to/evidence.json` instead of `--privacy-report` to include a Mobile Audit iPhone assessment. A researcher-supplied unencrypted Mach-O can be added with `--readable-binary /path/to/executable`; its relationship to the assessed app must be checked independently. The command creates `report.html`, `report.json`, `watch.html`, `watch.json`, `ai-review.json`, and `ai-review.md` in a **new** local directory. The first watch report triages test leads but has no change alerts until there is an earlier report to compare. The [synthetic unified report](examples/sample-research-scan.html) shows the layout; its app and activity are invented. The [research schema](schema/research-report.schema.json) describes the JSON contract.

The report links each lead to an observation, gives a controlled next test and a conditional remediation, and shows whether source, native code, app activity, request contents, and backend behavior were actually examined. When the evidence supports a meaningful hypothesis, **Possible attack path** explains how an attacker might use the entry point, what security boundary could fail, and what outcome could follow. It is explicitly conditional; the finding state and evidence show what was actually observed. Static leads also include a rule-specific test and a result that would weaken the suspected risk. These plans use no matched source literals. A grade is shown only when imported from a sufficiently documented iPhone assessment, labeled **provisional** and researcher-recorded; other scans say **assessment incomplete**.

The **Attack path hypotheses** section pairs co-present clues into five focused research questions: external links with web-code sinks, document imports with a deserializer reference, external links with a fixed client authentication comparison, global ATS exceptions with constructed HTTP URLs, and web-code sinks with a native WebView bridge reference. Each card cites both clues, names the unverified connection between them, and suggests a test and a disconfirming result. The structured `path_analysis` record also travels in `ai-review.json` and the watch report's candidate checklist. Pairing does not trace data flow or establish a vulnerability. The [synthetic attack-path example](examples/sample-attack-paths.html) exercises all five patterns. Package metadata and API-name references remain hypotheses until tested.

For third-party App Store apps, the iPhone workflow can gather privacy activity and guided test evidence without source code. The Mac command can [download and scan a licensed IPA](docs/IOS_PACKAGE_ACQUISITION.md) in one workflow. Native code marked as encrypted remains unavailable to this scanner. A supplied readable binary is analyzed separately and its identity with the app is not automatically proven. The scanner does not copy another app from a phone or reconstruct original Swift source.

The AI handoff contains a minimized evidence index and asks a model to rank hypotheses with evidence IDs, conditional attack scenarios, disconfirming tests, and missing evidence. Network domains are omitted from it by default; add `--ai-include-domains` if needed. No model is contacted automatically, and you should review the handoff before sharing it. App-derived text is untrusted data, not instructions for the model.

If you send `ai-review.json` to a model, save its answer as JSON in the `task.response_format` shape, then import it into a new report directory:

```sh
.venv/bin/mobile-audit import-ai-review \
  --report /path/to/new-research-report/report.json \
  --response /path/to/model-response.json \
  --output /path/to/research-report-with-ai-suggestions
```

The import checks that every suggestion cites existing evidence. Suggestions remain explicitly **unreviewed**, do not change the grade, and are excluded from later AI handoffs to avoid feeding a model its own claims as evidence. See the [synthetic model response](examples/sample-ai-response.json), [imported example report](examples/sample-ai-imported-report.html), and [response schema](schema/ai-response.schema.json).

If source lockfiles identify exact dependency versions, add `--check-known-vulns` to send only those package coordinates to [OSV's version-query API](https://google.github.io/osv.dev/post-v1-querybatch/). Returned advisories are version matches whose inclusion and relevance to the shipped iOS app still need checking. Without that flag, the scan stays local.

## Watch changes and triage CVE research paths

After a later scan of the **same bundle identifier**, add `--previous-report` to create change alerts alongside the new research report:

```sh
.venv/bin/mobile-audit research-scan \
  --privacy-report /path/to/later-AppPrivacyReport.ndjson \
  --app com.example.app --app-version 2.0 \
  --previous-report /path/to/earlier-report/report.json \
  --output /path/to/later-report
```

You can also compare two reports that already exist:

```sh
.venv/bin/mobile-audit watch-report \
  --previous /path/to/earlier-report/report.json \
  --current /path/to/later-report/report.json \
  --output /path/to/change-review
```

`watch.html` and `watch.json` show newly observed test leads, network domains, sensitive-resource categories, known-advisory version matches, reduced scan coverage, and changes in the provisional grade. Review these files before sharing them: unlike the AI handoff, they can contain the selected app's network domains. `watch-report --fail-on medium` exits with code 2 when a medium or high change alert appears, which lets a researcher use the command in a local scheduled job. Mobile Audit does **not** collect future activity automatically or send notifications; a new iPhone export or package/source scan must be supplied. Apple's App Privacy Report describes a [rolling seven-day period](https://developer.apple.com/documentation/network/inspecting-app-activity-data), so a newly observed domain is a change to investigate, **not** an intrusion detection.

Each watch report also sorts test leads into research stages: a single clue, multiple clues without a verified path, or researcher-reported impact awaiting independent review. When a lead has a conditional attack path, the triage card carries it forward. Paired-clue cards name the specific missing connection. It lists the remaining steps for a possible novel vulnerability, including reproduction, affected versions, and checking prior reports. It does not estimate a CVE probability or assign an ID. Published advisory matches are kept apart from novel-issue paths. The [synthetic change report](examples/sample-watch.html) and [watch schema](schema/watch-report.schema.json) show the format. The [CVE Program's current CNA rules](https://www.cve.org/ResourcesSupport/AllResources/CNARules) require evidence of a vulnerability and affected-product information for assignment.

## Baseline vulnerable apps

The [baseline set](baselines/README.md) covers native Swift and Flutter: a buildable iOS canary with corrected and vulnerable versions, separate Swift and Flutter clean controls, and six pinned public training apps. The repeatable [scorecard](examples/baseline-scorecard.md) checks 28 selected source patterns and 17 negative controls, with seven behavior cases awaiting device testing. These hand-picked exercises calibrate the rules; the scorecard is not a population detection rate or a novel CVE discovery. The canary's [test guide](baselines/CanaryApp/README.md) lists change alerts and a later physical-iPhone link check.

## Install

These instructions install the optional Mac CLI. The iPhone app has a separate [setup guide](ios/README.md).

Python 3.10 or newer is required. No third-party package is required for App Privacy Report import or iOS static scanning.

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -e .
```

## Import an iPhone App Privacy Report

Export the report using iOS Settings, transfer the file to your Mac, and first list the bundle identifiers it contains:

```sh
.venv/bin/mobile-audit privacy-report /path/to/AppPrivacyReport.ndjson --list-apps
```

Choose one identifier and generate both report formats:

```sh
.venv/bin/mobile-audit privacy-report /path/to/AppPrivacyReport.ndjson \
  --app com.example.app --json app-evidence.json --html app-evidence.html
```

The importer reads the export locally, keeps only access and network records attributed to the selected bundle identifier in its output, and records a SHA-256 hash plus source line numbers for provenance. It does not copy the full export or include the Apple `context` field, which can contain browsing context. The HTML and JSON may still contain sensitive selected-app domains. Review them before sharing.

Apple's export is newline-delimited JSON and describes recent activity. Network contact counts are aggregate values from Apple's reporting period; they are not measurements of a single user action. The export does not show request contents, private app files, app version, or exploitability. Incomplete access intervals are shown as incomplete. See [Apple's activity-data documentation](https://developer.apple.com/documentation/network/inspecting-app-activity-data) for the source fields.

A synthetic fixture and [example report](examples/sample-privacy.html) are provided for trying the workflow. The network importer was validated against a real iPhone export using Apple's newer v4 record shape. The private export and its app activity are excluded from the source bundle. Resource-access interval parsing is still covered by synthetic fixtures because that export contained no access records.

```sh
.venv/bin/mobile-audit privacy-report tests/fixtures/app_privacy_report.ndjson \
  --app com.example.maps --json sample.json --html sample.html
```

## Scan source or packages

The existing command remains available. It scans source directories, `.app` bundles, `.ipa` files, and `.apk` files:

```sh
.venv/bin/mobile-audit /path/to/ios/source --json legacy.json --html legacy.html
.venv/bin/mobile-audit /path/to/App.ipa --source /path/to/ios/source --evidence-json evidence.json --evidence-html evidence.html
```

`--json` and `--html` produce the original 1.0 static report. `--evidence-json` and `--evidence-html` adapt static rule matches to evidence schema 2.0. Each match becomes a **security lead** linked to a source observation and an **inconclusive** test result. The adapter does not promote a code pattern to a confirmed vulnerability. `--fail-on high` exits with code 2 for a high or critical static finding; exit code 1 means the scan failed.

### Examine an iOS package on a Mac

For an `.ipa` or `.app` you have obtained, the static report includes a MobSF-style iOS package profile: artifact hash and size, app metadata, app and extension bundles, declared privacy access, ATS settings, signing details, Mach-O architecture and hardening flags, linked libraries, entry points, and readable assets. The same profile appears in `research-scan` when a package is supplied. Findings remain **leads to test**, and package-only scans receive no A–F grade. The report marks encrypted executable code as unavailable for code-reference inspection. The [MobSF-to-iOS comparison](docs/MOBSF_IOS_COMPARISON.md) lists the mapped sections and remaining limits; the [synthetic package report](examples/sample-package-analysis.html) shows the layout.

Export source-like files shipped in the package to a new local directory:

```sh
.venv/bin/mobile-audit extract-ios-assets /path/to/App.ipa --output /path/to/extracted-assets
```

The output has the copied files and a `manifest.json` with package-relative paths and SHA-256 hashes. If a source map embeds JavaScript or TypeScript in `sourcesContent`, the exporter also writes that text under `_recovered_source_maps/` and records its hash. A JavaScript bundle may be minified or contain bytecode; the exporter preserves its original bytes. It does not decrypt an App Store executable or recreate original Swift or Objective-C source. A developer-provided source tree or unencrypted test build enables substantially deeper analysis. [OWASP explains the distinction between IPA resources, compiled binaries, and encrypted App Store code](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0054/).

For Android APK decoding, install the optional dependency:

```sh
.venv/bin/python -m pip install -e '.[android]'
```

On macOS, `codesign` enables signed-entitlement inspection for iOS bundles and IPAs.

### Static checks

| Platform | Checks |
| --- | --- |
| iOS | ATS exceptions, insecure WebView loads, file sharing, signed/source debug entitlements, weak Keychain accessibility, weak cryptography APIs, fixed key or IV literals, HTTP URL construction, fixed authentication comparisons, custom TLS trust handling, possible sensitive UserDefaults writes, bundled JavaScript/TypeScript risk patterns, embedded secrets |
| Flutter source | Selected Dart patterns for sensitive SharedPreferences writes, literal HTTP request URLs, fixed cryptographic keys, AES-ECB mode, and sensitive log interpolation |
| Android | Debuggable builds, cleartext traffic, backup review, exported providers/services/receivers without declared permissions, network security configuration, trust-all code patterns, embedded secrets |

The scanner uses conservative rules and redacts values that look like embedded secrets. A clean report means these checks found no issue; it is not a complete security assessment. Mach-O load commands and selected API-name references are inventoried. Native disassembly, decompilation, automated dynamic behavior, and backend authorization tests are not part of this release. Known-advisory matching is optional and requires exact versions from lockfiles. Binary API names can appear without being used in a reachable security path.

## Evidence model

Schema 2.0 separates **sessions**, **artifacts**, **observations**, **test results**, **findings**, and **coverage**. Every finding references observation IDs and coverage areas; every observation points to a hashed source artifact and a line number or finding index. The iPhone's schema 2.1 report adds **assessment** and **attack_vectors**. It lists the grade rationale and checks saved evidence files against their hashes before a file can support a grade or reproduced-impact vector. This checks file integrity, not the researcher's interpretation. Guided test outcomes remain researcher-recorded; the tool does not automatically promote them to confirmed vulnerability findings. Exact private case notes are omitted from shared HTML and JSON reports. App Privacy Report imports alone remain ungraded.

No analysis requires a service or account. The tool does not upload exports or reports. The original export remains wherever the user saved it; deleting generated reports does not delete that original file.

Generated files under `reports/` are ignored by Git so personal activity is not included in a later source release.

## Development

```sh
python3 -m unittest discover -s tests -v
```

The fixture is synthetic and includes unrelated-app records to test isolation. This project is an independent scanner and does not bundle MobSF code.
