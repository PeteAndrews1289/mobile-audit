# iOS baseline apps

This set measures whether Mobile Audit produces useful, correctly qualified evidence before it is used for research on unfamiliar apps. A deliberately vulnerable training app is a known test target, **not** a new CVE candidate. The upstream apps below are linked and pinned for repeatable source scans; their code and IPA files are not redistributed with Mobile Audit. The curated cases are in [benchmark.json](benchmark.json), and a completed source run is in the [scorecard](../examples/baseline-scorecard.md).

| App | Purpose | What has been checked here |
| --- | --- | --- |
| [Baseline Canary](CanaryApp/README.md) | Small iOS 17+ app with corrected 1.0 and vulnerable 1.1 variants under the same bundle ID. Tests source detection, change alerts, and a manual link check. | Both variants compile as unsigned generic-iPhone builds without starting a simulator. Fixed source produced one declared-link lead; vulnerable source produced four leads. The comparison produced three new test-lead alerts and a version-change note. No on-device behavior has been verified yet. |
| [Swift clean control](SwiftControls/Clean/clean_app.swift) | Source-only negative control for harmless preferences, comments, HTTPS, loopback URLs, and UI labels. | Six selected Swift rules stay clear. This is not a complete app or a broad false-positive study. |
| [Flutter clean control](FlutterControls/Clean/clean_app.dart) | Source-only negative control using secure storage and HTTPS. | Five selected Flutter rule families stay clear. This is not a complete app or a broad false-positive study. |
| [DVIA v2](https://github.com/prateek147/DVIA-v2) | Broad Swift training app for storage, cryptography, WebViews, IPC, network trust, and other classes. MIT licensed. | Three of three selected patterns detected; a commented-out MD5 call stayed clear at commit `96466ab85569dbcd37c69b2d15d22ff666f57031`. The project documents testing only through iOS 11; current-device installation is unverified. |
| [OWASP iGoat-Swift](https://github.com/OWASP/iGoat-Swift) | Established iOS training exercises spanning storage, transport, URL schemes, authentication, and more. GPL-3.0 licensed. | Three of three selected patterns detected; a rejected root password was not called a credential at commit `8c8a8ed6051279f06098f72d6d5aeeb65f8905f2`. Its app source uses an Xcode bundle-ID placeholder and includes a vendored framework; Mobile Audit avoids identifying that framework as the target app. Device installation is unverified, and some exercises require the project's server. |
| [iBugBazaar](https://github.com/payatu/iBugBazaar) | Swift training app whose README lists over 20 issues, including credentials, local storage, WebViews, and link handling. | Five selected pattern cases, one URL scheme inventory check, and a manual link case at commit `62f95c0ee1a857899b1f019635bbbaaad4becef4`. |
| [DVFA](https://github.com/Schmiemandev/dvfa) | Small Flutter finance app with a published challenge list and solutions. | Four selected Dart pattern cases and two manual cases at commit `bd291ed010cd362abe80204aae59a04335cfc756`. |
| [DVMA](https://github.com/cpeoples/dvma) | Larger Flutter training app with a structured vulnerability registry and iOS host configuration. | Five selected pattern cases and one manual WebView case at commit `c03ca9f0c303cd3f68b6b24e58048e94a0801216`. |
| [Oversecured Vulnerable iOS App](https://github.com/oversecured/OversecuredVulnerableiOSApp) | Small Swift training app with storage, cryptography, network, and incoming-link exercises. BSD licensed. | Five selected source patterns, a URL scheme inventory check, and two manual link cases at commit `859d862ddd50c606b0cf12b5df2bc5ea95499dfa`. |

The canary is the first physical-device target because it uses the current Xcode toolchain, needs no backend, and includes a corrected control. The public apps were read as source only. Some require an older Xcode configuration, Flutter SDK, server, or device setup. DVFA's iOS reverse-engineering challenge specifically requires a decrypted binary; this source benchmark does not attempt it. Upstream code is not bundled and stays under its own repository terms.

## Run the scorecard

From the `mobile-audit` directory with Python 3.10 or newer:

```sh
python3 baselines/fetch_upstream.py --destination /path/to/benchmark-sources
python3 -m mobile_audit benchmark \
  --manifest baselines/benchmark.json \
  --upstream-root /path/to/benchmark-sources \
  --output /path/to/benchmark-scorecard
```

The fetch script checks exact commits and uses sparse checkouts where possible. It does not build or execute downloaded apps. Pass `--app dvfa` to fetch one listed app. The benchmark runs the bundled controls even without upstream checkouts; external cases then appear as **skipped**. A checkout at a different commit is also skipped rather than compared silently. It writes `scorecard.md` and `scorecard.json`.

The complete source run detected **28 of 28 selected patterns**, kept **17 of 17 negative controls clear**, inventoried two selected URL schemes, and left **7 behavior cases pending manual testing**. This is a hand-selected development scorecard, not a population detection-rate estimate. A pattern match is a test lead, not proof of a reachable exploit. Unreviewed findings outside these cases are not counted as correct or false.

## Repeat the source scans

From the `mobile-audit` directory, run the canary commands in [its guide](CanaryApp/README.md). The scorecard fetch and scan commands above cover the external source trees at pinned commits. For a separate research report, point `--source` at the **app source directory**, excluding bundled Pods or server code, and pass the app bundle identifier and version read from the Xcode project. These source scans do not run app behavior, verify an exploit, or establish affected production versions.

## What we will measure

1. **Detection:** Does each known canary change create the expected evidence and alert? Does the corrected version stay clear of those three pattern matches?
2. **Qualification:** Does the report call a URL scheme an entry point rather than an authorization flaw? Does it keep static-only scans ungraded and avoid an intrusion or CVE claim?
3. **Human validation:** On a signed physical device, does the vulnerable canary's incoming link display another invented account's note while the corrected version blocks it? Can a researcher document that behavior and distinguish it from the static link declaration?
4. **Broader coverage:** For selected Swift and Flutter exercises, record the exact source path, expected pattern, observed lead, and whether the scanner missed or correctly qualified it. Controls include commented-out MD5 and HTTP, benign preferences, placeholders, and an HTTPS endpoint. Do not infer overall recall from these selected cases or from the number of leads alone.

No simulator was used for these checks. The canary uses invented data and sends no network request unless its Probe button is pressed with a researcher-supplied HTTPS endpoint.
