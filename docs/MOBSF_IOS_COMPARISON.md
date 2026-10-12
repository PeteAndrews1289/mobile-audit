# iOS package report compared with the supplied MobSF APK reports

This comparison uses the recurring sections in 16 locally supplied MobSF reports for Android ride-share APKs. File/app information, components, certificates, permissions, network settings, manifest/code analysis, trackers, and scan logs appeared in all 16. Shared-library binary analysis appeared in nine, domain malware checks in eight, email listings in seven, and store information in 14. It maps the *research questions* to iOS evidence; Android permissions, activities, and scores do not transfer directly to iOS.

| MobSF APK section | Current Mobile Audit iOS analogue | Limit |
| --- | --- | --- |
| Findings severity | Static findings with severity, confidence, location, and suggested action | A match is a test lead. Package-only scans receive no A–F grade. |
| File and app information | IPA SHA-256, size, file count; bundle ID, name, version, build, minimum iOS | An `.app` directory has no single-file hash. |
| App components | App, extension, framework, and resource bundle inventory; executable and linked-library lists | A declared component does not prove a reachable attack path. |
| Certificate information and analysis | Code-signature identifier, team ID, authorities, Mach-O signature command; strict bundle verification for a supplied `.app` | An IPA scan inspects extracted executable signatures but does not verify the reconstructed bundle or its resources. |
| Application permissions and abused permissions | Info.plist usage-description keys, privacy manifest declarations, signed entitlement keys | These are declarations; user grants, actual access, and abuse require activity or device evidence. |
| APKID and shared-library binary analysis | Mach-O architecture, encryption flag, minimum OS, SDK, PIE flag, signature command, linked libraries, selected API-name clues | No full native decompilation or reliable SDK classification; encrypted code is marked unavailable. |
| Browsable activities | URL schemes, universal-link domains when signed entitlements are readable, document types | Handler behavior and authorization must be tested on a device. |
| Network security | App Transport Security settings and exceptions; optional iPhone App Privacy Report contact data in a research scan | Neither proves traffic content, TLS validation, or endpoint security. |
| Manifest analysis | Info.plist, privacy manifests, and entitlements | Not equivalent to Android's manifest or component export model. |
| Code analysis | Bounded source and packaged web-code checks; selected references in readable native binaries | No original Swift reconstruction from a compiled IPA and no data-flow proof. |
| NIAP analysis | Selected findings mapped to OWASP MASVS/MASWE | No NIAP certification or full compliance claim. |
| Trackers | Privacy manifest declarations and library inventory | No tracker verdict from a library name or declaration alone. |
| Scan logs | Explicit checks run, warnings, visibility counts, and input provenance | No per-stage timing log yet. |
| Domain malware check | App-attributed contact domains from an optional iPhone export | No domain reputation lookup or maliciousness verdict. |
| Emails and store information | No systematic email harvesting or App Store metadata collection | Can be added later with a clear privacy and provenance model. |

The iOS package profile is available in both the static HTML/JSON report and a unified `research-scan` report. The latter can also include iPhone activity, source, exact-version lockfile advisory matches, and conditional attack-path hypotheses. The package profile itself is not sent in the minimized AI handoff.

## Reproduce with a training IPA

```sh
.venv/bin/mobile-audit /path/to/TrainingApp.ipa \
  --json /path/to/static-report.json --html /path/to/static-report.html

.venv/bin/mobile-audit research-scan \
  --package /path/to/TrainingApp.ipa --output /path/to/new-research-report
```

Use a package you are authorized to examine. For an App Store app, the iPhone privacy export alone cannot supply executable bytes. A developer or researcher-provided test build provides much deeper inspection. A score or CVE claim needs reproduced, affected-version-specific evidence beyond these static sections.
