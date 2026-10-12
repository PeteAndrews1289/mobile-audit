# Mobile Audit Product and Research Design

Mobile Audit is an open source tool for examining the security and privacy behavior of mobile apps. Its first audience is people testing apps installed on their own iPhones. A separate research workflow adds repeatable testing, app package analysis, and evidence management. The long-term research goal is to discover previously unknown vulnerabilities that can be responsibly disclosed and, where appropriate, assigned CVE IDs. The target is the application being run and its app-mediated services within the research scope. Finding vulnerabilities in iOS itself is outside the current project scope.

The first release will make narrow, verifiable claims about observed behavior. The final assessment report will identify potential attack vectors and give the app a security grade when enough relevant tests have been completed. Every grade will display its test coverage and evidence strength. The tool will distinguish a privacy observation, a security lead, a confirmed vulnerability, and a known vulnerability match.

## Product decisions

1. **iOS comes first.** The evidence format remains platform neutral so the existing Android scanner can join later.
2. **A standard iPhone is the starting point.** The initial app imports a report the user explicitly shares from iOS Settings. It does not require a jailbreak, a VPN, a modified target app, or access to the target's source code.
3. **Analysis stays local by default.** The tool will neither upload activity reports nor send captured credentials to a service. Sharing a sanitized report is an explicit user action.
4. **Evidence controls the language and grade.** Each claim identifies what was observed, how it was collected, what conditions were tested, and what remains unknown. Severity describes possible impact; confidence describes support for the claim; coverage describes what the test could inspect. Untested checks never count as passed checks.
5. **Active testing is a separate research mode.** Network interception, link testing, file fuzzing, and API tests require a defined target, test accounts, and an appropriate testing scope. The consumer workflow performs no automated attacks against third-party services.
6. **A CVE ID is an outcome of review and disclosure.** The tool may identify an existing CVE or prepare a new vulnerability candidate, but a CVE Numbering Authority decides assignment under the [current CNA rules](https://github.com/CVEProject/cve-documents/blob/master/CNA_Rules.md).

## What the tool can observe

| Testing mode | Inputs | Useful results | Important limits |
| --- | --- | --- | --- |
| iPhone app | User-shared App Privacy Report, optional notes about actions taken | App-attributed access to sensitive resources, contacted domains, timelines, changes across sessions | The report does not reveal request contents, private app files, or source code. iOS retains the last seven days of activity. |
| Mac with ordinary iPhone | UI test traces, screenshots, test proxy logs, user-entered scenarios | Repeatable workflows, permission prompts, observed cleartext traffic, some link and session behavior | Generic UI automation needs app-specific scripts. Certificate pinning or custom network handling can block traffic inspection. |
| Developer or researcher package analysis | Source, build artifacts, an analyzable IPA, dependency manifests | App Transport Security settings, entitlements, code patterns, component versions, known vulnerability matches | App Store binaries are encrypted; access to a usable binary cannot be assumed. A string or configuration setting alone does not prove runtime use. |
| Advanced research | Appropriate runtime access, authorized test environment, targeted fuzz inputs | Internal state, parser and link handling, crash triage, stronger candidates for novel vulnerabilities | Findings still require manual impact analysis and reproduction on relevant app and iOS versions. |

Apple describes the [App Privacy Report export](https://developer.apple.com/documentation/network/inspecting-app-activity-data) as newline-delimited JSON containing resource-access and network-activity events. [Xcode UI tests](https://developer.apple.com/documentation/xcuiautomation/xcuiapplication/init%28bundleidentifier%3A%29) can launch an already installed app by bundle identifier. [OWASP documents](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0146/) the access limitations of runtime analysis on ordinary devices and encrypted App Store binaries.

## Primary workflow: a third-party app running on an iPhone

The common target is an app installed from the App Store on the researcher's standard iPhone. A package, developer account, source tree, and Mac-compatible version are optional inputs. The core assessment must work when none of them is available. Package acquisition is nonetheless a priority for deeper research: the [acquisition guide](docs/IOS_PACKAGE_ACQUISITION.md) describes obtaining a licensed IPA on a Mac, checking that it matches the tested app version, and recording whether native code is encrypted.

1. Identify the target app, its version and bundle identifier when available, the iOS version, the test account state, and the scope of the session. Unknown values stay unknown.
2. Record controlled actions and outcomes while switching between Mobile Audit and the target app. Import a user-exported App Privacy Report when it exists; keep its app-attributed observations distinct from the researcher's notes and test results.
3. On a paired Mac, optionally add an attributed network trace, device diagnostic, screenshot, or repeatable UI trace. The report states the collection method and any attribution uncertainty. Proxy visibility is not assumed for every app.
4. Try to obtain a matching App Store IPA through a Mac-side acquisition tool, then add its static analysis to the same case. Record acquisition method, bundle identifier, version/build, hash, and encryption state. If a matching package is unavailable, state that coverage limit. Advanced extraction or instrumentation on a separate research device has its own provenance and version checks.
5. Give the user and developer an evidence-linked report: observed behavior, plausible attack paths, tests that would confirm or weaken them, practical remediation, and explicit coverage. A possible CVE remains a private candidate until reproduced impact and affected versions are reviewed.

The iPhone app cannot read another installed app's executable on a standard device. [Apple describes the app sandbox](https://support.apple.com/en-afri/guide/security/sec15bfe098e/web) as preventing access to other apps' information; [OWASP describes](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0054/) the separate access needed to extract an App Store binary. An unavailable binary is a coverage limit, never evidence that the app is safe. This product must remain useful without one.

An observation that appears to involve iOS itself must be separated from the assessed app. It does not affect the app's grade or become an app vulnerability case. This project currently develops tests and reports for applications rather than the operating system.

## Experience for an iPhone user

The app guides a person through enabling App Privacy Report in Settings, using an app they want to examine, and sharing the exported report back to Mobile Audit. iOS requires the user to perform this export; Mobile Audit will not imply that it can silently read reports or enumerate every installed app.

After import, the person selects an app represented in the report. Mobile Audit shows a timeline of sensitive resource access and contacted domains, grouped by test period. It explains what each observation establishes and what it does not. For example, a location access followed by a connection to an analytics domain is a reason to investigate; the two events do not prove that location data was sent to that domain.

A guided session lets the person mark the start and end of a workflow such as account creation, requesting location, making a purchase, or signing out. They repeat the report export after the workflow. The report groups matching events by app identifier and time. Events from delayed background activity remain visible and are not automatically attributed to the user's last action.

The user report has six sections:

1. **Security grade:** a letter grade for the assessed app when the minimum test set is complete, plus the percentage of applicable checks completed, evidence strength, app version, and assessment date.
2. **Potential attack vectors:** concrete entry points and plausible paths to impact, each labeled as a hypothesis, a test result, or a confirmed vulnerability. The report states attacker prerequisites and the missing validation step for hypotheses.
3. **What happened:** resource accesses, contacted domains, and changes between sessions.
4. **What we verified:** the exact observations and test outcomes behind each claim, including checks that passed, failed, were inconclusive, or were unavailable.
5. **Why it matters:** the demonstrated impact for confirmed findings and the possible impact for leads, stated separately.
6. **What to do:** practical user controls, questions to ask the developer, or a recommendation for deeper testing.

An App Privacy Report import by itself cannot support a broad security grade: it does not test authorization, link handling, network contents, or exploitability. Such a report shows privacy review leads, an empty app-specific attack-vector section, and **Security grade: assessment incomplete**. Once a guided assessment meets the published grading requirements, the report shows its letter grade and completed coverage next to it. Shared reports remove personal account values and unrelated apps by default. Because the imported Apple report may contain activity from the entire device, the app parses it locally and retains only the selected records unless the user chooses to preserve a research copy.

## Attack vectors and security grading

An attack-vector card must name the entry point, the attacker-controlled input or action, required access or user interaction, the possible security boundary crossed, the possible or demonstrated impact, the evidence, and the next validation step. It must also have one of three states: **hypothesis**, **tested but unconfirmed**, or **confirmed**. The first two states must not describe exploitation as established fact. For example, a domain contact after location access can prompt a question about data handling; it cannot claim location exfiltration without evidence of what was transferred.

The assessment rubric uses versioned, app-relevant checks grouped into authentication and authorization, links and platform interactions, network communication, sensitive-data handling, and content or file handling. A feature absent from an app is **not applicable** and is excluded from the coverage denominator; a check that could not be run is **unavailable**, not passed. The report lists every applicable check with its result and evidence. OWASP's [Mobile Application Security Verification Standard](https://mas.owasp.org/MASVS/) supplies a public vocabulary for these areas, while Mobile Audit publishes its own exact test and grade rules.

The pilot **A–F security grade** combines researcher-recorded impact with the breadth of completed applicable checks. The rubric requires at least four applicable checks, completed checks in at least three areas, at least 80% coverage, two recorded trials and an attached evidence file for each completed check, and no unresolved possible issue. A critical issue yields F; a high issue cannot score above D; a medium issue cannot score above C; and a low issue cannot score above B. Multiple independent findings may lower the grade further. An A requires at least 90% coverage and no reported impact. Less than the minimum produces **assessment incomplete**. The letter is labeled **provisional** because the current tool records the researcher's result without independently validating the target app. Each grade includes the rubric version, coverage, evidence strength, and app version so it can be interpreted in context.

The exact pilot calculation is: start at A, cap at B when coverage is 80–89%, then apply the worst documented-impact ceiling (low B, medium C, high D, critical F). If more than one check has documented impact, lower the result one additional letter, stopping at F. A check marked not applicable leaves the denominator only when the researcher records why the feature is absent. Unavailable and inconclusive checks stay in the denominator and require an explanation. A confirmed-impact selection without two trials, impact and severity text, and an evidence file remains an unconfirmed attack-vector card and cannot produce a grade.

Before public release of the letter grade, the rubric must be calibrated against intentionally vulnerable and known-good fixtures and reviewed on real app assessments. We should measure false positives, the number of applicable checks that are unavailable on an ordinary iPhone, and whether independent reviewers assign the same result. The iPhone-only privacy report can still provide useful leads while the Mac companion and guided tests build the evidence needed for a grade.

## Experience for a researcher

Research mode uses the same findings but adds app version, iOS version, device type, locale, account state, permissions granted, and the actions performed. Where possible, it records an input and a baseline result so another researcher can reproduce the behavior. It can import network captures and UI test artifacts from a Mac helper. The initial Mac helper will support manually guided sessions before attempting generic UI exploration.

An active test is tied to a declared scope and test account. It records rate limits, time, target endpoints, and whether a test touched production services. Public issue templates and exported reports omit sensitive inputs until disclosure is appropriate. A private case file can preserve the minimum reproducer needed for the vendor.

The first active test families should be small and independently verifiable:

- Deep links and universal links: unexpected actions, missing input validation, and security decisions made without the normal UI checks.
- Network trust and transport: observed plaintext transmission or acceptance of an invalid server identity, with captured evidence.
- File and content handling: crashes or unintended file access from a user-opened document or URL, followed by impact analysis.
- Authentication and session boundaries: behavior after sign-out, account switching, or opening a protected link, using accounts the tester controls.

These are research candidates, not automatic vulnerability declarations. OWASP's [iOS deep-link tests](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0395/) and [WebView tests](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0332/) provide initial methods and terminology.

## Evidence and finding model

The current Python prototype has a `Finding` record with text evidence and a report-wide coverage list. The next schema will retain the existing report as an import format while giving new observations stable identifiers and structured provenance.

| Record | Required fields | Purpose |
| --- | --- | --- |
| Target | Platform, app identifier, app name, version when known | Prevent findings from drifting across apps or releases. Unknown versions stay unknown. |
| Environment | iOS version, device class, region when relevant, granted permissions | Explain conditions that can change behavior. |
| Session | Start and end times, actions, test account label, test scope | Connect observations to a repeatable workflow. |
| Artifact | Type, collection method, creation time, hash, sensitivity, retention choice | Preserve provenance and control private data. |
| Observation | Event type, timestamp, target, structured values, artifact reference | State what the collector actually saw. |
| Test result | Rule and version, prerequisites, status, evidence IDs, tested conditions | Record passed, failed, inconclusive, and unavailable tests explicitly. |
| Finding | Claim, impact, attacker prerequisites, severity, confidence, coverage, evidence IDs, OWASP and CWE mappings | Explain a risk without inflating a signal into a confirmed vulnerability. |
| Attack vector | Entry point, attacker control, prerequisites, boundary, possible or demonstrated impact, state, evidence IDs, next test | Give the reader a concrete path to investigate without presenting a hypothesis as an exploit. |
| Assessment grade | Letter or incomplete state, rubric version, applicable and completed checks, coverage, evidence strength, grade-limiting findings | Make the app's security grade explainable and reproducible. |
| Disclosure case | Private reproducer, affected versions, vendor contact state, CVE status | Support coordinated handling of a confirmed issue. |

The rule engine accepts observations and emits test results. It should be deterministic and versioned. Community rules are reviewed as data and do not execute arbitrary code in the iPhone app. A rule cannot claim a secret was transmitted based only on a domain contact. Apple notes that a contacted domain can also come from content loaded within an app, so domain attribution does not by itself identify an embedded SDK. Any automated attack narrative must use a template whose prerequisites and conclusions are linked to verified evidence.

| Finding state | Meaning | Promotion requirement |
| --- | --- | --- |
| Observation | A collector recorded a resource access, domain contact, configuration value, or test result. | Source event and collection method are retained. |
| Security lead | A rule identifies a plausible risk that needs more evidence. | The rule states the missing test and does not claim exploitation. |
| Confirmed vulnerability | A reproducible behavior has a demonstrated security impact. | A reviewer verifies the result and records affected conditions and attacker prerequisites. |
| Known CVE match | A product or component version falls in a published affected range. | Identity and version are reliable and the record applies to the relevant feature or build. |
| New CVE candidate | A confirmed issue is prepared for vendor coordination and possible assignment. | Affected product, versions, impact, private reproducer, and disclosure contact are recorded. |

The consumer report displays observations, leads, and confirmed issues in ordinary language. New CVE candidates remain private until a researcher decides what to disclose and when. A language model may help rewrite a verified finding for different readers, but it cannot create evidence or change its finding state.

## Path from observation to CVE candidate

**Known vulnerability matching** is the first CVE-related feature. If a trusted manifest or package analysis identifies a component and version, Mobile Audit can query a source such as [OSV](https://google.github.io/osv.dev/quickstart/) and show the affected version range. A guessed library name or unknown version produces a possible match for review, not an affected-product claim.

**Novel vulnerability discovery** requires a different workflow:

1. A test produces an unexpected result, such as a protected action occurring after a crafted link is opened.
2. The researcher reproduces it from a clean state on the current version, documents the exact input and preconditions, and rules out expected behavior.
3. The researcher establishes a security impact: what access, data, or action an attacker gains, and whether the flaw is in the app, a shared component, or an app-mediated backend service within the test scope.
4. The case is reported to the appropriate developer or security contact. Affected and fixed versions are tracked. The public project does not disclose an unpatched reproducer automatically.
5. The appropriate CVE Numbering Authority decides whether to assign an ID. The tool updates the case with the published advisory and CVE record.

An unusual permission request, a contacted domain, or a crash without demonstrated impact remains a lead. The [CVE Program's rules](https://github.com/CVEProject/cve-documents/blob/master/CNA_Rules.md) call for evidence of a vulnerability and an appropriate assignment scope. Insecure default settings can qualify when they create a real security impact; the label `misconfiguration` alone does not settle that question.

## Open source quality and trust

Every published rule needs an explanation, a test fixture that triggers it, a control fixture that does not, and a note about common false positives. An intentionally vulnerable demonstration app and known-good counterpart will support end-to-end validation. For research claims, the project will record the app build, OS build, test inputs, and reproduction rate. It will distinguish a newly observed behavior from a regression introduced by an app update.

Before public release, the repository needs a license, contribution guide, security reporting policy, versioned rule documentation, and a clear statement of what information leaves the device. The app will not bundle third-party scanner code without a compatible license review. The existing Mobile Audit CLI can contribute package and source findings through a schema adapter; it remains useful without being the center of the consumer experience.

The project should measure its own quality: parser accuracy on real and synthetic exports, false-positive rates on controlled fixtures, percentage of findings with reproducible evidence, and the proportion of tests marked unavailable rather than silently skipped. These measures are more credible than a large count of automatically generated alerts.

## Delivery sequence

### Foundation

- Define the evidence schema, finding states, report wording, and sensitive-data handling.
- Obtain an App Privacy Report export from a test iPhone and validate the parser against its real event shapes. Until then, use synthetic fixtures marked as such.
- Add an adapter that converts the existing static scanner's output into the new schema.

**Done when:** every displayed finding links to its source observations and every unavailable check is visible.

### iPhone application

- Build a SwiftUI import flow for the user-shared report.
- Group events by app and guided session, show timelines, and generate a sanitized shareable report.
- Test that the app works without an account or network connection and that unrelated app activity is omitted from exports by default.

**Done when:** a person can inspect one installed app, see potential attack vectors labeled by evidence state, and understand exactly what was observed and what remains untested. The limited report states that the security assessment is incomplete.

### Mac research helper

- Add UI test session recording and replay for installed apps, beginning with explicit scripts.
- Import proxy captures and correlate events with session steps.
- Add a small set of bounded deep-link and network tests with private evidence files.
- Publish the first versioned grading rubric and show an A–F grade once its minimum applicable test set has been completed.

**Done when:** another researcher can repeat a test and obtain the same result or an explicit explanation of the difference, and can trace the grade to individual test outcomes.

### Package and vulnerability research

- Extend developer-provided source and package analysis, then add verified component-version matching to known advisories.
- Add crash triage, affected-version tracking, and a private disclosure case workflow.
- Publish only validated rules and coordinated advisories.

**Done when:** the tool can produce a complete, reproducible vulnerability report for at least one intentionally vulnerable fixture, and known-CVE matches require reliable component identity.

## Short path to a research pilot

The grade explanation, check coverage table, saved-file hash verification, manual target setup, first private case draft, and static-lead test recipes are implemented without booting a simulator. Each static recipe names a controlled next test, a disconfirming result, and a conditional explanation of how the suspected attack might be used. The iPhone's guided attack-vector reports carry the same type of conditional path alongside the researcher-recorded result. These paths do not assert that matched code is reachable or that the described behavior occurred. The [near-term roadmap](ROADMAP.md) sets acceptance gates for source-only work, one-simulator validation, physical-iPhone checks, dynamic evidence, and disclosure.

The following work remains:

1. **Version comparison:** show which guided checks changed between app releases and whether a candidate issue still reproduces. Never carry a passed check forward automatically.
2. **Disclosure tracking:** add affected and fixed versions, developer contact and response dates, coordination state, and links to published advisories. Keep this separate from a public CVE claim.
3. **Calibration fixtures:** test the rubric on an intentionally vulnerable app and a known-good counterpart, then document false positives and checks that ordinary iPhones cannot complete.
4. **Independent review:** add a reviewer sign-off or repeat session before a researcher-recorded case can be promoted to a validated finding.

After those pieces, run the guided workflow on a signed physical iPhone, beginning with a developer-controlled app and controlled test accounts. Check whether switching to a target app preserves the draft, whether attached evidence is stored and removed correctly, and whether report wording survives a real assessment. Import a Mac-side test trace for independent review before promoting any provisional result. A real third-party finding then needs repeatable impact, vendor coordination, and validation of affected and fixed versions; a CVE is possible only after that evidence and the appropriate numbering authority's decision.

## Foundation implementation status

The schema 2.0 contract, local App Privacy Report importer, single-app filter, readable and JSON renderers, and static-scanner adapter are implemented in the prototype. The iPhone app now emits schema 2.1 with structured attack vectors and assessment data; the Mac CLI continues to emit 2.0. Synthetic fixtures exercise event pairing, app isolation, malformed input, HTML escaping, grade eligibility, evidence-file deletion, and separation of private test URLs from shared reports. The importer retains source hashes and locators in generated reports, while the original Apple export remains on disk and is not embedded. A real-device v4 export validated the network record path and showed additional fields (`domainClassification` and `contextVerificationType`) that this release does not interpret because Apple's published field guide does not define them. A real resource-access record remains to be collected for that parser path.

## Mac package inspection status

The Mac CLI now inventories iOS package identity, bundle and privacy declarations, code-signature metadata, App Transport Security settings, entry points, readable assets, and bounded Mach-O facts. It records architectures, linked libraries, encryption state, build versions, and selected API-name references from readable code. These observations appear in static and unified research HTML/JSON reports; they do not establish reachability or impact. The asset exporter preserves packaged JavaScript, React Native bundles, HTML, source maps, and WASM with hashes. The extraction path validates archive members and limits bytes and file counts. It does not decrypt App Store code, reconstruct original Swift or Objective-C source, disassemble binaries, or execute a target. Two publicly available training IPAs, iGoat-Swift and DVIA-v2, have been scanned without a simulator. Their static findings are test leads rather than confirmed vulnerabilities. Package analysis remains optional for the primary iPhone workflow.

## Unified research scan status

The Mac `research-scan` command combines any available package, source, App Privacy Report or iPhone evidence export, and researcher-supplied readable Mach-O into one evidence-linked report. It checks that bundle identifiers agree, records version conflicts, ranks declared entry points and static matches as test leads, inventories exact dependency versions from Swift Package Manager, npm, and CocoaPods lockfiles, and can optionally query OSV for known advisory version matches. It produces HTML/JSON and a minimized AI review handoff without contacting a model. A reported iPhone grade stays provisional and researcher-recorded; package-only and privacy-only scans remain incomplete. Network domains are omitted from the AI handoff unless requested. Native decompilation, automated runtime instrumentation, package-to-binary identity verification, and independent exploit validation remain separate work. The report's coverage section identifies these gaps rather than inferring a clean app.

The `import-ai-review` command adds a model's response to a copy of the research report only when its suggestions cite existing evidence IDs. The suggestions are marked unreviewed, cannot change the grade, and are left out of subsequent AI exports. The model is useful for prioritizing tests and spotting gaps; promotion to a vulnerability still requires independent reproduction and impact review.

Version 0.5 adds a longitudinal watch report to every Mac research scan. With an earlier report for the same bundle identifier, it highlights newly observed leads, domains, resource categories, known-advisory version matches, lower coverage, and provisional-grade changes. Semantic comparison avoids treating a changed source-file line number or App Privacy Report contact count as a new issue by itself. The watch report also lists test leads as possible vulnerability research paths and states what evidence is missing. It deliberately contains no intrusion-detected state, CVE probability, or CVE assignment. A later source or App Privacy Report export must be supplied for each comparison; the tool has no continuous access to another iOS app's runtime. Longitudinal alerts need calibration against repeated real-device sessions before they can be treated as reliable monitoring.

The [baseline set](baselines/README.md) starts that calibration with an iOS 17+ canary app in corrected and deliberately vulnerable versions. Both compile without a simulator. Its source scans produce three new expected test-lead alerts while keeping an unchanged URL scheme as an entry-point question; a missing authorization check inside the link handler remains a manual-test blind spot. The [selected-case scorecard](examples/baseline-scorecard.md) adds Swift and Flutter clean controls plus pinned DVIA v2, iGoat-Swift, iBugBazaar, DVFA, DVMA, and Oversecured Vulnerable iOS App source targets. It currently detects 28 of 28 selected patterns and keeps 17 of 17 negative controls clear; seven behavior cases await device testing. These curated checks do not measure overall detection accuracy or validate any new vulnerability.

## iPhone implementation status

The SwiftUI prototype imports a user-selected export, lists apps present in it, saves one selected app's normalized activity, and compares successive exports across labeled sessions. It can also start a manually named target case without an App Privacy Report. It provides seven guided physical-iPhone checks spanning account boundaries, links, network trust, permissions, and file imports. It records outcomes, private evidence files, and optional export line numbers; reports show conditional attack-vector cards and a provisional grade once the rubric gate is met. A possible novel issue can have a separate private reproducer with prerequisites, exact steps, expected and observed behavior, attacker control, and possible prior reports. A private text draft includes that material; the public HTML and JSON reports omit it. The private draft's readiness check requires app and iOS versions, two trials, recorded impact, and a saved evidence file whose bytes still match its hash. This is a completeness check, not independent validation or CVE eligibility. The grade lists its limiting reasons and a check coverage table. Missing or changed evidence files cannot support a grade or reproduced-impact vector. The app also offers evidence-linked privacy review prompts, optional local session notes, older-snapshot review, selected-app deletion, and shareable HTML and schema 2.1 JSON reports for imported snapshots. The app contains synthetic samples for checking the workflow. The parser has been checked against synthetic data and a private real-device v4 export. An unsigned device build succeeded, and a single iOS 18.6 simulator run verified installation, launch, and the home screen. Guided flows, a signed physical-device run, and a real resource-access event remain to be checked. See [ios/README.md](ios/README.md) for setup and current limits.
