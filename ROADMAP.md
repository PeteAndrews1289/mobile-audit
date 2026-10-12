# Mobile Audit: next development gates

Mobile Audit aims to take an iOS app from a limited observation to a reproducible security assessment. A static match is a question to test. A possible new vulnerability needs repeatable behavior, a defined attacker capability, impact, and affected versions before it becomes a disclosure case. The [design](DESIGN.md) explains the longer product direction.

## Current checkpoint

- The Mac scanner combines available app activity, package metadata, developer source, and readable binary clues. It now pairs five kinds of co-present clues into attack-path hypotheses with evidence IDs, the missing connection, a controlled test, and a result that would weaken the hypothesis. These pairs remain low-confidence until the connection and impact are observed.
- A MobSF-style iOS package profile is available when an IPA or `.app` is supplied. Obtaining a matching package for a third-party App Store app is now the first acquisition gate; the primary target remains an app running on a standard iPhone.
- The Mac `acquire-ios` command now covers backend setup, interactive authentication, search, download, ZIP and identity validation, provenance recording, and a linked research scan. The first live third-party IPA was acquired and scanned in October 2026. Its bundle identifier and version matched the phone case; the main executable was correctly recorded as encrypted. The real package exposed and helped fix an executable-ordering limit in the scanner.
- The iPhone app has an import flow, guided checks, conditional attack paths on recorded vectors, private evidence and case drafting, and a provisional grade with coverage limits.
- A manually started iPhone case without an App Privacy Report currently exports a private case draft, but not a shareable evidence JSON/HTML assessment. This blocks the complete phone-first workflow for apps with no usable export record.
- The baseline has 28 selected positive pattern cases, 17 selected negative controls, and seven behavior cases awaiting device work. These selected cases are a regression set, not a detection-rate estimate.
- A simulator build, install, launch, and home screen have been checked once. The guided flows and a signed physical-iPhone session remain unverified.

## Gate 1: acquire and verify a third-party App Store package

1. **Validated:** download a licensed third-party App Store app through the Mac command without a simulator. [The acquisition guide](docs/IOS_PACKAGE_ACQUISITION.md) describes this workflow and its limits.
2. **Validated:** check ZIP integrity, bundle identifier, version/build, SHA-256, app extensions, and native executable encryption on a real package. Link it to the iPhone case only when identity agrees; display version mismatch and code visibility in the report.
3. **Validated locally:** use the `ipatool` adapter after the researcher authenticates directly through Mobile Audit's terminal command. Keep Apple Account credentials, two-factor codes, and session files outside Mobile Audit. Prepare a bundled or otherwise managed backend for a future standalone release.
4. Design a separate import for a readable research build or decrypted binary from a compatible dedicated device. Verify identity and version before combining its code clues with phone behavior.

**Pass condition:** one real third-party IPA is acquired on the Mac, imported without a simulator, and scanned. The report records provenance and clearly distinguishes inspectable metadata/resources from encrypted native code. A code-level finding is not claimed from encrypted bytes.

## Gate 2: make research leads reproducible without a simulator

1. Export a manually started iPhone case as shareable evidence JSON and HTML even when no App Privacy Report exists. Include target/version, guided outcomes, evidence hashes, attack-vector states, grade coverage, and explicit unavailable observations. Keep exact private reproducer notes and evidence bytes out of that export. The Mac `research-scan` should accept it as `--iphone-report`.
2. Compare two scans of the same app across versions at the *test-case* level: new, persistent, resolved, and untested because coverage changed. Preserve the evidence references and do not carry a passed guided check into a new release automatically.
3. Bind a paired hypothesis to a private case record with exact app and iOS versions, prerequisites, controlled inputs, trial count, observed impact, and evidence hashes. The iPhone app has a private case draft, but the Mac hypothesis-to-case link is not built yet. Keep proposed CVE language out of public exports.
4. Extend the baseline with negative controls for each newly published rule and track false positives by root cause. Pin upstream training-app revisions so future changes do not silently change the scorecard.

**Pass condition:** a researcher can start with only a third-party app on their iPhone, record a guided assessment, export a shareable report, and revisit each lead after an app update. The same inputs produce stable lead and evidence links. No local case draft is presented as a confirmed vulnerability.

## Gate 3: verify the workflow on a physical iPhone

1. On a signed physical iPhone, run a manual case against a developer-controlled app with test accounts. Verify app switching, evidence attachment, report export, deletion, and a clean reinstall. Collect a real resource-access event to validate that importer path.
2. Repeat the same intake and reporting flow with an in-scope third-party App Store app, starting without package or source access. Record which checks were testable and which were unavailable.
3. Use one simulator destination as a separate UI regression check when memory permits. Record time and peak memory; do not boot a second simulator for this gate.

**Pass condition:** exported reports match what was recorded on the phone, evidence hashes verify, deleted cases remove their stored evidence, and unavailable tests remain visible. The third-party pilot produces a useful report without an IPA.

## Gate 4: add bounded dynamic evidence

1. Record researcher-directed sessions with timestamps so network and privacy observations can be associated with the action that preceded them.
2. Import a researcher-supplied network trace and retain its source hash. Attribute only events that can be tied to the selected app and session; show uncertainty where attribution is incomplete.
3. Add controlled link, document-import, and account-boundary test templates. Compare observed behavior with an explicit expected result and a disconfirming result.

**Pass condition:** a second researcher can repeat a test from the saved steps and distinguish app behavior from package clues or unrelated network traffic. Tests that require unavailable access are marked unavailable, not passed.

## Gate 5: validate a novel-issue workflow

1. Reproduce a deliberately vulnerable canary behavior across clean installs and both test accounts, then confirm the corrected version closes it.
2. Add independent reviewer sign-off, affected/fixed version tracking, and a private disclosure timeline with developer responses.
3. Test the same workflow on a third-party app only within the researcher's authorization and disclosure scope. Keep exact reproducer details private until coordination permits release.

**Pass condition:** the case records attacker prerequisites, repeatable security impact, product and version identity, and independent review. Published advisory matching remains separate from proposing a new CVE; assignment belongs to the appropriate numbering authority.

## Gate 6: prepare an open-source release

- The MIT license, contribution rules, security reporting route, and data-handling guidance are now documented. Verify these with each public release.
- Publish a rule catalog with rationale, positive fixture, negative control, known false positives, and last validation date.
- Publish a benchmark method and results that separate source-pattern recall, false positives, dynamic-test coverage, and confirmed findings.

**Pass condition:** a new contributor can reproduce the baseline and understand exactly which claims the tool can and cannot support.
