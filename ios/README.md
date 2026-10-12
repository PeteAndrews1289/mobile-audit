# Mobile Audit for iPhone

This is a SwiftUI prototype for iOS 17 or newer. You can start a private research case for any app you name without an export. You can also import an App Privacy Report from iOS Settings, choose an app in it, store only that app's normalized activity, and compare later exports. The tool does not need the target app's source code. Research mode guides tests on a physical iPhone, records potential attack vectors, and calculates a provisional A–F security grade when enough checks are documented.

## Run it

1. Open [MobileAudit.xcodeproj](MobileAudit.xcodeproj) in Xcode.
2. Select the **MobileAudit** scheme and your iPhone as the run destination.
3. In **Signing & Capabilities**, select your Apple development team. If Xcode reports that the bundle identifier is taken, change `org.mobileaudit.prototype` to a unique identifier you control.
4. Press **Run**. Xcode may ask you to trust its developer profile on the phone.

The **Try a sample report** button loads invented activity, so you can check the interface before using a personal export. You can also run the app in an iPhone simulator without signing.

## Start a private research case for any app

1. Tap **Start a private research case**, enter the app name, and optionally enter its bundle identifier. Add the app version, iOS version, and the scope of your test before making a security claim.
2. Open a guided check, perform it in the target app using accounts and data you control, and record the result and repeated trials in Mobile Audit. Attach a local evidence file when you have one. This manual case has no App Privacy Report line numbers unless you start a separate assessment from an imported export.
3. For a possible new issue, open **Private case**, record the prerequisites, exact steps, expected and observed behavior, attacker control, and possible prior reports. The screen lists missing items before the case is ready for independent review.
4. Tap **Prepare private draft** when you want a text report for your own review or a developer. The draft includes exact private notes and verified file hashes, so inspect it before using the system share sheet. Evidence file contents are not embedded. You can delete the manual case and its saved evidence and draft from the case screen.

The tool does not independently run these tests or decide whether a CVE should be assigned. A case marked ready for independent review still needs someone else to reproduce the behavior, establish affected versions and real security impact, check for prior disclosure, and coordinate with the appropriate developer.

## Examine an installed app with an App Privacy Report

1. Enable **App Privacy Report** under **Settings → Privacy & Security** on the iPhone.
2. Use the app you want to examine. You can record your actions in a separate note.
3. In App Privacy Report, use its share action to save the export to **Files**.
4. Open Mobile Audit, tap **Import App Privacy Report**, select that file, then choose the app's bundle identifier from the list.
5. To compare a later test, open the saved app in Mobile Audit and start a labeled session. Add optional notes about your actions and conditions. Use the other app, finish the session, export App Privacy Report again, and import the same bundle identifier. The comparison appears under the saved app.
6. Tap **Start guided assessment** for that app and export. Record the app version, iOS version, and test scope. Open each check, perform its steps in the target app using test accounts and data you control, and return to Mobile Audit to record the result. For link checks, the app can open a URL through iOS; you record the target app's response.
7. Mark each check as passed, possible issue, reproduced impact, inconclusive, unavailable, or not applicable. Add a shareable observation, number of repeated trials, relevant export line numbers, and an evidence file. Confirmed impact also needs an impact description and severity. Open **Private case** within a check to keep exact reproduction steps separately. Attached files stay private on the device; shared reports include hashes, not the files or their names.
8. Select older saved exports to review their activity. Share the selected app's HTML report or evidence JSON when needed. You can delete an app's saved snapshots, assessments, evidence files, session notes, and generated reports from its detail screen.

The test-session buttons only record your label and timestamps in Mobile Audit. They do not start or stop Apple's collection. Apple reports aggregate activity for its rolling reporting period, so a difference between exports is a lead for investigation rather than proof that one action caused it.

The guided checks are performed by a person on the physical iPhone. Mobile Audit does not run another app inside itself or observe that app's screen. A possible issue becomes an attack-vector card with its entry point, attacker control, a conditional **Possible attack path**, prerequisites, possible impact, evidence, and next test. The path explains how the risk might be used; it is not a claim that the sequence occurred. A reproduced-impact card requires two trials, an impact description, severity, and an attached evidence file; the app labels it as researcher-reported.

The pilot grading rubric requires the app and iOS versions, a stated test scope, at least four applicable checks, completed checks in at least three areas, 80% coverage, and no unresolved possible issue. Each passed or reproduced-impact check needs two trials, a written observation, and an attached evidence file whose saved bytes still match its recorded SHA-256 hash. A missing, changed, or unreadable file prevents grading and cannot support a reproduced-impact vector. A confirmed critical issue yields F; high cannot score above D, medium above C, or low above B. Additional issues may lower the grade. The screen and HTML report explain the grade and list every guided check's recorded result. A report based only on an App Privacy Report says **Assessment incomplete**. The grade is provisional because the tool has not independently verified the researcher's actions.
Each assessment records its rubric version. If the check catalog changes in a later release, an older assessment becomes ungraded rather than being silently rescored with different rules.

## Data and limits

- Import and analysis happen on the device. There is no account or Mobile Audit server.
- The complete Apple export stays in the location where you saved it. Mobile Audit retains the selected app's normalized records and a SHA-256 hash of the original file. Unrelated app records and Apple's browsing `context` value are not saved.
- Saved snapshots, assessments, attached evidence, session notes, private case drafts, and generated reports use iOS file protection. The app does not upload them. Sharing opens the system share sheet; review summaries and domains before sharing. Private session notes, assessment scope text, exact case notes, test URLs, attached file contents, and original evidence filenames are omitted from public HTML and JSON reports. A private case draft intentionally includes exact case notes, so review and share it only with the intended recipient.
- iPhone evidence JSON follows [schema 2.1](../schema/evidence-report.schema.json). It adds structured attack vectors, including a conditional `attack_scenario`, guided check results, grade rationale, coverage information, and evidence integrity status. App Privacy Report observations retain source line numbers and the original export hash. APR-only reports still contain no vulnerability findings or active test results. A manual case currently produces a private text draft; public HTML and JSON reports require an imported snapshot. The Mac CLI continues to emit [schema 2.0](../schema/evidence-report-2.0.schema.json).
- An export can show app-attributed network domains and sensitive-resource access intervals. It does not show request bodies, private files, source code, or whether a connection was exploitable.
- The iPhone app does not inspect an app package or control another app's interface. It can ask iOS to open a researcher-provided test link. The optional Mac CLI can scan source and packages separately.

For a combined research report on the Mac, share the selected app's evidence JSON and pass it to `mobile-audit research-scan --iphone-report /path/to/evidence.json --output /path/to/new-report`. You can add `--package`, `--source`, or `--readable-binary` when those inputs are available. Later, add `--previous-report /path/to/earlier/report.json` to highlight newly observed activity and research leads for the same bundle identifier. The [Mac workflow](../README.md#run-one-ios-research-scan) explains the report, change triage, and optional AI handoff. The shared iPhone JSON can still include selected-app activity and domains, so inspect it before sending it outside your Mac.

## Build and parser checks

From the `ios` directory, `swift test` runs the Swift parser tests with a synthetic report. To check a private export, set `MOBILE_AUDIT_REAL_APR` to its path and `MOBILE_AUDIT_REAL_BUNDLE_ID` to one app in it; the test reads the export without copying it into the project. The Xcode project builds the iPhone interface. A private iPhone export was also used locally to validate Apple's v4 network records; that export is not in this project. A real resource-access record has not yet been validated.

The iPhone app emits evidence JSON schema 2.1; the Mac CLI emits 2.0. The iPhone app keeps optional local session notes, guided assessments, and review prompts. The core tests and unsigned iPhone device build run without booting a simulator. An additional smoke check built the app for an iOS 18.6 iPhone SE simulator, installed and launched it, and captured the [home screen](../examples/mobile-audit-simulator-launch.png). This verifies launch only; import, sample-report, guided-check, and sharing flows have not been exercised in the simulator. A signed physical-device run and hands-on guided testing remain to be completed.
