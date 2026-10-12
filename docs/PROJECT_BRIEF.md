# Mobile Audit: project brief

**Purpose:** Help a researcher assess an iOS app they use, combine the observations they can actually obtain, and turn suspected security issues into reproducible tests. The project extends the author's [published mobile-app security research](https://doi.org/10.1109/SoutheastCon63549.2026.11476248) into an open-source tool. It is an active prototype, not a vulnerability or CVE discovery claim.

## Working system

| Component | Current capability |
| --- | --- |
| SwiftUI iPhone app | Creates private app cases; imports Apple App Privacy Report exports; isolates one selected app's records; stores snapshots; guides account, link, storage, transport, and privacy checks; creates evidence-linked provisional assessments and private case drafts. |
| Python scanner and reporter | Scans supplied iOS source, `.app`/`.ipa` packages, Android `.apk` packages, and Flutter source. Produces HTML/JSON reports with artifact hashes, observations, coverage limits, conditional attack paths, and follow-up tests. |
| iOS package acquisition | Uses a locally authenticated `ipatool` backend to download an App Store copy licensed to the researcher's Apple Account. Checks ZIP integrity, app identity, version, hash, and native-code encryption before linking it to phone evidence. |
| Change and review workflow | Compares reports for new leads and coverage changes, separates known-advisory version matches from novel-issue hypotheses, and generates a minimized AI review packet whose suggestions remain unverified. |

## Validation completed

- **53 Python unit tests** pass. They cover App Privacy Report isolation, package identity and archive safety, encrypted-code visibility, evidence references, report generation, AI-review import, and change alerts.
- **9 Swift core tests** pass. One optional test for a researcher-supplied private export is skipped when no local export path is provided.
- The hand-selected source baseline detects **28 of 28 selected vulnerable patterns** and keeps **17 of 17 selected negative controls clear**. Seven behavior cases still need device testing. These counts are a development scorecard, not a general detection rate.
- The iPhone app has built and launched once in a simulator. Its guided flows and report sharing have not been verified end to end there or on a signed physical phone.
- One licensed third-party App Store IPA was acquired and scanned locally. Its identity matched the phone's version; its encrypted native code was correctly marked unavailable. That IPA, its report, and personal activity exports are excluded from this repository.

## Boundaries that shape the design

An ordinary iPhone app cannot read another app's private files or executable. App Privacy Report gives aggregate domain and resource-use evidence, not URLs, payloads, or proof of an attack. App Store native executables may remain encrypted after IPA acquisition. Mobile Audit therefore keeps observed evidence, hypotheses, researcher-recorded outcomes, and independently confirmed impact separate. A security grade is provisional and requires documented coverage; a CVE would require a reproduced vulnerability, affected-version analysis, and coordinated disclosure.

## What is next

1. Verify guided checks, evidence attachment, export, and deletion on a signed physical iPhone.
2. Export shareable evidence from a phone-first manual case even without an App Privacy Report.
3. Import bounded, researcher-supplied network observations and tie them to labeled test sessions.
4. Validate the canary's vulnerable and fixed behavior on a device, then invite external rule and false-positive review.

Start with the [README](../README.md), [iPhone guide](../ios/README.md), [baseline method](../baselines/README.md), and [roadmap](../ROADMAP.md).
