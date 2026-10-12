import Foundation

public enum ResearchCheckStatus: String, Codable, CaseIterable, Sendable {
    case notRun, passed, concern, confirmed, inconclusive, unavailable, notApplicable

    public var label: String {
        switch self {
        case .notRun: return "Not run"
        case .passed: return "Expected protection observed"
        case .concern: return "Possible issue"
        case .confirmed: return "Impact reproduced"
        case .inconclusive: return "Inconclusive"
        case .unavailable: return "Could not test"
        case .notApplicable: return "Feature not present"
        }
    }
}

public enum ResearchSeverity: String, Codable, CaseIterable, Sendable {
    case low, medium, high, critical

    public var label: String { rawValue.capitalized }
}

public struct ResearchEvidence: Codable, Identifiable, Sendable {
    public let id: UUID
    public let displayName: String
    public let storedFileName: String
    public let sha256: String
    public let byteCount: Int
    public let addedAt: Date

    public init(id: UUID = UUID(), displayName: String, storedFileName: String,
                sha256: String, byteCount: Int, addedAt: Date = Date()) {
        self.id = id
        self.displayName = displayName
        self.storedFileName = storedFileName
        self.sha256 = sha256
        self.byteCount = byteCount
        self.addedAt = addedAt
    }
}

/// Exact working notes stay on the device and are omitted from public assessment reports.
public struct PrivateCaseNotes: Codable, Sendable, Equatable {
    public var preconditions: String
    public var steps: String
    public var expected: String
    public var observed: String
    public var attackerControl: String
    public var priorArt: String

    public init(preconditions: String = "", steps: String = "", expected: String = "",
                observed: String = "", attackerControl: String = "", priorArt: String = "") {
        self.preconditions = preconditions
        self.steps = steps
        self.expected = expected
        self.observed = observed
        self.attackerControl = attackerControl
        self.priorArt = priorArt
    }

    public var isEmpty: Bool {
        [preconditions, steps, expected, observed, attackerControl, priorArt]
            .allSatisfy { $0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }
    }
}

public struct ResearchCheckRecord: Codable, Identifiable, Sendable {
    public var id: String
    public var status: ResearchCheckStatus
    /// A short, shareable description. Do not put credentials or private account data here.
    public var summary: String
    public var impact: String
    public var severity: ResearchSeverity?
    public var trials: Int
    public var evidenceLines: [Int]
    public var evidence: [ResearchEvidence]
    /// A test URL is local working material and is excluded from shared reports.
    public var testURL: String
    public var privateCase: PrivateCaseNotes?
    public var updatedAt: Date

    public init(id: String, status: ResearchCheckStatus = .notRun, summary: String = "",
                impact: String = "", severity: ResearchSeverity? = nil, trials: Int = 0,
                evidenceLines: [Int] = [], evidence: [ResearchEvidence] = [],
                testURL: String = "", privateCase: PrivateCaseNotes? = nil,
                updatedAt: Date = Date()) {
        self.id = id
        self.status = status
        self.summary = summary
        self.impact = impact
        self.severity = severity
        self.trials = trials
        self.evidenceLines = Array(Set(evidenceLines.filter { $0 > 0 })).sorted()
        self.evidence = evidence
        self.testURL = testURL
        self.privateCase = privateCase
        self.updatedAt = updatedAt
    }

    public var hasDocumentedImpact: Bool {
        status == .confirmed && trials >= 2 && severity != nil && !evidence.isEmpty &&
            !summary.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty &&
            !impact.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }
}

public struct ResearchAssessment: Codable, Identifiable, Sendable {
    public let id: UUID
    /// Nil for a case created without an App Privacy Report export.
    public let snapshotID: UUID?
    public let bundleID: String
    /// User-supplied app name for a manual target; nil for imported APR assessments.
    public let targetName: String?
    public let rubricVersion: String
    public let createdAt: Date
    public var updatedAt: Date
    public var appVersion: String
    public var iOSVersion: String
    public var scope: String
    public var records: [ResearchCheckRecord]

    public init(id: UUID = UUID(), snapshotID: UUID? = nil, bundleID: String,
                targetName: String? = nil,
                rubricVersion: String = GuidedCheckCatalog.rubricVersion, createdAt: Date = Date(),
                appVersion: String = "", iOSVersion: String = "", scope: String = "",
                records: [ResearchCheckRecord] = []) {
        self.id = id
        self.snapshotID = snapshotID
        self.bundleID = bundleID
        self.targetName = targetName
        self.rubricVersion = rubricVersion
        self.createdAt = createdAt
        self.updatedAt = createdAt
        self.appVersion = appVersion
        self.iOSVersion = iOSVersion
        self.scope = scope
        self.records = records
    }

    public func record(for id: String) -> ResearchCheckRecord {
        records.first(where: { $0.id == id }) ?? ResearchCheckRecord(id: id)
    }

    public var displayName: String {
        if let targetName, !targetName.isEmpty { return targetName }
        return bundleID
    }
}

public struct CaseReadiness: Sendable {
    public let issues: [String]
    public var readyForPrivateReview: Bool { issues.isEmpty }

    public static func review(_ assessment: ResearchAssessment, record: ResearchCheckRecord,
                              evidenceIntegrity: EvidenceIntegrityReport?) -> CaseReadiness {
        let notes = record.privateCase ?? PrivateCaseNotes()
        var issues: [String] = []
        if assessment.appVersion.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            issues.append("Record the affected app version.")
        }
        if assessment.iOSVersion.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            issues.append("Record the iOS version used for reproduction.")
        }
        if assessment.scope.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            issues.append("Record the test scope and accounts used.")
        }
        if record.status != .confirmed { issues.append("Reproduce a security impact before review.") }
        if record.trials < 2 { issues.append("Repeat the behavior from a clean state at least twice.") }
        if notes.preconditions.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            issues.append("Record the account state and other prerequisites.")
        }
        let steps = notes.steps.split(whereSeparator: \.isNewline)
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
        if steps.count < 2 || steps.contains(where: {
            $0.range(of: "^[0-9]+[.)]\\s+.+$", options: .regularExpression) == nil
        }) {
            issues.append("Record at least two numbered reproduction steps.")
        }
        if notes.expected.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            issues.append("Record the expected behavior.")
        }
        if notes.observed.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            issues.append("Record the observed behavior.")
        }
        if notes.attackerControl.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            issues.append("Explain what an attacker controls.")
        }
        if record.impact.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || record.severity == nil {
            issues.append("Record the security impact and provisional severity.")
        }
        if evidenceIntegrity?.verifiedEvidence(in: record).isEmpty != false {
            issues.append("Attach an evidence file that matches its saved hash.")
        }
        return CaseReadiness(issues: issues)
    }
}

public enum PrivateCaseReport {
    public static func render(_ assessment: ResearchAssessment, record: ResearchCheckRecord,
                              evidenceIntegrity: EvidenceIntegrityReport?) -> String {
        let check = GuidedCheckCatalog.check(record.id)
        let notes = record.privateCase ?? PrivateCaseNotes()
        let readiness = CaseReadiness.review(assessment, record: record, evidenceIntegrity: evidenceIntegrity)
        let verifiedHashes = evidenceIntegrity?.verifiedEvidence(in: record).map(\.sha256) ?? []
        let steps = notes.steps.trimmingCharacters(in: .whitespacesAndNewlines)
        let missing = readiness.issues.isEmpty ? "None" : readiness.issues.map { "- \($0)" }.joined(separator: "\n")
        return """
        MOBILE AUDIT — PRIVATE RESEARCH DRAFT
        Case ID: \(assessment.id.uuidString)/\(record.id)
        Created: \(ISO8601DateFormatter().string(from: Date()))
        State: \(readiness.readyForPrivateReview ? "Ready for independent review" : "Working lead")

        This is a researcher-recorded case, not an assigned CVE or an independently verified vulnerability.
        Review for credentials, account identifiers, and private data before sharing.

        APP AND CONDITIONS
        App: \(assessment.displayName)
        Bundle ID: \(assessment.bundleID.isEmpty ? "Not recorded" : assessment.bundleID)
        App version: \(assessment.appVersion.isEmpty ? "Not recorded" : assessment.appVersion)
        iOS version: \(assessment.iOSVersion.isEmpty ? "Not recorded" : assessment.iOSVersion)
        Test scope: \(assessment.scope.isEmpty ? "Not recorded" : assessment.scope)
        Check: \(check?.title ?? record.id)
        Account state and prerequisites: \(notes.preconditions.isEmpty ? "Not recorded" : notes.preconditions)

        REPRODUCTION STEPS
        \(steps.isEmpty ? "Not recorded" : steps)

        EXPECTED BEHAVIOR
        \(notes.expected.isEmpty ? "Not recorded" : notes.expected)

        OBSERVED BEHAVIOR
        \(notes.observed.isEmpty ? "Not recorded" : notes.observed)

        ATTACKER CONTROL AND IMPACT
        Attacker control: \(notes.attackerControl.isEmpty ? "Not recorded" : notes.attackerControl)
        Possible attack path (conditional): \(check?.attackScenario ?? "Not recorded")
        Impact: \(record.impact.isEmpty ? "Not recorded" : record.impact)
        Provisional severity: \(record.severity?.label ?? "Not recorded")
        Repeated trials: \(record.trials)

        EVIDENCE
        Verified local file SHA-256: \(verifiedHashes.isEmpty ? "None" : verifiedHashes.joined(separator: ", "))
        App Privacy Report lines: \(assessment.snapshotID == nil ? "No export attached" : record.evidenceLines.map(String.init).joined(separator: ", "))
        File contents are not embedded in this draft. Attach redacted evidence separately if needed.

        PRIOR REPORTS OR POSSIBLE DUPLICATES CHECKED
        \(notes.priorArt.isEmpty ? "Not recorded" : notes.priorArt)

        REMAINING BEFORE INDEPENDENT REVIEW
        \(missing)
        """
    }
}

public struct GuidedCheck: Sendable {
    public let id: String
    public let category: String
    public let title: String
    public let featureNeeded: String
    public let steps: [String]
    public let expectedProtection: String
    public let entryPoint: String
    public let attackerControl: String
    public let attackScenario: String
    public let securityBoundary: String
    public let possibleImpact: String
    public let nextStep: String
}

public enum GuidedCheckCatalog {
    public static let rubricVersion = "0.1-pilot"
    public static let checks: [GuidedCheck] = [
        GuidedCheck(
            id: "auth.signed_out", category: "Authentication", title: "Protected content after sign-out",
            featureNeeded: "An account with private content and a sign-out action.",
            steps: ["Sign in to a test account and open private content.",
                    "Sign out, then revisit the screen or use the app's normal navigation to reach it.",
                    "Repeat from a clean sign-in and record what remains visible."],
            expectedProtection: "Private account content requires a fresh sign-in after sign-out.",
            entryPoint: "Previously accessible private screen", attackerControl: "Access to the device after the account signs out",
            attackScenario: "If private content remains available after sign-out, a person using that device could revisit the screen and read it without signing in again.",
            securityBoundary: "Signed-out access to private account data",
            possibleImpact: "Exposure of another person's account content on a shared device.",
            nextStep: "Confirm whether the visible content remains accessible after a fresh launch and document the exact data shown."),
        GuidedCheck(
            id: "auth.cross_account", category: "Authentication", title: "Data isolation between two accounts",
            featureNeeded: "Two test accounts and private content belonging to one of them.",
            steps: ["Create private content in test account A and save a link or identifier for it.",
                    "Sign in as test account B and try to open A's content through the app's ordinary link or navigation flow.",
                    "Repeat with a second item and record the result."],
            expectedProtection: "Account B cannot read or change private content owned by account A.",
            entryPoint: "Account-scoped content or object link", attackerControl: "A separate test account and an identifier or link",
            attackScenario: "If the service does not check item ownership, someone signed in to account B could open an identifier for account A's item and read or change it.",
            securityBoundary: "Authorization between two accounts",
            possibleImpact: "Unauthorized reading or modification of another account's information.",
            nextStep: "Reproduce with two items and determine whether the app or its service grants the unauthorized access."),
        GuidedCheck(
            id: "links.signed_out", category: "Links", title: "Protected link while signed out",
            featureNeeded: "A universal link or custom link that opens protected app content.",
            steps: ["While signed in to a test account, obtain a link to its private content.",
                    "Sign out, open the link on the iPhone, and record where the app lands.",
                    "Repeat after force quitting and reopening the app."],
            expectedProtection: "The app asks for authentication before showing protected content or taking a protected action.",
            entryPoint: "Universal link or custom URL scheme", attackerControl: "A link delivered to a user",
            attackScenario: "If the link handler opens protected content before checking sign-in state, a sender could use a link to expose that content or trigger an action on a signed-out device.",
            securityBoundary: "Authentication at an externally reachable entry point",
            possibleImpact: "Unauthorized display of private content or execution of a protected action.",
            nextStep: "Verify the behavior after a clean logout and capture the screen and link shape without sharing private tokens."),
        GuidedCheck(
            id: "links.account_boundary", category: "Links", title: "Link to another account's content",
            featureNeeded: "A link containing an identifier for account-owned content and two test accounts.",
            steps: ["Create a private item in test account A and copy its link.",
                    "Sign in as test account B, open A's link, and observe whether data or an action is exposed.",
                    "Repeat using another item you control."],
            expectedProtection: "The link cannot bypass the current account's authorization checks.",
            entryPoint: "Universal link or custom URL scheme", attackerControl: "The link and its content identifier",
            attackScenario: "If a link resolves another account's item without an ownership check, someone signed in to account B could use account A's item link to view or change it.",
            securityBoundary: "Authorization between accounts through a link handler",
            possibleImpact: "Access to or modification of another account's private content.",
            nextStep: "Confirm which request or app action crosses the account boundary using only controlled accounts."),
        GuidedCheck(
            id: "network.server_identity", category: "Network", title: "Server identity validation",
            featureNeeded: "An authorized test connection and a network capture or controlled test proxy.",
            steps: ["Record a normal app request on the test iPhone.",
                    "In an authorized test setup, present an invalid server identity for that connection.",
                    "Record whether the app rejects it and repeat the observation."],
            expectedProtection: "The app rejects a server whose identity cannot be validated.",
            entryPoint: "App network connection", attackerControl: "A network position capable of presenting an invalid server identity",
            attackScenario: "If the app accepts an invalid server identity, someone on its network path could impersonate the service and observe or alter app traffic.",
            securityBoundary: "Trust in the remote service",
            possibleImpact: "Interception or alteration of app traffic if the invalid identity is accepted.",
            nextStep: "Preserve a redacted connection trace and verify the app accepted the invalid identity rather than a test configuration."),
        GuidedCheck(
            id: "privacy.permission_denied", category: "Privacy", title: "Behavior after sensitive permission denial",
            featureNeeded: "A feature requesting location, camera, microphone, contacts, or photos.",
            steps: ["Use the feature once with the relevant permission allowed.",
                    "Deny or revoke that permission in Settings and repeat the same feature.",
                    "Record prompts, behavior, and any new privacy-report events."],
            expectedProtection: "The app respects the denied permission and explains any reduced functionality.",
            entryPoint: "Sensitive-data feature", attackerControl: "No external attacker is established by this test",
            attackScenario: "No external attack path is established by this check. If the app still accesses a sensitive resource after permission denial, the user's privacy choice may not be respected; the access and cause need confirmation.",
            securityBoundary: "User-granted access to sensitive device data",
            possibleImpact: "Unexpected handling of sensitive information despite the user's permission choice.",
            nextStep: "Correlate the permission state with a fresh privacy export; do not infer data transfer from access timing alone."),
        GuidedCheck(
            id: "content.import", category: "Content", title: "Untrusted file or shared content",
            featureNeeded: "A document import, share extension, or external content feature.",
            steps: ["Open a harmless file or link you created through the app's supported import path.",
                    "Repeat with a malformed but non-destructive test item within your research scope.",
                    "Record the app's response and whether any protected action or data access occurred."],
            expectedProtection: "Unexpected content does not trigger a protected action or expose private data.",
            entryPoint: "File import or shared content", attackerControl: "A file or shared item supplied to the app",
            attackScenario: "If a supported import path mishandles a file supplied by another party, opening it could cause unintended app behavior or expose private data. A crash alone does not establish that impact.",
            securityBoundary: "Parsing of untrusted content and access to app data",
            possibleImpact: "Unintended app behavior or data exposure if content is mishandled.",
            nextStep: "A crash alone is a lead; establish a reproducible security impact before confirming a vulnerability.")
    ]

    public static func check(_ id: String) -> GuidedCheck? {
        checks.first(where: { $0.id == id })
    }
}

public struct AssessmentGrade: Sendable {
    public let letter: String?
    public let coveragePercent: Int
    public let completedChecks: Int
    public let applicableChecks: Int
    public let issues: [String]
    public let rationale: [String]

    public var label: String { letter.map { "\($0) · provisional" } ?? "Assessment incomplete" }
}

/// Results of checking the locally retained evidence bytes against their saved hashes.
/// The check verifies file integrity, not the researcher's account of what a file shows.
public struct EvidenceIntegrityReport: Sendable {
    public let verifiedIDs: Set<UUID>
    public let checkedCount: Int
    public let issues: [String]

    public init(verifiedIDs: Set<UUID>, checkedCount: Int, issues: [String]) {
        self.verifiedIDs = verifiedIDs
        self.checkedCount = checkedCount
        self.issues = issues
    }

    public func verifiedEvidence(in record: ResearchCheckRecord) -> [ResearchEvidence] {
        record.evidence.filter { verifiedIDs.contains($0.id) }
    }
}

public enum AssessmentGrader {
    public static func grade(_ assessment: ResearchAssessment?,
                             evidenceIntegrity: EvidenceIntegrityReport? = nil) -> AssessmentGrade {
        guard let assessment else {
            return AssessmentGrade(letter: nil, coveragePercent: 0, completedChecks: 0,
                                   applicableChecks: 0, issues: ["Start a guided assessment to evaluate this app."],
                                   rationale: [])
        }
        let records = GuidedCheckCatalog.checks.map { (definition: $0, record: assessment.record(for: $0.id)) }
        let applicable = records.filter { $0.record.status != .notApplicable }
        let completed = applicable.filter { $0.record.status == .passed || $0.record.status == .confirmed }
        let coverage = applicable.isEmpty ? 0 : Int((100.0 * Double(completed.count) / Double(applicable.count)).rounded())
        var issues: [String] = []
        if evidenceIntegrity == nil && assessment.records.contains(where: { !$0.evidence.isEmpty }) {
            issues.append("Attached evidence has not been checked against the saved files.")
        }
        issues.append(contentsOf: evidenceIntegrity?.issues ?? [])
        if assessment.rubricVersion != GuidedCheckCatalog.rubricVersion {
            issues.append("This assessment used an older test rubric. Start a new assessment.")
        }
        if assessment.appVersion.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            issues.append("Record the app version.")
        }
        if assessment.iOSVersion.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            issues.append("Record the iOS version.")
        }
        if assessment.scope.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            issues.append("Record the test scope and accounts used.")
        }
        if applicable.count < 4 { issues.append("At least four checks must apply to the app.") }
        if Set(completed.map(\.definition.category)).count < 3 {
            issues.append("Complete checks in at least three security areas.")
        }
        if coverage < 80 { issues.append("Complete at least 80% of applicable checks.") }
        if records.contains(where: { $0.record.status == .concern }) {
            issues.append("Resolve possible issues before assigning a grade.")
        }
        for item in records {
            let record = item.record
            if record.status == .notApplicable && record.summary.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                issues.append("Explain why \(item.definition.title) does not apply.")
            }
            if record.status == .passed || record.status == .confirmed {
                if record.trials < 2 || record.summary.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                    issues.append("Document two trials and an observation for \(item.definition.title).")
                }
                if evidenceIntegrity?.verifiedEvidence(in: record).isEmpty != false {
                    issues.append("Attach a verified evidence file for \(item.definition.title).")
                }
            }
            if record.status == .confirmed &&
                (record.severity == nil || record.impact.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty) {
                issues.append("Record impact and severity for \(item.definition.title).")
            }
            if (record.status == .inconclusive || record.status == .unavailable) &&
                record.summary.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                issues.append("Explain why \(item.definition.title) is \(record.status.label.lowercased()).")
            }
        }
        guard issues.isEmpty else {
            return AssessmentGrade(letter: nil, coveragePercent: coverage,
                                   completedChecks: completed.count, applicableChecks: applicable.count,
                                   issues: issues, rationale: [])
        }
        let confirmed = completed.map(\.record).filter { $0.status == .confirmed }
        let severityRank: [ResearchSeverity: Int] = [.low: 1, .medium: 2, .high: 3, .critical: 4]
        var rank = confirmed.compactMap { $0.severity.flatMap { severityRank[$0] } }.max() ?? 0
        var rationale: [String] = []
        if let highest = confirmed.compactMap(\.severity).max(by: { severityRank[$0, default: 0] < severityRank[$1, default: 0] }) {
            let ceiling = ["A", "B", "C", "D", "F"][rank]
            rationale.append("Highest researcher-recorded impact: \(highest.label). This limits the grade to \(ceiling).")
        } else {
            rationale.append("No reproduced security impact was recorded in the completed guided checks.")
        }
        if coverage < 90 { rationale.append("Coverage below 90% limits the grade to B.") }
        if coverage < 90 { rank = max(rank, 1) }
        if confirmed.count > 1 && rank < 4 {
            rationale.append("Two or more checks marked with reproduced impact lower the grade one level.")
            rank += 1
        }
        let letters = ["A", "B", "C", "D", "F"]
        return AssessmentGrade(letter: letters[rank], coveragePercent: coverage,
                               completedChecks: completed.count, applicableChecks: applicable.count,
                               issues: [], rationale: rationale)
    }
}

public enum AttackVectorState: String, Sendable {
    case hypothesis, testedUnconfirmed = "tested_unconfirmed", confirmed

    public var label: String {
        switch self {
        case .hypothesis: return "Hypothesis"
        case .testedUnconfirmed: return "Tested, unconfirmed"
        case .confirmed: return "Researcher-reported impact"
        }
    }
}

public struct AttackVector: Identifiable, Sendable {
    public let id: String
    public let title: String
    public let state: AttackVectorState
    public let entryPoint: String
    public let attackerControl: String
    public let attackScenario: String
    public let prerequisites: String
    public let securityBoundary: String
    public let possibleImpact: String
    public let observed: String
    public let evidenceLines: [Int]
    public let evidenceHashes: [String]
    public let nextStep: String
    public let severity: ResearchSeverity?
}

public enum AttackVectorEngine {
    public static func vectors(for assessment: ResearchAssessment?,
                               evidenceIntegrity: EvidenceIntegrityReport? = nil) -> [AttackVector] {
        guard let assessment, assessment.rubricVersion == GuidedCheckCatalog.rubricVersion else { return [] }
        return GuidedCheckCatalog.checks.compactMap { definition in
            let record = assessment.record(for: definition.id)
            let verifiedEvidence = evidenceIntegrity?.verifiedEvidence(in: record) ?? []
            let documentedImpact = record.hasDocumentedImpact && !verifiedEvidence.isEmpty
            let state: AttackVectorState
            switch record.status {
            case .concern: state = .testedUnconfirmed
            case .confirmed: state = documentedImpact ? .confirmed : .testedUnconfirmed
            case .inconclusive: state = .hypothesis
            default: return nil
            }
            return AttackVector(
                id: definition.id, title: definition.title, state: state,
                entryPoint: definition.entryPoint, attackerControl: definition.attackerControl,
                attackScenario: definition.attackScenario,
                prerequisites: definition.featureNeeded, securityBoundary: definition.securityBoundary,
                possibleImpact: documentedImpact ? record.impact : definition.possibleImpact,
                observed: record.summary, evidenceLines: record.evidenceLines,
                evidenceHashes: verifiedEvidence.map(\.sha256),
                nextStep: documentedImpact ? "Prepare a private, reproducible report for the developer." : definition.nextStep,
                severity: documentedImpact ? record.severity : nil
            )
        }
    }
}
