import Foundation
import XCTest
@testable import MobileAuditCore

final class MobileAuditCoreTests: XCTestCase {
    private func fixture() throws -> URL {
        try XCTUnwrap(Bundle.module.url(forResource: "sample", withExtension: "ndjson"))
    }

    func testIndexAndSelectedSnapshotDiscardOtherApps() throws {
        let file = try fixture()
        let index = try APRParser.index(file)
        XCTAssertEqual(index.apps.map(\.bundleID), ["com.example.other", "com.example.target"])
        let snapshot = try APRParser.snapshot(file, bundleID: "com.example.target")
        XCTAssertEqual(index.artifactSHA256, snapshot.artifactSHA256)
        XCTAssertEqual(snapshot.networkContacts.count, 1)
        XCTAssertEqual(snapshot.resourceAccesses.count, 1)
        XCTAssertTrue(snapshot.resourceAccesses[0].isComplete)
        XCTAssertEqual(snapshot.resourceAccesses[0].sourceLines, [3, 4])
        let encoded = String(data: try JSONEncoder().encode(snapshot), encoding: .utf8) ?? ""
        XCTAssertFalse(encoded.contains("private.other.test"))
        XCTAssertFalse(encoded.contains("private-page"))
        XCTAssertFalse(encoded.contains("domainClassification"))
        let leads = ReviewEngine.leads(for: snapshot)
        XCTAssertEqual(Set(leads.map(\.id)), ["tracking-api.example.test", "resource-location"])
        XCTAssertEqual(leads.first(where: { $0.id == "resource-location" })?.evidenceLines, [3, 4])
        XCTAssertFalse(leads.map(\.observed).joined().contains("private.other.test"))
    }

    func testComparisonDescribesSnapshotChanges() {
        let earlier = APRSnapshot(
            bundleID: "com.example.target", artifactSHA256: "one",
            networkContacts: [NetworkContact(sourceLine: 1, domain: "old.example", firstSeenAt: .now,
                                             lastSeenAt: .now, reportedContacts: 1,
                                             initiatedType: nil, domainType: nil, domainOwner: nil)],
            resourceAccesses: [], skippedSelectedRecords: 0
        )
        let later = APRSnapshot(
            bundleID: "com.example.target", artifactSHA256: "two",
            networkContacts: [NetworkContact(sourceLine: 2, domain: "new.example", firstSeenAt: .now,
                                             lastSeenAt: .now, reportedContacts: 2,
                                             initiatedType: nil, domainType: nil, domainOwner: nil)],
            resourceAccesses: [ResourceAccess(category: "camera", startedAt: .now, endedAt: nil,
                                              sourceLines: [3])], skippedSelectedRecords: 0
        )
        let comparison = APRComparison.compare(earlier, later)
        XCTAssertEqual(comparison?.newDomains, ["new.example"])
        XCTAssertEqual(comparison?.absentDomains, ["old.example"])
        XCTAssertEqual(comparison?.newResourceCategories, ["camera"])
    }

    func testHTMLReportEscapesActivityValues() {
        let snapshot = APRSnapshot(
            bundleID: "com.example.target", artifactSHA256: "abc",
            networkContacts: [NetworkContact(sourceLine: 1, domain: "<script>alert(1)</script>",
                                             firstSeenAt: .now, lastSeenAt: .now,
                                             reportedContacts: 1, initiatedType: nil,
                                             domainType: 1, domainOwner: nil)],
            resourceAccesses: [], skippedSelectedRecords: 0
        )
        let session = AuditSession(bundleID: snapshot.bundleID, label: "<test>", notes: "private account note",
                                   baselineSnapshotID: snapshot.id)
        let report = SnapshotHTMLReport.render(snapshot, comparison: nil, session: session)
        XCTAssertFalse(report.contains("<script>alert(1)</script>"))
        XCTAssertTrue(report.contains("&lt;script&gt;"))
        XCTAssertTrue(report.contains("&lt;test&gt;"))
        XCTAssertFalse(report.contains("private account note"))
        XCTAssertTrue(report.contains("Things to review"))
    }

    func testLegacySessionWithoutNotesAndSelectedAppDeletion() throws {
        let snapshotA = APRSnapshot(bundleID: "com.example.a", artifactSHA256: "a", networkContacts: [],
                                    resourceAccesses: [], skippedSelectedRecords: 0)
        let snapshotB = APRSnapshot(bundleID: "com.example.b", artifactSHA256: "b", networkContacts: [],
                                    resourceAccesses: [], skippedSelectedRecords: 0)
        let session = AuditSession(bundleID: snapshotA.bundleID, label: "Example",
                                   baselineSnapshotID: snapshotA.id)
        let oldData = try JSONEncoder().encode(session)
        var oldJSON = try XCTUnwrap(JSONSerialization.jsonObject(with: oldData) as? [String: Any])
        oldJSON.removeValue(forKey: "notes")
        let decoded = try JSONDecoder().decode(AuditSession.self, from: JSONSerialization.data(withJSONObject: oldJSON))
        XCTAssertNil(decoded.notes)

        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let storage = try AuditStorage(root: root)
        try storage.save(snapshotA)
        try storage.save(snapshotB)
        try storage.saveSessions([session])
        _ = try storage.writeHTMLReport(snapshotA, comparison: nil)
        _ = try storage.writeJSONReport(snapshotA)
        try storage.deleteApp(bundleID: snapshotA.bundleID, snapshots: [snapshotA, snapshotB], sessions: [session],
                              assessments: [])
        XCTAssertEqual(try storage.loadSnapshots().map(\.bundleID), [snapshotB.bundleID])
        XCTAssertTrue(try storage.loadSessions().isEmpty)
        let reports = try FileManager.default.contentsOfDirectory(at: root.appendingPathComponent("Reports"),
                                                                   includingPropertiesForKeys: nil)
        XCTAssertTrue(reports.isEmpty)
    }

    func testEvidenceJSONIncludesOnlySelectedAppAndNoPrivateNotes() throws {
        let snapshot = try APRParser.snapshot(fixture(), bundleID: "com.example.target")
        let session = AuditSession(bundleID: snapshot.bundleID, label: "Login flow",
                                   notes: "private account note", baselineSnapshotID: snapshot.id)
        let data = try EvidenceJSONReport.render(snapshot, session: session)
        let report = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        XCTAssertEqual(report["schema_version"] as? String, "2.1")
        XCTAssertEqual((report["target"] as? [String: Any])?["identifier"] as? String,
                       "com.example.target")
        XCTAssertEqual((report["observations"] as? [[String: Any]])?.count, 2)
        XCTAssertTrue((report["findings"] as? [Any])?.isEmpty ?? false)
        XCTAssertEqual((report["assessment"] as? [String: Any])?["status"] as? String, "incomplete")
        XCTAssertTrue((report["attack_vectors"] as? [Any])?.isEmpty ?? false)
        let serialized = String(decoding: data, as: UTF8.self)
        XCTAssertFalse(serialized.contains("private.other.test"))
        XCTAssertFalse(serialized.contains("private-page"))
        XCTAssertFalse(serialized.contains("private account note"))
    }

    func testGuidedAssessmentGradeAndAttackVectorEvidence() throws {
        let snapshot = try APRParser.snapshot(fixture(), bundleID: "com.example.target")
        var assessment = ResearchAssessment(snapshotID: snapshot.id, bundleID: snapshot.bundleID,
                                            appVersion: "1.2.3", iOSVersion: "26.0",
                                            scope: "Two accounts I control")
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let storage = try AuditStorage(root: root)
        let source = root.appendingPathComponent("private-screenshot.txt")
        assessment.records = GuidedCheckCatalog.checks.map {
            ResearchCheckRecord(id: $0.id, status: .passed, summary: "Expected protection observed twice.", trials: 2,
                                evidence: [])
        }
        for index in assessment.records.indices {
            try Data("Synthetic evidence for \(assessment.records[index].id)".utf8).write(to: source)
            assessment.records[index].evidence = [try storage.attachEvidence(source, assessmentID: assessment.id)]
        }
        XCTAssertNil(AssessmentGrader.grade(assessment).letter)
        XCTAssertEqual(AssessmentGrader.grade(assessment,
                                             evidenceIntegrity: storage.verifyEvidence(assessment)).letter, "A")
        let obsolete = ResearchAssessment(snapshotID: snapshot.id, bundleID: snapshot.bundleID,
                                          rubricVersion: "0.0", appVersion: "1.2.3", iOSVersion: "26.0",
                                          scope: "Two accounts I control", records: assessment.records)
        XCTAssertNil(AssessmentGrader.grade(obsolete).letter)
        XCTAssertTrue(AttackVectorEngine.vectors(for: obsolete).isEmpty)

        var failing = try XCTUnwrap(assessment.records.firstIndex(where: { $0.id == "links.account_boundary" }))
        assessment.records[failing].status = .confirmed
        assessment.records[failing].summary = "Account B could view account A's private test item."
        assessment.records[failing].impact = "Private content crossed the account boundary."
        assessment.records[failing].severity = .high
        assessment.records[failing].evidenceLines = [1]
        assessment.records[failing].testURL = "secret-app-link://private-token"
        let integrity = storage.verifyEvidence(assessment)
        let graded = AssessmentGrader.grade(assessment, evidenceIntegrity: integrity)
        XCTAssertEqual(graded.letter, "D")
        XCTAssertTrue(graded.rationale.contains { $0.contains("High") })
        let vectors = AttackVectorEngine.vectors(for: assessment, evidenceIntegrity: integrity)
        XCTAssertEqual(vectors.count, 1)
        XCTAssertEqual(vectors[0].state, .confirmed)
        XCTAssertEqual(vectors[0].evidenceLines, [1])
        XCTAssertTrue(vectors[0].attackScenario.contains("ownership check"))

        let html = SnapshotHTMLReport.render(snapshot, comparison: nil, assessment: assessment,
                                             evidenceIntegrity: integrity)
        XCTAssertTrue(html.contains("Potential attack vectors"))
        XCTAssertTrue(html.contains("Possible attack path"))
        XCTAssertTrue(html.contains("D · provisional"))
        XCTAssertTrue(html.contains("Why this grade"))
        XCTAssertTrue(html.contains("Guided check coverage"))
        XCTAssertFalse(html.contains("secret-app-link"))
        XCTAssertFalse(html.contains("private-screenshot.txt"))

        let data = try EvidenceJSONReport.render(snapshot, assessment: assessment,
                                                 evidenceIntegrity: integrity)
        let json = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        XCTAssertEqual((json["assessment"] as? [String: Any])?["grade"] as? String, "D")
        XCTAssertEqual((json["assessment"] as? [String: Any])?["evidence_integrity_status"] as? String,
                       "verified")
        XCTAssertFalse(((json["assessment"] as? [String: Any])?["grade_rationale"] as? [String] ?? []).isEmpty)
        XCTAssertEqual((json["attack_vectors"] as? [[String: Any]])?.count, 1)
        XCTAssertEqual((json["attack_vectors"] as? [[String: Any]])?.first?["attack_scenario"] as? String,
                       vectors[0].attackScenario)
        XCTAssertEqual((json["test_results"] as? [[String: Any]])?.count,
                       GuidedCheckCatalog.checks.count)
        let text = String(decoding: data, as: UTF8.self)
        XCTAssertFalse(text.contains("secret-app-link"))
        XCTAssertFalse(text.contains("private-screenshot.txt"))
        XCTAssertFalse(text.contains("Two accounts I control"))
        if let directoryPath = ProcessInfo.processInfo.environment["MOBILE_AUDIT_SAMPLE_REPORT_DIR"] {
            let directory = URL(fileURLWithPath: directoryPath, isDirectory: true)
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            let sampleHTML = html.replacingOccurrences(of: "<body>", with:
                "<body><div class=\"notice\"><strong>Synthetic demonstration:</strong> This app, test result, and grade are invented. Temporary test evidence was checked when this example was generated, but its files are not included. No real vulnerability is reported here.</div>")
            try sampleHTML.write(to: directory.appendingPathComponent("sample-assessment.html"),
                                 atomically: true, encoding: .utf8)
            var sampleJSON = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
            var sampleNotes = try XCTUnwrap(sampleJSON["notes"] as? [String])
            sampleNotes.insert("Synthetic demonstration: the app, test result, and grade are invented. Temporary evidence files were checked during generation and are not retained in this example.", at: 0)
            sampleJSON["notes"] = sampleNotes
            var sampleArtifacts = try XCTUnwrap(sampleJSON["artifacts"] as? [[String: Any]])
            for index in sampleArtifacts.indices where sampleArtifacts[index]["kind"] as? String == "research_evidence_file" {
                sampleArtifacts[index]["raw_retained"] = false
            }
            sampleJSON["artifacts"] = sampleArtifacts
            try JSONSerialization.data(withJSONObject: sampleJSON, options: [.prettyPrinted, .sortedKeys])
                .write(to: directory.appendingPathComponent("sample-assessment.json"), options: .atomic)
        }

        failing = try XCTUnwrap(assessment.records.firstIndex(where: { $0.id == "links.account_boundary" }))
        assessment.records[failing].evidence = []
        let missingIntegrity = storage.verifyEvidence(assessment)
        XCTAssertNil(AssessmentGrader.grade(assessment, evidenceIntegrity: missingIntegrity).letter)
        XCTAssertEqual(AttackVectorEngine.vectors(for: assessment, evidenceIntegrity: missingIntegrity).first?.state,
                       .testedUnconfirmed)
        let unverifiedJSON = try EvidenceJSONReport.render(snapshot, assessment: assessment,
                                                           evidenceIntegrity: missingIntegrity)
        let unverifiedReport = try XCTUnwrap(JSONSerialization.jsonObject(with: unverifiedJSON) as? [String: Any])
        let unverifiedTests = try XCTUnwrap(unverifiedReport["test_results"] as? [[String: Any]])
        XCTAssertEqual(unverifiedTests.first(where: { $0["rule_id"] as? String == "links.account_boundary" })?["status"] as? String,
                       "inconclusive")

        assessment.records[failing].status = .concern
        XCTAssertNil(AssessmentGrader.grade(assessment).letter)
    }

    func testAttachedResearchEvidenceIsDeletedWithApp() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let storage = try AuditStorage(root: root)
        let source = root.appendingPathComponent("example.png")
        try Data("screen evidence".utf8).write(to: source)
        let snapshot = APRSnapshot(bundleID: "com.example.target", artifactSHA256: String(repeating: "a", count: 64),
                                   networkContacts: [], resourceAccesses: [], skippedSelectedRecords: 0)
        let assessment = ResearchAssessment(snapshotID: snapshot.id, bundleID: snapshot.bundleID)
        let attached = try storage.attachEvidence(source, assessmentID: assessment.id)
        XCTAssertEqual(attached.sha256.count, 64)
        var saved = assessment
        saved.records = [ResearchCheckRecord(id: "links.signed_out", status: .confirmed,
                                             summary: "Protected item opened after sign-out.",
                                             impact: "Private content appeared after sign-out.", severity: .high,
                                             trials: 2, evidence: [attached])]
        let validIntegrity = storage.verifyEvidence(saved)
        XCTAssertEqual(validIntegrity.verifiedIDs, [attached.id])
        XCTAssertTrue(validIntegrity.issues.isEmpty)
        XCTAssertEqual(AttackVectorEngine.vectors(for: saved, evidenceIntegrity: validIntegrity).first?.state,
                       .confirmed)
        let evidencePath = root.appendingPathComponent("ResearchEvidence")
            .appendingPathComponent(assessment.id.uuidString).appendingPathComponent(attached.storedFileName)
        try Data(repeating: 0x58, count: attached.byteCount).write(to: evidencePath)
        let changedIntegrity = storage.verifyEvidence(saved)
        XCTAssertFalse(changedIntegrity.issues.isEmpty)
        XCTAssertTrue(changedIntegrity.verifiedIDs.isEmpty)
        XCTAssertEqual(AttackVectorEngine.vectors(for: saved, evidenceIntegrity: changedIntegrity).first?.state,
                       .testedUnconfirmed)
        let changedJSON = try storage.writeJSONReport(snapshot, assessment: saved)
        let changedData = try Data(contentsOf: changedJSON)
        let changedReport = try XCTUnwrap(JSONSerialization.jsonObject(with: changedData) as? [String: Any])
        XCTAssertEqual((changedReport["assessment"] as? [String: Any])?["evidence_integrity_status"] as? String,
                       "failed")
        let changedArtifacts = try XCTUnwrap(changedReport["artifacts"] as? [[String: Any]])
        XCTAssertEqual(changedArtifacts.first(where: { $0["kind"] as? String == "research_evidence_file" })?["raw_retained"] as? Bool,
                       false)
        let other = ResearchAssessment(snapshotID: UUID(), bundleID: "com.example.other")
        let otherEvidence = try storage.attachEvidence(source, assessmentID: other.id)
        var savedOther = other
        savedOther.records = [ResearchCheckRecord(id: "content.import", evidence: [otherEvidence])]
        try storage.save(snapshot)
        try storage.saveAssessments([saved, savedOther])
        XCTAssertEqual(try storage.loadAssessments().count, 2)
        try storage.deleteApp(bundleID: snapshot.bundleID, snapshots: [snapshot], sessions: [],
                              assessments: [saved, savedOther])
        XCTAssertEqual(try storage.loadAssessments().map(\.bundleID), ["com.example.other"])
        let directory = root.appendingPathComponent("ResearchEvidence").appendingPathComponent(assessment.id.uuidString)
        XCTAssertFalse(FileManager.default.fileExists(atPath: directory.path))
        let otherDirectory = root.appendingPathComponent("ResearchEvidence").appendingPathComponent(other.id.uuidString)
        XCTAssertTrue(FileManager.default.fileExists(atPath: otherDirectory.path))
    }

    func testManualCaseKeepsReproducerPrivateAndDeletesItsFiles() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let storage = try AuditStorage(root: root)
        let source = root.appendingPathComponent("synthetic-proof.txt")
        try Data("Invented evidence for a test case".utf8).write(to: source)

        var manual = ResearchAssessment(bundleID: "com.example.target", targetName: "Example App",
                                        appVersion: "1.2.3", iOSVersion: "26.0",
                                        scope: "Two test accounts I control")
        let attached = try storage.attachEvidence(source, assessmentID: manual.id)
        let privateMarker = "PRIVATE-REPRODUCER-ONLY-TEST-INPUT"
        let notes = PrivateCaseNotes(
            preconditions: "Start with test account B signed in.",
            steps: "1. Create a private item in test account A.\n2. Open \(privateMarker) from test account B.",
            expected: "Account B is denied access.",
            observed: "Account B sees account A's invented test item.",
            attackerControl: "An account and a link to the test item.",
            priorArt: "No matching vendor advisory found in this synthetic exercise.")
        let record = ResearchCheckRecord(
            id: "links.account_boundary", status: .confirmed,
            summary: "A test item was visible across two controlled accounts.",
            impact: "Private test content crossed an account boundary.", severity: .high,
            trials: 2, evidence: [attached], privateCase: notes)
        manual.records = [record]
        try storage.saveAssessments([manual])

        let loaded = try XCTUnwrap(storage.loadAssessments().first)
        XCTAssertNil(loaded.snapshotID)
        XCTAssertEqual(loaded.displayName, "Example App")
        XCTAssertEqual(loaded.record(for: record.id).privateCase, notes)
        let integrity = storage.verifyEvidence(loaded)
        XCTAssertTrue(CaseReadiness.review(loaded, record: record,
                                           evidenceIntegrity: integrity).readyForPrivateReview)
        let draftURL = try storage.writePrivateCaseDraft(loaded, checkID: record.id)
        let draft = try String(contentsOf: draftURL, encoding: .utf8)
        XCTAssertTrue(draft.contains(privateMarker))
        XCTAssertTrue(draft.contains("Possible attack path (conditional)"))
        XCTAssertTrue(draft.contains("No export attached"))
        XCTAssertTrue(draft.contains("not an assigned CVE"))
        try storage.removePrivateCaseDrafts(assessmentID: loaded.id, checkID: record.id)
        XCTAssertFalse(FileManager.default.fileExists(atPath: draftURL.path))
        _ = try storage.writePrivateCaseDraft(loaded, checkID: record.id)

        let snapshot = try APRParser.snapshot(fixture(), bundleID: "com.example.target")
        let publicAssessment = ResearchAssessment(
            id: manual.id, snapshotID: snapshot.id, bundleID: snapshot.bundleID,
            appVersion: manual.appVersion, iOSVersion: manual.iOSVersion,
            scope: manual.scope, records: manual.records)
        let publicJSON = try EvidenceJSONReport.render(snapshot, assessment: publicAssessment,
                                                       evidenceIntegrity: integrity)
        let publicHTML = SnapshotHTMLReport.render(snapshot, comparison: nil,
                                                   assessment: publicAssessment,
                                                   evidenceIntegrity: integrity)
        XCTAssertFalse(String(decoding: publicJSON, as: UTF8.self).contains(privateMarker))
        XCTAssertFalse(publicHTML.contains(privateMarker))
        XCTAssertFalse(String(decoding: publicJSON, as: UTF8.self).contains(notes.preconditions))
        XCTAssertFalse(publicHTML.contains(notes.preconditions))

        var unconfirmed = record
        unconfirmed.status = .concern
        XCTAssertFalse(CaseReadiness.review(loaded, record: unconfirmed,
                                            evidenceIntegrity: integrity).readyForPrivateReview)
        XCTAssertFalse(CaseReadiness.review(loaded, record: record,
                                            evidenceIntegrity: nil).readyForPrivateReview)
        var missingScope = loaded
        missingScope.scope = ""
        XCTAssertFalse(CaseReadiness.review(missingScope, record: record,
                                            evidenceIntegrity: integrity).readyForPrivateReview)
        var unnumbered = record
        unnumbered.privateCase?.steps = "Open test item\nObserve result"
        XCTAssertFalse(CaseReadiness.review(loaded, record: unnumbered,
                                            evidenceIntegrity: integrity).readyForPrivateReview)

        if let directoryPath = ProcessInfo.processInfo.environment["MOBILE_AUDIT_SAMPLE_REPORT_DIR"] {
            let directory = URL(fileURLWithPath: directoryPath, isDirectory: true)
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            let sample = "SYNTHETIC EXAMPLE — the app, case, and evidence are invented.\n\n" + draft
            try sample.write(to: directory.appendingPathComponent("sample-private-case.txt"),
                             atomically: true, encoding: .utf8)
        }

        try storage.deleteManualAssessment(loaded, assessments: [loaded])
        XCTAssertTrue(try storage.loadAssessments().isEmpty)
        XCTAssertFalse(FileManager.default.fileExists(atPath: draftURL.path))
        let evidenceDirectory = root.appendingPathComponent("ResearchEvidence")
            .appendingPathComponent(loaded.id.uuidString)
        XCTAssertFalse(FileManager.default.fileExists(atPath: evidenceDirectory.path))
    }

    func testOlderAssessmentAndCheckDecodeWithoutPrivateCaseFields() throws {
        let snapshotID = UUID()
        let original = ResearchAssessment(snapshotID: snapshotID, bundleID: "com.example.target",
                                          records: [ResearchCheckRecord(id: "auth.signed_out")])
        let data = try JSONEncoder().encode(original)
        var oldJSON = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        oldJSON.removeValue(forKey: "targetName")
        var records = try XCTUnwrap(oldJSON["records"] as? [[String: Any]])
        records[0].removeValue(forKey: "privateCase")
        oldJSON["records"] = records
        let decoded = try JSONDecoder().decode(ResearchAssessment.self,
                                               from: JSONSerialization.data(withJSONObject: oldJSON))
        XCTAssertEqual(decoded.snapshotID, snapshotID)
        XCTAssertNil(decoded.targetName)
        XCTAssertNil(decoded.record(for: "auth.signed_out").privateCase)
    }

    func testRealExportWhenProvided() throws {
        guard let path = ProcessInfo.processInfo.environment["MOBILE_AUDIT_REAL_APR"],
              let bundleID = ProcessInfo.processInfo.environment["MOBILE_AUDIT_REAL_BUNDLE_ID"] else {
            throw XCTSkip("Set MOBILE_AUDIT_REAL_APR and MOBILE_AUDIT_REAL_BUNDLE_ID to validate a private export")
        }
        let file = URL(fileURLWithPath: path)
        let index = try APRParser.index(file)
        XCTAssertTrue(index.apps.contains { $0.bundleID == bundleID })
        let snapshot = try APRParser.snapshot(file, bundleID: bundleID)
        XCTAssertFalse(snapshot.networkContacts.isEmpty)
        XCTAssertEqual(snapshot.artifactSHA256, index.artifactSHA256)
    }
}
