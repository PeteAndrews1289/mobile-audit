import Foundation
import SwiftUI

@MainActor
final class AuditModel: ObservableObject {
    @Published private(set) var snapshots: [APRSnapshot] = []
    @Published private(set) var sessions: [AuditSession] = []
    @Published private(set) var assessments: [ResearchAssessment] = []
    @Published private(set) var pendingApps: [APRAppOverview] = []
    @Published var isBusy = false
    @Published var errorMessage: String?
    @Published var statusMessage: String?

    private let storage: AuditStorage?
    private var pendingURL: URL?
    private var pendingHasSecurityScope = false

    init() {
        do {
            let instance = try AuditStorage()
            let savedSnapshots = try instance.loadSnapshots()
            let savedSessions = try instance.loadSessions()
            let savedAssessments = try instance.loadAssessments()
            storage = instance
            snapshots = savedSnapshots
            sessions = savedSessions
            assessments = savedAssessments
        } catch {
            storage = nil
            errorMessage = "Local storage could not be opened: \(error.localizedDescription)"
        }
    }

    var savedBundleIDs: [String] {
        Array(Set(snapshots.map(\.bundleID))).sorted()
    }

    var manualAssessments: [ResearchAssessment] {
        assessments.filter { $0.snapshotID == nil }.sorted { $0.createdAt > $1.createdAt }
    }

    func snapshots(for bundleID: String) -> [APRSnapshot] {
        snapshots.filter { $0.bundleID == bundleID }.sorted { $0.importedAt > $1.importedAt }
    }

    func latestSession(for bundleID: String) -> AuditSession? {
        sessions.filter { $0.bundleID == bundleID }.sorted { $0.startedAt > $1.startedAt }.first
    }

    func assessment(for snapshotID: UUID) -> ResearchAssessment? {
        assessments.first { $0.snapshotID == snapshotID }
    }

    func assessment(id: UUID) -> ResearchAssessment? {
        assessments.first { $0.id == id }
    }

    func evidenceIntegrity(for assessment: ResearchAssessment?) -> EvidenceIntegrityReport? {
        guard let storage, let assessment else { return nil }
        return storage.verifyEvidence(assessment)
    }

    func startAssessment(for snapshot: APRSnapshot, iOSVersion: String) {
        guard let storage, assessment(for: snapshot.id) == nil else { return }
        var updated = assessments
        updated.insert(ResearchAssessment(snapshotID: snapshot.id, bundleID: snapshot.bundleID,
                                          iOSVersion: iOSVersion), at: 0)
        do {
            try storage.saveAssessments(updated)
            assessments = updated
        } catch { errorMessage = "Assessment could not be started: \(error.localizedDescription)" }
    }

    @discardableResult
    func startManualAssessment(name: String, bundleID: String, iOSVersion: String) -> UUID? {
        guard let storage else { return nil }
        let cleanName = String(name.trimmingCharacters(in: .whitespacesAndNewlines).prefix(100))
        guard !cleanName.isEmpty else {
            errorMessage = "Enter the app's name to start a research case."
            return nil
        }
        let cleanBundleID = String(bundleID.trimmingCharacters(in: .whitespacesAndNewlines).prefix(200))
        let assessment = ResearchAssessment(bundleID: cleanBundleID, targetName: cleanName,
                                            iOSVersion: String(iOSVersion.prefix(80)))
        var updated = assessments
        updated.insert(assessment, at: 0)
        do {
            try storage.saveAssessments(updated)
            assessments = updated
            statusMessage = "Started a private case for \(cleanName)."
            return assessment.id
        } catch {
            errorMessage = "Research case could not be started: \(error.localizedDescription)"
            return nil
        }
    }

    func saveAssessmentMetadata(assessmentID: UUID, appVersion: String, iOSVersion: String, scope: String) {
        guard let storage, let index = assessments.firstIndex(where: { $0.id == assessmentID }) else { return }
        var updated = assessments
        updated[index].appVersion = String(appVersion.trimmingCharacters(in: .whitespacesAndNewlines).prefix(80))
        updated[index].iOSVersion = String(iOSVersion.trimmingCharacters(in: .whitespacesAndNewlines).prefix(80))
        updated[index].scope = String(scope.trimmingCharacters(in: .whitespacesAndNewlines).prefix(1000))
        updated[index].updatedAt = Date()
        do {
            try storage.removePrivateCaseDrafts(assessmentID: assessmentID)
            try storage.saveAssessments(updated)
            assessments = updated
            statusMessage = "Assessment details saved on this device."
        } catch { errorMessage = "Assessment details could not be saved: \(error.localizedDescription)" }
    }

    @discardableResult
    func saveCheck(assessmentID: UUID, record: ResearchCheckRecord) -> Bool {
        guard let storage, let index = assessments.firstIndex(where: { $0.id == assessmentID }),
              GuidedCheckCatalog.check(record.id) != nil else { return false }
        let assessment = assessments[index]
        let availableLines: Set<Int>
        if let snapshotID = assessment.snapshotID,
           let snapshot = snapshots.first(where: { $0.id == snapshotID && $0.bundleID == assessment.bundleID }) {
            availableLines = Set(snapshot.networkContacts.map(\.sourceLine) +
                                 snapshot.resourceAccesses.flatMap(\.sourceLines))
        } else {
            availableLines = []
        }
        guard Set(record.evidenceLines).isSubset(of: availableLines) else {
            errorMessage = "Evidence lines must belong to this app's selected export."
            return false
        }
        var updated = assessments
        var clean = record
        clean.summary = String(record.summary.trimmingCharacters(in: .whitespacesAndNewlines).prefix(2000))
        clean.impact = String(record.impact.trimmingCharacters(in: .whitespacesAndNewlines).prefix(2000))
        clean.testURL = String(record.testURL.trimmingCharacters(in: .whitespacesAndNewlines).prefix(2000))
        if let notes = record.privateCase {
            let trimmed = PrivateCaseNotes(
                preconditions: String(notes.preconditions.trimmingCharacters(in: .whitespacesAndNewlines).prefix(4000)),
                steps: String(notes.steps.trimmingCharacters(in: .whitespacesAndNewlines).prefix(8000)),
                expected: String(notes.expected.trimmingCharacters(in: .whitespacesAndNewlines).prefix(4000)),
                observed: String(notes.observed.trimmingCharacters(in: .whitespacesAndNewlines).prefix(4000)),
                attackerControl: String(notes.attackerControl.trimmingCharacters(in: .whitespacesAndNewlines).prefix(4000)),
                priorArt: String(notes.priorArt.trimmingCharacters(in: .whitespacesAndNewlines).prefix(4000)))
            clean.privateCase = trimmed.isEmpty ? nil : trimmed
        }
        clean.trials = min(max(record.trials, 0), 20)
        clean.updatedAt = Date()
        if let row = updated[index].records.firstIndex(where: { $0.id == record.id }) {
            updated[index].records[row] = clean
        } else {
            updated[index].records.append(clean)
        }
        updated[index].updatedAt = Date()
        do {
            try storage.removePrivateCaseDrafts(assessmentID: assessmentID, checkID: record.id)
            try storage.saveAssessments(updated)
            assessments = updated
            statusMessage = "Guided check saved on this device."
            return true
        } catch {
            errorMessage = "Guided check could not be saved: \(error.localizedDescription)"
            return false
        }
    }

    func attachEvidence(assessmentID: UUID, checkID: String, file: URL) {
        guard let storage, let index = assessments.firstIndex(where: { $0.id == assessmentID }),
              GuidedCheckCatalog.check(checkID) != nil else { return }
        do {
            let evidence = try storage.attachEvidence(file, assessmentID: assessments[index].id)
            var updated = assessments
            var record = updated[index].record(for: checkID)
            record.evidence.append(evidence)
            record.updatedAt = Date()
            if let row = updated[index].records.firstIndex(where: { $0.id == checkID }) {
                updated[index].records[row] = record
            } else {
                updated[index].records.append(record)
            }
            updated[index].updatedAt = Date()
            do {
                try storage.removePrivateCaseDrafts(assessmentID: assessments[index].id, checkID: checkID)
                try storage.saveAssessments(updated)
                assessments = updated
                statusMessage = "Evidence file saved privately on this device."
            } catch {
                try? storage.removeEvidence(evidence, assessmentID: assessments[index].id)
                throw error
            }
        } catch { errorMessage = "Evidence could not be attached: \(error.localizedDescription)" }
    }

    func removeEvidence(assessmentID: UUID, checkID: String, evidenceID: UUID) {
        guard let storage, let index = assessments.firstIndex(where: { $0.id == assessmentID }) else { return }
        let oldRecord = assessments[index].record(for: checkID)
        guard let evidence = oldRecord.evidence.first(where: { $0.id == evidenceID }) else { return }
        var updated = assessments
        var record = oldRecord
        record.evidence.removeAll { $0.id == evidenceID }
        record.updatedAt = Date()
        if let row = updated[index].records.firstIndex(where: { $0.id == checkID }) {
            updated[index].records[row] = record
        }
        updated[index].updatedAt = Date()
        do {
            try storage.removeEvidence(evidence, assessmentID: updated[index].id)
            try storage.removePrivateCaseDrafts(assessmentID: assessmentID, checkID: checkID)
            try storage.saveAssessments(updated)
            assessments = updated
        } catch { errorMessage = "Evidence could not be removed: \(error.localizedDescription)" }
    }

    func privateCaseDraft(assessmentID: UUID, checkID: String) throws -> URL {
        guard let storage, let assessment = assessment(id: assessmentID) else {
            throw APRImportError.unreadableFile
        }
        return try storage.writePrivateCaseDraft(assessment, checkID: checkID)
    }

    @discardableResult
    func savePrivateCaseNotes(assessmentID: UUID, checkID: String, notes: PrivateCaseNotes) -> Bool {
        guard let assessment = assessment(id: assessmentID) else { return false }
        var record = assessment.record(for: checkID)
        record.privateCase = notes.isEmpty ? nil : notes
        return saveCheck(assessmentID: assessmentID, record: record)
    }

    func deleteManualAssessment(id: UUID) -> Bool {
        guard let storage, let assessment = assessment(id: id), assessment.snapshotID == nil else { return false }
        do {
            try storage.deleteManualAssessment(assessment, assessments: assessments)
            assessments.removeAll { $0.id == id }
            statusMessage = "Deleted the private research case."
            return true
        } catch {
            assessments = (try? storage.loadAssessments()) ?? assessments
            errorMessage = "Research case could not be fully deleted: \(error.localizedDescription)"
            return false
        }
    }

    func sessionComparison(_ session: AuditSession) -> APRComparison? {
        guard let followupID = session.followupSnapshotID,
              let earlier = snapshots.first(where: { $0.id == session.baselineSnapshotID }),
              let later = snapshots.first(where: { $0.id == followupID }) else { return nil }
        return APRComparison.compare(earlier, later)
    }

    func prepareImport(_ url: URL) async {
        cancelPendingImport()
        statusMessage = nil
        let scope = url.startAccessingSecurityScopedResource()
        pendingURL = url
        pendingHasSecurityScope = scope
        isBusy = true
        do {
            let index = try await Task.detached(priority: .userInitiated) {
                try APRParser.index(url)
            }.value
            guard !index.apps.isEmpty else { throw APRImportError.noEntries("any app") }
            pendingApps = index.apps
        } catch {
            errorMessage = error.localizedDescription
            cancelPendingImport()
        }
        isBusy = false
    }

    func importSelectedApp(_ bundleID: String) async -> Bool {
        guard let url = pendingURL, let storage else {
            errorMessage = "Choose an App Privacy Report first."
            return false
        }
        isBusy = true
        defer { isBusy = false }
        do {
            let snapshot = try await Task.detached(priority: .userInitiated) {
                try APRParser.snapshot(url, bundleID: bundleID)
            }.value
            if snapshots.contains(where: { $0.bundleID == bundleID && $0.artifactSHA256 == snapshot.artifactSHA256 }) {
                statusMessage = "This export was already saved for \(bundleID)."
                cancelPendingImport()
                return true
            }
            try storage.save(snapshot)
            snapshots.insert(snapshot, at: 0)
            if let index = sessions.indices.filter({ index in
                guard let endedAt = sessions[index].endedAt else { return false }
                return sessions[index].bundleID == bundleID &&
                    sessions[index].followupSnapshotID == nil &&
                    sessions[index].baselineSnapshotID != snapshot.id &&
                    endedAt <= snapshot.importedAt
            }).max(by: { sessions[$0].startedAt < sessions[$1].startedAt }) {
                var updated = sessions
                updated[index].followupSnapshotID = snapshot.id
                do {
                    try storage.saveSessions(updated)
                    sessions = updated
                } catch {
                    errorMessage = "The snapshot was saved, but its session link could not be saved: \(error.localizedDescription)"
                }
            }
            statusMessage = "Saved a snapshot for \(bundleID)."
            cancelPendingImport()
            return true
        } catch {
            errorMessage = error.localizedDescription
            return false
        }
    }

    func cancelPendingImport() {
        if pendingHasSecurityScope { pendingURL?.stopAccessingSecurityScopedResource() }
        pendingURL = nil
        pendingHasSecurityScope = false
        pendingApps = []
    }

    func startSession(bundleID: String, label: String) {
        guard let storage, let baseline = snapshots(for: bundleID).first else {
            errorMessage = "Import a baseline report for this app first."
            return
        }
        guard !sessions.contains(where: { $0.bundleID == bundleID && $0.endedAt == nil }) else {
            errorMessage = "Finish the current session first."
            return
        }
        let cleanLabel = String(label.trimmingCharacters(in: .whitespacesAndNewlines).prefix(100))
        guard !cleanLabel.isEmpty else {
            errorMessage = "Give this session a short label."
            return
        }
        var updated = sessions
        updated.insert(AuditSession(bundleID: bundleID, label: cleanLabel,
                                    baselineSnapshotID: baseline.id), at: 0)
        do {
            try storage.saveSessions(updated)
            sessions = updated
        }
        catch { errorMessage = error.localizedDescription }
    }

    func finishSession(bundleID: String, notes: String) {
        guard let storage,
              let index = sessions.firstIndex(where: { $0.bundleID == bundleID && $0.endedAt == nil }) else { return }
        var updated = sessions
        updated[index].endedAt = Date()
        updated[index].notes = String(notes.trimmingCharacters(in: .whitespacesAndNewlines).prefix(4000))
        do {
            try storage.saveSessions(updated)
            sessions = updated
        }
        catch { errorMessage = error.localizedDescription }
    }

    func saveNotes(sessionID: UUID, notes: String) {
        guard let storage, let index = sessions.firstIndex(where: { $0.id == sessionID }) else { return }
        var updated = sessions
        updated[index].notes = String(notes.trimmingCharacters(in: .whitespacesAndNewlines).prefix(4000))
        do {
            try storage.saveSessions(updated)
            sessions = updated
            statusMessage = "Session notes saved on this device."
        } catch { errorMessage = error.localizedDescription }
    }

    func deleteApp(_ bundleID: String) -> Bool {
        guard let storage else { return false }
        do {
            try storage.deleteApp(bundleID: bundleID, snapshots: snapshots, sessions: sessions,
                                  assessments: assessments)
            snapshots.removeAll { $0.bundleID == bundleID }
            sessions.removeAll { $0.bundleID == bundleID }
            assessments.removeAll { $0.bundleID == bundleID }
            statusMessage = "Deleted saved data for \(bundleID)."
            return true
        } catch {
            snapshots = (try? storage.loadSnapshots()) ?? snapshots
            sessions = (try? storage.loadSessions()) ?? sessions
            assessments = (try? storage.loadAssessments()) ?? assessments
            errorMessage = "Saved data could not be fully deleted: \(error.localizedDescription)"
            return false
        }
    }

    func shareableReport(for snapshot: APRSnapshot) throws -> URL {
        guard let storage else { throw APRImportError.unreadableFile }
        let prior = snapshots(for: snapshot.bundleID)
            .filter { $0.id != snapshot.id && $0.importedAt < snapshot.importedAt }.first
        let comparison = prior.flatMap { APRComparison.compare($0, snapshot) }
        let session = sessions.first { $0.followupSnapshotID == snapshot.id }
        return try storage.writeHTMLReport(snapshot, comparison: comparison, session: session,
                                           assessment: assessment(for: snapshot.id))
    }

    func shareableJSONReport(for snapshot: APRSnapshot) throws -> URL {
        guard let storage else { throw APRImportError.unreadableFile }
        let session = sessions.first { $0.followupSnapshotID == snapshot.id }
        return try storage.writeJSONReport(snapshot, session: session,
                                           assessment: assessment(for: snapshot.id))
    }
}
