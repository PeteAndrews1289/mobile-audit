import Foundation
import CryptoKit

public final class AuditStorage {
    public let root: URL
    private let manager = FileManager.default

    public init(root: URL? = nil) throws {
        if let root {
            self.root = root
        } else {
            guard let support = manager.urls(for: .applicationSupportDirectory, in: .userDomainMask).first else {
                throw APRImportError.unreadableFile
            }
            self.root = support.appendingPathComponent("MobileAudit", isDirectory: true)
        }
        try manager.createDirectory(at: self.root, withIntermediateDirectories: true)
        try manager.createDirectory(at: snapshotsDirectory, withIntermediateDirectories: true)
        try manager.createDirectory(at: reportsDirectory, withIntermediateDirectories: true)
        try manager.createDirectory(at: evidenceDirectory, withIntermediateDirectories: true)
        try manager.createDirectory(at: caseDraftsDirectory, withIntermediateDirectories: true)
    }

    private var snapshotsDirectory: URL { root.appendingPathComponent("Snapshots", isDirectory: true) }
    private var reportsDirectory: URL { root.appendingPathComponent("Reports", isDirectory: true) }
    private var evidenceDirectory: URL { root.appendingPathComponent("ResearchEvidence", isDirectory: true) }
    private var caseDraftsDirectory: URL { root.appendingPathComponent("PrivateCaseDrafts", isDirectory: true) }
    private var sessionsURL: URL { root.appendingPathComponent("sessions.json") }
    private var assessmentsURL: URL { root.appendingPathComponent("assessments.json") }

    private func encoder() -> JSONEncoder {
        let value = JSONEncoder()
        value.outputFormatting = [.prettyPrinted, .sortedKeys]
        value.dateEncodingStrategy = .millisecondsSince1970
        return value
    }

    private func decoder() -> JSONDecoder {
        let value = JSONDecoder()
        value.dateDecodingStrategy = .millisecondsSince1970
        return value
    }

    private func write(_ data: Data, to url: URL) throws {
        #if os(iOS)
        try data.write(to: url, options: [.atomic, .completeFileProtection])
        #else
        try data.write(to: url, options: .atomic)
        #endif
    }

    public func save(_ snapshot: APRSnapshot) throws {
        let url = snapshotsDirectory.appendingPathComponent(snapshot.id.uuidString).appendingPathExtension("json")
        try write(encoder().encode(snapshot), to: url)
    }

    public func loadSnapshots() throws -> [APRSnapshot] {
        let urls = try manager.contentsOfDirectory(at: snapshotsDirectory, includingPropertiesForKeys: nil)
            .filter { $0.pathExtension == "json" }
        return try urls.map { try decoder().decode(APRSnapshot.self, from: Data(contentsOf: $0)) }
            .sorted { $0.importedAt > $1.importedAt }
    }

    public func saveSessions(_ sessions: [AuditSession]) throws {
        try write(encoder().encode(sessions), to: sessionsURL)
    }

    public func loadSessions() throws -> [AuditSession] {
        guard manager.fileExists(atPath: sessionsURL.path) else { return [] }
        return try decoder().decode([AuditSession].self, from: Data(contentsOf: sessionsURL))
    }

    public func saveAssessments(_ assessments: [ResearchAssessment]) throws {
        try write(encoder().encode(assessments), to: assessmentsURL)
    }

    public func loadAssessments() throws -> [ResearchAssessment] {
        guard manager.fileExists(atPath: assessmentsURL.path) else { return [] }
        return try decoder().decode([ResearchAssessment].self, from: Data(contentsOf: assessmentsURL))
    }

    public func attachEvidence(_ source: URL, assessmentID: UUID) throws -> ResearchEvidence {
        let scoped = source.startAccessingSecurityScopedResource()
        defer { if scoped { source.stopAccessingSecurityScopedResource() } }
        let attributes = try manager.attributesOfItem(atPath: source.path)
        let fileSize = (attributes[.size] as? NSNumber)?.intValue ?? 0
        guard fileSize > 0, fileSize <= 25 * 1024 * 1024 else {
            throw ResearchStorageError.invalidEvidenceSize
        }
        let data = try Data(contentsOf: source)
        guard !data.isEmpty, data.count <= 25 * 1024 * 1024 else {
            throw ResearchStorageError.invalidEvidenceSize
        }
        let extensionText = source.pathExtension.lowercased()
        let safeExtension = extensionText.range(of: "^[a-z0-9]{1,10}$", options: .regularExpression) != nil
            ? extensionText : "bin"
        let id = UUID()
        let fileName = "\(id.uuidString).\(safeExtension)"
        let directory = evidenceDirectory.appendingPathComponent(assessmentID.uuidString, isDirectory: true)
        try manager.createDirectory(at: directory, withIntermediateDirectories: true)
        try write(data, to: directory.appendingPathComponent(fileName))
        let hash = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
        return ResearchEvidence(id: id, displayName: source.lastPathComponent,
                                storedFileName: fileName, sha256: hash, byteCount: data.count)
    }

    public func removeEvidence(_ evidence: ResearchEvidence, assessmentID: UUID) throws {
        let url = evidenceDirectory.appendingPathComponent(assessmentID.uuidString, isDirectory: true)
            .appendingPathComponent(evidence.storedFileName)
        if manager.fileExists(atPath: url.path) { try manager.removeItem(at: url) }
    }

    public func verifyEvidence(_ assessment: ResearchAssessment) -> EvidenceIntegrityReport {
        var verified: Set<UUID> = []
        var issues: [String] = []
        var checkedCount = 0
        for record in assessment.records {
            for item in record.evidence {
                checkedCount += 1
                let nameIsSafe = item.storedFileName.range(
                    of: "^[0-9A-Fa-f-]{36}\\.[a-z0-9]{1,10}$", options: .regularExpression) != nil
                let url = evidenceDirectory.appendingPathComponent(assessment.id.uuidString, isDirectory: true)
                    .appendingPathComponent(item.storedFileName)
                let attributes = nameIsSafe ? try? manager.attributesOfItem(atPath: url.path) : nil
                let size = (attributes?[.size] as? NSNumber)?.intValue
                let isRegularFile = attributes?[.type] as? FileAttributeType == .typeRegular
                if nameIsSafe, isRegularFile, let size, size == item.byteCount,
                   size > 0, size <= 25 * 1024 * 1024, let data = try? Data(contentsOf: url) {
                    let hash = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
                    if data.count == size && hash == item.sha256 {
                        verified.insert(item.id)
                        continue
                    }
                }
                let title = GuidedCheckCatalog.check(record.id)?.title ?? "an unknown check"
                let issue = "Attached evidence for \(title) is missing, changed, or unreadable."
                if !issues.contains(issue) { issues.append(issue) }
            }
        }
        return EvidenceIntegrityReport(verifiedIDs: verified, checkedCount: checkedCount, issues: issues)
    }

    public func writeHTMLReport(_ snapshot: APRSnapshot, comparison: APRComparison?, session: AuditSession? = nil,
                                assessment: ResearchAssessment? = nil) throws -> URL {
        let url = reportsDirectory.appendingPathComponent(snapshot.id.uuidString).appendingPathExtension("html")
        let text = SnapshotHTMLReport.render(snapshot, comparison: comparison, session: session,
                                             assessment: assessment,
                                             evidenceIntegrity: assessment.map(verifyEvidence))
        try write(Data(text.utf8), to: url)
        return url
    }

    public func writeJSONReport(_ snapshot: APRSnapshot, session: AuditSession? = nil,
                                assessment: ResearchAssessment? = nil) throws -> URL {
        let url = reportsDirectory.appendingPathComponent(snapshot.id.uuidString).appendingPathExtension("json")
        try write(EvidenceJSONReport.render(snapshot, session: session, assessment: assessment,
                                            evidenceIntegrity: assessment.map(verifyEvidence)), to: url)
        return url
    }

    public func writePrivateCaseDraft(_ assessment: ResearchAssessment, checkID: String) throws -> URL {
        guard GuidedCheckCatalog.check(checkID) != nil else { throw ResearchStorageError.unknownCheck }
        let directory = caseDraftsDirectory.appendingPathComponent(assessment.id.uuidString, isDirectory: true)
        try manager.createDirectory(at: directory, withIntermediateDirectories: true)
        let url = directory.appendingPathComponent(checkID).appendingPathExtension("txt")
        let report = PrivateCaseReport.render(assessment, record: assessment.record(for: checkID),
                                              evidenceIntegrity: verifyEvidence(assessment))
        try write(Data(report.utf8), to: url)
        return url
    }

    public func removePrivateCaseDrafts(assessmentID: UUID, checkID: String? = nil) throws {
        let directory = caseDraftsDirectory.appendingPathComponent(assessmentID.uuidString, isDirectory: true)
        if let checkID {
            guard GuidedCheckCatalog.check(checkID) != nil else { throw ResearchStorageError.unknownCheck }
            let url = directory.appendingPathComponent(checkID).appendingPathExtension("txt")
            if manager.fileExists(atPath: url.path) { try manager.removeItem(at: url) }
        } else if manager.fileExists(atPath: directory.path) {
            try manager.removeItem(at: directory)
        }
    }

    private func removePrivateFiles(for assessment: ResearchAssessment) throws {
        for base in [evidenceDirectory, caseDraftsDirectory] {
            let directory = base.appendingPathComponent(assessment.id.uuidString, isDirectory: true)
            if manager.fileExists(atPath: directory.path) { try manager.removeItem(at: directory) }
        }
    }

    public func deleteManualAssessment(_ assessment: ResearchAssessment,
                                       assessments: [ResearchAssessment]) throws {
        guard assessment.snapshotID == nil else { throw ResearchStorageError.notManualAssessment }
        try removePrivateFiles(for: assessment)
        try saveAssessments(assessments.filter { $0.id != assessment.id })
    }

    public func deleteApp(bundleID: String, snapshots: [APRSnapshot], sessions: [AuditSession],
                          assessments: [ResearchAssessment]) throws {
        for assessment in assessments where assessment.bundleID == bundleID {
            try removePrivateFiles(for: assessment)
        }
        try saveAssessments(assessments.filter { $0.bundleID != bundleID })
        try saveSessions(sessions.filter { $0.bundleID != bundleID })
        for snapshot in snapshots where snapshot.bundleID == bundleID {
            let name = snapshot.id.uuidString
            let snapshotURL = snapshotsDirectory.appendingPathComponent(name).appendingPathExtension("json")
            let reportURL = reportsDirectory.appendingPathComponent(name).appendingPathExtension("html")
            let jsonURL = reportsDirectory.appendingPathComponent(name).appendingPathExtension("json")
            if manager.fileExists(atPath: reportURL.path) { try manager.removeItem(at: reportURL) }
            if manager.fileExists(atPath: jsonURL.path) { try manager.removeItem(at: jsonURL) }
            if manager.fileExists(atPath: snapshotURL.path) { try manager.removeItem(at: snapshotURL) }
        }
    }
}

public enum ResearchStorageError: LocalizedError {
    case invalidEvidenceSize, unknownCheck, notManualAssessment

    public var errorDescription: String? {
        switch self {
        case .invalidEvidenceSize: return "Choose a non-empty evidence file smaller than 25 MB."
        case .unknownCheck: return "This guided check is not available in the current rubric."
        case .notManualAssessment: return "Only a manually created case can be deleted here."
        }
    }
}
