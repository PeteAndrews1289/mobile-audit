import Foundation

public struct APRAppOverview: Identifiable, Hashable, Sendable {
    public let bundleID: String
    public let networkEntries: Int
    public let accessEvents: Int

    public var id: String { bundleID }

    public init(bundleID: String, networkEntries: Int, accessEvents: Int) {
        self.bundleID = bundleID
        self.networkEntries = networkEntries
        self.accessEvents = accessEvents
    }
}

public struct APRIndex: Sendable {
    public let artifactSHA256: String
    public let apps: [APRAppOverview]

    public init(artifactSHA256: String, apps: [APRAppOverview]) {
        self.artifactSHA256 = artifactSHA256
        self.apps = apps
    }
}

public struct NetworkContact: Codable, Identifiable, Sendable {
    public let sourceLine: Int
    public let domain: String
    public let firstSeenAt: Date
    public let lastSeenAt: Date
    public let reportedContacts: Int
    public let initiatedType: String?
    public let domainType: Int?
    public let domainOwner: String?

    public var id: String { "network-\(sourceLine)" }

    public init(sourceLine: Int, domain: String, firstSeenAt: Date, lastSeenAt: Date,
                reportedContacts: Int, initiatedType: String?, domainType: Int?, domainOwner: String?) {
        self.sourceLine = sourceLine
        self.domain = domain
        self.firstSeenAt = firstSeenAt
        self.lastSeenAt = lastSeenAt
        self.reportedContacts = reportedContacts
        self.initiatedType = initiatedType
        self.domainType = domainType
        self.domainOwner = domainOwner
    }
}

public struct ResourceAccess: Codable, Identifiable, Sendable {
    public let category: String
    public let startedAt: Date?
    public let endedAt: Date?
    public let sourceLines: [Int]

    public var id: String { "access-\(sourceLines.map(String.init).joined(separator: "-"))" }
    public var isComplete: Bool { startedAt != nil && endedAt != nil }
    public var observedAt: Date { startedAt ?? endedAt ?? .distantPast }

    public init(category: String, startedAt: Date?, endedAt: Date?, sourceLines: [Int]) {
        self.category = category
        self.startedAt = startedAt
        self.endedAt = endedAt
        self.sourceLines = sourceLines.sorted()
    }
}

public struct APRSnapshot: Codable, Identifiable, Sendable {
    public let id: UUID
    public let bundleID: String
    public let importedAt: Date
    public let artifactSHA256: String
    public let networkContacts: [NetworkContact]
    public let resourceAccesses: [ResourceAccess]
    public let skippedSelectedRecords: Int

    public var uniqueDomains: [String] {
        Array(Set(networkContacts.map(\.domain))).sorted()
    }

    public init(id: UUID = UUID(), bundleID: String, importedAt: Date = Date(), artifactSHA256: String,
                networkContacts: [NetworkContact], resourceAccesses: [ResourceAccess], skippedSelectedRecords: Int) {
        self.id = id
        self.bundleID = bundleID
        self.importedAt = importedAt
        self.artifactSHA256 = artifactSHA256
        self.networkContacts = networkContacts
        self.resourceAccesses = resourceAccesses
        self.skippedSelectedRecords = skippedSelectedRecords
    }
}

public struct AuditSession: Codable, Identifiable, Sendable {
    public let id: UUID
    public let bundleID: String
    public let label: String
    public var notes: String?
    public let startedAt: Date
    public var endedAt: Date?
    public let baselineSnapshotID: UUID
    public var followupSnapshotID: UUID?

    public init(id: UUID = UUID(), bundleID: String, label: String, notes: String? = nil, startedAt: Date = Date(),
                endedAt: Date? = nil, baselineSnapshotID: UUID, followupSnapshotID: UUID? = nil) {
        self.id = id
        self.bundleID = bundleID
        self.label = label
        self.notes = notes
        self.startedAt = startedAt
        self.endedAt = endedAt
        self.baselineSnapshotID = baselineSnapshotID
        self.followupSnapshotID = followupSnapshotID
    }
}

public enum APRImportError: LocalizedError, Sendable {
    case fileTooLarge
    case lineTooLarge(Int)
    case tooManyRecords
    case invalidJSON(Int)
    case noEntries(String)
    case unreadableFile

    public var errorDescription: String? {
        switch self {
        case .fileTooLarge: return "The export exceeds the 256 MB import limit."
        case .lineTooLarge(let line): return "Export line \(line) exceeds the size limit."
        case .tooManyRecords: return "The export contains too many records."
        case .invalidJSON(let line): return "The export is not valid NDJSON at line \(line)."
        case .noEntries(let bundleID): return "No usable activity was found for \(bundleID)."
        case .unreadableFile: return "The selected export could not be read. Try saving it to Files first."
        }
    }
}
