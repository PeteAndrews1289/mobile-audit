import Foundation

public struct ContactCountChange: Identifiable, Sendable {
    public let domain: String
    public let before: Int
    public let after: Int

    public var id: String { domain }
}

public struct APRComparison: Sendable {
    public let earlier: APRSnapshot
    public let later: APRSnapshot
    public let newDomains: [String]
    public let absentDomains: [String]
    public let countChanges: [ContactCountChange]
    public let newResourceCategories: [String]
    public let absentResourceCategories: [String]

    public static func compare(_ earlier: APRSnapshot, _ later: APRSnapshot) -> APRComparison? {
        guard earlier.bundleID == later.bundleID else { return nil }
        func counts(_ snapshot: APRSnapshot) -> [String: Int] {
            var result: [String: Int] = [:]
            for contact in snapshot.networkContacts {
                result[contact.domain, default: 0] += contact.reportedContacts
            }
            return result
        }
        let earlierCounts = counts(earlier)
        let laterCounts = counts(later)
        let earlierDomains = Set(earlierCounts.keys)
        let laterDomains = Set(laterCounts.keys)
        let changed = earlierDomains.intersection(laterDomains).compactMap { domain -> ContactCountChange? in
            let before = earlierCounts[domain] ?? 0
            let after = laterCounts[domain] ?? 0
            return before == after ? nil : ContactCountChange(domain: domain, before: before, after: after)
        }.sorted { $0.domain < $1.domain }
        let earlierResources = Set(earlier.resourceAccesses.map(\.category))
        let laterResources = Set(later.resourceAccesses.map(\.category))
        return APRComparison(
            earlier: earlier,
            later: later,
            newDomains: laterDomains.subtracting(earlierDomains).sorted(),
            absentDomains: earlierDomains.subtracting(laterDomains).sorted(),
            countChanges: changed,
            newResourceCategories: laterResources.subtracting(earlierResources).sorted(),
            absentResourceCategories: earlierResources.subtracting(laterResources).sorted()
        )
    }
}
