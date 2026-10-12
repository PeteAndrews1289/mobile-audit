import Foundation

/// A prompt for further investigation, not a vulnerability finding.
public struct ReviewLead: Identifiable, Sendable {
    public let id: String
    public let title: String
    public let observed: String
    public let whyItMatters: String
    public let nextStep: String
    public let evidenceLines: [Int]

    public init(id: String, title: String, observed: String, whyItMatters: String,
                nextStep: String, evidenceLines: [Int]) {
        self.id = id
        self.title = title
        self.observed = observed
        self.whyItMatters = whyItMatters
        self.nextStep = nextStep
        self.evidenceLines = evidenceLines.sorted()
    }
}

public enum ReviewEngine {
    public static func leads(for snapshot: APRSnapshot, comparison: APRComparison? = nil) -> [ReviewLead] {
        var result: [ReviewLead] = []

        let trackingContacts = Dictionary(grouping: snapshot.networkContacts.filter { $0.domainType == 1 },
                                          by: { $0.domain })
        for domain in trackingContacts.keys.sorted() {
            let lines = trackingContacts[domain, default: []].map(\.sourceLine)
            result.append(ReviewLead(
                id: "tracking-\(domain)",
                title: "Potential tracking domain contacted",
                observed: "Apple's report marks \(domain) as potentially used for cross-app or cross-site profiling.",
                whyItMatters: "This may warrant a privacy review. The export does not show identifiers or other data sent to this domain.",
                nextStep: "Check whether the contact fits the feature you used. Repeat a focused session or inspect authorized network traffic to learn what was sent.",
                evidenceLines: lines
            ))
        }

        let accessGroups = Dictionary(grouping: snapshot.resourceAccesses, by: { $0.category })
        for category in accessGroups.keys.sorted() {
            let accesses = accessGroups[category, default: []]
            result.append(ReviewLead(
                id: "resource-\(category)",
                title: "Sensitive resource accessed: \(category)",
                observed: "The export contains \(accesses.count) \(category) access interval(s) for this app.",
                whyItMatters: "Unexpected access could expose personal information. This record does not show what the app read, stored, or transmitted.",
                nextStep: "Compare the timing with actions you took and permission prompts. Repeat the workflow with access allowed and denied if you control the test device.",
                evidenceLines: accesses.flatMap(\.sourceLines)
            ))
        }

        if let comparison, !comparison.newDomains.isEmpty {
            let domains = Set(comparison.newDomains)
            let lines = snapshot.networkContacts.filter { domains.contains($0.domain) }.map(\.sourceLine)
            result.append(ReviewLead(
                id: "new-domains",
                title: "Newly listed network destinations",
                observed: "\(comparison.newDomains.count) domain(s) appear in this export but not the earlier one: \(comparison.newDomains.joined(separator: ", ")).",
                whyItMatters: "A new destination may reflect different app behavior or movement within Apple's rolling reporting period. It does not establish what data was sent.",
                nextStep: "Repeat the workflow with a fresh baseline and investigate unexpected destinations using an authorized network capture.",
                evidenceLines: lines
            ))
        }

        return result
    }
}
