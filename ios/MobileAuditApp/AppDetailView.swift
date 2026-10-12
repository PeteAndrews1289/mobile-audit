import SwiftUI
import UIKit

struct AppDetailView: View {
    @EnvironmentObject private var model: AuditModel
    @Environment(\.dismiss) private var dismiss
    let bundleID: String
    @State private var sessionLabel = ""
    @State private var sessionNotes = ""
    @State private var selectedSnapshotID: UUID?
    @State private var showingDeleteConfirmation = false
    @State private var reportURL: URL?
    @State private var jsonURL: URL?
    @State private var evidenceIntegrity: EvidenceIntegrityReport?

    private var snapshots: [APRSnapshot] { model.snapshots(for: bundleID) }
    private var selected: APRSnapshot? {
        snapshots.first(where: { $0.id == selectedSnapshotID }) ?? snapshots.first
    }
    private var comparison: APRComparison? {
        guard let selected, let index = snapshots.firstIndex(where: { $0.id == selected.id }),
              index + 1 < snapshots.count else { return nil }
        return APRComparison.compare(snapshots[index + 1], selected)
    }
    private var latestSession: AuditSession? { model.latestSession(for: bundleID) }
    private var selectedAssessment: ResearchAssessment? {
        selected.flatMap { model.assessment(for: $0.id) }
    }
    private var reportRevision: String {
        "\(selected?.id.uuidString ?? "none")-\(selectedAssessment?.updatedAt.timeIntervalSince1970 ?? 0)"
    }
    private var activeSession: AuditSession? {
        model.sessions.first { $0.bundleID == bundleID && $0.endedAt == nil }
    }

    var body: some View {
        List {
            Section("Test session") {
                if let session = activeSession {
                    Text("Session in progress: \(session.label)")
                    Text("Started \(session.startedAt.formatted(date: .abbreviated, time: .shortened))")
                        .foregroundStyle(.secondary)
                    TextField("Actions and test conditions (optional)", text: $sessionNotes, axis: .vertical)
                        .lineLimit(3...6)
                    Button("Save notes") { model.saveNotes(sessionID: session.id, notes: sessionNotes) }
                    Button("Finish session") { model.finishSession(bundleID: bundleID, notes: sessionNotes) }
                } else if selected != nil {
                    TextField("What will you test?", text: $sessionLabel)
                    Button("Start session") {
                        model.startSession(bundleID: bundleID, label: sessionLabel)
                        sessionLabel = ""
                    }
                    if let session = latestSession, session.endedAt != nil {
                        Text("Latest session: \(session.label)")
                        TextField("Actions and test conditions (optional)", text: $sessionNotes, axis: .vertical)
                            .lineLimit(3...6)
                        Button("Save notes") { model.saveNotes(sessionID: session.id, notes: sessionNotes) }
                        if session.followupSnapshotID == nil {
                            Text("Export App Privacy Report again, then import this app to compare.")
                                .foregroundStyle(.secondary)
                        }
                    }
                }
                Text("Start here, use the other app, finish the session, then import a new export. Apple does not label which action caused each network contact.")
                    .font(.footnote).foregroundStyle(.secondary)
                Text("Mobile Audit stores session notes locally and omits them from shared reports.")
                    .font(.footnote).foregroundStyle(.secondary)
            }

            if let selected {
                Section("Selected snapshot") {
                    LabeledContent("Imported", value: selected.importedAt.formatted(date: .abbreviated, time: .shortened))
                    LabeledContent("Network entries", value: "\(selected.networkContacts.count)")
                    LabeledContent("Resource intervals", value: "\(selected.resourceAccesses.count)")
                    LabeledContent("Unique domains", value: "\(selected.uniqueDomains.count)")
                    if let reportURL {
                        ShareLink(item: reportURL) {
                            Label("Share this app's HTML report", systemImage: "square.and.arrow.up")
                        }
                    }
                    if let jsonURL {
                        ShareLink(item: jsonURL) {
                            Label("Share evidence JSON", systemImage: "curlybraces")
                        }
                    }
                    Text("Review the report before sharing; selected-app domains may be sensitive.")
                        .font(.footnote).foregroundStyle(.secondary)
                }

                Section("Security assessment") {
                    let grade = AssessmentGrader.grade(selectedAssessment, evidenceIntegrity: evidenceIntegrity)
                    Text(grade.label).font(.headline)
                    Text("\(grade.completedChecks)/\(grade.applicableChecks) applicable guided checks completed · \(grade.coveragePercent)% coverage")
                        .font(.subheadline).foregroundStyle(.secondary)
                    if let evidenceIntegrity, !evidenceIntegrity.issues.isEmpty {
                        Text("Some attached evidence files are missing or changed. Open the guided assessment to review them.")
                            .font(.footnote).foregroundStyle(.orange)
                    }
                    if selectedAssessment == nil {
                        Button("Start guided assessment") {
                            model.startAssessment(for: selected, iOSVersion: UIDevice.current.systemVersion)
                        }
                    } else if let selectedAssessment {
                        NavigationLink("Open guided assessment") {
                            ResearchAssessmentView(assessmentID: selectedAssessment.id)
                        }
                    }
                    Text("A letter grade requires documented physical-iPhone tests. Outcomes you record are provisional and are not automatically verified by Mobile Audit.")
                        .font(.footnote).foregroundStyle(.secondary)
                }

                let vectors = AttackVectorEngine.vectors(for: selectedAssessment,
                                                         evidenceIntegrity: evidenceIntegrity)
                Section("Potential attack vectors") {
                    if vectors.isEmpty {
                        Text("No app-specific attack vector recorded yet. Guided checks can turn a test result into an evidence-linked vector.")
                            .foregroundStyle(.secondary)
                    }
                    ForEach(vectors) { vector in
                        VStack(alignment: .leading, spacing: 5) {
                            Text(vector.title).font(.headline)
                            Text(vector.state.label).font(.subheadline).foregroundStyle(.orange)
                            Text("Entry point: \(vector.entryPoint)")
                            Text("Attacker control: \(vector.attackerControl)")
                            Text("Possible attack path: \(vector.attackScenario)")
                            Text("Possible impact: \(vector.possibleImpact)")
                            Text("Observed: \(vector.observed.isEmpty ? "No observation recorded" : vector.observed)")
                                .foregroundStyle(.secondary)
                            Text("Next: \(vector.nextStep)").font(.footnote)
                            if !vector.evidenceLines.isEmpty {
                                Text("Export lines: \(vector.evidenceLines.map(String.init).joined(separator: ", "))")
                                    .font(.caption).foregroundStyle(.tertiary)
                            }
                            if !vector.evidenceHashes.isEmpty {
                                Text("\(vector.evidenceHashes.count) attached evidence file(s); hashes appear in the report.")
                                    .font(.caption).foregroundStyle(.tertiary)
                            }
                        }
                        .padding(.vertical, 3)
                    }
                }

                if let session = model.sessions.first(where: { $0.followupSnapshotID == selected.id }),
                   let sessionComparison = model.sessionComparison(session) {
                    ComparisonSection(title: "Session: \(session.label)", comparison: sessionComparison)
                } else if let comparison {
                    ComparisonSection(title: "Since prior export", comparison: comparison)
                }

                let leads = ReviewEngine.leads(for: selected, comparison: comparison)
                Section("Things to review") {
                    if leads.isEmpty {
                        Text("No review prompts from this export. This does not establish that the app is safe.")
                            .foregroundStyle(.secondary)
                    }
                    ForEach(leads) { lead in
                        VStack(alignment: .leading, spacing: 6) {
                            Text(lead.title).font(.headline)
                            Text(lead.observed)
                            Text(lead.whyItMatters).foregroundStyle(.secondary)
                            Text("Next check: \(lead.nextStep)").font(.footnote)
                            Text("Evidence: export line(s) \(lead.evidenceLines.map(String.init).joined(separator: ", "))")
                                .font(.caption).foregroundStyle(.tertiary)
                        }
                        .padding(.vertical, 3)
                    }
                    Text("These are prompts for further testing, not confirmed vulnerabilities.")
                        .font(.footnote).foregroundStyle(.secondary)
                }

                Section("Network activity") {
                    if selected.networkContacts.isEmpty {
                        Text("No network entries in this export.").foregroundStyle(.secondary)
                    }
                    ForEach(selected.networkContacts) { contact in
                        VStack(alignment: .leading, spacing: 5) {
                            Text(contact.domain).font(.headline).textSelection(.enabled)
                            Text("\(contact.reportedContacts) reported contact(s) · last seen \(contact.lastSeenAt.formatted(date: .abbreviated, time: .shortened))")
                                .font(.subheadline).foregroundStyle(.secondary)
                            if contact.domainType == 1 {
                                Text("Apple flags this domain as potentially used for cross-app or cross-site profiling. This does not show what data was sent.")
                                    .font(.footnote).foregroundStyle(.orange)
                            }
                            Text("Export line \(contact.sourceLine)")
                                .font(.caption).foregroundStyle(.tertiary)
                        }
                        .padding(.vertical, 2)
                    }
                }

                Section("Sensitive resource access") {
                    if selected.resourceAccesses.isEmpty {
                        Text("No resource access recorded for this app in this export.")
                            .foregroundStyle(.secondary)
                    }
                    ForEach(selected.resourceAccesses) { access in
                        VStack(alignment: .leading, spacing: 5) {
                            Text(access.category).font(.headline)
                            Text(access.observedAt.formatted(date: .abbreviated, time: .shortened))
                                .font(.subheadline).foregroundStyle(.secondary)
                            if !access.isComplete {
                                Text("Incomplete access interval").font(.footnote).foregroundStyle(.orange)
                            }
                            Text("Export lines \(access.sourceLines.map(String.init).joined(separator: ", "))")
                                .font(.caption).foregroundStyle(.tertiary)
                        }
                    }
                }

                if selected.skippedSelectedRecords > 0 {
                    Section("Import note") {
                        Text("\(selected.skippedSelectedRecords) selected-app record(s) had invalid fields and were skipped.")
                    }
                }

                Section("Limits") {
                    Text("This export does not reveal request bodies, private app files, or whether an observed connection is exploitable.")
                    Text("Contact counts cover Apple's rolling reporting period. A count change between exports is not a per-session request count.")
                }

                Section("Saved exports") {
                    ForEach(snapshots) { item in
                        Button {
                            selectedSnapshotID = item.id
                        } label: {
                            HStack {
                                Text(item.importedAt.formatted(date: .abbreviated, time: .shortened))
                                Spacer()
                                if item.id == selected.id { Image(systemName: "checkmark") }
                            }
                        }
                    }
                }

                Section("Data on this device") {
                    Button("Delete all saved data for this app", role: .destructive) {
                        showingDeleteConfirmation = true
                    }
                }
            }
        }
        .navigationTitle(bundleID)
        .navigationBarTitleDisplayMode(.inline)
        .task(id: latestSession?.id) {
            sessionNotes = latestSession?.notes ?? ""
        }
        .task(id: reportRevision) {
            reportURL = nil
            jsonURL = nil
            evidenceIntegrity = model.evidenceIntegrity(for: selectedAssessment)
            if let selected {
                do {
                    reportURL = try model.shareableReport(for: selected)
                    jsonURL = try model.shareableJSONReport(for: selected)
                } catch { model.errorMessage = "A report could not be created: \(error.localizedDescription)" }
            }
        }
        .confirmationDialog("Delete saved data for \(bundleID)?", isPresented: $showingDeleteConfirmation) {
            Button("Delete saved data", role: .destructive) {
                if model.deleteApp(bundleID) { dismiss() }
            }
        } message: {
            Text("This removes snapshots, assessments, attached research evidence, session notes, and generated reports from Mobile Audit. The original Apple export in Files stays where you saved it.")
        }
    }
}

private struct ComparisonSection: View {
    let title: String
    let comparison: APRComparison

    var body: some View {
        Section(title) {
            if comparison.newDomains.isEmpty && comparison.absentDomains.isEmpty &&
                comparison.countChanges.isEmpty && comparison.newResourceCategories.isEmpty {
                Text("No domain or resource-category changes in these exports.")
                    .foregroundStyle(.secondary)
            }
            ForEach(comparison.newDomains, id: \.self) { domain in
                Label("Newly listed: \(domain)", systemImage: "plus.circle")
            }
            ForEach(comparison.absentDomains, id: \.self) { domain in
                Label("No longer listed: \(domain)", systemImage: "minus.circle")
            }
            ForEach(comparison.countChanges) { change in
                Text("\(change.domain): reported contacts \(change.before) → \(change.after)")
            }
            ForEach(comparison.newResourceCategories, id: \.self) { category in
                Label("New resource category: \(category)", systemImage: "plus.circle")
            }
            Text("These are differences between rolling seven-day reports. They do not prove that a session caused the changes.")
                .font(.footnote).foregroundStyle(.secondary)
        }
    }
}
