import SwiftUI
import UniformTypeIdentifiers

struct ResearchAssessmentView: View {
    @EnvironmentObject private var model: AuditModel
    @Environment(\.dismiss) private var dismiss
    let assessmentID: UUID
    @State private var appVersion = ""
    @State private var iOSVersion = ""
    @State private var scope = ""
    @State private var evidenceIntegrity: EvidenceIntegrityReport?
    @State private var showingDeleteConfirmation = false

    private var assessment: ResearchAssessment? { model.assessment(id: assessmentID) }
    private var grade: AssessmentGrade {
        AssessmentGrader.grade(assessment, evidenceIntegrity: evidenceIntegrity)
    }

    var body: some View {
        List {
            Section("Security grade") {
                Text(grade.label).font(.title2.bold())
                Text("\(grade.completedChecks) of \(grade.applicableChecks) applicable checks completed · \(grade.coveragePercent)% coverage")
                if !grade.issues.isEmpty {
                    ForEach(grade.issues, id: \.self) { issue in
                        Text(issue).font(.footnote).foregroundStyle(.secondary)
                    }
                }
                if !grade.rationale.isEmpty {
                    Text("Why this grade").font(.subheadline.bold())
                    ForEach(grade.rationale, id: \.self) { reason in
                        Text(reason).font(.footnote).foregroundStyle(.secondary)
                    }
                }
                if let evidenceIntegrity, evidenceIntegrity.checkedCount > 0 {
                    Text("\(evidenceIntegrity.verifiedIDs.count) of \(evidenceIntegrity.checkedCount) attached evidence files match their saved hashes.")
                        .font(.footnote).foregroundStyle(.secondary)
                }
                Text("Grades are provisional and based on researcher-recorded outcomes. Mobile Audit cannot watch another app or independently verify your observations.")
                    .font(.footnote).foregroundStyle(.secondary)
            }

            Section("Assessment details") {
                LabeledContent("App", value: assessment?.displayName ?? "Unknown")
                if let bundleID = assessment?.bundleID, !bundleID.isEmpty {
                    LabeledContent("Bundle ID", value: bundleID)
                }
                if assessment?.snapshotID == nil {
                    Text("No App Privacy Report is attached to this case. You can record tests and evidence for this app directly.")
                        .font(.footnote).foregroundStyle(.secondary)
                }
                TextField("App version", text: $appVersion)
                    .textInputAutocapitalization(.never)
                TextField("iOS version", text: $iOSVersion)
                    .textInputAutocapitalization(.never)
                TextField("Test scope and accounts used (no account IDs)", text: $scope, axis: .vertical)
                    .lineLimit(2...5)
                Button("Save assessment details") {
                    model.saveAssessmentMetadata(assessmentID: assessmentID, appVersion: appVersion,
                                                 iOSVersion: iOSVersion, scope: scope)
                }
                Text("The scope stays on this device. Shared reports state only whether it was recorded.")
                    .font(.footnote).foregroundStyle(.secondary)
            }

            if assessment?.rubricVersion == GuidedCheckCatalog.rubricVersion {
                Section("Guided checks") {
                    ForEach(GuidedCheckCatalog.checks, id: \.id) { check in
                        NavigationLink {
                            GuidedCheckView(assessmentID: assessmentID, checkID: check.id)
                        } label: {
                            VStack(alignment: .leading, spacing: 4) {
                                Text(check.title).font(.headline)
                                Text("\(check.category) · \(assessment?.record(for: check.id).status.label ?? "Not run")")
                                    .font(.subheadline).foregroundStyle(.secondary)
                            }
                        }
                    }
                }
            } else {
                Section("Guided checks") {
                    Text("This assessment uses an older rubric. Start a new assessment before assigning a grade.")
                        .foregroundStyle(.secondary)
                }
            }

            Section("Using a physical iPhone") {
                Text("Read one check, switch to the app you are testing, perform the steps with accounts and data you control, then return here to record the outcome. Link checks can open a URL through iOS.")
                Text("Mark a feature not present only with a reason. Mark a possible issue as confirmed only after reproducing a security impact and attaching evidence.")
            }
            if assessment?.snapshotID == nil {
                Section("Private case") {
                    Button("Delete this research case", role: .destructive) {
                        showingDeleteConfirmation = true
                    }
                    Text("This also removes its attached evidence and private report drafts from Mobile Audit.")
                        .font(.footnote).foregroundStyle(.secondary)
                }
            }
        }
        .navigationTitle("Research assessment")
        .navigationBarTitleDisplayMode(.inline)
        .task(id: assessmentID) {
            appVersion = assessment?.appVersion ?? ""
            iOSVersion = assessment?.iOSVersion ?? ""
            scope = assessment?.scope ?? ""
        }
        .task(id: assessment?.updatedAt) {
            evidenceIntegrity = model.evidenceIntegrity(for: assessment)
        }
        .confirmationDialog("Delete this private research case?", isPresented: $showingDeleteConfirmation) {
            Button("Delete research case", role: .destructive) {
                if model.deleteManualAssessment(id: assessmentID) { dismiss() }
            }
        }
    }
}

private struct GuidedCheckView: View {
    @EnvironmentObject private var model: AuditModel
    @Environment(\.openURL) private var openURL
    let assessmentID: UUID
    let checkID: String
    @State private var draft: ResearchCheckRecord
    @State private var lineText = ""
    @State private var showingEvidenceImporter = false

    init(assessmentID: UUID, checkID: String) {
        self.assessmentID = assessmentID
        self.checkID = checkID
        _draft = State(initialValue: ResearchCheckRecord(id: checkID))
    }

    private var check: GuidedCheck { GuidedCheckCatalog.check(checkID)! }
    private var assessment: ResearchAssessment? { model.assessment(id: assessmentID) }

    var body: some View {
        Form {
            Section("Test setup") {
                Text("Feature needed: \(check.featureNeeded)")
                ForEach(Array(check.steps.enumerated()), id: \.offset) { index, step in
                    Text("\(index + 1). \(step)")
                }
                Text("Expected protection: \(check.expectedProtection)")
                    .foregroundStyle(.secondary)
            }

            if check.category == "Links" {
                Section("Open a test link") {
                    TextField("https://… or app-scheme://…", text: $draft.testURL)
                        .textInputAutocapitalization(.never)
                        .keyboardType(.URL)
                    Button("Open link through iOS") {
                        guard let url = URL(string: draft.testURL),
                              let scheme = url.scheme?.lowercased(),
                              !["file", "data", "javascript"].contains(scheme) else {
                            model.errorMessage = "Enter an HTTP, HTTPS, or app link."
                            return
                        }
                        openURL(url)
                    }
                    Text("The link stays on this device and is omitted from shared reports. Mobile Audit cannot see what the target app does after it opens.")
                        .font(.footnote).foregroundStyle(.secondary)
                }
            }

            Section("Record the result") {
                Picker("Outcome", selection: $draft.status) {
                    ForEach(ResearchCheckStatus.allCases, id: \.self) { status in
                        Text(status.label).tag(status)
                    }
                }
                TextField(draft.status == .notApplicable ? "Why is this feature absent?" : "What did you observe? (shareable summary)",
                          text: $draft.summary, axis: .vertical)
                    .lineLimit(3...7)
                if draft.status == .passed || draft.status == .confirmed || draft.status == .concern {
                    Stepper("Repeated trials: \(draft.trials)", value: $draft.trials, in: 0...20)
                }
                if draft.status == .confirmed {
                    Picker("Impact", selection: $draft.severity) {
                        Text("Choose severity").tag(ResearchSeverity?.none)
                        ForEach(ResearchSeverity.allCases, id: \.self) { severity in
                            Text(severity.label).tag(ResearchSeverity?.some(severity))
                        }
                    }
                    TextField("Security impact demonstrated (shareable summary)", text: $draft.impact,
                              axis: .vertical).lineLimit(3...7)
                }
                if assessment?.snapshotID != nil {
                    TextField("App Privacy Report line numbers, if relevant", text: $lineText)
                        .keyboardType(.numbersAndPunctuation)
                    Text("Only line numbers from this app's selected export are accepted.")
                        .font(.footnote).foregroundStyle(.secondary)
                }
                Text("Do not put passwords or private account values in shareable summaries.")
                    .font(.footnote).foregroundStyle(.secondary)
                Button("Save result") { _ = saveDraft() }
            }

            Section("Investigate a possible new vulnerability") {
                NavigationLink("Private reproducer and report draft") {
                    PrivateCaseView(assessmentID: assessmentID, checkID: checkID)
                }
                Text("Record exact steps, expected and observed behavior, attacker control, and prior reports. These notes are kept out of the public assessment report.")
                    .font(.footnote).foregroundStyle(.secondary)
            }

            Section("Private evidence files") {
                Button("Attach screenshot or other evidence") {
                    if saveDraft() { showingEvidenceImporter = true }
                }
                if draft.evidence.isEmpty {
                    Text("No evidence file attached.").foregroundStyle(.secondary)
                }
                ForEach(draft.evidence) { evidence in
                    VStack(alignment: .leading, spacing: 4) {
                        Text(evidence.displayName).font(.subheadline)
                        Text("SHA-256 \(evidence.sha256)").font(.caption).foregroundStyle(.secondary)
                            .textSelection(.enabled)
                        Button("Remove file", role: .destructive) {
                            model.removeEvidence(assessmentID: assessmentID, checkID: checkID, evidenceID: evidence.id)
                            loadDraft()
                        }
                    }
                }
                Text("Files stay in Mobile Audit on this device. Shared reports include only their hashes, not the files or original names. Review the report before sharing.")
                    .font(.footnote).foregroundStyle(.secondary)
            }

            Section("Potential attack vector") {
                LabeledContent("Entry point", value: check.entryPoint)
                LabeledContent("Attacker control", value: check.attackerControl)
                Text("Possible attack path: \(check.attackScenario)")
                LabeledContent("Boundary", value: check.securityBoundary)
                Text("Possible impact: \(check.possibleImpact)")
                Text("Next check: \(check.nextStep)").foregroundStyle(.secondary)
            }
        }
        .navigationTitle(check.title)
        .navigationBarTitleDisplayMode(.inline)
        .task(id: checkID) { loadDraft() }
        .fileImporter(isPresented: $showingEvidenceImporter,
                      allowedContentTypes: [.image, .movie, .pdf, .plainText, .data]) { result in
            switch result {
            case .success(let url):
                model.attachEvidence(assessmentID: assessmentID, checkID: checkID, file: url)
                loadDraft()
            case .failure(let error):
                model.errorMessage = error.localizedDescription
            }
        }
    }

    private func loadDraft() {
        draft = assessment?.record(for: checkID) ?? ResearchCheckRecord(id: checkID)
        lineText = draft.evidenceLines.map(String.init).joined(separator: ", ")
    }

    private func saveDraft() -> Bool {
        if assessment?.snapshotID == nil {
            lineText = ""
        }
        let parts = lineText.split(whereSeparator: { $0 == "," || $0.isWhitespace })
        let parsed = parts.compactMap { Int($0) }
        guard parsed.count == parts.count, parsed.allSatisfy({ $0 > 0 }) else {
            model.errorMessage = "Use positive App Privacy Report line numbers separated by commas."
            return false
        }
        draft.evidenceLines = Array(Set(parsed)).sorted()
        draft.privateCase = assessment?.record(for: checkID).privateCase
        return model.saveCheck(assessmentID: assessmentID, record: draft)
    }
}

private struct PrivateCaseView: View {
    @EnvironmentObject private var model: AuditModel
    let assessmentID: UUID
    let checkID: String
    @State private var notes = PrivateCaseNotes()
    @State private var evidenceIntegrity: EvidenceIntegrityReport?
    @State private var draftURL: URL?

    private var assessment: ResearchAssessment? { model.assessment(id: assessmentID) }
    private var readiness: CaseReadiness? {
        guard let assessment else { return nil }
        var record = assessment.record(for: checkID)
        record.privateCase = notes
        return CaseReadiness.review(assessment, record: record, evidenceIntegrity: evidenceIntegrity)
    }

    var body: some View {
        Form {
            Section("Private reproduction notes") {
                TextField("Account state and prerequisites", text: $notes.preconditions, axis: .vertical)
                    .lineLimit(2...5)
                TextField("Numbered steps, one per line", text: $notes.steps, axis: .vertical)
                    .lineLimit(5...12)
                TextField("What should have happened?", text: $notes.expected, axis: .vertical)
                    .lineLimit(2...5)
                TextField("What actually happened?", text: $notes.observed, axis: .vertical)
                    .lineLimit(2...5)
                TextField("What could an attacker control?", text: $notes.attackerControl, axis: .vertical)
                    .lineLimit(2...5)
                TextField("Related advisories or possible duplicates checked", text: $notes.priorArt,
                          axis: .vertical).lineLimit(2...5)
                Button("Save private notes") { _ = saveNotes() }
                Text("These exact notes stay on this device and are omitted from public HTML and evidence JSON. Use test accounts and redact personal data in any draft you share.")
                    .font(.footnote).foregroundStyle(.secondary)
            }

            Section("Ready for independent review") {
                if readiness?.readyForPrivateReview == true {
                    Text("The recorded case has the minimum details for another researcher to review. Its impact has not been independently verified.")
                } else {
                    ForEach(readiness?.issues ?? [], id: \.self) { issue in
                        Text(issue).font(.footnote).foregroundStyle(.secondary)
                    }
                }
            }

            Section("Private report draft") {
                Button("Prepare draft") {
                    guard saveNotes() else { return }
                    do {
                        draftURL = try model.privateCaseDraft(assessmentID: assessmentID, checkID: checkID)
                    } catch {
                        model.errorMessage = "Private draft could not be created: \(error.localizedDescription)"
                    }
                }
                if let draftURL {
                    ShareLink(item: draftURL) {
                        Label("Share private draft", systemImage: "square.and.arrow.up")
                    }
                }
                Text("The draft includes exact reproduction notes and may contain sensitive test details. Review it before sharing with a developer or reviewer. Mobile Audit never submits it automatically.")
                    .font(.footnote).foregroundStyle(.secondary)
            }
        }
        .navigationTitle("Private case")
        .navigationBarTitleDisplayMode(.inline)
        .task(id: assessmentID) {
            notes = assessment?.record(for: checkID).privateCase ?? PrivateCaseNotes()
            evidenceIntegrity = model.evidenceIntegrity(for: assessment)
        }
        .task(id: assessment?.updatedAt) {
            evidenceIntegrity = model.evidenceIntegrity(for: assessment)
        }
        .onChange(of: notes) { _, _ in draftURL = nil }
    }

    private func saveNotes() -> Bool {
        let saved = model.savePrivateCaseNotes(assessmentID: assessmentID, checkID: checkID, notes: notes)
        if saved {
            evidenceIntegrity = model.evidenceIntegrity(for: assessment)
            draftURL = nil
        }
        return saved
    }
}
