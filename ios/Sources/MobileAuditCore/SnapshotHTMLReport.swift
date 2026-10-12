import Foundation

public enum SnapshotHTMLReport {
    private static func escape(_ value: String) -> String {
        value.replacingOccurrences(of: "&", with: "&amp;")
            .replacingOccurrences(of: "<", with: "&lt;")
            .replacingOccurrences(of: ">", with: "&gt;")
            .replacingOccurrences(of: "\"", with: "&quot;")
            .replacingOccurrences(of: "'", with: "&#39;")
    }

    private static func stamp(_ date: Date) -> String {
        ISO8601DateFormatter().string(from: date)
    }

    public static func render(_ snapshot: APRSnapshot, comparison: APRComparison?, session: AuditSession? = nil,
                              assessment: ResearchAssessment? = nil,
                              evidenceIntegrity: EvidenceIntegrityReport? = nil) -> String {
        let leads = ReviewEngine.leads(for: snapshot, comparison: comparison)
        let grade = AssessmentGrader.grade(assessment, evidenceIntegrity: evidenceIntegrity)
        let vectors = AttackVectorEngine.vectors(for: assessment, evidenceIntegrity: evidenceIntegrity)
        let appVersion = assessment?.appVersion ?? ""
        let iOSVersion = assessment?.iOSVersion ?? ""
        let gradeIssues = grade.issues.map { "<li>\(escape($0))</li>" }.joined()
        let gradeRationale = grade.rationale.map { "<li>\(escape($0))</li>" }.joined()
        let evidenceStatus: String
        if evidenceIntegrity?.checkedCount == 0 || assessment == nil {
            evidenceStatus = "No research evidence files are attached."
        } else if let evidenceIntegrity {
            evidenceStatus = evidenceIntegrity.issues.isEmpty
                ? "\(evidenceIntegrity.verifiedIDs.count) attached evidence file(s) matched their saved SHA-256 hashes."
                : "At least one attached evidence file is missing, changed, or unreadable; it cannot support a grade or reproduced-impact vector."
        } else {
            evidenceStatus = "Attached evidence file integrity was not checked."
        }
        let checkRows: String
        if let assessment, assessment.rubricVersion == GuidedCheckCatalog.rubricVersion {
            checkRows = GuidedCheckCatalog.checks.map { definition in
                let record = assessment.record(for: definition.id)
                let verifiedCount = evidenceIntegrity?.verifiedEvidence(in: record).count ?? 0
                return "<tr><td>\(escape(definition.category))</td><td>\(escape(definition.title))</td><td>\(escape(record.status.label))</td><td>\(record.trials)</td><td>\(verifiedCount)</td></tr>"
            }.joined()
        } else {
            checkRows = ""
        }
        let assessmentHTML = """
        <h2>Security grade</h2>
        <div class="notice"><strong>\(escape(grade.label))</strong> · \(grade.completedChecks)/\(grade.applicableChecks) applicable guided checks completed (\(grade.coveragePercent)% coverage).</div>
        <p>Rubric \(escape(assessment?.rubricVersion ?? GuidedCheckCatalog.rubricVersion)) · App version \(escape(appVersion.isEmpty ? "not recorded" : appVersion)) · iOS \(escape(iOSVersion.isEmpty ? "not recorded" : iOSVersion)) · Assessment updated \(escape(assessment.map { stamp($0.updatedAt) } ?? "not started"))</p>
        <p>Guided check outcomes are recorded by the researcher on a physical iPhone. Mobile Audit does not independently verify actions in another app. A letter grade is provisional and covers the stated test scope.</p>
        <p>Evidence integrity: \(escape(evidenceStatus)) This check verifies saved bytes, not whether a file proves a security impact.</p>
        \(gradeIssues.isEmpty ? "" : "<p>Needed before grading:</p><ul>\(gradeIssues)</ul>")
        \(gradeRationale.isEmpty ? "" : "<p>Why this grade:</p><ul>\(gradeRationale)</ul>")
        \(checkRows.isEmpty ? "" : "<h3>Guided check coverage</h3><table><thead><tr><th>Area</th><th>Check</th><th>Recorded outcome</th><th>Trials</th><th>Verified files</th></tr></thead><tbody>\(checkRows)</tbody></table>")
        """
        let vectorHTML = vectors.isEmpty ?
            "<p>No app-specific attack vector has been recorded. Start the guided assessment to investigate possible entry points.</p>" :
            vectors.map { vector in
                let lines = vector.evidenceLines.isEmpty ? "None linked" : vector.evidenceLines.map(String.init).joined(separator: ", ")
                let hashes = vector.evidenceHashes.isEmpty ? "None attached" : vector.evidenceHashes.joined(separator: ", ")
                return """
                <article><p class="tag">\(escape(vector.state.label))\(vector.severity.map { " · \(escape($0.label)) severity" } ?? "")</p>
                <h3>\(escape(vector.title))</h3>
                <p><strong>Entry point:</strong> \(escape(vector.entryPoint))</p>
                <p><strong>Attacker control:</strong> \(escape(vector.attackerControl))</p>
                <p><strong>Possible attack path:</strong> \(escape(vector.attackScenario))</p>
                <p><strong>Prerequisites:</strong> \(escape(vector.prerequisites))</p>
                <p><strong>Security boundary:</strong> \(escape(vector.securityBoundary))</p>
                <p><strong>\(vector.state == .confirmed ? "Researcher-reported impact" : "Possible impact"):</strong> \(escape(vector.possibleImpact))</p>
                <p><strong>Observed:</strong> \(escape(vector.observed.isEmpty ? "No observation recorded" : vector.observed))</p>
                <p><strong>Evidence:</strong> export lines \(escape(lines)); attached file SHA-256 \(escape(hashes))</p>
                <p><strong>Next step:</strong> \(escape(vector.nextStep))</p></article>
                """
            }.joined()
        let reviewHTML = leads.isEmpty ? "<p>No review prompts were generated from this export.</p>" : leads.map { lead in
            "<article><h3>\(escape(lead.title))</h3>" +
                "<p><strong>Observed:</strong> \(escape(lead.observed))</p>" +
                "<p><strong>Why review it:</strong> \(escape(lead.whyItMatters))</p>" +
                "<p><strong>Next check:</strong> \(escape(lead.nextStep))</p>" +
                "<p><small>Evidence: export line(s) \(lead.evidenceLines.map(String.init).joined(separator: ", "))</small></p></article>"
        }.joined()
        let sessionHTML: String
        if let session {
            sessionHTML = "<h2>Test session</h2><p>\(escape(session.label)) · " +
                "\(escape(stamp(session.startedAt))) to \(escape(session.endedAt.map(stamp) ?? "in progress"))</p>" +
                "<p>The label and times are user-supplied context. The export does not attribute an event to this session. Private notes are omitted from shared reports.</p>"
        } else {
            sessionHTML = ""
        }
        let domains = snapshot.networkContacts.map { item in
            let classification: String
            if item.domainType == 1 {
                classification = "Apple: potentially used for cross-app or cross-site profiling"
            } else if item.domainType == 2 {
                classification = "Apple: not identified for that profiling category"
            } else {
                classification = "Apple classification unavailable"
            }
            return "<tr><td>\(escape(item.domain))</td><td>\(item.reportedContacts)</td>" +
                "<td>\(escape(stamp(item.firstSeenAt)))</td><td>\(escape(stamp(item.lastSeenAt)))</td>" +
                "<td>\(escape(classification))</td><td>Line \(item.sourceLine)</td></tr>"
        }.joined()
        let accesses = snapshot.resourceAccesses.map { item in
            "<tr><td>\(escape(item.category))</td><td>\(escape(item.startedAt.map(stamp) ?? "Unknown"))</td>" +
                "<td>\(escape(item.endedAt.map(stamp) ?? "Unknown"))</td>" +
                "<td>\(item.isComplete ? "Complete" : "Incomplete")</td>" +
                "<td>Lines \(item.sourceLines.map(String.init).joined(separator: ", "))</td></tr>"
        }.joined()
        var comparisonHTML = ""
        if let comparison {
            let changes = comparison.countChanges.map {
                "<li>\(escape($0.domain)): reported contacts \($0.before) → \($0.after)</li>"
            }.joined()
            let new = comparison.newDomains.map { "<li>\(escape($0))</li>" }.joined()
            let missing = comparison.absentDomains.map { "<li>\(escape($0))</li>" }.joined()
            let resources = comparison.newResourceCategories.map { "<li>\(escape($0))</li>" }.joined()
            comparisonHTML = """
            <h2>Compared with prior export</h2>
            <p>Earlier import: \(escape(stamp(comparison.earlier.importedAt))). Changes describe two rolling seven-day snapshots, not requests caused by a particular action.</p>
            <h3>Newly listed domains</h3><ul>\(new.isEmpty ? "<li>None</li>" : new)</ul>
            <h3>Domains no longer listed</h3><ul>\(missing.isEmpty ? "<li>None</li>" : missing)</ul>
            <h3>Changed aggregate contact counts</h3><ul>\(changes.isEmpty ? "<li>None</li>" : changes)</ul>
            <h3>Newly listed resource categories</h3><ul>\(resources.isEmpty ? "<li>None</li>" : resources)</ul>
            """
        }
        let skipped = snapshot.skippedSelectedRecords > 0
            ? "<p>\(snapshot.skippedSelectedRecords) selected-app record(s) had invalid fields and were skipped.</p>"
            : ""
        return """
        <!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
        <title>Mobile Audit · \(escape(snapshot.bundleID))</title>
        <style>body{font:16px system-ui;margin:2rem auto;padding:0 1rem;max-width:1000px;color:#17283a}h1{overflow-wrap:anywhere}p{line-height:1.5}table{border-collapse:collapse;width:100%;display:block;overflow-x:auto}th,td{border:1px solid #cdd8e1;padding:.6rem;text-align:left;vertical-align:top}td{overflow-wrap:anywhere}code{overflow-wrap:anywhere}.notice{background:#fff3db;border-left:4px solid #c77818;padding:1rem}article{border:1px solid #cdd8e1;border-radius:8px;padding:0 1rem;margin:1rem 0}li{margin:.35rem 0}.tag{text-transform:uppercase;letter-spacing:.05em;font-size:.78rem;font-weight:700;color:#8b4b18}</style>
        </head><body><h1>\(escape(snapshot.bundleID))</h1>
        <p>Imported \(escape(stamp(snapshot.importedAt))) · \(snapshot.networkContacts.count) network entries · \(snapshot.resourceAccesses.count) resource intervals · \(snapshot.uniqueDomains.count) unique domains</p>
        <div class="notice">The App Privacy Report section shows observed activity. Domain contacts and permission access alone do not establish a vulnerability or reveal request contents. Apple's contact counts cover its reporting window.</div>
        \(assessmentHTML)
        <h2>Potential attack vectors</h2><p>The paths below are conditional explanations of how a risk could be used. The recorded state and evidence show what has actually been tested.</p>\(vectorHTML)
        \(sessionHTML)
        \(comparisonHTML)
        <h2>Things to review</h2><p>These are leads for further testing, not confirmed security findings.</p>\(reviewHTML)
        <h2>Network activity</h2><table><thead><tr><th>Domain</th><th>Reported contacts</th><th>First seen</th><th>Last seen</th><th>Classification</th><th>Evidence</th></tr></thead><tbody>\(domains)</tbody></table>
        <h2>Resource access</h2><table><thead><tr><th>Resource</th><th>Started</th><th>Ended</th><th>Status</th><th>Evidence</th></tr></thead><tbody>\(accesses)</tbody></table>
        \(skipped)
        <h2>Coverage</h2><ul><li>Observed: app-attributed domains and sensitive-resource intervals in this export.</li><li>Unavailable: request contents, app private files, source code, and exploitability.</li></ul>
        <p>Source export SHA-256: <code>\(escape(snapshot.artifactSHA256))</code>. Only this app's normalized records are included; the original export and other apps are omitted.</p>
        </body></html>
        """
    }
}
