import Foundation

/// Schema 2.1 adds a provisional assessment and structured attack vectors.
/// APR observations alone do not become vulnerability findings.
public enum EvidenceJSONReport {
    private static func stamp(_ date: Date) -> String {
        ISO8601DateFormatter().string(from: date)
    }

    private static func nullable(_ value: String?) -> Any {
        if let value { return value }
        return NSNull()
    }

    private static func nullable(_ value: Int?) -> Any {
        if let value { return value }
        return NSNull()
    }

    private static func nullable(_ value: Date?) -> Any {
        if let value { return stamp(value) }
        return NSNull()
    }

    public static func render(_ snapshot: APRSnapshot, session: AuditSession? = nil,
                              assessment: ResearchAssessment? = nil,
                              evidenceIntegrity: EvidenceIntegrityReport? = nil) throws -> Data {
        let artifactID = "artifact-\(snapshot.artifactSHA256.prefix(16))"
        let provenance = { (lines: [Int]) -> [String: Any] in
            ["artifact_id": artifactID,
             "collector": "apple_app_privacy_report",
             "locator": ["line_numbers": lines.sorted()]]
        }

        let network: [[String: Any]] = snapshot.networkContacts.map { contact in
            ["id": "obs-network-\(contact.sourceLine)",
             "kind": "network_contact",
             "observed_at": stamp(contact.lastSeenAt),
             "details": ["domain": contact.domain,
                         "first_seen_at": stamp(contact.firstSeenAt),
                         "last_seen_at": stamp(contact.lastSeenAt),
                         "reported_contacts": contact.reportedContacts,
                         "initiated_type": nullable(contact.initiatedType),
                         "domain_type": nullable(contact.domainType),
                         "domain_owner": nullable(contact.domainOwner)],
             "provenance": provenance([contact.sourceLine]),
             "session_id": NSNull()]
        }
        let resources: [[String: Any]] = snapshot.resourceAccesses.map { access in
            ["id": "obs-access-\(access.sourceLines.map(String.init).joined(separator: "-"))",
             "kind": "resource_access",
             "observed_at": stamp(access.observedAt),
             "details": ["category": access.category,
                         "started_at": nullable(access.startedAt),
                         "ended_at": nullable(access.endedAt),
                         "interval_status": access.isComplete ? "complete" : "incomplete"],
             "provenance": provenance(access.sourceLines),
             "session_id": NSNull()]
        }
        let sessionRecords: [[String: Any]] = session.map { item in
            [["id": item.id.uuidString,
              "started_at": stamp(item.startedAt),
              "ended_at": nullable(item.endedAt),
              "actions": [item.label],
              "account_label": NSNull(),
              "scope": NSNull()]]
        } ?? []
        let grade = AssessmentGrader.grade(assessment, evidenceIntegrity: evidenceIntegrity)
        let matchingAssessment = assessment?.rubricVersion == GuidedCheckCatalog.rubricVersion ? assessment : nil
        let vectors: [[String: Any]] = AttackVectorEngine.vectors(for: assessment,
                                                                 evidenceIntegrity: evidenceIntegrity).map { vector in
            ["id": vector.id,
             "title": vector.title,
             "state": vector.state.rawValue,
             "entry_point": vector.entryPoint,
             "attacker_control": vector.attackerControl,
             "attack_scenario": vector.attackScenario,
             "prerequisites": vector.prerequisites,
             "security_boundary": vector.securityBoundary,
             "impact": vector.possibleImpact,
             "observed": vector.observed,
             "evidence_line_numbers": vector.evidenceLines,
             "evidence_sha256": vector.evidenceHashes,
             "next_step": vector.nextStep,
             "severity": nullable(vector.severity?.rawValue)]
        }
        let checks: [[String: Any]] = (matchingAssessment == nil && assessment != nil ? [] : GuidedCheckCatalog.checks).map { definition in
            let record = matchingAssessment?.record(for: definition.id) ?? ResearchCheckRecord(id: definition.id)
            let documentedImpact = record.hasDocumentedImpact &&
                evidenceIntegrity?.verifiedEvidence(in: record).isEmpty == false
            return ["id": definition.id,
                    "category": definition.category,
                    "title": definition.title,
                    "status": record.status.rawValue,
                    "summary": record.summary,
                    "impact": documentedImpact ? record.impact : "",
                    "severity": nullable(documentedImpact ? record.severity?.rawValue : nil),
                    "trials": record.trials,
                    "evidence_line_numbers": record.evidenceLines,
                    "evidence_sha256": evidenceIntegrity?.verifiedEvidence(in: record).map(\.sha256) ?? []]
        }
        let attachedCount = assessment?.records.reduce(0) { $0 + $1.evidence.count } ?? 0
        let integrityStatus: String
        if attachedCount == 0 { integrityStatus = "no_evidence" }
        else if let evidenceIntegrity {
            integrityStatus = evidenceIntegrity.issues.isEmpty ? "verified" : "failed"
        } else { integrityStatus = "not_checked" }
        let assessmentRecord: [String: Any] = [
            "status": grade.letter == nil ? "incomplete" : "provisional",
            "grade": nullable(grade.letter),
            "rubric_version": assessment?.rubricVersion ?? GuidedCheckCatalog.rubricVersion,
            "updated_at": nullable(assessment?.updatedAt),
            "app_version": nullable(assessment?.appVersion.isEmpty == false ? assessment?.appVersion : nil),
            "ios_version": nullable(assessment?.iOSVersion.isEmpty == false ? assessment?.iOSVersion : nil),
            "scope_recorded": assessment?.scope.isEmpty == false,
            "completed_checks": grade.completedChecks,
            "applicable_checks": grade.applicableChecks,
            "coverage_percent": grade.coveragePercent,
            "evidence_strength": "researcher_recorded_not_independently_verified",
            "evidence_integrity_status": integrityStatus,
            "grading_requirements": grade.issues,
            "grade_rationale": grade.rationale,
            "checks": checks
        ]
        let allEvidence = matchingAssessment?.records.flatMap(\.evidence) ?? []
        let evidenceArtifacts: [[String: Any]] = allEvidence.map { item in
            ["id": "artifact-research-\(item.id.uuidString)",
             "kind": "research_evidence_file",
             "collection_method": "user_file_import",
             "source_name": "Private research evidence file",
             "sha256": item.sha256,
             "sensitivity": "research_evidence",
             "raw_retained": evidenceIntegrity?.verifiedIDs.contains(item.id) ?? false,
             "integrity_status": evidenceIntegrity?.verifiedIDs.contains(item.id) == true ? "verified" : "unverified",
             "created_at": stamp(item.addedAt)]
        }
        var lineToObservation: [Int: String] = [:]
        for contact in snapshot.networkContacts {
            lineToObservation[contact.sourceLine] = "obs-network-\(contact.sourceLine)"
        }
        for access in snapshot.resourceAccesses {
            let observationID = "obs-access-\(access.sourceLines.map(String.init).joined(separator: "-"))"
            for line in access.sourceLines { lineToObservation[line] = observationID }
        }
        let guidedResults: [[String: Any]] = (matchingAssessment?.records ?? []).compactMap { record in
            guard record.status != .notRun && record.status != .notApplicable else { return nil }
            let status: String
            let hasVerifiedEvidence = evidenceIntegrity?.verifiedEvidence(in: record).isEmpty == false
            switch record.status {
            case .passed: status = hasVerifiedEvidence ? "passed" : "inconclusive"
            case .confirmed: status = record.hasDocumentedImpact && hasVerifiedEvidence ? "failed" : "inconclusive"
            case .concern, .inconclusive: status = "inconclusive"
            case .unavailable: status = "unavailable"
            case .notRun, .notApplicable: return nil
            }
            return ["id": "guided-\(record.id)",
                    "rule_id": record.id,
                    "rule_version": GuidedCheckCatalog.rubricVersion,
                    "status": status,
                    "explanation": "Researcher-recorded outcome: \(record.summary)",
                    "evidence_ids": Array(Set(record.evidenceLines.compactMap { lineToObservation[$0] })).sorted(),
                    "prerequisites": [GuidedCheckCatalog.check(record.id)?.featureNeeded ?? ""],
                    "tested_conditions": ["\(record.trials) recorded trial(s)", "Status: \(record.status.label)"]]
        }

        var coverage: [[String: String]] = [
            ["area": "resource_access", "status": "observed",
             "detail": "Imported app-attributed access intervals; absence of an event is not proof that access never occurred."],
            ["area": "network_domains", "status": "observed",
             "detail": "Imported selected-app domains and Apple's aggregate contact counts."],
            ["area": "network_request_contents", "status": "unavailable",
             "detail": "The export does not contain request or response contents."],
            ["area": "app_private_storage", "status": "unavailable",
             "detail": "The export does not expose the app's private files or database."],
            ["area": "source_and_binary", "status": "unavailable",
             "detail": "No source project or usable app binary was examined by this import."],
            ["area": "vulnerability_exploitation", "status": "unavailable",
             "detail": "The App Privacy Report import performs no active vulnerability test."]
        ]
        if let assessment {
            coverage.append(["area": "guided_app_checks", "status": "observed",
                             "detail": "Guided checks were recorded by a researcher on a physical iPhone; the tool did not independently observe the target app."])
            if assessment.records.contains(where: {
                $0.hasDocumentedImpact && evidenceIntegrity?.verifiedEvidence(in: $0).isEmpty == false
            }),
               let index = coverage.firstIndex(where: { $0["area"] == "vulnerability_exploitation" }) {
                coverage[index] = ["area": "vulnerability_exploitation", "status": "observed",
                                   "detail": "A researcher recorded reproduced impact and attached evidence; independent validation remains pending."]
            }
        }
        var notes = [
            "App Privacy Report observations alone do not establish a vulnerability or identify transmitted data.",
            "Network contact counts cover Apple's reporting period, not one test session.",
            "Other apps, browsing context, and private session notes are omitted.",
            "Session metadata, when present, is user-supplied context; observations are not attributed to it."
        ]
        if assessment != nil {
            notes.append("Guided check outcomes and the provisional grade are researcher-recorded; attached evidence file contents are not in this report.")
            notes.append("Attached evidence hashes were checked against locally retained bytes when available; this does not validate the researcher's interpretation.")
        }
        if snapshot.skippedSelectedRecords > 0 {
            notes.append("\(snapshot.skippedSelectedRecords) selected-app record(s) with invalid fields were skipped.")
        }
        let report: [String: Any] = [
            "schema_version": "2.1",
            "tool": ["name": "mobile-audit", "version": "0.4.1"],
            "generated_at": stamp(Date()),
            "mode": "app_privacy_report",
            "target": ["platform": "ios", "identifier": snapshot.bundleID,
                       "name": NSNull(), "version": nullable(assessment?.appVersion.isEmpty == false ? assessment?.appVersion : nil)],
            "environment": ["os_version": nullable(assessment?.iOSVersion.isEmpty == false ? assessment?.iOSVersion : nil), "device_class": NSNull(),
                            "region": NSNull(), "permissions": NSNull()],
            "sessions": sessionRecords,
            "artifacts": [["id": artifactID,
                           "kind": "apple_app_privacy_report",
                           "collection_method": "user_export_from_ios_settings",
                           "source_name": "App Privacy Report export",
                           "sha256": snapshot.artifactSHA256,
                           "sensitivity": "device_activity",
                           "raw_retained": false,
                           "created_at": NSNull()]] + evidenceArtifacts,
            "observations": network + resources,
            "test_results": guidedResults,
            "findings": [[String: Any]](),
            "coverage": coverage,
            "notes": notes,
            "assessment": assessmentRecord,
            "attack_vectors": vectors
        ]
        return try JSONSerialization.data(withJSONObject: report, options: [.prettyPrinted, .sortedKeys])
    }
}
