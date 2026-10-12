"""Map the existing static scanner's results into evidence schema 2.0."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .evidence import (
    Artifact, Coverage, EvidenceFinding, EvidenceReport, Observation,
    TestResult, stable_id,
)
from .models import Report


def _target_identity(report: Report) -> tuple[str, str | None]:
    bundles = report.inventory.get("ios_bundles")
    if isinstance(bundles, list):
        for item in bundles:
            if isinstance(item, dict):
                identifier = item.get("bundle_id")
                if isinstance(identifier, str) and identifier and "$(" not in identifier:
                    return "ios", identifier
        if bundles:
            return "ios", None
    if report.inventory.get("input_type") == "apk":
        platform = "android"
    elif report.inventory.get("input_type") in {"ipa", "app_bundle"}:
        platform = "ios"
    else:
        platforms = {item.platform for item in report.findings}
        platform = next(iter(platforms)) if len(platforms) == 1 and "mobile" not in platforms else "mobile"
    return platform, None


def adapt_static_report(static_report: Report) -> EvidenceReport:
    legacy = static_report.to_dict()
    digest = hashlib.sha256(json.dumps(legacy, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()
    artifact_id = stable_id("artifact", "static_scan_report", digest)
    platform, identifier = _target_identity(static_report)
    report = EvidenceReport(
        mode="static_scan",
        target={
            "platform": platform,
            "identifier": identifier,
            "name": Path(static_report.target).name,
            "version": None,
        },
        environment={"os_version": None, "device_class": None, "region": None, "permissions": None},
        artifacts=[Artifact(
            id=artifact_id,
            kind="static_scan_report",
            collection_method="mobile_audit_static_scanner",
            source_name="Static scan report",
            sha256=digest,
            sensitivity="app_source_or_package_metadata",
            raw_retained=False,
        )],
    )
    for index, finding in enumerate(static_report.sorted_findings(), 1):
        observation_id = stable_id("obs", digest, "static_rule_match", index)
        report.observations.append(Observation(
            id=observation_id,
            kind="static_rule_match",
            observed_at=static_report.scanned_at,
            details={
                "rule_id": finding.rule_id,
                "platform": finding.platform,
                "location": finding.location,
                "evidence": finding.evidence,
            },
            artifact_id=artifact_id,
            source_locator={"finding_index": index},
            collector="mobile_audit_static_scanner",
        ))
        report.test_results.append(TestResult(
            id=stable_id("test", digest, index),
            rule_id=finding.rule_id,
            rule_version="legacy-1",
            status="inconclusive",
            explanation="A static pattern matched. Runtime behavior and security impact were not verified.",
            evidence_ids=[observation_id],
        ))
        report.findings.append(EvidenceFinding(
            id=stable_id("finding", digest, index),
            rule_id=finding.rule_id,
            title=finding.title,
            state="security_lead",
            severity=finding.severity,
            confidence=finding.confidence,
            claim=f"The static scanner found a pattern at {finding.location}; its runtime impact needs verification.",
            impact=None,
            attacker_prerequisites=[],
            evidence_ids=[observation_id],
            recommendation=finding.recommendation,
            mappings={key: value for key, value in {"masvs": finding.masvs, "maswe": finding.maswe}.items() if value},
            coverage_areas=["static_rules"],
        ))
    report.coverage = [Coverage("static_rules", "observed", "The static scanner ran its configured rules on the supplied material.")]
    report.coverage.extend(Coverage("static:" + item, "observed", "This static scanner check ran.") for item in sorted(set(static_report.coverage)))
    report.coverage.extend([
        Coverage("runtime_behavior", "unavailable", "The static scanner did not execute the app."),
        Coverage("network_request_contents", "unavailable", "No network capture was supplied."),
        Coverage("backend_authorization", "unavailable", "No authorized backend test was performed."),
    ])
    report.notes = [
        "Static matches are security leads, not confirmed vulnerabilities.",
        "The source artifact is represented by a hash; the original path and full report are not embedded.",
    ]
    visibility = static_report.inventory.get("ios_binary_visibility")
    if isinstance(visibility, dict):
        readable = visibility.get("not_encrypted", 0)
        encrypted = visibility.get("encrypted", 0)
        report.coverage.append(Coverage(
            "ios_executable_code_references", "observed" if readable else "unavailable",
            f"{readable} readable executable(s); {encrypted} encrypted executable(s). "
            "Only bounded API-name references were scanned in readable code."
        ))
        if encrypted:
            report.notes.append("Encrypted iOS executable code was not inspected; package metadata and resources were still scanned.")
    if identifier is None:
        report.notes.append("The app bundle identifier could not be resolved from this scan.")
    if static_report.warnings:
        report.notes.append(f"{len(static_report.warnings)} static scan note(s) remain in the original report.")
    return report
