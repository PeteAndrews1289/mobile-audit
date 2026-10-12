"""Versioned evidence records shared by privacy and static analysis.

Only normalized, target-specific values belong in an EvidenceReport. Raw App
Privacy Reports can describe every app on a device and are never embedded here.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


SCHEMA_VERSION = "2.0"
TOOL_VERSION = "0.6.0"
FINDING_STATES = {
    "observation", "security_lead", "confirmed_vulnerability",
    "known_cve_match", "new_cve_candidate",
}
TEST_STATUSES = {"passed", "failed", "inconclusive", "unavailable"}
COVERAGE_STATUSES = {"observed", "unavailable"}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def stable_id(prefix: str, *parts: object) -> str:
    encoded = json.dumps(parts, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return f"{prefix}-{hashlib.sha256(encoded).hexdigest()[:16]}"


@dataclass(frozen=True)
class Artifact:
    id: str
    kind: str
    collection_method: str
    source_name: str
    sha256: str
    sensitivity: str
    raw_retained: bool = False
    created_at: str | None = None


@dataclass(frozen=True)
class Session:
    id: str
    started_at: str
    ended_at: str | None
    actions: list[str]
    account_label: str | None
    scope: str | None


@dataclass(frozen=True)
class Observation:
    id: str
    kind: str
    observed_at: str
    details: dict[str, Any]
    artifact_id: str
    source_locator: dict[str, Any]
    collector: str
    session_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        item = asdict(self)
        item["provenance"] = {
            "artifact_id": item.pop("artifact_id"),
            "locator": item.pop("source_locator"),
            "collector": item.pop("collector"),
        }
        return item


@dataclass(frozen=True)
class TestResult:
    id: str
    rule_id: str
    rule_version: str
    status: str
    explanation: str
    evidence_ids: list[str]
    prerequisites: list[str] = field(default_factory=list)
    tested_conditions: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class EvidenceFinding:
    id: str
    rule_id: str
    title: str
    state: str
    severity: str
    confidence: str
    claim: str
    impact: str | None
    attacker_prerequisites: list[str]
    evidence_ids: list[str]
    recommendation: str
    mappings: dict[str, str]
    coverage_areas: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class Coverage:
    area: str
    status: str
    detail: str


@dataclass
class EvidenceReport:
    mode: str
    target: dict[str, str | None]
    environment: dict[str, Any]
    sessions: list[Session] = field(default_factory=list)
    artifacts: list[Artifact] = field(default_factory=list)
    observations: list[Observation] = field(default_factory=list)
    test_results: list[TestResult] = field(default_factory=list)
    findings: list[EvidenceFinding] = field(default_factory=list)
    coverage: list[Coverage] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    generated_at: str = field(default_factory=utc_now)

    def to_dict(self) -> dict[str, Any]:
        artifact_ids = {artifact.id for artifact in self.artifacts}
        observation_ids = {observation.id for observation in self.observations}
        session_ids = {session.id for session in self.sessions}
        coverage_areas = {item.area for item in self.coverage}
        if len(artifact_ids) != len(self.artifacts) or len(observation_ids) != len(self.observations):
            raise ValueError("Evidence contains duplicate artifact or observation IDs")
        if len(session_ids) != len(self.sessions):
            raise ValueError("Evidence contains duplicate session IDs")
        for observation in self.observations:
            if observation.artifact_id not in artifact_ids:
                raise ValueError(f"Observation {observation.id} has no source artifact")
            if not observation.source_locator:
                raise ValueError(f"Observation {observation.id} has no source locator")
            if observation.session_id is not None and observation.session_id not in session_ids:
                raise ValueError(f"Observation {observation.id} has no matching session")
        for test in self.test_results:
            if test.status not in TEST_STATUSES or not set(test.evidence_ids) <= observation_ids:
                raise ValueError(f"Invalid test result {test.id}")
        for finding in self.findings:
            if finding.state not in FINDING_STATES or not finding.evidence_ids:
                raise ValueError(f"Invalid finding {finding.id}")
            if not set(finding.evidence_ids) <= observation_ids:
                raise ValueError(f"Finding {finding.id} has missing evidence")
            if not set(finding.coverage_areas) <= coverage_areas:
                raise ValueError(f"Finding {finding.id} has missing coverage")
        for coverage in self.coverage:
            if coverage.status not in COVERAGE_STATUSES:
                raise ValueError(f"Invalid coverage status for {coverage.area}")
        return {
            "schema_version": SCHEMA_VERSION,
            "tool": {"name": "mobile-audit", "version": TOOL_VERSION},
            "generated_at": self.generated_at,
            "mode": self.mode,
            "target": self.target,
            "environment": self.environment,
            "sessions": [asdict(item) for item in self.sessions],
            "artifacts": [asdict(item) for item in self.artifacts],
            "observations": [item.to_dict() for item in self.observations],
            "test_results": [asdict(item) for item in self.test_results],
            "findings": [asdict(item) for item in self.findings],
            "coverage": [asdict(item) for item in self.coverage],
            "notes": self.notes,
        }
