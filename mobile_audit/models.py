from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass(frozen=True)
class Finding:
    rule_id: str
    title: str
    platform: str
    severity: str
    confidence: str
    location: str
    evidence: str
    recommendation: str
    masvs: str
    maswe: str | None = None


@dataclass
class Report:
    target: str
    scanned_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    findings: list[Finding] = field(default_factory=list)
    inventory: dict[str, object] = field(default_factory=dict)
    coverage: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def add(self, finding: Finding) -> None:
        if finding not in self.findings:
            self.findings.append(finding)

    def sorted_findings(self) -> list[Finding]:
        return sorted(
            self.findings,
            key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.platform, f.location, f.rule_id),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": "1.0",
            "tool": "mobile-audit 0.6.0",
            "target": self.target,
            "scanned_at": self.scanned_at,
            "findings": [asdict(f) for f in self.sorted_findings()],
            "inventory": self.inventory,
            "coverage": sorted(set(self.coverage)),
            "warnings": self.warnings,
        }


def relative_location(path: Path, root: Path, line: int | None = None) -> str:
    try:
        location = path.relative_to(root).as_posix()
    except ValueError:
        location = path.name
    return f"{location}:{line}" if line else location
