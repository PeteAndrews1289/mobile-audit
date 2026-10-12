"""Readable and machine-readable renderers for evidence schema 2.0."""

from __future__ import annotations

import html
import json
from pathlib import Path

from .evidence import EvidenceReport, Observation


def write_evidence_json(report: EvidenceReport, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report.to_dict(), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def _escape(value: object) -> str:
    return html.escape(str(value), quote=True)


def _observation_body(observation: Observation) -> tuple[str, str]:
    details = observation.details
    if observation.kind == "resource_access":
        category = str(details["category"])
        end = details.get("ended_at")
        status = details.get("interval_status")
        body = f"Started {_escape(details.get('started_at') or 'unknown')} · Ended {_escape(end or 'unknown')}"
        if status != "complete":
            body += " · Incomplete interval"
        return f"Resource access: {category}", body
    if observation.kind == "network_contact":
        domain = str(details["domain"])
        body = (
            f"First seen {_escape(details['first_seen_at'])} · Last seen {_escape(details['last_seen_at'])} "
            f"· {_escape(details['reported_contacts'])} reported contacts"
        )
        if details.get("initiated_type"):
            body += f" · {_escape(details['initiated_type'])}"
        if details.get("domain_type") == 1:
            body += " · Apple marked this domain as potentially used for cross-app or cross-site profiling"
        elif details.get("domain_type") == 2:
            body += " · Apple did not mark this domain for cross-app or cross-site profiling"
        return f"Domain contact: {domain}", body
    if observation.kind == "static_rule_match":
        return (
            f"Static match: {details.get('rule_id', 'unknown')}",
            f"{_escape(details.get('location', 'unknown'))} · {_escape(details.get('evidence', ''))}",
        )
    return observation.kind, _escape(json.dumps(details, ensure_ascii=False))


def write_evidence_html(report: EvidenceReport, path: Path) -> None:
    report.to_dict()  # Validate references before writing a shareable file.
    path.parent.mkdir(parents=True, exist_ok=True)
    target = report.target.get("name") or report.target.get("identifier") or "Unknown app"
    kind = "App Privacy Report" if report.mode == "app_privacy_report" else "Static scan"
    access_count = sum(item.kind == "resource_access" for item in report.observations)
    network_count = sum(item.kind == "network_contact" for item in report.observations)
    domain_count = len({item.details["domain"] for item in report.observations if item.kind == "network_contact"})
    observations = []
    for item in report.observations:
        title, body = _observation_body(item)
        locator = item.source_locator
        source = (
            "Export line " + ", ".join(map(str, locator["line_numbers"]))
            if "line_numbers" in locator else f"Static finding {locator.get('finding_index', '?')}"
        )
        observations.append(
            f'<article class="card" id="{_escape(item.id)}"><h3>{_escape(title)}</h3>'
            f'<p>{body}</p><p class="meta">{_escape(source)} · {_escape(item.id)}</p></article>'
        )
    finding_cards = []
    for finding in report.findings:
        links = " ".join(
            f'<a href="#{_escape(evidence_id)}">{_escape(evidence_id)}</a>' for evidence_id in finding.evidence_ids
        )
        finding_cards.append(
            '<article class="card finding">'
            f'<p class="eyebrow">{_escape(finding.state.replace("_", " "))} · {_escape(finding.severity)} severity · {_escape(finding.confidence)} confidence</p>'
            f'<h3>{_escape(finding.title)}</h3><p>{_escape(finding.claim)}</p>'
            f'<p><strong>Suggested action:</strong> {_escape(finding.recommendation)}</p>'
            f'<p class="meta">Evidence: {links} · Coverage: {_escape(", ".join(finding.coverage_areas) or "unspecified")}</p></article>'
        )
    coverage = "".join(
        f'<li><strong>{_escape(item.area.replace("_", " "))}</strong> '
        f'<span class="status {item.status}">{_escape(item.status)}</span><br>{_escape(item.detail)}</li>'
        for item in report.coverage
    )
    notes = "".join(f"<li>{_escape(item)}</li>" for item in report.notes)
    artifacts = "".join(
        f"<li>{_escape(item.source_name)} · SHA-256 <code>{_escape(item.sha256)}</code>"
        f" · {_escape(item.collection_method)}</li>" for item in report.artifacts
    )
    document = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Mobile Audit · {_escape(target)}</title><style>
:root{{font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:#18283b;background:#f4f7fa}}
*{{box-sizing:border-box}}body{{margin:0}}header{{background:#12314d;color:white;padding:2.5rem max(1.2rem,calc((100vw - 940px)/2))}}
header h1{{margin:.2rem 0}}header p{{color:#d9e5ef;margin:.4rem 0;overflow-wrap:anywhere}}main{{max-width:940px;margin:auto;padding:1.5rem}}
.eyebrow{{text-transform:uppercase;letter-spacing:.07em;font-size:.73rem;font-weight:700;color:#496985}}header .eyebrow{{color:#b7d6ed}}
.stats{{display:grid;grid-template-columns:repeat(4,1fr);gap:.65rem;margin:1rem 0 2rem}}.stat,.card,.panel{{background:#fff;border:1px solid #d7e2ea;border-radius:12px;padding:1rem 1.2rem}}
.stat strong{{display:block;font-size:1.8rem}}.stat span,.meta{{color:#5b7084;font-size:.82rem}}h2{{margin:2rem 0 .8rem}}.card{{margin:.7rem 0;overflow-wrap:anywhere}}.card h3{{margin:.1rem 0 .5rem}}
.finding{{border-left:4px solid #c77532}}.status{{border-radius:20px;padding:.15rem .5rem;font-size:.72rem;text-transform:uppercase;font-weight:700}}
.status.observed{{background:#e1f2e8;color:#1d6841}}.status.unavailable{{background:#f0e9e0;color:#77552b}}
li{{margin:.7rem 0;line-height:1.4}}a{{color:#0b5f9a;overflow-wrap:anywhere}}.small{{font-size:.85rem;color:#5b7084}}
@media(max-width:650px){{.stats{{grid-template-columns:repeat(2,1fr)}}}}
</style></head><body><header><p class="eyebrow">Mobile Audit · {_escape(kind)}</p><h1>{_escape(target)}</h1>
<p>{_escape(report.target.get('identifier') or 'Bundle identifier unknown')} · Generated {_escape(report.generated_at)}</p></header>
<main><p>This report describes evidence collected for one app. Observations alone do not prove a vulnerability.</p>
<div class="stats"><div class="stat"><strong>{access_count}</strong><span>Resource intervals</span></div>
<div class="stat"><strong>{network_count}</strong><span>Network entries</span></div>
<div class="stat"><strong>{domain_count}</strong><span>Unique domains</span></div>
<div class="stat"><strong>{len(report.findings)}</strong><span>Security leads</span></div></div>
<h2>Findings</h2>{''.join(finding_cards) or '<div class="panel">No vulnerability findings from this import.</div>'}
<h2>Observations</h2>{''.join(observations) or '<div class="panel">No observations.</div>'}
<h2>Coverage and limits</h2><div class="panel"><ul>{coverage}</ul></div>
<h2>Report notes</h2><div class="panel"><ul>{notes}</ul></div>
<h2>Source artifact</h2><div class="panel"><ul>{artifacts}</ul></div>
<p class="small">The original imported artifact is not embedded in this report.</p></main></body></html>"""
    path.write_text(document, encoding="utf-8")
