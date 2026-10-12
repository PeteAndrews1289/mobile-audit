"""Readable and machine-readable output for longitudinal app research."""

from __future__ import annotations

import html
import json
import os
import shutil
import tempfile
from pathlib import Path


def _escape(value: object) -> str:
    return html.escape(str(value), quote=True)


def _validate_watch(report: dict[str, object]) -> None:
    if not isinstance(report, dict) or report.get("schema_version") != "watch-1.0":
        raise ValueError("Expected a Mobile Audit watch report")
    for key in ("alerts", "candidate_triage", "notes"):
        if not isinstance(report.get(key), list):
            raise ValueError(f"Watch report has invalid {key}")
    if not isinstance(report.get("target"), dict) or not isinstance(report.get("comparison"), dict):
        raise ValueError("Watch report has invalid target or comparison")


def watch_html(report: dict[str, object]) -> str:
    _validate_watch(report)
    target = report["target"]
    label = target.get("name") or target.get("identifier") or "Unidentified iOS app"
    alert_cards = []
    for alert in report["alerts"]:
        references = ", ".join(_escape(identifier) for identifier in alert["evidence_ids"])
        alert_cards.append(
            f'<article class="card { _escape(alert["severity"]) }">'
            f'<p class="eyebrow">{_escape(alert["severity"])} · {_escape(alert["kind"].replace("_", " "))}</p>'
            f'<h3>{_escape(alert["summary"])}</h3>'
            f'<p>{_escape(alert["explanation"])}</p>'
            f'<p><b>Next check:</b> {_escape(alert["next_action"])}</p>'
            f'<p class="meta">Evidence IDs: {references or "None in this report"}</p></article>'
        )
    candidate_cards = []
    for candidate in report["candidate_triage"]:
        missing = "".join(f"<li>{_escape(step)}</li>" for step in candidate["missing_steps"])
        scenario = (f'<p><b>Possible attack path:</b> {_escape(candidate["attack_scenario"])}</p>'
                    if candidate.get("attack_scenario") else "")
        candidate_cards.append(
            f'<article class="card"><p class="eyebrow">{_escape(candidate["stage"].replace("_", " "))}'
            f' · {_escape(candidate["priority"])} test priority</p>'
            f'<h3>{_escape(candidate["title"])}</h3><p>{_escape(candidate["rationale"])}</p>'
            f'{scenario}'
            f'<p><b>CVE readiness:</b> {_escape(candidate["cve_readiness"].replace("_", " "))}; '
            f'<b>novelty:</b> {_escape(candidate["novelty"])}</p>'
            f'<p><b>Evidence still needed:</b></p><ul>{missing}</ul>'
            f'<p class="meta">Lead {_escape(candidate["lead_id"])} · Evidence '
            f'{", ".join(_escape(identifier) for identifier in candidate["evidence_ids"])}</p></article>'
        )
    notes = "".join(f"<li>{_escape(note)}</li>" for note in report["notes"])
    compared = "Compared with an earlier report" if report["previous"] else "First snapshot: no change alerts yet"
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Mobile Audit watch · {_escape(label)}</title><style>
:root{{font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#f4f7fa;color:#15283a}}
*{{box-sizing:border-box}}body{{margin:0}}header{{background:#112f49;color:white;padding:2.2rem max(1rem,calc((100vw - 1060px)/2))}}
header p{{color:#d7e4ed}}main{{max-width:1060px;margin:auto;padding:1.4rem}}h1{{margin:.2rem 0}}h2{{margin:2rem 0 .7rem}}
.card,.panel{{background:#fff;border:1px solid #d8e2ea;border-radius:11px;padding:1rem 1.2rem;margin:.7rem 0;overflow-wrap:anywhere}}
.high{{border-left:4px solid #b24747}}.medium{{border-left:4px solid #b47d32}}.low{{border-left:4px solid #568aa3}}
.eyebrow{{text-transform:uppercase;letter-spacing:.06em;font-size:.73rem;font-weight:700;color:#54728b}}
.meta{{color:#607489;font-size:.83rem}}li{{margin:.4rem 0}}p{{line-height:1.45}}@media(max-width:700px){{main{{padding:1rem}}}}
</style></head><body><header><p>Mobile Audit · change and research triage</p><h1>{_escape(label)}</h1>
<p>{_escape(target.get("identifier") or "Bundle identifier unknown")} · App version {_escape(target.get("version") or "unknown")}</p>
<p>{_escape(compared)} · {_escape(report["generated_at"])}</p></header><main>
<div class="panel"><b>{len(report["alerts"])} change alert(s)</b> · {len(report["candidate_triage"])} test lead(s) triaged.
These alerts flag newly available evidence; they do not detect an intrusion or establish a CVE.</div>
<h2>Changes to review</h2>{''.join(alert_cards) or '<div class="panel">No new signals in the compared reports. A first snapshot has no earlier baseline.</div>'}
<h2>Possible vulnerability research paths</h2>{''.join(candidate_cards) or '<div class="panel">No candidate leads from the checks that ran.</div>'}
<h2>Interpretation</h2><div class="panel"><ul>{notes}</ul></div>
<p class="meta">{_escape(report["omitted_alert_count"])} additional alert(s) and {_escape(report["omitted_candidate_count"])} additional candidate(s) omitted by report limits. Review the underlying research report for full evidence.</p>
</main></body></html>"""


def write_watch_files(report: dict[str, object], directory: Path) -> None:
    _validate_watch(report)
    (directory / "watch.json").write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    (directory / "watch.html").write_text(watch_html(report), encoding="utf-8")


def write_watch_bundle(report: dict[str, object], output: Path) -> Path:
    """Create a new directory with a standalone watch report without overwriting."""
    _validate_watch(report)
    output = output.expanduser().resolve()
    if output.exists():
        raise ValueError("Choose a new output directory; an existing report will not be overwritten")
    output.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".mobile-audit-watch-", dir=output.parent))
    try:
        write_watch_files(report, staging)
        os.replace(staging, output)
        return output
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise
