from __future__ import annotations

import html
import json
from pathlib import Path

from .ios_package_reporting import render_ios_package_sections
from .models import Report


def write_json(report: Report, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report.to_dict(), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def write_html(report: Report, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    escape = lambda value: html.escape(str(value), quote=True)
    scope = {
        "source": "Source scan",
        "app_bundle": "App bundle scan",
        "ipa": "IPA scan",
        "apk": "APK scan",
    }.get(report.inventory.get("input_type"), "Static scan")
    counts = {severity: sum(f.severity == severity for f in report.findings) for severity in ("critical", "high", "medium", "low", "info")}
    cards = "".join(
        f'<div class="stat {severity}"><strong>{counts[severity]}</strong><span>{severity.title()}</span></div>'
        for severity in counts
    )
    findings = "".join(
        '<article class="finding">'
        f'<div class="finding-head"><span class="badge {escape(f.severity)}">{escape(f.severity)}</span>'
        f'<h3>{escape(f.title)}</h3><small>{escape(f.rule_id)}</small></div>'
        f'<p class="location">{escape(f.location)}</p>'
        f'<p><b>Evidence:</b> {escape(f.evidence)}</p>'
        f'<p><b>Action:</b> {escape(f.recommendation)}</p>'
        f'<p class="meta">{escape(f.platform)} · {escape(f.confidence)} confidence · {escape(f.masvs)}'
        + (f' · {escape(f.maswe)}' if f.maswe else "") + '</p></article>'
        for f in report.sorted_findings()
    ) or '<p class="empty">No findings from the checks that ran.</p>'
    coverage = "".join(f"<li>{escape(item)}</li>" for item in sorted(set(report.coverage)))
    warnings = "".join(f"<li>{escape(item)}</li>" for item in report.warnings)
    inventory = escape(json.dumps(report.inventory, indent=2, ensure_ascii=False))
    package_sections = render_ios_package_sections(report.inventory)
    document = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Mobile Audit Report</title><style>
:root{{font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:#172235;background:#f5f7fb}}
*{{box-sizing:border-box}}body{{margin:0}}header{{background:#102a43;color:white;padding:2.5rem max(2rem,calc((100vw - 1050px)/2))}}
h1{{margin:.2rem 0;font-size:2rem}}header p{{margin:.4rem 0;color:#d8e4ee;overflow-wrap:anywhere}}
main{{max-width:1050px;margin:auto;padding:2rem}}h2{{margin:2.2rem 0 1rem}}.stats{{display:grid;grid-template-columns:repeat(5,1fr);gap:.6rem}}
.stat{{background:white;border-radius:12px;padding:1rem;border-top:4px solid #99a7b8;box-shadow:0 2px 10px #102a4310}}.stat strong{{display:block;font-size:1.7rem}}.stat span{{font-size:.8rem;text-transform:uppercase;letter-spacing:.06em}}
.stat.high{{border-color:#dc4848}}.stat.medium{{border-color:#df8b22}}.stat.low{{border-color:#d8bb28}}.stat.critical{{border-color:#9f2537}}
.finding{{background:white;border:1px solid #d9e1e8;border-radius:12px;padding:1.1rem 1.3rem;margin:.8rem 0;box-shadow:0 2px 10px #102a430c}}
.finding-head{{display:flex;align-items:center;gap:.7rem;flex-wrap:wrap}}.finding h3{{margin:0;flex:1;min-width:200px}}.finding small{{color:#617487}}
.badge{{border-radius:100px;padding:.25rem .65rem;background:#dce5ec;text-transform:uppercase;font-weight:700;font-size:.7rem;letter-spacing:.04em}}
.badge.high,.badge.critical{{background:#ffe0e0;color:#8b1e2a}}.badge.medium{{background:#fff0d6;color:#85510c}}.badge.low{{background:#f6efd0;color:#675719}}
.location{{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;color:#375a7a;overflow-wrap:anywhere}}.meta{{color:#607486;font-size:.83rem}}
.panel{{background:white;border:1px solid #d9e1e8;border-radius:12px;padding:1rem 1.3rem;overflow-x:auto}}pre{{white-space:pre-wrap;overflow-wrap:anywhere;font-size:.8rem}}li{{margin:.35rem 0}}
table{{width:100%;border-collapse:collapse;font-size:.88rem}}th,td{{text-align:left;vertical-align:top;border-bottom:1px solid #d9e1e8;padding:.55rem .65rem;overflow-wrap:anywhere}}th{{background:#f4f7fa}}.notice{{background:#eef5fa;border-left:4px solid #3875a2;padding:.75rem 1rem}}
@media(max-width:650px){{main{{padding:1rem}}.stats{{grid-template-columns:repeat(2,1fr)}}header{{padding:2rem 1rem}}}}
</style></head><body><header><h1>Mobile Audit</h1><p>{escape(report.target)}</p><p>Scanned {escape(report.scanned_at)} · {escape(scope)}</p></header>
<main><div class="stats">{cards}</div>{package_sections}<h2>Findings</h2>{findings}
<h2>Checks run</h2><div class="panel"><ul>{coverage}</ul></div>
<h2>Scan notes</h2><div class="panel">{'<ul>'+warnings+'</ul>' if warnings else '<p>No scan warnings.</p>'}</div>
<h2>Inventory</h2><div class="panel"><pre>{inventory}</pre></div></main></body></html>"""
    path.write_text(document, encoding="utf-8")
