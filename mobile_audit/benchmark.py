"""Reproducible, selected-case source benchmark for Mobile Audit.

This module reads app source. It never builds or runs a benchmark app.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from .scanner import scan


def _within(base: Path, relative: str) -> Path:
    if not isinstance(relative, str) or not relative:
        raise ValueError("Benchmark path is missing")
    resolved = (base / relative).resolve()
    if not resolved.is_relative_to(base.resolve()):
        raise ValueError(f"Benchmark path escapes its root: {relative}")
    return resolved


def _commit(repo: Path) -> str | None:
    try:
        result = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"],
                                capture_output=True, text=True, timeout=10, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return result.stdout.strip() if result.returncode == 0 else None


def _location_matches(location: str, case: dict[str, object]) -> bool:
    path = case.get("path")
    if path is None:
        return True
    line = case.get("line")
    if line is not None:
        return location == f"{path}:{line}"
    return location == path or location.startswith(f"{path}:")


def _case_result(case: dict[str, object], report: object) -> dict[str, object]:
    from .models import Report
    if not isinstance(report, Report):
        raise TypeError("Expected a static scan report")
    expected = case["expect"]
    result: dict[str, object] = {"id": case["id"], "app": case["app"], "title": case["title"],
                                 "expect": expected, "rule": case.get("rule"),
                                 "path": case.get("path"), "reason": case.get("reason"),
                                 "locations": []}
    if expected == "manual":
        result["status"] = "manual_pending"
        return result
    if expected == "inventory":
        matches = [item for item in report.inventory.get("ios_entry_points", [])
                   if isinstance(item, dict) and item.get("kind") == case.get("entry_kind")
                   and item.get("value") == case.get("value")
                   and _location_matches(str(item.get("location", "")), case)]
        result["locations"] = sorted({str(item["location"]) for item in matches})
        result["status"] = "recorded" if matches else "missed"
        return result
    matches = [item.location for item in report.findings
               if item.rule_id == case.get("rule") and _location_matches(item.location, case)]
    result["locations"] = sorted(set(matches))[:20]
    if expected == "present":
        result["status"] = "detected" if matches else "missed"
    elif expected == "absent":
        result["status"] = "false_alarm" if matches else "clear"
    else:
        raise ValueError(f"Unknown case expectation: {expected}")
    return result


def evaluate_benchmark(manifest_path: Path, project_root: Path,
                       upstream_root: Path | None = None) -> dict[str, object]:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("schema_version") != "1.0":
        raise ValueError("Expected benchmark manifest schema 1.0")
    apps = manifest.get("apps")
    cases = manifest.get("cases")
    if not isinstance(apps, list) or not isinstance(cases, list):
        raise ValueError("Benchmark manifest needs apps and cases lists")
    app_ids = [item.get("id") for item in apps]
    case_ids = [item.get("id") for item in cases]
    if len(set(app_ids)) != len(app_ids) or len(set(case_ids)) != len(case_ids):
        raise ValueError("Duplicate app or case ID in benchmark manifest")
    if any(case.get("app") not in app_ids for case in cases):
        raise ValueError("Benchmark case names an unknown app")

    app_results: list[dict[str, object]] = []
    case_results: list[dict[str, object]] = []
    for app in apps:
        app_id = str(app["id"])
        origin = app.get("origin")
        if origin == "local":
            source = _within(project_root, str(app["source"]))
            repo = None
        elif origin == "upstream":
            repo = _within(upstream_root, str(app["directory"])) if upstream_root else None
            source = _within(repo, str(app["source"])) if repo else None
        else:
            raise ValueError(f"Unknown benchmark app origin: {origin}")
        row: dict[str, object] = {"id": app_id, "label": app.get("label", app_id),
                                  "origin": origin, "commit": app.get("commit"),
                                  "status": "ready", "source_files_checked": 0,
                                  "finding_count": 0}
        if source is None or not source.is_dir():
            row["status"] = "source_missing"
        elif repo and _commit(repo) != app.get("commit"):
            row["status"] = "commit_mismatch"
        if row["status"] != "ready":
            app_results.append(row)
            case_results.extend({"id": case["id"], "app": app_id, "title": case["title"],
                                 "expect": case["expect"], "status": "skipped", "locations": [],
                                 "reason": row["status"]}
                                for case in cases if case["app"] == app_id)
            continue
        for case in cases:
            if case["app"] == app_id and case.get("path") and not _within(source, str(case["path"])).is_file():
                raise ValueError(f"Benchmark case {case['id']} source file is missing: {case['path']}")
        report = scan(source)
        row["source_files_checked"] = report.inventory.get("source_files_checked", 0)
        row["finding_count"] = len(report.findings)
        row["entry_point_count"] = len(report.inventory.get("ios_entry_points", []))
        row["warnings"] = report.warnings[:20]
        app_results.append(row)
        case_results.extend(_case_result(case, report) for case in cases if case["app"] == app_id)

    counts = {status: sum(case["status"] == status for case in case_results)
              for status in ("detected", "missed", "clear", "false_alarm", "recorded", "manual_pending", "skipped")}
    selected_positives = sum(case["expect"] == "present" and case["status"] != "skipped"
                             for case in case_results)
    negative_controls = sum(case["expect"] == "absent" and case["status"] != "skipped"
                            for case in case_results)
    return {"schema_version": "1.0", "generated_at": datetime.now(timezone.utc).isoformat(),
            "method": "Source-only selected cases; no app execution or vulnerability confirmation",
            "apps": app_results, "cases": case_results,
            "summary": {"selected_positive_detected": counts["detected"],
                        "selected_positive_total": selected_positives,
                        "negative_controls_clear": counts["clear"],
                        "negative_controls_total": negative_controls,
                        "inventory_recorded": counts["recorded"],
                        "manual_pending": counts["manual_pending"],
                        "skipped": counts["skipped"],
                        "missed": counts["missed"], "false_alarms": counts["false_alarm"]}}


def _markdown(result: dict[str, object]) -> str:
    summary = result["summary"]
    apps = result["apps"]
    cases = result["cases"]
    lines = ["# Mobile Audit baseline scorecard", "",
             "This measures selected source patterns in intentionally vulnerable training apps and corrected controls. It is not a security grade, population recall estimate, exploit confirmation, or CVE claim.", "",
             f"- **Selected cases detected:** {summary['selected_positive_detected']}/{summary['selected_positive_total']}",
             f"- **Negative controls clear:** {summary['negative_controls_clear']}/{summary['negative_controls_total']}",
             f"- **Entry points inventoried:** {summary['inventory_recorded']}",
             f"- **Manual cases pending:** {summary['manual_pending']}",
             f"- **Cases skipped:** {summary['skipped']}", "",
             "| App | Source files | Static findings | Selected cases | Status |",
             "| --- | ---: | ---: | --- | --- |"]
    for app in apps:
        own = [case for case in cases if case["app"] == app["id"]]
        detected = sum(case["status"] == "detected" for case in own)
        positives = sum(case["expect"] == "present" and case["status"] != "skipped" for case in own)
        clear = sum(case["status"] == "clear" for case in own)
        controls = sum(case["expect"] == "absent" and case["status"] != "skipped" for case in own)
        score = f"{detected}/{positives} detected; {clear}/{controls} controls" if app["status"] == "ready" else "not run"
        lines.append(f"| {app['label']} | {app['source_files_checked']} | {app['finding_count']} | {score} | {app['status']} |")
    lines.extend(["", "## Case results", "",
                  "| Case | App | Expected evidence | Result | Source location |",
                  "| --- | --- | --- | --- | --- |"])
    for case in cases:
        wanted = str(case.get("rule") or case.get("title"))
        location = ", ".join(case["locations"][:2]) if case["locations"] else str(case.get("path") or "—")
        lines.append(f"| {case['id']} | {case['app']} | {wanted} | {case['status']} | {location.replace('|', '\\|')} |")
    lines.extend(["", "A `missed` case is a known scanner gap at that source path. `manual_pending` cases require a signed device or controlled environment. Unreviewed findings are not counted as true or false positives. Upstream source must match the pinned commit in `baselines/benchmark.json`.", ""])
    return "\n".join(lines)


def write_scorecard(result: dict[str, object], output: Path) -> None:
    output.mkdir(parents=True, exist_ok=True)
    (output / "scorecard.json").write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    (output / "scorecard.md").write_text(_markdown(result), encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="mobile-audit benchmark",
                                     description="Score pinned, source-only benchmark cases without launching an app")
    parser.add_argument("--manifest", type=Path, default=Path(__file__).resolve().parents[1] / "baselines/benchmark.json")
    parser.add_argument("--upstream-root", type=Path, help="Directory containing separately cloned training apps")
    parser.add_argument("--output", type=Path, required=True, help="Directory for scorecard.json and scorecard.md")
    args = parser.parse_args(argv)
    try:
        result = evaluate_benchmark(args.manifest, args.manifest.expanduser().resolve().parent.parent,
                                    args.upstream_root)
        write_scorecard(result, args.output)
    except (FileNotFoundError, ValueError, OSError, json.JSONDecodeError) as exc:
        print(f"mobile-audit benchmark: {exc}", file=sys.stderr)
        return 1
    summary = result["summary"]
    print(f"Selected cases detected: {summary['selected_positive_detected']}/{summary['selected_positive_total']}; "
          f"negative controls clear: {summary['negative_controls_clear']}/{summary['negative_controls_total']}; "
          f"manual pending: {summary['manual_pending']}; skipped: {summary['skipped']}")
    print(f"Scorecard: {args.output.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
