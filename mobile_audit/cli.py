from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

from .ai_review import import_ai_review
from .benchmark import main as benchmark_main
from .evidence_reporting import write_evidence_html, write_evidence_json
from .ios_acquisition import acquire_ios_app, find_ipatool, run_ipatool_interactive
from .models import SEVERITY_ORDER
from .package_assets import extract_ios_assets
from .privacy_report import import_privacy_report, list_apps
from .reporting import write_html, write_json
from .research import build_research_scan
from .research_reporting import write_research_bundle
from .scanner import scan
from .static_adapter import adapt_static_report
from .watch import build_watch_report, load_research_report
from .watch_reporting import write_watch_bundle


def _acquire_ios_main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="mobile-audit acquire-ios",
        description="Find, download, verify, and scan a licensed App Store iPhone app on this Mac.",
    )
    actions = parser.add_subparsers(dest="action", required=True)
    actions.add_parser("setup", help="Install the ipatool acquisition backend with Homebrew")
    auth = actions.add_parser("auth", help="Sign in through ipatool's interactive terminal flow")
    auth.add_argument("--backend", help="Path to an existing ipatool binary")
    search = actions.add_parser("search", help="Search the iPhone App Store for an app")
    search.add_argument("term", help="App name or search term")
    search.add_argument("--backend", help="Path to an existing ipatool binary")
    download = actions.add_parser("download", help="Acquire an IPA and create a research report")
    target = download.add_mutually_exclusive_group(required=True)
    target.add_argument("--bundle-id", help="Expected iOS bundle identifier")
    target.add_argument("--app-id", type=int, help="Numeric App Store app identifier")
    download.add_argument("--output", type=Path, required=True, help="New directory for the IPA, acquisition record, and scan")
    download.add_argument("--phone-version", help="Version installed on the tested iPhone, when known")
    download.add_argument("--name", help="App display name for the report")
    download.add_argument("--privacy-report", type=Path, help="Optional raw App Privacy Report export")
    download.add_argument("--iphone-report", type=Path, help="Optional Mobile Audit iPhone evidence report")
    download.add_argument("--ios-version", help="iOS version used for the guided tests")
    download.add_argument("--backend", help="Path to an existing ipatool binary")
    args = parser.parse_args(argv)
    try:
        if args.action == "setup":
            installed = shutil.which("ipatool")
            if installed:
                print(f"App Store acquisition backend ready: {installed}")
                return 0
            if sys.platform != "darwin" or not (brew := shutil.which("brew")):
                raise RuntimeError("Automatic setup requires macOS and Homebrew; install ipatool from its official release")
            if subprocess.run([brew, "install", "ipatool"], check=False).returncode != 0:
                raise RuntimeError("Homebrew could not install ipatool")
            print(f"App Store acquisition backend ready: {find_ipatool()}")
            return 0
        if args.action == "auth":
            if not sys.stdin.isatty():
                raise RuntimeError("Run this command in an interactive terminal so Apple Account prompts stay there")
            return run_ipatool_interactive(["auth", "login"], backend=args.backend)
        if args.action == "search":
            status = run_ipatool_interactive(["search", args.term, "--platform", "iphone"], backend=args.backend)
            if status:
                print("If search needs an Apple Account session, run 'mobile-audit acquire-ios auth' in a terminal.", file=sys.stderr)
            return status
        result = acquire_ios_app(output=args.output, bundle_id=args.bundle_id,
                                 app_id=args.app_id, phone_version=args.phone_version,
                                 name=args.name, privacy_report=args.privacy_report,
                                 iphone_report=args.iphone_report, ios_version=args.ios_version,
                                 backend=args.backend)
    except (FileNotFoundError, ValueError, RuntimeError, OSError, zipfile.BadZipFile) as exc:
        print(f"mobile-audit: {exc}", file=sys.stderr)
        return 1
    print(f"Acquired: {result['package']['bundle_id']} {result['package']['version'] or '(version unknown)'}")
    print(f"Phone/package version: {result['version_match']}")
    print(f"IPA: {(args.output / 'package.ipa').resolve()}")
    print(f"Research report: {(args.output / 'scan' / 'report.html').resolve()}")
    print(f"Acquisition record: {(args.output / 'acquisition.json').resolve()}")
    return 0


def _privacy_main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="mobile-audit privacy-report",
        description="Import an Apple App Privacy Report locally for one selected iOS app",
    )
    parser.add_argument("export", type=Path, help="App Privacy Report NDJSON export")
    parser.add_argument("--app", help="Bundle identifier of the app to report on")
    parser.add_argument("--list-apps", action="store_true", help="List bundle identifiers represented in the export")
    parser.add_argument("--json", type=Path, help="Write an evidence schema 2.0 JSON report")
    parser.add_argument("--html", type=Path, help="Write a readable, shareable HTML report")
    args = parser.parse_args(argv)
    if args.list_apps and (args.app or args.json or args.html):
        parser.error("--list-apps cannot be combined with --app or output paths")
    if not args.list_apps and not args.app:
        parser.error("--app is required unless --list-apps is used")
    try:
        if args.list_apps:
            apps = list_apps(args.export)
            print("Apps in export:")
            for app in apps:
                print(f"  {app}")
            return 0
        report = import_privacy_report(args.export, args.app)
        if args.json:
            write_evidence_json(report, args.json)
        if args.html:
            write_evidence_html(report, args.html)
    except (FileNotFoundError, ValueError, OSError) as exc:
        print(f"mobile-audit: {exc}", file=sys.stderr)
        return 1
    accesses = sum(item.kind == "resource_access" for item in report.observations)
    networks = sum(item.kind == "network_contact" for item in report.observations)
    print(f"App: {args.app}")
    print(f"Observed: {accesses} resource intervals, {networks} network entries")
    print("Vulnerability findings: 0 (App Privacy Report observations do not establish exploitability)")
    if args.json:
        print(f"JSON report: {args.json.resolve()}")
    if args.html:
        print(f"HTML report: {args.html.resolve()}")
    return 0


def _scan_main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="mobile-audit",
        description="Scan iOS/Android source or packages. Use 'mobile-audit privacy-report' for an iPhone activity export.",
    )
    parser.add_argument("target", type=Path, help="Source directory, .app bundle, .ipa, or .apk")
    parser.add_argument("--source", type=Path, help="Optional source directory to scan alongside a package")
    parser.add_argument("--json", type=Path, help="Write a machine-readable JSON report")
    parser.add_argument("--html", type=Path, help="Write a standalone HTML report")
    parser.add_argument("--evidence-json", type=Path, help="Write findings in evidence schema 2.0")
    parser.add_argument("--evidence-html", type=Path, help="Write a readable evidence schema report")
    parser.add_argument("--fail-on", choices=["critical", "high", "medium", "low", "info"], help="Exit 2 if a finding meets this severity")
    args = parser.parse_args(argv)
    try:
        report = scan(args.target, args.source)
        if args.json:
            write_json(report, args.json)
        if args.html:
            write_html(report, args.html)
        if args.evidence_json or args.evidence_html:
            evidence = adapt_static_report(report)
            if args.evidence_json:
                write_evidence_json(evidence, args.evidence_json)
            if args.evidence_html:
                write_evidence_html(evidence, args.evidence_html)
    except (FileNotFoundError, ValueError, RuntimeError, OSError, zipfile.BadZipFile) as exc:
        print(f"mobile-audit: {exc}", file=sys.stderr)
        return 1
    print(f"Scanned: {report.target}")
    print(f"Findings: {len(report.findings)}")
    for finding in report.sorted_findings():
        print(f"  [{finding.severity.upper()}] {finding.title} — {finding.location}")
    if report.warnings:
        print(f"Scan notes: {len(report.warnings)}")
    if args.json:
        print(f"JSON report: {args.json.resolve()}")
    if args.html:
        print(f"HTML report: {args.html.resolve()}")
    if args.evidence_json:
        print(f"Evidence JSON: {args.evidence_json.resolve()}")
    if args.evidence_html:
        print(f"Evidence HTML: {args.evidence_html.resolve()}")
    if args.fail_on and any(SEVERITY_ORDER[f.severity] <= SEVERITY_ORDER[args.fail_on] for f in report.findings):
        return 2
    return 0


def _extract_ios_assets_main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="mobile-audit extract-ios-assets",
        description="Export source-like files shipped in an iOS .ipa or .app without decrypting executable code.",
    )
    parser.add_argument("target", type=Path, help="An iOS .ipa file or .app bundle")
    parser.add_argument("--output", type=Path, required=True, help="New directory for extracted assets and manifest")
    args = parser.parse_args(argv)
    try:
        result = extract_ios_assets(args.target, args.output)
    except (FileNotFoundError, ValueError, OSError, zipfile.BadZipFile) as exc:
        print(f"mobile-audit: {exc}", file=sys.stderr)
        return 1
    print(f"Extracted {result['asset_count']} packaged asset(s) and "
          f"{result['recovered_source_count']} embedded source file(s) ({result['total_bytes']} bytes total)")
    if result["skipped_oversize_assets"]:
        print(f"Skipped {result['skipped_oversize_assets']} asset(s) over 50 MB")
    print(f"Output: {args.output.resolve()}")
    return 0


def _research_main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="mobile-audit research-scan",
        description="Combine iOS package, source, iPhone activity, and readable-binary evidence in one local research report.",
    )
    parser.add_argument("--package", type=Path, help="Supplied .ipa or .app bundle")
    parser.add_argument("--source", type=Path, help="Developer source directory, when available")
    parser.add_argument("--privacy-report", type=Path, help="Raw Apple App Privacy Report export")
    parser.add_argument("--iphone-report", type=Path, help="Mobile Audit evidence JSON exported from the iPhone")
    parser.add_argument("--readable-binary", type=Path, help="Optional researcher-supplied Mach-O binary")
    parser.add_argument("--app", help="Bundle identifier; required when the privacy export has no matching package")
    parser.add_argument("--name", help="Display name for the target app")
    parser.add_argument("--app-version", help="Version tested, if known")
    parser.add_argument("--ios-version", help="iOS version used for the activity or guided tests")
    parser.add_argument("--check-known-vulns", action="store_true", help="Send exact dependency coordinates to OSV for known-advisory lookup")
    parser.add_argument("--ai-include-domains", action="store_true", help="Include selected-app network domains in the AI handoff")
    parser.add_argument("--previous-report", type=Path, help="Earlier research report.json for change alerts")
    parser.add_argument("--output", type=Path, required=True, help="New directory for HTML, JSON, and AI-review files")
    args = parser.parse_args(argv)
    try:
        report = build_research_scan(
            package=args.package, source=args.source, privacy_report=args.privacy_report,
            iphone_report=args.iphone_report, readable_binary=args.readable_binary,
            app=args.app, name=args.name, app_version=args.app_version,
            ios_version=args.ios_version, check_known_vulns=args.check_known_vulns,
        )
        previous = load_research_report(args.previous_report) if args.previous_report else None
        write_research_bundle(report, args.output, ai_include_domains=args.ai_include_domains,
                              previous_report=previous)
    except (FileNotFoundError, ValueError, RuntimeError, OSError, zipfile.BadZipFile) as exc:
        print(f"mobile-audit: {exc}", file=sys.stderr)
        return 1
    print(f"Research scan: {report['target']['identifier'] or report['target']['name'] or 'unidentified iOS app'}")
    print(f"Test leads: {len(report['leads'])}; known advisory version matches: {len(report['known_advisories'])}")
    print(f"Report, change triage, and AI review files: {args.output.resolve()}")
    return 0


def _import_ai_review_main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="mobile-audit import-ai-review",
        description="Add evidence-cited model suggestions to a copy of a research report as unreviewed leads.",
    )
    parser.add_argument("--report", type=Path, required=True, help="Existing research report.json")
    parser.add_argument("--response", type=Path, required=True, help="Model response JSON in the documented format")
    parser.add_argument("--output", type=Path, required=True, help="New directory for the updated report and AI handoff")
    parser.add_argument("--ai-include-domains", action="store_true", help="Include network domains in the new AI handoff")
    parser.add_argument("--previous-report", type=Path, help="Earlier research report.json to retain change alerts")
    args = parser.parse_args(argv)
    try:
        if not args.report.is_file() or args.report.stat().st_size > 30 * 1024 * 1024:
            raise ValueError("Research report is missing or exceeds the 30 MB limit")
        report = json.loads(args.report.read_bytes())
        updated = import_ai_review(report, args.response)
        previous = load_research_report(args.previous_report) if args.previous_report else None
        write_research_bundle(updated, args.output, ai_include_domains=args.ai_include_domains,
                              previous_report=previous)
    except (FileNotFoundError, ValueError, TypeError, KeyError, OSError) as exc:
        print(f"mobile-audit: {exc}", file=sys.stderr)
        return 1
    print(f"Imported {updated['llm_reviews'][-1]['hypothesis_count']} unreviewed suggestion(s)")
    print(f"Updated report: {args.output.resolve()}")
    return 0


def _watch_main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="mobile-audit watch-report",
        description="Compare two iOS research reports and triage evidence for possible vulnerability research.",
    )
    parser.add_argument("--current", type=Path, required=True, help="Current research report.json")
    parser.add_argument("--previous", type=Path, help="Earlier research report.json from the same bundle identifier")
    parser.add_argument("--output", type=Path, required=True, help="New directory for watch.html and watch.json")
    parser.add_argument("--fail-on", choices=["high", "medium", "low", "info"],
                        help="Exit 2 when a change alert meets this severity; useful in scheduled local runs")
    args = parser.parse_args(argv)
    try:
        current = load_research_report(args.current)
        previous = load_research_report(args.previous) if args.previous else None
        watch = build_watch_report(current, previous)
        write_watch_bundle(watch, args.output)
    except (FileNotFoundError, ValueError, TypeError, KeyError, OSError) as exc:
        print(f"mobile-audit: {exc}", file=sys.stderr)
        return 1
    print(f"Change alerts: {len(watch['alerts'])}; research paths: {len(watch['candidate_triage'])}")
    print(f"Watch report: {args.output.resolve()}")
    severity = {"high": 0, "medium": 1, "low": 2, "info": 3}
    if args.fail_on and any(severity[item["severity"]] <= severity[args.fail_on] for item in watch["alerts"]):
        return 2
    return 0


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments and arguments[0] == "acquire-ios":
        return _acquire_ios_main(arguments[1:])
    if arguments and arguments[0] == "benchmark":
        return benchmark_main(arguments[1:])
    if arguments and arguments[0] == "privacy-report":
        return _privacy_main(arguments[1:])
    if arguments and arguments[0] == "extract-ios-assets":
        return _extract_ios_assets_main(arguments[1:])
    if arguments and arguments[0] == "research-scan":
        return _research_main(arguments[1:])
    if arguments and arguments[0] == "import-ai-review":
        return _import_ai_review_main(arguments[1:])
    if arguments and arguments[0] == "watch-report":
        return _watch_main(arguments[1:])
    return _scan_main(arguments)
