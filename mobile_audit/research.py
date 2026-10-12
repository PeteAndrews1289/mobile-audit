"""Combine app activity, package, source, and readable-binary evidence in one case.

This layer ranks places to test. It does not infer that a code reference is
reachable, independently validate researcher-recorded tests, or assign CVEs.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Callable

from .dependencies import collect_dependencies, lookup_known_advisories
from .evidence import stable_id, utc_now
from .macho import MAX_HEADER_BYTES, MAX_REFERENCE_BYTES, inspect_macho, scan_api_references
from .privacy_report import import_privacy_report
from .research_paths import PATH_PATTERNS
from .research_recipes import attack_scenario_for, recipe_for
from .scanner import scan


MAX_IPHONE_REPORT_BYTES = 20 * 1024 * 1024
MAX_EVIDENCE = 5000
MAX_LEADS = 500
_PACKAGE_PROFILE_KEYS = (
    "input_type", "ios_package_file", "ios_bundles", "ios_entry_points",
    "ios_privacy_permissions", "ios_privacy_manifests", "ios_entitlements",
    "ios_transport_security", "ios_signatures", "ios_binaries",
    "ios_binary_visibility", "ios_binary_candidates", "ios_main_executable", "ios_signature_candidates",
    "ios_plaintext_code_assets",
)
_HASH = re.compile(r"^[a-f0-9]{64}$")
_PRIORITY = {"high": 0, "medium": 1, "low": 2}
_API_LEADS = {
    "external_url_handler": ("External URL handler", "high", "Parameters supplied through another app or browser", "Unauthorized app action or access to protected content", "Open a controlled link while signed out and under a second test account; compare authorized and unauthorized outcomes.", "Validate every parameter and enforce authorization in the handler."),
    "universal_link_handler": ("Universal link handler", "high", "Parameters in a web link", "Unauthorized app action or access to protected content", "Open a controlled link while signed out and under a second test account.", "Recheck authentication and object authorization after resolving the link."),
    "webview_native_bridge": ("WebView native bridge", "medium", "Potentially untrusted web content or messages", "Web content invoking privileged native functionality", "Identify the allowed origins and bridge methods; test a controlled page or message in scope.", "Restrict bridge exposure to trusted origins and validate message input."),
    "custom_server_trust": ("Custom server trust handling", "high", "Network endpoint and certificate presented to the app", "Acceptance of an untrusted server identity", "In an authorized test environment, verify whether an invalid server certificate is rejected.", "Use platform trust evaluation and reject untrusted certificates."),
    "object_deserialization": ("Object deserialization", "medium", "Serialized input delivered through an app entry point", "Unsafe parsing of attacker-controlled data", "Identify the input path and test benign malformed objects or documents in scope.", "Constrain allowed types and validate data before deserialization."),
}


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def _main_bundle(inventory: dict[str, object], package: Path | None) -> dict[str, object] | None:
    bundles = inventory.get("ios_bundles")
    if not isinstance(bundles, list):
        return None
    candidates = [item for item in bundles if isinstance(item, dict)
                  and isinstance(item.get("bundle_id"), str) and item["bundle_id"]
                  and "$(" not in item["bundle_id"]]
    if not candidates:
        return None
    if package and package.is_file():
        packaged = [item for item in candidates if str(item.get("location", "")).startswith("Payload/")]
        if packaged:
            candidates = packaged
    elif package:
        primary = next((item for item in candidates if item.get("location") == "Info.plist"), None)
        if primary:
            return primary
    else:
        # A source tree may contain vendored frameworks and build products. Their
        # literal bundle IDs must never become the identity of the assessed app
        # when the app's own Info.plist uses an Xcode build setting placeholder.
        nested_bundle_suffixes = (".framework", ".xcframework", ".appex", ".app", ".bundle", ".xctest")
        candidates = [item for item in candidates if not any(
            part.lower().endswith(nested_bundle_suffixes)
            for part in str(item.get("location", "")).split("/")[:-1]
        )]
        if not candidates:
            return None
    return min(candidates, key=lambda item: (str(item.get("location", "")).count("/"), len(str(item.get("location", "")))))


def _load_iphone_report(path: Path) -> tuple[dict[str, object], str]:
    if not path.is_file() or path.stat().st_size > MAX_IPHONE_REPORT_BYTES:
        raise ValueError("iPhone evidence report is missing or exceeds the 20 MB limit")
    data = path.read_bytes()
    try:
        document = json.loads(data)
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValueError("iPhone evidence report is not valid JSON") from exc
    if not isinstance(document, dict) or document.get("schema_version") not in {"2.0", "2.1"}:
        raise ValueError("Expected a Mobile Audit iPhone evidence report in schema 2.0 or 2.1")
    target = document.get("target")
    if not isinstance(target, dict) or target.get("platform") != "ios" or not isinstance(target.get("identifier"), str):
        raise ValueError("iPhone evidence report has no iOS bundle identifier")
    artifacts = document.get("artifacts")
    observations = document.get("observations")
    if not isinstance(artifacts, list) or not isinstance(observations, list):
        raise ValueError("iPhone evidence report has no artifact or observation list")
    if len(artifacts) > MAX_EVIDENCE or len(observations) > MAX_EVIDENCE:
        raise ValueError("iPhone evidence report exceeds the research-scan record limit")
    artifact_ids = {item["id"] for item in artifacts if isinstance(item, dict)
                    and isinstance(item.get("id"), str) and isinstance(item.get("sha256"), str)
                    and _HASH.fullmatch(item["sha256"])}
    if len(artifact_ids) != len(artifacts):
        raise ValueError("iPhone evidence report has invalid or duplicate artifacts")
    observation_ids = set()
    for item in observations:
        if not isinstance(item, dict) or not isinstance(item.get("id"), str):
            raise ValueError("iPhone evidence report has an invalid observation")
        provenance = item.get("provenance")
        if not isinstance(provenance, dict) or provenance.get("artifact_id") not in artifact_ids or not provenance.get("locator"):
            raise ValueError("iPhone evidence report has an observation without a source artifact")
        observation_ids.add(item["id"])
    if len(observation_ids) != len(observations):
        raise ValueError("iPhone evidence report has duplicate observations")
    tests = document.get("test_results", [])
    if not isinstance(tests, list):
        raise ValueError("iPhone evidence report has invalid test results")
    for item in tests:
        ids = item.get("evidence_ids") if isinstance(item, dict) else None
        if not isinstance(ids, list) or not all(isinstance(value, str) for value in ids) or not set(ids) <= observation_ids:
            raise ValueError("iPhone evidence report has a test without matching observations")
    vectors = document.get("attack_vectors", [])
    if not isinstance(vectors, list):
        raise ValueError("iPhone evidence report has invalid attack vectors")
    return document, hashlib.sha256(data).hexdigest()


def _observation(report: dict[str, object], *, kind: str, source_id: str,
                 locator: str, summary: str, details: dict[str, object] | None = None) -> str:
    evidence = report["evidence"]
    if not isinstance(evidence, list) or len(evidence) >= MAX_EVIDENCE:
        raise ValueError(f"Research report exceeds {MAX_EVIDENCE} evidence items")
    identifier = stable_id("evidence", source_id, kind, locator, summary)
    evidence.append({"id": identifier, "kind": kind, "source_id": source_id,
                     "locator": locator, "summary": summary, "details": details or {}})
    return identifier


def _lead(report: dict[str, object], *, kind: str, title: str, priority: str,
          evidence_ids: list[str], attacker_control: str, possible_impact: str,
          next_test: str, remediation: str, confidence: str = "low",
          state: str = "hypothesis", disconfirming_result: str | None = None,
          attack_scenario: str | None = None,
          path_analysis: dict[str, object] | None = None) -> None:
    leads = report["leads"]
    if not isinstance(leads, list) or len(leads) >= MAX_LEADS:
        raise ValueError(f"Research report exceeds {MAX_LEADS} leads")
    lead = {"id": stable_id("lead", kind, title, sorted(evidence_ids)),
            "kind": kind, "title": title, "priority": priority, "confidence": confidence,
            "state": state, "evidence_ids": evidence_ids,
            "attacker_control": attacker_control, "possible_impact": possible_impact,
            "next_test": next_test, "remediation_if_confirmed": remediation}
    if disconfirming_result is not None:
        lead["disconfirming_result"] = disconfirming_result
    scenario = attack_scenario if attack_scenario is not None else attack_scenario_for(kind)
    if scenario:
        lead["attack_scenario"] = scenario
    if path_analysis is not None:
        lead["path_analysis"] = path_analysis
    leads.append(lead)


def _api_references(report: dict[str, object], categories: list[str], location: str,
                    source_id: str) -> None:
    for category in sorted(set(categories)):
        details = _API_LEADS.get(category)
        if details is None:
            continue
        evidence_id = _observation(report, kind="binary_api_reference", source_id=source_id,
                                   locator=location, summary=f"Readable binary references {category.replace('_', ' ')}")
        title, priority, control, impact, test, remediation = details
        _lead(report, kind=category, title=title, priority=priority,
              evidence_ids=[evidence_id], attacker_control=control,
              possible_impact=impact, next_test=test, remediation=remediation)


def _package_and_source(report: dict[str, object], package: Path | None, source: Path | None) -> None:
    target = package or source
    if target is None:
        return
    static = scan(target, source if package else None)
    inventory = static.inventory
    fingerprint_data = static.to_dict()
    fingerprint_data.pop("target", None)
    fingerprint_data.pop("scanned_at", None)
    fingerprint_data["inventory"] = dict(inventory)
    fingerprint_data["inventory"].pop("source_root", None)
    fingerprint = hashlib.sha256(json.dumps(fingerprint_data, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
    source_id = stable_id("source", "static_scan", fingerprint)
    report["inputs"].append({"id": source_id, "kind": "static_scan", "sha256": fingerprint,
                             "hash_scope": "scanner_output", "name": "Package and source checks" if package and source else "Package checks" if package else "Source checks"})
    report["static_warnings"] = static.warnings[:100]
    if package:
        report["package_profile"] = {key: inventory[key] for key in _PACKAGE_PROFILE_KEYS if key in inventory}
        package_file = inventory.get("ios_package_file", {})
        package_hash = package_file.get("sha256") if isinstance(package_file, dict) else None
        report["inputs"].append({"id": stable_id("source", "package", package_hash or fingerprint),
                                 "kind": "ios_package", "sha256": package_hash,
                                 "hash_scope": "entire_file" if package_hash else "not_available_for_directory",
                                 "name": "Supplied iOS package"})
    bundle = _main_bundle(inventory, package)
    if bundle:
        target_info = report["target"]
        if package or not target_info["identifier"]:
            target_info["identifier"] = bundle["bundle_id"]
        if package or not target_info["version"]:
            target_info["version"] = bundle.get("version")
    for finding in static.sorted_findings():
        if finding.platform == "android":
            continue
        evidence_id = _observation(report, kind="static_rule_match", source_id=source_id,
                                   locator=finding.location, summary=finding.evidence,
                                   details={"rule_id": finding.rule_id, "platform": finding.platform,
                                            "severity": finding.severity, "confidence": finding.confidence,
                                            "masvs": finding.masvs, "maswe": finding.maswe})
        priority = "high" if finding.severity in {"critical", "high"} else "medium" if finding.severity == "medium" else "low"
        recipe = recipe_for(finding.rule_id)
        _lead(report, kind=finding.rule_id, title=finding.title, priority=priority,
              evidence_ids=[evidence_id], attacker_control=recipe.attacker_control,
              possible_impact=recipe.possible_impact, next_test=recipe.next_test,
              remediation=finding.recommendation, confidence=finding.confidence,
              state="static_lead", disconfirming_result=recipe.disconfirming_result)
    for entry in inventory.get("ios_entry_points", [])[:200]:
        if not isinstance(entry, dict):
            continue
        kind = entry.get("kind")
        value = entry.get("value")
        if not isinstance(kind, str) or not isinstance(value, str):
            continue
        evidence_id = _observation(report, kind="declared_entry_point", source_id=source_id,
                                   locator=str(entry.get("location", "package configuration")),
                                   summary=f"{kind.replace('_', ' ')}: {value}")
        if kind == "document_type":
            control = "A document opened by the user"
            impact = "Unexpected file access, parser failure, or unintended app action"
            remediation = "Validate document structure and restrict imports to required types and access."
        else:
            control = "A link and its parameters"
            impact = "Unauthorized app action or protected-content access"
            remediation = "Validate link input and enforce authorization for every requested action."
        _lead(report, kind=kind, title=f"Test {kind.replace('_', ' ')}: {value}",
              priority="medium", evidence_ids=[evidence_id], attacker_control=control,
              possible_impact=impact, next_test=str(entry.get("next_test", "Test the entry point with controlled input.")),
              remediation=remediation)
    binaries = inventory.get("ios_binaries", [])
    if isinstance(binaries, list):
        for binary in binaries[:256]:
            if isinstance(binary, dict) and isinstance(binary.get("location"), str):
                _api_references(report, binary.get("api_reference_categories", []), binary["location"], source_id)
    report["visibility"]["package_binaries"] = inventory.get("ios_binary_visibility", {"not_encrypted": 0, "encrypted": 0, "unknown": 0})
    report["visibility"]["source_files_checked"] = inventory.get("source_files_checked", 0)
    report["visibility"]["source_like_assets_listed"] = len(inventory.get("ios_plaintext_code_assets", []))
    report["coverage"].append({"area": "package_configuration", "status": "observed" if package else "unavailable",
                                "detail": "Package configuration and entry points were scanned." if package else "No package was supplied."})
    report["coverage"].append({"area": "source_patterns", "status": "observed" if source else "unavailable",
                                "detail": "Developer source was scanned with bounded rules." if source else "No developer source was supplied."})
    binary_counts = report["visibility"]["package_binaries"]
    readable = binary_counts.get("not_encrypted", 0) if isinstance(binary_counts, dict) else 0
    encrypted = binary_counts.get("encrypted", 0) if isinstance(binary_counts, dict) else 0
    uninspected = binary_counts.get("uninspected", 0) if isinstance(binary_counts, dict) else 0
    main_executable = inventory.get("ios_main_executable", {})
    main_state = main_executable.get("encryption", "unknown") if isinstance(main_executable, dict) else "unknown"
    report["coverage"].append({"area": "native_code", "status": "limited" if readable and encrypted else "observed" if readable else "unavailable",
                                "detail": f"Main app executable: {main_state}. {readable} readable, {encrypted} encrypted, and {uninspected} uninspected package executable(s); readable code was checked only for selected API names."})


def _activity(report: dict[str, object], privacy_report: Path | None,
              iphone_report: Path | None, app: str | None) -> None:
    if not privacy_report and not iphone_report:
        report["coverage"].append({"area": "app_activity", "status": "unavailable", "detail": "No iPhone activity export was supplied."})
        return
    if privacy_report:
        identifier = app or report["target"].get("identifier")
        if not isinstance(identifier, str) or not identifier:
            raise ValueError("--app is required to select one app from an App Privacy Report")
        imported = import_privacy_report(privacy_report, identifier).to_dict()
        source_hash = imported["artifacts"][0]["sha256"]
        source_id = stable_id("source", "privacy_report", source_hash)
        report["inputs"].append({"id": source_id, "kind": "app_privacy_report", "sha256": source_hash,
                                 "hash_scope": "entire_file", "name": "Selected-app App Privacy Report import"})
    else:
        imported, source_hash = _load_iphone_report(iphone_report)
        source_id = stable_id("source", "iphone_evidence", source_hash)
        report["inputs"].append({"id": source_id, "kind": "iphone_evidence_report", "sha256": source_hash,
                                 "hash_scope": "entire_file", "name": "iPhone evidence report"})
        assessment = imported.get("assessment")
        if isinstance(assessment, dict):
            provisional = assessment.get("status") == "provisional" and assessment.get("evidence_integrity_status") == "verified"
            report["assessment"] = {
                "status": "provisional" if provisional else "incomplete",
                "grade": assessment.get("grade") if provisional and assessment.get("grade") in {"A", "B", "C", "D", "F"} else None,
                "coverage_percent": assessment.get("coverage_percent"),
                "evidence_strength": "researcher_recorded_not_independently_verified",
                "source": "iPhone evidence report",
            }
        for index, vector in enumerate(imported.get("attack_vectors", [])[:100]):
            if not isinstance(vector, dict) or not isinstance(vector.get("title"), str):
                continue
            attack_scenario = vector.get("attack_scenario")
            if not isinstance(attack_scenario, str):
                attack_scenario = None
            evidence_id = _observation(report, kind="iphone_attack_vector", source_id=source_id,
                                       locator=f"attack_vectors[{index}]", summary=vector["title"],
                                       details={"reported_state": str(vector.get("state", "unknown"))})
            state = "researcher_reported_impact" if vector.get("state") == "confirmed" else "researcher_recorded"
            _lead(report, kind="iphone_guided_check", title=vector["title"], priority="high" if state == "researcher_reported_impact" else "medium",
                  evidence_ids=[evidence_id], attacker_control=str(vector.get("attacker_control", "Not recorded"))[:300],
                  possible_impact=str(vector.get("impact", "Not established"))[:500],
                  next_test="Independently repeat the guided check and verify impact." if state == "researcher_reported_impact" else str(vector.get("next_step", "Run a controlled test."))[:500],
                  remediation="Determine the root cause after independent reproduction.", state=state,
                  attack_scenario=attack_scenario[:1000] if attack_scenario else None)
    imported_id = imported.get("target", {}).get("identifier")
    if isinstance(imported_id, str) and report["target"].get("identifier") and report["target"]["identifier"] != imported_id:
        raise ValueError("The iPhone activity bundle identifier does not match the supplied package")
    if isinstance(imported_id, str):
        report["target"]["identifier"] = imported_id
    imported_version = imported.get("target", {}).get("version")
    if isinstance(imported_version, str) and imported_version:
        existing = report["target"].get("version")
        if existing and existing != imported_version:
            report["notes"].append("The package and iPhone report name different app versions; cross-source conclusions require version review.")
        else:
            report["target"]["version"] = imported_version
    imported_environment = imported.get("environment")
    if isinstance(imported_environment, dict):
        observed_ios = imported_environment.get("os_version")
        if isinstance(observed_ios, str) and observed_ios:
            existing_ios = report["environment"].get("ios_version")
            if existing_ios and existing_ios != observed_ios:
                report["notes"].append("The supplied iOS version differs from the iPhone report; verify the test environment.")
            else:
                report["environment"]["ios_version"] = observed_ios
    imported_observations = imported.get("observations", [])
    remaining = MAX_EVIDENCE - len(report["evidence"])
    if len(imported_observations) > remaining:
        report["notes"].append(f"Only the first {remaining} iPhone activity observation(s) fit in this research report.")
    for item in imported_observations[:remaining]:
        if not isinstance(item, dict):
            continue
        kind = item.get("kind")
        details = item.get("details")
        if not isinstance(details, dict):
            continue
        if kind == "network_contact":
            domain = details.get("domain")
            if not isinstance(domain, str):
                continue
            summary = f"App-attributed contact with {domain}"
            safe_details = {"domain": domain, "reported_contacts": details.get("reported_contacts")}
        elif kind == "resource_access":
            category = details.get("category")
            if not isinstance(category, str):
                continue
            summary = f"App-attributed {category} access interval"
            safe_details = {"category": category, "interval_status": details.get("interval_status")}
        else:
            continue
        _observation(report, kind=kind, source_id=source_id, locator=str(item.get("id", "observation")),
                     summary=summary, details=safe_details)
    report["coverage"].append({"area": "app_activity", "status": "observed",
                                "detail": "Selected-app resource and network metadata imported; request contents and causation remain unavailable."})


def _readable_binary(report: dict[str, object], binary: Path | None) -> None:
    if binary is None:
        return
    if not binary.is_file():
        raise FileNotFoundError(binary)
    size = binary.stat().st_size
    if size > 1_500_000_000:
        raise ValueError("Researcher-supplied binary exceeds the 1.5 GB input limit")
    with binary.open("rb") as stream:
        inspection = inspect_macho(stream.read(min(size, MAX_HEADER_BYTES)), size)
    if inspection["format"] == "unknown":
        raise ValueError("--readable-binary must be a Mach-O executable or library")
    digest = _sha256_file(binary)
    source_id = stable_id("source", "readable_binary", digest)
    report["inputs"].append({"id": source_id, "kind": "researcher_supplied_binary", "sha256": digest,
                             "hash_scope": "entire_file", "name": "Researcher-supplied Mach-O binary"})
    report["visibility"]["supplied_binary"] = {"size": size, "encryption": inspection["encryption"],
                                                  "architectures": inspection["architectures"]}
    if inspection["encryption"] == "not_encrypted" and size <= MAX_REFERENCE_BYTES:
        with binary.open("rb") as stream:
            categories = scan_api_references(stream, size)
        _api_references(report, categories, "researcher-supplied Mach-O", source_id)
        report["coverage"].append({"area": "researcher_supplied_native_code", "status": "observed",
                                    "detail": "Readable Mach-O was checked for selected API-name references; binary-to-app identity and reachability were not verified."})
    else:
        report["coverage"].append({"area": "researcher_supplied_native_code", "status": "unavailable",
                                    "detail": "The supplied binary is encrypted, partially unreadable, or above the 256 MB reference-scan limit."})


def _cross_signal_leads(report: dict[str, object]) -> None:
    """Suggest a data-flow check when two independently observed clues coexist."""
    leads = report["leads"]
    if not isinstance(leads, list):
        return
    observed = tuple(leads)
    added = 0
    for pattern in PATH_PATTERNS:
        starts = [lead for lead in observed if lead["kind"] in pattern.start_kinds]
        targets = [lead for lead in observed if lead["kind"] in pattern.target_kinds]
        if not starts or not targets or len(leads) >= MAX_LEADS:
            continue
        start = min(starts, key=lambda item: (item["kind"], item["title"], item["id"]))
        target = min(targets, key=lambda item: (item["kind"], item["title"], item["id"]))
        start_ids = sorted(set(start["evidence_ids"]))
        target_ids = sorted(set(target["evidence_ids"]))
        cited = sorted(set(start_ids + target_ids))
        path_analysis = {
            "basis": "co_presence_only",
            "clues": [
                {"role": pattern.start_role, "evidence_ids": start_ids},
                {"role": pattern.target_role, "evidence_ids": target_ids},
            ],
            "missing_link": pattern.missing_link,
        }
        _lead(report, kind=pattern.kind, title=pattern.title, priority="medium", evidence_ids=cited,
              attacker_control=pattern.attacker_control, possible_impact=pattern.possible_impact,
              next_test=pattern.next_test, disconfirming_result=pattern.disconfirming_result,
              remediation=pattern.remediation, confidence="low", state="hypothesis",
              path_analysis=path_analysis)
        added += 1
    report["coverage"].append({"area": "cross_signal_review", "status": "limited",
                                "detail": f"{added} paired test lead(s) generated from co-present clues; no data flow or exploit path was verified."})


def build_research_scan(*, package: Path | None = None, source: Path | None = None,
                        privacy_report: Path | None = None, iphone_report: Path | None = None,
                        readable_binary: Path | None = None, app: str | None = None,
                        name: str | None = None, app_version: str | None = None,
                        ios_version: str | None = None, check_known_vulns: bool = False,
                        osv_post: Callable[[bytes], bytes] | None = None) -> dict[str, object]:
    """Build a single bounded report without launching or attacking the target app."""
    if not any((package, source, privacy_report, iphone_report, readable_binary)):
        raise ValueError("Supply a package, source directory, iPhone report, privacy report, or readable binary")
    if privacy_report and iphone_report:
        raise ValueError("Choose either the raw App Privacy Report or its iPhone evidence export")
    for path in (package, source, privacy_report, iphone_report, readable_binary):
        if path is not None and not path.exists():
            raise FileNotFoundError(path)
    if package and not (package.suffix.lower() == ".ipa" or package.is_dir() and package.suffix == ".app"):
        raise ValueError("--package requires an .ipa or .app bundle")
    if source and not source.is_dir():
        raise ValueError("--source requires a source directory")
    report: dict[str, object] = {
        "schema_version": "research-1.0", "tool": {"name": "mobile-audit", "version": "0.6.0"},
        "generated_at": utc_now(),
        "target": {"platform": "ios", "identifier": app, "name": name, "version": app_version},
        "environment": {"ios_version": ios_version},
        "inputs": [], "visibility": {}, "coverage": [], "evidence": [], "leads": [],
        "package_profile": {},
        "dependencies": [], "known_advisories": [], "assessment": {"status": "incomplete", "grade": None,
        "coverage_percent": None, "evidence_strength": "not_assessed", "source": None},
        "llm_reviews": [], "static_warnings": [], "notes": ["Static matches and API references are test leads, not proven vulnerabilities.",
                                     "This report does not run the target app, decrypt executable code, or validate backend authorization."],
    }
    _package_and_source(report, package, source)
    package_id = report["target"].get("identifier")
    if package and app and package_id and app != package_id:
        raise ValueError("--app does not match the supplied package bundle identifier")
    _activity(report, privacy_report, iphone_report, app)
    if app_version and report["target"].get("version") and report["target"]["version"] != app_version:
        report["notes"].append("The supplied --app-version differs from another input; verify which build was tested.")
    _readable_binary(report, readable_binary)
    if source:
        dependencies, warnings = collect_dependencies(source)
        report["dependencies"] = dependencies
        report["notes"].extend(warnings)
        dependency_digest = hashlib.sha256(json.dumps(dependencies, sort_keys=True).encode()).hexdigest()
        dependency_source_id = stable_id("source", "dependency_inventory", dependency_digest)
        report["inputs"].append({"id": dependency_source_id, "kind": "dependency_inventory", "sha256": dependency_digest,
                                 "hash_scope": "parsed_lockfile_inventory", "name": "Parsed dependency lockfiles"})
        report["coverage"].append({"area": "dependency_inventory", "status": "observed" if dependencies else "limited",
                                    "detail": f"{len(dependencies)} exact-version lockfile entries found; inclusion in the iOS build is unverified."})
        if check_known_vulns:
            try:
                matches, notes = lookup_known_advisories(dependencies, post=osv_post) if osv_post else lookup_known_advisories(dependencies)
                report["known_advisories"] = matches
                report["notes"].extend(notes)
                queryable = any(item.get("ecosystem") in {"SwiftURL", "npm"} for item in dependencies)
                report["coverage"].append({"area": "known_advisories", "status": "observed" if queryable else "limited",
                                            "detail": "Exact-version coordinates were sent to OSV; version matches require usage and applicability review."
                                            if queryable else "No supported exact-version coordinates were available for an OSV lookup."})
                for match in matches[:MAX_LEADS - len(report["leads"])]:
                    evidence_id = _observation(report, kind="known_advisory_match", source_id=dependency_source_id,
                                               locator=f"{match['ecosystem']}:{match['name']}@{match['version']}",
                                               summary=f"OSV lists {match['id']} for the declared package version")
                    _lead(report, kind="known_advisory", title=f"Review {match['id']} for {match['name']}",
                          priority="medium", evidence_ids=[evidence_id],
                          attacker_control="Depends on the advisory and whether this code ships in the app",
                          possible_impact="See the linked advisory; applicability to this build is unverified",
                          next_test="Confirm this dependency and affected feature are in the shipped iOS build, then review the advisory and fixed version.",
                          remediation="Update to a fixed version if the advisory applies.", state="known_version_match")
            except (OSError, ValueError) as exc:
                report["coverage"].append({"area": "known_advisories", "status": "unavailable",
                                            "detail": "OSV lookup failed; no known-vulnerability conclusion was drawn."})
                report["notes"].append(f"Known-advisory lookup failed: {type(exc).__name__}")
        else:
            report["coverage"].append({"area": "known_advisories", "status": "unavailable",
                                        "detail": "Online advisory lookup was not requested."})
    else:
        report["coverage"].extend([
            {"area": "dependency_inventory", "status": "unavailable", "detail": "No source lockfiles were supplied."},
            {"area": "known_advisories", "status": "unavailable", "detail": "No exact-version dependency inventory was available."},
        ])
    report["coverage"].extend([
        {"area": "network_request_contents", "status": "unavailable", "detail": "No proxy or request-content capture was ingested."},
        {"area": "backend_authorization", "status": "unavailable", "detail": "No independent two-account or backend authorization test was run."},
        {"area": "native_decompilation", "status": "unavailable", "detail": "Native binary decompilation is not implemented in this release."},
    ])
    _cross_signal_leads(report)
    report["leads"].sort(key=lambda item: (_PRIORITY.get(item["priority"], 9), item["title"], item["id"]))
    _validate_report(report)
    return report


def _validate_report(report: dict[str, object]) -> None:
    if not isinstance(report, dict) or report.get("schema_version") != "research-1.0":
        raise ValueError("Expected a Mobile Audit research report")
    if not isinstance(report.get("generated_at"), str):
        raise ValueError("Research report has no generation timestamp")
    for key in ("inputs", "evidence", "leads", "llm_reviews", "notes"):
        if not isinstance(report.get(key), list):
            raise ValueError(f"Research report has no valid {key} list")
    for key in ("target", "environment", "visibility", "assessment"):
        if not isinstance(report.get(key), dict):
            raise ValueError(f"Research report has no valid {key} object")
    if "package_profile" in report and not isinstance(report["package_profile"], dict):
        raise ValueError("Research report has an invalid package profile")
    for key in ("coverage", "dependencies", "known_advisories", "static_warnings"):
        if not isinstance(report.get(key), list):
            raise ValueError(f"Research report has no valid {key} list")
    if not all(isinstance(item, str) for item in report["notes"] + report["static_warnings"]):
        raise ValueError("Research report notes are invalid")
    if not all(isinstance(item, dict) and isinstance(item.get("source_id"), str)
               and isinstance(item.get("hypothesis_count"), int)
               and item.get("status") == "unreviewed" for item in report["llm_reviews"]):
        raise ValueError("Research report has invalid AI review records")
    if len(report["evidence"]) > MAX_EVIDENCE or len(report["leads"]) > MAX_LEADS:
        raise ValueError("Research report exceeds record limits")
    for key in ("inputs", "evidence", "leads"):
        items = report[key]
        if not all(isinstance(item, dict) and isinstance(item.get("id"), str) and item["id"] for item in items):
            raise ValueError(f"Research report has invalid {key} IDs")
        if len({item["id"] for item in items}) != len(items):
            raise ValueError(f"Research report contains duplicate {key} IDs")
    source_ids = {item["id"] for item in report["inputs"]}
    evidence_ids = {item["id"] for item in report["evidence"]}
    if not all(isinstance(item.get("kind"), str) and isinstance(item.get("name"), str) and isinstance(item.get("hash_scope"), str)
               and (item.get("sha256") is None or isinstance(item.get("sha256"), str))
               for item in report["inputs"]):
        raise ValueError("Research report has invalid input provenance")
    for item in report["evidence"]:
        if item.get("source_id") not in source_ids:
            raise ValueError("Research report evidence has no source input")
        if not isinstance(item.get("kind"), str) or not isinstance(item.get("locator"), str) or not isinstance(item.get("summary"), str) or not isinstance(item.get("details"), dict):
            raise ValueError("Research report has an invalid evidence item")
    for lead in report["leads"]:
        ids = lead.get("evidence_ids")
        if not isinstance(ids, list) or not ids or not all(isinstance(value, str) for value in ids) or not set(ids) <= evidence_ids:
            raise ValueError("Research lead is missing evidence")
        for key in ("kind", "title", "priority", "confidence", "state", "attacker_control",
                    "possible_impact", "next_test", "remediation_if_confirmed"):
            if not isinstance(lead.get(key), str):
                raise ValueError("Research report has an invalid lead")
        if "disconfirming_result" in lead and not isinstance(lead["disconfirming_result"], str):
            raise ValueError("Research report has an invalid disconfirming result")
        if "attack_scenario" in lead and not isinstance(lead["attack_scenario"], str):
            raise ValueError("Research report has an invalid attack scenario")
        path_analysis = lead.get("path_analysis")
        if path_analysis is not None:
            if lead["state"] != "hypothesis" or lead["confidence"] != "low":
                raise ValueError("Co-present clues must remain a low-confidence hypothesis")
            if (not isinstance(path_analysis, dict) or set(path_analysis) != {"basis", "clues", "missing_link"}
                    or path_analysis.get("basis") != "co_presence_only"
                    or not isinstance(path_analysis.get("missing_link"), str)
                    or not path_analysis["missing_link"]
                    or not isinstance(path_analysis.get("clues"), list)
                    or len(path_analysis["clues"]) != 2):
                raise ValueError("Research report has an invalid attack path analysis")
            for clue in path_analysis["clues"]:
                if (not isinstance(clue, dict) or set(clue) != {"role", "evidence_ids"}
                        or not isinstance(clue["role"], str) or not clue["role"]
                        or not isinstance(clue["evidence_ids"], list) or not clue["evidence_ids"]
                        or not all(isinstance(value, str) for value in clue["evidence_ids"])
                        or not set(clue["evidence_ids"]) <= set(ids)):
                    raise ValueError("Research report attack path has uncited clues")
            if (len({clue["role"] for clue in path_analysis["clues"]}) != 2
                    or {value for clue in path_analysis["clues"] for value in clue["evidence_ids"]} != set(ids)):
                raise ValueError("Research report attack path clues do not cover its evidence")
    for item in report["known_advisories"]:
        if not isinstance(item, dict) or not all(isinstance(item.get(key), str) for key in ("id", "url", "ecosystem", "name", "version")):
            raise ValueError("Research report has an invalid known advisory")
    for item in report["coverage"]:
        if not isinstance(item, dict) or not all(isinstance(item.get(key), str) for key in ("area", "status", "detail")):
            raise ValueError("Research report has an invalid coverage item")
