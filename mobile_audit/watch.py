"""Compare research snapshots and rank evidence needed for vulnerability research.

These alerts describe changes in available evidence. They do not detect a live
compromise, infer causation from App Privacy Report data, or assign CVE IDs.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from .evidence import stable_id, utc_now
from .research import _validate_report
from .research_paths import CROSS_SIGNAL_KINDS


MAX_REPORT_BYTES = 30 * 1024 * 1024
MAX_ALERTS = 200
MAX_CANDIDATES = 30
_SEVERITY = {"high": 0, "medium": 1, "low": 2, "info": 3}
_COVERAGE = {"unavailable": 0, "limited": 1, "observed": 2}
_ENTRY_KINDS = {"custom_url_scheme", "universal_link_domain", "document_type",
                "external_url_handler", "universal_link_handler"}


def load_research_report(path: Path) -> dict[str, object]:
    """Load a bounded existing report without reading its referenced artifacts."""
    if not path.is_file() or path.stat().st_size > MAX_REPORT_BYTES:
        raise ValueError("Research report is missing or exceeds the 30 MB limit")
    try:
        report = json.loads(path.read_bytes())
        _validate_report(report)
    except (UnicodeDecodeError, ValueError, TypeError, KeyError, AttributeError) as exc:
        raise ValueError("Expected a valid Mobile Audit research report") from exc
    return report


def _fingerprint(report: dict[str, object]) -> str:
    data = json.dumps(report, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def _brief(value: object, limit: int = 240) -> str:
    return " ".join(str(value).split())[:limit]


def _signal_key(item: dict[str, object]) -> tuple[str, str, str]:
    """Use semantic values, not file hashes or timestamps, for a snapshot diff."""
    kind = str(item.get("kind", ""))
    details = item.get("details")
    details = details if isinstance(details, dict) else {}
    if kind == "network_contact":
        domain = details.get("domain")
        return kind, str(domain).lower().rstrip(".") if isinstance(domain, str) else "", ""
    if kind == "resource_access":
        return kind, str(details.get("category", "")), ""
    if kind == "static_rule_match":
        locator = re.sub(r":\d+$", "", str(item.get("locator", "")))
        return kind, str(details.get("rule_id", "")), locator
    if kind == "declared_entry_point":
        return kind, str(item.get("summary", "")), ""
    if kind == "binary_api_reference":
        return kind, str(item.get("summary", "")), str(item.get("locator", ""))
    if kind == "iphone_attack_vector":
        return kind, str(item.get("summary", "")), str(details.get("reported_state", ""))
    return kind, str(item.get("summary", "")), str(item.get("locator", ""))


def _evidence_index(report: dict[str, object]) -> dict[str, dict[str, object]]:
    return {item["id"]: item for item in report["evidence"]}


def _lead_key(lead: dict[str, object], evidence: dict[str, dict[str, object]]) -> tuple[object, ...]:
    if lead["kind"] in CROSS_SIGNAL_KINDS:
        # A correlation rule uses one representative pair of clues. Adding a
        # second sink must not make the existing research question look new.
        return lead["kind"], lead["title"], lead["state"], ()
    signals = tuple(sorted(_signal_key(evidence[identifier]) for identifier in lead["evidence_ids"]))
    return lead["kind"], lead["title"], lead["state"], signals


def _alert(kind: str, severity: str, summary: str, explanation: str, action: str,
           *, key: object, evidence_ids: list[str] | None = None,
           lead_ids: list[str] | None = None) -> dict[str, object]:
    return {
        "id": stable_id("alert", kind, key), "kind": kind, "severity": severity,
        "summary": _brief(summary), "explanation": _brief(explanation, 550),
        "next_action": _brief(action, 550),
        "evidence_ids": evidence_ids or [], "lead_ids": lead_ids or [],
    }


def _candidate_cards(report: dict[str, object]) -> tuple[list[dict[str, object]], int]:
    evidence = _evidence_index(report)
    version = report["target"].get("version")
    candidates: list[tuple[int, dict[str, object]]] = []
    for lead in report["leads"]:
        if lead["state"] in {"llm_suggestion", "known_version_match"}:
            continue
        kinds = {evidence[identifier]["kind"] for identifier in lead["evidence_ids"]}
        if lead["state"] == "researcher_reported_impact":
            rank, stage = 0, "reported_impact_needs_independent_review"
            rationale = "A researcher recorded impact, but this report has not independently reproduced it or established a new product flaw."
            missing = ["Repeat the behavior independently with controlled accounts or data.",
                       "Identify the affected app, component, and versions.",
                       "Check prior advisories and coordinate disclosure with the appropriate vendor."]
        elif lead["kind"] in CROSS_SIGNAL_KINDS or len(kinds) > 1:
            rank, stage = 1, "multiple_clues_no_path_verified"
            rationale = "More than one clue points to a testable path; no data flow or security impact has been demonstrated."
            missing = ["Trace attacker-controlled input to the relevant code path.",
                       "Reproduce a security impact under controlled conditions.",
                       "Identify affected versions and check prior advisories."]
            path_analysis = lead.get("path_analysis")
            if isinstance(path_analysis, dict):
                missing[0] = "Verify the missing connection: " + path_analysis["missing_link"]
        else:
            rank, stage = 2 if lead["priority"] == "high" else 3, "test_lead_only"
            rationale = "A code, package, or guided-test clue suggests a question to test; exploitability is unknown."
            missing = ["Confirm the feature is reachable in the shipped app.",
                       "Test controlled input and document any security impact.",
                       "Identify affected versions and check prior advisories."]
        if not version:
            missing.insert(0, "Record the exact app version or build tested.")
        card = {
            "id": stable_id("candidate", lead["id"]), "lead_id": lead["id"],
            "title": lead["title"], "priority": lead["priority"], "stage": stage,
            "cve_readiness": "independent_review_required" if rank == 0 else "not_demonstrated",
            "novelty": "unassessed", "rationale": rationale,
            "evidence_ids": lead["evidence_ids"], "missing_steps": missing,
        }
        if lead.get("attack_scenario"):
            card["attack_scenario"] = lead["attack_scenario"]
        candidates.append((rank, card))
    candidates.sort(key=lambda pair: (pair[0], _SEVERITY.get(pair[1]["priority"], 9), pair[1]["title"], pair[1]["id"]))
    omitted = max(0, len(candidates) - MAX_CANDIDATES)
    return [card for _, card in candidates[:MAX_CANDIDATES]], omitted


def build_watch_report(current: dict[str, object], previous: dict[str, object] | None = None) -> dict[str, object]:
    """Produce local change alerts and a deterministic CVE research checklist."""
    _validate_report(current)
    if previous is not None:
        _validate_report(previous)
        current_id = current["target"].get("identifier")
        previous_id = previous["target"].get("identifier")
        if not isinstance(current_id, str) or not current_id or current_id != previous_id:
            raise ValueError("Snapshot comparison requires the same nonempty iOS bundle identifier in both reports")
    candidates, omitted_candidates = _candidate_cards(current)
    alerts: list[dict[str, object]] = []
    new_leads = 0
    no_longer_observed = 0
    if previous is not None:
        old_evidence = _evidence_index(previous)
        new_evidence = _evidence_index(current)
        old_lead_keys = {_lead_key(item, old_evidence) for item in previous["leads"]
                         if item["state"] != "llm_suggestion"}
        new_lead_keys = {_lead_key(item, new_evidence) for item in current["leads"]
                         if item["state"] != "llm_suggestion"}
        no_longer_observed = len(old_lead_keys - new_lead_keys)
        counted_keys: set[tuple[object, ...]] = set()
        for lead in current["leads"]:
            if lead["state"] in {"llm_suggestion", "known_version_match"}:
                continue
            key = _lead_key(lead, new_evidence)
            if key in old_lead_keys or key in counted_keys:
                continue
            counted_keys.add(key)
            new_leads += 1
            if lead["state"] == "researcher_reported_impact":
                kind, severity = "new_researcher_reported_impact", "high"
                explanation = "A researcher newly reported impact. The tool has not independently reproduced or validated it."
                action = "Have a second reviewer repeat the test and document affected versions and impact."
            elif lead["kind"] in _ENTRY_KINDS:
                kind, severity = "new_entry_point", "medium"
                explanation = "This entry point is newly observed in the available inputs; it may reflect a new build or broader scan coverage."
                action = lead["next_test"]
            else:
                kind, severity = "new_test_lead", lead["priority"]
                explanation = "This test lead is newly observed, which does not establish a newly introduced vulnerability."
                action = lead["next_test"]
            alerts.append(_alert(kind, severity, lead["title"], explanation, action,
                                 key=key, evidence_ids=lead["evidence_ids"], lead_ids=[lead["id"]]))
        old_signals = {_signal_key(item) for item in previous["evidence"]}
        for item in current["evidence"]:
            key = _signal_key(item)
            if key in old_signals:
                continue
            if item["kind"] == "network_contact" and key[1]:
                alerts.append(_alert(
                    "new_network_domain", "low", f"Newly observed network domain: {key[1]}",
                    "App Privacy Report covers a rolling activity window; a new contact is not evidence of intrusion or causation.",
                    "Check whether the domain is expected for the app version and actions performed, then repeat the observation.",
                    key=key, evidence_ids=[item["id"]],
                ))
            elif item["kind"] == "resource_access" and key[1]:
                alerts.append(_alert(
                    "new_resource_category", "low", f"Newly observed resource access: {key[1]}",
                    "The access may reflect a new feature, permission, or collection window; intent and impact are unknown.",
                    "Compare with the actions and permissions recorded for this session.",
                    key=key, evidence_ids=[item["id"]],
                ))
        old_advisories = {(item["id"], item["ecosystem"], item["name"], item["version"])
                          for item in previous["known_advisories"]}
        for item in current["known_advisories"]:
            key = item["id"], item["ecosystem"], item["name"], item["version"]
            if key not in old_advisories:
                alerts.append(_alert(
                    "new_known_advisory_match", "medium", f"Known advisory version match: {item['id']}",
                    "The declared dependency version matches a published advisory; inclusion and applicability to this iOS build are unverified.",
                    "Confirm the dependency ships in the build and review the advisory's affected feature and fixed version.",
                    key=key,
                ))
        old_coverage = {item["area"]: item["status"] for item in previous["coverage"]}
        for item in current["coverage"]:
            old = old_coverage.get(item["area"])
            if old is not None and _COVERAGE.get(item["status"], 0) < _COVERAGE.get(old, 0):
                alerts.append(_alert(
                    "coverage_reduced", "medium", f"Less evidence for {item['area'].replace('_', ' ')}",
                    f"Coverage changed from {old} to {item['status']}. Missing leads cannot be treated as fixed.",
                    "Supply the missing input or repeat the check before comparing security outcomes.",
                    key=(item["area"], old, item["status"]),
                ))
        before = previous["target"].get("version")
        after = current["target"].get("version")
        if before != after:
            alerts.append(_alert(
                "app_version_changed", "info", f"App version changed: {before or 'unknown'} → {after or 'unknown'}",
                "A version change can explain new or missing observations; affected versions need separate verification.",
                "Record the exact builds and repeat candidate tests on both versions where possible.",
                key=(before, after),
            ))
        old_grade = previous["assessment"].get("grade")
        new_grade = current["assessment"].get("grade")
        letters = {"A": 0, "B": 1, "C": 2, "D": 3, "F": 4}
        if old_grade in letters and new_grade in letters and letters[new_grade] > letters[old_grade]:
            alerts.append(_alert(
                "provisional_grade_declined", "medium", f"Provisional grade changed from {old_grade} to {new_grade}",
                "Both grades are researcher-recorded; test coverage and app versions may differ.",
                "Compare completed guided checks, coverage, and the evidence behind each grade.",
                key=(old_grade, new_grade),
            ))
    unique = {item["id"]: item for item in alerts}
    ordered = sorted(unique.values(), key=lambda item: (_SEVERITY[item["severity"]], item["kind"], item["summary"], item["id"]))
    omitted_alerts = max(0, len(ordered) - MAX_ALERTS)
    return {
        "schema_version": "watch-1.0", "tool": {"name": "mobile-audit", "version": "0.6.0"},
        "generated_at": utc_now(),
        "target": current["target"],
        "current": {"canonical_report_sha256": _fingerprint(current), "generated_at": current["generated_at"],
                    "version": current["target"].get("version")},
        "previous": None if previous is None else {
            "canonical_report_sha256": _fingerprint(previous), "generated_at": previous["generated_at"],
            "version": previous["target"].get("version")},
        "alerts": ordered[:MAX_ALERTS], "omitted_alert_count": omitted_alerts,
        "candidate_triage": candidates, "omitted_candidate_count": omitted_candidates,
        "comparison": {"newly_observed_lead_count": new_leads,
                       "no_longer_observed_lead_count": no_longer_observed,
                       "previous_input_kinds": sorted({item["kind"] for item in previous["inputs"]}) if previous else [],
                       "current_input_kinds": sorted({item["kind"] for item in current["inputs"]})},
        "notes": [
            "Alerts are changes in evidence between two researcher-supplied snapshots, not intrusion detections.",
            "App Privacy Report describes a rolling seven-day window; newly observed domains do not prove malicious activity.",
            "A lead no longer observed is not a verified fix, especially when scan coverage or app version changed.",
            "Candidate triage ranks missing research steps; it does not estimate CVE probability or assign an ID.",
        ],
    }
