"""Import model suggestions as explicitly unreviewed, evidence-cited hypotheses."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .evidence import stable_id
from .research import _validate_report


MAX_RESPONSE_BYTES = 1024 * 1024
MAX_HYPOTHESES = 50
_PRIORITIES = {"high", "medium", "low"}
_HYPOTHESIS_FIELDS = {"hypothesis", "priority", "priority_reason", "supporting_evidence_ids",
                      "attacker_control", "possible_impact", "test_plan", "disconfirming_result",
                      "missing_evidence", "confidence"}
_OPTIONAL_HYPOTHESIS_FIELDS = {"attack_scenario"}


def _short(item: dict, key: str, limit: int) -> str:
    value = item.get(key)
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise ValueError(f"AI response field {key} is missing or too long")
    return value.strip()


def import_ai_review(report: dict[str, object], response_file: Path) -> dict[str, object]:
    """Return a new report with cited, unreviewed LLM suggestions; never alter findings or grade."""
    _validate_report(report)
    if not response_file.is_file() or response_file.stat().st_size > MAX_RESPONSE_BYTES:
        raise ValueError("AI response is missing or exceeds the 1 MB limit")
    raw = response_file.read_bytes()
    try:
        response = json.loads(raw)
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValueError("AI response must be valid JSON") from exc
    if not isinstance(response, dict) or response.get("format") != "mobile-audit-ai-response-1.0" or set(response) != {"format", "hypotheses"}:
        raise ValueError("AI response has an unsupported format")
    hypotheses = response.get("hypotheses")
    if not isinstance(hypotheses, list) or len(hypotheses) > MAX_HYPOTHESES:
        raise ValueError(f"AI response needs at most {MAX_HYPOTHESES} hypotheses")
    known_evidence = {item["id"] for item in report["evidence"]}
    digest = hashlib.sha256(raw).hexdigest()
    source_id = stable_id("source", "ai_review", digest)
    updated = json.loads(json.dumps(report))
    if not isinstance(updated.get("llm_reviews"), list):
        updated["llm_reviews"] = []
    if any(item.get("source_id") == source_id for item in updated["llm_reviews"]):
        raise ValueError("This AI response has already been imported")
    new_leads = []
    for index, item in enumerate(hypotheses):
        if not isinstance(item, dict):
            raise ValueError("AI response contains an invalid hypothesis")
        if not _HYPOTHESIS_FIELDS <= set(item) or set(item) - (_HYPOTHESIS_FIELDS | _OPTIONAL_HYPOTHESIS_FIELDS):
            raise ValueError("AI response hypothesis has missing or unsupported fields")
        title = _short(item, "hypothesis", 180)
        priority = item.get("priority")
        if priority not in _PRIORITIES:
            raise ValueError("AI response priority must be high, medium, or low")
        evidence_ids = item.get("supporting_evidence_ids")
        if not isinstance(evidence_ids, list) or not evidence_ids or len(evidence_ids) > 20 or not all(isinstance(value, str) for value in evidence_ids):
            raise ValueError("AI hypothesis needs 1-20 evidence IDs")
        if not set(evidence_ids) <= known_evidence:
            raise ValueError("AI hypothesis cites evidence that is absent from this report")
        reason = _short(item, "priority_reason", 700)
        control = _short(item, "attacker_control", 400)
        scenario = _short(item, "attack_scenario", 1000) if "attack_scenario" in item else None
        impact = _short(item, "possible_impact", 700)
        test = _short(item, "test_plan", 1000)
        disconfirm = _short(item, "disconfirming_result", 700)
        missing = _short(item, "missing_evidence", 700)
        confidence = item.get("confidence")
        if confidence not in {"high", "medium", "low"}:
            raise ValueError("AI response confidence must be high, medium, or low")
        lead = {
            "id": stable_id("lead", "ai_review", digest, index),
            "kind": "llm_suggestion", "title": title, "priority": priority,
            "confidence": confidence, "state": "llm_suggestion",
            "evidence_ids": sorted(set(evidence_ids)),
            "attacker_control": control, "possible_impact": impact,
            "next_test": test, "remediation_if_confirmed": "Determine the root cause after reproducing the behavior.",
            "priority_reason": reason, "disconfirming_result": disconfirm,
            "missing_evidence": missing, "review_source_id": source_id,
        }
        if scenario:
            lead["attack_scenario"] = scenario
        new_leads.append(lead)
    if len(updated["leads"]) + len(new_leads) > 500:
        raise ValueError("Imported AI suggestions would exceed the research lead limit")
    updated["inputs"].append({"id": source_id, "kind": "ai_response", "sha256": digest,
                              "hash_scope": "entire_file", "name": "Researcher-imported AI suggestions"})
    updated["llm_reviews"].append({"source_id": source_id, "hypothesis_count": len(new_leads),
                                   "status": "unreviewed"})
    updated["leads"].extend(new_leads)
    updated["leads"].sort(key=lambda item: ({"high": 0, "medium": 1, "low": 2}.get(item["priority"], 9), item["title"], item["id"]))
    updated["notes"].append("Imported AI suggestions are unreviewed hypotheses; they do not alter the security grade or establish a vulnerability.")
    _validate_report(updated)
    return updated
