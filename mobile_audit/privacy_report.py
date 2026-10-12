"""Local import of Apple's newline-delimited App Privacy Report export."""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from .evidence import Artifact, Coverage, EvidenceReport, Observation, stable_id


MAX_REPORT_BYTES = 256 * 1024 * 1024
MAX_LINE_BYTES = 1024 * 1024
MAX_RECORDS = 1_000_000


def _records(path: Path, digest: Any) -> Iterator[tuple[int, dict[str, Any]]]:
    path = path.expanduser()
    if not path.is_file():
        raise FileNotFoundError(path)
    if path.stat().st_size > MAX_REPORT_BYTES:
        raise ValueError("App Privacy Report exceeds the 256 MiB import limit")
    with path.open("rb") as stream:
        total_bytes = 0
        for line_number, raw in enumerate(stream, 1):
            total_bytes += len(raw)
            if total_bytes > MAX_REPORT_BYTES:
                raise ValueError("App Privacy Report exceeds the 256 MiB import limit")
            if line_number > MAX_RECORDS:
                raise ValueError("App Privacy Report exceeds the record limit")
            if len(raw) > MAX_LINE_BYTES:
                raise ValueError(f"App Privacy Report line {line_number} exceeds the size limit")
            digest.update(raw)
            if not raw.strip():
                continue
            try:
                item = json.loads(raw)
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                raise ValueError(f"Invalid App Privacy Report JSON at line {line_number}") from exc
            if not isinstance(item, dict):
                raise ValueError(f"Expected an object at line {line_number}")
            yield line_number, item


def _timestamp(value: object) -> str | None:
    if not isinstance(value, str) or len(value) > 64:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    # Fixed precision makes ordering normalized timestamp strings reliable.
    return parsed.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _selected_access(record: dict[str, Any], bundle_id: str) -> bool:
    accessor = record.get("accessor")
    return (
        isinstance(accessor, dict)
        and accessor.get("identifier") == bundle_id
        and accessor.get("identifierType") == "bundleID"
    )


def list_apps(path: Path) -> list[str]:
    """List bundle IDs represented in an export; never writes their activity."""
    bundle_ids: set[str] = set()
    digest = hashlib.sha256()
    for _, record in _records(path, digest):
        kind = record.get("type")
        if kind == "networkActivity":
            identifier = record.get("bundleID")
        elif kind == "access":
            accessor = record.get("accessor")
            identifier = accessor.get("identifier") if isinstance(accessor, dict) and accessor.get("identifierType") == "bundleID" else None
        else:
            identifier = None
        if isinstance(identifier, str) and 0 < len(identifier) <= 255:
            bundle_ids.add(identifier)
    return sorted(bundle_ids)


def import_privacy_report(path: Path, bundle_id: str) -> EvidenceReport:
    if not bundle_id or len(bundle_id) > 255:
        raise ValueError("--app must be a valid bundle identifier from --list-apps")
    digest = hashlib.sha256()
    access_events: list[dict[str, Any]] = []
    network_events: list[dict[str, Any]] = []
    skipped_selected = 0
    for line, record in _records(path, digest):
        kind = record.get("type")
        if kind == "access" and _selected_access(record, bundle_id):
            stamp = _timestamp(record.get("timeStamp"))
            category = record.get("category")
            interval_kind = record.get("kind")
            if not stamp or not isinstance(category, str) or not category or interval_kind not in {"intervalBegin", "intervalEnd"}:
                skipped_selected += 1
                continue
            access_events.append({
                "line": line,
                "timestamp": stamp,
                "category": category[:100],
                "kind": interval_kind,
                "interval_id": record.get("identifier") if isinstance(record.get("identifier"), str) else f"line-{line}",
            })
        elif kind == "networkActivity" and record.get("bundleID") == bundle_id:
            first = _timestamp(record.get("firstTimeStamp"))
            last = _timestamp(record.get("timeStamp"))
            domain = record.get("domain")
            hits = record.get("hits")
            if (
                not first or not last or first > last or not isinstance(domain, str)
                or not 0 < len(domain) <= 253 or isinstance(hits, bool)
                or not isinstance(hits, int) or hits < 0
            ):
                skipped_selected += 1
                continue
            domain_type = record.get("domainType")
            initiated_type = record.get("initiatedType")
            owner = record.get("domainOwner")
            network_events.append({
                "line": line,
                "first": first,
                "last": last,
                "domain": domain,
                "hits": hits,
                "domain_type": domain_type if isinstance(domain_type, int) and not isinstance(domain_type, bool) else None,
                "initiated_type": initiated_type[:100] if isinstance(initiated_type, str) else None,
                "domain_owner": owner[:253] if isinstance(owner, str) and owner else None,
            })
    if not access_events and not network_events:
        raise ValueError("No usable entries for this app. Check --list-apps and the selected bundle identifier")

    source_hash = digest.hexdigest()
    artifact_id = stable_id("artifact", "apple_app_privacy_report", source_hash)
    report = EvidenceReport(
        mode="app_privacy_report",
        target={"platform": "ios", "identifier": bundle_id, "name": None, "version": None},
        environment={"os_version": None, "device_class": None, "region": None, "permissions": None},
        artifacts=[Artifact(
            id=artifact_id,
            kind="apple_app_privacy_report",
            collection_method="user_export_from_ios_settings",
            source_name="App Privacy Report export",
            sha256=source_hash,
            sensitivity="device_activity",
            raw_retained=False,
        )],
    )

    def add_access(start: dict[str, Any] | None, end: dict[str, Any] | None) -> None:
        events = [event for event in (start, end) if event]
        lines = sorted(event["line"] for event in events)
        category = start["category"] if start else end["category"]
        observed_at = start["timestamp"] if start else end["timestamp"]
        report.observations.append(Observation(
            id=stable_id("obs", source_hash, "resource_access", lines),
            kind="resource_access",
            observed_at=observed_at,
            details={
                "category": category,
                "started_at": start["timestamp"] if start else None,
                "ended_at": end["timestamp"] if end else None,
                "interval_status": "complete" if start and end else "incomplete",
            },
            artifact_id=artifact_id,
            source_locator={"line_numbers": lines},
            collector="apple_app_privacy_report",
        ))

    intervals: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in access_events:
        intervals[event["interval_id"]].append(event)
    for events in intervals.values():
        opened: dict[str, Any] | None = None
        for event in sorted(events, key=lambda item: (item["timestamp"], 0 if item["kind"] == "intervalBegin" else 1, item["line"])):
            if event["kind"] == "intervalBegin":
                if opened:
                    add_access(opened, None)
                opened = event
            elif opened and opened["timestamp"] <= event["timestamp"] and opened["category"] == event["category"]:
                add_access(opened, event)
                opened = None
            else:
                add_access(None, event)
        if opened:
            add_access(opened, None)

    for event in network_events:
        report.observations.append(Observation(
            id=stable_id("obs", source_hash, "network_contact", event["line"]),
            kind="network_contact",
            observed_at=event["last"],
            details={
                "domain": event["domain"],
                "first_seen_at": event["first"],
                "last_seen_at": event["last"],
                "reported_contacts": event["hits"],
                "initiated_type": event["initiated_type"],
                "domain_type": event["domain_type"],
                "domain_owner": event["domain_owner"],
            },
            artifact_id=artifact_id,
            source_locator={"line_numbers": [event["line"]]},
            collector="apple_app_privacy_report",
        ))
    report.observations.sort(key=lambda item: (item.observed_at, item.kind, item.id))
    incomplete = sum(item.details.get("interval_status") == "incomplete" for item in report.observations)
    report.coverage = [
        Coverage("resource_access", "observed", "Imported app-attributed access intervals from the Apple export; absence of an event is not proof that access never occurred."),
        Coverage("network_domains", "observed", "Imported domains and Apple's aggregate contact counts for the selected app."),
        Coverage("network_request_contents", "unavailable", "The Apple export does not include request bodies, response bodies, or transmitted data."),
        Coverage("app_private_storage", "unavailable", "The Apple export does not expose the app's private files or database."),
        Coverage("source_and_binary", "unavailable", "No source project or usable app binary was supplied for this import."),
        Coverage("vulnerability_exploitation", "unavailable", "This import performs no active security tests or exploitation attempts."),
    ]
    report.notes = [
        "This report contains observations, not vulnerability findings. A domain contact does not establish what data was sent or which library initiated it.",
        "Apple's network contact counts cover its reporting period; they are not per-action measurements.",
        "The export's website context and activity from other apps are omitted from this report.",
    ]
    if incomplete:
        report.notes.append(f"{incomplete} resource-access interval(s) were incomplete in the export.")
    if skipped_selected:
        report.notes.append(f"{skipped_selected} selected-app record(s) had missing or invalid fields and were skipped.")
    return report
