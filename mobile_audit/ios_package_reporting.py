"""Readable, evidence-limited iOS package sections for the static HTML report."""

from __future__ import annotations

import html


def _escape(value: object) -> str:
    return html.escape(str(value), quote=True)


def _size(value: object) -> str:
    if not isinstance(value, int):
        return "Unknown"
    return f"{value / 1024 / 1024:.2f} MiB" if value >= 1024 * 1024 else f"{value:,} bytes"


def _table(headers: list[str], rows: list[list[object]]) -> str:
    heading = "".join(f"<th>{_escape(item)}</th>" for item in headers)
    body = "".join("<tr>" + "".join(f"<td>{_escape(value)}</td>" for value in row) + "</tr>" for row in rows)
    return f"<table><thead><tr>{heading}</tr></thead><tbody>{body}</tbody></table>" if rows else "<p>No records in this package.</p>"


def _main_bundle(bundles: list[dict[str, object]]) -> dict[str, object]:
    apps = [item for item in bundles if item.get("kind") == "app"]
    candidates = apps or bundles
    return min(candidates, key=lambda item: (str(item.get("location", "")).count("/"),
                                             len(str(item.get("location", ""))))) if candidates else {}


def render_ios_package_sections(inventory: dict[str, object]) -> str:
    if inventory.get("input_type") not in {"ipa", "app_bundle"}:
        return ""
    artifact = inventory.get("ios_package_file")
    artifact = artifact if isinstance(artifact, dict) else {}
    bundles = [item for item in inventory.get("ios_bundles", []) if isinstance(item, dict)]
    app = _main_bundle(bundles)
    digest = artifact.get("sha256") or "Unavailable for an .app directory"
    overview = _table(["Field", "Value"], [
        ["App", app.get("display_name") or artifact.get("name") or "Unknown"],
        ["Bundle identifier", app.get("bundle_id") or "Unknown"],
        ["Version / build", f"{app.get('version') or 'Unknown'} / {app.get('build') or 'Unknown'}"],
        ["Minimum iOS", app.get("minimum_ios") or "Not declared"],
        ["Package size", _size(artifact.get("size_bytes"))],
        ["File count", artifact.get("file_count", "Unknown")],
        ["SHA-256 of supplied IPA", digest],
    ])
    parts = [
        '<h2>Package overview</h2><div class="panel">'
        '<p class="notice">Static package observations are leads for testing. No A-F grade is assigned from this package alone.</p>'
        + overview + '</div>'
    ]
    acquisition = inventory.get("acquisition")
    if isinstance(acquisition, dict):
        backend = acquisition.get("backend") if isinstance(acquisition.get("backend"), dict) else {}
        requested = acquisition.get("requested") if isinstance(acquisition.get("requested"), dict) else {}
        parts.append('<h2>Package acquisition</h2><div class="panel">'
                     + _table(["Field", "Value"], [
                         ["Method", acquisition.get("method", "Unknown")],
                         ["Retrieved", acquisition.get("retrieved_at", "Unknown")],
                         ["Backend", backend.get("version") or backend.get("name") or "Unknown"],
                         ["Phone version supplied", requested.get("phone_version") or "Unknown"],
                         ["Phone/package version", acquisition.get("version_match", "unknown")],
                     ])
                     + '<p>Apple Account credentials and session files are not included in this report.</p></div>')

    kinds = {kind: sum(item.get("kind") == kind for item in bundles)
             for kind in ("app", "extension", "framework", "resource_bundle")}
    entry_points = [item for item in inventory.get("ios_entry_points", []) if isinstance(item, dict)]
    counts = ", ".join(f"{count} {kind}{'' if count == 1 else 's'}" for kind, count in kinds.items() if count)
    entry_rows = [[item.get("kind", ""), item.get("value", ""), item.get("location", "")]
                  for item in entry_points[:100]]
    bundle_rows = [[item.get("kind", ""), item.get("bundle_id", ""),
                    item.get("version") or "Unknown", item.get("minimum_ios") or "Unknown",
                    item.get("executable") or "None", item.get("location", "")]
                   for item in bundles[:100]]
    parts.append('<h2>Components and entry points</h2><div class="panel">'
                 f'<p>{_escape(counts or "No declared bundles")}; {_escape(len(entry_points))} declared entry point(s). '
                 'A declared entry point is not evidence that its handler is vulnerable.</p>'
                 '<h3>Declared bundles</h3>'
                 + _table(["Kind", "Bundle ID", "Version", "Minimum iOS", "Executable", "Info.plist"], bundle_rows)
                 + '<h3>Entry points to test</h3>'
                 + _table(["Type", "Value", "Declared in"], entry_rows) + '</div>')

    permissions = [item for item in inventory.get("ios_privacy_permissions", []) if isinstance(item, dict)]
    permission_rows = [[item.get("key", ""), "Yes" if item.get("purpose_provided") else "No", item.get("location", "")]
                       for item in permissions[:100]]
    manifests = [item for item in inventory.get("ios_privacy_manifests", []) if isinstance(item, dict)]
    manifest_rows = [[item.get("location", ""), "Yes" if item.get("tracking_declared") else "No",
                      ", ".join(item.get("collected_data_types", [])[:10]),
                      ", ".join(item.get("accessed_api_types", [])[:10]),
                      ", ".join(item.get("tracking_domains", [])[:10])]
                     for item in manifests[:50]]
    entitlements = [item for item in inventory.get("ios_entitlements", []) if isinstance(item, dict)]
    entitlement_rows = [[item.get("location", ""), "Signed executable" if item.get("signed") else "Source file",
                         ", ".join(item.get("keys", [])[:30])]
                        for item in entitlements[:50]]
    parts.append('<h2>Privacy permissions and capabilities</h2><div class="panel">'
                 '<h3>Usage descriptions</h3><p>These keys request access at runtime; their presence does not mean the user granted it.</p>'
                 + _table(["iOS permission key", "Purpose text present", "Declared in"], permission_rows)
                 + '<h3>Privacy manifests</h3><p>These are developer declarations, not proof of actual collection or tracking.</p>'
                 + _table(["File", "Tracking declared", "Collected data types", "Required-reason APIs", "Tracking domains"], manifest_rows)
                 + '<h3>Entitlement keys</h3>'
                 + _table(["Source", "Origin", "Keys"], entitlement_rows) + '</div>')

    transport = [item for item in inventory.get("ios_transport_security", []) if isinstance(item, dict)]
    transport_rows = [[item.get("location", ""),
                       "Yes" if item.get("global_arbitrary_loads") else "No",
                       "Yes" if item.get("web_arbitrary_loads") else "No",
                       "Yes" if item.get("media_arbitrary_loads") else "No",
                       ", ".join(item.get("exception_domains", [])[:20]) or "None",
                       "Yes" if item.get("nested_ats_configuration") else "No"]
                      for item in transport[:50]]
    parts.append('<h2>Network configuration</h2><div class="panel">'
                 '<p>App Transport Security declarations describe allowed transport exceptions. They do not show network traffic.</p>'
                 + _table(["Bundle", "Global HTTP exception", "Web content exception", "Media exception", "Exception domains", "Nested ATS settings"], transport_rows)
                 + '</div>')

    signatures = [item for item in inventory.get("ios_signatures", []) if isinstance(item, dict)]
    visibility = inventory.get("ios_binary_visibility")
    visibility = visibility if isinstance(visibility, dict) else {}
    main_executable = inventory.get("ios_main_executable")
    main_executable = main_executable if isinstance(main_executable, dict) else {}
    signature_rows = [[item.get("location", ""), item.get("metadata_status", "unavailable"),
                       item.get("verification", "not_performed"), item.get("team_id") or "Unknown",
                       ", ".join(item.get("authorities", [])[:3]), item.get("note", "")]
                      for item in signatures[:50]]
    binaries = [item for item in inventory.get("ios_binaries", []) if isinstance(item, dict)]
    binary_rows: list[list[object]] = []
    linked: set[str] = set()
    for item in binaries[:100]:
        arches = [arch for arch in item.get("architectures", []) if isinstance(arch, dict)]
        for arch in arches:
            linked.update(str(name) for name in arch.get("linked_libraries", []) if isinstance(name, str))
        binary_rows.append([
            item.get("location", ""), ", ".join(str(arch.get("architecture", "")) for arch in arches),
            item.get("encryption", "unknown"),
            ", ".join(str(arch.get("minimum_os", "Unknown")) for arch in arches),
            ", ".join(str(arch.get("sdk_version", "Unknown")) for arch in arches),
            ", ".join("yes" if arch.get("pie_flag") else "no" for arch in arches),
            ", ".join("yes" if arch.get("code_signature_command") else "no" for arch in arches),
            ", ".join(item.get("api_reference_categories", [])),
        ])
    libraries = sorted(linked)
    library_list = "".join(f"<li>{_escape(name)}</li>" for name in libraries[:60])
    signature_scope = (
        "IPA signature metadata comes from extracted executables; full bundle verification is not performed."
        if artifact.get("format") == "ipa" else
        "For a supplied .app directory, strict bundle verification is attempted on this Mac."
    )
    parts.append('<h2>Signing and native binaries</h2><div class="panel">'
                 f'<p>{_escape(len(binaries))} of {_escape(inventory.get("ios_binary_candidates", len(binaries)))} executable candidate(s) inspected: '
                 f'{_escape(visibility.get("not_encrypted", 0))} readable, '
                 f'{_escape(visibility.get("encrypted", 0))} encrypted executable(s), '
                 f'{_escape(visibility.get("unknown", 0))} undetermined, '
                 f'{_escape(visibility.get("uninspected", 0))} uninspected. '
                 f'{_escape(len(signatures))} of {_escape(inventory.get("ios_signature_candidates", len(signatures)))} executable signature candidate(s) checked.</p>'
                 f'<p>Main app executable: {_escape(main_executable.get("encryption", "unknown"))} '
                 f'({_escape(main_executable.get("location", "not identified"))}).</p>'
                 f'<p>{_escape(signature_scope)} '
                 'PIE and code-signature entries are Mach-O header facts, not proof of exploitability.</p>'
                 + _table(["Executable or bundle", "Metadata", "Verification", "Team ID", "Authorities", "Note"], signature_rows)
                 + '<h3>Binary visibility</h3>'
                 + _table(["Binary", "Architectures", "Encryption", "Minimum OS", "SDK", "PIE flag", "Signature command", "Readable API clues"], binary_rows)
                 + f'<h3>Linked libraries ({_escape(len(libraries))})</h3>'
                 + (f'<ul>{library_list}</ul>' if libraries else '<p>No linked libraries recovered from the inspected Mach-O headers.</p>')
                 + (f'<p>Showing the first 60 of {_escape(len(libraries))}.</p>' if len(libraries) > 60 else '')
                 + '</div>')
    assets = [item for item in inventory.get("ios_plaintext_code_assets", []) if isinstance(item, dict)]
    parts.append('<h2>Readable packaged assets</h2><div class="panel">'
                 f'<p>{_escape(len(assets))} source-like or web asset(s) inventoried. '
                 'Readable assets can be extracted for review; encrypted native code cannot be reconstructed by this scan.</p>'
                 + _table(["Path", "Size"], [[item.get("location", ""), _size(item.get("size"))]
                                             for item in assets[:50]]) + '</div>')
    return "".join(parts)
