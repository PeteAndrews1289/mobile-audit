"""Bounded, read-only Mach-O visibility checks for iOS app packages.

The scanner reads load commands and selected references. It does not decrypt,
disassemble, execute, or infer that a referenced API is actually reachable.
"""

from __future__ import annotations

import struct
from typing import BinaryIO


MAX_HEADER_BYTES = 8 * 1024 * 1024
MAX_REFERENCE_BYTES = 256 * 1024 * 1024
MAX_LOAD_COMMANDS = 4096

_THIN_MAGICS = {
    b"\xce\xfa\xed\xfe": ("<", False),
    b"\xcf\xfa\xed\xfe": ("<", True),
    b"\xfe\xed\xfa\xce": (">", False),
    b"\xfe\xed\xfa\xcf": (">", True),
}
_FAT_MAGICS = {
    b"\xca\xfe\xba\xbe": (">", False),
    b"\xbe\xba\xfe\xca": ("<", False),
    b"\xca\xfe\xba\xbf": (">", True),
    b"\xbf\xba\xfe\xca": ("<", True),
}
_CPU_NAMES = {
    7: "x86", 0x01000007: "x86_64",
    12: "arm", 0x0100000C: "arm64",
}
_DYLIB_COMMANDS = {0x0C, 0x18, 0x1F, 0x20, 0x23}
_BUILD_PLATFORMS = {1: "macos", 2: "ios", 3: "tvos", 4: "watchos", 6: "mac_catalyst", 7: "ios_simulator"}
_REFERENCES = {
    "external_url_handler": (b"application:openURL:options:", b"scene:openURLContexts:"),
    "universal_link_handler": (b"continueUserActivity:restorationHandler:",),
    "webview_native_bridge": (b"WKScriptMessageHandler", b"userContentController:didReceiveScriptMessage:"),
    "custom_server_trust": (b"SecTrustSetExceptions", b"didReceiveAuthenticationChallenge:"),
    "object_deserialization": (b"NSKeyedUnarchiver", b"unarchiveObjectWithData:"),
}


def _thin(prefix: bytes, offset: int) -> dict[str, object]:
    if offset < 0 or offset + 4 > len(prefix):
        return {"architecture": "unknown", "encryption": "unknown", "note": "Mach-O header not in scan window"}
    spec = _THIN_MAGICS.get(prefix[offset:offset + 4])
    if spec is None:
        return {"architecture": "unknown", "encryption": "unknown", "note": "Unrecognized Mach-O header"}
    endian, is_64 = spec
    header_size = 32 if is_64 else 28
    if offset + header_size > len(prefix):
        return {"architecture": "unknown", "encryption": "unknown", "note": "Truncated Mach-O header"}
    cpu, _, _, command_count, command_bytes, flags = struct.unpack_from(endian + "6I", prefix, offset + 4)
    architecture = _CPU_NAMES.get(cpu, f"cpu-{cpu}")
    result: dict[str, object] = {
        "architecture": architecture,
        "encryption": "not_marked_encrypted",
        "linked_libraries": [],
        "pie_flag": bool(flags & 0x200000),
        "code_signature_command": False,
    }
    if command_count > MAX_LOAD_COMMANDS or command_bytes > MAX_HEADER_BYTES:
        result.update(encryption="unknown", note="Mach-O load-command limits exceeded")
        return result
    cursor = offset + header_size
    end = cursor + command_bytes
    if end > len(prefix):
        result.update(encryption="unknown", note="Load commands extend beyond scan window")
        return result
    libraries: list[str] = []
    for _ in range(command_count):
        if cursor + 8 > end:
            result.update(encryption="unknown", note="Truncated load command")
            return result
        command, size = struct.unpack_from(endian + "2I", prefix, cursor)
        if size < 8 or cursor + size > end:
            result.update(encryption="unknown", note="Invalid load-command size")
            return result
        kind = command & 0x7FFFFFFF
        if kind in {0x21, 0x2C} and size >= 20:
            _, _, cryptid = struct.unpack_from(endian + "3I", prefix, cursor + 8)
            result["encryption"] = "encrypted" if cryptid else "not_encrypted"
        elif kind == 0x1D:
            result["code_signature_command"] = True
        elif kind == 0x32 and size >= 24:
            platform, minimum, sdk = struct.unpack_from(endian + "3I", prefix, cursor + 8)
            result["build_platform"] = _BUILD_PLATFORMS.get(platform, f"platform-{platform}")
            result["minimum_os"] = _version(minimum)
            result["sdk_version"] = _version(sdk)
        elif kind == 0x25 and size >= 16:
            minimum, sdk = struct.unpack_from(endian + "2I", prefix, cursor + 8)
            result["build_platform"] = "ios"
            result["minimum_os"] = _version(minimum)
            result["sdk_version"] = _version(sdk)
        elif kind in _DYLIB_COMMANDS and size >= 24:
            name_offset = struct.unpack_from(endian + "I", prefix, cursor + 8)[0]
            if 24 <= name_offset < size and len(libraries) < 100:
                raw = prefix[cursor + name_offset:cursor + size].split(b"\0", 1)[0]
                if raw:
                    libraries.append(raw.decode("utf-8", errors="replace")[:250])
        cursor += size
    result["linked_libraries"] = sorted(set(libraries))
    return result


def _version(value: int) -> str:
    return f"{(value >> 16) & 0xFFFF}.{(value >> 8) & 0xFF}.{value & 0xFF}"


def inspect_macho(prefix: bytes, file_size: int) -> dict[str, object]:
    """Return per-architecture encryption and library metadata from a bounded prefix."""
    if len(prefix) < 4:
        return {"format": "unknown", "size": file_size, "architectures": [], "encryption": "unknown"}
    magic = prefix[:4]
    if magic in _THIN_MAGICS:
        arches = [_thin(prefix, 0)]
        form = "Mach-O"
    elif magic in _FAT_MAGICS:
        endian, is_64 = _FAT_MAGICS[magic]
        if len(prefix) < 8:
            arches = []
        else:
            count = struct.unpack_from(endian + "I", prefix, 4)[0]
            entry_size = 32 if is_64 else 20
            if count > 32 or 8 + count * entry_size > len(prefix):
                arches = []
            else:
                arches = []
                for index in range(count):
                    start = 8 + index * entry_size
                    slice_offset = struct.unpack_from(endian + ("Q" if is_64 else "I"), prefix, start + 8)[0]
                    arches.append(_thin(prefix, slice_offset))
        form = "Fat Mach-O"
    else:
        return {"format": "unknown", "size": file_size, "architectures": [], "encryption": "unknown"}
    statuses = {arch["encryption"] for arch in arches}
    if not statuses or "unknown" in statuses:
        encryption = "unknown"
    elif "encrypted" in statuses:
        encryption = "encrypted" if statuses == {"encrypted"} else "mixed"
    else:
        encryption = "not_encrypted"
    return {"format": form, "size": file_size, "architectures": arches, "encryption": encryption}


def scan_api_references(stream: BinaryIO, file_size: int) -> list[str]:
    """Find bounded API-name references; return category names, never nearby values."""
    if file_size > MAX_REFERENCE_BYTES:
        return []
    pending = {kind: set(values) for kind, values in _REFERENCES.items()}
    found: set[str] = set()
    overlap = b""
    remaining = min(file_size, MAX_REFERENCE_BYTES)
    while remaining > 0 and (chunk := stream.read(min(1024 * 1024, remaining))):
        remaining -= len(chunk)
        window = overlap + chunk
        for kind, values in pending.items():
            for value in tuple(values):
                if value in window:
                    values.remove(value)
                    found.add(kind)
        overlap = window[-128:]
        if all(not values for values in pending.values()):
            break
    return sorted(found)
