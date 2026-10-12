"""Bounded source patterns for Flutter's Dart application code.

These are leads for review, not proofs of reachability or exploitability.
"""

from __future__ import annotations

import re

from .models import Finding, Report
from .sensitive_names import sensitive_storage_key


_PREF_WRITE = re.compile(r"\b[A-Za-z_]\w*\.set(?:String|Bool|Int|Double|StringList)\s*\(\s*(?:(['\"])([^'\"]{1,100})\1|([A-Za-z_]\w*))")
_KEY_CONST = re.compile(r"\b(?:static\s+)?const\s+String\s+([A-Za-z_]\w*)\s*=\s*(['\"])([^'\"]{1,100})\2")
_HTTP_URI = re.compile(r"\bUri\.parse\s*\(\s*(['\"])http://(?!localhost(?:[:/]|$)|127\.0\.0\.1(?:[:/]|$)|10\.0\.2\.2(?:[:/]|$))[^'\"\r\n]{1,200}\1")
_STATIC_CRYPTO_KEY = re.compile(r"\b(?:[A-Za-z_]\w*\.)?Key\.fromUtf8\s*\(\s*(['\"])([^'\"\r\n]{8,128})\1")
_SENSITIVE_LOG = re.compile(r"\b(?:debugPrint|print|log)\s*\(\s*(['\"])[^'\"\r\n]{0,200}\$(?:\{)?(?:pin|password|token|secret|credential|cvv|cardNo|cardNumber)\b", re.IGNORECASE)
_AES_ECB = re.compile(r"\bAES\s*\([^;\r\n]{0,300}\bmode\s*:\s*(?:[A-Za-z_]\w*\.)?AESMode\.ecb\b")


def scan_dart_code(text: str, location: str, report: Report) -> None:
    has_preferences = "SharedPreferences" in text
    key_constants = {match.group(1): match.group(3) for match in _KEY_CONST.finditer(text)}
    in_block_comment = False
    for number, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if in_block_comment:
            if "*/" in stripped:
                in_block_comment = False
            continue
        if stripped.startswith("/*"):
            in_block_comment = "*/" not in stripped
            continue
        if not stripped or stripped.startswith(("//", "*")):
            continue
        where = f"{location}:{number}"
        if has_preferences:
            match = _PREF_WRITE.search(line)
            key = (match.group(2) or key_constants.get(match.group(3), "")) if match else ""
            if key and sensitive_storage_key(key):
                report.add(Finding(
                    "MOBILE-FLUTTER-PREFS-SENSITIVE", "Possible sensitive value in Flutter preferences",
                    "mobile", "medium", "medium", where,
                    f"SharedPreferences write to key {key!r}; value redacted",
                    "Confirm the value and use platform secure storage for secrets rather than SharedPreferences.",
                    "MASVS-STORAGE-1", "MASWE-0001",
                ))
        if _HTTP_URI.search(line):
            report.add(Finding(
                "MOBILE-FLUTTER-CLEARTEXT-URL", "Cleartext URL in Flutter request path",
                "mobile", "medium", "medium", where,
                "Uri.parse uses an HTTP URL; destination redacted",
                "Check whether the request is reachable and carries sensitive data; use HTTPS and enforce server identity validation.",
                "MASVS-NETWORK-1", "MASWE-0026",
            ))
        match = _STATIC_CRYPTO_KEY.search(line)
        if match and "$" not in match.group(2):
            report.add(Finding(
                "MOBILE-FLUTTER-STATIC-CRYPTO-KEY", "Cryptographic key literal in Flutter source",
                "mobile", "medium", "high", where,
                "Key.fromUtf8 receives a fixed literal (value redacted)",
                "Determine what this key protects; avoid relying on a key shared across app installations for confidential data.",
                "MASVS-STORAGE-1", "MASWE-0004",
            ))
        if _SENSITIVE_LOG.search(line):
            report.add(Finding(
                "MOBILE-FLUTTER-SENSITIVE-LOG", "Possible sensitive value in Flutter log",
                "mobile", "medium", "medium", where,
                "Logging call interpolates a sensitive variable (value redacted)",
                "Remove sensitive values from logs and review release build logging behavior.",
                "MASVS-STORAGE-2", "MASWE-0005",
            ))
        if _AES_ECB.search(line):
            report.add(Finding(
                "MOBILE-FLUTTER-WEAK-CRYPTO", "AES ECB mode in Flutter source",
                "mobile", "medium", "high", where,
                "AESMode.ecb selected for encryption; security impact depends on the data being protected",
                "Use an authenticated encryption mode such as AES-GCM with a unique nonce for each encryption.",
                "MASVS-CRYPTO-1", "MASWE-0007",
            ))
    report.coverage.append("Flutter Dart source patterns")
