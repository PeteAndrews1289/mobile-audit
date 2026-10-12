"""Conservative checks for JavaScript and TypeScript shipped with iOS apps."""

from __future__ import annotations

import re

from .models import Finding, Report


_PATTERNS = [
    ("IOS-WEB-DYNAMIC-CODE", re.compile(r"\b(?:eval\s*\(|new\s+Function\s*\()"),
     "Dynamic JavaScript execution needs input review", "low",
     "Dynamic code execution call found; its input and reachability are unverified",
     "Avoid executing constructed code. If input can come from a link, message, or network response, validate the path and replace dynamic execution."),
    ("IOS-WEB-HTML-INJECTION", re.compile(r"\b(?:dangerouslySetInnerHTML|\.innerHTML\s*=|document\.write\s*\()"),
     "HTML injection sink needs input review", "low",
     "HTML-writing API found; whether untrusted content reaches it is unverified",
     "Render untrusted content as text or apply context-appropriate sanitization after tracing its source."),
    ("IOS-WEB-CLEARTEXT-URL", re.compile(r"(?i)[\"'`]http://(?!localhost\b|127\.0\.0\.1\b|\[::1\])[^\s\"'`]{3,}"),
     "Plain HTTP URL shipped in web code", "medium",
     "HTTP URL literal found (value redacted); runtime use and data sensitivity are unverified",
     "If the endpoint is used for app traffic, migrate it to HTTPS and remove the cleartext route."),
    ("IOS-WEB-BROWSER-STORAGE", re.compile(r"(?is)\blocalStorage\.setItem\s*\(\s*[\"'`][^\"'`]{0,80}(?:token|password|secret|credential)[^\"'`]{0,80}[\"'`]"),
     "Possible sensitive value stored in WebView local storage", "medium",
     "Sensitive-looking storage key found (value redacted); actual stored data is unverified",
     "Check the value and threat model; use an appropriate protected store for credentials rather than WebView local storage."),
]


def _first_match(rule_id: str, pattern: re.Pattern[str], text: str) -> re.Match[str] | None:
    if rule_id != "IOS-WEB-CLEARTEXT-URL":
        return pattern.search(text)
    for match in pattern.finditer(text):
        # Tizen systeminfo.getCapability takes URI-shaped capability IDs. These
        # strings are not network destinations, including in bundled OM SDK JS.
        prefix = text[max(0, match.start() - 80):match.start()]
        if re.search(r"\bgetCapability\s*\(\s*$", prefix):
            continue
        return match
    return None


def scan_web_code(text: str, location: str, report: Report) -> None:
    """Emit at most one lead per pattern per file; never copy surrounding source."""
    for rule_id, pattern, title, severity, evidence, recommendation in _PATTERNS:
        match = _first_match(rule_id, pattern, text)
        if match is None:
            continue
        line = text.count("\n", 0, match.start()) + 1
        report.add(Finding(
            rule_id, title, "ios", severity, "low", f"{location}:{line}", evidence,
            recommendation, "MASVS-PLATFORM-1", None,
        ))
    report.coverage.append("Bundled JavaScript and TypeScript source patterns")
