"""Conservative pairs of clues that merit an attack-path investigation.

These patterns match co-presence only. They do not trace data flow, establish
that both clues belong to one feature, or verify an exploit.
"""

from __future__ import annotations

from dataclasses import dataclass


_LINK_ENTRIES = frozenset({"custom_url_scheme", "universal_link_domain",
                           "external_url_handler", "universal_link_handler"})
_WEB_SINKS = frozenset({"IOS-WEB-DYNAMIC-CODE", "IOS-WEB-HTML-INJECTION"})


@dataclass(frozen=True)
class PathPattern:
    kind: str
    title: str
    start_kinds: frozenset[str]
    target_kinds: frozenset[str]
    start_role: str
    target_role: str
    attacker_control: str
    possible_impact: str
    missing_link: str
    next_test: str
    disconfirming_result: str
    remediation: str


PATH_PATTERNS = (
    PathPattern(
        "external_link_web_sink_review", "Trace external links into web code",
        _LINK_ENTRIES, _WEB_SINKS, "external_link_entry", "web_code_sink",
        "A controlled link and its parameters",
        "Script execution or content injection if link data reaches a web sink",
        "No path from a link parameter to the bundled web-code sink has been verified.",
        "Trace the link handler to the bundled web code, then pass a benign marker through a controlled link and observe whether it reaches the sink.",
        "The handler does not pass link-controlled data to the sink, or the data is safely handled before rendering or execution.",
        "If a path is confirmed, validate link data and replace unsafe dynamic code or HTML writes.",
    ),
    PathPattern(
        "document_deserializer_review", "Trace imported documents into a deserializer",
        frozenset({"document_type"}), frozenset({"object_deserialization"}),
        "document_entry", "deserializer_reference",
        "A benign document opened by the user",
        "Unexpected app behavior if document bytes reach an unsafe parser",
        "No path from the declared document import to the referenced deserializer has been verified.",
        "Trace the document import handler to the deserializer; use a small, benign malformed document in scope and record the result.",
        "The import path never uses this deserializer, or it rejects the test document before unsafe parsing.",
        "If a path is confirmed, restrict accepted types and validate document structure before parsing.",
    ),
    PathPattern(
        "external_link_auth_boundary_review", "Trace external links through account checks",
        _LINK_ENTRIES, frozenset({"MOBILE-AUTH-LITERAL-CHECK"}),
        "external_link_entry", "client_auth_comparison",
        "A link and its parameters, opened under controlled account states",
        "A protected action could be reached if the link handler relies on a fixed client-side comparison without server authorization",
        "No path from the link handler to this comparison or a protected action has been verified.",
        "Trace the link handler through the authentication branch; compare signed-out and second-account outcomes with benign test links and data you control.",
        "The link cannot reach the branch, or the protected action is denied by server authorization regardless of the comparison.",
        "If a path is confirmed, enforce authentication and object authorization at the protected service or action.",
    ),
    PathPattern(
        "http_exception_request_review", "Trace cleartext request through ATS exception",
        frozenset({"IOS-ATS-GLOBAL"}),
        frozenset({"IOS-CLEARTEXT-URL", "MOBILE-FLUTTER-CLEARTEXT-URL", "IOS-WEB-CLEARTEXT-URL"}),
        "transport_exception", "cleartext_request_construction",
        "A network path carrying a request from the app",
        "Sensitive request data could be exposed or altered if the constructed HTTP URL is used under the global exception",
        "No evidence shows the URL is requested at runtime, uses the exception, or carries sensitive data.",
        "Exercise the feature associated with the URL using a test account; record whether a real HTTP request occurs, whether ATS permits it, and what data class it carries.",
        "The URL is unused or blocked, or the reachable request carries no sensitive data.",
        "Remove the global exception and use HTTPS for any reachable app traffic.",
    ),
    PathPattern(
        "web_content_native_bridge_review", "Trace web content into the native bridge",
        _WEB_SINKS, frozenset({"webview_native_bridge"}),
        "web_code_sink", "native_bridge_reference",
        "Web content influenced by a controlled page, link, or message",
        "Untrusted content could invoke privileged native behavior if it shares a WebView with an exposed bridge",
        "No evidence shows the web sink and native bridge run in the same WebView or that untrusted content can call a privileged bridge method.",
        "Identify the WebView and allowed origins for both clues; use a benign controlled message to test whether the content can reach a bridge method.",
        "The code runs in a different WebView, or the bridge rejects messages from the controlled content.",
        "Restrict bridge methods and origins, and validate every message before native actions.",
    ),
)

CROSS_SIGNAL_KINDS = frozenset(pattern.kind for pattern in PATH_PATTERNS)
