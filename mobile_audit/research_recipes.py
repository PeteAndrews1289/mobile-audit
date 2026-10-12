"""Controlled follow-up plans for static leads in an iOS research scan.

The plans describe hypotheses, not verified data flow or exploitability. They
never interpolate matched source text, URLs, or credential values.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class TestRecipe:
    attacker_control: str
    possible_impact: str
    next_test: str
    disconfirming_result: str


_GENERIC = TestRecipe(
    "Depends on the input path and target feature",
    "Requires validation of reachability and security impact",
    "Trace the matched code or setting to a reachable feature, then test the suspected behavior with controlled inputs.",
    "The matched path is unreachable in the assessed build, or the controlled test shows no security boundary is crossed.",
)

_CLEARTEXT = TestRecipe(
    "A network endpoint or network path, if the feature accepts one",
    "Sensitive traffic could be exposed or changed if a reachable request uses cleartext HTTP",
    "Trace the URL into an actual request in a controlled session; record whether ATS blocks it and whether any sensitive data travels over HTTP.",
    "The URL is unused in the assessed build, or the request is blocked before sensitive data is sent.",
)

_STATIC_KEY = TestRecipe(
    "A copy of the distributed app or access to data protected by its cryptography",
    "A shared key could let someone read or forge protected app data if the same key is used in production",
    "Trace the literal to the encryption or authentication call and identify what production data it protects; compare two controlled installations.",
    "The literal is test-only or never protects production data, or each installation uses a separate protected key.",
)

_SENSITIVE_STORAGE = TestRecipe(
    "Access to a device backup, app container, or another exposure path that must be established",
    "A secret or personal value could be disclosed if it is stored without suitable protection",
    "Use a test account and inspect the value written by the matched path; record its sensitivity and the actual storage protection.",
    "The matched key holds no sensitive value in the assessed release, or the suspected storage path is never reached.",
)

_RECIPES: dict[str, TestRecipe] = {
    "IOS-ATS-GLOBAL": TestRecipe(
        "A network path reached by the app, if cleartext traffic occurs",
        "Cleartext traffic could expose or alter data when a reachable feature uses HTTP",
        "Confirm this is the release configuration, then exercise network features with a controlled account and identify any HTTP requests and their data sensitivity.",
        "The exception is absent from the release build, or no tested reachable feature sends sensitive cleartext traffic.",
    ),
    "IOS-ATS-NESTED-CONFIG": TestRecipe(
        "A network path affected by the actual ATS policy",
        "Intended domain protections may not apply if their keys are nested incorrectly",
        "Compare the shipped plist with Apple's ATS key hierarchy and test effective behavior for an intended domain in a controlled setup.",
        "The nested dictionary is unrelated app data, or the effective policy provides the intended protection.",
    ),
    "IOS-ATS-DOMAIN": TestRecipe(
        "Traffic to the exception domain, if the app uses it",
        "Data sent to the allowed domain could be exposed or altered if the app uses HTTP",
        "Exercise the feature associated with the exception domain in a controlled session; record whether it actually uses HTTP and carries sensitive data.",
        "The domain exception is unused in the assessed build, or no sensitive HTTP request occurs.",
    ),
    "IOS-ATS-WEB": TestRecipe(
        "A web resource loaded into the app's WebView, if its origin is controllable",
        "Insecure web content could expose session data or influence WebView behavior",
        "Identify reachable WebView destinations and check whether a controlled page loads active resources over HTTP.",
        "The release WebView never loads insecure active content on the tested path.",
    ),
    "IOS-FILE-SHARING": TestRecipe(
        "A person with access to the device's exposed Documents files",
        "Private app files could be copied if they are placed in the shared Documents directory",
        "With a test account, list files exposed through the app's file-sharing interface after normal use; check whether any are private.",
        "Only user-intended shareable files appear in the exposed directory.",
    ),
    "IOS-DEBUG-ENTITLEMENT": TestRecipe(
        "Access to the distributed app on a device where debugging is possible",
        "A release app may permit debugging or inspection that its production build should restrict",
        "Inspect the signed entitlements of the exact distributed build and compare them with the source entitlement file.",
        "The signed release app has no debugging entitlement; the match came only from a development configuration.",
    ),
    "IOS-STATIC-CRYPTO-KEY": _STATIC_KEY,
    "MOBILE-FLUTTER-STATIC-CRYPTO-KEY": _STATIC_KEY,
    "IOS-STATIC-CRYPTO-IV": TestRecipe(
        "Repeated encrypted values, if they can be observed or supplied",
        "Nonce or IV reuse could weaken confidentiality or integrity for a mode that requires unique values",
        "Trace the literal into an encryption call, then compare IV or nonce values across two controlled encryptions of test data.",
        "A fresh value is generated for every relevant encryption, or the literal never reaches encryption.",
    ),
    "IOS-CLEARTEXT-URL": _CLEARTEXT,
    "MOBILE-FLUTTER-CLEARTEXT-URL": _CLEARTEXT,
    "IOS-WEB-CLEARTEXT-URL": _CLEARTEXT,
    "IOS-KEYCHAIN-ACCESS": TestRecipe(
        "A device state in which stored items become available",
        "A sensitive item could be available under weaker device-state conditions than intended",
        "Identify the item stored with this accessibility class and verify its required availability using a test account and the assessed release build.",
        "No sensitive item uses the matched class, or the availability matches the app's documented protection needs.",
    ),
    "IOS-WEAK-CRYPTO": TestRecipe(
        "The data supplied to the matched cryptographic operation, if externally influenced",
        "A security-sensitive hash or encryption use could allow weak protection of app data",
        "Trace the operation's purpose and input; determine whether it protects security-sensitive data or is only a nonsecurity checksum.",
        "The matched operation is used only for a nonsecurity checksum or unreachable legacy path.",
    ),
    "MOBILE-FLUTTER-WEAK-CRYPTO": TestRecipe(
        "The plaintext encrypted by the matched code, if an attacker can observe ciphertext",
        "Repeated plaintext patterns could remain visible if AES ECB protects real data",
        "Trace the ECB call to its data and output; compare controlled repeated test inputs and document what the ciphertext protects.",
        "The call is unused in the release build or never protects sensitive production data.",
    ),
    "IOS-USERDEFAULTS-SENSITIVE": _SENSITIVE_STORAGE,
    "MOBILE-FLUTTER-PREFS-SENSITIVE": _SENSITIVE_STORAGE,
    "IOS-WEB-BROWSER-STORAGE": _SENSITIVE_STORAGE,
    "IOS-CUSTOM-TRUST": TestRecipe(
        "A network endpoint or certificate presented to the app in an authorized test setup",
        "The app could accept an untrusted server identity if the custom path bypasses validation",
        "Trace the trust callback, then check whether the assessed build rejects an invalid certificate in a controlled environment.",
        "The invalid certificate is rejected and platform trust validation remains required.",
    ),
    "IOS-WEB-DYNAMIC-CODE": TestRecipe(
        "JavaScript input, if a link, message, or network response reaches the call",
        "Untrusted input could execute script with the WebView's privileges",
        "Trace the call's argument to its sources; use a benign marker from a controlled source to check whether input reaches execution.",
        "The argument is a fixed trusted string, or controlled untrusted input never reaches the call.",
    ),
    "IOS-WEB-HTML-INJECTION": TestRecipe(
        "Text or markup supplied through a reachable web or app input",
        "Untrusted markup could change the rendered page or invoke WebView behavior",
        "Trace the HTML-writing value to its sources; use benign markup from a controlled input and observe whether it is rendered as markup or text.",
        "Controlled untrusted markup is treated as text or cannot reach the sink.",
    ),
    "MOBILE-FLUTTER-SENSITIVE-LOG": TestRecipe(
        "Access to diagnostic logs, if they are retained or exported",
        "A sensitive value could be exposed through release logging",
        "Use a test account and trigger the matched path in a release build; inspect only the resulting test logs for sensitive values.",
        "The release build does not log the value, or the interpolated value is not sensitive.",
    ),
    "MOBILE-PRIVATE-KEY": TestRecipe(
        "A copy of the distributed app or source artifact containing the key",
        "A production private key could be copied and used outside the app",
        "Determine whether the matched key ships in a release artifact, who owns it, and whether it authenticates production operations.",
        "The key is an unused test fixture and is absent from every distributed build.",
    ),
    "MOBILE-HARDCODED-SECRET": TestRecipe(
        "A copy of the distributed app or source artifact containing the value",
        "A live credential could be extracted and used outside its intended client context",
        "Identify the credential owner and scope without copying its value into the report; confirm whether it ships and remains active.",
        "The value is a nonsecret placeholder or is absent or inactive in the distributed build.",
    ),
    "MOBILE-AUTH-LITERAL-CHECK": TestRecipe(
        "An authentication-related input, if a user can reach this comparison",
        "A fixed value could bypass access control if the branch grants access and the server does not recheck it",
        "Trace both branches of the comparison; with controlled accounts, check whether the literal grants or only denies access and whether the server enforces authorization.",
        "The branch only rejects an input, or server authorization blocks the protected action regardless of the comparison.",
    ),
}


# These are possible paths through a security boundary, not reproduction steps.
# In particular, a configuration or API-name match does not show that the path
# is reachable in the distributed app.
_ATTACK_SCENARIOS: dict[str, str] = {
    "IOS-ATS-GLOBAL": "If a reachable feature sends sensitive data over HTTP, someone able to observe or alter that network path could read or change the traffic. The report does not show that such a request occurs.",
    "IOS-ATS-NESTED-CONFIG": "If intended ATS domain settings are ignored because of their nesting, a reachable HTTP request might remain allowed where the developer expected stricter rules. Effective behavior and request sensitivity need testing.",
    "IOS-ATS-DOMAIN": "If the app uses the exception domain for sensitive HTTP requests, someone on that network path could observe or change those requests. Actual use of the exception needs testing.",
    "IOS-ATS-WEB": "If the WebView loads active content over HTTP, someone able to alter its delivery could change what the WebView renders. Access to app data or native functions is not established.",
    "IOS-FILE-SHARING": "If private files are written to the shared Documents directory, a person with access to the device's file-sharing surface could copy them. The report does not identify the files stored there.",
    "IOS-DEBUG-ENTITLEMENT": "If the distributed build retains a debugging entitlement, someone with device access and debugging capability could inspect app runtime state. The exact signed release build must be checked.",
    "IOS-STATIC-CRYPTO-KEY": "If the same embedded key protects production data across installations, someone who obtains a copy of the app could recover the key and use it against that protected data. Key use and scope are unverified.",
    "MOBILE-FLUTTER-STATIC-CRYPTO-KEY": "If the same embedded key protects production data across installations, someone who obtains a copy of the app could recover the key and use it against that protected data. Key use and scope are unverified.",
    "IOS-STATIC-CRYPTO-IV": "If encryption reuses this fixed IV or nonce in a mode requiring a fresh value, repeated protected data could lose confidentiality or integrity. The report does not establish that the literal reaches encryption.",
    "IOS-CLEARTEXT-URL": "If the app sends sensitive requests to this HTTP endpoint, someone on the network path could read or alter them. The scanner found a URL construction, not a completed request.",
    "MOBILE-FLUTTER-CLEARTEXT-URL": "If the app sends sensitive requests to this HTTP endpoint, someone on the network path could read or alter them. The scanner found a URL construction, not a completed request.",
    "IOS-WEB-CLEARTEXT-URL": "If this HTTP URL is loaded by a reachable app feature, someone on the network path could change the returned content. The shipped literal alone does not show a request occurred.",
    "IOS-KEYCHAIN-ACCESS": "If a sensitive item uses this accessibility class under a device state that should keep it protected, a person with access in that state might retrieve it. The stored item and required protection are unknown.",
    "IOS-WEAK-CRYPTO": "If the matched operation protects authentication, integrity, or confidential data, its weak algorithm could undermine that protection. A nonsecurity checksum would not support this attack path.",
    "MOBILE-FLUTTER-WEAK-CRYPTO": "If AES ECB protects production data, someone who can observe repeated ciphertext could infer repeated plaintext patterns. The protected data and observation path are unverified.",
    "IOS-USERDEFAULTS-SENSITIVE": "If a real secret is written to the matched preferences key, someone who gains access to that app data through a separately established path could read it. The value and access path need confirmation.",
    "MOBILE-FLUTTER-PREFS-SENSITIVE": "If a real secret is written to the matched preferences key, someone who gains access to that app data through a separately established path could read it. The value and access path need confirmation.",
    "IOS-WEB-BROWSER-STORAGE": "If the WebView stores a live credential here and untrusted web content can access that storage, the content could read it. Both the stored value and content access need confirmation.",
    "IOS-CUSTOM-TRUST": "If the custom trust callback accepts an invalid server identity, someone able to present that identity on the app's network path could impersonate the service and observe or alter traffic. Acceptance is unverified.",
    "IOS-WEB-DYNAMIC-CODE": "If a link, message, or response controls the string passed to dynamic JavaScript execution, its sender could run script in that WebView context. No input-to-sink path has been shown.",
    "IOS-WEB-HTML-INJECTION": "If untrusted text reaches this HTML-writing call without safe handling, its sender could alter rendered content or script behavior in the WebView. Reachability and sanitization are unknown.",
    "MOBILE-FLUTTER-SENSITIVE-LOG": "If the release app logs real secrets and those logs are retained or shared, a person with access to the logs could read them. Release logging behavior is unverified.",
    "MOBILE-PRIVATE-KEY": "If a production private key ships in the app, anyone who obtains the distributed artifact could copy it and use the authority that key grants. The key's role and release inclusion need confirmation.",
    "MOBILE-HARDCODED-SECRET": "If a live credential ships in the app, someone who obtains the distributed artifact could recover it and use its granted access outside the app. The credential's validity and scope are unverified.",
    "MOBILE-AUTH-LITERAL-CHECK": "If this comparison grants access based on a fixed value and no server check enforces authorization, someone able to submit that value could reach a protected action. The branch direction and server behavior are unknown.",
    "custom_url_scheme": "If the app acts on parameters from a custom link without checking the current account, a sender could use a link to request an unauthorized action. The handler behavior is untested.",
    "universal_link_domain": "If the app acts on a universal link without rechecking the current account, a sender could use a link to request protected content or an action. The handler behavior is untested.",
    "document_type": "If the app imports a file supplied by another party and its parser mishandles that content, opening the file could trigger unintended behavior. No parser flaw is established by the declaration.",
    "external_url_handler": "If an external link parameter reaches a protected app action without authorization, a sender could use a crafted link to invoke that action. An API-name reference does not establish a reachable handler.",
    "universal_link_handler": "If a universal link parameter reaches protected content without authorization, a sender could use a link to request that content. An API-name reference does not establish a reachable handler.",
    "webview_native_bridge": "If untrusted WebView content can call a privileged native bridge method, a content sender could ask the app to perform that method's action. Allowed origins and bridge permissions are unknown.",
    "custom_server_trust": "If the app accepts an invalid server identity, someone able to present that identity on its network path could impersonate the service. An API reference alone does not show that trust is bypassed.",
    "object_deserialization": "If an app entry point passes untrusted serialized content to this API without safe type and structure checks, its sender could trigger unintended parsing behavior. The input path is unverified.",
    "external_link_web_sink_review": "If a link parameter flows into the bundled dynamic-code or HTML-writing call, a link sender could influence WebView content. The two clues coexist, but no data flow has been traced.",
    "document_deserializer_review": "If an imported document reaches the deserializer without validation, its sender could trigger unintended parsing behavior when the app opens it. The two clues coexist, but no data flow has been traced.",
    "external_link_auth_boundary_review": "If a link reaches a protected action and the app relies on a fixed client-side comparison without a server authorization check, its sender could request an action outside the current account's rights. No such path has been traced.",
    "http_exception_request_review": "If the constructed HTTP URL is used for sensitive traffic under the global ATS exception, someone on the network path could read or alter that traffic. No runtime request or sensitive payload has been observed.",
    "web_content_native_bridge_review": "If untrusted web content reaches a WebView with an exposed native bridge, its sender could invoke a privileged app method. The two code clues have not been linked to one WebView.",
}


def recipe_for(rule_id: str) -> TestRecipe:
    """Return a safe, literal-free test plan for a static rule."""
    return _RECIPES.get(rule_id, _GENERIC)


def attack_scenario_for(kind: str) -> str | None:
    """Return a conditional, literal-free use case when the evidence supports one."""
    return _ATTACK_SCENARIOS.get(kind)
