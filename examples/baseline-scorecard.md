# Mobile Audit baseline scorecard

This measures selected source patterns in intentionally vulnerable training apps and corrected controls. It is not a security grade, population recall estimate, exploit confirmation, or CVE claim.

- **Selected cases detected:** 28/28
- **Negative controls clear:** 17/17
- **Entry points inventoried:** 2
- **Manual cases pending:** 7
- **Cases skipped:** 0

| App | Source files | Static findings | Selected cases | Status |
| --- | ---: | ---: | --- | --- |
| Baseline Canary 1.0 | 4 | 0 | 0/0 detected; 3/3 controls | ready |
| Baseline Canary 1.1 | 4 | 3 | 3/3 detected; 0/0 controls | ready |
| Swift clean source control | 2 | 0 | 0/0 detected; 6/6 controls | ready |
| Flutter clean source control | 1 | 0 | 0/0 detected; 5/5 controls | ready |
| DVIA v2 | 284 | 11 | 3/3 detected; 1/1 controls | ready |
| OWASP iGoat-Swift | 297 | 6 | 3/3 detected; 1/1 controls | ready |
| iBugBazaar | 85 | 13 | 5/5 detected; 1/1 controls | ready |
| DVFA FinTech | 10 | 5 | 4/4 detected; 0/0 controls | ready |
| DVMA | 464 | 23 | 5/5 detected; 0/0 controls | ready |
| Oversecured Vulnerable iOS App | 16 | 5 | 5/5 detected; 0/0 controls | ready |

## Case results

| Case | App | Expected evidence | Result | Source location |
| --- | --- | --- | --- | --- |
| CB-01-F | canary-fixed | IOS-ATS-GLOBAL | clear | — |
| CB-02-F | canary-fixed | IOS-USERDEFAULTS-SENSITIVE | clear | — |
| CB-03-F | canary-fixed | IOS-CUSTOM-TRUST | clear | — |
| CB-01 | canary-vulnerable | IOS-ATS-GLOBAL | detected | Info.plist |
| CB-02 | canary-vulnerable | IOS-USERDEFAULTS-SENSITIVE | detected | CanaryView.swift:47 |
| CB-03 | canary-vulnerable | IOS-CUSTOM-TRUST | detected | TrustProbe.swift:13 |
| CB-04 | canary-vulnerable | Incoming link accesses another account's note | manual_pending | CanaryView.swift |
| SC-01 | swift-clean | MOBILE-AUTH-LITERAL-CHECK | clear | clean_app.swift |
| SC-02 | swift-clean | IOS-USERDEFAULTS-SENSITIVE | clear | clean_app.swift |
| SC-03 | swift-clean | MOBILE-HARDCODED-SECRET | clear | config.plist |
| SC-04 | swift-clean | IOS-STATIC-CRYPTO-KEY | clear | clean_app.swift |
| SC-05 | swift-clean | IOS-CLEARTEXT-URL | clear | clean_app.swift |
| SC-06 | swift-clean | IOS-STATIC-CRYPTO-IV | clear | clean_app.swift |
| FC-01 | flutter-clean | MOBILE-FLUTTER-PREFS-SENSITIVE | clear | — |
| FC-02 | flutter-clean | MOBILE-FLUTTER-CLEARTEXT-URL | clear | — |
| FC-03 | flutter-clean | MOBILE-FLUTTER-STATIC-CRYPTO-KEY | clear | — |
| FC-04 | flutter-clean | MOBILE-FLUTTER-SENSITIVE-LOG | clear | — |
| FC-05 | flutter-clean | MOBILE-FLUTTER-WEAK-CRYPTO | clear | — |
| DVIA-01 | dvia-v2 | IOS-ATS-GLOBAL | detected | Info.plist |
| DVIA-02 | dvia-v2 | IOS-CUSTOM-TRUST | detected | Vulnerabilities/Transport Layer Protection/Controller/TransportLayerProtectionViewController.swift:186, Vulnerabilities/Transport Layer Protection/Controller/TransportLayerProtectionViewController.swift:204 |
| DVIA-03 | dvia-v2 | MOBILE-AUTH-LITERAL-CHECK | detected | Vulnerabilities/Application Patching/Controller/ApplicationPatchingDetailsViewController.swift:38 |
| DVIA-04 | dvia-v2 | IOS-WEAK-CRYPTO | clear | Vendor/RNCryptor/RNOpenSSLCryptor.m |
| IG-01 | igoat-swift | IOS-ATS-GLOBAL | detected | Info.plist |
| IG-02 | igoat-swift | MOBILE-HARDCODED-SECRET | detected | Source/Exercises/Key Management/Hard Coded Keys/BrokenCryptographyExerciseVC.swift:32 |
| IG-03 | igoat-swift | IOS-USERDEFAULTS-SENSITIVE | detected | Source/Exercises/InsecureLocalDataStorage/NSUserDefaults/NSUserDefaultsStorageExerciseVC.swift:13 |
| IG-04 | igoat-swift | MOBILE-HARDCODED-SECRET | clear | Source/Exercises/Binary Patching/BinaryPatchingVC.swift |
| IB-01 | ibugbazaar | IOS-USERDEFAULTS-SENSITIVE | detected | vulnios_prod/Login/Loginscreen.swift:159, vulnios_prod/Login/Loginscreen.swift:160 |
| IB-02 | ibugbazaar | IOS-WEAK-CRYPTO | detected | vulnios_prod/Other/Vulnerable functions.swift:43, vulnios_prod/Other/Vulnerable functions.swift:53 |
| IB-03 | ibugbazaar | Declared URL scheme | recorded | vulnios-prod-Info.plist |
| IB-04 | ibugbazaar | MOBILE-AUTH-LITERAL-CHECK | detected | vulnios_prod/Login/checklogin.swift:21 |
| IB-05 | ibugbazaar | IOS-USERDEFAULTS-SENSITIVE | detected | vulnios_prod/NsUserdefault/Userdefault.swift:78, vulnios_prod/NsUserdefault/Userdefault.swift:80 |
| IB-08 | ibugbazaar | IOS-USERDEFAULTS-SENSITIVE | clear | vulnios_prod/NsUserdefault/Userdefault.swift |
| IB-06 | ibugbazaar | MOBILE-HARDCODED-SECRET | detected | vulnios-prod-Info.plist |
| IB-07 | ibugbazaar | Deep-link file access | manual_pending | vulnios_prod/Deeplink/Link_file_theft.swift |
| DF-01 | dvfa | MOBILE-FLUTTER-PREFS-SENSITIVE | detected | lib/login_screen.dart:46 |
| DF-02 | dvfa | MOBILE-FLUTTER-CLEARTEXT-URL | detected | lib/dashboard_screen.dart:29 |
| DF-03 | dvfa | MOBILE-FLUTTER-STATIC-CRYPTO-KEY | detected | lib/dashboard_screen.dart:58 |
| DF-04 | dvfa | MOBILE-FLUTTER-SENSITIVE-LOG | detected | lib/login_screen.dart:36 |
| DF-05 | dvfa | Deep link starts a transfer | manual_pending | lib/main.dart |
| DF-06 | dvfa | Sensitive data in background screenshot | manual_pending | — |
| DM-01 | dvma | IOS-ATS-GLOBAL | detected | ios/Runner/Info.plist |
| DM-02 | dvma | IOS-FILE-SHARING | detected | ios/Runner/Info.plist |
| DM-03 | dvma | MOBILE-FLUTTER-STATIC-CRYPTO-KEY | detected | lib/modules/crypto/hardcoded_keys_ivs/hardcoded_crypto.dart:17 |
| DM-04 | dvma | MOBILE-FLUTTER-PREFS-SENSITIVE | detected | lib/modules/storage/insecure_local_storage/insecure_storage.dart:29, lib/modules/storage/insecure_local_storage/insecure_storage.dart:30 |
| DM-05 | dvma | MOBILE-FLUTTER-WEAK-CRYPTO | detected | lib/modules/crypto/weak_algorithms/weak_crypto.dart:36 |
| DM-06 | dvma | WebView mixed-content behavior | manual_pending | lib/modules/network/insecure_webview_networking/insecure_webview_networking_screen.dart |
| OV-01 | ovia | IOS-FILE-SHARING | detected | Info.plist |
| OV-02 | ovia | IOS-ATS-GLOBAL | detected | Info.plist |
| OV-03 | ovia | IOS-STATIC-CRYPTO-KEY | detected | Utils/Crypto.swift:4 |
| OV-03-IV | ovia | IOS-STATIC-CRYPTO-IV | detected | Utils/Crypto.swift:5 |
| OV-04 | ovia | IOS-CLEARTEXT-URL | detected | Network/NetworkCalls.swift:3 |
| OV-05 | ovia | Declared URL scheme | recorded | Info.plist |
| OV-06 | ovia | Session theft through the incoming link | manual_pending | Controller/Main/MainViewController.swift |
| OV-07 | ovia | File overwrite through the incoming link | manual_pending | Controller/Main/MainViewController.swift |

A `missed` case is a known scanner gap at that source path. `manual_pending` cases require a signed device or controlled environment. Unreviewed findings are not counted as true or false positives. Upstream source must match the pinned commit in `baselines/benchmark.json`.
