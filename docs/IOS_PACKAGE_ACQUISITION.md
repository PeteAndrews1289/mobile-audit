# Getting an iOS app package for Mobile Audit

The usual target is an App Store app installed on a researcher's ordinary iPhone. The first objective is to obtain the corresponding IPA on a Mac and verify which app version it contains. **Obtaining an IPA and reading its native executable are separate steps.** An App Store IPA can expose bundle metadata, resources, frameworks, and configuration while its native code remains encrypted.

## Practical routes

| Route | What it supplies | When to use it | Limit |
| --- | --- | --- | --- |
| Mobile Audit's `acquire-ios` command using [ipatool](https://github.com/majd/ipatool) | An IPA, acquisition record, and research scan produced in one Mac workflow | Primary integrated route for an app associated with the researcher's Apple Account | Requires local interactive sign-in and an app license; App Store protocol changes can interrupt authentication or downloads; native code may be encrypted |
| [iMazing Manage Apps](https://imazing.com/guides/how-to-manage-apps-without-itunes) | An IPA downloaded into its Mac app library, which can be exported | Alternative GUI route if the integrated backend cannot obtain a package | Third-party GUI and Apple Account sign-in; the package may have a different version from the phone and native code may be encrypted |
| Developer or publisher build | An IPA or `.app` supplied by its owner | Full static analysis when the build is unencrypted and permission to use it exists | Rarely available for arbitrary third-party apps; may differ from the App Store build |
| Apple silicon Mac App Store installation | A local iPhone/iPad app bundle when the publisher allows Mac availability | Useful alternative for a supported app | Availability is set by the publisher; do not assume its package or behavior matches the iPhone version |
| Dedicated jailbroken research iPhone | A running app's decrypted *compiled* executable, exported as a research artifact | Deeper native-code analysis when a compatible app and iOS version can run on the research device | Requires a separate supported device and version matching; it does not recreate original Swift or Objective-C source |

Mobile Audit running as an ordinary iPhone app cannot copy another installed app's package. iOS sandboxes third-party apps. A normal device backup or an app's shared Documents directory is not an executable-package export. The Mac download routes obtain a licensed App Store copy rather than extracting the installed bundle from the phone. [Apple's sandbox description](https://support.apple.com/en-afri/guide/security/sec15bfe098e/web) and [OWASP's extraction guide](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0054/) explain these limits.

## First pilot with the existing scanner

1. Pick one free app already installed under the researcher's Apple Account. Record its name and exact version/build shown on the iPhone when available.
2. From this project directory, run `python3 -m mobile_audit acquire-ios setup`, then `python3 -m mobile_audit acquire-ios auth` in an interactive terminal. Only ipatool handles the account prompts.
3. Run `python3 -m mobile_audit acquire-ios search "App Name"` to find the bundle identifier, then `python3 -m mobile_audit acquire-ios download --bundle-id BUNDLE.ID --phone-version VERSION --output /path/to/new-acquisition`. The phone version flag is optional when unknown. Add `--iphone-report` or `--privacy-report` if one is available for this app.
4. Open `scan/report.html` in the new output directory. Check `acquisition.json` for bundle identifier, version/build, package SHA-256, and encryption counts. Treat a package/phone version mismatch as two separate observations until reconciled.
5. Use the report to identify what the package actually revealed and which code-level questions still need a readable binary or a controlled runtime test.

Mobile Audit invokes ipatool for authentication, search, and download, passing terminal input directly to ipatool for sign-in. It does not receive credential flags or read ipatool's session files. The backend's [FAQ](https://github.com/majd/ipatool/wiki/FAQ/bfd186ac64f70d71f9af563279282fa2b58a4ecc) says the account needs a license even for free apps and warns that use of its unofficial App Store protocol could affect the account.

## Remaining acquisition work

1. Repeat the validated live App Store acquisition with another licensed app and document failures caused by account state, storefront, or protocol changes. The first third-party package matched the phone case and was scanned without a simulator.
2. Add a matching **Import IPA** path for externally supplied packages and a simple app picker in a future Mac interface. The current command accepts bundle or App Store ID and creates the acquisition record automatically.
3. Bundle or manage the MIT-licensed acquisition backend in a distributable Mac app, with the upstream license and attribution. Keep authentication local and exclude credentials and session files from reports.
4. Accept a separately obtained readable binary or decrypted research IPA only after checking its identity and version against the encrypted package. Mark any unverified relationship as such. An LLM can review the resulting evidence, but it cannot decrypt the package.

**Acceptance test met for the first pilot:** a third-party IPA was obtained on the Mac without a simulator, imported, and reported with matching identity/version and explicit native-code encryption. A readable app build remains a separate research path.
