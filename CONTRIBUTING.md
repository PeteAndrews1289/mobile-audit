# Contributing to Mobile Audit

Mobile Audit is an evidence-first research prototype. Contributions should make a security claim easier to check, reproduce, or reject.

## Set up and check changes

- Use Python 3.10 or newer. Run `python3 -m unittest discover -s tests -v` from the repository root.
- On macOS with Xcode, run `swift test` from `ios/` for the iPhone app's core logic. A simulator or signed phone is needed for UI and device behavior checks.
- Keep scanner rules narrow. Add a positive fixture and a negative control for a new pattern, including a plausible harmless use of the same API or string.
- Label static matches as leads. Record the test that could confirm or weaken a hypothesis, and do not turn an unreviewed AI suggestion into a finding or grade.

## Data and attribution

- Use synthetic accounts, domains, and activity in committed examples and tests. Do not commit App Privacy Report exports, third-party IPAs, credentials, session files, private case notes, or unredacted live reports.
- The bundled canary and controls are maintained here. Other vulnerable training apps are fetched from their pinned upstream repositories under their own licenses; do not copy their code into a pull request.
- Preserve a source artifact hash, version, and coverage limit whenever a report format or detector changes.
- Follow the target owner's authorization and disclosure rules for live research. Please report vulnerabilities in this scanner through the channel in [SECURITY.md](SECURITY.md).
