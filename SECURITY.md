# Security policy

Octa Pass is a password manager, so security reports are our highest priority.

## Project status

Octa Pass is in **public alpha**: the hosted service at [vault.octap.app](https://vault.octap.app) is open for sign-ups, the apps aren't in any store yet, and nothing has had its external audit. Reviews of the security design and the code are very welcome now, while changes are cheap:

- [Security model plan](plans/03-security-model.md)
- [Security docs](docs/security/overview.md)

Open a regular GitHub issue (label `security-design`) for design feedback that doesn't describe an exploitable bug in released software.

## Reporting a vulnerability

**Don't open public issues for vulnerabilities.** Report privately:

- GitHub: **Security → Report a vulnerability** on this repository (private advisory), or
- Email: not available yet. Use a GitHub private security advisory (above) until a security mailbox and key are published here.

Please include affected component and version, reproduction steps, and impact.

## What to expect

| Step | Target |
|---|---|
| Acknowledgement | 3 working days |
| Initial assessment | 10 working days |
| Fix for critical/high severity | as fast as possible, normally within 30 days |
| Public disclosure | coordinated, by default 90 days after the report or when a fix ships, whichever comes first |

We credit reporters in the advisory and the changelog unless you prefer to stay anonymous. A paid bug bounty will start at public beta (see [roadmap](plans/09-roadmap.md)).

## Scope

In scope: `crates/*`, `packages/*`, `apps/server`, `apps/extension`, `apps/safari`, `apps/desktop`, `apps/ios`, `apps/android`, `apps/cli`, `apps/web`, and the share-link viewer.

Out of scope: attacks that need an already compromised (malware-infected or unlocked and physically accessed) device, social engineering of the maintainers, denial of service through volume, and reports from automated scanners without a demonstrated impact.

## Safe harbour

We won't pursue legal action against good-faith research that respects user privacy, avoids data destruction and service disruption, and gives us reasonable time to fix the issue before disclosure.
