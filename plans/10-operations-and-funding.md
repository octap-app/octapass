# 10 — Operations, funding and legal

**Scope decision (maintainer, 2026-11-02):** everything planned for after 1.0 (roadmap phases 7 and 8, every P2 item in plan 01, all of plan 16) is inside 1.0. P2 still says what comes last, but it's required for 1.0. See [plan 09](09-roadmap.md).

## Cost model for the free hosted service

Vault data is small: a typical vault (500 items) is about 1–2 MB of ciphertext. Attachments, email and egress are what cost money.

| Item | Assumption | Monthly cost estimate |
|---|---|---|
| Compute (API, 2–3 instances) | 100k active users | €150–400 |
| PostgreSQL (managed, HA) | ~200 GB incl. history | €200–500 |
| Object storage (attachments) | 10% of users use ~200 MB avg = 2 TB | €20–60 (S3-compatible, e.g. Hetzner/Backblaze/Wasabi) |
| Transactional email | ~300k emails/month | €0–100 |
| Pwned Passwords proxy | Cached ranges at the edge | ~€0–30 |
| HIBP email breach API key | Subscription | ~€30–400 depending on tier |
| Backups, monitoring, status page | | €50–100 |
| **Total at 100k MAU** | | **≈ €500–1,600 / month** |

**What the wider 1.0 adds.** These are first estimates, not quotes, and none of them is in the total above.

| Item | Why it's now in 1.0 | Estimate |
|---|---|---|
| External audit | The surface roughly doubles: SSH agent, Octa Pass Connect, post-quantum sharing, key transparency, teams, the file safe. Budget for about twice the original scope, and get real quotes before fixing dates. | One-off, to be quoted |
| Key transparency log | Public, append-only, must stay online and be monitored | €20–100 / month |
| Octa Pass Safe sync | Stored in object storage under the same 1 GB quota until a decision says otherwise, so egress grows before storage does | €20–200 / month at 100k MAU |
| Own alias service (only if plan 00's question is answered yes) | Separate mail hosts, reputation, abuse desk time | €100–500 / month plus staff time |
| Signing and store entitlements | Windows passkey plugin needs a signed package; watch apps and the Hotspot entitlement need App Store review | Covered by the accounts below, plus an Authenticode certificate at about €200–400 / year |

The free tier stays generous but bounded: **1 GB attachments per account, 100 MB max file, 6 family members**. Every limit applies equally to the self-hosted defaults (and can be changed there).

## Funding (no ads)

1. **Donations:** GitHub Sponsors + Open Collective (transparent ledger). Publish monthly hosting costs to show where money goes.
2. **Supporter badge:** a cosmetic recognition for donors in the app. No feature gating.
3. **Grants:** NLnet / NGI (EU), Sovereign Tech Fund, OTF. Privacy and security tooling fits these well.
4. **Corporate sponsors** listed on the website (a text list, no tracking pixels, no ad networks).
5. **Optional, needs a decision before teams ship in 1.0 (was "before beta"):** a paid tier for organisations (teams, SSO, policies, priority support). That code would still be MIT. Payment would be for hosting and support, not for features.

## Legal and compliance

| Item | Plan |
|---|---|
| Entity | Start under a fiscal host (Open Collective Europe/Foundation). Later, a non-profit association or foundation that owns the trademark. |
| Trademark | Register the final name once cleared (plan 00). A trademark policy allows forks but not misleading use of the name. |
| Privacy policy | Plain-language, generated from "what the server can see" (plan 03). No data sale, no ads, no tracking. |
| GDPR | EU hosting, DPA available, data export (the vault export) and deletion (account deletion wipes everything within 30 days, including backups on rotation). Records of processing. |
| Law-enforcement requests | Publish a transparency report twice a year. We can only hand over ciphertext + the metadata listed in plan 03. |
| Export controls | Open-source crypto: file the US BIS/ENC notification for published source; Apple/Google store encryption declarations. |
| App store accounts | Apple Developer ($99/yr), Google Play ($25 once), Microsoft Partner Center, Chrome Web Store ($5 once), Mozilla AMO (free). |
| Contributor terms | DCO (`Signed-off-by`), no CLA; contributions are MIT (see the 2026-11-07 licence decision in `00-idea-review.md`). |
| Licence headers | SPDX headers (`SPDX-License-Identifier: MIT`) on source files. |

## Incident response

- On-call rotation once there's a team. Status page.
- Runbooks: database restore, key compromise (TLS/signing keys), mass-signup abuse, extension store takedown, data-loss bug.
- Security incidents are disclosed publicly within 72 hours of confirmation (GDPR requires authority notification within 72 h when applicable).

## Masked email relay: decisions needed before it runs

`apps/relay` is built and off (plan 06 History). None of these are settled, and all of them are the maintainer's. It must not take public mail until they are.

| Decision | What's needed |
|---|---|
| **Domain** | A dedicated domain, not the product's own, so a reputation problem can't reach sign-up and security emails. Aliases on it live as long as users keep them, so it can't be changed later without breaking every signed-up account that uses one. |
| **Mail provider** | The smart host all outgoing mail goes through. It must allow forwarding third-party mail with our domain as sender, take a custom return path, and pass feedback-loop reports back. Many transactional providers forbid forwarding, so this needs reading the terms and likely asking them. Running our own outbound IPs is the alternative, with all the work below. |
| **Reputation** | IP or subdomain warm-up plan, sending caps during it, monitoring (Google Postmaster Tools, Microsoft SNDS), feedback-loop sign-ups. Forwarded spam counts against us: there's no content filter. Whether to add one (for example rspamd in front) is part of this decision. |
| **Abuse desk** | Who reads `abuse@` and `postmaster@` (`OCTAPASS_RELAY_OPERATOR_EMAIL`), how fast, and a published policy: what gets an alias or account stopped, and how to appeal. |
| **DNS** | MX, SPF, DKIM (selector and rotation), DMARC with a report address, and PTR for inbound. `docs/self-hosting/relay.md` has the shape. Whether to publish MTA-STS and TLS reporting. |
| **Retention** | Today nothing expires: contacts and blocks stay until the alias goes, counters until the window ends. Whether contacts should age out, and what the privacy policy says. Relay backups hold sealed addresses, so they need the 30-day rule too; the relay has no backup feature of its own. |
| **Legal** | Mail passes through us in plaintext, which is different from the vault. The privacy policy, the DPA, the transparency report and law-enforcement answers need to say so. In the EU, forwarding mail may bring provider obligations the vault doesn't have. |
| **Limits** | The defaults (200 aliases, 25 a day, 25 MiB, bounce and complaint thresholds) are starting points, not tested numbers. |
| **Cost** | Not in the table above: the provider's price per message, an IP or two, and abuse handling time, which is the real cost. |

## History

- 2026-11-02: the scope decision above. Funding matters earlier now: a larger audit has to be paid for before 1.0, not after it, and teams arrive with no decision yet on a paid tier. Both are in plan 00's open questions. Running costs for the new services are estimated above and need real numbers before public beta.
- 2026-10-24 (first production deployment, branch m17-release): the maintainer runs Octa Pass for their own passwords at `https://vault.octap.app`, from `deploy/octap.app/` (Docker Compose, deployable through Komodo). Decisions: one container serves the API and the web vault on one HTTP port (`OCTAPASS_WEB_DIR` in the server rather than a Caddy sidecar: one process, one set of headers, no second image to pin); TLS stays with the maintainer's proxy; the port is published on `127.0.0.1` so only the proxy reaches it, which keeps `OCTAPASS_TRUST_PROXY` safe. Sign-ups are invite-only, the invite list (`OCTAPASS_INVITES`) is applied at start and holds exactly the maintainer's email. Without SMTP the operator reads sign-up codes from the log (`OCTAPASS_EMAIL_TO_LOG`), never from the API. Backups are built into the server (`OCTAPASS_BACKUP_DIR`: daily `VACUUM INTO` + secrets + hard-linked attachments, 14 kept, `admin backup`/`admin restore`) instead of a cron sidecar, because the distroless image has no shell; off-site copies are the operator's job. Client builds for this deployment set `VITE_SERVER_URL=https://vault.octap.app` (the server choice stays editable) and the desktop app allows the self-distributed extension IDs through `OCTAPASS_EXTRA_EXTENSION_IDS` at build time; artifacts and install steps in `deploy/octap.app/RELEASE.md`. Runbook for this deployment: the README in that folder.
- 2026-11-02 (branch `m25-platform-extras`): the masked email relay is built and off; the decisions above are what stands between it and public mail. `deploy/` doesn't include it.
