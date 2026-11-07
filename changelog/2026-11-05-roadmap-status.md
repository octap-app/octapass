---
title: The roadmap now lists what isn't built
date: 2026-11-05
summary: The roadmap's status was checked against the code after every November branch merged, and it now has a list of what's still missing before 1.0.
tags: [docs]
---

The [roadmap](/docs/reference/roadmap/) was out of date. It listed the newer item types, the Windows passkey provider, the watch apps and the docs MCP server as not built, but all of them merged on 2026-11-04. Phases 7 and 8 are now built, though none of that code has been reviewed yet.

The roadmap also has a new **Not built yet** section. The main gaps are push notifications, SCIM and SAML, key transparency witnesses, autofill without asking on phones, the Nearby list, signed and store builds, reproducible builds, and the review and external audit. Each gap is checked against the code in `plans/09-roadmap.md`.
