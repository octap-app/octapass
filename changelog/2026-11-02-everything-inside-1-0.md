---
title: Everything planned for after 1.0 is now part of 1.0
date: 2026-11-02
summary: The Windows passkey provider, SSH agent, teams, watch apps, post-quantum sharing, the developer toolkit and the file safe all move inside 1.0, and the roadmap now says what's actually built.
tags: [decision, docs]
---

The maintainer decided that roadmap phases 7 and 8, every P2 item and the whole developer toolkit and file safe plan are required for 1.0. They come before the external audit, so the audit reviews what actually ships.

The [roadmap](/docs/reference/roadmap/) is rewritten to match the code. The core, server, web vault, extension, desktop apps, native phone apps and CLI are built, but nothing is released: there's no public service, nothing is in a store, and nothing has been audited.

The estimate changes too: about 8–11 months from now at the current pace, so Q3 2027 at the earliest, or 18–24 months for a traditional small team. What sets the date now is review, real devices, store approval and the audit, not writing code.

One question stays open: the decision moves Octa Pass's own masked-email service into scope, but whether to run a mail service at all hasn't been decided.
