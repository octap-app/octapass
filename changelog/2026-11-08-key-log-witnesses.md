---
title: Key log witnesses stop a server showing different people different logs
date: 2026-11-08
summary: Independent witnesses can now cosign a server's key log, so it can't show you one log and your contact another. Self-hosters can use any C2SP witness, or run ours.
tags: [security, server, core]
---

The [key log](/docs/security/post-quantum-and-key-log/#the-key-log) shows a swapped public key to its real owner, but it couldn't catch a server that shows you one log and your contact another. **Witnesses** now close that gap. They are independent parties who cosign the log only if it extends what they cosigned before.

- **Servers** send their log's state to the witnesses listed in `OCTAPASS_KEY_LOG_WITNESSES` every 10 minutes. Clients get the newest state a quorum of witnesses cosigned with every key log check. `octapass-server admin key-log` prints what witness operators need, and `admin key-log witness` tests the setup.
- **Your devices** pin a server's witnesses the first time they see them. From then on they refuse a log that enough of those witnesses haven't cosigned in the last 7 days. A log that doesn't extend what the witnesses cosigned raises an alert in **Sharing**.
- **`octapass-witness`** is a small standalone server you can run to witness someone else's Octa Pass server.
- **Standard protocols.** It uses the C2SP signed-note, checkpoint, cosignature and tlog-witness specs, checked against the Go reference implementations. An Octa Pass server can use existing public witnesses, and our witness can witness other logs.

A witness sees only the log's name, size and root hash: no emails, keys or accounts. Devices never contact witnesses. Nobody has been chosen to witness the hosted service yet, so for now it runs without them, and like the rest of the key log this hasn't had the outside cryptographer's review. See [key log witnesses](/docs/self-hosting/key-log-witnesses/).
