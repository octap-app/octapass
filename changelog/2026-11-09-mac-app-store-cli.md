---
title: The Mac App Store build installs the CLI from the website
date: 2026-11-09
summary: The Mac app from the App Store and TestFlight doesn't carry the octapass command-line tool; the one-line install adds it.
tags: [desktop, cli]
---

The Mac app built for the App Store and TestFlight leaves out the `octapass` command-line tool and its Git and Docker helpers. Apple requires every program in a store app to be sandboxed, and the CLI couldn't read your files and SSH keys from inside a sandbox. That build doesn't offer the Terminal command either.

Install the CLI with the one-line script from the [CLI page](/docs/platforms/cli/). The Mac app you download as a disk image keeps the bundled CLI.
