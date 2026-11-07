---
title: The whole website reads well to search engines and AI agents
date: 2026-11-08
summary: The sitemap now says when each page last changed and links its English and Arabic versions, the home page and the changelog have Markdown copies, and the site publishes a security.txt.
tags: [website, docs]
---

- **Sitemap:** [`/sitemap-index.xml`](/sitemap-index.xml) lists every docs page in English and Arabic, every changelog entry, both home pages and the changelog. Each URL has a `<lastmod>` (the last commit to the page's source, or a changelog entry's date) and, where the page exists in both languages, its English, Arabic and default alternates.
- **Markdown for AI agents:** besides the docs, the home page ([`/index.md`](/index.md), [`/ar/index.md`](/ar/index.md)) and the changelog ([`/changelog/index.md`](/changelog/index.md), and each entry at `/changelog/<slug>.md`) have Markdown copies. Each page links to its copy, and [`/llms.txt`](/llms.txt) lists them next to the docs, along with what Octa Pass is, its MIT licence and where its source lives.
- **Structured data:** the home page describes Octa Pass as a free, MIT-licensed security app with the web vault as its download, docs pages carry when they last changed and a breadcrumb trail, and changelog entries are marked up as posts with their date.
- **One social card tag per docs page**, where there were two.
- **[`/.well-known/security.txt`](/.well-known/security.txt)** points security researchers to the private reporting channels in [`SECURITY.md`](https://github.com/octap-app/octapass/blob/main/SECURITY.md). It is rebuilt with every deploy, so its expiry date is always a year after the last one.

The details are in [docs for AI agents](/docs/contributing/ai-agents/) and `plans/08-website-docs-seo-ai.md`.
