# Changelog

One Markdown file per notable change, served on the website at `/changelog/` and as an RSS feed at `/changelog/rss.xml`.

## Adding an entry

Create `changelog/YYYY-MM-DD-short-slug.md`:

```markdown
---
title: Short headline in sentence case
date: 2026-10-22
summary: One sentence, shown in the list and the RSS feed.
tags: [docs, security]          # any of: decision, docs, website, security, core, server, extension, desktop, mobile, cli, release
---

What changed and why, in a few short paragraphs or a list. Link to the plan or docs page.
```

- Files must start with the date (`[0-9]*.md`); this README is ignored by the website.
- Write for users and contributors, not as a commit log.
- Once apps ship, release entries use the title `vX.Y.Z: …` and list **Added / Changed / Fixed / Security**.
