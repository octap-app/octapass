---
title: The docs sidebar lists its pages again
date: 2026-11-05
summary: The docs sidebar showed its section headings with no pages under them. Every section now lists its pages, in English and Arabic.
tags: [website, docs]
---

The docs sidebar showed only its section headings, with nothing under them. The website builds each section from the files in the repository's `docs/` folder, and the sidebar matched pages by a path that never fits that folder, so every section came out empty.

The website now reads the sections' pages itself and lists them in their set order. Arabic pages use their Arabic titles, and an untranslated page still shows in the Arabic sidebar.
