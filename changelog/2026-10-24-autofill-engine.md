---
title: The autofill engine for the browser extension
date: 2026-10-24
summary: The engine the browser extension will use to find forms, show the Octa Pass menu and fill safely is in the repository, with a 76-page test corpus it passes in Chrome.
tags: [extension, security]
---

Milestone 2 builds the parts of the [browser extension](/docs/platforms/browser-extension/) before the extension itself. The first one is the **autofill engine** (`packages/autofill`). It runs in the page and never sees your vault: it works out what each field is for, asks the extension which of your items fit, and fills only what you pick.

## What it handles

- **Forms**: sign-in (including email first, password next), sign-up with or without a confirm field, password changes, one-time codes (also split into single-digit boxes), card checkouts and addresses. It reads `autocomplete` attributes first, then labels and field names in English, Chinese, Spanish, Hindi, Arabic, Portuguese, French, Russian, Japanese and German, and every type comes with an explanation of why.
- **Modern pages**: forms inside shadow DOM, same-origin frames and modal dialogs, and inputs controlled by React, Vue, Angular or Svelte. Frames from other sites are reported to the extension, which will ask you before filling there.
- **The Octa Pass menu**: a small icon in the field and a list of suggestions in Octa Pass colours, light or dark, usable from the keyboard. On new-password fields it offers **Use suggested password** with a preview, fills the confirm field too and saves a draft right away, so a password can't get lost if the sign-up succeeds but you dismiss the save prompt.
- **Saving**: it notices a submitted form, or a sign-in that leads to a request, a new address or the form going away, and lets the extension offer to save or update the login.

## Safety

It follows the [autofill safety rules](/docs/features/autofill/#safety-rules). Nothing fills without a real click or key press on the menu. Hidden, see-through, tiny and off-screen fields are never filled. It refuses when the page covers the field or our menu, restyles or moves the menu, or tries to rush the click, the tricks behind 2025's clickjacking attacks on password-manager extensions.

## Tested in a real browser

A corpus of 76 synthetic pages (`tools/autofill-corpus`) covers all of the above plus decoy honeypot fields and clickjacking pages, and runs in Chrome with an accuracy score. The engine passes all 420 checks. The last 16 pages were written separately, without looking at the engine: it scored 95% on them at first, and the gaps they showed were fixed with general rules.
