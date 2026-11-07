---
title: Contributing
description: How to contribute to Octa Pass through design review, documentation, code, translations and security research, plus the DCO sign-off and the MIT licence terms.
status: stable
sidebar:
  order: 1
---

Octa Pass is built but not released, and it hasn't had its external audit. This is the best time to influence it.

## Ways to help

| Area | How |
|---|---|
| **Design review** | Read the [security overview](/docs/security/overview/) and [threat model](/docs/security/threat-model/) and open an issue with anything that looks wrong. Cryptographers and security engineers are especially welcome. |
| **Documentation** | Fix unclear pages, add import guides, improve examples. See [writing docs](/docs/contributing/writing-docs/). |
| **Code** | The core, server, apps and website are all in the repository. See [development setup](/docs/contributing/development-setup/). |
| **Translations** | The apps, website and docs are in English and Arabic (see [languages](/docs/features/languages/)). Fixes are welcome, and more languages come through [Weblate](/docs/contributing/translations/). |
| **Security** | Report vulnerabilities privately as described in `SECURITY.md`. Please don't open public issues for them. |

## Ground rules

- **No ads, trackers or third-party scripts** anywhere in the project.
- Changes to cryptography, keys, authentication, sync or autofill need a security section in the pull request description.
- Notable changes get a [changelog](/changelog/) entry.
- Be kind. We follow the [code of conduct](https://github.com/octap-app/octapass/blob/main/CODE_OF_CONDUCT.md).

## Sign-off, not a CLA

Octa Pass uses the Developer Certificate of Origin. Sign off each commit:

```bash
git commit -s -m "docs: clarify recovery code rotation"
```

There's no Contributor Licence Agreement: you keep the copyright to your work and license it under MIT. See [licence](/docs/reference/license/).

## AI-assisted contributions

AI tools are welcome. Agents working in the repository must follow `AGENTS.md`, and the human contributor is the author of every commit. See [docs for AI agents](/docs/contributing/ai-agents/).
