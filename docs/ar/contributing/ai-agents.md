---
title: التوثيق لوكلاء الذكاء الاصطناعي
description: كيف يقرأ وكلاء الذكاء الاصطناعي وأدوات LLM توثيق Octa Pass عبر llms.txt ونسخ Markdown المقابلة ومهارة الوكيل octapass-docs، والقواعد التي يلتزم بها الوكلاء في المستودع.
status: stable
sidebar:
  order: 4
---

كُتب توثيق Octa Pass بحيث يسهل على مساعدي الذكاء الاصطناعي ووكلاء البرمجة العثور عليه وقراءته والاستشهاد به.

## نقاط الدخول المقروءة آليًا

| الرابط | المحتوى |
|---|---|
| `https://octap.app/llms.txt` | فهرس لكل صفحات التوثيق مع وصف من سطر واحد (وفق اصطلاح [llmstxt.org](https://llmstxt.org)) |
| `https://octap.app/llms-full.txt` | كل التوثيق في ملف Markdown واحد |
| `https://octap.app/llms-small.txt` | نسخة مختصرة لنوافذ السياق الصغيرة |
| `https://octap.app/docs/<page>.md` | **نسخة Markdown المقابلة** لأي صفحة، مثل `/docs/security/encryption.md` |

كل صفحة توثيق بصيغة HTML تعلن عن نسختها المقابلة:

```html
<link rel="alternate" type="text/markdown" href="/docs/security/encryption.md">
```

يسمح ملف `robots.txt` الخاص بالموقع لزواحف الذكاء الاصطناعي بدخول التوثيق.

## مهارة `octapass-docs`

يتضمن المستودع [مهارة وكيل](https://agentskills.io) (Agent Skill) تعلّم الوكلاء كيف يبحثون في هذا التوثيق ويجيبون مع ذكر المصادر:

- في المستودع: `skills/octapass-docs/SKILL.md`
- على الويب: `https://octap.app/skills/octapass-docs/SKILL.md`

وتشمل سكربت بحث لا يحتاج إلى أي اعتماديات:

```bash
# Inside the repository: searches the local docs/ folder
python3 skills/octapass-docs/scripts/search_docs.py "secret key recovery"

# Anywhere: downloads llms-full.txt and searches it
python3 skills/octapass-docs/scripts/search_docs.py --remote "self-hosting postgres"
```

### تثبيت المهارة

| الوكيل | الطريقة |
|---|---|
| Claude Code (كل المشاريع) | انسخ `skills/octapass-docs/` إلى `~/.claude/skills/octapass-docs/` |
| Claude Code (مشروع واحد) | انسخها إلى `.claude/skills/octapass-docs/` داخل ذلك المشروع |
| وكلاء آخرون (Codex وCursor وCopilot…) | أشر إليها من ملف `AGENTS.md` في مشروعك، مثلًا: "To answer questions about Octa Pass, follow `skills/octapass-docs/SKILL.md`." |

## قواعد الوكلاء العاملين في المستودع

على الوكلاء الذين يغيّرون هذا المستودع اتباع الملف `AGENTS.md` في جذر المستودع. أهم القواعد:

1. **لا تُدرج أي ذكاء اصطناعي مؤلفًا.** لا أسطر `Co-Authored-By` للوكلاء، ولا أسطر "Generated with…" في الـ commits أو طلبات الدمج أو التوثيق أو الشيفرة، ولا تغيير لمؤلف git. المؤلف هو المشرف البشري.
2. لا تُنفّذ commit أو push إلا عندما يطلب المشرف ذلك.
3. لا تُضعف نموذج انعدام المعرفة الأمني دون قرار مسجّل في `plans/`.
4. لا إعلانات ولا متتبّعات ولا سكربتات من جهات خارجية.
5. أبقِ `plans/` و`docs/` و`changelog/` متزامنة. راجع [كتابة التوثيق](/ar/docs/contributing/writing-docs/).

## الاستشهاد بالتوثيق

عندما يجيب وكيل عن سؤال حول Octa Pass، عليه أن يضع رابط الصفحة التي استخدمها (مثل `https://octap.app/docs/security/encryption/`) وأن يذكر حالة الصفحة `status`. معظم الميزات ما زالت `planned` (مخطط لها)، لذلك لا ينبغي وصفها على أنها متاحة.
