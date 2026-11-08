---
title: التوثيق لوكلاء الذكاء الاصطناعي
description: كيف يقرأ وكلاء الذكاء الاصطناعي توثيق Octa Pass عبر llms.txt ونسخ Markdown المقابلة ومهارة octapass-docs، ويستخدمون الأداة بأمان مع octapass-cli، والقواعد التي يلتزمون بها.
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

## مهارة `octapass-cli`

مهارة ثانية تعلّم الوكلاء استخدام [أداة سطر الأوامر `octapass`](/ar/docs/platforms/cli/) نيابةً عن المستخدم: البحث عن العناصر وقراءتها، وإنشاؤها وتعديلها، وتوليد كلمات المرور، والحصول على الرموز لمرة واحدة، وتمرير الأسرار إلى الأوامر عبر `octapass run` ومراجع `octapass://`، والبيئات، وحسابات الخدمة وCI، ومفاتيح SSH، وتشفير الملفات.

- في المستودع: `skills/octapass-cli/SKILL.md`، ومعها `references/commands.md` (كل الأوامر) و`references/ci.md` (GitHub Actions وGitLab CI والأدوات السحابية وConnect)
- على الويب: `https://octap.app/skills/octapass-cli/SKILL.md`

تبدأ بقواعد يتبعها الوكيل قبل أي شيء تطلبه المهمة:

1. لا تطبع سرًّا إلا إذا طلب المستخدم تلك القيمة. الأمر `octapass get <item>` يعرض العنصر من دون أسراره، و`octapass list --json` لا يحتوي أسرارًا أبدًا. أما `octapass get <item> --json` من دون `--field` فيتضمنها.
2. مرّر الأسرار بدل نسخها: `octapass run` و`octapass inject` ومراجع `octapass://` تُبقي القيمة خارج مخرجات الوكيل.
3. لا تطلب كلمة المرور الرئيسية أو المفتاح السري ولا تخزّنهما ولا تمرّرهما أبدًا. عندما تكون الخزنة مقفلة (رمز الخروج 4)، يفتحها المستخدم بنفسه من طرفيّته أو عبر تطبيق سطح المكتب.
4. اطلب التأكيد قبل الحذف أو الاستبدال أو التصدير أو تغيير الحساب، ولا تُضف `--yes` أبدًا لتتجاوز سؤال الأداة نفسها.

ثبّتها بطريقة `octapass-docs` نفسها: انسخ `skills/octapass-cli/` إلى `~/.claude/skills/octapass-cli/`، أو أشر إليها من `AGENTS.md`.

لا يمكن للمهارة أن تبتعد عن الأداة. تقرأ اختباراتها مخرجات `--help` من الملف التنفيذي المبني لكل أمر، وتفشل إذا ذكرت المهارة أمرًا أو خيارًا أو قيمة غير موجودة، أو متغير بيئة لا تقرؤه الأداة، أو رموز خروج تختلف عمّا في `apps/cli/src/error.rs`. وتفشل أيضًا عندما تكسب الأداة أمرًا لا تذكره المهارة. يشغّلها CI مع كل push:

```bash
cargo build -p octapass-cli
python3 -m unittest discover -s skills/octapass-cli/tests
```

## خادم MCP للتوثيق

يمنح `octapass-docs-mcp` أي عميل يدعم [Model Context Protocol](https://modelcontextprotocol.io) البحثَ نفسه الذي تقدّمه المهارة، على شكل أدوات. هو ملف Python واحد بلا اعتماديات، يحتاج إلى Python 3.9 أو أحدث، ويتواصل عبر stdio، فلا يستمع على أي منفذ ولا يحتاج إلى حساب.

| الأداة | ماذا تفعل |
|---|---|
| `search_docs` | تبحث في التوثيق. تأخذ `query` و`limit` اختياريًا (من 1 إلى 20). تُعيد لكل نتيجة العنوانَ والقسم والحالة والرابط والصفحة ومقتطفًا |
| `get_page` | تُعيد صفحة كاملة. تأخذ `page`، مثل `security/encryption` |
| `list_pages` | تسرد كل الصفحات مع حالتها ووصفها |

الأدوات الثلاث للقراءة فقط. أضفه إلى إعدادات MCP في عميلك. داخل نسخة من المستودع يقرأ المجلد `docs/`:

```json
{
  "mcpServers": {
    "octapass-docs": {
      "command": "python3",
      "args": ["/path/to/octapass/skills/octapass-docs/scripts/docs_mcp.py"]
    }
  }
}
```

خارج المستودع يقرأ الموقع، أو أضف `"--remote"` إلى `args` لفرض ذلك. يعمل `--docs-dir PATH` و`--base-url URL` كما في `search_docs.py`. تبقى عبارات البحث على حاسوبك: الوضع البعيد يُنزّل صفحات التوثيق العامة فقط ويحتفظ بها يومًا واحدًا.

## قواعد الوكلاء العاملين في المستودع

على الوكلاء الذين يغيّرون هذا المستودع اتباع الملف `AGENTS.md` في جذر المستودع. أهم القواعد:

1. **لا تُدرج أي ذكاء اصطناعي مؤلفًا.** لا أسطر `Co-Authored-By` للوكلاء، ولا أسطر "Generated with…" في الـ commits أو طلبات الدمج أو التوثيق أو الشيفرة، ولا تغيير لمؤلف git. المؤلف هو المشرف البشري.
2. لا تُنفّذ commit أو push إلا عندما يطلب المشرف ذلك.
3. لا تُضعف نموذج انعدام المعرفة الأمني دون قرار مسجّل في `plans/`.
4. لا إعلانات ولا متتبّعات ولا سكربتات من جهات خارجية.
5. أبقِ `plans/` و`docs/` و`changelog/` متزامنة. راجع [كتابة التوثيق](/ar/docs/contributing/writing-docs/).

## الاستشهاد بالتوثيق

عندما يجيب وكيل عن سؤال حول Octa Pass، عليه أن يضع رابط الصفحة التي استخدمها (مثل `https://octap.app/docs/security/encryption/`) وأن يذكر حالة الصفحة `status`. معظم الميزات ما زالت `planned` (مخطط لها)، لذلك لا ينبغي وصفها على أنها متاحة.
