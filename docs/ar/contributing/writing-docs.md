---
title: كتابة التوثيق
description: كيف تكتب توثيق Octa Pass وتنظّمه، بما في ذلك front matter وشارات الحالة والملاحظات الجانبية وأسلوب الروابط ونسخ Markdown المقابلة وllms.txt ومدخلات سجل التغييرات.
status: stable
sidebar:
  order: 3
---

## أين يوجد التوثيق

التوثيق ملفات Markdown في مجلد `docs/` في جذر المستودع. يحمّلها الموقع الموجود في `apps/website` (Astro + Starlight) ويقدّمها تحت `/docs/`. مسار الملف يصبح الرابط:

| الملف | الرابط |
|---|---|
| `docs/index.md` | `/docs/` |
| `docs/security/encryption.md` | `/docs/security/encryption/` |
| `docs/ar/security/encryption.md` | `/ar/docs/security/encryption/` |

تُتجاهل الملفات والمجلدات التي تبدأ بـ `_`.

تُنشر كل صفحة أيضًا على النحو التالي:

- **نسخة Markdown مقابلة** على رابط الصفحة مضافًا إليه `.md`، مثل `/docs/security/encryption.md`
- جزءًا من **`/llms.txt`** (الفهرس) و**`/llms-full.txt`** (كل التوثيق) و**`/llms-small.txt`** (المختصر)

لذلك اكتب صفحات مفهومة بوصفها Markdown مستقلًا. راجع [التوثيق لوكلاء الذكاء الاصطناعي](/ar/docs/contributing/ai-agents/).

## Front matter

```yaml
---
title: Encryption and keys
description: One sentence, 120–160 characters, unique, describing the page for search results.
status: planned
sidebar:
  order: 2
---
```

| الحقل | مطلوب | ملاحظات |
|---|---|---|
| `title` | نعم | حالة الأحرف كما في الجملة. يصبح عنوان الصفحة `h1`، فلا تكرره في النص. |
| `description` | نعم | يُستخدم في وصف الصفحة (meta description) وبطاقات المشاركة و`llms.txt`. كن محددًا. |
| `status` | نعم | `planned` أو `in-progress` أو `beta` أو `stable`. يصف **الميزة** لا الصفحة. |
| `sidebar.order` | موصى به | الترتيب داخل المجلد |

### قيم الحالة

| الحالة | المعنى |
|---|---|
| `planned` | مصمَّمة ولم تُبنَ بعد. تصف الصفحة التصميم. |
| `in-progress` | قيد البناء؛ قد تتغير التفاصيل. |
| `beta` | متاحة للاختبار. |
| `stable` | صدرت، أو صفحة عن المشروع نفسه. |

## الملاحظات الجانبية

تبدأ الصفحات عن الميزات غير المبنية بملاحظة:

```md
:::note[Planned]
This describes the design. It isn't available yet. See the [roadmap](/docs/reference/roadmap/).
:::
```

المتاح أيضًا: `:::tip` و`:::caution` و`:::danger`. استخدم `caution` و`danger` فقط للمخاطر الحقيقية على البيانات أو الأمان.

## الأسلوب

- لغة بسيطة وجمل قصيرة وعناوين بحالة الأحرف كما في الجملة، ولا رموز تعبيرية في العناوين.
- المضارع في وصف التصميم ("Octa Pass encrypts…"). لا تدّعِ أبدًا وجود تنزيل أو صفحة في متجر قبل أن توجد.
- استخدم الجداول للبيانات الجدولية فعلًا، ووسّم كتل الشيفرة بلغتها (`bash` و`yaml` و`json` و`text`).
- موضوع واحد في كل صفحة. قسّم الصفحات التي تزيد على نحو 1,500 كلمة.
- سمِّ المنتج **Octa Pass** في النص، و`octapass` في الأوامر والمعرّفات.

## الروابط

استخدم مسارات الموقع المطلقة مع شرطة مائلة في النهاية:

```md
See [encryption](/docs/security/encryption/) and [conflicts](/docs/features/offline-and-sync/#conflicts).
```

## سجل التغييرات

للتغيير المهم (قسم جديد في صفحة، أو قرار تصميم تغيّر، أو إصدار)، أضف ملفًا إلى `changelog/` باسم `YYYY-MM-DD-short-slug.md`. الصيغة موجودة في `changelog/README.md`.

## الترجمات

الإنجليزية هي المصدر. الصفحات العربية موجودة في `docs/ar/` بالمسارات نفسها، والصفحة التي لا ترجمة لها تعرض النص الإنجليزي مع تنبيه. اكتب بالإنجليزية أولًا: راجع [الترجمات](/ar/docs/contributing/translations/) لمعرفة كيف تتبعها اللغات الأخرى.

## أبقِ الخطط والتوثيق متزامنين

تُسجَّل القرارات في `plans/`. عندما تغيّر خطة شيئًا يراه المستخدمون، حدّث صفحة التوثيق المقابلة في طلب الدمج نفسه.
