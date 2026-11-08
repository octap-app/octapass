---
title: الاستيراد من Ente Auth
description: انقل رموز التحقق بخطوتين من Ente Auth إلى Octa Pass بالتصدير النصي العادي أو JSON المشفّر بكلمة مرور، وتُطابَق مع بيانات الدخول التي لديك.
status: beta
sidebar:
  order: 20
---

يعمل مستورِد Ente Auth في خزنة الويب وإضافة المتصفح وتطبيقي سطح المكتب والهاتف و[واجهة سطر الأوامر](/ar/docs/platforms/cli/) (`octapass import ente-auth`، والاسم المستعار `ente`). تُقرأ كل البيانات على جهازك.

## التصدير من Ente Auth

1. في Ente Auth، افتح **Settings ← Data ← Export codes**.
2. اختر **Plain text** أو **Encrypted**. المشفّر موصى به: يبقى ملف JSON مشفّرًا حتى يفك Octa Pass تشفيره على جهازك بكلمة مرور التصدير.
3. احفظ ملف `.txt` أو `.json`.

## ما يُحفظ

| Ente Auth | Octa Pass |
|---|---|
| كل رمز | الرمز لمرة واحدة في بيانات الدخول |
| جهة الإصدار والحساب | عنوان بيانات الدخول واسم المستخدم |
| `note` في `codeDisplay` | ملاحظات بيانات الدخول |
| `tags` في `codeDisplay` | الوسوم |
| `pinned` في `codeDisplay` | مفضّل |
| `lastUsedAt` في `codeDisplay` | تاريخ آخر استخدام (يكتبه Ente بالميكرو ثانية) |
| الرموز `trashed` | تُتخطّى، مع تحذير |
| رموز HOTP | [رموز معتمدة على عدّاد](/ar/docs/features/totp/#الرموز-المعتمدة-على-عدّاد-hotp)، مع عدّادها |
| رموز Steam | حقل مخفي في بيانات الدخول مع الإعداد الكامل. لا يستطيع Octa Pass عرض هذه الرموز بعد. |
| الأيقونات وعدد النقرات والترتيب | لا تُستورد |

### التصدير المشفّر

يحوي JSON المشفّر من Ente الأسطر نفسها الموجودة في الملف العادي، مشفّرة بمفتاح مشتق من كلمة مرور التصدير:

```text
{"version": 1, "kdfParams": {"memLimit", "opsLimit", "salt"}, "encryptedData", "encryptionNonce"}
key       = Argon2id(password, salt, t = opsLimit, m = memLimit / 1024 KiB, p = 1, 32 bytes)
plaintext = libsodium secretstream XChaCha20-Poly1305, one authenticated message
```

يتبع Octa Pass المخطط نفسه الذي يتبعه الأمر `ente auth decrypt` في Ente: يقبل الرسالة الواحدة التي تنتهي بالوسم FINAL، أو بالوسم MESSAGE كما كانت تكتبه إصدارات Ente الأقدم. ويُرفض أي تدفق فيه رسائل أكثر، أو وسم PUSH أو REKEY، أو بايتات زائدة أو ناقصة، أو أي بايت تغيّر، ولا يُستورد شيء. يحدد التصدير مقدار ذاكرة Argon2id وعدد الدورات؛ ويقبل Octa Pass حتى 1 GiB، وعملًا إجماليًا قدره أربع دورات عند 1 GiB، فلا يستطيع ملف مصطنع تجميد الجهاز.

لا معرّفات في تصدير Ente. استيراد الملف نفسه مرة أخرى يجد الرموز بسرّها بدل إضافتها مرتين.

## الاستيراد إلى Octa Pass

اختر **الاستيراد ← Ente Auth**، وأسقط الملف، وأدخل كلمة مرور التصدير إن كان مشفّرًا، ثم راجع واستورد. راجع [نظرة عامة على الاستيراد](/ar/docs/import-export/overview/).
