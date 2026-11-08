---
title: الاستيراد من المتصفحات
description: استورد كلمات المرور المحفوظة إلى Octa Pass من Chrome وEdge وBrave وOpera وVivaldi وArc وFirefox وSafari أو كلمات السر من Apple باستخدام تصدير CSV.
status: beta
sidebar:
  order: 5
---

يعمل مستورِد المتصفحات في خزنة الويب وإضافة المتصفح وتطبيقي سطح المكتب والهاتف و[واجهة سطر الأوامر](/ar/docs/platforms/cli/) (`octapass import chrome`). تُقرأ كل البيانات على جهازك.

## Chrome والمتصفحات الأخرى المبنية على Chromium

تشترك Chrome وEdge وBrave وOpera وVivaldi وArc في صيغة CSV واحدة.

1. افتح مدير كلمات المرور في المتصفح (في Chrome: **Settings ← Passwords and autofill ← Google Password Manager ← Settings**).
2. اختر **Export passwords** وأكّد بكلمة مرور جهازك.
3. استورد ملف CSV في Octa Pass عبر **الاستيراد ← Chrome أو Edge أو Brave**.

## Firefox

1. افتح `about:logins`.
2. استخدم القائمة **⋯** ← **Export passwords** وأكّد.
3. استورد عبر **الاستيراد ← Firefox**.

## Safari وكلمات السر من Apple

1. على macOS، افتح تطبيق **Passwords** (أو إعدادات كلمات المرور في Safari في الإصدارات الأقدم).
2. اختر **File ← Export All Passwords**. يشمل ملف CSV الملاحظات ورموز TOTP.
3. استورد عبر **الاستيراد ← Safari أو تطبيق كلمات السر من Apple**.

على iOS وmacOS 26 وما بعده، يستطيع تطبيق Passwords أيضًا نقل كلمات المرور و**مفاتيح المرور** مباشرة بصيغة تبادل بيانات الاعتماد. يدعم Octa Pass ذلك: راجع [استيراد ملف CXF](/ar/docs/import-export/from-cxf/).

## ما يُستورد

لا يحمل أي من هذه التصديرات مفاتيح المرور ولا المجلدات ولا الملفات المرفقة.

### Chrome والمتصفحات الأخرى المبنية على Chromium

صف العناوين هو `name,url,username,password,note` (يحذف Edge العمود `note`).

| حقل Chrome | في Octa Pass |
|---|---|
| `name` | العنوان (اسم الموقع إن كان فارغًا) |
| `url` | الموقع. بيانات دخول تطبيقات Android (`android://…@com.example.app/`) تحتفظ بمعرّف التطبيق |
| `username` | اسم المستخدم |
| `password` | كلمة المرور، مع إبقاء المسافات |
| `note` | الملاحظات |
| أي عمود آخر | حقل مخصص باسم العمود، ويكون مخفيًا حين يوحي الاسم بأنه سر |

لا يصدّر Chrome معرّفات ولا تواريخ، لذلك تعرض بيانات الدخول تاريخ استيرادها. الاستيراد مرة أخرى يجد بيانات الدخول نفسها بالموقع واسم المستخدم.

### Firefox

صف العناوين هو `url,username,password,httpRealm,formActionOrigin,guid,timeCreated,timeLastUsed,timePasswordChanged` (من `LoginExport.sys.mjs` في Firefox). الأزمنة بالميلي ثانية.

| حقل Firefox | في Octa Pass |
|---|---|
| `url` | الموقع |
| `username` | اسم المستخدم |
| `password` | كلمة المرور |
| `httpRealm` | نطاق HTTP (HTTP realm)، لبيانات الدخول المحفوظة من نافذة تسجيل الدخول المنبثقة لموقع بدل نموذج |
| `formActionOrigin` | موقع ثانٍ، حين يسجّل النموذج الدخول إلى موقع آخر |
| `guid` | يُحفظ مع العنصر، فيحدّثه استيراد الملف مرة أخرى |
| `timeCreated` | تاريخ الإنشاء |
| `timePasswordChanged` | تاريخ تغيير كلمة المرور، وتاريخ آخر تغيير للعنصر |
| `timeLastUsed` | تاريخ آخر استخدام |

يُتخطّى تسجيل دخول مزامنة Firefox نفسه (`chrome://FirefoxAccounts`).

### Safari وكلمات السر من Apple

صف العناوين هو `Title,URL,Username,Password,Notes,OTPAuth`. تحذف إصدارات Safari الأقدم العمود `Notes`.

| حقل Safari | في Octa Pass |
|---|---|
| `Title` | العنوان |
| `URL` | الموقع |
| `Username` | اسم المستخدم |
| `Password` | كلمة المرور |
| `Notes` | الملاحظات. الصف الذي فيه ملاحظات فقط يصير ملاحظة آمنة |
| `OTPAuth` | الرمز لمرة واحدة |

لا تواريخ ولا معرّفات في CSV من تطبيق Passwords. لنقل مفاتيح المرور، استخدم نقل [تبادل بيانات الاعتماد](/ar/docs/import-export/from-cxf/) بدلًا من ذلك.

## بعد الاستيراد

- احذف ملف CSV المصدَّر. فهو غير مشفّر.
- أوقف حفظ كلمات المرور المدمج في متصفحك لتتجنب التنبيهات المكررة. توضح [إضافة المتصفح](/ar/docs/platforms/browser-extension/) كيف.
