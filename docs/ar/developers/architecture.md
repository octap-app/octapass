---
title: البنية
description: كيف بُني Octa Pass، بنواة Rust مشتركة تُترجم إلى WebAssembly وروابط أصلية، وواجهات TypeScript وReact، وتطبيقات Tauri، وخادم مزامنة axum.
status: in-progress
sidebar:
  order: 1
---

:::note[قيد التطوير]
تصف هذه الصفحة الشيفرة كما هي اليوم. النواة والخادم وخزنة الويب والإضافة وتطبيق سطح المكتب وتطبيقات الهاتف الأصلية وواجهة سطر الأوامر كلها موجودة. وما بقي منتظرًا موجود في [خارطة الطريق](/ar/docs/reference/roadmap/).
:::

## نظرة عامة

```text
 React screens (apps/web) ─► Web vault    Extension    Desktop (Tauri,     CLI
                             (WASM)       (WASM)       Windows, Linux)     (native Rust)

 SwiftUI apps ┐
 (iPhone, Mac)│
              ├─ UniFFI (octapass-mobile, octapass-ffi) ─ native autofill services
 Compose app ─┘
                                        │ every client links the same core
                                        ▼
        crates/octapass-core: crypto · keys · vault · sync · TOTP · import · passkeys · matching
                                        │ HTTPS + WebSocket, ciphertext only
                                        ▼
        apps/server (Rust, axum): OPAQUE auth · sync API · sharing · email · web vault
             │                       │                       │
       SQLite / PostgreSQL     Disk or S3-compatible      SMTP
```

يجري كل التشفير وفك التشفير في `octapass-core` على العميل.

## لماذا هذه المنظومة

| الخيار | السبب |
|---|---|
| نواة Rust | تنفيذ واحد آمن للذاكرة للتشفير، يُستخدم في كل مكان |
| WebAssembly للويب والإضافة | الشيفرة نفسها كما في التطبيقات الأصلية، وتبقى المفاتيح في ذاكرة WASM حيث يمكن مسحها |
| UniFFI لـ Swift وKotlin | تطبيقات الهاتف وامتدادات الملء التلقائي فيها تستدعي النواة نفسها |
| Tauri 2 لسطح المكتب على Windows وLinux | ملفات تنفيذية صغيرة؛ وتُربط النواة مباشرة. وتحلّ محلّه تطبيقات أصلية، بدءًا بـ Mac ([الخطة 19](https://github.com/octapass/octapass/blob/main/plans/19-native-desktop-apps.md)). |
| SwiftUI وJetpack Compose للهواتف، وSwiftUI على Mac | القوائم والصفحات السفلية وDynamic Type وقارئات الشاشة لا تكون من الدرجة الأولى إلا في الواجهات الأصلية. تحل هذه محل تطبيقات الهاتف السابقة المبنية بـ Tauri. |
| axum + sqlx للخادم | اللغة نفسها كالنواة، مع أنواع API مشتركة. يدعم PostgreSQL وSQLite. |
| Astro + Starlight للموقع | HTML ثابت، وبحث مدمج، وتعدد لغات مع الكتابة من اليمين إلى اليسار، ودعم `llms.txt` |

## بنية المستودع

```text
apps/
  website/      Astro + Starlight: landing page, docs, changelog, llms.txt
  web/          Web vault (React + Vite, core via WASM in a Web Worker)
  extension/    Browser extension (MV3), for Chromium, Firefox and Safari
  safari/       The macOS and iOS apps that carry the extension into Safari
  desktop/      Tauri 2 desktop app, for Windows and Linux
  macos/        Native Mac app (SwiftUI), built from the iPhone app's screens
  ios/          Native iPhone and iPad app (SwiftUI) + AutoFill extension
  android/      Native Android app (Compose) + Autofill and Credential Manager services
  mobile/       Earlier Tauri 2 phone app, removed when the native apps reach parity
  server/       Sync and auth server (Rust, axum)
  cli/          octapass CLI (Rust)
crates/
  octapass-core/  octapass-wasm/  octapass-ffi/  octapass-mobile/  octapass-api/
packages/
  autofill/  core/  ui/  vault-client/
docs/  plans/  changelog/  skills/  tools/  brand/  deploy/
```

## وحدات النواة

| الوحدة | المسؤولية |
|---|---|
| `kdf` و`keys` و`secret_key` | Argon2id وHKDF و[هرمية المفاتيح](/ar/docs/security/encryption/) |
| `envelope` و`stream` | أغلفة النص المشفَّر بـ XChaCha20-Poly1305 وتشفير الملفات على دفعات |
| `opaque` و`credentials` و`session` و`device` و`account` و`recovery` | تسجيل الدخول، وتغيير كلمة المرور الرئيسية وإعادة تعيينها، ومفاتيح الأجهزة |
| `item` و`environment` | مخططات عناصر ذات إصدارات تحافظ على الحقول غير المعروفة |
| `sharing` | مفاتيح خزنة مختومة، وتفويضات موقّعة، وروابط مشاركة، ومفاتيح الوصول في الطوارئ |
| `local` و`backup` | الخزنات المحلية وملفات النسخ الاحتياطي |
| `tools` | الرموز لمرة واحدة (RFC 6238 وSteam و`otpauth://` و`otpauth-migration://`)، والمولّد، وقوة كلمة المرور، وبصمات الاختراق (breach hashes)، ورموز QR، ومفاتيح SSH، والبريد المُقنَّع |
| `matching` و`rules` | مطابقة الروابط باستخدام Public Suffix List والنطاقات المكافئة، وقواعد كلمات المرور لكل موقع |
| `passkey` | مصادِق WebAuthn برمجي |
| `import` / `export` | المحلِّلات والكاتبات، بما فيها CXF |

تقع المزامنة في طبقة أعلى: `packages/vault-client` لخزنة الويب والإضافة، و`apps/desktop/crates/vault` و`crates/octapass-mobile-vault` للعملاء الأصليين.

## حفظ بيانات دخول جديدة خطوة بخطوة

1. يكتشف سكربت المحتوى إرسال النموذج ويرسل الرابط واسم المستخدم وكلمة المرور إلى service worker الخاص بالإضافة عبر منفذ خاص.
2. تسأل الإضافة هل تريد الحفظ، في واجهة معزولة عن الصفحة.
3. عند الحفظ تنشئ النواة العنصر، وتولّد مفتاح العنصر، وتشفّر الحقول، وتلفّ مفتاح العنصر بمفتاح الخزنة. يخزّنه العميل محليًا ويضع الدفع في قائمة الانتظار.
4. يرسل الدفع المراجعة (revision) والمفتاح الملفوف والنص المشفَّر إلى [واجهة API للمزامنة](/ar/docs/developers/sync-api/). يخزّنه الخادم، ويرفع مراجعة الخزنة، ويُخطر الأجهزة الأخرى.
5. تسحب الأجهزة الأخرى التغيير وتفك تشفيره محليًا.

## الأدوات

مساحات عمل pnpm لـ TypeScript، ومساحات عمل Cargo لـ Rust. يشغّل CI على GitHub Actions الأوامر `cargo fmt` وclippy و`cargo test` (الخادم على SQLite وPostgreSQL)، وفحص الأنواع وVitest لكل حزمة، واختبارات العملاء على خادم حقيقي، وبناء الموقع، واختبارات Playwright من طرف إلى طرف. يعمل الـ fuzzing أسبوعيًا. أما `cargo deny` و`cargo vet` فمخطط لهما.
