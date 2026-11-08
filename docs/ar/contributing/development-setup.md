---
title: إعداد بيئة التطوير
description: أعدّ مستودع Octa Pass الموحّد محليًا باستخدام Node.js وpnpm وRust، وشغّل موقع التوثيق، وتعرّف على مكان كل جزء من المشروع.
status: stable
sidebar:
  order: 2
---

يضم المستودع الخطط والتوثيق والموقع ونواة التشفير بلغة Rust وخادم المزامنة وكل التطبيقات: خزنة الويب، وإضافة المتصفح، وتطبيقات سطح المكتب والهاتف، وواجهة سطر الأوامر، وإضافتي VS Code وJetBrains.

## المتطلبات

| الأداة | الإصدار |
|---|---|
| Node.js | 22.13 أو أحدث (يُنصح بـ 24؛ تستخدم اختبارات e2e الوحدة `node:sqlite`) |
| pnpm | 11 |
| Rust | الإصدار المذكور في `rust-toolchain.toml`، يثبّته rustup، مع الهدف `wasm32-unknown-unknown` |
| wasm-pack | `cargo install wasm-pack --locked` |
| Google Chrome | لاختبارات e2e (من طرف إلى طرف) فقط |
| Git | أي إصدار حديث |

## تشغيل الموقع

```bash
git clone https://github.com/octap-app/octapass.git
cd octapass
pnpm install
pnpm dev        # http://localhost:4321
```

سكربتات أخرى في الجذر:

```bash
pnpm build      # static build into apps/website/dist
pnpm preview    # serve the build locally
pnpm check      # type-check the website
```

## تشغيل خزنة الويب

تعمل خزنة الويب على المنظومة الحقيقية: نواة التشفير بلغة Rust مُترجمة إلى WebAssembly، داخل Web Worker، وتتصل بـ `octapass-server`. أمر واحد يشغّل الاثنين:

```bash
pnpm install
pnpm --filter @octapass/web dev:stack   # server on :8080, web vault on http://localhost:5174
```

يبني الخادم (`cargo build -p octapass-server`)، ويعيد بناء نواة WASM (`pnpm --filter @octapass/core build:if-stale`) كلما تغيّرت مصادرها بلغة Rust منذ آخر بناء. ويتحقق `pnpm build:web` و`pnpm start` واختبارات المتصفح الشاملة من النواة بالطريقة نفسها، فلا يتركها سحبُ تغييرات على حزم Rust على بناء قديم. يعمل الخادم في وضع التطوير بمجلد بيانات مؤقت يُحذف عند الضغط على Ctrl-C؛ اضبط `OCTAPASS_DATA_DIR=./somewhere` للاحتفاظ به. في وضع التطوير تعرض شاشة إنشاء الحساب رمز التحقق من البريد الإلكتروني، فلا حاجة إلى خادم بريد.

لتشغّل النصفين بنفسك:

```bash
OCTAPASS_DEV_MODE=true OCTAPASS_WEB_ORIGINS=http://localhost:5174 cargo run -p octapass-server
pnpm --filter @octapass/web dev         # talks to http://localhost:8080
```

يوجّه `VITE_SERVER_URL` خزنة الويب إلى خادم آخر. أما `VITE_VAULT_BACKEND=mock` (أو `pnpm --filter @octapass/web dev:mock`) فيشغّلها على المحاكاة داخل المتصفح بدلًا من ذلك، بعناصر نموذجية ودون خادم، وهو مفيد لعمل الواجهة والعروض التجريبية.

### الاختبارات

```bash
cargo test --workspace                              # crypto core, test vectors, server
pnpm --filter @octapass/core test                   # the WASM flows in Node (after its build)
pnpm --filter @octapass/vault-client test           # item model, tools, mock, HTTP client, worker bridge
pnpm --filter @octapass/vault-client test:server    # the real service against a real octapass-server
pnpm --filter @octapass/web test                    # UI tests, on the mock
pnpm --filter @octapass/web e2e                     # Chrome against a real server: see below
pnpm --filter @octapass/web build                   # type-check and production build
```

تبني حزمة اختبارات e2e (`apps/web/e2e`) الخادم وخزنة الويب، وتشغّلهما على منفذين حرّين بمجلد بيانات جديد، وتقود Chrome المثبّت في النظام عبر `playwright-core`. تنشئ حسابًا، وتتحقق من أن ملفات قاعدة بيانات الخادم لا تحتوي أي نص صريح من الخزنة، وتقفل الخزنة وتفتحها، وتسجّل الدخول من جديد بالمفتاح السري، وتفتحها بمفتاح مرور افتراضي (WebAuthn PRF)، وتزامن تعديلًا من متصفح ثانٍ، وتحذف الحساب مع التحقق من أن أي جدول لا يزال يذكره. اضبط `HEADED=1` لمشاهدة التشغيل، و`CHROME_PATH` إن لم يكن Chrome في `/Applications`.

## تقديم الخادم أو تشغيل التطبيقات الأصلية

يبني `pnpm start` خزنة الويب والخادم ويقدّمهما معًا على منفذ واحد، `127.0.0.1:8380`، لينشرهما نفق أو وكيل. يبقى وضع التطوير معطّلًا. ويسأل التشغيل الأول في الطرفية عن أمرين:

- **أين يفتحه الناس:** عبر نفق أو وكيل على عنوان تختاره (مثل `https://pass.example.com`)، أو على هذا الحاسوب فقط على `http://localhost:8380`.
- **من يستطيع إنشاء حساب:** عناوين البريد التي تدعوها فقط، أو أي شخص يستطيع فتح العنوان، أو لا أحد جديد. بريدك في git هو الدعوة المقترحة، ويمكنك تغييره أو إضافة غيره.

ثم يعرض حفظ الإجابات في الملف `.env.local` في جذر المستودع، وهو مستثنى من git، ويعيد `pnpm start --setup` طرح الأسئلة. ودون طرفية، أو مع `OCTAPASS_NO_PROMPT=1`، يستخدم القيم الافتراضية ويطبعها. ويفعل `pnpm serve` الشيء نفسه دون بناء.

تحدّد سكربتات التطبيقات الأصلية الجهاز والخادم بنفسها، ولا تسأل إلا حين لا تستطيع التحديد:

| الأمر | الجهاز | الخادم |
|---|---|---|
| `pnpm dev:ios` | المحاكي المشغَّل، وإلا فاختيار | `pnpm dev:api` أو `pnpm start` على هذا الـ Mac، أيهما يعمل |
| `pnpm dev:ios:device` | الـ iPhone أو الـ iPad الموصول، وإلا فاختيار | العنوان العام لـ `pnpm start` أو عنوان تكتبه، لأن الهاتف لا يصل إلى localhost على الـ Mac |
| `pnpm dev:android` | المحاكي أو الهاتف الوحيد، وإلا فاختيار | `pnpm dev:api` أو `pnpm start` على هذا الحاسوب، عبر `adb reverse` |

ويسأل `pnpm dev:ios:device` أيضًا عن الفريق الذي يوقّع التطبيق. تأتي الخيارات من الحسابات المسجَّلة في Xcode ومن شهادات Apple Development في سلسلة المفاتيح، ويمكن حفظ الإجابات في الملف `apps/ios/device.env` المستثنى من git. يقبل كل أمر الخيار `--setup` لإعادة طرح كل الأسئلة. وتتخطى متغيرات البيئة الأسئلة: `OCTAPASS_SERVER_URL` و`DEVICE` و`APPLE_DEVELOPMENT_TEAM` و`ANDROID_SERIAL`.

تعيد أوامر iPhone وAndroid بناء مكتبة Rust الخاصة بالتطبيق كلما تغيّرت مصادرها منذ آخر بناء، لأن روابط Swift وKotlin المحفوظة في المستودع تتغيّر معها. وحين يفشل بناء Xcode، تطبع أسطر الأخطاء ومسار السجل الكامل في `apps/ios/build/`.

## بناء التطبيقات

لكل تطبيق أمر بناء في جذر المستودع:

| الأمر | ما يبنيه | أين يعمل |
|---|---|---|
| `pnpm build:extension` | إضافتا Chrome وFirefox، غير مُحزَّمتين في `apps/extension/dist` | في أي مكان |
| `pnpm build:safari` | تطبيقات Safari لنظام macOS ومحاكي iOS | على Mac |
| `pnpm build:ios` | تطبيق iPhone وiPad، موقَّعًا لـ App Store Connect (ويرفعه `--upload`) | على Mac |
| `pnpm build:android` | تطبيق Android، كملف APK للإصدار غير موقَّع | حيثما توجد أدوات Android SDK |
| `pnpm build:desktop` | تطبيق سطح المكتب للنظام الذي تعمل عليه: `build:macos` أو `build:windows` أو `build:linux` | في أي مكان |
| `pnpm build:macos` | تطبيق Mac وصورة القرص، في `apps/macos/build` | على Mac |
| `pnpm build:windows` | مثبّت Windows | على Windows، أو بالترجمة المتقاطعة على Mac |
| `pnpm build:linux` | حزم `.deb` و`.rpm` وAppImage | على Linux |
| `pnpm build:cli` | الأمر `octapass` ومساعداه لـ Git وDocker | في أي مكان |
| `pnpm build:vscode` | إضافة VS Code، كملف `.vsix` | في أي مكان |
| `pnpm build:jetbrains` | ملحق JetBrains، كملف `.zip` | حيثما يوجد JDK 17 |

تعرض الإضافات وتطبيقات iPhone وAndroid وسطح المكتب خادمًا واحدًا باسم "Octa Pass" في شاشة تسجيل الدخول، ويظل بإمكان أي شخص كتابة خادم آخر تحت "استضافة ذاتية". يسأل أول بناء في الطرفية عن هذا الخادم، ويعرض العنوان العام لـ `pnpm start` والخدمة المستضافة، ويمكنه حفظ الإجابة في `.env.local` باسم `OCTAPASS_BUILD_SERVER_URL`. ودون طرفية تستخدم عمليات البناء الخدمة المستضافة. ويتقدّم `VITE_SERVER_URL`، الذي يضبطه سير عمل الإصدار، على الاثنين، ويعيد `--setup` طرح السؤال. ولا تقبل التطبيقات إلا عناوين `https://`، أو `http://localhost` على الحاسوب نفسه.

تكون عمليات البناء غير موقَّعة ما لم تُضبط إعدادات التوقيع الخاصة بالتطبيق كما يصفها ملف README الخاص به. وتحتاج عمليات بناء Windows وLinux إلى Tauri CLI (`cargo install tauri-cli --locked --version 2.12.4`).

يبني `pnpm build:macos` تطبيق Mac (`apps/macos`)، وهو تطبيق SwiftUI الأصلي الذي صار Octa Pass على Mac. أما تطبيق Tauri (`apps/desktop`) فهو لنظامَي Windows وLinux فقط، ولم يعد يُبنى لنظام macOS. ويحتاج تطبيق Mac إلى XcodeGen وإلى فريق مطوّرين لدى Apple، من `APPLE_DEVELOPMENT_TEAM` أو الفريق الذي يوقّع به `pnpm dev:ios:device` تطبيق iPhone: فالتطبيق يحفظ مفاتيحه في سلسلة مفاتيح Mac، وهذا يتطلب تطبيقًا موقَّعًا، لذا لا يوجد بناء غير موقَّع. وهو موقَّع للتطوير، فيفتح على أجهزة Mac المسجّلة لدى ذلك الفريق. ولم يُعَدّ بعدُ التوقيع بـ Developer ID والتوثيق لدى Apple (notarization) اللذان تحتاجهما التنزيلات التي يفتحها أي شخص.

## أين توجد الأشياء

| المسار | المحتويات |
|---|---|
| `plans/` | الخطط والقرارات الداخلية، مرقّمة وتُقرأ بالترتيب |
| `docs/` | هذا التوثيق، ويُقدَّم على `/docs/` |
| `changelog/` | ملف Markdown واحد لكل تغيير مهم، ويُقدَّم على `/changelog/` |
| `skills/octapass-docs/` | مهارة الوكيل للاستعلام عن هذا التوثيق |
| `apps/website/` | موقع Astro + Starlight |
| `apps/web/` | خزنة الويب (Vite + React) |
| `packages/ui/` | رموز التصميم ومكوّنات React الأساسية للواجهة |
| `packages/vault-client/` | نموذج العناصر وواجهة `VaultService` والأدوات المحلية والخدمة الحقيقية (`src/remote`) والمحاكاة |
| `packages/core/` | بناء WASM لنواة التشفير (`@octapass/core`) |
| `crates/` | Rust: `octapass-core` (التشفير والعناصر والأدوات) و`octapass-wasm` (الربط) و`octapass-api` (أنواع واجهة API) |
| `apps/server/` | خادم المزامنة (axum + SQLite) |
| `AGENTS.md` | قواعد وكلاء البرمجة بالذكاء الاصطناعي |

تخطيط كل التطبيقات والحزم (crates) موجود في [البنية](/ar/docs/developers/architecture/#بنية-المستودع).

## بناء الموقع لنطاق حقيقي

يأتي رابط الموقع ورابط المستودع من `apps/website/src/site.config.ts`. يمكن تجاوزهما وقت البناء:

```bash
PUBLIC_SITE_URL=https://octap.app PUBLIC_REPO_URL=https://github.com/octap-app/octapass pnpm build
```
