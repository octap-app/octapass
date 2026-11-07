---
title: التشفير والمفاتيح
description: هرمية المفاتيح والخوارزميات في Octa Pass بالتفصيل، بما في ذلك Argon2id وHKDF وXChaCha20-Poly1305 وX25519 وEd25519 والمفتاح السري والمفاتيح الخاصة بكل عنصر.
status: in-progress
sidebar:
  order: 2
---

:::note[قيد التطوير]
هذا التصميم منفَّذ في نواة Rust (`crates/octapass-core`) التي تشغّلها خزنة الويب بصيغة WebAssembly. وقد تُضبط المعاملات قبل الإصدار 1.0. ستُسجَّل التغييرات في [سجل التغييرات](/changelog/).
:::

## الأوليات التشفيرية

| الغرض | الخوارزمية |
|---|---|
| اشتقاق المفتاح من كلمة المرور | Argon2id، بذاكرة 64 MiB، و3 تكرارات، وتوازٍ 1. تُخزَّن المعاملات لكل حساب ويمكن ترقيتها. |
| اشتقاق المفاتيح | HKDF-SHA256، مع تسمية `info` مميزة لكل غرض |
| التشفير المتماثل | XChaCha20-Poly1305 مع قيم nonce عشوائية بطول 192 بت وبيانات مرتبطة |
| تشفير المفتاح العام (المشاركة) | صناديق مختومة هجينة X25519 + ML-KEM-768 (HKDF + XChaCha20-Poly1305)، مع صناديق X25519 وحدها للحسابات التي ليس لها مفتاح ML-KEM بعد. لم يراجعها خبير تشفير من خارج المشروع بعد. |
| التوقيعات | Ed25519 |
| تسجيل الدخول | OPAQUE (RFC 9807) فوق ristretto255 مع Argon2id. راجع [المصادقة](/ar/docs/security/authentication/). |
| مفاتيح المرور | ES256 (P-256) وEdDSA |
| العشوائية | CSPRNG الخاص بنظام التشغيل (`getrandom`؛ و`crypto.getRandomValues` في WebAssembly) |

كل هذا منفَّذ مرة واحدة، في نواة Rust، باستخدام حزم RustCrypto. وتُصفَّر كل مواد المفاتيح من الذاكرة عندما لا تعود هناك حاجة إليها.

قيمة التوازي 1 لأن WebAssembly يشغّل مسارات Argon2 واحدًا بعد الآخر، لذلك فإن أي قيمة أعلى لن تفعل سوى إبطاء فتح القفل في المتصفح.

## هرمية المفاتيح

```text
master password ─NFKD─► Argon2id(salt = HKDF(account_salt, email)) ─► pw_key ─┐
                                                                               ├─► HKDF ─► AUK (Account Unlock Key)
Secret Key (128-bit, made on device) ─► HKDF(salt = account_salt) ─► sk_key ───┘     └──► auth_secret ─► OPAQUE

AUK                  unwraps  ASK (Account Symmetric Key, random 256-bit)
ASK                  unwraps  your private keys (X25519 encryption, Ed25519 signing)
ASK                  unwraps  your personal Vault Keys
your X25519 key      opens    shared Vault Keys (sealed to each member, signed by the sharer)
Vault Key            unwraps  Item Keys (random, one per item)
Item Key             decrypts item overview (title, URLs, icon hint) and item details
Item Key             unwraps  File Keys (random, one per attachment)
File Key             decrypts the attachment's file, in 64 KiB chunks

Recovery Key (256-bit, shown once)               wraps ASK (stored on the server)
Device Key (hardware-backed, biometric-gated)    wraps ASK (stored only on that device)
```

### تفاصيل الاشتقاق

```text
account_salt = 16 random bytes, made at sign-up and returned by prelogin
argon2_salt  = HKDF-SHA256(ikm = account_salt, salt = "octapass/v1", info = email)[0..16]
pw_key       = Argon2id(NFKD(password), argon2_salt, 64 MiB, 3 iterations, 1 lane) → 32 bytes
sk_key       = HKDF-SHA256(ikm = Secret Key, salt = account_salt, info = "octapass/v1/secret-key")
AUK          = HKDF-SHA256(ikm = pw_key ‖ sk_key, info = "octapass/v1/auk")
auth_secret  = HKDF-SHA256(ikm = pw_key ‖ sk_key, info = "octapass/v1/auth")
```

تُزال المسافات من طرفي البريد الإلكتروني ويُحوَّل إلى أحرف صغيرة. وتخضع كلمة المرور لتسوية NFKD، بحيث تعطي كلمة المرور نفسها المكتوبة على لوحات مفاتيح مختلفة المفتاح نفسه، لكن لا تُزال المسافات من طرفيها. ولأن معاملات KDF تأتي من الخادم، ترفض التطبيقات أي قيم أضعف من القيم الافتراضية: لا يستطيع خادم خبيث أن يجعل تخمين كلمة مرورك أقل كلفة.

`auth_secret` هو مُدخل كلمة المرور إلى [OPAQUE](/ar/docs/security/authentication/). وهو أيضًا لا يغادر جهازك أبدًا؛ فكل ما يفعله OPAQUE هو إثبات أنك تعرفه.

### لماذا سرّان

يُنشأ **المفتاح السري** على جهازك، ويُحفظ على أجهزتك المسجَّل الدخول عليها وفي [مجموعة الاسترداد](/ar/docs/getting-started/recovery-kit/)، ولا يُرسل إلى الخادم أبدًا. يبدو هكذا:

```text
OP1-XXXXXX-XXXXXX-XXXXX-XXXXX-XXXX
```

هذه بادئة إصدار إضافة إلى 128 بت عشوائية مكتوبة في 26 محرفًا بترميز Crockford base32. عند كتابته، لا تهم حالة الأحرف ولا المسافات ولا الشرطات، وتُقرأ الأحرف المتشابهة مثل `O` و`0` بالطريقة نفسها. إذا تسرّبت قاعدة بيانات الخادم، فسيحصل المهاجم على سجلات OPAQUE والمفاتيح المغلَّفة لكن دون المفتاح السري، ولا يمكن كسر 128 بت عشوائية بالقوة الغاشمة. لذلك حتى كلمة المرور الرئيسية الضعيفة آمنة في حال اختراق الخادم. يستخدم 1Password النهج نفسه القائم على سرّين.

### لماذا مفاتيح لكل عنصر

لكل عنصر مفتاحه العشوائي الخاص، مغلَّفًا بمفتاح خزنته. يمكن مشاركة عنصر أو نقله بإعادة تغليف مفتاح صغير واحد بدلًا من إعادة تشفير الخزنة كلها. وعند إزالة شخص من خزنة مشتركة، يُعاد تغليف مفاتيح العناصر تحت مفتاح خزنة جديد.

ترتبط المرفقات بمفتاح العنصر بالطريقة نفسها: لكل ملف مفتاحه العشوائي الخاص، مغلَّفًا بمفتاح العنصر ومحفوظًا في التفاصيل المشفَّرة للعنصر. لا يعيد تدوير المفاتيح تغليف سوى مفاتيح العناصر، لذلك تبقى الملفات قابلة للقراءة دون تنزيلها أو تشفيرها من جديد.

## صيغة النص المشفَّر

```text
version (1 byte, 0x01) ‖ key_id (16 bytes) ‖ nonce (24 bytes) ‖ ciphertext ‖ tag (16 bytes)
```

يُرمَّز بصيغة base64url دون حشو في JSON. قيمة `key_id` هي أول 16 بايت من `SHA-256("octapass/v1/keyid" ‖ key)`، بحيث يستطيع التطبيق معرفة المفتاح الذي يحتاج إليه النص المشفَّر دون محاولة فك تشفيره.

**البيانات المرتبطة** تربط كل نص مشفَّر بالمكان الذي ينتمي إليه: `"octapass/v1|"` متبوعة بسياق.

| السياق | ما بداخله | مشفَّر باستخدام |
|---|---|---|
| `ask` | مفتاح الحساب | AUK |
| `recovery` | مفتاح الحساب | رمز الاسترداد |
| `privkeys` | المفتاحان الخاصان X25519 وEd25519 | مفتاح الحساب |
| `vaultkey:<vault id>` | مفتاح الخزنة | مفتاح الحساب |
| `itemkey:<vault id>:<item id>` | مفتاح العنصر | مفتاح الخزنة |
| `item:<vault id>:<item id>:overview` | العنوان والنوع وعناوين URL والوسوم | مفتاح العنصر |
| `item:<vault id>:<item id>:details` | كل ما عدا ذلك | مفتاح العنصر |
| `attachmentkey:<vault id>:<item id>:<attachment id>` | مفتاح الملف | مفتاح العنصر |
| `attachment:<vault id>:<item id>:<attachment id>` | كل أجزاء الملف | مفتاح الملف |
| `service-account-name:<vault id>:<service account id>` | اسم حساب الخدمة | مفتاح حساب منشئه |
| `audit-detail:<account id>` | قيد في سجل الأمان لا يقرؤه سواك | مفتاح الحساب |

يفشل فك التشفير إذا نقل الخادم مفتاحًا مشفَّرًا أو حقلًا أو ملفًا إلى عنصر أو خزنة أخرى.

### الملفات

تُشفَّر المرفقات جزءًا بعد جزء، فلا يحتاج التطبيق ولا الخادم إلى تحميل ملف كامل في الذاكرة:

```text
file    = header ‖ chunk_0 ‖ … ‖ chunk_n
header  = version (0x01) ‖ key_id (16 bytes) ‖ nonce prefix (19 random bytes)
chunk_i = XChaCha20-Poly1305(file key, nonce = prefix ‖ i (4 bytes) ‖ last (1 byte), associated data = "octapass/v1|attachment:…")
```

يحمل كل جزء 64 KiB من الملف، باستثناء الجزء الأخير الذي يحمل الباقي، وهو الوحيد المعلَّم بأنه الأخير. يفشل فك تشفير أي ملف قُطع، أو أُسقطت منه أجزاء أو أُعيد ترتيبها أو أُضيفت إليه، أو نُقل إلى عنصر آخر، ولا تعرض التطبيقات جزءًا من ملف كهذا أبدًا. يضيف التشفير 52 بايت، إضافة إلى 16 بايت لكل 64 KiB. معرّفات الخزنات والعناصر هي UUID، لذلك لا يمكن أن تحتوي على الفاصل `:`. ويخزّن كل عنصر أيضًا `schemaVersion` داخل نظرته العامة وتفاصيله المشفَّرة.

## حسابات الخدمة

[حساب الخدمة](/ar/docs/features/service-accounts/) عضو في الخزنة ليس شخصًا. يحمل رمزه جذرًا عشوائيًا بطول 256 بت لا يُرسل إلى الخادم أبدًا. ويُشتق منه مفتاحان:

```text
encryption key = X25519(HKDF-SHA256(root, salt = service account id, info = "octapass/v1/service-account/encryption"))
signing key    = Ed25519(HKDF-SHA256(root, salt = service account id, info = "octapass/v1/service-account/signing"))
token          = "opsa1_" + base64url(0x01 ‖ id (16) ‖ vault id (16) ‖ root (32) ‖ creator's public signing key (32) ‖ URL length (2, big-endian) ‖ server URL ‖ checksum (4))
```

يصله مفتاح الخزنة على هيئة منحة موقَّعة عادية، مختومة لمفتاح X25519، تمامًا كما يحدث للعضو. ويُتحقق من المنحة مقابل مفتاح المنشئ **الموجود في الرمز**، لا مقابل مفتاح يحدده الخادم أبدًا. ولتسجيل الدخول، يوقّع تحديًا يُستخدم مرة واحدة:

```text
"octapass/v1/service-account-auth" ‖ 0x00 ‖ for each of id, challenge: length (4, big-endian) ‖ UTF-8 bytes
```

مجموع التحقق هو أول 4 بايت من SHA-256 لكل ما يسبقه. يكتشف النسخ التالفة ولا يحمي شيئًا.

## رمز الاسترداد

رمز الاسترداد هو 256 بت عشوائية إضافة إلى مجموع تحقق بطول 16 بت، ويُعرض في 55 محرفًا موزعة على 11 مجموعة من 5 محارف. يكتشف مجموع التحقق الأخطاء المطبعية. يغلّف الرمز مفتاح الحساب عبر `HKDF-SHA256(ikm = code, info = "octapass/v1/recovery")`. راجع [استرداد الحساب](/ar/docs/security/account-recovery/).

## فتح القفل بالجهاز في خزنة الويب

يمكن لخزنة الويب فتح القفل باستخدام قفل جهازك نفسه (Touch ID أو Face ID أو Windows Hello أو رمز مرور الجهاز) عبر مفتاح مرور مع امتداد WebAuthn PRF. يعطي مفتاح المرور سرًا بطول 32 بايت لا يعمل إلا على ذلك الجهاز بعد أن يتحقق الجهاز من أنك أنت. تحوّله الخزنة إلى مفتاح جهاز باستخدام `HKDF-SHA256(ikm = PRF output, salt = 16 random bytes, info = "octapass/v1/device-unlock")` وتغلّف به مفتاح حسابك (السياق `device-unlock`). تبقى النسخة المغلَّفة في ذلك المتصفح ولا تُرسل إلى الخادم أبدًا. وتظل بحاجة إلى كلمة المرور الرئيسية مرة كل 14 يومًا على الأقل.

## البقاء مفتوحًا

مع تفعيل [البقاء مفتوحًا](/ar/docs/features/biometric-unlock/)، تلفّ التطبيقات مفتاح حسابك بالطريقة نفسها (السياق `device-unlock`) تحت سر عشوائي من 32 بايتًا يُحفظ حيث يحميه قفل جهازك نفسه دون أن يسأل عنه شيء: على iPhone عنصر في سلسلة المفاتيح لا يوجد إلا ما دام للهاتف رمز دخول، وعلى Android مفتاح في مخزن المفاتيح لا يُستخدم إلا والهاتف مفتوح، وعلى Mac عنصر في سلسلة المفاتيح للتطبيق، وعلى Windows حماية البيانات التي يوفرها النظام لمستخدمك، وعلى Linux حلقة مفاتيح Secret Service. ولا تحفظ إضافة المتصفح شيئًا على القرص. وتغيير كلمة مرورك الرئيسية، أو تدوير مفتاحك السري، أو تسجيل الخروج، يحذفه، وما زال التحقق بكلمة المرور الرئيسية كل 14 يومًا قائمًا.

## متجهات الاختبار

توجد متجهات اختبار حتمية لاشتقاق المفاتيح، والمفتاح السري، ورمز الاسترداد، وغلاف النص المشفَّر، والملفات المرفقة، ورسائل OPAQUE، وفتح القفل بالجهاز، وحساب خدمة، وحساب كامل، في [`crates/octapass-core/tests/vectors`](https://github.com/octap-app/octapass/tree/main/crates/octapass-core/tests/vectors). يمكن للتطبيقات الأخرى استخدامها للتأكد من قابليتها للتشغيل البيني.

## القفل

يصفّر القفل مفتاح الحساب وكل مفتاح مشتق منه في الذاكرة، ويغلق فهرس البحث غير المشفَّر.

## ذات صلة

- [المصادقة](/ar/docs/security/authentication/)
- [استرداد الحساب](/ar/docs/security/account-recovery/)
- [نموذج التهديدات](/ar/docs/security/threat-model/)
