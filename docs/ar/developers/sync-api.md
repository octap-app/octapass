---
title: واجهة API للمزامنة
description: "الإصدار 1 من واجهة API للمزامنة في Octa Pass: تسجيل الدخول عبر OPAQUE، والرموز، وتغيير كلمة المرور الرئيسية وإعادة تعيينها، والمزامنة المبنية على المراجعات، وكتابة العناصر، والإشعارات الحية، والمشاركة، والعائلات، والمؤسسات، وتسجيل الدخول الموحّد، وروابط المشاركة، والوصول في الطوارئ."
status: in-progress
sidebar:
  order: 2
---

:::note[قيد التطوير]
الخادم الموجود في `apps/server` ينفّذ كل ما في هذه الصفحة عدا [المخطط له](#مخطط-له) في آخرها. قد تتغير التفاصيل قبل الإصدار الأول. تقدّم كل الخوادم وثيقة OpenAPI 3.1 الكاملة عند `GET /v1/openapi.json`، وهي محفوظة في `apps/server/openapi.json`. أنواع الطلبات والاستجابات موجودة في حزمة Rust المسماة `octapass-api`.
:::

واجهة API للمزامنة عامة وموثَّقة ليتمكن أصحاب الاستضافة الذاتية والعملاء من جهات خارجية من استخدامها. لا يخزّن الخادم إلا النص المشفَّر: لا يستطيع قراءة عناوين العناصر ولا الروابط ولا أسماء المستخدمين ولا كلمات المرور ولا الملاحظات.

## الاصطلاحات

- JSON عبر HTTPS تحت البادئة `/v1`، وأسماء الحقول بنمط camelCase.
- كل قيمة ثنائية (الأملاح ورسائل OPAQUE والمفاتيح والنص المشفَّر) تُكتب بصيغة **base64url دون حشو**.
- المعرّفات نصوص UUIDv7 يولّدها العميل، بأحرف صغيرة وشرطات.
- الطوابع الزمنية نصوص RFC 3339 بتوقيت UTC.
- ترسل الطلبات الموثَّقة `Authorization: Bearer <accessToken>`.
- حجم أجسام الطلبات محدود بـ 1 MiB، باستثناء `POST /v1/batch` و`POST /v1/vaults/{vaultId}/rotate` (16 MiB) و[رفع المرفقات](#المرفقات)، وهي بايتات خام حتى حد حجم الملف في الخادم.
- يقتصر CORS على الأصول المذكورة في `OCTAPASS_WEB_ORIGINS`.

## نقاط النهاية

| نقطة النهاية | الغرض |
|---|---|
| `GET /healthz`، `GET /readyz` | الحيوية (liveness)، والجاهزية (قاعدة البيانات ومخزن المرفقات يمكن الوصول إليهما) |
| `GET /v1/server-info` | الاسم والإصدار و`apiVersion: 1` ووضع التسجيل و`pushRelay` (تستطيع الهواتف التسجيل لتلقي إشعارات الدفع) |
| `GET /v1/openapi.json` | هذه الواجهة بصيغة OpenAPI 3.1 |
| `POST /v1/auth/prelogin` | معاملات KDF وملح الحساب لبريد إلكتروني |
| `POST /v1/auth/register/start`، `…/finish` | تسجيل OPAQUE مع التحقق من البريد الإلكتروني |
| `POST /v1/auth/login/start`، `…/finish` | تسجيل دخول OPAQUE، ويعيد الرموز وحزمة الحساب |
| `POST /v1/auth/login/second-factor` | إكمال تسجيل دخول طلب تسجيل الدخول بخطوتين |
| `POST /v1/auth/refresh` | تدوير رمزَي الوصول والتحديث |
| `POST /v1/auth/logout` | إلغاء رموز هذا الجهاز |
| `POST /v1/auth/reauth/start`، `…/finish` | تحقق جديد من كلمة المرور قبل إجراء خطير |
| `POST /v1/auth/recover/start`، `…/verify`، `…/registration`، `…/finish` | إعادة تعيين كلمة المرور الرئيسية برمز الاسترداد |
| `GET /v1/account` | حزمة الحساب |
| `DELETE /v1/account` | حذف الحساب وكل ما فيه |
| `GET /v1/account/usage` | ما تحتويه الخزنات التي يملكها الحساب، وحدود الخادم |
| `POST /v1/account/password/registration`، `PUT /v1/account/password` | تغيير كلمة المرور الرئيسية |
| `GET`، `DELETE /v1/account/two-step` | حالة تسجيل الدخول بخطوتين؛ وإيقافه |
| `POST /v1/account/two-step/totp`، `…/totp/confirm` | إضافة تطبيق المصادقة أو استبداله |
| `POST /v1/account/two-step/recovery-codes` | رموز استرداد جديدة |
| `POST /v1/account/two-step/security-keys/options`، `POST …/security-keys` | تسجيل مفتاح أمان |
| `DELETE /v1/account/two-step/security-keys/{id}` | إزالة مفتاح أمان |
| `DELETE /v1/account/two-step/trusted-devices` | إلزام كل جهاز آخر بتنفيذ الخطوة الثانية عند تسجيل دخوله التالي |
| `GET /v1/sync?since=…` | الخزنات، والعناصر التي تغيّرت منذ مراجعات معيّنة |
| `PUT /v1/vaults/{vaultId}/items/{itemId}` | إنشاء عنصر (`If-None-Match: *`) أو تحديثه (`If-Match`) |
| `DELETE /v1/vaults/{vaultId}/items/{itemId}` | نقل عنصر إلى سلة المهملات (`If-Match`) |
| `POST /v1/vaults/{vaultId}/items/{itemId}/restore` | استعادة عنصر من سلة المهملات |
| `GET /v1/vaults/{vaultId}/items/{itemId}/history` | آخر 10 نسخ سابقة من العنصر، الأحدث أولًا، نصًا مشفَّرًا |
| `POST /v1/batch` | حتى 1,000 عملية كتابة للعناصر دفعة واحدة، ذرّية لكل خزنة |
| `GET /v1/vaults/{vaultId}/items/{itemId}/attachments` | مرفقات عنصر: المعرّفات والأحجام المخزَّنة والأوقات |
| `PUT /v1/vaults/{vaultId}/items/{itemId}/attachments/{attachmentId}` | رفع ملف مشفَّر (بايتات خام) |
| `GET /v1/vaults/{vaultId}/items/{itemId}/attachments/{attachmentId}` | تنزيل ملف مشفَّر |
| `DELETE /v1/vaults/{vaultId}/items/{itemId}/attachments/{attachmentId}` | حذف ملف |
| `GET /v1/ws` | WebSocket: إشعارات "تغيّرت الخزنة"، وإشعارات تسجيل الخروج والحذف |
| `GET /v1/devices` | الأجهزة المسجَّل دخولها |
| `PATCH /v1/devices/current` | إعادة تسمية هذا الجهاز |
| `PUT /v1/devices/current/push`، `DELETE …` | تسجيل رمز الدفع لهذا الجهاز أو إزالته ([إشعارات الدفع](#إشعارات-الدفع)) |
| `DELETE /v1/devices/{deviceId}` | تسجيل خروج جهاز عن بُعد |
| `GET /v1/accounts/lookup?email=` | معرّف حساب ومفاتيحه العامة وبصمته، للمشاركة معه |
| `GET`، `POST /v1/transparency/…` | [سجل المفاتيح](#سجل-المفاتيح) |
| `POST /v1/vaults` | إنشاء خزنة مشتركة |
| `GET`، `POST /v1/vaults/{vaultId}/members` | عرض الأعضاء؛ وإضافة عضو (أو تغيير دوره) بتفويض موقّع |
| `DELETE /v1/vaults/{vaultId}/members/{accountId}` | إزالة عضو، أو المغادرة |
| `POST /v1/vaults/{vaultId}/rotate` | مفتاح خزنة جديد، عند الطلب أو بعد مغادرة عضو: تفويضات جديدة (أو المفتاح الملفوف لخزنة شخصية) ومفاتيح عناصر مُعاد لفّها في معاملة واحدة |
| `GET`، `POST /v1/families` | عائلة الحساب والدعوات؛ وإنشاء عائلة |
| `DELETE /v1/families/{familyId}` | حذف العائلة وخزنتها العائلية (Family vault) |
| `POST /v1/families/{familyId}/invites` | دعوة شخص، مع تفويضه لخزنة العائلة |
| `POST /v1/families/{familyId}/invites/accept` | الانضمام |
| `DELETE /v1/families/{familyId}/invites/{accountId}` | إلغاء دعوة أو رفضها |
| `DELETE /v1/families/{familyId}/members/{accountId}` | المغادرة، أو إزالة عضو |
| `GET`، `POST /v1/share-links` | روابط المشاركة الخاصة بالحساب؛ وإنشاء رابط |
| `GET /v1/share-links/{id}` | عرض رابط مشاركة (دون حاجة إلى حساب؛ ويُحتسب مشاهدة) |
| `DELETE /v1/share-links/{id}` | حذف أحد روابطك |
| `GET`، `POST /v1/emergency-contacts` | جهات الطوارئ في الاتجاهين؛ وإضافة جهة |
| `DELETE /v1/emergency-contacts/{id}` | إزالة جهة، أو التنحي عن كونك جهة |
| `POST /v1/emergency-contacts/{id}/request`، `…/deny`، `…/approve` | الجدول الزمني للوصول في الطوارئ |
| `GET /v1/emergency-contacts/{id}/release`، `…/sync` | للجهة، بعد الإفراج: المفتاح المختوم وخزنات مانح الوصول |
| `GET /v1/emergency-contacts/{id}/vaults/{vaultId}/items/{itemId}/attachments/{attachmentId}` | للجهة، بعد الإفراج: أحد ملفات مانح الوصول المشفَّرة |
| `PUT /v1/emergency-contacts/{id}/key` | لمانح الوصول: ختم مفتاح خزنة دُوّر مفتاحها للجهة من جديد |
| `POST /v1/emergency-contacts/{id}/takeover/registration`، `…/takeover` | لجهة تولٍّ أُفرج لها: كلمة مرور رئيسية ومفتاح سري ورمز استرداد جديدة لمانح الوصول |
| `POST /v1/families/{familyId}/organiser-recovery` | يسمح عضو للمنظِّم بالمساعدة في استرداد حسابه |
| `PUT /v1/account/secret-key` | مفتاح سري جديد، بكلمة المرور الرئيسية نفسها |
| `GET`، `POST /v1/orgs` | مؤسسة الحساب والدعوات؛ وإنشاء مؤسسة |
| `PATCH`، `DELETE /v1/orgs/{orgId}` | إعادة التسمية (المالك)؛ والحذف برمز إعادة مصادقة (المالك) |
| `GET /v1/orgs/{orgId}/members`، `PATCH`، `DELETE …/members/{accountId}` | الأعضاء؛ وتغيير دور (المالك)؛ والإزالة أو المغادرة |
| `POST /v1/orgs/{orgId}/invites`، `DELETE …/invites/{inviteId}`، `POST …/invites/{inviteId}/accept` | الدعوات |
| `GET`، `POST /v1/orgs/{orgId}/groups`، `PATCH`، `DELETE …/groups/{groupId}`، `PUT`، `DELETE …/groups/{groupId}/members/{accountId}` | المجموعات (المسؤول) |
| `GET`، `POST /v1/orgs/{orgId}/vaults`، `DELETE …/vaults/{vaultId}`، `PUT`، `DELETE …/vaults/{vaultId}/groups/{groupId}` | خزنات المؤسسة والمجموعات المرتبطة بها |
| `GET /v1/orgs/{orgId}/access`، `POST …/vaults/{vaultId}/grants` | ما تنتظره الخزنات من حامل المفتاح؛ وتقديمه |
| `PUT /v1/orgs/{orgId}/policies`، `GET …/events` | السياسات (المالك)؛ وسجل النشاط (المسؤول) |
| `GET`، `PUT`، `DELETE /v1/orgs/{orgId}/sso`، `PUT …/sso/saml`، `POST …/sso/test` | إعدادات موفّر الهوية، OpenID Connect أو SAML (المالك) |
| `POST /v1/auth/login/sso`، `GET /v1/sso/start/{token}`، `GET /v1/sso/callback`، `POST /v1/sso/saml/{orgId}/acs`، `GET /v1/sso/saml/{orgId}/metadata` | خطوة تسجيل الدخول الموحّد |
| `GET /v1/orgs/{orgId}/scim`، `POST …/scim/tokens`، `DELETE …/scim/tokens/{tokenId}` | رموز SCIM (المالك) |
| `/v1/scim/v2/Users`، `/v1/scim/v2/Groups`، `…/ServiceProviderConfig`، `…/ResourceTypes`، `…/Schemas` | SCIM 2.0 لموفّري الهوية، برمز SCIM الخاص بالمؤسسة |
| `GET /v1/security-log` | سجل الأمان الخاص بالحساب |
| `GET /v1/icons/{domain}` | أيقونة موقع بصيغة PNG (دون حاجة إلى حساب)؛ راجع [أيقونات المواقع](#أيقونات-المواقع) |

## المصادقة

يستخدم Octa Pass بروتوكول OPAQUE (RFC 9807) عبر `opaque-ke` 4.0.1، بالإعدادات التالية:

| الإعداد | القيمة |
|---|---|
| OPRF | ristretto255 |
| تبادل المفاتيح | TripleDH على ristretto255 مع SHA-512 |
| تمديد المفتاح | Identity (نُفّذ Argon2id أصلًا على العميل) |
| مدخل كلمة المرور | `auth_secret`، راجع [التشفير](/ar/docs/security/encryption/) |
| معرّف بيانات الاعتماد | البريد الإلكتروني، بعد قص الفراغات وتحويله إلى أحرف صغيرة |
| المعرّفات والسياق | القيم الافتراضية في opaque-ke (لا شيء) |

### إنشاء الحساب

1. استدعاء `POST /v1/auth/prelogin` اختياري قبل إنشاء الحساب. يولّد العميل ملح الحساب بنفسه (16 بايت).
2. يعيد `POST /v1/auth/register/start` مع `{ email, registrationRequest }` القيمة `{ registrationResponse, verificationRequired: true }` ويرسل بالبريد رمزًا من 6 أرقام صالحًا 15 دقيقة. في وضع التطوير تحتوي الاستجابة أيضًا على `devVerificationCode`. إذا كان للبريد حساب أصلًا، يتلقى صاحبه إشعارًا بدل الرمز، وتبدو الاستجابة مطابقة تمامًا.
3. يعيد `POST /v1/auth/register/finish` مع `{ email, verificationCode, registrationUpload, account, personalVault: { id, wrappedVaultKey } }` القيمة `{ accountId }`. خمس محاولات خاطئة تستنفد الرمز. طلب رمز جديد قبل انتهاء القديم يُبقي المحاولات الخاطئة التي جرت، فانتظر 15 دقيقة كاملة بعد الخامسة. يمكن إرسال 10 رموز كحد أقصى إلى بريد واحد، ومحاولة 20 رمزًا خاطئًا كحد أقصى، في كل يوم بتوقيت UTC.

يتحقق الخادم من شكل حزمة الحساب: `accountSalt` من 16 بايت، ومفاتيح عامة من 32 بايت، ومعاملات Argon2id بين m = 64 MiB وt = 3 وp = 1 وبين m = 1 GiB وt = 16 وp = 4 (النطاق الذي يقبله العملاء)، و[أغلفة النص المشفَّر](/ar/docs/security/encryption/#صيغة-النص-المشفَّر) بالإصدار 1 لكل مفتاح ملفوف.

### تسجيل الدخول

1. يعيد `POST /v1/auth/prelogin` مع `{ email }` القيمة `{ kdf, accountSalt }`. البريد غير المعروف يحصل على ملح وهمي حتمي والمعاملات الافتراضية، فلا تكشف الإجابة هل الحساب موجود.
2. يعيد `POST /v1/auth/login/start` مع `{ email, credentialRequest }` القيمة `{ loginId, credentialResponse }`. البريد غير المعروف يحصل على استجابة وهمية سليمة الشكل.
3. يعيد `POST /v1/auth/login/finish` مع `{ loginId, credentialFinalization, device: { name, platform }, trustedDeviceToken? }` القيمة `{ accessToken, refreshToken, expiresIn, account, trustedDeviceToken }`. يصلح `loginId` لمدة 30 ثانية ويعمل مرة واحدة. كل فشل، مهما كان سببه، هو الاستجابة نفسها `401` بنوع المشكلة `login-failed`.

تسجيل الدخول الذي ينشئ جلسة دون `trustedDeviceToken` صالح يرسل إلى مالك الحساب بالبريد إشعار "New sign-in" فيه اسم الجهاز ومنصته والوقت، إلا إذا كان الجهاز الوحيد للحساب خلال 10 دقائق من إنشائه.

إذا كان [تسجيل الدخول بخطوتين](#تسجيل-الدخول-بخطوتين) مفعّلًا للحساب ولم يُرسَل `trustedDeviceToken` صالح، فالجواب بدلًا من ذلك هو `401 second-factor-required` بعد إثبات كلمة المرور، ويستكمل تسجيل الدخول من هناك.

### الرموز

- رموز الوصول عشوائية وتدوم 15 دقيقة (`expiresIn: 900`).
- رموز التحديث عشوائية وتدوم 30 يومًا. يعيد `POST /v1/auth/refresh` مع `{ refreshToken }` زوجًا جديدًا، ويتوقف رمز التحديث القديم عن العمل. تقديم رمز تحديث سبق تدويره يلغي الجلسة كلها، لأن ذلك يعني أن الرمز نُسخ.
- لا يخزّن الخادم إلا تجزئات SHA-256 للرموز.
- يلغي `POST /v1/auth/logout` رموز الجهاز المتصل ويعيد `204`.

### إعادة المصادقة

الإجراءات الخطيرة تحتاج إلى إثبات أن المستخدم أدخل كلمة مروره الرئيسية للتو. يجري العميل المسجَّل دخوله تسجيل دخول OPAQUE ثانيًا:

1. يعيد `POST /v1/auth/reauth/start` مع `{ credentialRequest }` القيمة `{ reauthId, credentialResponse }`.
2. يعيد `POST /v1/auth/reauth/finish` مع `{ reauthId, credentialFinalization, purpose }` القيمة `{ reauthToken, expiresIn: 300 }`. قيمة `purpose` هي `delete-account` أو `change-password` أو `rotate-secret-key` أو `emergency-takeover` أو `two-step` (أي تغيير في تسجيل الدخول بخطوتين) أو `organisation` (حذف مؤسسة أو إحدى خزناتها).

يعمل رمز إعادة المصادقة مرة واحدة، للحساب الذي طلبه وللغرض المذكور فقط، خلال 5 دقائق. كلمة المرور الخاطئة تحصل على `401 login-failed`.

### تغيير كلمة المرور الرئيسية

يبقى مفتاح الحساب (ASK) كما هو، فلا يُعاد تشفير شيء: يرسل العميل سجل OPAQUE جديدًا ومفتاح ASK ملفوفًا بكلمة المرور الجديدة، مع ملح حساب جديد.

1. أعد المصادقة بالغرض `change-password`.
2. اشتق المفاتيح الجديدة، ثم استدعِ `POST /v1/account/password/registration` مع `{ registrationRequest }`. يعيد `{ registrationResponse }` ولا يخزّن شيئًا.
3. استدعِ `PUT /v1/account/password` مع الترويسة `X-Reauth-Token` و`{ registrationUpload, account: { kdf, accountSalt, wrappedAsk } }`. قد يحمل `account` أيضًا `recoveryWrappedAsk` لاستبدال رمز الاسترداد. الاستجابة `204`: يُسجَّل خروج كل جهاز آخر (تنتهي جلساته ويحصل على `session-revoked` ولا يتخطى بعد ذلك تسجيل الدخول بخطوتين)؛ ويبقى هذا الجهاز. يصل الحساب بريد إلكتروني ويُسجَّل إدخال `password-changed` في سجل الأمان.

### تدوير المفتاح السري

التبادل نفسه بكلمة المرور الرئيسية نفسها: يُشتق AUK وسر OPAQUE من كلمة المرور والمفتاح السري معًا، لذلك يعني المفتاح السري الجديد سجل OPAQUE جديدًا. ويبقى ASK كما هو، فلا يُعاد تشفير شيء وتظل جهات الطوارئ تعمل.

1. أعد المصادقة بالغرض `rotate-secret-key`.
2. ولّد المفتاح السري وملحًا جديدًا، ثم استدعِ `POST /v1/account/password/registration` كما سبق.
3. استدعِ `PUT /v1/account/secret-key` مع الترويسة `X-Reauth-Token` والجسم نفسه الذي يُرسل لتغيير كلمة المرور. قد يحمل `account` أيضًا `recoveryWrappedAsk` لاستبدال رمز الاسترداد كذلك. الاستجابة `204`: يُسجَّل خروج كل جهاز آخر، ويصل الحساب بريد إلكتروني ويُسجَّل إدخال `secret-key-rotated` في سجل الأمان.

اعرض المفتاح السري الجديد في مجموعة استرداد جديدة قبل أي شيء آخر. وإذا ضاعت الاستجابة، فقارن `accountSalt` من `GET /v1/account` بالملح الذي أرسلته، لتعرف هل نجح الطلب: فالمفتاح الجديد موجود على هذا الجهاز وحده. تسجّل الأجهزة الأخرى الدخول بالمفتاح الجديد؛ واحذف سجل فتح القفل بالجهاز على هذا الجهاز.

### إعادة تعيين كلمة المرور الرئيسية

من نسي كلمة المرور الرئيسية، أو فقد المفتاح السري أيضًا، يعيد تعيينها برمز الاسترداد من مجموعة الاسترداد. لا يستطيع الخادم التحقق من رمز الاسترداد؛ بل يثبت العميل أنه فتح ASK بالتوقيع بمفتاح Ed25519 الخاص بالحساب، الذي لا يفكّه إلا ASK.

1. يعيد `POST /v1/auth/recover/start` مع `{ email }` القيمة `{ recoveryId }` ويرسل بالبريد رمزًا من 6 أرقام. البريد الذي لا حساب له يحصل على الجواب نفسه ودون بريد. حصة الرموز اليومية هي نفسها حصة إنشاء الحساب، وتُحتسب منفصلة.
2. يعيد `POST /v1/auth/recover/verify` مع `{ recoveryId, verificationCode }` القيمة `{ account, challenge }`: حزمة الحساب، التي يفتح رمز الاسترداد حقل `recoveryWrappedAsk` فيها، و32 بايتًا عشوائية للتوقيع. الرمز الخاطئ هو `400 invalid-verification-code`؛ وخمسة منها تستنفد إعادة التعيين.
3. يفتح العميل ASK برمز الاسترداد (ومفاتيحه الخاصة بـ ASK)، ويشتق المفاتيح الجديدة، ويرسل `POST /v1/auth/recover/registration` مع `{ recoveryId, registrationRequest }` للحصول على `{ registrationResponse }`.
4. `POST /v1/auth/recover/finish` مع `{ recoveryId, registrationUpload, account: { kdf, accountSalt, wrappedAsk, recoveryWrappedAsk }, signature }`. إعادة التعيين تستبدل رمز الاسترداد دائمًا، لذلك `recoveryWrappedAsk` مطلوب. التوقيع `signature` هو Ed25519 بمفتاح توقيع الحساب على:

   ```text
   "openpass/v1/account-recovery" ‖ 0x00 ‖ for each field: len (u32 BE) ‖ UTF-8 bytes
   fields = accountId, challenge, registrationUpload, accountSalt, wrappedAsk, recoveryWrappedAsk
   ```

   الاستجابة `204`: يُسجَّل خروج كل الأجهزة ولا يتخطى أي منها تسجيل الدخول بخطوتين بعد الآن. التوقيع الخاطئ هو `401 login-failed` وينهي إعادة التعيين. يصل الحساب بريد إلكتروني ويُسجَّل إدخال `password-reset` في سجل الأمان.
5. سجّل الدخول بكلمة المرور الجديدة. إذا كان تسجيل الدخول بخطوتين مفعّلًا، يطلب تسجيل الدخول الخطوة الثانية كالمعتاد: إعادة التعيين لا تتخطاها أبدًا.

تدوم إعادة التعيين 15 دقيقة من `recover/start`. أي `recoveryId` غير معروف أو منتهٍ أو مكتمل، أو استدعاء `registration` قبل `verify`، هو `400 recovery-expired`: ابدأ من جديد.

### تسجيل الدخول بخطوتين

يمكن للحساب أن يطلب من الأجهزة الجديدة خطوة ثانية بعد كلمة المرور: رمز من تطبيق مصادقة، أو مفتاح أمان، أو رمز استرداد يُستخدم مرة واحدة. تحمي هذه الخطوة الوصول إلى النص المشفَّر ولا دور لها في التشفير.

**الأجهزة الموثوقة.** كل تسجيل دخول ناجح يعيد `trustedDeviceToken`. احتفظ به مع الجلسة وأرسله مع تسجيل الدخول التالي من الجهاز نفسه: الرمز الصالح يتخطى الخطوة الثانية، ويُستهلك ويُستبدل بالرمز الجديد في الجواب (لا يمكن لتسجيلَي دخول استخدامه معًا). يخص الرمز الجهاز الذي سجّل الدخول به، ولا يصلح إلا ما دام ذلك الجهاز في `GET /v1/devices` (لم يُسجَّل خروجه ولم تنقضِ جلسته)، ولمدة 30 يومًا كحد أقصى. تسجيل الخروج، أو تسجيل خروج الجهاز عن بُعد، أو انقضاء الجلسة، أو إعادة استخدام رمز تحديث للحساب، كلها تُنسي الرمز. تفعيل تسجيل الدخول بخطوتين يُنسي رموز كل الأجهزة عدا جهاز المتصل، و`DELETE /v1/account/two-step/trusted-devices` يفعل الشيء نفسه في أي وقت. التحديث لا يمنح رمزًا أبدًا.

**الخطوة الثانية.** يجيب `login/finish` بـ `401` ونوع المشكلة `second-factor-required` وعضو `secondFactor`:

```json
{
  "challengeId": "…",
  "methods": ["totp", "webauthn", "recovery-code"],
  "webauthn": { "challenge": "…", "rpId": "vault.example.com", "allowCredentials": ["…"], "timeout": 120000, "userVerification": "discouraged" },
  "expiresIn": 300
}
```

يوجد `webauthn` فقط عندما يكون للحساب مفاتيح أمان. أكمل بـ `POST /v1/auth/login/second-factor` مع واحد فقط مما يلي:

| الحقل | القيمة |
|---|---|
| `totpCode` | الرمز من 6 أرقام (RFC 6238: SHA-1، و30 ثانية، ويُقبل الخطوة السابقة والتالية). كل خطوة تعمل مرة واحدة. |
| `recoveryCode` | أحد رموز الاسترداد. لا يهم حجم الأحرف ولا الفراغات ولا الشرطات. كل رمز يعمل مرة واحدة. |
| `webauthn` | `{ credentialId, clientDataJson, authenticatorData, signature }` من `navigator.credentials.get()` بالخيارات المعطاة |

```json
{ "challengeId": "…", "totpCode": "123456" }
```

| الاستجابة | المعنى |
|---|---|
| `200` | الجسم نفسه كما في `login/finish` الناجح |
| `401 invalid-second-factor` | رمز خاطئ أو مستخدم سابقًا، أو إثبات (assertion) لا يتحقق. يبقى التحدي صالحًا لـ 5 محاولات إجمالًا. |
| `401 login-failed` | تحدٍّ غير معروف أو منتهٍ (5 دقائق) أو استُنفدت محاولاته: ابدأ تسجيل الدخول من جديد |
| `429 rate-limited` | 10 خطوات ثانية خاطئة للحساب (تُحتسب كل محاولة قبل فحصها، فلا تتجاوز التخمينات المتوازية الحد؛ وتُرد المحاولة الصحيحة): إيقاف مؤقت، ومحاولة واحدة إضافية كل 5 دقائق. يبقى التحدي صالحًا حتى انتهائه. يُسجَّل ويُرسل بريد إلى المالك (مرة واحدة في الساعة على الأكثر). |

**الإعدادات.** كل تغيير يحتاج إلى `X-Reauth-Token` بالغرض `two-step`، عدا تأكيد الإعداد، فمعرّف الإعداد يخوّله.

- يعيد `GET /v1/account/two-step` القيمة `{ enabled, methods, securityKeys: [{ id, name, createdAt, lastUsedAt }], recoveryCodesLeft, rpId }`.
- يعيد `POST /v1/account/two-step/totp` القيمة `{ setupId, secret, otpauthUri, expiresIn: 600 }`: سر مصادقة جديد (160 بت، base32) ورابط `otpauth://` لرمز QR. لا يتغير شيء بعد.
- يفعّل `POST /v1/account/two-step/totp/confirm` مع `{ setupId, code }` تسجيل الدخول بخطوتين بتطبيق المصادقة ذاك، أو يستبدل الحالي. يعيد `{ recoveryCodes }` (10 رموز مثل `ABCDE-12345`) فقط عندما فعّله. الرمز الخاطئ يحصل على `401 invalid-second-factor` ويبقى الإعداد صالحًا؛ والمنتهي يحصل على `400`.
- يعيد `POST /v1/account/two-step/recovery-codes` القيمة `{ recoveryCodes }` ويُبطل القديمة.
- يوقف `DELETE /v1/account/two-step` تسجيل الدخول بخطوتين ويزيل تطبيق المصادقة ومفاتيح الأمان ورموز الاسترداد. الاستجابة `204`.
- يعيد `POST /v1/account/two-step/security-keys/options` القيمة `{ setupId, publicKey: { challenge, rp, user, algorithms, excludeCredentials, timeout } }` لاستخدامها في `navigator.credentials.create()`. يجب أن يكون تسجيل الدخول بخطوتين مفعّلًا أصلًا (بتطبيق مصادقة)، وللحساب 10 مفاتيح كحد أقصى. الإفادة (attestation) هي `none`؛ ويُقبل مفتاحا ES256 وEd25519.
- يعيد `POST /v1/account/two-step/security-keys` مع `{ setupId, name, credentialId, clientDataJson, attestationObject }` سجل المفتاح. الاستجابة `409 already-exists` لمفتاح مسجَّل أصلًا.
- يزيل `DELETE /v1/account/two-step/security-keys/{id}` مفتاحًا. الاستجابة `204`.
- ينسّي `DELETE /v1/account/two-step/trusted-devices` كل جهاز موثوق عدا جهاز المتصل (دون إعادة مصادقة: لأنه يسحب الثقة فقط). تبقى الجلسات؛ وسجّل خروج الأجهزة بـ `DELETE /v1/devices/{deviceId}`. الاستجابة `204`.

ترتبط مفاتيح الأمان بمعرّف الطرف المعتمِد `rpId` (مضيف خزنة الويب افتراضيًا، ويمكن تجاوزه بـ `OCTAPASS_WEBAUTHN_RP_ID`)، ويجب أن تأتي مراسم WebAuthn من أصل خزنة ويب أو من الرابط العام للخادم.

يخزّن الخادم سر المصادقة مختومًا بمفتاح مشتق من سره الخاص (XChaCha20-Poly1305، مرتبط بالحساب)، ورموز الاسترداد على شكل HMAC، والمفاتيح العامة لمفاتيح الأمان.

## المزامنة

لكل خزنة `revision` (مراجعة) تزيد بواحد مع كل تغيير في عناصرها. يخزّن كل عنصر مراجعة الخزنة عند آخر تغيير فيه.

```http
GET /v1/sync?since=0192b7a0-…:41,0192b7a1-…:7
Authorization: Bearer …
```

```json
{
  "vaults": [{ "id": "0192b7a0-…", "type": "personal", "revision": 43, "wrappedVaultKey": "…", "role": "owner" }],
  "items": [{ "id": "…", "vaultId": "0192b7a0-…", "revision": 43, "encryptedItemKey": "…", "overview": "…", "details": "…", "updatedAt": "2026-10-23T09:12:44.120Z" }],
  "deleted": [{ "vaultId": "0192b7a0-…", "itemId": "…", "revision": 42 }]
}
```

- تسرد `vaults` دائمًا كل خزنة يستطيع الحساب الوصول إليها، مع مراجعتها الحالية. الخزنة التي تختفي من القائمة هي خزنة لم يعد الحساب قادرًا على الوصول إليها (غادرها أو أُزيل منها أو حُذفت): احذفها محليًا.
- قيمة `type` هي `personal` أو `shared` أو `family`، وقيمة `role` هي `read` أو `write` أو `manage` أو `owner`. للخزنات المشتركة والعائلية أيضًا `keyId` و`grant`، موصوفان تحت [المشاركة](#المشاركة).
- تحتوي `items` العناصر التي مراجعتها أكبر من المراجعة المعطاة في `since`، بما فيها العناصر في سلة المهملات (لها `deletedAt`). الخزنات التي تُترك خارج `since` تُعاد كاملة.
- تحتوي `deleted` العناصر المحذوفة نهائيًا. تبقى العناصر في سلة المهملات 30 يومًا ثم تُمحى، وتترك شاهد حذف (tombstone) لمدة 90 يومًا. العميل الذي لم يزامن لمدة أطول من ذلك عليه أن يزامن من الصفر (أن يترك الخزنة خارج `since`) وأن يحذف العناصر المحلية التي لم يعد الخادم يعيدها.
- تذكّر `revision` كل خزنة وأرسلها قيمةً لـ `since` في المرة التالية.
- الاستجابات مقسّمة إلى صفحات: نحو 1,000 عنصر أو 8 MiB لكل صفحة. عندما تكون `hasMore` تساوي `true` فقد توقفت الاستجابة مبكرًا. تكون `revision` كل خزنة حينها هي المراجعة التي اكتملت الاستجابة حتى بلوغها (الصفحة لا تنتهي أبدًا في منتصف مراجعة)، فخزّن المراجعات وزامن من جديد بها حتى تصبح `hasMore` تساوي `false`.

## الكتابة والتعارضات

أنشئ عنصرًا بـ `If-None-Match: *`، وحدّثه بآخر مراجعة رأيتها:

```http
PUT /v1/vaults/0192b7a0-…/items/0192b7a2-…
If-Match: "41"
Content-Type: application/json

{ "encryptedItemKey": "…", "overview": "…", "details": "…" }
```

الاستجابة `200` مع `{ "revision": 44 }` وترويسة `ETag: "44"`. يجب أن تكون الحقول الثلاثة كلها أغلفة نص مشفَّر بالإصدار 1؛ ويمكن أن يبلغ `overview` حتى 64 KiB و`details` حتى 512 KiB.

إذا تغيّر العنصر على الخادم، أو كان موجودًا أصلًا عند الإنشاء، فالاستجابة `409` بنوع المشكلة `conflict` والعنصر المخزَّن في `current`:

```json
{
  "type": "https://octap.app/problems/conflict",
  "title": "Conflict",
  "status": 409,
  "detail": "the item changed on the server",
  "current": { "id": "…", "vaultId": "…", "revision": 43, "encryptedItemKey": "…", "overview": "…", "details": "…", "updatedAt": "…" }
}
```

يدمج العميل حقلًا بحقل حين يستطيع. وإلا فإن نسخة الخادم هي التي تفوز، ويحتفظ العميل بنسخته على أنها نسخة تعارض. راجع [العمل دون اتصال والمزامنة](/ar/docs/features/offline-and-sync/).

- الكتابة دون `If-Match` أو `If-None-Match` تحصل على `428`.
- يحتاج `DELETE …/items/{itemId}` إلى `If-Match` وينقل العنصر إلى سلة المهملات.
- يُخرج `POST …/items/{itemId}/restore` العنصر من سلة المهملات.
- كل `PUT` يستبدل نسخة يضيف تلك النسخة إلى سجل العنصر، إلا إذا ضبط الجسم `"skipHistory": true`، للكتابات التي هي حفظ سجلات لا تعديلات (كتقدّم عدّاد رمز يُستخدم مرة واحدة). النقل إلى سلة المهملات والاستعادة لا يضيفان شيئًا. يعيد `GET …/history` القيمة `{ revisions: [{ revision, overview, details, updatedAt }] }`، ويستطيع كل عضو في الخزنة قراءتها. افتح النسخة بقيمة `encryptedItemKey` الحالية للعنصر: فالتعديل يُبقي مفتاح العنصر، والتدوير يعيد لفّه فقط. العميل الذي يمنح عنصرًا مفتاحًا جديدًا يفقد سجله. يُحتسب السجل في `itemBytes` ويذهب مع عنصره.
- حذف عنصر موجود أصلًا في سلة المهملات، أو استعادة عنصر ليس فيها، لا يغيّر شيئًا ويعيد المراجعة الحالية.
- الخزنات والعناصر التي لا يستطيع الحساب الوصول إليها تجيب بـ `404`. الأعضاء بدور `read` يحصلون على `403 forbidden`.
- في خزنة لها `keyId` (الخزنات المشتركة والعائلية، والخزنة الشخصية بدءًا من أول تدوير لها)، يجب أن يكون `encryptedItemKey` ملفوفًا بمفتاح الخزنة الحالي. بعد تدوير المفتاح، تجيب الكتابة التي ما زالت تستخدم المفتاح القديم بـ `409 vault-key-changed`: زامن، وافتح المفتاح الجديد، وشفّر من جديد. والعميل الذي يحمل تغييرات مصفوفة دون اتصال عليه أن يعيد لفّ مفاتيح عناصرها بعد فكّها بالمفتاح القديم قبل أن يتخلص منه؛ فكل مراجعة تقدّمت، لذلك يمر التعديل عندها بمعالجة التعارضات المعتادة.
- يمكن لكل حساب أن يخزّن افتراضيًا 50,000 عنصر و1 GiB من النص المشفَّر للعناصر في الخزنات التي يملكها، بما فيها سلة المهملات (ويمكن لأصحاب الاستضافة الذاتية تغيير ذلك). الكتابة التي ستتجاوز الحد تجيب بـ `403 quota-exceeded`. التحديثات التي لا تكبّر الحجم والحذف والاستعادة تعمل دائمًا.

## الكتابة على دفعات

ترسل عمليات الاستيراد والتعديل الجماعي كتابات كثيرة في طلب واحد:

```http
POST /v1/batch
Authorization: Bearer …
Content-Type: application/json

{
  "operations": [
    { "op": "put", "vaultId": "0192b7a0-…", "itemId": "0192b7a3-…", "item": { "encryptedItemKey": "…", "overview": "…", "details": "…" } },
    { "op": "put", "vaultId": "0192b7a0-…", "itemId": "0192b7a2-…", "ifMatch": 41, "item": { … } },
    { "op": "delete", "vaultId": "0192b7a0-…", "itemId": "0192b7a4-…", "ifMatch": "*" },
    { "op": "restore", "vaultId": "0192b7a0-…", "itemId": "0192b7a5-…" }
  ]
}
```

| `op` | `ifMatch` | يعادل |
|---|---|---|
| `put` | محذوف: إنشاء | `PUT` مع `If-None-Match: *` |
| `put` | مراجعة: تحديث تلك المراجعة | `PUT` مع `If-Match` |
| `put` | `"*"`: تحديث أي شيء مخزَّن، إن وُجد | الدفعات فقط |
| `delete` | مطلوب: مراجعة، أو `"*"` | `DELETE` مع `If-Match` |
| `restore` | يُتجاهل | `POST …/restore` |

الاستجابة `200` مع نتيجة واحدة لكل عملية، بترتيب الطلب:

```json
{
  "results": [
    { "itemId": "0192b7a3-…", "status": 200, "revision": 44 },
    { "itemId": "0192b7a2-…", "status": 409, "problem": { "type": "https://octap.app/problems/conflict", "status": 409, "current": { … }, … } },
    { "itemId": "0192b7a4-…", "status": 424, "problem": { "type": "https://octap.app/problems/batch-aborted", … } }
  ]
}
```

- كل `status` و`problem` هو ما كانت نقطة نهاية العنصر الواحد ستجيب به.
- **ذرّية لكل خزنة.** إذا فشلت أي عملية على خزنة، لا تُطبَّق أي عملية من عمليات تلك الخزنة: العمليات الفاشلة تبلغ بخطئها، وتجيب البقية بـ `424 batch-aborted`. العمليات على الخزنات الأخرى في الدفعة نفسها لا تتأثر.
- كل التغييرات على خزنة واحدة تتشارك مراجعة جديدة واحدة.
- 1,000 عملية و16 MiB للطلب كحد أقصى، وكل عنصر مرة واحدة على الأكثر. يجب أن تكون المعرّفات سليمة الصيغة. مخالفة أي منها ترفض الطلب كله بـ `400`.
- الاستجابة `500` تعني أن بعض الخزنات ربما كُتبت. زامن قبل إعادة المحاولة.

## المرفقات

ملفات تُحفظ مع عنصر. يُشفَّر كل ملف على الجهاز بمفتاح عشوائي خاص به، دفعة بعد دفعة (الصيغة في [README النواة](https://github.com/octap-app/octapass/tree/main/crates/octapass-core#attachments)). يدخل مفتاح الملف، ملفوفًا بمفتاح العنصر، في تفاصيل العنصر المشفَّرة مع اسم الملف ونوع الوسائط والحجم. يخزّن الخادم النص المشفَّر ولا يعرف إلا حجمه ووقت رفعه والعنصر الذي ينتمي إليه.

```http
PUT /v1/vaults/{vaultId}/items/{itemId}/attachments/{attachmentId}
Authorization: Bearer …
Content-Type: application/octet-stream
Content-Length: 70052

<the encrypted file>
```

- معرّف المرفق UUID ينشئه العميل. ارفع أولًا، ثم أضف الملف إلى تفاصيل العنصر بعملية كتابة عادية للعنصر، حتى لا يسرد أي عنصر ملفًا غير موجود. إذا فشلت عملية الكتابة تلك، فاحذف الملف المرفوع.
- يجب أن يكون الجسم مرفقًا مشفَّرًا (52 بايت على الأقل، ويبدأ ببايت الإصدار `0x01`) وبطول `Content-Length` تمامًا. دون `Content-Length` الجواب `411 length-required`؛ وإذا تجاوز حد حجم الملف فـ `413 payload-too-large`، قبل قراءة أي جزء من الجسم.
- يحتاج الرفع إلى `write` أو `manage` أو `owner` على الخزنة، وإلى عنصر ليس في سلة المهملات. يجيب بـ `201` مع `{ id, vaultId, itemId, size, createdAt }`، حيث `size` هو الحجم المخزَّن.
- تُحتسب البايتات على حصة مرفقات **مالك الخزنة** (1 GiB افتراضيًا)، لا على حصة من رفعها، كما هو الحال مع العناصر. الرفع الذي سيتجاوزها يحصل على `403 quota-exceeded`، وذلك أيضًا قبل قراءة جسمه.
- يبثّ `GET …/attachments/{attachmentId}` الملف المشفَّر (`application/octet-stream`) إلى أي عضو في الخزنة، بما فيه ما في سلة المهملات. ويسرد `GET …/attachments` ملفات عنصر.
- يجيب `DELETE …/attachments/{attachmentId}` (للكاتبين) بـ `204`؛ أخرج الملف من تفاصيل العنصر أولًا.
- تذهب الملفات مع عنصرها: عند تفريغ سلة المهملات بعد 30 يومًا، وعند حذف خزنتها، وعند حذف الحساب. يضع الخادم كل ملف في قائمة الحذف في المعاملة نفسها ثم يحذفه من التخزين بعدها مباشرة، ويعيد المحاولة بتباعد متزايد (من دقيقة إلى يوم) ما دام تخزين الكائنات لا يمكن الوصول إليه.
- إضافة الملفات أو إزالتها لا تغيّر مراجعة الخزنة؛ بل تغيّرها عملية كتابة العنصر التي تسردها.

يعيد `GET /v1/account/usage` ما تحتويه الخزنات التي يملكها الحساب، بما فيها سلة المهملات، بجانب حدود الخادم: `{ items, maxItems, itemBytes, maxItemBytes, attachmentBytes, maxAttachmentBytes, maxFileBytes }`. كل الأحجام بالبايتات المخزَّنة.

## المشاركة

تعمل الخزنات المشتركة مثل الشخصية في المزامنة والكتابة، لكن يحتفظ كل عضو بنسخته الخاصة من مفتاح الخزنة، مختومة بمفتاحه العام X25519 وموقّعة ممن منحها. يخزّن الخادم هذه التفويضات ويتحقق ممن يحق له منح ماذا؛ ولا يستطيع فتحها. الصيغ موجودة في [README الخاص بـ `octapass-core`](https://github.com/octap-app/octapass/tree/main/crates/octapass-core#sharing)، وتُتاح جهة العميل عبر `@octapass/core`.

### الأدوار

| الدور | يستطيع |
|---|---|
| `read` | المزامنة وفك التشفير |
| `write` | وأيضًا إنشاء العناصر وتعديلها وحذفها واستعادتها |
| `manage` | وأيضًا إضافة الأعضاء وإزالتهم (عدا المالكين)، وتغيير الأدوار الأدنى من `owner`، وتدوير المفتاح |
| `owner` | وأيضًا منح `owner` وإزالته. تُحذف الخزنة مع آخر مالك لها. |

### التفويضات

التفويض (grant) هو `{ vaultId, recipientAccountId, role, wrappedVaultKey, grantedBy, grantedAt, signature }`. القيمة `wrappedVaultKey` هي المفتاح المختوم (105 بايت للإصدار 1، و1,193 بايت للإصدار الهجين 2)، و`grantedAt` بالمللي ثانية منذ Unix، و`signature` توقيع Ed25519 للمانح على ذلك كله. لا يقبل الخادم إلا التفويضات التي يكون `grantedBy` فيها هو الحساب المسجَّل دخوله، ويخزّن مع كل واحد منها مفتاح توقيع المانح العام.

في المزامنة، يحمل سجل الخزنة المشتركة بقية تفويض العضو:

```json
{
  "id": "0192b7a9-…", "type": "shared", "revision": 12, "role": "write",
  "wrappedVaultKey": "AT…", "keyId": "Xq…",
  "grant": { "grantedBy": "0192b7a0-…", "granterPublicSignKey": "…", "grantedAt": 1761177600000, "signature": "…" }
}
```

يعيد العملاء بناء التفويض الموقّع من السجل ومن معرّف حسابهم، و**يتحققون من التوقيع قبل استخدام المفتاح**. يأتي المفتاح العام للمانح من الخادم، لذلك يقارن العملاء البصمات خارج القناة (حضوريًا أو في مكالمة) ويحذّرون من الأعضاء الذين لم يتحققوا منهم.

### الإنشاء والدعوة

1. `POST /v1/vaults` مع `{ id, keyId, grant }`، حيث يمنح `grant` الحساب المسجَّل دخوله دور `owner`. الاستجابة `201` مع سجل الخزنة.
2. يعيد `GET /v1/accounts/lookup?email=` القيمة `{ accountId, email, publicEncKey, publicSignKey, fingerprint }`، أو `404`. `fingerprint` هي صيغة الأرقام؛ وعلى العملاء أن يحسبوا بصمتهم الخاصة من المفاتيح.
3. `POST /v1/vaults/{vaultId}/members` مع `{ email, grant, keyId }` (يحتاج إلى `manage`؛ و`owner` لمنح `owner`). الجواب دائمًا `202` دون جسم: لبريد لا حساب له، أو لتفويض لحساب آخر، لا يُخزَّن شيء. إرسال تفويض لعضو موجود يستبدل تفويضه، وهكذا تتغير الأدوار. `keyId` اختياري ويسمّي مفتاح الخزنة الذي يختمه التفويض: إذا دُوّر المفتاح منذ ذلك، فالجواب `409 vault-key-changed` ولا يُخزَّن شيء. ينبغي للعملاء إرساله، حتى لا يترك تدوير يتسابق مع الدعوة تفويضًا بالمفتاح القديم.
4. يسرد `GET /v1/vaults/{vaultId}/members` القيم `{ accountId, email, role, publicEncKey, publicSignKey, fingerprint, grantedBy, addedAt }` لأي عضو.

تتشارك عمليات البحث والدعوات حصة واحدة لكل حساب (راجع [حدود المعدّل](#حدود-المعدّل))، لأنها المواضع التي يظهر فيها وجود بريد إلكتروني.

### إزالة الأعضاء وتدوير المفتاح

يمكن أيضًا تدوير مفتاح الخزنة عند الطلب، دون أن يغادر أحد: بالطلب نفسه، من أي شخص لديه `manage`.

يزيل `DELETE /v1/vaults/{vaultId}/members/{accountId}` عضوًا (يحتاج إلى `manage`، و`owner` لإزالة مالك)، أو يغادر عندما يكون المعرّف معرّفك. لا يستطيع آخر مالك المغادرة. أما الخزنات العائلية فتغيّر أعضاءها عبر [العائلات](#العائلات).

العضو المُزال ما زال يعرف مفتاح الخزنة القديم، لذلك يدوّره العميل بعد ذلك:

```http
POST /v1/vaults/0192b7a9-…/rotate
Content-Type: application/json

{
  "revision": 12,
  "keyId": "new key id",
  "grants": [{ "vaultId": "…", "recipientAccountId": "…", "role": "owner", … }, …],
  "items": [{ "itemId": "…", "encryptedItemKey": "wrapped under the new key" }, …],
  "invites": [{ "vaultId": "…", "recipientAccountId": "…", "role": "write", … }]
}
```

- `revision` هي مراجعة الخزنة التي زامن العميل إليها. أي تغيير منذ ذلك الحين يجيب بـ `409 vault-changed`: زامن ودوّر من جديد.
- يجب أن تغطي `grants` الأعضاء الحاليين بالضبط، كلٌّ بدوره الحالي. ويجب أن تغطي `items` عناصر الخزنة بالضبط، بما فيها سلة المهملات، كلٌّ ملفوف بالمفتاح الجديد. أي شيء آخر هو `400` ولا يتغير شيء.
- `invites` للخزنات العائلية: تفويض بالمفتاح الجديد لكل دعوة معلّقة يراد إبقاؤها، بدور الدعوة. التفويض لمن لا دعوة معلّقة له، أو تفويضان لدعوة واحدة، هو `400`. الدعوات المعلّقة التي تتركها خارج القائمة تُلغى، فلا تحتفظ أي دعوة بالمفتاح القديم؛ ويمكن للمنظِّم أن يدعو من جديد.
- في معاملة واحدة يستبدل الخادم كل تفويض وكل مفتاح عنصر والدعوات المُعاد ختمها و`keyId` الخاص بالخزنة، ويلغي الدعوات المعلّقة الأخرى، ويمنح كل عنصر المراجعة الجديدة، فيزامنها كل الأعضاء من جديد. لا تتغير أجسام العناصر: تبقى مشفَّرة بمفاتيح عناصرها.
- يحتاج إلى `manage`. الجواب هو `{ revision }`. ويُسجَّل `vault-key-rotated` في سجل الأمان للحساب الذي دوّر المفتاح.
- **الخزنة الشخصية** تُدوَّر بالطريقة نفسها، مع `"grants": []`، ودون `invites`، ومع `wrappedVaultKey`، وهو المفتاح الجديد ملفوفًا بمفتاح الحساب (السياق `vaultkey:<vaultId>`). لا تقبل `wrappedVaultKey` إلا الخزنات الشخصية، وهي تحتاج إليه. يمنح التدوير الخزنة `keyId`، فترفض منذ ذلك الحين الكتابات بالمفتاح القديم.
- تبقى جهات الطوارئ المحصورة بخزنة على المفتاح القديم وتُعلَّم بـ `keyStale`؛ راجع [الوصول في الطوارئ](#الوصول-في-الطوارئ).

## سجل المفاتيح

سجل للمفاتيح العامة للحسابات لا يقبل إلا الإضافة، ويتحقق منه العملاء (التصميم: الخطة 03؛ والصيغ: [README الخاص بـ `octapass-core`](https://github.com/octapass/octapass/tree/main/crates/octapass-core#key-log)). كل ما هنا يحتاج إلى حساب مسجَّل دخوله. **لم يراجعه خبير تشفير من خارج المشروع بعد.**

| نقطة النهاية | ما تفعله |
|---|---|
| `GET /v1/transparency/head?since=` | المفاتيح العامة للسجل، ورأس موقَّع الآن، وإثبات اتساق RFC 9162 من الحجم `since`. وعلى خادم لديه [شهود](/ar/docs/self-hosting/key-log-witnesses/)، بعد أن يوقّع النصاب، أيضًا `witnesses: { witnesses, quorum }` (مفاتيح تحقق C2SP) و`witnessed: { checkpoint, consistency }`: أحدث نقطة تحقق موقّعة توقيعًا مشتركًا بصيغة ملاحظة C2SP موقّعة، وإثبات اتساق منها إلى الرأس |
| `POST /v1/transparency/label` | `{ blinded }` ← `{ evaluated, proof }`: خطوة VOPRF التي تعطي تسمية البريد الإلكتروني. تُحتسب على حصة لكل حساب (40، ثم واحدة كل 30 ثانية) |
| `GET /v1/transparency/proof?label=&since=` | مثل `head` (مع حقول الشهود)، إضافة إلى `entry: { leafIndex, record, inclusion }` لأحدث سجل للتسمية، إن وُجد |
| `GET /v1/transparency/entries?start=&end=` | `{ start, frontier, leaves }`: حتى 10,000 ورقة بطول 64 بايت، والأشجار الفرعية الكاملة قبل `start`، ليتمكن العميل من إعادة بناء الجذر |
| `POST /v1/transparency/publish` | `{ record, wrappedPqPrivateKey }` ← `{ leafIndex }`. يخزّن مفتاح ML-KEM للحساب ويضيف سجله. إرسال السجل نفسه مرة أخرى يحصل على الجواب نفسه. وسجل مختلف لهذا السجل هو `409 already-exists`: خذ السجل من `GET /v1/account` |

يظهر `keyRecord` أيضًا في `GET /v1/account` (مع `wrappedPqPrivateKey`)، و`GET /v1/accounts/lookup`، وفي كل عضو في `GET /v1/vaults/{vaultId}/members`. لا يختم العملاء للمفتاح `publicPqKey` في السجل إلا بعد التحقق منه مقابل المفاتيح المقدَّمة معه. حذف الحساب يحذف سجله؛ وتبقى الورقة، لأن السجل لا يستطيع إعادة ورقة، ولا تحمل سوى تجزئتين.

## العائلات

العائلة منظِّم وحتى 5 أشخاص آخرين (6 إجمالًا؛ ويضبط أصحاب الاستضافة الذاتية `OCTAPASS_FAMILY_MAX_MEMBERS` من 2 إلى 100) يتشاركون خزنة عائلية (Family vault). كل حساب في عائلة واحدة على الأكثر.

1. `POST /v1/families` مع `{ id, vault }`، حيث `vault` هو الجسم نفسه الخاص بـ `POST /v1/vaults`. الاستجابة `201` مع سجل العائلة: `{ id, organiserId, vaultId, maxMembers, members, invites, createdAt }`.
2. `POST /v1/families/{familyId}/invites` مع `{ email, grant, keyId }` (للمنظِّم فقط؛ تفويض `write` للخزنة العائلية؛ و`keyId` كما في دعوات الخزنات). دائمًا `202`، كما في دعوات الخزنات. لا يمكن أن يتجاوز الأعضاء مع الدعوات المعلّقة الحد: `409 family-full`، ويُفحص قبل فحص البريد. يصل المدعوَّ بريد إلكتروني.
3. يعيد `GET /v1/families` القيمة `{ family, invitations }`: عائلة الحساب (مع الدعوات المعلّقة للمنظِّم فقط) والدعوات التي تلقّاها.
4. ينضم `POST /v1/families/{familyId}/invites/accept` فيحوّل تفويض الدعوة إلى عضوية في الخزنة العائلية. `409 already-exists` ما دام في عائلة أخرى.
5. يلغي `DELETE /v1/families/{familyId}/invites/{accountId}` دعوة (المنظِّم) أو يرفضها (المدعوّ).
6. يغادر `DELETE /v1/families/{familyId}/members/{accountId}` العائلة، أو (المنظِّم) يزيل عضوًا، فيغادر أيضًا الخزنة العائلية. يدوّر المنظِّم مفتاحها بعد ذلك، مع تفويضات بالمفتاح الجديد للدعوات المعلّقة في `invites` (وما يُترك خارجها يُلغى). لا يستطيع المنظِّم المغادرة؛ ويحذف `DELETE /v1/families/{familyId}` العائلة وخزنتها.

## المؤسسات

القواعد موجودة في [المؤسسات](/ar/docs/features/organisations/). الأدوار هي `owner` و`admin` و`member`، ولا تفتح شيئًا. كل حساب في مؤسسة واحدة. المؤسسات التي ليس الحساب عضوًا فيها تجيب بـ `404`؛ والدور الأدنى من اللازم يجيب بـ `403`.

خزنة المؤسسة خزنة مشتركة تحمل `orgId` في `VaultRecord` الخاص بها. تُفتح كما تُفتح أي خزنة مشتركة، ويعمل `POST /v1/vaults/{vaultId}/rotate` كالمعتاد. يجب أن يكون أعضاؤها أعضاء في المؤسسة: `POST /v1/vaults/{vaultId}/members` لأي شخص آخر يجيب بـ `202` ولا يخزّن شيئًا، كما في البريد غير المعروف.

1. `POST /v1/orgs` مع `{ id, name }` يجعل المستدعي المالك. ويجيب `POST …/invites` مع `{ email, role }` دائمًا بـ `202`. الدعوات لا تحمل مفتاحًا وتدوم 14 يومًا. ويسرد `GET /v1/orgs` الدعوات الموجّهة إلى بريد الحساب، مع السياسات التي تأتي مع الانضمام.
2. يأخذ `POST …/vaults` الجسم نفسه الخاص بـ `POST /v1/vaults`. يستحق الشخص خزنة بصفته مالكًا للمؤسسة (الدور `owner`)، أو عضوًا مباشرًا، أو عبر مجموعة مرتبطة. والدور الأعلى هو الذي يُعتمد.
3. يسرد `GET …/access` الخزنات التي ينتظرها شيء: `grants` يجب إنشاؤها، وهل يجب `rotate`. وتعني `canApply` أن المستدعي يحمل المفتاح ويحق له إدارة الخزنة. **هذه القائمة تأتي من الخادم: اعرض كل شخص، مع بصمة محسوبة على الجهاز، على إنسان، ولا تختم شيئًا دون تأكيده.** وإلا فإن خادمًا معاديًا يستطيع إضافة نفسه.
4. `POST …/vaults/{vaultId}/grants` مع `{ keyId, grants }` يخزّنها. يجب أن يكون كل منها من المستدعي، لشخص يستحقها، بذلك الدور تمامًا (`400`)؛ والمفتاح الذي دُوّر منذ ذلك يجيب بـ `409 vault-key-changed`.

يحدث سحب الوصول على الخادم فورًا. كل من لم يعد مستحقًا يفقد الخزنة وتُعلَّم للتدوير. وكل من انخفض الدور الذي يستحقه يفقدها حتى يُنشأ تفويض بدور أدنى، لأن الدور جزء من التفويض الموقَّع. والتغيير الذي يترك خزنة دون أحد يستطيع إدارتها يجيب بـ `409 org-vault-orphaned` مع `vaultIds`؛ ويمضي `DELETE …/members/{accountId}?orphanVaults=true` رغم ذلك. ويحتاج `DELETE …/vaults/{vaultId}` إلى رمز إعادة مصادقة بالغرض `organisation`، ولا يحتاج إلى مفتاح.

يأخذ `PUT …/policies` القيمة `{ requireTwoStep, requireSso, ssoMaxAgeHours, disableShareLinks, disableEmergencyAccess, disableExport, maxAutoLockMinutes?, minPasswordLength? }`. يفرض الخادم الخمس الأولى: `403 org-policy`، أو حجب الخزنات عن `/v1/sync` وعن مسارات الخزنات للعضو الذي لم يفعّل تسجيل الدخول بخطوتين (`accessWithheld` في `GET /v1/orgs`). أما `disableExport` و`maxAutoLockMinutes` و`minPasswordLength` فعلى العملاء تطبيقها. ويحتاج `requireSso` إلى تجربة تسجيل دخول مكتملة، وإلا فـ `400 sso-config`.

### تسجيل الدخول الموحّد

يضيف تسجيل الدخول الموحّد خطوة بعد OPAQUE ولا يشارك في اشتقاق المفاتيح. راجع [تسجيل الدخول الموحّد](/ar/docs/features/single-sign-on/).

1. يجيب `POST /v1/auth/login/finish` بـ `401 sso-required` بعد أن تثبت صحة كلمة المرور، مع `sso: { challengeId, url, orgName, expiresIn }`. المالكون مستثنون.
2. يفتح العميل `url` في متصفح ويحتفظ بـ `challengeId`. يرسل الخادم، بصفته الطرف المعتمِد في OpenID Connect، المتصفح إلى الموفّر (تدفق الرمز، وPKCE، و`state`، و`nonce`)، وينتهي `GET /v1/sso/callback` بصفحة فيها رمز من 6 أرقام.
3. يجيب `POST /v1/auth/login/sso` مع `{ challengeId, code }` كما يجيب `login/finish`، أو بـ `401 second-factor-required` إن كانت الخطوة الثانية تالية. `409 sso-pending`: لم ينتهِ المتصفح بعد. `401 invalid-second-factor`: رمز خاطئ، حتى 5 مرات. `401 login-failed`: ابدأ من جديد.

يفشل التحديث بـ `401 unauthorized` متى صار تسجيل الدخول الموحّد للجلسة أقدم من `ssoMaxAgeHours` (0: عند تسجيل الدخول فقط). ويسجّل العميل الدخول حينها من جديد.

**SAML.** يأخذ `PUT …/sso/saml` القيمة `{ metadataXml }`، أو `{ entityId, ssoUrl, certificates }` (من 1 إلى 4 شهادات بصيغة PEM أو DER بترميز base64)، ويستبدل إعدادات OpenID Connect؛ ويفعل `PUT …/sso` العكس. وكلاهما يمحو ربط كل عضو حين يتغيّر الموفّر. يجيب `GET …/sso` بـ `protocol` (`oidc` أو `saml`) حين توجد إعدادات، وبـ `saml: { entityId, ssoUrl, certificates: [{ sha256, notAfter? }] }` لـ SAML، ودائمًا بـ `samlServiceProvider: { entityId, acsUrl, metadataUrl }`. ومع إعدادات SAML، ترسل الخطوة 2 المتصفح إلى موفّر الهوية مع AuthnRequest مضغوط (ربط HTTP-Redirect)، ويرسل الموفّر `SAMLResponse` و`RelayState` إلى `POST /v1/sso/saml/{orgId}/acs`، الذي ينتهي بصفحة الرمز نفسها. القواعد التي يجب أن يستوفيها الرد في [تسجيل الدخول الموحّد](/ar/docs/features/single-sign-on/). و`GET /v1/sso/saml/{orgId}/metadata` هو البيانات الوصفية لمزوّد الخدمة (`application/samlmetadata+xml`).

### SCIM

يستدعي موفّرو الهوية `/v1/scim/v2` (RFC 7643 وRFC 7644) مع `Authorization: Bearer opscim_…`، وهو رمز أنشأه مالك بـ `POST /v1/orgs/{orgId}/scim/tokens` و`{ name }`، فيجيب بـ `{ token, secret }` ولا يظهر السر إلا تلك المرة (10 لكل مؤسسة، ثم `409 already-exists`). ويجيب `GET …/scim` بـ `{ baseUrl, tokens }`؛ ويلغي `DELETE …/scim/tokens/{tokenId}` رمزًا. تستخدم طلبات SCIM وأجوبتها `application/scim+json` ومخطط أخطاء SCIM (`status` نصًا، و`scimType`)، لا مستندات المشكلات؛ والرمز المفقود أو الخاطئ يُجاب بـ `401`.

يحصل المستخدم المُزوَّد على دعوة (بلا داعٍ، بدور `member`)، ولا ينضم إلا بقبولها عبر `POST …/invites/{inviteId}/accept`؛ والمستخدم النشط العضو من قبل يُربط فورًا. ومجموعة SCIM مجموعةٌ في المؤسسة يديرها الموفّر (وتبقى المجموعات المنشأة عبر `/v1/orgs` بعيدة عن متناوله)؛ ويُطبَّق أعضاؤها على مجموعة المؤسسة لمن كان عضوًا من المستخدمين. والتعطيل (`active: false`) أو الحذف أو الإخراج من مجموعة يوفّق خزائن المؤسسة فورًا كما يفعل تغيير المسؤول، لكنه يمضي حين يترك خزنة بلا مدير. ولا يُزال المالكون أبدًا. انظر [التزويد عبر SCIM](/ar/docs/features/scim/) لما هو مدعوم.

## روابط المشاركة

يحمل رابط المشاركة عنصرًا واحدًا إلى شخص بلا حساب. يشفّر العميل لقطة بمفتاح عشوائي يوضع في جزء الرابط بعد `#` (`https://<host>/s/<id>#<key>`)، وهو جزء لا ترسله المتصفحات إلى الخوادم أبدًا.

- `POST /v1/share-links` مع `{ ciphertext, expiresAt, maxViews, passphraseRequired }`: يكون `expiresAt` من ساعة إلى 30 يومًا من الآن، و`maxViews` من 1 إلى 100، والنص المشفَّر حتى 600 KiB. الاستجابة `201` مع `{ id, expiresAt }`. يمكن أن يكون للحساب 100 رابط مفتوح (`403 quota-exceeded`).
- لا يحتاج `GET /v1/share-links/{id}` إلى حساب. يحتسب مشاهدة ويعيد `{ ciphertext, passphraseRequired, expiresAt, viewsLeft }` مع `Cache-Control: no-store`. آخر مشاهدة تحذف الرابط؛ والروابط المنتهية والمستنفدة وغير المعروفة كلها تجيب بـ `404`. لكل عنوان IP 10 مشاهدات دفعة واحدة، ثم مشاهدة كل 6 ثوانٍ.
- يسرد `GET /v1/share-links` الروابط المفتوحة للحساب دون نصها المشفَّر؛ ويحذف `DELETE /v1/share-links/{id}` رابطًا (و`404` لرابط غيرك).

## الوصول في الطوارئ

يختم مانح الوصول مفتاح حسابه (ASK)، أو مفتاح خزنة واحدة، بالمفتاح العام لجهة اتصال. يمكن للجهة أن تطلبه؛ وما لم يرفض المانح الطلب خلال فترة الانتظار، يفرج عنه الخادم.

1. `POST /v1/emergency-contacts` مع `{ contactAccountId, sealedKey, scope, accessLevel, waitDays }`. قيمة `scope` هي `{ "type": "account" }` أو `{ "type": "vault", "vaultId": "…" }` (خزنة يملكها المانح)، وقيمة `accessLevel` هي `view` أو `takeover`، وقيمة `waitDays` من 1 إلى 30. الاستجابة `201` مع السجل؛ و`409 already-exists` للجهة نفسها مرتين. يصل الجهة بريد إلكتروني، لذلك إضافة الجهات [محدودة المعدّل](#حدود-المعدّل)، لكل حساب ولكل جهة؛ وإزالة جهة ثم إضافتها من جديد تُحتسب جهة جديدة.
2. يعيد `GET /v1/emergency-contacts` القيمة `{ granted, received }`: سجلات فيها `{ id, grantorId, grantorEmail, contactId, contactEmail, scope, accessLevel, waitDays, status, requestedAt, releasesAt, releasedAt, createdAt }`. قيمة `status` هي `idle` أو `requested` أو `released`.
3. ترسل الجهة `POST …/{id}/request`. يصل المانح بريد إلكتروني فورًا وتذكير كل يوم ما دام الطلب ينتظر.
4. يستطيع المانح `POST …/{id}/deny` في أي وقت، وهذا يسترد أيضًا مفتاحًا أُفرج عنه أصلًا، أو `POST …/{id}/approve` للإفراج عنه الآن.
5. عند `releasesAt` يُفرَج عن الطلب، ويصل الطرفين بريد إلكتروني.
6. بعد الإفراج، تستدعي الجهة `GET …/{id}/release`: `{ contact, sealedKey, grantor }`. لنطاق الحساب، يكون `grantor` هو حزمة حساب المانح (يفتح مفتاح ASK المُفرَج عنه مفاتيحها الخاصة). نطاق الخزنة لا يحصل على `grantor`: لأن المفاتيح الخاصة في الحزمة ستفتح الخزنات المشتركة مع المانح، فتحصل الجهة على المفتاح المختوم لتلك الخزنة وحدها. ويُجري `GET …/{id}/sync?since=` مزامنة للقراءة فقط لخزنات المانح ضمن النطاق. ويبثّ `GET …/{id}/vaults/{vaultId}/items/{itemId}/attachments/{attachmentId}` أحد [مرفقات](#المرفقات) المانح المشفَّرة من خزنة ضمن النطاق، تمامًا كتنزيل المانح نفسه؛ والملف في خزنة خارج النطاق هو `404`. تفك الجهة تشفيره بمفتاح العنصر من العنصر المزامَن ومفتاح الملف في تفاصيله. قبل الإفراج، تجيب الثلاثة بـ `403`.
7. ينهي `DELETE …/{id}` الأمر، من أي من الطرفين.

كل خطوة تُسجَّل في سجل الأمان الخاص بالمانح.

**بعد التدوير.** تحمل السجلات أيضًا `keyStale` عندما تكون صحيحة (نطاق خزنة دُوّر مفتاحها) و`organiserRecovery` عندما تكون صحيحة. يجدّد المانح السجل القديم بـ `PUT …/{id}/key` مع `{ sealedKey, keyId }`، حيث يسمّي `keyId` مفتاح الخزنة الذي يختمه: `409 vault-key-changed` إن دُوّر منذ ذلك. ولا يجوز للعملاء فعل ذلك إلا بعد أن يقارن المستخدم بصمة الجهة، ولا يفعلونه من تلقاء أنفسهم أبدًا: فالخادم يتحكم في `keyStale` وفي المفتاح العام الذي يعيده البحث كليهما.

**تولّي الحساب.** يحتاج `takeover` إلى نطاق الحساب (وإلا فـ `400`). بعد الإفراج، تستطيع الجهة استبدال بيانات اعتماد المانح:

1. `GET …/{id}/release`، ثم افتح ASK وأنشئ بيانات اعتماد جديدة بمفتاح سري وملح ورمز استرداد جديدة.
2. `POST …/{id}/takeover/registration` مع `{ registrationRequest }`. يشغّل OPAQUE تحت بريد المانح ولا يخزّن شيئًا.
3. `POST …/{id}/takeover` مع `X-Reauth-Token` (رمز **الجهة** نفسها، بالغرض `emergency-takeover`) و`{ registrationUpload, account, signature }`. القيمة `account.recoveryWrappedAsk` مطلوبة. والتوقيع `signature` بمفتاح Ed25519 الخاص بالمانح، على `"openpass/v1/emergency-takeover" ‖ 0x00 ‖` متبوعًا بقيم UTF-8 مسبوقة بطولها (u32 big-endian): `recordId, grantorId, contactId, currentAccountSalt, registrationUpload, accountSalt, wrappedAsk, recoveryWrappedAsk`. راجع متجه الاختبار `emergencyTakeover` في `crates/octapass-core/tests/vectors/key-rotation.json`.

الاستجابة `204`، في معاملة واحدة: تُستبدل بيانات الاعتماد، ويُسجَّل خروج كل أجهزة المانح، ويُوقف تسجيل الدخول بخطوتين، ويُحذف السجل، ويُسجَّل `emergency-takeover` (مع `two-step-disabled` إن كان مفعّلًا). ويصل المانح بريد إلكتروني. أما السجل الذي رُفض أو أُزيل أولًا، أو سجل العرض، أو التوقيع الخاطئ، أو الملح الذي تغيّر منذ ذلك (أي تغيير في بيانات الاعتماد) فيجيب بـ `403`: اقرأ الإفراج من جديد. وإذا ضاعت الاستجابة، فإن اختفاء السجل من `GET /v1/emergency-contacts` يعني أن الطلب نجح: فالمجموعة الجديدة هي النسخة الوحيدة.

**الاسترداد عبر المنظِّم.** يختار عضو العائلة ذلك بـ `POST /v1/families/{familyId}/organiser-recovery` مع `{ sealedKey, waitDays }`، فيختم ASK الخاص به للمنظِّم. الاستجابة `201` مع سجل طوارئ: نطاق الحساب، و`takeover`، و`organiserRecovery: true`. و`409 already-exists` إن كان مفعّلًا أصلًا، أو إن كان المنظِّم جهة طوارئ له أصلًا. ويتبع خطوات الطلب والانتظار والتولّي نفسها، إلا أن `…/sync` وتنزيل المرفقات يجيبان بـ `403`: يستطيع المنظِّم إعادة تعيين الحساب، ولا يستطيع قراءته أبدًا. يوقفه `DELETE /v1/emergency-contacts/{id}`؛ وتزيله أيضًا مغادرة العائلة، أو الإزالة منها، أو حذف العائلة.

## حسابات الخدمة

يقرأ [حساب الخدمة](/ar/docs/features/service-accounts/) خزنة مشتركة واحدة دون حضور أي شخص. يُنشأ كل شيء على جهاز منشئه؛ ولا يصل الرمز إلى الخادم أبدًا.

| الطريقة | المسار | من | ماذا |
|---|---|---|---|
| `POST` | `/v1/vaults/{vaultId}/service-accounts` | مدير خزنة مشتركة | يخزّن المفاتيح العامة والاسم المختوم والتفويض الموقَّع. `grant.recipientAccountId` هو معرّف حساب الخدمة؛ والدور `read` أو `write`. |
| `GET` | `/v1/vaults/{vaultId}/service-accounts` | المدير | كلها، بما فيها الملغاة. |
| `DELETE` | `/v1/vaults/{vaultId}/service-accounts/{id}` | المدير | يلغيه فورًا. دوّر مفتاح الخزنة بعد ذلك. |
| `POST` | `/v1/service-accounts/challenge` | أي أحد | تحدٍّ يُستخدم مرة واحدة، صالح 30 ثانية. ولا يتوقف الجواب على وجود المعرّف. |
| `POST` | `/v1/service-accounts/session` | أي أحد | يتحقق من توقيع Ed25519 على التحدي، ويجيب برمز وصول صالح 15 دقيقة. |
| `GET` | `/v1/service-accounts/sync` | حساب الخدمة | خزنته الوحيدة، بشكل `GET /v1/sync`. وكل صفحة أولى قيدُ `service-account-read` في سجل الأمان الخاص بمنشئه. |
| `PUT` | `/v1/service-accounts/items/{itemId}` | حساب خدمة بدور `write` | مثل `PUT /v1/vaults/{vaultId}/items/{itemId}`. |

لا يُقبل رمز وصول الشخص على النقطتين الأخيرتين، ولا يُقبل رمز حساب الخدمة في أي مكان آخر.

يأخذ `POST /v1/vaults/{vaultId}/rotate` القيمة `serviceGrants`: تفويض بالمفتاح الجديد لكل حساب خدمة نشط، بدوره. وما يُترك خارجها يبقى بمفتاح لم يعد يفتح الخزنة، فيفشل بأمان (fails closed).

## سجل الأمان

يعيد `GET /v1/security-log` أحداث الحساب نفسه، الأحدث أولًا، وتُحفظ سنة: `{ events: [{ type, createdAt, otherAccountEmail, emergencyContactId }] }`. الأنواع: `emergency-contact-added` و`emergency-contact-removed` و`emergency-access-requested` و`emergency-access-denied` و`emergency-access-approved` و`emergency-access-released` و`two-step-enabled` و`two-step-disabled` و`authenticator-changed` و`security-key-added` و`security-key-removed` و`recovery-codes-renewed` و`recovery-code-used` و`two-step-locked` و`trusted-devices-forgotten` و`password-changed` و`password-reset` و`vault-exported` و`secret-key-rotated` و`vault-key-rotated` و`emergency-takeover` و`organiser-recovery-enabled` و`organiser-recovery-disabled` و`service-account-created` و`service-account-revoked` و`service-account-read` و`service-account-wrote` و`service-account-denied` و`connect-secret-read`. يُحذف `otherAccountEmail` متى حُذف ذلك الحساب. تحمل قيود حسابات الخدمة `serviceAccountId`؛ وتحمل قيود `connect-secret-read` القيمة `sealedDetail`، وهي غلاف لا يفتحه سوى الحساب. يرسل العملاء هذه القيم بـ `POST /v1/security-log/connect` مع `{ sealedDetails: [...] }`، 100 على الأكثر في كل مرة. تُسرد أحدث 500 قيد من القيود المتكررة (`service-account-read` و`service-account-wrote` و`connect-secret-read`) وأحدث 500 من كل القيود الأخرى، حتى لا تستطيع الآلات إزاحة قيود الأشخاص.

## الإشعارات الحية

`GET /v1/ws` هو WebSocket يخبر العميل المسجَّل دخوله متى يزامن. ولا ينقل بيانات العناصر أبدًا.

1. اتصل، ثم أرسل `{ "type": "auth", "accessToken": "…" }` رسالةً أولى، خلال 10 ثوانٍ. لا تستطيع المتصفحات ضبط الترويسات على WebSocket، لذلك يسافر الرمز في هذه الرسالة.
2. يجيب الخادم بـ `{ "type": "authenticated", "expiresIn": 897 }`، وهي الثواني المتبقية لرمز الوصول ذاك.
3. بعد كل تحديث للرمز، أرسل رسالة `auth` جديدة برمز الوصول الجديد، للجهاز نفسه. عندما ينتهي الرمز دون رسالة، يغلق الخادم الاتصال.

ثم يرسل الخادم:

| الرسالة | المعنى |
|---|---|
| `{ "type": "vault-changed", "vaultId": "…", "revision": 44 }` | تغيّرت خزنة يستطيع الحساب الوصول إليها. زامنها إن كانت المراجعة أحدث من مراجعتك. |
| `{ "type": "membership-changed", "vaultId": "…" }` | كسبت خزنة مشتركة أو عائلية عضوًا أو فقدته، أو دُوّر مفتاحها. تُرسل إلى كل عضو، وإلى من فقد الوصول للتو. زامن. |
| `{ "type": "session-revoked" }` | سُجّل خروج هذا الجهاز (عن بُعد، أو بتسجيل خروجه هو، أو لأن رمز التحديث الخاص به أُعيد استخدامه). يُغلق الاتصال. |
| `{ "type": "account-deleted" }` | حُذف الحساب. امسح البيانات المحلية. يُغلق الاتصال. |

- يرسل الخادم ping كل 30 ثانية ويقطع الاتصالات التي لا تجيب قبل الـ ping التالي. المتصفحات تجيب عن pings تلقائيًا.
- رمز الإغلاق `4401` يعني أن الاتصال غير موثَّق أو لم يعد موثَّقًا (رمز سيئ أو منتهٍ، أو جلسة مُلغاة، أو حساب محذوف). و`4400` يعني خطأ في البروتوكول، كرسالة أولى ليست `auth`. أعد الاتصال مع تأخير عشوائي (jitter) بعد حالات الإغلاق الأخرى.
- الإشعارات تلميح لا سجل. العميل الذي كان دون اتصال، أو فاتته رسالة، يزامن عند إعادة الاتصال كالمعتاد.
- لا ترى نسخة الخادم الواحدة إلا التغييرات المكتوبة عبرها. على عمليات النشر متعددة النسخ أن تُبقي العملاء يزامنون عند التركيز وإعادة الاتصال إلى أن تُشارَك الإشعارات بين النسخ.

## الأجهزة

كل تسجيل دخول ينشئ جهازًا يسمّيه العميل.

- يعيد `GET /v1/devices` القيمة `[{ id, name, platform, createdAt, lastSeenAt, current }]` للأجهزة المسجَّل دخولها في الحساب، الأحدث ظهورًا أولًا. يتحدّث `lastSeenAt` عند تحديث الرمز وعند تسجيل الدخول عبر WebSocket، فهو دقيق إلى نحو 15 دقيقة.
- يعيد `PATCH /v1/devices/current` مع `{ name }` (من 1 إلى 64 حرفًا) تسمية الجهاز المتصل. الاستجابة `204`.
- يسجّل `DELETE /v1/devices/{deviceId}` خروج ذلك الجهاز: تتوقف رموزه عن العمل، وتحصل اتصالاته الحية على `session-revoked`، ولا يتخطى بعد ذلك تسجيل الدخول بخطوتين. حذف الجهاز الحالي مثل تسجيل الخروج. الاستجابة `204`، أو `404` إن لم يكن في الحساب جهاز مسجَّل دخوله بهذا المعرّف.

الأجهزة التي لم تبقَ لها جلسة (سُجّل خروجها، أو خاملة تجاوزت رمز التحديث ومدته 30 يومًا) يحذفها الخادم في صيانته.

## إشعارات الدفع

يمكن إيقاظ الهواتف لتزامن عندما يكون للخادم [مرحّل دفع](/ar/docs/self-hosting/push-relay/) (push relay): عندها يقول `GET /v1/server-info` القيمة `pushRelay: true`. ومن دونه، يجيب كل مسار هنا بـ `404` بالنوع `push-off`.

- يحفظ `PUT /v1/devices/current/push` مع `{ platform, token, sandbox }` الوسيلة التي يُوقَظ بها الجهاز المتصل. القيمة `platform` هي `apns` (رمز الجهاز بالست عشري، بأي حالة أحرف؛ ويُخزَّن بأحرف صغيرة) أو `fcm` (رمز التسجيل: أحرف وأرقام و`-` و`_` و`:`)، و4096 حرفًا على الأكثر. والقيمة `sandbox` لبناءات iPhone التطويرية، التي تصل إليها Apple عبر بيئة sandbox الخاصة بها؛ وتُتجاهل مع `fcm`. الاستجابة `204`. رمز واحد لكل جهاز: الرمز الجديد يحل محل القديم، والرمز الذي كان لجهاز آخر ينتقل إلى هذا الجهاز. استدعه عند كل بدء للتطبيق، لأن النظام قد يغيّر الرمز.
- يوقف `DELETE /v1/devices/current/push` إشعارات الدفع إلى هذا الجهاز. الاستجابة `204`. وتسجيل خروج الجهاز يفعل الشيء نفسه.

يحمل إشعار الدفع كلمة واحدة، ولا يحمل أبدًا أي شيء عن الحساب أو خزناته أو عناصره:

| الكلمة | تُرسل إلى | متى |
|---|---|---|
| `sync` | كل عضو في الخزنة | تغيّر عنصر أو سلة المهملات أو عضو أو مفتاح خزنة (التغييرات نفسها التي تُرسَل لها `vault-changed` و`membership-changed` عبر [WebSocket](#الإشعارات-الحية)) |
| `alert` | الشخص الآخر | مشاركة خزنة معه، ودعوة عائلة، وإضافته جهة اتصال للطوارئ، وطلب وصول في الطوارئ (إلى المانح)، والرفض، والإتاحة (للطرفين)، والتذكير اليومي بطلب لم يُجَب |

تُجمَع التغييرات مدة ثانيتين، فتوقظ الدفعة الواحدة كل جهاز مرة واحدة، وتتقدم `alert` على `sync` في الجولة نفسها. على iPhone تكون `sync` إشعار دفع في الخلفية (`content-available`)، وتعرض `alert` نصوص التطبيق نفسه `phone.native.pushAlertTitle` و`phone.native.pushAlertBody`. وعلى Android كلتاهما رسائل بيانات (`{ "octapass": "sync" | "alert" }`)، ويعرض التطبيق تنبيهه الخاص عند `alert`. وفي الحالتين يزامن العميل بعدها كالمعتاد؛ ولا يُوثق بإشعار الدفع نفسه في أي شيء. إشعارات الدفع بأفضل جهد (best effort): يجب أن يظل العميل يزامن عند فتحه.

## حذف الحساب

```http
DELETE /v1/account
Authorization: Bearer …
X-Reauth-Token: …
Content-Type: application/json

{ "confirmEmail": "alice@example.com" }
```

يحتاج الطلب إلى رمز إعادة مصادقة بالغرض `delete-account` وإلى بريد الحساب. في معاملة واحدة يحذف الخادم الحساب، وسجل OPAQUE ومفاتيحه، وكل الأجهزة والجلسات، ورموز التحقق المعلّقة، وكل خزنة ينفرد بملكيتها (شخصية أو مشتركة أو عائلية) مع كل عناصرها ومرفقاتها وشواهد حذفها (أما خزنة المؤسسة التي فيها أشخاص آخرون فتبقى)، وعضوياته الأخرى في الخزنات، والعائلة التي ينظّمها (أو عضويته في عائلة ودعواتها)، وروابط مشاركته، وسجلات الوصول في الطوارئ في الاتجاهين، وسجل أمانه. تحتفظ سجلات أمان الحسابات الأخرى بأحداثها لكنها لم تعد تسمّيه. التفويضات التي منحها لأعضاء خزنات ما زالت قائمة تحتفظ بمعرّف حسابه العشوائي ومفتاح توقيعه العام، لأنها جزء مما وقّعه؛ ولا يبقى شيء آخر عنه. يحصل أعضاء خزناته المشتركة على `membership-changed`. السجل الوحيد الباقي هو عدّاد مجهول لعمليات الحذف في اليوم. ثم يرسل الخادم بريد تأكيد، ويمكن استخدام عنوان البريد لحساب جديد فورًا.

الأجهزة الأخرى المسجَّل دخولها تحصل على `401` بنوع المشكلة `account-deleted` عند طلبها أو تحديثها التالي، والمتصلة منها تحصل على `account-deleted` عبر WebSocket فورًا. على العملاء حينها مسح كل البيانات المحلية لذلك الحساب.

| الاستجابة | المعنى |
|---|---|
| `204` | حُذف |
| `400 invalid-request` | `confirmEmail` لا يطابق. يبقى رمز إعادة المصادقة صالحًا. |
| `403 reauth-required` | رمز إعادة مصادقة مفقود أو منتهٍ أو مستخدم أو يخص شخصًا آخر |

## الأخطاء

الأخطاء بصيغة `application/problem+json` (RFC 9457). طابِق على `type`، ولا تطابق أبدًا على `title` أو `detail`.

| `type` (بعد `https://octap.app/problems/`) | الحالة | متى |
|---|---|---|
| `invalid-request` | 400 | JSON أو حقل أو ترويسة بصيغة خاطئة |
| `invalid-verification-code` | 400 | رمز إنشاء حساب أو إعادة تعيين خاطئ أو منتهٍ أو مستنفد |
| `recovery-expired` | 400 | إعادة تعيين لكلمة المرور الرئيسية غير معروفة أو منتهية أو مستنفدة أو لم يُتحقق منها بعد |
| `unauthorized` | 401 | رمز مفقود أو غير صالح أو منتهٍ |
| `login-failed` | 401 | أي تسجيل دخول أو إعادة مصادقة فاشلة، أو تحدٍّ للخطوة الثانية غير معروف أو منتهٍ |
| `second-factor-required` | 401 | كلمة المرور صحيحة؛ أكمل بالخطوة الثانية (راجع `secondFactor`) |
| `invalid-second-factor` | 401 | رمز خطوة ثانية أو مفتاح أمان خاطئ، أو رمز خاطئ عند تأكيد تطبيق مصادقة |
| `account-deleted` | 401 | حُذف الحساب الذي يقف وراء هذا الرمز |
| `forbidden` | 403 | دور لا يسمح بالإجراء، مثل الكتابة في خزنة بدور `read` |
| `quota-exceeded` | 403 | الكتابة أو الرفع سيتجاوز حصة العناصر أو التخزين أو المرفقات لمالك الخزنة |
| `reauth-required` | 403 | إجراء خطير دون رمز إعادة مصادقة صالح |
| `signups-closed`، `invite-required` | 403 | الخادم لا يقبل إنشاء الحساب هذا |
| `not-found` | 404 | مسار أو خزنة أو عنصر غير معروف؛ أو موقع بلا أيقونة صالحة للاستخدام |
| `icons-off` | 404 | استدعاء `GET /v1/icons/…` على خادم فيه `OCTAPASS_ICONS=off`: توقف عن السؤال |
| `method-not-allowed` | 405 | طريقة HTTP خاطئة |
| `conflict` | 409 | تغيّر العنصر؛ راجع `current` |
| `vault-key-changed` | 409 | مفتاح عنصر ملفوف بمفتاح خزنة دُوّر وتُرك، أو `keyId` دعوة أو تجديد طوارئ يسمّي مثل هذا المفتاح |
| `vault-changed` | 409 | تدوير مفتاح بُني على مراجعة قديمة للخزنة |
| `already-exists` | 409 | عائلة ثانية، أو عائلة لحساب في عائلة أصلًا، أو جهة الطوارئ نفسها مرتين، أو معرّف مرفق مستخدم أصلًا على العنصر |
| `family-full` | 409 | لا مكان في العائلة لدعوة أخرى |
| `sso-required` | 401 | كلمة المرور صحيحة؛ أكمل عبر موفّر الهوية (راجع `sso`) |
| `sso-pending` | 409 | `login/sso` قبل أن ينتهي المتصفح لدى موفّر الهوية |
| `sso-config` | 400 | لا يمكن استخدام موفّر الهوية، أو تجربة تسجيل الدخول غير موجودة، أو تسجيل الدخول الموحّد مطلوب الآن |
| `org-policy` | 403 | سياسة في المؤسسة تمنع هذا لأعضائها |
| `org-vault-orphaned` | 409 | سيترك هذا خزنات المؤسسة دون أحد يستطيع إدارتها (راجع `vaultIds`) |
| `batch-aborted` | 424 | في دفعة: فشلت عملية أخرى على الخزنة نفسها |
| `account-exists`، `vault-exists` | 409 | إنشاء حساب ببريد أو معرّف خزنة مأخوذ |
| `payload-too-large` | 413 | جسم أكبر من 1 MiB (و16 MiB للدفعة)، أو مرفق يتجاوز حد حجم الملف |
| `length-required` | 411 | رفع مرفق دون `Content-Length` |
| `precondition-required` | 428 | كتابة عنصر دون `If-Match` / `If-None-Match` |
| `rate-limited` | 429 | محاولات كثيرة؛ راجع `Retry-After` |
| `email-unavailable` | 503 | لا يستطيع الخادم إرسال البريد، فلا يستطيع التحقق من إنشاء الحسابات أو إعادة التعيين |
| `unavailable` | 503 | غير جاهز، أو مثقل |
| `internal` | 500 | خلل برمجي؛ تفاصيله في سجل الخادم فقط |

## حدود المعدّل

تستخدم نقاط نهاية المصادقة وعمليات البحث ومشاهدات روابط المشاركة وجهات الطوارئ الجديدة دلاء رموز (token buckets). البريد غير المعروف يُحدّ تمامًا كالحقيقي.

| الدلو | يُحتسب على | الافتراضي |
|---|---|---|
| لكل عنوان IP للعميل (IPv6 بحسب /64) | كل طلب مصادقة | 30، ثم واحد كل ثانيتين |
| لكل بريد وIP | تسجيلات الدخول وإعادات المصادقة الفاشلة | 10، ثم واحد في الدقيقة |
| لكل بريد | تسجيلات الدخول الفاشلة من أي مكان | 100، ثم واحد كل 10 ثوانٍ |
| لكل بريد | `register/start` و`register/finish` | 20، ثم واحد في الدقيقة |
| لكل بريد | `recover/start` | 20، ثم واحد في الدقيقة (دلو منفصل عن دلو إنشاء الحساب) |
| لكل حساب | `GET /v1/accounts/lookup` والدعوات (الخزنات والعائلات) | 20، ثم واحد كل 30 ثانية |
| لكل حساب | `POST /v1/transparency/label` | 40، ثم واحد كل 30 ثانية |
| لكل عنوان IP للعميل | `GET /v1/share-links/{id}` | 10، ثم واحد كل 6 ثوانٍ |
| لكل حساب | `POST /v1/emergency-contacts` | 10، ثم واحد كل 15 دقيقة |
| لكل جهة | `POST /v1/emergency-contacts` الذي يسمّي تلك الجهة، من أي حساب | 5، ثم واحد في الساعة |
| لكل عنوان IP للعميل | `GET /v1/icons/{domain}` | 200، ثم أربعة في الثانية |

بدء تسجيل الدخول لا يكلّف البريد شيئًا، فلا يستطيع أحد قفل حساب بإغراق `login/start`؛ ولا تُحتسب دلاء البريد إلا عند فشل تسجيل الدخول، ولا تُفحص إلا قبل بدء تسجيل دخول جديد. المهاجم الذي يستنفد دلو (البريد، IP) الخاص به لا يحجب المالك على عنوان آخر. ولإنشاء الحسابات فوق ذلك الحدود اليومية الموصوفة تحت [إنشاء الحساب](#إنشاء-الحساب). لكل IP 20 عملية تسجيل دخول جارية كحد أقصى؛ وبدء المزيد ينهي أقدمها.

## أيقونات المواقع

يعيد `GET /v1/icons/{domain}` أيقونة موقع، فلا يسأل العملاء أي خدمة أيقونات أبدًا، ولا تُرسل قائمة مواقع الخزنة إلى أي مكان آخر. لا يأخذ رمزًا ولا يقرأ ملفات تعريف الارتباط: لا يستطيع الخادم ربط الطلب بحساب. `{domain}` اسم DNS عام مثل `example.com` (يجوز أن يتبعه `:443` أو `:80`؛ ولا مخطط ولا مسار ولا منفذ آخر). يرسل العملاء النطاق المسجَّل لأول رابط في العنصر، فيعرف الخادم `bank.com` لا `login.bank.com`. عناوين IP والتسميات المفردة والأسماء المخصصة للاستخدام الخاص (`localhost` و`.local` و`.internal` و`.test` وما شابهها) تحصل على `400`.

| الجواب | المعنى | `Cache-Control` |
|---|---|---|
| `200 image/png` | الأيقونة، بحد أقصى 128 × 128 بكسل | `public, max-age=604800` (7 أيام) |
| `404 not-found` | الموقع بلا أيقونة صالحة: اعرض الحرف الأول | `public, max-age=86400` (يوم واحد) |
| `404 icons-off` | الخادم أوقف الأيقونات: توقف عن السؤال | لا شيء |
| `429 rate-limited` | راجع `Retry-After` | لا شيء |

كل جواب يحمل `Access-Control-Allow-Origin: *`. كيف يجلب الخادم:

- **من الموقع فقط.** يقرأ الصفحة الرئيسية (HTTPS أولًا، ثم HTTP، ثم الأمر نفسه مع `www.`)، ويأخذ وسمَي `<link rel="icon">` و`<link rel="apple-touch-icon">` (مفضّلًا حجمًا معلنًا من 64 إلى 128 بكسل)، ثم يرجع إلى `/apple-touch-icon.png` و`/favicon.ico`. لا يسأل أي خدمة أيقونات من جهة خارجية أبدًا؛ ولا يتبع رابطًا إلى مضيف آخر إلا إذا سمّته صفحة الموقع نفسها (شبكة CDN مثلًا).
- **عناوين عامة فقط.** يحلّ الأسماء بنفسه ولا يتصل إلا بالعناوين التي فحصها: لا الخاصة ولا loopback ولا link-local ولا multicast ولا CGNAT (`100.64.0.0/10`) ولا نطاقات التوثيق أو قياس الأداء أو المحجوزة، ولا عناوين IPv6 المحلية الفريدة أو link-local، ولا عناوين IPv4 داخل عناوين IPv6 (المُعيَّنة، 6to4). المنفذان 80 و443 فقط، ولا بيانات اعتماد في الروابط، ولا وكيل. تُتبع إعادات التوجيه يدويًا، 3 على الأكثر، وكل واحدة تُفحص بالطريقة نفسها.
- **صغير وسريع.** 3 ثوانٍ للاتصال، و5 لكل طلب، و15 لكل موقع؛ تُقرأ الصفحة حتى 512 KB وتُرفض الأيقونات التي تتجاوز 256 KB، وتُحتسب بعد فك الضغط حتى يتوقف هجوم gzip bomb عند الحد.
- **مُعاد ترميزها.** تُفحص البايتات لمعرفة نوعها (PNG أو ICO أو GIF أو JPEG أو WebP أو BMP أو SVG، أيًّا كان `Content-Type`)، وتُفك بحدود (2048 بكسل للضلع، و32 MB من الذاكرة)، وتُصغَّر إلى 128 بكسل وتُرمَّز من جديد بصيغة PNG. يُرسم SVG إلى بكسلات دون تحميل صور أو خطوط خارجية، ويُرفض SVG المضغوط. لا يحصل العملاء أبدًا على ملف الموقع نفسه، ولذلك لا يحصلون أبدًا على SVG فيه سكربتات.
- **مخزَّنة مؤقتًا** في `<data dir>/icons` لمدة 7 أيام (و1 يوم للإخفاقات)، بأسماء ملفات مفتاحها سر الخادم، حتى لا يكون المجلد قائمة مواقع مقروءة. جلب واحد لكل موقع في كل مرة، وثمانية مواقع في آن واحد عبر كل العملاء.

## البريد المُقنَّع

خدمة البريد المُقنَّع الخاصة بالخادم، إن كانت لديه واحدة: يبيّن ذلك `maskedEmailRelay` في `GET /v1/server-info`. ومن دونها تجيب كل المسارات هنا بالرمز 404 والنوع `masked-email-off`. تحتاج كلها إلى جلسة. توجّه الأسماء المستعارة البريد إلى البريد الإلكتروني المؤكَّد للحساب ولا شيء غيره، فلا يذكر أي طلب وجهة. راجع [المرحّل](/ar/docs/self-hosting/relay/).

| الطريقة والمسار | المحتوى | الجواب |
|---|---|---|
| `GET /v1/masked-email/aliases` | | `200 { aliases, maxAliases, domain }`، الأحدث أولًا |
| `POST /v1/masked-email/aliases` | | `201` اسم مستعار. و`409 masked-email-limit` عند بلوغ حدّ الحساب، و`429 rate-limited` عند بلوغ الحد اليومي |
| `PATCH /v1/masked-email/aliases/{id}` | `{ enabled }` | `200` الاسم المستعار. وتشغيله ينهي الإيقاف المؤقت أيضًا |
| `DELETE /v1/masked-email/aliases/{id}` | | `204`. وتُحذف جهات اتصاله معه، ويُرفض البريد المرسل إليه |
| `POST /v1/masked-email/aliases/{id}/block` | `{ sender }` | `204`. لا يستطيع هذا العنوان الوصول إلى هذا الاسم المستعار |
| `POST /v1/masked-email/aliases/{id}/unblock` | `{ sender }` | `204` |

الاسم المستعار هو `{ id, address, enabled, paused, forwarded, blocked, replied, createdAt }`. وتعني `paused` أن الخدمة أوقفته، أو أوقفت الحساب كله، بعد ارتداد رسائل أو بلاغات عن بريد مزعج. ويجيب المسار بالرمز 503 حين يتعذّر الوصول إلى المرحّل.

## بيانات السلامة

لا يحتاج `GET /v1/health/data` إلى رمز. يعيد قوائم المواقع الموقَّعة للوحة الأمان، وهو الملف نفسه للجميع:

```json
{ "payload": "<base64>", "signature": "<base64>" }
```

`signature` توقيع Ed25519 بمفتاح المشروع على `openpass/v1/health-data ‖ 0x00 ‖ payload`، حيث `payload` هي البايتات المفكوكة لكائن JSON: `{ "format": 1, "version": 2, "issuedAt": "…", "passkeyDomains": ["…"], "twoFactorDomains": ["…"] }`. تثبّت العملاء المفتاح العام، وتتحقق من التوقيع قبل قراءة الحمولة، ولا تستخدم ملفًا إلا إذا كان `version` فيه أعلى مما لديها، فلا يستطيع الخادم تغيير القوائم ولا إرجاعها إلى نسخة أقدم. النطاقات أسماء قابلة للتسجيل بأحرف صغيرة؛ وتُتجاهل الحقول غير المعروفة، ويُرفض `format` غير المعروف. تسأل العملاء مرة في اليوم على الأكثر.

## فحص تسريب البريد الإلكتروني

يحتاج `POST /v1/health/breach-email` إلى رمز وصول. يسأل Have I Been Pwned عن عنوان واحد، للعملاء الذين اختار مستخدموهم تفعيل الميزة (راجع [فحص التسريبات](/ar/docs/security/breach-checks/#تنبيهات-تسريب-البريد-الإلكتروني-اختيارية)). يوضع العنوان في الجسم حتى يبقى خارج عناوين URL وسجلات الوصول، ولا يحتفظ الخادم بأي شيء عنه.

```json
{ "email": "name@example.com" }
```

```json
{
  "breaches": [
    { "name": "Adobe", "title": "Adobe", "domain": "adobe.com", "breachDate": "2013-10-04", "dataClasses": ["Email addresses", "Passwords"] }
  ]
}
```

العنوان غير المعروف يحصل على `200` مع قائمة فارغة. وتعني `404` أن الخادم ليس لديه مفتاح HIBP؛ ويخبر `GET /v1/server-info` بذلك مسبقًا عبر `emailBreachChecks`. وتأتي `429` مع `Retry-After`: نفدت حصة الحساب، أو بلغ الخادم حده في HIBP. وتعني `503` أن HIBP لم تُجب أو رفضت المفتاح. ولا تُمرَّر أوصاف HIBP بصيغة HTML أبدًا.

## مخطط له

مخطط له للإصدار 1.0: رموز تحديث مرتبطة بمفتاح Ed25519 لكل جهاز، وبيانات خزنة موقّعة (signed vault manifests). بعد كل دفع، يوقّع العميل `(vault_id, revision, hash of item revisions)` بمفتاح Ed25519 الخاص بحسابه، فلا يستطيع الخادم إخفاء عناصر أو إرجاعها إلى حالة سابقة.
