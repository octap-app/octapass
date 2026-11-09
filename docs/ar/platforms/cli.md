---
title: سطر الأوامر
description: أداة سطر الأوامر octapass لقراءة العناصر والرموز لمرة واحدة وكلمات المرور المولَّدة، وإدارة مفاتيح SSH، وحفظ ملفات .env ومتغيرات البيئة، وتمرير الأسرار إلى السكربتات بمراجع octapass://، والاستيراد والتصدير، مع جلسة محفوظة في سلسلة مفاتيح نظام التشغيل.
status: beta
sidebar:
  order: 5
---

:::note[معاينة]
تعمل أداة سطر الأوامر اليوم مع خادم Octa Pass، لكن لا توجد إصدارات جاهزة بعد: ابنِها من الشيفرة المصدرية. قد تتغير الأوامر ورموز الخروج قبل الإصدار 1.0.
:::

`octapass` ملف تنفيذي أصلي مكتوب بلغة Rust. يستخدم النواة نفسها التي تستخدمها كل التطبيقات الأخرى، فلا تغادر كلمة المرور الرئيسية والمفتاح السري والعناصر المفكوكة التشفير حاسوبك. يحتفظ بنسخة مشفّرة من خزنتك، فتعمل قراءة العناصر دون اتصال أيضًا.

## التثبيت

تحتاج إلى [Rust](https://rustup.rs). من نسخة مستنسخة من المستودع:

```bash
cargo install --path apps/cli
octapass --version
```

لتبقى مفتوح القفل بين الأوامر، تستخدم الأداة سلسلة مفاتيح النظام: Keychain على macOS، وCredential Manager على Windows، وSecret Service (GNOME Keyring وKWallet) على Linux. من دونها تعمل الأداة أيضًا، لكن كل أمر يطلب كلمة المرور الرئيسية.

## بداية سريعة

```bash
octapass login --server https://vault.example.com
octapass list --search github
octapass get GitHub --field password
octapass totp GitHub
octapass lock
```

يطلب `login` بريدك الإلكتروني وكلمة المرور الرئيسية، وفي أول مرة على هذا الحاسوب يطلب المفتاح السري أيضًا (تجده في [مجموعة الاسترداد](/ar/docs/getting-started/recovery-kit/)). إذا كان الحساب يستخدم [تسجيل الدخول بخطوتين](/ar/docs/features/two-step-sign-in/)، فيطلب بعد ذلك رمزًا من تطبيق المصادقة أو رمز استرداد للخطوتين. مفاتيح الأمان تعمل في خزنة الويب فقط. من دون `--server` يستخدم `OCTAPASS_SERVER`، ثم الخدمة المستضافة.

## الأوامر

| الأمر | ما يفعله |
|---|---|
| `octapass signup [--server URL] [--email E] [--code C] [--timeout 30m]` | ينشئ حسابًا، ويطبع مجموعة الاسترداد، ويسجّل الدخول. لا بد أن تبلغ كلمة المرور الرئيسية درجة «قوية»، كما في خزنة الويب. |
| `octapass login [--server URL] [--email E] [--timeout 30m]` | يسجّل الدخول ويفتح القفل. |
| `octapass unlock [--timeout 30m]` | يفتح القفل بكلمة المرور الرئيسية ويبقى مفتوحًا حتى تمرّ مدة المهلة دون نشاط منك (من دقيقة واحدة إلى 24 ساعة، والافتراضي 30 دقيقة). |
| `octapass lock` | يقفل الآن. |
| `octapass logout` | يسجّل الخروج على الخادم ويزيل الحساب من هذا الحاسوب: المفتاح السري والنسخة المشفّرة وإدخال سلسلة المفاتيح. |
| `octapass status` | يخبرك هل سجّلت الدخول وهل القفل مفتوح. |
| `octapass change-master-password` | يغيّرها: يطلب كلمة المرور الرئيسية الحالية والجديدة. يبقى المفتاح السري ورمز الاسترداد والعناصر كما هي، ويُسجَّل خروج الأجهزة الأخرى. |
| `octapass rotate-secret-key [--new-recovery-code]` | يستبدل مفتاحك السري ويطبع مجموعة الاسترداد الجديدة. تبقى كلمة المرور الرئيسية كما هي؛ ويُسجَّل خروج الأجهزة الأخرى وتحتاج إلى المفتاح الجديد. |
| `octapass rotate-vault-key <vault>` | يعطي خزنة تملكها أو تديرها مفتاحًا جديدًا. |
| `octapass reset-master-password [--server URL] [--email E] [--code C]` | يعيد ضبط كلمة مرور رئيسية منسية بالرمز المرسل إلى بريدك ورمز الاسترداد من مجموعة الاسترداد، ثم يطبع المجموعة الجديدة. |
| `octapass service-account create\|list\|revoke` | ينشئ [حسابات الخدمة](/ar/docs/features/service-accounts/) ويلغيها. |
| `octapass org …` | يدير [مؤسستك](/ar/docs/features/organisations/): الأعضاء والدعوات والمجموعات والخزائن وخطوة المراجعة `access apply` و`rotate` والسياسات و[تسجيل الدخول الموحّد](/ar/docs/features/single-sign-on/) (OpenID Connect وSAML) ورموز [SCIM](/ar/docs/features/scim/) وسجل النشاط. |
| `octapass connect serve\|status\|clients\|revoke\|approve\|pair\|read` | يشغّل [Octa Pass Connect](/ar/docs/features/connect/) ويديره. |
| `octapass aws credential-process`, `octapass kube credential`, `octapass docker-credential` | [بيانات اعتماد لأدوات أخرى](#السحابة-وdevops). |
| `octapass oauth create\|token\|show` | [رموز OAuth2 حية](/ar/docs/features/connect/#live-api-tokens) من عناصر بيانات اعتماد API. |
| `octapass list [--vault V] [--search Q]` | يعرض العناصر: العنوان واسم المستخدم والخزنة والمعرّف. يبحث البحث في العناوين وأسماء المستخدمين والروابط والوسوم. |
| `octapass get <item> [--field F] [--vault V] [-n]` | يعرض عنصرًا دون أسراره، أو يطبع حقلًا واحدًا. |
| `octapass totp <item> [--vault V]` | يطبع الرمز الحالي لمرة واحدة. |
| `octapass create <type> --title T [FIELD=VALUE…]` | يضيف عنصرًا من أي نوع يُكتب: بيانات دخول أو كلمة مرور أو ملاحظة أو بطاقة أو هوية أو شبكة Wi-Fi أو حساب بنكي أو بيانات API أو ترخيص برنامج أو وثيقة هوية أو محفظة عملات رقمية أو قاعدة بيانات أو عنصر مخصص أو قالب. انظر [تغيير العناصر](#تغيير-العناصر). |
| `octapass edit <item> [FIELD=VALUE…]` | يغيّر حقول عنصر أو عنوانه أو روابطه أو وسومه أو تفضيله. |
| `octapass delete <item> [--vault V]` | ينقل عنصرًا إلى سلة المهملات. |
| `octapass restore <item>` | يعيد عنصرًا من سلة المهملات. |
| `octapass generate [--length N \| --words N]` | يولّد كلمة مرور أو عبارة مرور. لا يحتاج إلى حساب. |
| `octapass read octapass://<vault>/<item>/<field> [-n]` | يطبع القيمة التي يشير إليها المرجع. |
| `octapass run [--env E] [--project P] [--stage S] [--env-file F] [--env-file-out PATH] [--no-masking] -- <command>` | يشغّل أمرًا بعد تحميل البيئات، ويستبدل المراجع في بيئته بقيمها، مع إخفاء الأسرار في خرجه. |
| `octapass env …` | يعرض البيئات ويُظهرها وينشئها ويغيّرها ويستوردها ويصدّرها. انظر [البيئات](#البيئات). |
| `octapass inject -i template -o out [--force]` | ينسخ ملفًا نصيًا ويستبدل مراجع octapass:// بقيمها. |
| `octapass import <format> <file> [--vault V] [--key-file F] [--dry-run]` | يستورد تصدير تطبيق آخر، أو تصدير Octa Pass. |
| `octapass ssh list \| generate \| import \| export \| public` | يعرض مفاتيح SSH ويُنشئها ويستوردها ويصدّرها ويطبع العام منها. انظر [مفاتيح SSH](#مفاتيح-ssh). |
| `octapass gpg list \| import \| public` | يعرض مفاتيح OpenPGP لتوقيع الإيداعات ويستوردها ويطبع العام منها. انظر [Git](#git). |
| `octapass git setup [--global] [--signing-key ITEM] [--agent]` | يوجّه Git إلى مساعد بيانات الاعتماد وتوقيع الإيداعات. انظر [Git](#git). |
| `octapass encrypt [paths] [--self] [--to WHO] [--passphrase] [--output F] [--armor] [--shred] [--force]` | يشفّر الملفات والمجلدات بصيغة age. انظر [تشفير الملفات](/ar/docs/features/file-encryption/). |
| `octapass decrypt [paths] [--identity F] [--output F] [--force]` | يفك تشفير ملفات age؛ ويُفك الملف `.tar.age` إلى مجلد. |
| `octapass shred <paths> [--yes]` | يكتب فوق الملفات ويحذفها، ويقول ما حققه ذلك على هذا القرص. |
| `octapass file-key [--export] [--output F] [--force]` | يطبع مفتاح age العام لك، أو يصدّر المفتاح السري للملفات المشفّرة لك. |
| `octapass safe list \| create \| ls \| add \| get \| mkdir \| mv \| rm \| sync \| set-sync \| delete \| mount` | يتعامل مع [الخزائن](/ar/docs/features/octa-pass-safe/) المشفّرة. يحتاج `mount` إلى بناء بالخاصية `fuse`، على Linux. |
| `octapass context-menu install \| remove \| status` | يضيف «تشفير باستخدام Octa Pass» إلى مدير الملفات أو يزيله. |
| `octapass export [--format json\|csv\|cxf] [--encrypted] [--output F]` | يصدّر كل العناصر. |

شغّل `octapass <command> --help` لعرض كل الخيارات.

### تغيير كلمة المرور الرئيسية أو إعادة ضبطها

```bash
octapass change-master-password
octapass reset-master-password --server https://vault.example.com
```

يطلب `change-master-password` كلمة المرور الرئيسية الحالية (لإثبات أنك أنت)، ثم كلمة جديدة مرتين. لا يتغير المفتاح السري ولا رمز الاسترداد ولا العناصر؛ ويُسجَّل خروج كل جهاز آخر ولا بد أن يفعّل فتح القفل بالجهاز من جديد.

`reset-master-password` لكلمة مرور رئيسية منسية. يرسل إليك رمزًا بالبريد الإلكتروني (ويعيده خادم التطوير بدلًا من ذلك)، ثم يطلب الرمز ورمز الاسترداد من [مجموعة الاسترداد](/ar/docs/getting-started/recovery-kit/) وكلمة مرور رئيسية جديدة مرتين. يطبع إلى stdout مجموعة الاسترداد **الجديدة** بالمفتاح السري الجديد ورمز الاسترداد الجديد: احفظها في مكان آمن، لأن المجموعة القديمة تتوقف عن العمل. ثم يسجّل الدخول بكلمة المرور الجديدة؛ وإذا كان تسجيل الدخول بخطوتين مفعّلًا، فيطلب الخطوة الثانية كالمعتاد.

مع `--password-stdin`، يقرأ `change-master-password` كلمة المرور الحالية من السطر الأول والجديدة من السطر الثاني. ويقرأ `reset-master-password` رمز الاسترداد من السطر الأول وكلمة المرور الجديدة من السطر الثاني؛ مرّر الرمز المرسل بالبريد بالخيار `--code` ما لم يعدْه خادم التطوير.

### العناصر والحقول

`<item>` هو عنوان العنصر (بأي حالة أحرف) أو معرّفه. إذا كان لعنصرين العنوان نفسه، يفشل الأمر برمز الخروج 7 ويعرض معرّفيهما؛ استخدم المعرّف، أو `--vault` للبحث في خزنة واحدة. لا تُحتسب العناصر الموجودة في سلة المهملات.

يقبل `--field` القيم `password` و`username` و`totp` (الرمز الحالي) و`notes` و`url` (الأول) و`title`، وأي حقل آخر في العنصر (مثل `number` أو `cvv` في البطاقة) أو تسمية حقل مخصص:

```bash
octapass get GitHub                       # every field, secrets left out
octapass get GitHub --field password      # just the password
octapass get "AWS prod" --field "access key id"
octapass get GitHub --json                # the whole item, secrets included
```

لا تُطبع الأسرار إلا عندما تطلبها. وعندما يكون الخرج طرفية، يُرسَل تحذير إلى stderr أولًا. يحذف `-n` سطر النهاية بعد القيمة. ويطبع `reset-master-password` أسرارًا أيضًا، لأن مجموعة الاسترداد الجديدة هي النسخة الوحيدة.

### تغيير العناصر

```sh
octapass create login --title GitHub --url https://github.com username=ada password
octapass create login --title Mail --generate --words 5
octapass create card --title Visa number cvv cardholder="Ada Lovelace" expiry=04/29
octapass create note --title "Router" --stdin notes < router.txt
octapass create bank-account --title Savings bank-name="Example Bank" iban="DE89 3704 0044 0532 0130 00" swift=COBADEFFXXX pin
octapass create licence --title "Editor Pro" product="Editor Pro" license-key licensed-to=Ada expiry-date=2027-06-01
octapass create database --title Warehouse database-type=postgresql host=db.internal port=5432 database=shop username=admin --generate
octapass create wallet --title Cold address.bitcoin=bc1q… --stdin seed-phrase < seed.txt
octapass create template --title "Gym locker" Locker Combination=hidden
octapass create custom --title "North gym" --template "Gym locker" locker=12 combination
octapass edit GitHub password --add-tag work
octapass edit GitHub --unset "API key" --title "GitHub (work)"
octapass delete GitHub
```

اكتب `field=value`، أو `field` وحده لتكتب القيمة دون أن تظهر. **فضّل ذلك للأسرار**: فالبرامج الأخرى تستطيع رؤية وسائط سطر الأوامر، وقد تحتفظ بها صدفتك. يقرأ `--stdin field` قيمة حقل واحد من stdin، بعد سطر `--password-stdin` إن وُجد. وينشئ `--generate` كلمة مرور جديدة.

لكل نوع حقوله: `username` و`password` و`totp` و`notes` لبيانات الدخول؛ و`cardholder` و`number` و`expiry` و`cvv` و`pin` و`brand` و`notes` للبطاقة؛ و`firstName` و`lastName` و`email` و`phone` و`birthDate` و`notes` و`address.line1` و`address.city` وغيرها للهوية؛ و`ssid` و`security` و`password` و`notes` لشبكة Wi-Fi. وفي بيانات الدخول وWi-Fi يصير أي اسم آخر حقلًا مخصصًا، مخفيًا ما لم تضف `--plain`. ولمفاتيح SSH ومفاتيح OpenPGP والبيئات أوامرها الخاصة، وكذلك للشهادات والمفاتيح الأخرى (`octapass cert` و`octapass key` مع `--save`)؛ ويستطيع `edit` تغيير عنوانها وروابطها ووسومها.

تأخذ الأنواع الأحدث الحقول التي يعرضها محررها. ويُكتب اسم الحقل `licenseKey` أو `license-key` أو `license_key`:

| النوع (وأسماؤه المختصرة) | الحقول |
|---|---|
| `bank-account` (`bank`) | `bankName` و`accountHolder` و`accountType` (`checking` أو `savings` أو `business` أو `other`) و`iban` و`accountNumber` و`routingNumber` و`swift` و`branch` و`pin` و`notes` |
| `api-credential` (`api`) | `credentialType` (`apiKey` أو `bearerToken` أو `oauth` أو `jwt` أو `basicAuth` أو `other`) و`username` و`key` و`secret` و`host` و`expiryDate` و`notes` |
| `licence` (`license` و`software-license`) | `product` و`version` و`licenseKey` و`licensedTo` و`email` و`publisher` و`orderNumber` و`purchaseDate` و`expiryDate` و`notes` |
| `id-document` (`id`) | `documentType` (`passport` أو `driverLicense` أو `nationalId` أو `other`) و`number` و`fullName` و`birthDate` و`issuer` و`country` و`issueDate` و`expiryDate` و`notes` |
| `wallet` (`crypto-wallet`) | `walletName` و`seedPhrase` و`passphrase` و`notes`، و`address.<network>` لكل عنوان (`address.bitcoin` أو `address.ethereum` أو اسم شبكة أخرى) |
| `database` (`db`) | `databaseType` (`postgresql` أو `mysql` أو `sqlServer` أو `oracle` أو `mongodb` أو `redis` أو `sqlite` أو `server` أو `other`) و`host` و`port` و`database` و`username` و`password` و`connectionString` و`notes` |
| `custom` | حقولك أنت، بأسمائها: مخفية ما لم تضف `--plain`. ويبدأ `--template NAME` بحقول قالب. |
| `template` | أسماء الحقول، وقيمة كل منها نوعه: `text` (الافتراضي) أو `hidden` أو `multiline` أو `url` أو `date` أو `email` أو `phone` أو `totp`. لا يحمل القالب قيمًا. |

تُكتب التواريخ `YYYY-MM-DD`. وتُفحص القيم كما تفحصها التطبيقات: أرقام التحقق في IBAN، وشكل رمز SWIFT، والمنفذ، وعنوان البريد، وعنوان المحفظة في سطر واحد. وتنبّه الحقول المخفية (رمز PIN أو مفتاح أو سر أو عبارة الاسترداد أو كلمة مرور قاعدة البيانات) حين تأتي في سطر الأوامر، فاكتبها أو استعمل `--stdin`. ويعمل `--generate` مع كل نوع له كلمة مرور: بيانات الدخول وWi-Fi وقواعد البيانات. ويحذف `--unset address.bitcoin` عنوانًا، ويحذف `--unset Locker` حقلًا من عنصر مخصص.

تبقى الحقول التي لا يعرفها Octa Pass كما هي. وتذهب كلمة المرور المتغيّرة إلى سجل كلمات المرور في العنصر. وإذا غيّر جهاز آخر العنصر أولًا، تحتفظ الخزنة بالنسختين، كما في كل التطبيقات الأخرى.

### توليد كلمات المرور

```bash
octapass generate                          # 20 random characters
octapass generate --length 32 --no-symbols
octapass generate --avoid-ambiguous        # no I l 1 O 0 o |
octapass generate --words 5                # five words from the EFF list, joined by -
octapass generate --words 4 --separator _ --capitalize --number
```

طول كلمة المرور من 4 إلى 128 حرفًا، وعبارة المرور من 3 إلى 20 كلمة، من مولّد الأرقام العشوائية الآمن في نظام التشغيل. انظر [مولّد كلمات المرور](/ar/docs/features/password-generator/).

## مفاتيح SSH

```bash
octapass ssh list
octapass ssh generate --type ed25519 --comment ada@laptop
octapass ssh generate --type rsa-3072 --title "Old server" --passphrase
octapass ssh import ~/.ssh/id_ed25519
octapass ssh import --scan
octapass ssh export "Laptop key" --out ~/.ssh/id_ed25519 --passphrase
octapass ssh public "Laptop key" >> ~/.ssh/authorized_keys
```

- يعرض `ssh list` العنوان والنوع والبصمة والخزنة. ويضيف `--json` المفتاح العام والمعرّف.
- ينشئ `ssh generate` مفتاح Ed25519 أو ECDSA P-256/P-384 أو RSA 3072/4096 على هذا الحاسوب ويحفظه في Personal، أو في الخزنة التي تحددها بـ `--vault`. القيمة الافتراضية لـ `--title` هي التعليق أو نوع المفتاح. يطلب `--passphrase` عبارة مرور تُحفظ للتصدير؛ أما المفتاح المخزَّن نفسه فلا عبارة مرور له.
- يقرأ `ssh import` المفاتيح الخاصة بصيغ OpenSSH وPEM وPKCS#8، ويطلب عبارة مرور إذا كان الملف محميًا بها. ويقرأ `--scan` المجلد `~/.ssh` أيضًا ويتخطى المفاتيح الموجودة في الخزنة بحسب البصمة.
- يطلب `ssh export` كلمة المرور الرئيسية مرة أخرى، ثم يكتب مفتاح OpenSSH خاصًا لا يقرؤه غيرك (الوضع `0600`). لا يستبدل ملفًا موجودًا دون `--force`. يطلب `--passphrase` عبارة مرور جديدة؛ ومن دونه تُستخدم عبارة المرور المحفوظة للمفتاح، ويترك `--no-passphrase` الملف دون حماية. ومن دون `--out` يذهب المفتاح إلى stdout، ولا يُطبع على طرفية أبدًا.
- يطبع `ssh public` سطر `authorized_keys` (المفتاح العام وتعليقه).

مفاتيح DSA وFIDO (`sk-`) تُعرض ويمكن استيرادها، لكن لا يمكن توليدها ولا استخدامها ولا تصديرها إلى صيغ أخرى حتى الآن. مفاتيح PuTTY وكذلك 3DES تحتاج إلى تحويلها أولًا بـ `ssh-keygen`. انظر [مفاتيح SSH](/ar/docs/features/ssh-keys/).

## Git

```sh
octapass git setup --global                               # Git asks Octa Pass for passwords
octapass git setup --global --signing-key "Laptop key"    # and signs commits with this key
```

يغيّر `setup` إعدادات Git نفسها، وإعدادات هذا المستودع دون `--global`؛ ويعرضها `--dry-run` أولًا.

### كلمات المرور

يعطي `git-credential-octapass` لـ Git اسم المستخدم وكلمة المرور لبيانات الدخول المحفوظة لذلك المضيف. وهو أشد من الملء التلقائي، لأن Git يسمّي بالضبط أين تذهب كلمة المرور: لا بد أن يطابق المخطط (scheme) والمضيف والمنفذ رابط بيانات الدخول (بصرف النظر عن `www.` في أوله)، ولا تُرسل كلمة مرور عبر `http://` إلا إذا كان رابط بيانات الدخول يقول `http://`. ومع تفعيل `credential.useHttpPath`، تجيب بيانات الدخول المحفوظة لمسار مستودع عن ذلك المستودع، مقدَّمةً على بيانات الدخول المحفوظة للمضيف كله.

- أغلب منصات استضافة الشيفرة تريد رمزًا (token) بدل كلمة مرورك. أضف إلى بيانات الدخول حقلًا مخصصًا اسمه **Git token** فيعطي Octa Pass ذلك الرمز بدلًا منها.
- إذا ناسبت عدة بيانات دخول، لا يُعطى شيء ويُقال لك السبب: ضع اسم المستخدم في رابط المستودع البعيد، أو اضبط `credential.username`.
- حين يبلغ Git أن كلمة مرور رُفضت، لا يُحذف شيء من خزنتك. ولا يحفظ Octa Pass شيئًا من Git أيضًا، ما لم تُعِدّ المساعد بصيغة `octapass --store`.
- الخزنة المقفلة تُفتح عبر [تطبيق سطح المكتب](#الجلسات)، أو تطلب كلمة المرور الرئيسية في طرفيتك، ما لم يكن `GIT_TERMINAL_PROMPT=0`.

### توقيع الإيداعات

يأخذ `--signing-key` مفتاح SSH أو مفتاح OpenPGP من خزنتك ويفعّل `commit.gpgsign`.

- **مفاتيح SSH:** يشغّل Git الأمر `octapass-git-sign` بدل `ssh-keygen`، وتوقّع الأداة بالمفتاح من خزنتك المفتوحة. أضف `--agent` لتوقّع عبر [وكيل SSH](/ar/docs/features/ssh-keys/#وكيل-ssh) في تطبيق سطح المكتب بدلًا من ذلك، وهو يسألك في كل مرة. ويستطيع أي مفتاح من نوع Ed25519 أو ECDSA أو RSA التوقيع.
- **مفاتيح OpenPGP:** أدخل واحدًا بـ `octapass gpg import key.asc` (من `gpg --armor --export-secret-keys`). يشغّل Git الأمر `octapass-git-sign` بدل `gpg`. وتستطيع مفاتيح Ed25519 وECDSA التوقيع. **أما مفاتيح OpenPGP من نوع RSA فلا تستطيع**: فمكتبة OpenPGP توقّع بحزمة (crate) عليها تنبيه أمني مفتوح يتعلق بالتوقيت، لذا يحتفظ Octa Pass بالمفتاح لكنه يرفض التوقيع به. ويطبع `octapass gpg public <item>` المفتاح العام لإعدادات منصة استضافة الشيفرة.

التحقق من التواقيع، وأي مفتاح ليس في خزنتك، يذهب إلى `ssh-keygen` أو `gpg` الحقيقي.

## أدوات المطورين

تنشئ `octapass cert` و`acme` و`key` و`jwt` و`hash` و`hmac` و`encode` و`decode` و`detect` و`random` و`pwhash` و`totp-secret` الشهادات والمفاتيح والرموز والتجزئات والترميزات وتقرؤها. لا يحتاج أي منها إلى حساب ما لم يحفظ في الخزنة، وكلها تقبل `--json`. تقرأ الملفات أو stdin وتكتب إلى stdout، فتناسب خطوط الأنابيب (pipelines). انظر [أدوات المطورين](/ar/docs/features/developer-toolkit/).

لا يُطبع المفتاح الخاص الذي يولّده مولّد على طرفية أبدًا. مرّر `--save` للحفظ في الخزنة أو `--out-key <file>`، أو مرّر الخرج عبر أنبوب.

## الأسرار في السكربتات والتطبيقات

أشِر إلى الأسرار بـ `octapass://<vault>/<item>/<field>` بدلًا من كتابتها في الملفات. كل جزء اسم (بأي حالة أحرف) أو معرّف. المسافات مسموحة؛ واكتب `%2F` بدل `/` داخل الاسم.

```bash
# .env.octapass
DATABASE_PASSWORD=octapass://Personal/Postgres/password
STRIPE_KEY=octapass://Personal/Stripe/api key
```

```bash
octapass run --env-file .env.octapass -- npm start
DATABASE_PASSWORD=octapass://Personal/Postgres/password octapass run -- ./migrate.sh
octapass read octapass://Personal/Postgres/password
```

يحلّ `octapass run` كل متغير تكون قيمته كلها مرجعًا، من البيئة ومن ملفات env (الملفات اللاحقة تتغلب على السابقة وعلى البيئة)، ثم يبدأ الأمر بها. تذهب القيم إلى ذلك الأمر وحده: لا يطبعها `octapass` ولا يكتبها على القرص. إذا تعذّر حلّ مرجع، لا يبدأ الأمر. ينتهي `run` برمز الخروج الذي ينتهي به الأمر نفسه (127 إذا تعذّر العثور عليه).

**تُخفى الأسرار في خرج الأمر.** ما دام سر محمّلًا، يبدأ `run` الأمر كعملية فرعية ويرشّح stdout وstderr الخاصين به، فيستبدل كل سر بـ `<concealed by Octa Pass>`، حتى حين يصل مجزّأً. والأسرار هي المراجع إلى حقول سرية والمتغيرات المخفية؛ أما اسم المستخدم أو المتغير الذي وسمته بأنه عادي فيبقى ظاهرًا، وكذلك القيم الأقصر من 4 أحرف، التي كانت ستحوّل الخرج إلى ضجيج. ويُخفى كل سطر من السر متعدد الأسطر أيضًا.

يصير خرج الأمر عندئذ أنبوبًا لا طرفيتك، فقد تختفي الألوان ولن تعمل البرامج التي تملأ الشاشة: استخدم `--no-masking` (أو `OCTAPASS_NO_MASKING=1`) لهذه البرامج، فيسلّم `run` الطرفية كما كان من قبل. ومن دون أسرار محمّلة لا يتغير شيء. يفيد الإخفاء مع السجلات والشاشات المشتركة، لكنه ليس حدًّا أمنيًا: فالبرنامج يظل قادرًا على ترميز قيمة أو تجزئتها أو إرسالها.

ملفات env أسطر بصيغة `KEY=value`، مع تعليقات `#`، و`export ` اختيارية، وقيم بين علامتي اقتباس مفردتين (تؤخذ كما كُتبت) وقيم بين علامتي اقتباس مزدوجتين (مع `\n` و`\t` و`\r` و`\"` و`\\`، وفواصل أسطر حقيقية للقيم متعددة الأسطر مثل مفاتيح PEM). ويبدأ ` #` بعد قيمة غير مقتبسة تعليقًا. يقرأ الصيغة نفسها `env import` في الأداة، وخزنة الويب والإضافة؛ ولكل منها تنفيذه الخاص، وتُبقيها الاختبارات متطابقة.

### البيئات

احتفظ بملف `.env` كاملًا أو بمتغير واحد في الخزنة وسلّمه إلى أمر. القيم مشفّرة في الخزنة وتُفك هنا على الجهاز؛ ولا تُرسَل إلى أي مكان آخر.

```bash
octapass env create "Shop API (production)" --project shop-api --stage production
octapass env set "Shop API (production)" DB_PASSWORD=octapass://Personal/Postgres/password LOG_LEVEL=info
octapass env import .env.local --new "Shop API (development)" --project shop-api --stage development
octapass env list
octapass env show "Shop API (development)" --reveal
octapass env export "Shop API (development)" --format docker -o .env
octapass env diff shop-api staging production
```

تُسمّى البيئة بعنوانها (بأي حالة أحرف) أو معرّفها أو `vault/title` أو `project:stage` (و`project:` وحدها هي المجموعة المشتركة للمشروع). بيئة المشروع التي بلا مرحلة مشتركة: يحمّلها `run` أولًا وتتغلب عليها متغيرات المرحلة. يجمع `octapass env list` البيئات بحسب المشروع ويعرض كل مرحلة؛ ويطبع `env diff` الأسماء الناقصة أو التي تحمل قيمًا مختلفة، ولا يطبع القيم نفسها أبدًا.

يقبل `octapass run` الخيار `--env` أكثر من مرة (الأحدث يتغلب)، أو `--project P --stage S`، ويحمّل المجموعة نفسها التي يحمّلها خطّاف الصدفة. تُطبَّق المتغيرات بهذا الترتيب: المجموعة المشتركة للمشروع، ثم المرحلة، ثم البيئات المسماة، ثم ملفات `--env-file`، ثم المراجع في الناتج. المرحلة `production` التي تُحمَّل دون تسميتها في سطر الأوامر تطلب تأكيدًا؛ ويتخطى `--yes` السؤال في السكربت. مع `--env-file-out PATH` تُكتب المتغيرات في ملف لا يقرؤه غيرك طوال تشغيل الأمر (ويُحذف بعده، وعند Ctrl-C أيضًا)، للأدوات التي تقرأ ملفًا فقط مثل `env_file:` في Docker Compose.

يضبط الملف `octapass.toml` في المجلد الحالي أو في مجلد أعلى (حتى جذر المستودع) القيم الافتراضية:

```toml
project = "shop-api"
stage = "development"
env = ["Personal/Shop API extras"]
vault = "Personal"
```

تستبدل `--env` و`--project` و`--stage` تلك القيم الافتراضية، ويتغلب `OCTAPASS_STAGE` على مرحلة الملف. يطبع `octapass env hook zsh|bash|fish|powershell` خطّافًا تضعه في ملف بدء الصدفة، يحمّل بيئة مجلد مسموح به عند دخولك إليه ويفرغها عند خروجك منه أو عند تغيّر الملف أو عند قفل Octa Pass. اسمح بمجلد مرة واحدة بـ `octapass env allow`؛ وتُفهرس قائمة المسموح بها بمسار الملف ومحتواه. لا يطلب الخطّاف كلمة المرور الرئيسية أبدًا، ولا يُحمَّل شيء ما دامت الأداة مقفلة. لا يكتب Octa Pass الأسرار أبدًا في بيئة النظام الدائمة؛ استخدم `run` أو الخطّاف أو ملفًا يُحذف بعد ذلك. انظر [البيئات](/ar/docs/features/environments/) لأمثلة Docker وCI وNode وPython.

يستبدل `octapass inject` مراجع `octapass://` في أي ملف نصي (أو stdin) ويكتب الناتج إلى stdout أو إلى `--output`، وهو لا يقرؤه غيرك ولا يُستبدل دون `--force`.

يسمّي المرجع الخزنة باسمها، فيعمل `octapass://Team Ops/Deploy/password` مع خزنة مشتركة. (مراجع `octapass://` في ملفات الإعداد مخطط لها للإصدار 1.0.)

## السحابة وDevOps

كل من هذه يطبع ما تتوقعه أداة واحدة، من عنصر في الخزنة، فيبقى السر خارج ملف إعدادها. وتعمل مع جلسة سلسلة المفاتيح أو مع [حساب خدمة](/ar/docs/features/service-accounts/).

### AWS

`~/.aws/config`:

```ini
[profile prod]
credential_process = octapass aws credential-process "AWS prod" --vault CI
```

يحتاج العنصر إلى الحقلين `accessKeyId` و`secretAccessKey` (ويعمل أيضًا اسم المستخدم وكلمة المرور في بيانات الدخول)، واختياريًا `sessionToken` و`expiration`.

### Kubernetes

في ملف kubeconfig:

```yaml
users:
  - name: prod
    user:
      exec:
        apiVersion: client.authentication.k8s.io/v1
        command: octapass
        args: ["kube", "credential", "Cluster prod", "--vault", "CI"]
        interactiveMode: Never
```

يحتاج العنصر إلى حقل `token` (ويعمل أيضًا `accessToken` الحي في عنصر OAuth2)، أو `clientCertificateData` مع `clientKeyData`.

### Docker

يثبّت `cargo install --path apps/cli` أيضًا `docker-credential-octapass`. في `~/.docker/config.json`:

```json
{ "credsStore": "octapass" }
```

بعدها يحفظ `docker login` في خزنتك بيانات دخول موسومة بـ `docker-credential`، وينقلها `docker logout` إلى سلة المهملات. تستطيع حسابات الخدمة قراءتها لا حفظها.

### Terraform وPulumi

استخدم `octapass run`: انظر [حسابات الخدمة](/ar/docs/features/service-accounts/#terraform-and-pulumi).

## الجلسات

ينشئ `octapass unlock` (و`login`) مفتاح جلسة عشوائيًا ويحفظه في سلسلة مفاتيح نظام التشغيل. أما مفتاح حسابك، مشفّرًا بمفتاح الجلسة هذا، فيبقى في مجلد بيانات الأداة. لا يفتح أي منهما خزنتك وحده، ولا تُخزَّن كلمة المرور الرئيسية أبدًا.

- يمدّد كل أمر نهاية الجلسة، فتنتهي بعد المهلة دون أي أمر. وينهيها `octapass lock` فورًا.
- كل 14 يومًا تُطلب كلمة المرور الرئيسية من جديد، كما مع Touch ID في التطبيقات الأخرى.
- يطلب `octapass export` و`octapass ssh export` كلمة المرور الرئيسية دائمًا من جديد.
- من دون سلسلة مفاتيح، أو مع `OCTAPASS_NO_KEYRING=1`، لا يُحفظ شيء: كل أمر يحتاج إلى الخزنة يطلب كلمة المرور الرئيسية، أو يقرؤها بـ `--password-stdin`.

اسم إدخال سلسلة المفاتيح "Octa Pass CLI" وبصمة تجزئة، فلا يكشف بريدك الإلكتروني ولا الخادم. مجلد البيانات هو `~/Library/Application Support/com.octapass.cli` على macOS، و`%APPDATA%\com.octapass.cli` على Windows، و`~/.local/share/com.octapass.cli` على Linux، ولا يقرؤه غيرك. يحوي المفتاح السري والخزنة المشفّرة ورمز التحديث، مثل [تطبيق سطح المكتب](/ar/docs/platforms/desktop/).

تتزامن الأوامر مع الخادم أولًا. وإذا تعذّر الوصول إليه، تستخدم النسخة الموجودة على هذا الحاسوب وتذكر ذلك على stderr.

### فتح القفل عبر تطبيق سطح المكتب

ما دام [تطبيق سطح المكتب](/ar/docs/platforms/desktop/) يعمل ومسجّلًا الدخول إلى الحساب نفسه، يسأله `octapass` المقفل بدلًا من أن يطلب كلمة مرورك الرئيسية. يطلب التطبيق Touch ID أو Windows Hello أو كلمة مرور نظامك، مسمّيًا البرنامج، ثم يسلّم مفتاح حسابك مشفّرًا لهذا الأمر وحده. لا يُحفظ شيء على القرص ولا في سلسلة المفاتيح.

- تشمل الموافقة هذا البرنامج في هذه الطرفية لمدة 30 دقيقة من عدم النشاط، في ذاكرة التطبيق. وينهيها قفل التطبيق، وكذلك `octapass lock`.
- التطبيق المقفل تفتحه المطالبة نفسها، إن كان فتح القفل بالجهاز مفعّلًا فيه. وإلا فافتح التطبيق أولًا أو استخدم كلمة مرورك الرئيسية.
- تُستخدم الجلسة المحفوظة في سلسلة المفاتيح أولًا، إن كانت لديك. ومع `OCTAPASS_NO_DESKTOP=1` لا يُسأل التطبيق أبدًا.
- على Mac يعمل التطبيق في عزلة (sandbox)، فيستمع في مجلده الخاص، `~/Library/Group Containers/<team>.app.octap/cli.sock`، ويبحث عنه `octapass` هناك. ويحدّد `OCTAPASS_DESKTOP_DATA_DIR` مجلدًا آخر (للتطوير).
- ما زال `octapass export` و`octapass ssh export` يطلبان كلمة المرور الرئيسية.

## الأتمتة بالسكربتات

- يطبع `--json` بصيغة JSON لكل من `status` و`list` و`get` و`totp` و`generate` و`import` وأوامر `env` وأوامر `ssh`.
- يقرأ `--password-stdin` كلمة المرور الرئيسية من السطر الأول في stdin، لأوامر `login` و`unlock` و`export` وأي أمر يُشغَّل والقفل مغلق. وتُقرأ كلمة مرور الملف (تصدير مشفّر، أو استيراد محمي بكلمة مرور) من السطر التالي.
- تذهب الرسائل إلى stderr والبيانات إلى stdout. لا توجد ألوان.
- تعمل أوامر `octapass` واحدًا تلو الآخر: الأمر الثاني ينتظر الأول.

```bash
octapass status --json
octapass list --json --search aws | jq -r '.[].id'
printf '%s\n' "$OCTAPASS_PASSWORD" | octapass --password-stdin get GitHub --field password
```

### رموز الخروج

| الرمز | المعنى |
|:-:|---|
| 0 | تم. في `status`: القفل مفتوح. |
| 1 | خطأ آخر. |
| 2 | وسائط أو مدخلات غير صالحة (خيار غير معروف، أو مرجع أو ملف env غير صالح، أو ملف استيراد ليس بهذه الصيغة). |
| 3 | لم تسجّل الدخول، أو انتهت جلسة الخادم (شغّل `octapass login` من جديد). |
| 4 | القفل مغلق ولم تُعطَ كلمة مرور رئيسية. |
| 5 | كلمة مرور رئيسية أو مفتاح سري خاطئ (أو كلمة مرور ملف التصدير). |
| 6 | لا يوجد هذا العنصر أو الحقل أو الخزنة. |
| 7 | أكثر من عنصر (أو خزنة) يطابق. |
| 8 | تعذّر الوصول إلى الخادم. |

### متغيرات البيئة

| المتغير | الاستخدام |
|---|---|
| `OCTAPASS_SERVER` | الخادم لأمر `login` حين لا يوجد `--server`. |
| `OCTAPASS_EMAIL` | البريد الإلكتروني لأمر `login` حين لا يوجد `--email`. |
| `OCTAPASS_SECRET_KEY` | المفتاح السري لأول `login` دون طرفية. |
| `OCTAPASS_SSO_CODE` | الرمز من صفحة تسجيل الدخول، حين تشترط مؤسسة [تسجيل الدخول الموحّد](/ar/docs/features/single-sign-on/). ويطبع `login` العنوان الذي تفتحه. |
| `OCTAPASS_TWO_STEP_CODE` | رمز من تطبيق المصادقة، أو رمز استرداد للخطوتين، لأمر `login` دون طرفية حين يستخدم الحساب [تسجيل الدخول بخطوتين](/ar/docs/features/two-step-sign-in/). |
| `OCTAPASS_STAGE` | المرحلة التي يحمّلها `run` وخطّاف الصدفة حين لا يُعطى `--stage`، وهي تتغلب على `octapass.toml`. |
| `OCTAPASS_NO_KEYRING` | القيمة `1` لعدم استخدام سلسلة المفاتيح أبدًا. |
| `OCTAPASS_SERVICE_ACCOUNT_TOKEN` | القراءة بصفة [حساب خدمة](/ar/docs/features/service-accounts/): بلا تسجيل دخول ولا سلسلة مفاتيح. لا تعمل إلا الأوامر التي تقرأ. |
| `OCTAPASS_CONNECT` | مكان [Connect](/ar/docs/developers/connect-api/#finding-it)، لاستخدام `octapass connect` كعميل. |
| `OCTAPASS_CONNECT_TOKEN` | رمز هذا العميل، لأمر `octapass connect read`. |
| `OCTAPASS_OAUTH_CLIENT_SECRET`, `OCTAPASS_OAUTH_REFRESH_TOKEN` | أسرار لأمر `octapass oauth create` دون طرفية. |
| `OCTAPASS_NO_DESKTOP` | القيمة `1` لعدم سؤال تطبيق سطح المكتب أبدًا. |
| `OCTAPASS_NO_MASKING` | القيمة `1` ليترك `run` خرج الأمر كما هو، مثل `--no-masking`. |
| `OCTAPASS_CLI_DATA_DIR` | مجلد بيانات آخر (مثلًا مجلد لكل تشغيل اختبار). |

## الاستيراد والتصدير

```bash
octapass import chrome ~/Downloads/Chrome\ Passwords.csv
octapass import bitwarden-json ./bitwarden_export.json --vault Personal
octapass import otpauth ./codes.txt --dry-run
```

الصيغ، كما يسردها `octapass import --help`: `octapass` (تصدير Octa Pass: ملف `.octapass` المشفّر مع ملفاته المرفقة، أو JSON غير مشفّر)، و`cxf` (صيغة FIDO لتبادل بيانات الاعتماد)، و`chrome` (ويشمل Edge وBrave وOpera وVivaldi وArc)، و`firefox`، و`safari` (ويشمل Apple Passwords)، و`bitwarden-json` (ويشمل المحمي بكلمة مرور) و`bitwarden-csv`، و`onepassword-1pux` و`onepassword-csv`، و`lastpass-csv`، و`keepass` (`.kdbx` مع `--key-file` إن كان له ملف مفتاح، أو XML أو CSV)، و`protonpass`، و`dashlane`، و`enpass`، و`keeper`، و`nordpass`، و`roboform`، و`zoho-vault`، و`avira`، و`norton`، و`mcafee`، و`kaspersky`، و`aegis`، و`2fas`، و`andotp`، و`ente-auth`، و`raivo`، و`generic-csv` (أي CSV له صف عناوين) و`otpauth` (روابط `otpauth://` وروابط Google Authenticator بصيغة `otpauth-migration://`، رابط في كل سطر). وما زالت الأسماء القصيرة الأقدم `bitwarden` و`1password` و`1password-csv` و`lastpass` و`csv` تعمل. تُضاف الرموز لمرة واحدة الخاصة بحسابات موجودة عندك إلى تلك الحسابات. الملف المحمي بكلمة مرور يطلب كلمة مروره في طرفية. انظر [الاستيراد](/ar/docs/import-export/overview/).

```bash
octapass export --encrypted --output backup.octapass
octapass export --format json --output backup.json
octapass export --format cxf --output export.cxf.json
octapass export --format csv > logins.csv
```

يكتب `--encrypted` كل شيء، ومنه الملفات المرفقة، مشفّرًا بكلمة مرور تختارها (تُطلب مرتين)؛ ويعيده `octapass import octapass` إلى أي حساب. يحوي `json` كل شيء عدا الملفات، بصيغة تصدير خزنة الويب نفسها؛ و`cxf` لمديري كلمات المرور الآخرين الذين يدعمون صيغة تبادل بيانات الاعتماد؛ و`csv` فيه صف لكل عنصر لمديري كلمات المرور الآخرين. الملفات المكتوبة بـ `--output` لا يقرؤها غيرك. التصدير غير المشفّر ليس مشفّرًا، فاحذفه عند الانتهاء. انظر [التصدير](/ar/docs/import-export/export/).

## ملاحظات أمنية

- لا تضع كلمة المرور الرئيسية في سطر الأوامر أبدًا، فيراها سجل الصدفة وقوائم العمليات لدى المستخدمين الآخرين. دع `octapass` يطلبها، أو استخدم `--password-stdin`.
- الأمر الذي يبدأه `octapass run` يستطيع قراءة أسراره وطباعتها وتسجيلها، وبرامج أخرى تعمل باسمك تستطيع قراءة بيئته. والإخفاء يخفي النسخ الصريحة في خرجه، لا أكثر. شغّل الأوامر التي تثق بها فقط.
- كل من يستطيع استخدام حسابك والجلسة مفتوحة القفل يستطيع قراءة خزنتك، كما في أي تطبيق مفتوح القفل. اقفل عند ابتعادك، أو استخدم `--timeout` قصيرًا.
- على macOS قد تسألك Keychain مرة واحدة هل يحق لـ `octapass` استخدام إدخالها، ومرة أخرى بعد تثبيت إصدار جديد.
