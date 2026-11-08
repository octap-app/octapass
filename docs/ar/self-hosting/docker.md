---
title: التشغيل باستخدام Docker
description: شغّل خادم Octa Pass وخزنة الويب في حاوية Docker واحدة خلف وكيل HTTPS خاص بك، مع Docker Compose والدعوات والنسخ الاحتياطية وفحوص السلامة.
status: beta
sidebar:
  order: 3
---

:::note[لا صورة منشورة]
لا توجد صورة منشورة بعد: ابنِها من المستودع. الإعدادات أدناه تعمل اليوم.
:::

تشغّل الصورة خادم المزامنة وخزنة الويب على منفذ واحد: `/v1/…` هو الـ API (بما فيه WebSocket على `/v1/ws`)، وكل ما عداه خزنة الويب. ضعها خلف وكيل عكسي ينهي TLS؛ فالتطبيقات ترفض الخوادم التي لا تستخدم HTTPS.

## ابنِ الصورة

من جذر المستودع:

```bash
docker build -f apps/server/Dockerfile -t octapass-server .
```

يبني هذا نواة التشفير إلى WebAssembly، ويبني خزنة الويب والخادم، وينسخها إلى صورة distroless تعمل بمستخدم غير جذر. والصور الأساسية مثبّتة بالمعرّف الرقمي (digest).

## Docker Compose

يوجد مثال كامل في [`deploy/octap.app`](https://github.com/octap-app/octapass/tree/main/deploy/octap.app): انسخ المجلد، وغيّر النطاق والبريد الإلكتروني المدعو، ثم شغّل `docker compose up -d --build`. الأساسيات:

```yaml
services:
  octapass:
    build: { context: ../.., dockerfile: apps/server/Dockerfile }
    restart: unless-stopped
    ports: ["127.0.0.1:8380:8080"]      # only your proxy should reach it
    environment:
      OCTAPASS_PUBLIC_URL: https://vault.example.com
      OCTAPASS_WEB_ORIGINS: https://vault.example.com
      OCTAPASS_SIGNUPS: invite
      OCTAPASS_INVITES: you@example.com
      OCTAPASS_TRUST_PROXY: "true"
      OCTAPASS_SMTP_URL: ${OCTAPASS_SMTP_URL:-}
      OCTAPASS_EMAIL_TO_LOG: ${OCTAPASS_EMAIL_TO_LOG:-false}
      OCTAPASS_BACKUP_DIR: /backups
    volumes:
      - octapass-data:/data
      - octapass-backups:/backups
    read_only: true
    tmpfs: [/tmp]
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]

volumes:
  octapass-data:
  octapass-backups:
```

ثم وجّه `https://vault.example.com` إلى `127.0.0.1:8380` في الوكيل (Caddy أو Traefik أو nginx أو نفق Cloudflare)، مع السماح بـ WebSockets.

- **من يستطيع التسجيل.** مع `OCTAPASS_SIGNUPS=invite` لا يستطيع إنشاء حساب إلا عناوين البريد الموجودة في `OCTAPASS_INVITES` (مفصولة بفواصل). وهي مدعوّة في كل تشغيل إلى أن يوجد حسابها؛ ويضيف `octapass-server admin invite` المزيد دون إعادة تشغيل.
- **رمز التحقق.** يحتاج التسجيل إلى رمز يُرسَل بالبريد الإلكتروني. اضبط `OCTAPASS_SMTP_URL`، أو اضبط `OCTAPASS_EMAIL_TO_LOG=true` واقرأ الرمز بالأمر `docker compose logs octapass | grep "verification code"`. لا يُعاد الرمز إلى المتصفح أبدًا خارج وضع التطوير.
- **خزنة الويب** تستخدم دائمًا الخادم الذي تُقدَّم منه. تحصل صفحاتها على سياسة أمان للمحتوى لا تسمح إلا بذلك المصدر مع `wasm-unsafe-eval` (نواة التشفير)، وعلى ترويسات العزل بين المصادر. وتحتفظ استجابات الـ API بـ `default-src 'none'`.
- **PostgreSQL** بدل SQLite: أضف خدمة `postgres:17` واضبط `OCTAPASS_DATABASE_URL=postgres://octapass:<password>@db:5432/octapass`. النسخ الاحتياطية المجدولة لـ SQLite فقط؛ استخدم `pg_dump` هناك.

## فحوص السلامة

- `GET /healthz`: العملية حية
- `GET /readyz`: قاعدة البيانات والتخزين يمكن الوصول إليهما
- `octapass-server healthcheck` ينتهي بالرمز 0 عندما يستجيب `/healthz`. وتستخدمه الصورة كـ `HEALTHCHECK` لها، إذ لا تحوي صدفة (shell) ولا curl.

## أوامر المسؤول

شغّلها داخل الحاوية: `docker compose exec octapass octapass-server admin …`. انظر [الإعدادات](/ar/docs/self-hosting/configuration/#أداة-المسؤول).

## التحديث

```bash
git pull && docker compose up -d --build
```

تعمل ترحيلات قاعدة البيانات تلقائيًا عند البدء، خلف قفل، فلا ترحّل إلا نسخة واحدة في كل مرة. انسخ احتياطيًا أولًا: انظر [النسخ الاحتياطية](/ar/docs/self-hosting/backups/).
