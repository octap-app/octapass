---
title: Backups
description: Back up and restore a self-hosted Octa Pass server safely, why encrypted backups can be stored anywhere, and how users can keep their own vault exports.
status: beta
sidebar:
  order: 5
---

## Server backups

Set `OCTAPASS_BACKUP_DIR` and the server backs itself up while it runs:

| Variable | Default | Description |
|---|---|---|
| `OCTAPASS_BACKUP_DIR` | unset | Turns on scheduled backups into this folder. SQLite only. |
| `OCTAPASS_BACKUP_EVERY_HOURS` | `24` | A new backup when the newest one is older than this. Checked every 10 minutes, so restarts neither skip nor repeat one. |
| `OCTAPASS_BACKUP_KEEP` | `14` | How many backups to keep; older ones are deleted. |

Each backup is a folder `octapass-YYYYMMDD-HHMMSS` (UTC) with the database (copied with SQLite's `VACUUM INTO`, consistent while the server runs), the two server secrets and the `attachments` folder. Attachment files never change, so files the previous backup already has are hard-linked instead of copied. A backup is written under a temporary name and renamed when complete.

By hand, and to restore (stop the server first):

```bash
octapass-server admin backup /backups
octapass-server admin restore /backups/octapass-20261024-030000
```

`admin restore` moves the current database, secrets and attachments to `<data dir>/before-restore-<time>/` instead of deleting them, then copies the backup in. In Docker: `docker compose stop octapass`, then `docker compose run --rm --no-deps octapass admin restore /backups/…`, then `docker compose up -d`.

Everything in a backup is either ciphertext or the metadata listed in [what the server sees](/docs/security/what-the-server-sees/). That means backups can be stored on any provider without exposing vault contents. Still, protect them: they contain users' emails, the server's secrets and encrypted data that an attacker could keep for the long term. **Without `opaque-server-setup.bin`, nobody can sign in again**, so never back up the database alone.

## Recommended routine

1. Keep scheduled backups on (daily is the default).
2. Copy them off the server, following the 3-2-1 rule: three copies, two kinds of media, one off-site.
3. Test a restore on a separate machine every few months.
4. Back up before every upgrade.

With PostgreSQL, use your normal tools (`pg_dump`, WAL archiving), together with a copy of the data directory: the two secret files and the `attachments` folder, or your S3 bucket. Files are encrypted on users' devices, so the copy can live anywhere too. Back up the database and the files together; a restored database lists files by random names that must exist in storage.

## User-level backups

Each user can keep an encrypted [export](/docs/import-export/export/) of their own vault. It doesn't depend on the server at all.
