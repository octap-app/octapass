//! `octapass encrypt`, `decrypt`, `shred`, `file-key`, `safe` and `context-menu` (plan 16 §4). The
//! work is in `octapass-files`; this file is arguments, questions and what gets printed.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command as Process;

use octapass_core::tools::age::{self, AgeError, Keys, Target};
use octapass_desktop_vault::vault::safes::SafeInfo;
use octapass_files::files::{self, Decrypted, Encrypted, FilesError};
use octapass_files::menu;
use octapass_files::safe::{Entry, ROOT_ID, Safe, SafeError, Warning};
use octapass_files::shred::{self, Guarantee, Report};
use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::cli::{ContextMenuCommand, DecryptArgs, EncryptArgs, OnOff, SafeCommand};
use crate::error::{CliError, Exit, Result};
use crate::session::DEFAULT_IDLE;
use crate::{App, Opened, format_table};

const RECIPIENT_CACHE: &str = "file-recipient";
const SAFES_FOLDER: &str = "safes";

fn file_error(error: FilesError) -> CliError {
    match error {
        FilesError::NotFound(path) => {
            CliError::not_found(format!("{} doesn't exist.", path.display()))
        }
        FilesError::Exists(path) => CliError::usage(format!(
            "{} already exists. Pass --force to replace it.",
            path.display()
        )),
        FilesError::NoOutputName(path) => CliError::usage(format!(
            "{} doesn't end in .age. Say where to write with --output.",
            path.display()
        )),
        FilesError::UnsafeArchive(name) => CliError::usage(format!(
            "This archive holds something unsafe to unpack, so nothing was: {name}"
        )),
        FilesError::Age(error) => age_error(error),
        FilesError::Io(error) => CliError::other(error.to_string()),
    }
}

fn age_error(error: AgeError) -> CliError {
    match error {
        AgeError::WrongPassphrase => CliError::new(
            Exit::InvalidCredentials,
            "That passphrase doesn't open this file.",
        ),
        AgeError::NoMatchingKey => CliError::new(
            Exit::InvalidCredentials,
            "Your keys can't open this file. It was encrypted for someone else.",
        ),
        AgeError::InvalidRecipient(_) | AgeError::InvalidIdentity | AgeError::NoRecipients => {
            CliError::usage(error.to_string())
        }
        other => CliError::other(other.to_string()),
    }
}

fn safe_error(error: SafeError) -> CliError {
    match error {
        SafeError::NotFound => CliError::not_found("Nothing by that name in this Safe."),
        SafeError::Locked => CliError::locked(),
        other => CliError::other(other.to_string()),
    }
}

/// Says something where the user can see it, without a terminal. Failing is fine: the exit code
/// and stderr still say.
fn notify(title: &str, text: &str) {
    let result = if cfg!(target_os = "macos") {
        let quote = |value: &str| value.replace('\\', r"\\").replace('"', "\\\"");
        Process::new("osascript")
            .arg("-e")
            .arg(format!(
                "display notification \"{}\" with title \"{}\"",
                quote(text),
                quote(title)
            ))
            .status()
    } else if cfg!(windows) {
        return;
    } else {
        Process::new("notify-send").args([title, text]).status()
    };
    let _ = result;
}

fn plain_size(bytes: u64) -> String {
    match bytes {
        0..1024 => format!("{bytes} B"),
        1024..1_048_576 => format!("{:.1} KB", bytes as f64 / 1024.0),
        1_048_576..1_073_741_824 => format!("{:.1} MB", bytes as f64 / 1_048_576.0),
        _ => format!("{:.1} GB", bytes as f64 / 1_073_741_824.0),
    }
}

fn report_json(report: &Report) -> Value {
    serde_json::to_value(report).expect("reports serialize")
}

fn shred_summary(report: &Report) -> String {
    match report.guarantee {
        Guarantee::Overwritten => format!("Overwrote and deleted {}.", report.path.display()),
        Guarantee::BestEffort => format!(
            "Deleted {}, overwriting what could be reached. {}",
            report.path.display(),
            report.note
        ),
    }
}

impl App {
    /// The account's public age key, without unlocking when this device remembers it.
    fn cached_recipient(&self, opened: &Opened) -> Option<String> {
        let account = opened.account_id()?;
        let text = fs::read_to_string(self.context.data_dir.join(RECIPIENT_CACHE)).ok()?;
        let (cached, recipient) = text.trim().rsplit_once(' ')?;
        (cached == account)
            .then(|| age::check_recipient(recipient).ok())
            .flatten()
    }

    fn remember_recipient(&self, opened: &Opened, recipient: &str) {
        if let Some(account) = opened.account_id() {
            let _ = fs::write(
                self.context.data_dir.join(RECIPIENT_CACHE),
                format!("{account} {recipient}\n"),
            );
        }
    }

    async fn own_recipient(&mut self, opened: &Opened) -> Result<String> {
        if let Some(recipient) = self.cached_recipient(opened) {
            return Ok(recipient);
        }
        self.unlocked(opened).await?;
        let keys = opened.vault.file_keys()?;
        self.remember_recipient(opened, &keys.file_recipient);
        Ok(keys.file_recipient.clone())
    }

    /// Who a file is for, as `age1…` keys, from `--to` and `--self`. Everyone named by email gets a
    /// line saying whether their key was compared, because the server handed it out.
    async fn recipients(&mut self, to: &[String], for_self: bool) -> Result<Vec<String>> {
        let mut recipients = Vec::new();
        let mut emails = Vec::new();
        for who in to {
            if who.starts_with("age1") {
                recipients.push(age::check_recipient(who).map_err(age_error)?);
            } else if who.contains('@') {
                emails.push(who.clone());
            } else {
                return Err(CliError::usage(format!(
                    "“{who}” isn't an email or an age1… key."
                )));
            }
        }
        let need_account = for_self || to.is_empty() || !emails.is_empty();
        if !need_account {
            return Ok(recipients);
        }
        let opened = self.open(DEFAULT_IDLE)?;
        if for_self || to.is_empty() {
            recipients.push(self.own_recipient(&opened).await?);
        }
        if !emails.is_empty() {
            self.unlocked(&opened).await?;
            for email in emails {
                let found = opened.vault.file_recipient(&email).await?;
                if !found.verified {
                    self.note(&format!(
                        "{}'s key came from the server and hasn't been compared. Check that their fingerprint is {}.",
                        found.email, found.fingerprint
                    ));
                }
                recipients.push(found.recipient);
            }
        }
        Ok(recipients)
    }

    fn shred_original(&mut self, path: &Path) -> Result<Value> {
        let report = shred::shred(path).map_err(|error| CliError::other(error.to_string()))?;
        let summary = shred_summary(&report);
        self.note(&summary);
        Ok(report_json(&report))
    }

    pub(crate) async fn encrypt(&mut self, args: EncryptArgs) -> Result<Option<i32>> {
        let result = self.encrypt_inner(&args).await;
        if args.notify {
            match &result {
                Ok(count) => notify("Octa Pass", &format!("Encrypted {count} item(s).")),
                Err(error) => notify("Octa Pass", &error.message),
            }
        }
        result.map(|_| None)
    }

    async fn encrypt_inner(&mut self, args: &EncryptArgs) -> Result<usize> {
        let passphrase = if args.passphrase {
            Some(self.file_password("Passphrase: ", true)?)
        } else {
            None
        };
        let recipients = match passphrase {
            Some(_) => Vec::new(),
            None => self.recipients(&args.to, args.for_self).await?,
        };
        let target = match &passphrase {
            Some(passphrase) => Target::Passphrase(passphrase),
            None => Target::Recipients(&recipients),
        };

        let from_stdin = args.paths.is_empty() || args.paths == [PathBuf::from("-")];
        if from_stdin {
            if args.shred {
                return Err(CliError::usage("--shred needs files, not stdin."));
            }
            let output = args.output.as_deref();
            let to_stdout = output.is_none_or(|path| path == Path::new("-"));
            if to_stdout {
                if self.context.stdout_is_terminal && !args.armor {
                    return Err(CliError::usage(
                        "That would print binary to the terminal. Pass --output or --armor.",
                    ));
                }
                let mut input = Zeroizing::new(Vec::new());
                self.context
                    .stdin
                    .read_to_end(&mut input)
                    .map_err(|error| CliError::usage(error.to_string()))?;
                files::encrypt_stream(
                    &target,
                    args.armor,
                    &mut &input[..],
                    &mut self.context.stdout,
                )
                .map_err(file_error)?;
            } else if let Some(path) = output {
                let mut temporary = tempfile::NamedTempFile::new_in(
                    path.parent()
                        .filter(|p| !p.as_os_str().is_empty())
                        .unwrap_or(Path::new(".")),
                )
                .map_err(|error| CliError::other(error.to_string()))?;
                let stdin = &mut self.context.stdin;
                files::encrypt_stream(&target, args.armor, stdin, temporary.as_file_mut())
                    .map_err(file_error)?;
                temporary
                    .persist(path)
                    .map_err(|error| CliError::other(error.to_string()))?;
            }
            return Ok(1);
        }

        if args.output.is_some() && args.paths.len() > 1 {
            return Err(CliError::usage("--output takes one input."));
        }
        let mut done: Vec<(Encrypted, Option<Value>)> = Vec::new();
        for path in &args.paths {
            let folder = path.is_dir();
            let cwd_path = self.context.cwd.join(path);
            if args.output.as_deref() == Some(Path::new("-")) {
                if folder {
                    return Err(CliError::usage("A folder can't go to stdout."));
                }
                let mut input = fs::File::open(&cwd_path).map_err(|_| {
                    CliError::not_found(format!("{} doesn't exist.", path.display()))
                })?;
                files::encrypt_stream(&target, args.armor, &mut input, &mut self.context.stdout)
                    .map_err(file_error)?;
                continue;
            }
            let output = match &args.output {
                Some(output) => self.context.cwd.join(output),
                None => files::encrypted_name(&cwd_path, folder),
            };
            let result = files::encrypt_path(&cwd_path, &target, args.armor, &output, args.force)
                .map_err(file_error)?;
            for skipped in &result.skipped {
                self.note(&format!(
                    "Left out {}: it's a link or special file.",
                    skipped.display()
                ));
            }
            self.note(&format!(
                "Encrypted {} to {}.",
                path.display(),
                result.output.display()
            ));
            let shredded = if args.shred {
                Some(self.shred_original(&cwd_path)?)
            } else {
                None
            };
            done.push((result, shredded));
        }
        let count = done.len();
        if self.global.json {
            let list: Vec<Value> = done
                .iter()
                .map(|(result, shredded)| {
                    json!({
                        "output": result.output,
                        "folder": result.folder,
                        "bytes": result.bytes,
                        "skipped": result.skipped,
                        "shred": shredded,
                    })
                })
                .collect();
            self.out_json(&json!(list))?;
        }
        Ok(count)
    }

    pub(crate) async fn decrypt(&mut self, args: DecryptArgs) -> Result<Option<i32>> {
        let result = self.decrypt_inner(&args).await;
        if args.notify {
            match &result {
                Ok(count) => notify("Octa Pass", &format!("Decrypted {count} item(s).")),
                Err(error) => notify("Octa Pass", &error.message),
            }
        }
        result.map(|_| None)
    }

    /// The keys for one file: a passphrase if that's what it needs, otherwise identity files, or
    /// the account's keys.
    async fn keys_for(
        &mut self,
        needs_passphrase: bool,
        identity_files: &[PathBuf],
    ) -> Result<Keys> {
        if needs_passphrase {
            let passphrase = self.file_password("Passphrase: ", false)?;
            return Ok(Keys {
                identities: Vec::new(),
                passphrase: Some(passphrase),
            });
        }
        if !identity_files.is_empty() {
            let mut identities = Vec::new();
            for path in identity_files {
                let text = Zeroizing::new(
                    fs::read_to_string(self.context.cwd.join(path))
                        .map_err(|error| CliError::usage(format!("{}: {error}", path.display())))?,
                );
                identities.extend(age::parse_identity_file(&text).map_err(age_error)?);
            }
            return Ok(Keys {
                identities,
                passphrase: None,
            });
        }
        let opened = self.open(DEFAULT_IDLE)?;
        self.unlocked(&opened).await?;
        let keys = opened.vault.file_keys()?;
        self.remember_recipient(&opened, &keys.file_recipient);
        Ok(Keys {
            identities: keys.identities(),
            passphrase: None,
        })
    }

    async fn decrypt_inner(&mut self, args: &DecryptArgs) -> Result<usize> {
        if args.paths.is_empty() || args.paths == [PathBuf::from("-")] {
            let mut input = Vec::new();
            self.context
                .stdin
                .read_to_end(&mut input)
                .map_err(|error| CliError::usage(error.to_string()))?;
            let needs = age::Opening::new(&input[..])
                .map_err(age_error)?
                .needs_passphrase();
            let keys = self.keys_for(needs, &args.identity).await?;
            match args
                .output
                .as_deref()
                .filter(|path| *path != Path::new("-"))
            {
                Some(path) => {
                    let path = self.context.cwd.join(path);
                    let mut temporary =
                        tempfile::NamedTempFile::new_in(path.parent().unwrap_or(Path::new(".")))
                            .map_err(|error| CliError::other(error.to_string()))?;
                    files::decrypt_stream(&keys, &input[..], temporary.as_file_mut())
                        .map_err(file_error)?;
                    temporary
                        .persist(&path)
                        .map_err(|error| CliError::other(error.to_string()))?;
                }
                None => {
                    files::decrypt_stream(&keys, &input[..], &mut self.context.stdout)
                        .map_err(file_error)?;
                }
            }
            return Ok(1);
        }
        if args.output.is_some() && args.paths.len() > 1 {
            return Err(CliError::usage("--output takes one input."));
        }
        let mut done: Vec<Decrypted> = Vec::new();
        for path in &args.paths {
            let source = self.context.cwd.join(path);
            let needs = files::needs_passphrase(&source).map_err(|error| match error {
                FilesError::Io(io) if io.kind() == std::io::ErrorKind::NotFound => {
                    CliError::not_found(format!("{} doesn't exist.", path.display()))
                }
                other => file_error(other),
            })?;
            let keys = self.keys_for(needs, &args.identity).await?;
            if args.output.as_deref() == Some(Path::new("-")) {
                let input =
                    fs::File::open(&source).map_err(|error| CliError::other(error.to_string()))?;
                files::decrypt_stream(&keys, input, &mut self.context.stdout)
                    .map_err(file_error)?;
                continue;
            }
            let named = files::decrypted_name(&source);
            let as_folder = named.as_ref().is_some_and(|(_, folder)| *folder);
            let output = match (&args.output, named) {
                (Some(output), _) => self.context.cwd.join(output),
                (None, Some((output, _))) => output,
                (None, None) => {
                    return Err(file_error(FilesError::NoOutputName(path.clone())));
                }
            };
            let result = if as_folder {
                files::decrypt_folder(&source, &keys, &output)
            } else {
                files::decrypt_file(&source, &keys, &output, args.force)
            }
            .map_err(file_error)?;
            self.note(&format!(
                "Decrypted {} to {}.",
                path.display(),
                result.output.display()
            ));
            done.push(result);
        }
        let count = done.len();
        if self.global.json {
            let list: Vec<Value> = done
                .iter()
                .map(|result| {
                    json!({ "output": result.output, "folder": result.folder, "bytes": result.bytes })
                })
                .collect();
            self.out_json(&json!(list))?;
        }
        Ok(count)
    }

    pub(crate) fn shred(&mut self, paths: Vec<PathBuf>, yes: bool) -> Result<Option<i32>> {
        let paths: Vec<PathBuf> = paths
            .iter()
            .map(|path| self.context.cwd.join(path))
            .collect();
        if let Some(missing) = paths
            .iter()
            .find(|path| fs::symlink_metadata(path).is_err())
        {
            return Err(CliError::not_found(format!(
                "{} doesn't exist.",
                missing.display()
            )));
        }
        if !yes {
            if !self.context.terminal.interactive() {
                return Err(CliError::usage(
                    "This can't be undone. Pass --yes to go ahead without a terminal.",
                ));
            }
            for path in &paths {
                let note = shred::storage_of(path).note();
                self.note(&format!("{}: {note}", path.display()));
            }
            let answer = self
                .context
                .terminal
                .ask("Overwrite and delete this for good? Type yes: ")
                .map_err(|error| CliError::usage(error.to_string()))?;
            if answer.trim() != "yes" {
                return Err(CliError::usage("Nothing was deleted."));
            }
        }
        let mut reports = Vec::new();
        for path in &paths {
            let report = shred::shred(path)
                .map_err(|error| CliError::other(format!("{}: {error}", path.display())))?;
            if !report.hard_linked.is_empty() {
                self.note(&format!(
                    "{} has other hard links, so its data stays under those names.",
                    report.path.display()
                ));
            }
            reports.push(report);
        }
        if self.global.json {
            let list: Vec<Value> = reports.iter().map(report_json).collect();
            self.out_json(&json!(list))?;
        } else {
            for report in &reports {
                let summary = shred_summary(report);
                self.out(&summary)?;
            }
        }
        Ok(None)
    }

    pub(crate) async fn file_key(
        &mut self,
        export: bool,
        output: Option<PathBuf>,
        force: bool,
    ) -> Result<Option<i32>> {
        let opened = self.open(DEFAULT_IDLE)?;
        if !export {
            let recipient = self.own_recipient(&opened).await?;
            if self.global.json {
                self.out_json(&json!({ "recipient": recipient }))?;
            } else {
                self.out(&recipient)?;
            }
            return Ok(None);
        }
        // As with any private key, asks for the master password again (plan 16 §6).
        if !self.can_ask_password() {
            return Err(CliError::usage(
                "Exporting a secret key needs your master password: run it in a terminal, or pass --password-stdin.",
            ));
        }
        let password = self.master_password()?;
        opened.vault.unlock(password).await?;
        let keys = opened.vault.file_keys()?;
        self.remember_recipient(&opened, &keys.file_recipient);
        let text = Zeroizing::new(format!(
            "# Octa Pass file key. Opens every file encrypted for you with `octapass encrypt --self`.\n# public key: {}\n{}\n",
            keys.file_recipient,
            keys.file_identity.as_str()
        ));
        match output {
            Some(path) => {
                let path = self.context.cwd.join(path);
                crate::environments::write_secret_file(&path, text.as_bytes(), force)?;
                self.note(&format!("Wrote your file key to {}.", path.display()));
            }
            None => self.out_secret(text.trim_end(), true, true)?,
        }
        Ok(None)
    }

    // ---------- Safes ----------

    fn safe_folder(&self, safe: &SafeInfo) -> PathBuf {
        self.context.data_dir.join(SAFES_FOLDER).join(&safe.safe_id)
    }

    fn find_safe(&self, opened: &Opened, query: &str) -> Result<SafeInfo> {
        let safes = opened.vault.list_safes()?;
        let lowered = query.to_lowercase();
        let mut matching: Vec<SafeInfo> = safes
            .into_iter()
            .filter(|safe| {
                safe.safe_id == query
                    || safe.item_id == query
                    || safe.name.to_lowercase() == lowered
            })
            .collect();
        match matching.len() {
            0 => Err(CliError::not_found(format!("No Safe called “{query}”."))),
            1 => Ok(matching.remove(0)),
            _ => Err(CliError::new(
                Exit::Ambiguous,
                format!("More than one Safe is called “{query}”. Use its id."),
            )),
        }
    }

    fn open_safe(&self, opened: &Opened, info: &SafeInfo) -> Result<Safe> {
        let key = opened.vault.safe_key(&info.item_id)?;
        let folder = self.safe_folder(info);
        let safe = if folder.join("safe.json").exists() {
            Safe::open(&folder, &key)
        } else {
            Safe::create(&folder, &info.safe_id, &key)
        }
        .map_err(safe_error)?;
        Ok(safe)
    }

    fn warn_about(&mut self, safe: &Safe) -> Result<()> {
        for warning in safe.warnings().map_err(safe_error)? {
            let text = match warning {
                Warning::DamagedBlob { .. } => {
                    "Part of this Safe is damaged and couldn't be read.".to_owned()
                }
                Warning::RolledBack { .. } => {
                    "Something in this Safe is older than this device last saw: it may have been rolled back.".to_owned()
                }
                Warning::Missing { .. } => {
                    "Something this device saw in this Safe is gone, with no record of it being deleted.".to_owned()
                }
                Warning::Orphaned { name } => {
                    format!("“{name}” lost its folder, so it's at the top of the Safe now.")
                }
            };
            self.note(&format!("Warning: {text}"));
        }
        Ok(())
    }

    async fn sync_safe(&mut self, opened: &Opened, info: &SafeInfo, safe: &Safe) -> Result<()> {
        if !info.sync {
            return Ok(());
        }
        let remote = opened
            .vault
            .safe_remote(&info.item_id)?
            .with_server_limit()
            .await?;
        let report = safe.sync(&remote).await.map_err(safe_error)?;
        for name in &report.conflicts {
            self.note(&format!(
                "Changed on two devices, so a copy was kept: {name}"
            ));
        }
        for name in &report.too_big {
            self.note(&format!(
                "{name} is too big for the server, so it stays on this device."
            ));
        }
        Ok(())
    }

    fn entry_json(entry: &Entry) -> Value {
        json!({
            "id": entry.id,
            "name": entry.name,
            "folder": entry.folder,
            "size": entry.size,
            "modified": entry.modified,
        })
    }

    /// The folder `path` names and the last name in it.
    fn split_path(path: &str) -> Result<(String, String)> {
        let trimmed = path.trim_matches('/');
        if trimmed.is_empty() {
            return Err(CliError::usage("Name something inside the Safe."));
        }
        Ok(match trimmed.rsplit_once('/') {
            Some((folder, name)) => (folder.to_owned(), name.to_owned()),
            None => (String::new(), trimmed.to_owned()),
        })
    }

    fn make_folders(safe: &Safe, path: &str) -> Result<Entry> {
        let mut current = safe.root_entry();
        for name in path.split('/').filter(|part| !part.is_empty()) {
            current = match safe.lookup(&current.id, name) {
                Ok(found) => found,
                Err(SafeError::NotFound) => {
                    safe.create_folder(&current.id, name).map_err(safe_error)?
                }
                Err(error) => return Err(safe_error(error)),
            };
        }
        Ok(current)
    }

    fn add_to_safe(&mut self, safe: &Safe, folder: &str, source: &Path) -> Result<u64> {
        let name = source
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| CliError::usage(format!("{} has no usable name.", source.display())))?
            .to_owned();
        let metadata = fs::symlink_metadata(source)
            .map_err(|_| CliError::not_found(format!("{} doesn't exist.", source.display())))?;
        if metadata.is_dir() {
            let inner = safe
                .lookup(folder, &name)
                .or_else(|_| safe.create_folder(folder, &name))
                .map_err(safe_error)?;
            let mut count = 0;
            for entry in fs::read_dir(source).map_err(|error| CliError::other(error.to_string()))? {
                let path = entry
                    .map_err(|error| CliError::other(error.to_string()))?
                    .path();
                count += self.add_to_safe(safe, &inner.id, &path)?;
            }
            return Ok(count);
        }
        if !metadata.is_file() {
            self.note(&format!(
                "Left out {}: it's a link or special file.",
                source.display()
            ));
            return Ok(0);
        }
        let entry = match safe.lookup(folder, &name) {
            Ok(entry) => entry,
            Err(SafeError::NotFound) => safe.create_file(folder, &name).map_err(safe_error)?,
            Err(error) => return Err(safe_error(error)),
        };
        let mut input =
            fs::File::open(source).map_err(|error| CliError::other(error.to_string()))?;
        safe.import(&entry.id, &mut input).map_err(safe_error)?;
        Ok(1)
    }

    pub(crate) async fn safe(&mut self, command: SafeCommand) -> Result<Option<i32>> {
        let opened = self.open(DEFAULT_IDLE)?;
        self.unlocked(&opened).await?;
        match command {
            SafeCommand::List => {
                let safes = opened.vault.list_safes()?;
                if self.global.json {
                    self.out_json(&json!(safes))?;
                } else if safes.is_empty() {
                    self.note("No Safes yet. Make one with `octapass safe create <name>`.");
                } else {
                    let rows: Vec<[String; 3]> = safes
                        .iter()
                        .map(|safe| {
                            [
                                safe.name.clone(),
                                if safe.sync { "synced" } else { "this device" }.to_owned(),
                                safe.safe_id.clone(),
                            ]
                        })
                        .collect();
                    for line in format_table(["NAME", "KEPT", "ID"], &rows) {
                        self.out(&line)?;
                    }
                }
            }
            SafeCommand::Create { name, sync } => {
                let info = opened.vault.create_safe(&name, sync).await?;
                self.open_safe(&opened, &info)?;
                if self.global.json {
                    self.out_json(&json!(info))?;
                } else {
                    self.note(&format!("Made the Safe “{}”.", info.name));
                }
            }
            SafeCommand::Ls { safe, path } => {
                let info = self.find_safe(&opened, &safe)?;
                let handle = self.open_safe(&opened, &info)?;
                self.sync_safe(&opened, &info, &handle).await?;
                self.warn_about(&handle)?;
                let folder = handle.resolve(&path).map_err(safe_error)?;
                let entries = handle.list(&folder.id).map_err(safe_error)?;
                if self.global.json {
                    let list: Vec<Value> = entries.iter().map(Self::entry_json).collect();
                    self.out_json(&json!(list))?;
                } else {
                    for entry in entries {
                        let line = if entry.folder {
                            format!("{}/", entry.name)
                        } else {
                            format!("{}  {}", entry.name, plain_size(entry.size))
                        };
                        self.out(&line)?;
                    }
                }
            }
            SafeCommand::Add { safe, files, to } => {
                let info = self.find_safe(&opened, &safe)?;
                let handle = self.open_safe(&opened, &info)?;
                let folder = Self::make_folders(&handle, &to)?;
                let mut count = 0;
                for file in files {
                    let source = self.context.cwd.join(file);
                    count += self.add_to_safe(&handle, &folder.id, &source)?;
                }
                self.sync_safe(&opened, &info, &handle).await?;
                self.note(&format!("Added {count} file(s) to “{}”.", info.name));
            }
            SafeCommand::Get {
                safe,
                path,
                output,
                force,
            } => {
                let info = self.find_safe(&opened, &safe)?;
                let handle = self.open_safe(&opened, &info)?;
                self.sync_safe(&opened, &info, &handle).await?;
                let entry = handle.resolve(&path).map_err(safe_error)?;
                if entry.folder {
                    return Err(CliError::usage("That's a folder."));
                }
                if output.as_deref() == Some(Path::new("-")) {
                    handle
                        .export(&entry.id, &mut self.context.stdout)
                        .map_err(safe_error)?;
                } else {
                    let target = self
                        .context
                        .cwd
                        .join(output.unwrap_or_else(|| PathBuf::from(&entry.name)));
                    if target.exists() && !force {
                        return Err(CliError::usage(format!(
                            "{} already exists. Pass --force to replace it.",
                            target.display()
                        )));
                    }
                    let folder = target.parent().unwrap_or(Path::new("."));
                    let mut temporary = tempfile::NamedTempFile::new_in(folder)
                        .map_err(|error| CliError::other(error.to_string()))?;
                    handle
                        .export(&entry.id, temporary.as_file_mut())
                        .map_err(safe_error)?;
                    temporary
                        .persist(&target)
                        .map_err(|error| CliError::other(error.to_string()))?;
                    self.note(&format!("Wrote {}.", target.display()));
                }
            }
            SafeCommand::Mkdir { safe, path } => {
                let info = self.find_safe(&opened, &safe)?;
                let handle = self.open_safe(&opened, &info)?;
                Self::make_folders(&handle, &path)?;
                self.sync_safe(&opened, &info, &handle).await?;
            }
            SafeCommand::Mv { safe, from, to } => {
                let info = self.find_safe(&opened, &safe)?;
                let handle = self.open_safe(&opened, &info)?;
                let entry = handle.resolve(&from).map_err(safe_error)?;
                let (folder, name) = Self::split_path(&to)?;
                let folder = handle.resolve(&folder).map_err(safe_error)?;
                handle
                    .rename(&entry.id, &folder.id, &name)
                    .map_err(safe_error)?;
                self.sync_safe(&opened, &info, &handle).await?;
            }
            SafeCommand::Rm {
                safe,
                path,
                recursive,
            } => {
                let info = self.find_safe(&opened, &safe)?;
                let handle = self.open_safe(&opened, &info)?;
                let entry = handle.resolve(&path).map_err(safe_error)?;
                if entry.id == ROOT_ID {
                    return Err(CliError::usage("Name something inside the Safe."));
                }
                if recursive {
                    handle.remove_all(&entry.id)
                } else {
                    handle.remove(&entry.id)
                }
                .map_err(safe_error)?;
                self.sync_safe(&opened, &info, &handle).await?;
            }
            SafeCommand::Sync { safe } => {
                let info = self.find_safe(&opened, &safe)?;
                if !info.sync {
                    return Err(CliError::usage(format!(
                        "“{}” stays on this device. Turn sync on with `octapass safe set-sync`.",
                        info.name
                    )));
                }
                let handle = self.open_safe(&opened, &info)?;
                self.sync_safe(&opened, &info, &handle).await?;
                self.warn_about(&handle)?;
            }
            SafeCommand::Delete { safe, yes } => {
                let info = self.find_safe(&opened, &safe)?;
                if !yes {
                    if !self.context.terminal.interactive() {
                        return Err(CliError::usage(
                            "This deletes the Safe and everything in it. Pass --yes to go ahead without a terminal.",
                        ));
                    }
                    let answer = self
                        .context
                        .terminal
                        .ask(&format!(
                            "Delete the Safe “{}” and everything in it? Type its name: ",
                            info.name
                        ))
                        .map_err(|error| CliError::usage(error.to_string()))?;
                    if answer.trim() != info.name {
                        return Err(CliError::usage("Nothing was deleted."));
                    }
                }
                opened.vault.delete_safe(&info.item_id).await?;
                let folder = self.safe_folder(&info);
                if folder.exists() {
                    fs::remove_dir_all(&folder)
                        .map_err(|error| CliError::other(error.to_string()))?;
                }
                self.note(&format!("Deleted the Safe “{}”.", info.name));
            }
            SafeCommand::SetSync { safe, state } => {
                let info = self.find_safe(&opened, &safe)?;
                let on = matches!(state, OnOff::On);
                let info = opened.vault.set_safe_sync(&info.item_id, on).await?;
                if on {
                    let handle = self.open_safe(&opened, &info)?;
                    self.sync_safe(&opened, &info, &handle).await?;
                }
            }
            SafeCommand::Mount { safe, mountpoint } => {
                let info = self.find_safe(&opened, &safe)?;
                let handle = self.open_safe(&opened, &info)?;
                let target = self.context.cwd.join(mountpoint);
                self.mount_safe(opened, handle, &info, &target).await?;
            }
        }
        Ok(None)
    }

    #[cfg(feature = "fuse")]
    async fn mount_safe(
        &mut self,
        opened: Opened,
        safe: Safe,
        info: &SafeInfo,
        target: &Path,
    ) -> Result<()> {
        use std::sync::Arc;
        use std::time::Duration;

        self.sync_safe(&opened, info, &safe).await?;
        self.warn_about(&safe)?;
        let safe = Arc::new(safe);
        let account = opened.account_id();
        let unlock = Arc::clone(&opened.unlock);
        let has_session = unlock.available();
        // Other `octapass` commands, `lock` among them, must be able to run while this waits.
        drop(opened);
        let mount = octapass_files::safe::fuse::mount(Arc::clone(&safe), target, &info.name)
            .map_err(safe_error)?;
        self.note(&format!(
            "“{}” is at {}. It stays there until you unmount it or the vault locks.",
            info.name,
            target.display()
        ));
        // The session in the keyring is what "the vault locked" means to the CLI: `octapass lock`
        // or the idle timeout ends it.
        while !mount.finished() {
            tokio::time::sleep(Duration::from_secs(1)).await;
            let alive = account
                .as_deref()
                .is_some_and(|account| unlock.expires_at(account).is_some());
            if has_session && !alive {
                self.note("The vault locked, so the Safe was locked too.");
                break;
            }
        }
        drop(mount);
        safe.lock().map_err(safe_error)?;
        Ok(())
    }

    #[cfg(not(feature = "fuse"))]
    async fn mount_safe(
        &mut self,
        _opened: Opened,
        _safe: Safe,
        _info: &SafeInfo,
        _target: &Path,
    ) -> Result<()> {
        Err(CliError::usage(
            "This build of the CLI can't mount a Safe. On Linux, use a build with FUSE; on macOS and Windows, open the Safe in the desktop app.",
        ))
    }

    // ---------- Right-click menus ----------

    pub(crate) fn context_menu(&mut self, command: ContextMenuCommand) -> Result<Option<i32>> {
        let home = self
            .context
            .env
            .iter()
            .find(|(key, _)| key == "HOME" || key == "USERPROFILE")
            .map(|(_, value)| PathBuf::from(value))
            .ok_or_else(|| CliError::other("This user has no home folder."))?;
        let mut locations = menu::Locations::under(&home);
        if let Some((_, data)) = self
            .context
            .env
            .iter()
            .find(|(key, _)| key == "XDG_DATA_HOME")
        {
            locations.data = PathBuf::from(data);
        }
        let surfaces = menu::surfaces();
        match command {
            ContextMenuCommand::Install => {
                let program =
                    std::env::current_exe().map_err(|error| CliError::other(error.to_string()))?;
                menu::install(
                    surfaces,
                    &menu::Launcher::Cli(program),
                    &locations,
                    menu::Language::English,
                )
                .map_err(|error| CliError::other(error.to_string()))?;
                for surface in surfaces {
                    let name = surface.name();
                    self.note(&format!("Added “Encrypt with Octa Pass” to {name}."));
                }
            }
            ContextMenuCommand::Remove => {
                menu::remove(surfaces, &locations)
                    .map_err(|error| CliError::other(error.to_string()))?;
            }
            ContextMenuCommand::Status => {
                let list: Vec<Value> = surfaces
                    .iter()
                    .map(|surface| {
                        json!({ "surface": surface, "installed": menu::installed(*surface, &locations) })
                    })
                    .collect();
                if self.global.json {
                    self.out_json(&json!(list))?;
                } else {
                    for surface in surfaces {
                        let state = if menu::installed(*surface, &locations) {
                            "installed"
                        } else {
                            "not installed"
                        };
                        let line = format!("{}: {state}", surface.name());
                        self.out(&line)?;
                    }
                }
            }
        }
        Ok(None)
    }
}
