//! The developer toolkit in the CLI (plan 16). Everything goes through the core's `toolkit::run`, as
//! it does in every app; this file reads files and stdin, keeps private keys off the terminal, and
//! saves to the vault.
//!
//! The rules for private keys are `octapass ssh`'s: never printed on a terminal, written only with
//! permissions for the user alone, never over an existing file unless asked, and read back out of
//! the vault only after the master password (plan 16 §6).

use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use octapass_core::tools::toolkit::digest::{self, Algorithm, Hasher};
use octapass_core::tools::toolkit::keys::KeyKind;
use octapass_core::tools::toolkit::{self, hash_result};
use octapass_desktop_vault::model::{Item, ItemDraft, SessionStatus};
use octapass_net_tools::acme::{self, Challenge};
use octapass_net_tools::dns::{Cloudflare, DigitalOcean, DnsProvider, Hook};
use octapass_net_tools::{NetError, fetch, tls, trust};
use rand_core::OsRng;
use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::error::{CliError, Exit, Result};
use crate::session::DEFAULT_IDLE;
use crate::tools_cli::*;
use crate::{App, Opened, format_table, items};

/// Exit code of `cert expiring` when something needs renewing. Documented in `docs/platforms/cli.md`.
const EXIT_NEEDS_RENEWAL: i32 = 10;
const HASH_CHUNK: usize = 1 << 20;

fn net_error(error: NetError) -> CliError {
    match error {
        NetError::Usage(message) => CliError::usage(message),
        other => CliError::other(other.to_string()),
    }
}

fn is_type(item: &Item, kind: &str) -> bool {
    item.overview.get("type").and_then(Value::as_str) == Some(kind)
}

fn text_of<'a>(value: &'a Value, name: &str) -> &'a str {
    value.get(name).and_then(Value::as_str).unwrap_or_default()
}

fn subject_json(subject: &SubjectArgs) -> Value {
    json!({
        "commonName": subject.cn,
        "organization": subject.org,
        "organizationalUnit": subject.org_unit,
        "country": subject.country,
        "state": subject.state,
        "locality": subject.locality,
    })
}

fn expiry(unix_seconds: u64) -> String {
    time::OffsetDateTime::from_unix_timestamp(unix_seconds as i64)
        .ok()
        .and_then(|date| {
            date.format(&time::format_description::well_known::Rfc3339)
                .ok()
        })
        .unwrap_or_default()
}

impl App {
    pub(crate) async fn tool(&mut self, command: ToolCommand) -> Result<Option<i32>> {
        match command {
            ToolCommand::Cert(command) => self.cert(command).await,
            ToolCommand::Acme(command) => self.acme(command).await,
            ToolCommand::Key(command) => self.key(command).await,
            ToolCommand::Jwt(command) => self.jwt(command).await,
            ToolCommand::Hash(args) => self.hash(args),
            ToolCommand::Hmac(args) => self.hmac(args),
            ToolCommand::Encode(args) => self.codec("encoding.encode", args),
            ToolCommand::Decode(args) => self.codec("encoding.decode", args),
            ToolCommand::Detect { text } => self.detect(text),
            ToolCommand::Random(command) => self.random(command).await,
            ToolCommand::Pwhash(command) => self.pwhash(command),
            ToolCommand::TotpSecret(args) => self.totp_secret(args).await,
        }
    }

    // ---------- Plumbing ----------

    fn call(&self, op: &str, input: &Value) -> Result<Value> {
        let now = (self.context.clock)() * 1000;
        let reply = toolkit::run(op, &input.to_string(), now, &mut OsRng)
            .map_err(|error| CliError::usage(format!("{error}.")))?;
        serde_json::from_str(&reply).map_err(|_| CliError::other("Unexpected tool output."))
    }

    /// A file's bytes, or stdin's without a file or for `-`.
    fn read_bytes(&mut self, file: Option<&Path>) -> Result<Vec<u8>> {
        match file {
            Some(path) if path != Path::new("-") => fs::read(path).map_err(|error| {
                CliError::usage(format!("Can't read {}: {error}", path.display()))
            }),
            _ => {
                let mut bytes = Vec::new();
                self.context
                    .stdin
                    .read_to_end(&mut bytes)
                    .map_err(|error| CliError::usage(format!("Couldn't read stdin: {error}")))?;
                Ok(bytes)
            }
        }
    }

    /// As text; binary input comes back as base64, which the core reads as DER.
    fn read_text(&mut self, file: Option<&Path>) -> Result<Zeroizing<String>> {
        let bytes = Zeroizing::new(self.read_bytes(file)?);
        Ok(Zeroizing::new(match std::str::from_utf8(&bytes) {
            Ok(text) => text.to_owned(),
            Err(_) => STANDARD.encode(&*bytes),
        }))
    }

    fn argument_or_stdin(&mut self, value: Option<String>) -> Result<Zeroizing<String>> {
        match value {
            Some(value) => Ok(Zeroizing::new(value)),
            None => {
                let text = self.read_text(None)?;
                Ok(Zeroizing::new(text.trim().to_owned()))
            }
        }
    }

    fn check_writable(&self, path: Option<&Path>, force: bool) -> Result<()> {
        match path {
            Some(path) if path.exists() && !force => Err(CliError::usage(format!(
                "{} already exists. Pass --force to replace it.",
                path.display()
            ))),
            _ => Ok(()),
        }
    }

    fn write_public(&self, path: &Path, bytes: &[u8]) -> Result<()> {
        fs::write(path, bytes)
            .map_err(|error| CliError::other(format!("Couldn't write {}: {error}", path.display())))
    }

    fn write_secret(&mut self, path: &Path, bytes: &[u8]) -> Result<()> {
        crate::write_private(path, bytes).map_err(|error| {
            CliError::other(format!("Couldn't write {}: {error}", path.display()))
        })?;
        self.note(&format!("Wrote {}. Only you can read it.", path.display()));
        Ok(())
    }

    /// Stops a command before any work when its private key would land nowhere safe.
    fn check_private_destination(&self, keep: &KeepArgs) -> Result<()> {
        self.check_writable(keep.out_key.as_deref(), keep.force)?;
        self.check_writable(keep.out.as_deref(), keep.force)?;
        if !keep.save
            && keep.out_key.is_none()
            && self.context.stdout_is_terminal
            && !self.global.json
        {
            return Err(CliError::usage(
                "Pass --save or --out-key: private keys aren't printed in the terminal.",
            ));
        }
        Ok(())
    }

    async fn save_draft(&mut self, draft: &Value, vault: Option<&str>) -> Result<Item> {
        let opened = self.opened_unlocked().await?;
        let vault_id = self.ssh_target(&opened, vault)?;
        let item = opened
            .vault
            .save_item(ItemDraft {
                id: None,
                vault_id,
                revision: None,
                overview: draft["overview"].clone(),
                details: draft["details"].clone(),
            })
            .await?;
        Ok(item)
    }

    /// Hands a generator's result over: to the vault, to files, or to stdout when that's a pipe.
    /// `public` is what's safe to show either way; `draft` becomes the vault item.
    async fn keep(
        &mut self,
        keep: &KeepArgs,
        public: &str,
        secret: &str,
        draft: impl FnOnce(&Self) -> Result<Value>,
        result: &Value,
    ) -> Result<Option<i32>> {
        if keep.save {
            let draft = draft(self)?;
            let item = self.save_draft(&draft, keep.vault.as_deref()).await?;
            if let Some(path) = &keep.out {
                self.write_public(path, public.as_bytes())?;
            }
            if self.global.json {
                self.out_json(&json!({ "id": item.id, "title": item.title() }))?;
            } else {
                self.note(&format!("Saved “{}”.", item.title()));
                if keep.out.is_none() {
                    self.out(public.trim_end())?;
                }
            }
            return Ok(None);
        }
        if let Some(path) = &keep.out_key {
            self.write_secret(path, secret.as_bytes())?;
        }
        if let Some(path) = &keep.out {
            self.write_public(path, public.as_bytes())?;
            self.note(&format!("Wrote {}.", path.display()));
        }
        if self.global.json {
            let mut shown = result.clone();
            if keep.out_key.is_some()
                && let Some(object) = shown.as_object_mut()
            {
                for field in ["privateKey", "identity", "jwk", "secret"] {
                    object.remove(field);
                }
            }
            self.out_json(&shown)?;
        } else if keep.out.is_none() {
            self.out(public.trim_end())?;
            if keep.out_key.is_none() {
                self.out(secret.trim_end())?;
            }
        }
        Ok(None)
    }

    // ---------- Certificates ----------

    async fn cert(&mut self, command: CertCommand) -> Result<Option<i32>> {
        match command {
            CertCommand::SelfSigned {
                names,
                subject,
                days,
                key_type,
                client_auth,
                keep,
            } => {
                self.check_private_destination(&keep)?;
                let result = self.call(
                    "cert.selfSigned",
                    &json!({
                        "sans": names,
                        "subject": subject_json(&subject),
                        "days": days,
                        "keyType": key_type.name(),
                        "clientAuth": client_auth,
                    }),
                )?;
                self.keep_certificate(&keep, &result, "selfSigned").await
            }
            CertCommand::CaCreate {
                name,
                days,
                key_type,
                permit,
                unconstrained,
                keep,
            } => {
                self.check_private_destination(&keep)?;
                let result = self.call(
                    "cert.caCreate",
                    &json!({
                        "subject": { "commonName": name },
                        "days": days,
                        "keyType": key_type.name(),
                        "permitted": permit,
                        "unconstrained": unconstrained,
                    }),
                )?;
                if unconstrained {
                    self.note("This CA can issue for any name. Keep its key safe, and trust it only where you need it.");
                }
                self.keep_certificate(&keep, &result, "localCa").await
            }
            CertCommand::Issue {
                names,
                ca,
                subject,
                days,
                key_type,
                client_auth,
                keep,
            } => {
                self.check_private_destination(&keep)?;
                let (ca_certificate, ca_key) = self.load_ca(&ca).await?;
                let result = self.call(
                    "cert.issue",
                    &json!({
                        "sans": names,
                        "subject": subject_json(&subject),
                        "days": days,
                        "keyType": key_type.name(),
                        "clientAuth": client_auth,
                        "caCertificate": ca_certificate,
                        "caKey": ca_key.as_str(),
                    }),
                )?;
                self.keep_certificate(&keep, &result, "localCa").await
            }
            CertCommand::Csr {
                names,
                subject,
                key_type,
                key,
                out_key,
                out,
                force,
            } => self.csr(names, subject, key_type, key, out_key, out, force),
            CertCommand::SignCsr { file, ca, days } => {
                let csr = self.read_text(file.as_deref())?;
                let (ca_certificate, ca_key) = self.load_ca(&ca).await?;
                let result = self.call(
                    "cert.signCsr",
                    &json!({
                        "csr": csr.as_str(),
                        "days": days,
                        "caCertificate": ca_certificate,
                        "caKey": ca_key.as_str(),
                    }),
                )?;
                if self.global.json {
                    return self.out_json(&result).map(|()| None);
                }
                self.out(text_of(&result, "certificate").trim_end())
                    .map(|()| None)
            }
            CertCommand::Read { file, host } => {
                let text = self.read_text(file.as_deref())?;
                let report =
                    self.call("cert.read", &json!({ "text": text.as_str(), "host": host }))?;
                self.show_certificates(&report, None)
            }
            CertCommand::Fetch { target } => {
                let (host, port) = tls::parse_target(&target).map_err(net_error)?;
                self.note(&format!(
                    "Connecting to {host}:{port} to read its certificate."
                ));
                let probe = tls::probe(&host, port).map_err(net_error)?;
                let report = self.call("cert.read", &json!({ "text": probe.pem, "host": host }))?;
                self.show_certificates(&report, Some(&probe))
            }
            CertCommand::Convert {
                file,
                to,
                key,
                chain,
                name,
                out,
                force,
            } => self.cert_convert(file, to, key, chain, name, out, force),
            CertCommand::P12Read {
                file,
                out_key,
                force,
            } => self.p12_read(file, out_key, force),
            CertCommand::Trust(args) => self.trust(args, trust::Action::Install).await,
            CertCommand::Untrust(args) => self.trust(args, trust::Action::Remove).await,
            CertCommand::List { vault } => self.cert_list(vault).await,
            CertCommand::Expiring { within, vault } => self.cert_expiring(within, vault).await,
            CertCommand::Export {
                item,
                part,
                out,
                force,
                vault,
            } => self.cert_export(item, part, out, force, vault).await,
        }
    }

    async fn keep_certificate(
        &mut self,
        keep: &KeepArgs,
        result: &Value,
        source: &str,
    ) -> Result<Option<i32>> {
        let mut public = text_of(result, "certificate").to_owned();
        public.push_str(text_of(result, "chain"));
        let private_key = Zeroizing::new(text_of(result, "privateKey").to_owned());
        let title = keep.title.clone();
        let input = json!({
            "title": title,
            "certificate": result["certificate"],
            "chain": result.get("chain"),
            "privateKey": result["privateKey"],
            "source": source,
        });
        self.keep(
            keep,
            &public,
            &private_key,
            |app| app.call("item.certificate", &input),
            result,
        )
        .await
    }

    /// A CA's certificate and key: from a file (or two), or from a Certificate item.
    async fn load_ca(&mut self, ca: &CaArgs) -> Result<(String, Zeroizing<String>)> {
        let path = Path::new(&ca.ca);
        if path.is_file() {
            let certificate = self.read_text(Some(path))?;
            let key = match &ca.ca_key {
                Some(file) => self.read_text(Some(file))?,
                None => certificate.clone(),
            };
            return Ok((certificate.to_string(), key));
        }
        let opened = self.opened_unlocked().await?;
        let item = self.certificate_item(&opened, &ca.ca, None)?;
        let key = item.detail("privateKey").ok_or_else(|| {
            CliError::not_found(format!("“{}” has no private key.", item.title()))
        })?;
        Ok((
            item.detail("certificate").unwrap_or_default().to_owned(),
            Zeroizing::new(key.to_owned()),
        ))
    }

    fn certificate_item(&self, opened: &Opened, query: &str, vault: Option<&str>) -> Result<Item> {
        let item = self.find_item(opened, query, vault)?;
        if !is_type(&item, "certificate") {
            return Err(CliError::not_found(format!(
                "“{}” isn't a certificate.",
                item.title()
            )));
        }
        Ok(item)
    }

    #[allow(clippy::too_many_arguments)]
    fn csr(
        &mut self,
        names: Vec<String>,
        subject: SubjectArgs,
        key_type: ToolKeyType,
        key: Option<PathBuf>,
        out_key: Option<PathBuf>,
        out: Option<PathBuf>,
        force: bool,
    ) -> Result<Option<i32>> {
        self.check_writable(out_key.as_deref(), force)?;
        self.check_writable(out.as_deref(), force)?;
        let existing = key
            .as_deref()
            .map(|file| self.read_text(Some(file)))
            .transpose()?;
        if existing.is_none()
            && out_key.is_none()
            && self.context.stdout_is_terminal
            && !self.global.json
        {
            return Err(CliError::usage(
                "Pass --out-key or --key: private keys aren't printed in the terminal.",
            ));
        }
        let result = self.call(
            "cert.csr",
            &json!({
                "sans": names,
                "subject": subject_json(&subject),
                "keyType": key_type.name(),
                "key": existing.as_ref().map(|key| key.as_str()),
            }),
        )?;
        let private_key = Zeroizing::new(text_of(&result, "privateKey").to_owned());
        if let Some(path) = &out_key {
            self.write_secret(path, private_key.as_bytes())?;
        }
        if let Some(path) = &out {
            self.write_public(path, text_of(&result, "csr").as_bytes())?;
        }
        if self.global.json {
            let mut shown = result;
            if (out_key.is_some() || existing.is_some())
                && let Some(object) = shown.as_object_mut()
            {
                object.remove("privateKey");
            }
            return self.out_json(&shown).map(|()| None);
        }
        if out.is_none() {
            self.out(text_of(&result, "csr").trim_end())?;
        }
        if out_key.is_none() && existing.is_none() {
            self.out(private_key.trim_end())?;
        }
        Ok(None)
    }

    fn show_certificates(
        &mut self,
        report: &Value,
        probe: Option<&tls::Probe>,
    ) -> Result<Option<i32>> {
        if self.global.json {
            let mut shown = report.clone();
            if let Some(probe) = probe {
                shown["connection"] = json!({
                    "protocol": probe.protocol,
                    "cipherSuite": probe.cipher_suite,
                    "trusted": probe.trusted,
                    "trustError": probe.trust_error,
                });
            }
            return self.out_json(&shown).map(|()| None);
        }
        if let Some(csr) = report.get("csr") {
            self.out(&format!("Certificate request: {}", text_of(csr, "subject")))?;
            let names: Vec<&str> = csr["sans"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .collect();
            self.out(&format!("  Names:     {}", names.join(", ")))?;
            self.out(&format!("  Key:       {}", key_description(csr)))?;
            self.out(&format!(
                "  Signature: {}",
                if csr["signatureValid"] == true {
                    "valid"
                } else {
                    "INVALID"
                }
            ))?;
            return Ok(None);
        }
        if let Some(probe) = probe {
            self.out(&format!(
                "{}:{}  {}, {}",
                probe.host, probe.port, probe.protocol, probe.cipher_suite
            ))?;
            match &probe.trust_error {
                None => self.out("Trusted by the Mozilla root program for this name.")?,
                Some(reason) => self.out(&format!("Not publicly trusted: {reason}"))?,
            }
        }
        for certificate in report["certificates"].as_array().into_iter().flatten() {
            self.out(&format!("Subject:   {}", text_of(certificate, "subject")))?;
            self.out(&format!("Issuer:    {}", text_of(certificate, "issuer")))?;
            let sans: Vec<&str> = certificate["sans"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|san| text_of(san, "value"))
                .collect();
            if !sans.is_empty() {
                self.out(&format!("Names:     {}", sans.join(", ")))?;
            }
            self.out(&format!(
                "Valid:     {} to {} ({} days left)",
                expiry(certificate["notBefore"].as_u64().unwrap_or(0)),
                expiry(certificate["notAfter"].as_u64().unwrap_or(0)),
                certificate["daysLeft"]
            ))?;
            self.out(&format!("Key:       {}", key_description(certificate)))?;
            self.out(&format!(
                "Signature: {}",
                text_of(certificate, "signatureAlgorithm")
            ))?;
            self.out(&format!("SHA-256:   {}", text_of(certificate, "sha256")))?;
            for problem in certificate["problems"].as_array().into_iter().flatten() {
                self.out(&format!(
                    "{}:   {}",
                    severity_label(problem),
                    problem_text(text_of(problem, "code"))
                ))?;
            }
            self.out("")?;
        }
        for problem in report["problems"].as_array().into_iter().flatten() {
            self.out(&format!(
                "{}:   {}",
                severity_label(problem),
                problem_text(text_of(problem, "code"))
            ))?;
        }
        Ok(None)
    }

    #[allow(clippy::too_many_arguments)]
    fn cert_convert(
        &mut self,
        file: Option<PathBuf>,
        to: CertFormat,
        key: Option<PathBuf>,
        chain: Option<PathBuf>,
        name: Option<String>,
        out: Option<PathBuf>,
        force: bool,
    ) -> Result<Option<i32>> {
        self.check_writable(out.as_deref(), force)?;
        let text = self.read_text(file.as_deref())?;
        if to == CertFormat::P12 {
            let path = out
                .as_deref()
                .ok_or_else(|| CliError::usage("Pass --out with a file name."))?;
            let key = key
                .as_deref()
                .ok_or_else(|| CliError::usage("PKCS#12 needs the private key: pass --key."))?;
            let key = self.read_text(Some(key))?;
            let chain = chain
                .as_deref()
                .map(|file| self.read_text(Some(file)))
                .transpose()?;
            let password = self.file_password("Password for the file: ", true)?;
            let result = self.call(
                "cert.p12Write",
                &json!({
                    "certificate": text.as_str(),
                    "chain": chain.as_ref().map(|chain| chain.as_str()),
                    "privateKey": key.as_str(),
                    "password": password.as_str(),
                    "friendlyName": name,
                }),
            )?;
            let bytes = STANDARD
                .decode(text_of(&result, "base64"))
                .map_err(|_| CliError::other("Unexpected tool output."))?;
            self.write_secret(path, &bytes)?;
            return Ok(None);
        }
        let format = if to == CertFormat::Der { "der" } else { "pem" };
        let result = self.call(
            "cert.convert",
            &json!({ "text": text.as_str(), "to": format }),
        )?;
        let value = text_of(&result, "value");
        if result["binary"] == true {
            let bytes = STANDARD
                .decode(value)
                .map_err(|_| CliError::other("Unexpected tool output."))?;
            return match out {
                Some(path) => self.write_public(&path, &bytes).map(|()| None),
                None if self.context.stdout_is_terminal => Err(CliError::usage(
                    "Pass --out with a file name: DER is binary.",
                )),
                None => self
                    .context
                    .stdout
                    .write_all(&bytes)
                    .map(|()| None)
                    .map_err(|error| CliError::other(format!("Couldn't write: {error}"))),
            };
        }
        match out {
            Some(path) => self.write_public(&path, value.as_bytes()).map(|()| None),
            None => self.out(value.trim_end()).map(|()| None),
        }
    }

    fn p12_read(
        &mut self,
        file: PathBuf,
        out_key: Option<PathBuf>,
        force: bool,
    ) -> Result<Option<i32>> {
        self.check_writable(out_key.as_deref(), force)?;
        let bytes = self.read_bytes(Some(&file))?;
        let password = self.file_password("Password of the file: ", false)?;
        let mut result = self.call(
            "cert.p12Read",
            &json!({ "base64": STANDARD.encode(&bytes), "password": password.as_str() }),
        )?;
        if let Some(path) = &out_key {
            let key = Zeroizing::new(text_of(&result, "privateKey").to_owned());
            if key.is_empty() {
                return Err(CliError::not_found("This file holds no private key."));
            }
            self.write_secret(path, key.as_bytes())?;
        }
        // The key leaves only through --out-key.
        if let Some(object) = result.as_object_mut() {
            object.remove("privateKey");
        }
        if self.global.json {
            return self.out_json(&result).map(|()| None);
        }
        let mut pem = text_of(&result, "certificate").to_owned();
        pem.push_str(text_of(&result, "chain"));
        self.out(pem.trim_end()).map(|()| None)
    }

    async fn trust(&mut self, args: TrustArgs, action: trust::Action) -> Result<Option<i32>> {
        let path = Path::new(&args.ca);
        let pem = if path.is_file() {
            self.read_text(Some(path))?.to_string()
        } else {
            let opened = self.opened_unlocked().await?;
            let item = self.certificate_item(&opened, &args.ca, None)?;
            item.detail("certificate").unwrap_or_default().to_owned()
        };
        let report = self.call("cert.read", &json!({ "text": pem }))?;
        let info = &report["certificates"][0];
        if info["isCa"] != true {
            return Err(CliError::usage("That certificate isn't a CA."));
        }
        let name = trust::entry_name(text_of(info, "sha256"));
        let store = trust::detect(&name, text_of(info, "sha1"), text_of(info, "serial"))
            .map_err(net_error)?;
        // A public certificate in a temporary folder: it's only there for the system's tools.
        let folder = std::env::temp_dir().join(format!("{name}-{}", std::process::id()));
        fs::create_dir_all(&folder).map_err(|error| {
            CliError::other(format!("Couldn't make a temporary folder: {error}"))
        })?;
        let file = folder.join(format!("{name}.pem"));
        self.write_public(&file, pem.as_bytes())?;
        let steps = trust::plan(action, &store, &file);
        let outcome = self.run_trust_steps(&args, action, info, &steps);
        let _ = fs::remove_dir_all(&folder);
        outcome
    }

    fn run_trust_steps(
        &mut self,
        args: &TrustArgs,
        action: trust::Action,
        info: &Value,
        steps: &[trust::Step],
    ) -> Result<Option<i32>> {
        let plan: Vec<String> = steps.iter().map(trust::Step::display).collect();
        if args.dry_run {
            if self.global.json {
                return self.out_json(&json!({ "steps": plan })).map(|()| None);
            }
            for line in &plan {
                self.out(line)?;
            }
            return Ok(None);
        }
        if !args.yes {
            if !self.context.terminal.interactive() {
                return Err(CliError::usage(
                    "Changing what this device trusts needs a yes: pass --yes, or run it in a terminal.",
                ));
            }
            let verb = match action {
                trust::Action::Install => "Trust",
                trust::Action::Remove => "Stop trusting",
            };
            self.note(&format!(
                "{verb} “{}” on this device? This will run:",
                text_of(info, "subject")
            ));
            for line in &plan {
                self.note(&format!("  {line}"));
            }
            let answer = self
                .context
                .terminal
                .ask("Continue? [y/N] ")
                .map_err(|error| CliError::other(format!("Couldn't read the answer: {error}")))?;
            if !matches!(answer.trim().to_lowercase().as_str(), "y" | "yes") {
                return Err(CliError::new(Exit::Error, "Nothing changed."));
            }
        }
        trust::run(steps).map_err(net_error)?;
        self.note("Done. Browsers may need a restart.");
        Ok(None)
    }

    /// The certificates in the vault, soonest to expire first.
    async fn certificates(&mut self, vault: Option<&str>) -> Result<(Opened, Vec<Item>)> {
        let opened = self.opened_unlocked().await?;
        let vaults = opened.vault.list_vaults()?;
        let only = vault
            .map(|query| items::find_vault(&vaults, query).map(|vault| vault.id.clone()))
            .transpose()?;
        let mut certificates: Vec<Item> = opened
            .vault
            .live_items()?
            .into_iter()
            .filter(|item| is_type(item, "certificate"))
            .filter(|item| only.as_ref().is_none_or(|id| &item.vault_id == id))
            .collect();
        certificates.sort_by(|a, b| a.detail("notAfter").cmp(&b.detail("notAfter")));
        Ok((opened, certificates))
    }

    fn renewal(&self, item: &Item) -> Result<Value> {
        let report = self.call(
            "cert.read",
            &json!({ "text": item.detail("certificate").unwrap_or_default() }),
        )?;
        let info = &report["certificates"][0];
        self.call(
            "cert.renewal",
            &json!({ "notBefore": info["notBefore"], "notAfter": info["notAfter"] }),
        )
    }

    async fn cert_list(&mut self, vault: Option<String>) -> Result<Option<i32>> {
        let (opened, certificates) = self.certificates(vault.as_deref()).await?;
        let vaults = opened.vault.list_vaults()?;
        let mut rows = Vec::new();
        for item in &certificates {
            let renewal = self.renewal(item)?;
            rows.push(json!({
                "id": item.id,
                "title": item.title(),
                "vault": items::vault_name(&vaults, &item.vault_id),
                "keyType": item.detail("keyType"),
                "notAfter": item.detail("notAfter"),
                "fingerprint": item.detail("fingerprint"),
                "state": renewal["state"],
                "daysLeft": renewal["daysLeft"],
            }));
        }
        if self.global.json {
            return self.out_json(&Value::Array(rows)).map(|()| None);
        }
        if rows.is_empty() {
            self.note("No certificates.");
            return Ok(None);
        }
        let table: Vec<[String; 4]> = rows
            .iter()
            .map(|row| {
                [
                    text_of(row, "title").to_owned(),
                    text_of(row, "keyType").to_owned(),
                    format!("{} days", row["daysLeft"]),
                    text_of(row, "vault").to_owned(),
                ]
            })
            .collect();
        for line in format_table(["TITLE", "KEY", "EXPIRES IN", "VAULT"], &table) {
            self.out(&line)?;
        }
        Ok(None)
    }

    async fn cert_expiring(
        &mut self,
        within: Option<i64>,
        vault: Option<String>,
    ) -> Result<Option<i32>> {
        let (_opened, certificates) = self.certificates(vault.as_deref()).await?;
        let mut due = Vec::new();
        for item in &certificates {
            let renewal = self.renewal(item)?;
            let days_left = renewal["daysLeft"].as_i64().unwrap_or(0);
            let in_window = renewal["state"] != "ok";
            if in_window || within.is_some_and(|days| days_left <= days) {
                due.push(json!({
                    "id": item.id,
                    "title": item.title(),
                    "state": renewal["state"],
                    "daysLeft": days_left,
                    "renewable": item.details.get("acme").is_some(),
                }));
            }
        }
        if self.global.json {
            self.out_json(&Value::Array(due.clone()))?;
        } else if due.is_empty() {
            self.note("Nothing needs renewing.");
        } else {
            for entry in &due {
                let line = if entry["state"] == "expired" {
                    format!("{}: expired", text_of(entry, "title"))
                } else {
                    format!(
                        "{}: expires in {} days",
                        text_of(entry, "title"),
                        entry["daysLeft"]
                    )
                };
                self.out(&line)?;
            }
        }
        Ok((!due.is_empty()).then_some(EXIT_NEEDS_RENEWAL))
    }

    /// Unlocks with the master password even when a session is open, as `octapass ssh export` does.
    async fn reconfirmed(&mut self) -> Result<Opened> {
        let opened = self.open(DEFAULT_IDLE)?;
        if opened.vault.snapshot().session.status == SessionStatus::SignedOut {
            return Err(CliError::signed_out());
        }
        if !self.can_ask_password() {
            return Err(CliError::usage(
                "Exporting a private key needs your master password: run it in a terminal, or pass --password-stdin.",
            ));
        }
        let password = self.master_password()?;
        opened.vault.unlock(password).await?;
        self.sync(&opened.vault).await?;
        Ok(opened)
    }

    async fn cert_export(
        &mut self,
        query: String,
        part: CertPart,
        out: Option<PathBuf>,
        force: bool,
        vault: Option<String>,
    ) -> Result<Option<i32>> {
        self.check_writable(out.as_deref(), force)?;
        let secret = matches!(part, CertPart::Key | CertPart::P12);
        if secret && out.is_none() && self.context.stdout_is_terminal {
            return Err(CliError::usage(
                "Pass --out with a file name: private keys aren't printed in the terminal.",
            ));
        }
        let opened = if secret {
            self.reconfirmed().await?
        } else {
            self.opened_unlocked().await?
        };
        let item = self.certificate_item(&opened, &query, vault.as_deref())?;
        let certificate = item.detail("certificate").unwrap_or_default().to_owned();
        let chain = item.detail("chain").unwrap_or_default().to_owned();
        let no_key = || CliError::not_found(format!("“{}” has no private key.", item.title()));
        let output: Zeroizing<Vec<u8>> = match part {
            CertPart::Certificate => Zeroizing::new(certificate.into_bytes()),
            CertPart::Chain => Zeroizing::new(chain.into_bytes()),
            CertPart::Fullchain => Zeroizing::new(format!("{certificate}{chain}").into_bytes()),
            CertPart::Key => Zeroizing::new(
                item.detail("privateKey")
                    .ok_or_else(no_key)?
                    .as_bytes()
                    .to_vec(),
            ),
            CertPart::P12 => {
                let key = item.detail("privateKey").ok_or_else(no_key)?;
                let password = self.file_password("Password for the file: ", true)?;
                let result = self.call(
                    "cert.p12Write",
                    &json!({
                        "certificate": certificate,
                        "chain": chain,
                        "privateKey": key,
                        "password": password.as_str(),
                        "friendlyName": item.title(),
                    }),
                )?;
                Zeroizing::new(
                    STANDARD
                        .decode(text_of(&result, "base64"))
                        .map_err(|_| CliError::other("Unexpected tool output."))?,
                )
            }
        };
        match out {
            Some(path) if secret => self.write_secret(&path, &output)?,
            Some(path) => self.write_public(&path, &output)?,
            None => self
                .context
                .stdout
                .write_all(&output)
                .map_err(|error| CliError::other(format!("Couldn't write: {error}")))?,
        }
        Ok(None)
    }

    // ---------- ACME ----------

    fn acme_challenge(&mut self, options: &AcmeOptions) -> Result<Challenge> {
        match options.challenge {
            AcmeChallenge::Http => Ok(match &options.webroot {
                Some(dir) => Challenge::Http01Webroot { dir: dir.clone() },
                None => Challenge::Http01Standalone {
                    port: options.http_port,
                },
            }),
            AcmeChallenge::Dns => {
                let token = |app: &Self, name: &str| {
                    app.context
                        .var(name)
                        .ok_or_else(|| CliError::usage(format!("Set {name} to your API token.")))
                };
                let provider: Box<dyn DnsProvider> = match options.dns {
                    DnsProviderArg::Manual => {
                        if !self.context.terminal.interactive() {
                            return Err(CliError::usage(
                                "--dns manual needs a terminal. Use --dns hook in scripts.",
                            ));
                        }
                        Box::new(ManualDns)
                    }
                    DnsProviderArg::Hook => Box::new(Hook {
                        program: options
                            .dns_hook
                            .clone()
                            .ok_or_else(|| CliError::usage("Pass --dns-hook with your script."))?,
                    }),
                    DnsProviderArg::Cloudflare => {
                        Box::new(Cloudflare::new(token(self, "CLOUDFLARE_API_TOKEN")?))
                    }
                    DnsProviderArg::Digitalocean => {
                        Box::new(DigitalOcean::new(token(self, "DIGITALOCEAN_TOKEN")?))
                    }
                };
                Ok(Challenge::Dns01 {
                    provider,
                    propagation: Duration::from_secs(options.dns_wait),
                })
            }
        }
    }

    async fn acme(&mut self, command: AcmeCommand) -> Result<Option<i32>> {
        match command {
            AcmeCommand::Issue {
                domains,
                email,
                agree_tos,
                staging,
                zerossl,
                directory,
                eab_kid,
                eab_key,
                key_type,
                options,
                title,
                vault,
            } => {
                if !agree_tos {
                    return Err(CliError::usage(
                        "Read the CA's terms of service, then pass --agree-tos.",
                    ));
                }
                let directory = match (directory, zerossl, staging) {
                    (Some(url), false, false) => url,
                    (None, true, false) => acme::ZEROSSL.to_owned(),
                    (None, false, true) => acme::LETS_ENCRYPT_STAGING.to_owned(),
                    (None, false, false) => acme::LETS_ENCRYPT.to_owned(),
                    _ => {
                        return Err(CliError::usage(
                            "Choose one of --directory, --zerossl and --staging.",
                        ));
                    }
                };
                let eab_key = eab_key.or_else(|| self.context.var("OCTAPASS_ACME_EAB_KEY"));
                let external_account = match (eab_kid, eab_key) {
                    (Some(kid), Some(hmac_key)) => Some(acme::ExternalAccount {
                        kid,
                        hmac_key: Zeroizing::new(hmac_key),
                    }),
                    (None, None) if zerossl => {
                        return Err(CliError::usage(
                            "ZeroSSL needs --eab-kid and --eab-key from your account.",
                        ));
                    }
                    (None, None) => None,
                    _ => return Err(CliError::usage("Pass both --eab-kid and --eab-key.")),
                };
                let certificate_key = kind_of(key_type);
                let challenge = self.acme_challenge(&options)?;
                let opened = self.opened_unlocked().await?;
                let vault_id = self.ssh_target(&opened, vault.as_deref())?;
                let settings = json!({
                    "directory": directory,
                    "domains": domains,
                    "email": email,
                    "challenge": match options.challenge {
                        AcmeChallenge::Http => "http-01",
                        AcmeChallenge::Dns => "dns-01",
                    },
                    "keyType": key_type.name(),
                });
                let issued = self.run_acme(
                    acme::Request {
                        directory,
                        domains,
                        email,
                        account_key: None,
                        certificate_key,
                        external_account,
                        agreed_to_terms: true,
                    },
                    challenge,
                )?;
                self.save_acme(&opened, vault_id, None, None, title, settings, issued)
                    .await
            }
            AcmeCommand::Renew {
                item,
                options,
                vault,
            } => {
                let opened = self.opened_unlocked().await?;
                let found = self.certificate_item(&opened, &item, vault.as_deref())?;
                let settings = found.details.get("acme").cloned().ok_or_else(|| {
                    CliError::usage(format!("“{}” didn't come from ACME.", found.title()))
                })?;
                let domains: Vec<String> = settings["domains"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect();
                let certificate_key =
                    serde_json::from_value::<KeyKind>(settings["keyType"].clone())
                        .unwrap_or(KeyKind::P256);
                let challenge = self.acme_challenge(&options)?;
                let issued = self.run_acme(
                    acme::Request {
                        directory: text_of(&settings, "directory").to_owned(),
                        domains,
                        email: settings["email"].as_str().map(str::to_owned),
                        account_key: settings["accountKey"]
                            .as_str()
                            .map(|key| Zeroizing::new(key.to_owned())),
                        certificate_key,
                        external_account: None,
                        agreed_to_terms: true,
                    },
                    challenge,
                )?;
                let title = Some(found.title().to_owned());
                let vault_id = found.vault_id.clone();
                let id = found.id.clone();
                self.save_acme(
                    &opened,
                    vault_id,
                    Some(id),
                    Some(found.revision),
                    title,
                    settings,
                    issued,
                )
                .await
            }
        }
    }

    fn run_acme(&mut self, request: acme::Request, challenge: Challenge) -> Result<acme::Issued> {
        self.note(&format!(
            "Asking {} for a certificate. Only your public keys and the names go there.",
            request.directory
        ));
        let mut steps = Vec::new();
        let result = acme::issue(request, challenge, |step| steps.push(step.to_owned()));
        for step in steps {
            self.note(&step);
        }
        result.map_err(net_error)
    }

    #[allow(clippy::too_many_arguments)]
    async fn save_acme(
        &mut self,
        opened: &Opened,
        vault_id: String,
        id: Option<String>,
        revision: Option<u64>,
        title: Option<String>,
        mut settings: Value,
        issued: acme::Issued,
    ) -> Result<Option<i32>> {
        settings["accountKey"] = json!(issued.account_key.as_str());
        settings["accountUrl"] = json!(issued.account_url);
        let draft = self.call(
            "item.certificate",
            &json!({
                "title": title,
                "certificate": issued.certificate_chain,
                "privateKey": issued.private_key.as_str(),
                "source": "acme",
                "acme": settings,
            }),
        )?;
        let item = opened
            .vault
            .save_item(ItemDraft {
                id,
                vault_id,
                revision,
                overview: draft["overview"].clone(),
                details: draft["details"].clone(),
            })
            .await?;
        if self.global.json {
            return self
                .out_json(&json!({ "id": item.id, "title": item.title(), "notAfter": item.detail("notAfter") }))
                .map(|()| None);
        }
        self.note(&format!(
            "Saved “{}”, valid until {}.",
            item.title(),
            item.detail("notAfter").unwrap_or_default()
        ));
        Ok(None)
    }

    // ---------- Keys ----------

    async fn key(&mut self, command: KeyCommand) -> Result<Option<i32>> {
        match command {
            KeyCommand::Generate { key_type, keep } => {
                self.check_private_destination(&keep)?;
                let result = self.call("key.generate", &json!({ "type": key_type.name() }))?;
                let secret = Zeroizing::new(text_of(&result, "privateKey").to_owned());
                let public = text_of(&result, "publicPem").to_owned();
                let input = json!({
                    "title": keep.title.clone().unwrap_or_else(|| format!("{} key", key_type.name())),
                    "kind": "asymmetric",
                    "algorithm": key_type.name(),
                    "privateKey": result["privateKey"],
                    "publicKey": result["publicPem"],
                    "fingerprint": result["fingerprints"]["sshSha256"],
                });
                self.keep(
                    &keep,
                    &public,
                    &secret,
                    |app| app.call("item.key", &input),
                    &result,
                )
                .await
            }
            KeyCommand::Inspect { file } => {
                let text = self.read_text(file.as_deref())?;
                let passphrase = self.key_passphrase(&text)?;
                let result = self.call(
                    "key.inspect",
                    &json!({ "key": text.as_str(), "passphrase": passphrase.as_ref().map(|p| p.as_str()) }),
                )?;
                if self.global.json {
                    return self.out_json(&result).map(|()| None);
                }
                self.out(&format!(
                    "{} {}",
                    if result["isPrivate"] == true {
                        "Private key:"
                    } else {
                        "Public key:"
                    },
                    key_description(&result)
                ))?;
                self.out(&format!(
                    "SSH:       {}",
                    text_of(&result["fingerprints"], "sshSha256")
                ))?;
                self.out(&format!(
                    "SPKI:      {}",
                    text_of(&result["fingerprints"], "spkiSha256")
                ))?;
                self.out(&format!(
                    "Pin:       {}",
                    text_of(&result["fingerprints"], "spkiPin")
                ))?;
                self.out(&format!(
                    "JWK:       {}",
                    text_of(&result["fingerprints"], "jwkThumbprint")
                ))?;
                self.out(text_of(&result, "publicOpenssh"))?;
                self.out(text_of(&result, "publicPem").trim_end())?;
                Ok(None)
            }
            KeyCommand::Convert {
                file,
                to,
                encrypt,
                comment,
                out,
                force,
            } => {
                self.check_writable(out.as_deref(), force)?;
                let text = self.read_text(file.as_deref())?;
                let passphrase = self.key_passphrase(&text)?;
                let to_passphrase = encrypt
                    .then(|| self.file_password("Passphrase for the result: ", true))
                    .transpose()?;
                let result = self.call(
                    "key.convert",
                    &json!({
                        "key": text.as_str(),
                        "passphrase": passphrase.as_ref().map(|p| p.as_str()),
                        "to": to.name(),
                        "toPassphrase": to_passphrase.as_ref().map(|p| p.as_str()),
                        "comment": comment,
                    }),
                )?;
                self.write_converted(&result, out.as_deref())
            }
            KeyCommand::Age { keep } => {
                self.check_private_destination(&keep)?;
                let result = self.call("key.age", &json!({}))?;
                let secret = Zeroizing::new(text_of(&result, "identity").to_owned());
                let public = text_of(&result, "recipient").to_owned();
                let input = json!({
                    "title": keep.title.clone().unwrap_or_else(|| "age key".to_owned()),
                    "kind": "age",
                    "algorithm": "X25519",
                    "privateKey": result["identity"],
                    "publicKey": result["recipient"],
                });
                self.keep(
                    &keep,
                    &public,
                    &secret,
                    |app| app.call("item.key", &input),
                    &result,
                )
                .await
            }
            KeyCommand::Gpg {
                user_id,
                key_type,
                keep,
            } => {
                self.check_private_destination(&keep)?;
                let kind = match key_type {
                    GpgKeyType::Ed25519 => "ed25519",
                    GpgKeyType::Rsa4096 => "rsa4096",
                };
                let result =
                    self.call("key.gpg", &json!({ "userId": user_id, "keyType": kind }))?;
                let secret = Zeroizing::new(text_of(&result, "privateKey").to_owned());
                let public = text_of(&result, "publicKey").to_owned();
                let input = json!({
                    "title": keep.title.clone().unwrap_or_else(|| user_id.clone()),
                    "kind": "openpgp",
                    "algorithm": kind,
                    "privateKey": result["privateKey"],
                    "publicKey": result["publicKey"],
                    "fingerprint": result["fingerprint"],
                    "keyId": result["keyId"],
                    "userId": result["userId"],
                });
                self.keep(
                    &keep,
                    &public,
                    &secret,
                    |app| app.call("item.key", &input),
                    &result,
                )
                .await
            }
            KeyCommand::Export {
                item,
                out,
                force,
                vault,
            } => self.key_export(item, out, force, vault).await,
        }
    }

    async fn key_export(
        &mut self,
        query: String,
        out: Option<PathBuf>,
        force: bool,
        vault: Option<String>,
    ) -> Result<Option<i32>> {
        self.check_writable(out.as_deref(), force)?;
        if out.is_none() && self.context.stdout_is_terminal {
            return Err(CliError::usage(
                "Pass --out with a file name: private keys aren't printed in the terminal.",
            ));
        }
        let opened = self.reconfirmed().await?;
        let item = self.find_item(&opened, &query, vault.as_deref())?;
        if !is_type(&item, "key") {
            return Err(CliError::not_found(format!(
                "“{}” isn't a key.",
                item.title()
            )));
        }
        let secret = item
            .detail("privateKey")
            .or_else(|| item.detail("secret"))
            .ok_or_else(|| {
                CliError::not_found(format!("“{}” has no private key.", item.title()))
            })?;
        match out {
            Some(path) => self.write_secret(&path, secret.as_bytes())?,
            None => self.out_secret(secret.trim_end(), true, true)?,
        }
        Ok(None)
    }

    /// Asks for a passphrase when the text is a key that needs one.
    fn key_passphrase(&mut self, text: &str) -> Result<Option<Zeroizing<String>>> {
        let protected = text.contains("ENCRYPTED PRIVATE KEY")
            || text.contains("Proc-Type: 4,ENCRYPTED")
            || (text.contains("OPENSSH PRIVATE KEY")
                && self.call("key.inspect", &json!({ "key": text })).is_err());
        protected
            .then(|| self.file_password("Passphrase of the key: ", false))
            .transpose()
    }

    fn write_converted(&mut self, result: &Value, out: Option<&Path>) -> Result<Option<i32>> {
        let value = Zeroizing::new(text_of(result, "value").to_owned());
        let private = result["isPrivate"] == true;
        let binary = result["binary"] == true;
        let bytes: Zeroizing<Vec<u8>> = if binary {
            Zeroizing::new(
                STANDARD
                    .decode(value.as_str())
                    .map_err(|_| CliError::other("Unexpected tool output."))?,
            )
        } else {
            let mut text = value.as_bytes().to_vec();
            if !value.ends_with('\n') {
                text.push(b'\n');
            }
            Zeroizing::new(text)
        };
        match out {
            Some(path) if private => self.write_secret(path, &bytes)?,
            Some(path) => self.write_public(path, &bytes)?,
            None if self.context.stdout_is_terminal && (private || binary) => {
                return Err(CliError::usage(if private {
                    "Pass --out with a file name: private keys aren't printed in the terminal."
                } else {
                    "Pass --out with a file name: DER is binary."
                }));
            }
            None => self
                .context
                .stdout
                .write_all(&bytes)
                .map_err(|error| CliError::other(format!("Couldn't write: {error}")))?,
        }
        Ok(None)
    }

    // ---------- JWT ----------

    fn secret_input(&mut self, args: &SecretArgs) -> Result<Option<Value>> {
        let Some(file) = &args.secret_file else {
            return Ok(None);
        };
        let text = self.read_text(Some(file))?;
        Ok(Some(json!({
            "value": text.trim_end_matches(['\r', '\n']),
            "encoding": args.secret_encoding,
        })))
    }

    async fn jwt(&mut self, command: JwtCommand) -> Result<Option<i32>> {
        match command {
            JwtCommand::Decode { token } => {
                let token = self.argument_or_stdin(token)?;
                let decoded = self.call("jwt.decode", &json!({ "token": token.as_str() }))?;
                self.show_token(&decoded)
            }
            JwtCommand::Verify {
                token,
                key,
                jwks_url,
                secret,
                leeway,
            } => {
                let token = self.argument_or_stdin(token)?;
                let key_text = match (key, jwks_url) {
                    (Some(file), None) => Some(self.read_text(Some(&file))?),
                    (None, Some(url)) => {
                        self.note(&format!("Fetching keys from {url}."));
                        Some(Zeroizing::new(fetch::jwks(&url).map_err(net_error)?))
                    }
                    (None, None) => None,
                    _ => return Err(CliError::usage("Pass --key or --jwks-url, not both.")),
                };
                let secret = self.secret_input(&secret)?;
                if key_text.is_none() && secret.is_none() {
                    return Err(CliError::usage(
                        "Pass --key, --jwks-url or --secret-file: a token can't be verified without one.",
                    ));
                }
                let verified = self.call(
                    "jwt.verify",
                    &json!({
                        "token": token.as_str(),
                        "key": key_text.as_ref().map(|key| key.as_str()),
                        "secret": secret,
                        "leewaySeconds": leeway,
                    }),
                )?;
                let valid = verified["valid"] == true;
                if self.global.json {
                    self.out_json(&verified)?;
                } else {
                    self.out(if valid {
                        "Valid."
                    } else if verified["signatureValid"] != true {
                        "NOT valid: the signature doesn't match."
                    } else if verified["expired"] == true {
                        "NOT valid: the signature is right, but the token has expired."
                    } else {
                        "NOT valid: the signature is right, but the token isn't valid yet."
                    })?;
                    self.show_token(&verified["decoded"])?;
                }
                Ok((!valid).then_some(Exit::Error as i32))
            }
            JwtCommand::Sign {
                claims,
                alg,
                key,
                secret,
                kid,
                iat,
                expires_in,
            } => {
                let claims = self.argument_or_stdin(claims)?;
                let payload: Value = serde_json::from_str(&claims)
                    .map_err(|_| CliError::usage("The claims aren't valid JSON."))?;
                let key_text = key
                    .as_deref()
                    .map(|file| self.read_text(Some(file)))
                    .transpose()?;
                let secret = self.secret_input(&secret)?;
                let signed = self.call(
                    "jwt.sign",
                    &json!({
                        "payload": payload,
                        "algorithm": alg,
                        "key": key_text.as_ref().map(|key| key.as_str()),
                        "secret": secret,
                        "keyId": kid,
                        "issuedNow": iat,
                        "expiresInSeconds": expires_in,
                    }),
                )?;
                if signed["warnings"]
                    .as_array()
                    .is_some_and(|warnings| !warnings.is_empty())
                {
                    self.note(
                        "Warning: this secret is shorter than the hash, so it's easier to guess.",
                    );
                }
                if self.global.json {
                    return self.out_json(&signed).map(|()| None);
                }
                self.out(text_of(&signed, "token")).map(|()| None)
            }
            JwtCommand::Decrypt { token, key, secret } => {
                let token = self.argument_or_stdin(token)?;
                let key_text = key
                    .as_deref()
                    .map(|file| self.read_text(Some(file)))
                    .transpose()?;
                let secret = self.secret_input(&secret)?;
                let opened = self.call(
                    "jwt.decrypt",
                    &json!({
                        "token": token.as_str(),
                        "key": key_text.as_ref().map(|key| key.as_str()),
                        "secret": secret,
                    }),
                )?;
                if self.global.json {
                    return self.out_json(&opened).map(|()| None);
                }
                let text = opened["text"].as_str().map(str::to_owned);
                match text {
                    Some(text) => self.out_secret(&text, true, true).map(|()| None),
                    None => self
                        .out_secret(text_of(&opened, "base64url"), true, true)
                        .map(|()| None),
                }
            }
            JwtCommand::Keygen { alg, bits, keep } => {
                self.check_private_destination(&keep)?;
                self.jwt_keygen(alg, bits, keep).await
            }
            JwtCommand::Jwks { files } => {
                let mut keys = Vec::new();
                for file in &files {
                    keys.push(self.read_text(Some(file))?.to_string());
                }
                let jwks = self.call("jwt.jwks", &json!({ "keys": keys }))?;
                self.out(&jwks.to_string()).map(|()| None)
            }
        }
    }

    async fn jwt_keygen(
        &mut self,
        alg: String,
        bits: Option<u32>,
        keep: KeepArgs,
    ) -> Result<Option<i32>> {
        let result = self.call(
            "jwt.generateKey",
            &json!({ "algorithm": alg, "bits": bits }),
        )?;
        let secret = Zeroizing::new(
            result
                .get("privateKey")
                .or_else(|| result.get("secret"))
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
        );
        let public = result
            .get("jwks")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let input = json!({
            "title": keep.title.clone().unwrap_or_else(|| format!("{alg} signing key")),
            "kind": "jwt",
            "algorithm": alg,
            "privateKey": result.get("privateKey"),
            "publicKey": result.get("publicKey"),
            "secret": result.get("secret"),
            "jwk": result["jwk"],
            "jwks": result.get("jwks"),
            "keyId": result["keyId"],
        });
        self.keep(
            &keep,
            &public,
            &secret,
            |app| app.call("item.key", &input),
            &result,
        )
        .await
    }

    fn show_token(&mut self, decoded: &Value) -> Result<Option<i32>> {
        if self.global.json {
            return self.out_json(decoded).map(|()| None);
        }
        self.out(&format!("Header:  {}", decoded["header"]))?;
        if let Some(payload) = decoded.get("payload") {
            let text = serde_json::to_string_pretty(payload).unwrap_or_default();
            self.out("Payload:")?;
            self.out(&text)?;
        } else if let Some(text) = decoded["payloadText"].as_str() {
            self.out(&format!("Payload: {text}"))?;
        } else {
            self.out("Payload: encrypted")?;
        }
        for claim in decoded["claims"].as_array().into_iter().flatten() {
            if let Some(line) = claim_line(claim) {
                self.out(&line)?;
            }
        }
        for warning in decoded["warnings"].as_array().into_iter().flatten() {
            self.out(&format!(
                "Warning: {}",
                warning_text(warning.as_str().unwrap_or_default())
            ))?;
        }
        self.note(
            "This shows what the token says, not that it's genuine. Use `octapass jwt verify`.",
        );
        Ok(None)
    }

    // ---------- Hashes and encodings ----------

    fn hash(&mut self, args: HashArgs) -> Result<Option<i32>> {
        if let Some(checksum) = &args.check {
            return self.hash_check(checksum, &args);
        }
        let algorithms = hash_algorithms(&args.algorithms)?;
        let mut rows: Vec<(String, Hashes)> = Vec::new();
        if let Some(text) = &args.text {
            rows.push(("-".to_owned(), hash_all(&algorithms, &mut text.as_bytes())?));
        } else if args.files.is_empty() {
            let mut stdin = std::mem::replace(&mut self.context.stdin, Box::new(std::io::empty()));
            rows.push(("-".to_owned(), hash_all(&algorithms, &mut stdin)?));
        } else {
            for path in &args.files {
                let mut file = fs::File::open(path).map_err(|error| {
                    CliError::usage(format!("Can't read {}: {error}", path.display()))
                })?;
                rows.push((
                    path.display().to_string(),
                    hash_all(&algorithms, &mut file)?,
                ));
            }
        }
        if self.global.json {
            let files: Vec<Value> = rows
                .iter()
                .map(|(name, hashes)| {
                    let hashes: Vec<_> = hashes
                        .iter()
                        .map(|(algorithm, bytes)| hash_result(*algorithm, bytes))
                        .collect();
                    json!({ "name": name, "hashes": hashes })
                })
                .collect();
            return self.out_json(&Value::Array(files)).map(|()| None);
        }
        let several = algorithms.len() > 1;
        for (name, hashes) in rows {
            for (algorithm, bytes) in hashes {
                let hex = digest::to_hex(&bytes);
                if several {
                    self.out(&format!("{}  {hex}  {name}", algorithm.name()))?;
                } else {
                    self.out(&format!("{hex}  {name}"))?;
                }
                if algorithm.is_legacy() {
                    self.note(&format!(
                        "{} is for checking old checksums only: don't rely on it for security.",
                        algorithm.name()
                    ));
                }
            }
        }
        Ok(None)
    }

    fn hash_check(&mut self, checksum: &str, args: &HashArgs) -> Result<Option<i32>> {
        let published = digest::parse_checksum(checksum)
            .map_err(|_| CliError::usage("That isn't a checksum this tool reads."))?;
        let candidates = digest::checksum_candidates(&published);
        if candidates.is_empty() {
            return Err(CliError::usage("No hash has that length."));
        }
        let results = if let Some(text) = &args.text {
            hash_all(&candidates, &mut text.as_bytes())?
        } else if let [path] = args.files.as_slice() {
            let mut file = fs::File::open(path).map_err(|error| {
                CliError::usage(format!("Can't read {}: {error}", path.display()))
            })?;
            hash_all(&candidates, &mut file)?
        } else if args.files.is_empty() {
            let mut stdin = std::mem::replace(&mut self.context.stdin, Box::new(std::io::empty()));
            hash_all(&candidates, &mut stdin)?
        } else {
            return Err(CliError::usage("--check takes one file."));
        };
        let matched = results
            .iter()
            .find(|(_, bytes)| *bytes == published.bytes)
            .map(|(algorithm, _)| *algorithm);
        if self.global.json {
            self.out_json(&json!({
                "matches": matched.is_some(),
                "algorithm": matched.map(Algorithm::name),
            }))?;
        } else {
            match matched {
                Some(algorithm) => self.out(&format!("OK ({})", algorithm.name()))?,
                None => self.out("MISMATCH")?,
            }
        }
        Ok(matched.is_none().then_some(Exit::Error as i32))
    }

    fn hmac(&mut self, args: HmacArgs) -> Result<Option<i32>> {
        let key = self
            .secret_input(&args.secret)?
            .ok_or_else(|| CliError::usage("Pass --secret-file with the key."))?;
        let data = match &args.text {
            Some(text) => text.clone().into_bytes(),
            None => self.read_bytes(args.file.as_deref())?,
        };
        let result = self.call(
            "hash.hmac",
            &json!({ "algorithm": args.algorithm, "key": key, "base64": STANDARD.encode(&data) }),
        )?;
        if self.global.json {
            return self.out_json(&result).map(|()| None);
        }
        self.out(text_of(&result, "hex")).map(|()| None)
    }

    fn codec(&mut self, op: &str, args: CodecArgs) -> Result<Option<i32>> {
        let encoding = op == "encoding.encode";
        let bytes = match args.text {
            Some(text) => text.into_bytes(),
            None => self.read_bytes(None)?,
        };
        let input = if encoding {
            json!({ "format": args.format, "base64": STANDARD.encode(&bytes) })
        } else {
            let value = String::from_utf8(bytes)
                .map_err(|_| CliError::usage("The text to decode isn't valid UTF-8."))?;
            json!({ "format": args.format, "value": value.trim_end_matches(['\r', '\n']) })
        };
        let result = self.call(op, &input)?;
        if self.global.json {
            return self.out_json(&result).map(|()| None);
        }
        if encoding {
            return self.out(text_of(&result, "value")).map(|()| None);
        }
        if let Some(text) = result["text"].as_str() {
            return self.out(text).map(|()| None);
        }
        let raw = STANDARD
            .decode(text_of(&result, "base64"))
            .map_err(|_| CliError::other("Unexpected tool output."))?;
        if self.context.stdout_is_terminal {
            return self.out(text_of(&result, "hex")).map(|()| None);
        }
        self.context
            .stdout
            .write_all(&raw)
            .map(|()| None)
            .map_err(|error| CliError::other(format!("Couldn't write: {error}")))
    }

    fn detect(&mut self, text: Option<String>) -> Result<Option<i32>> {
        let text = self.argument_or_stdin(text)?;
        let result = self.call("encoding.detect", &json!({ "value": text.as_str() }))?;
        if self.global.json {
            return self.out_json(&result).map(|()| None);
        }
        let candidates = result["candidates"].as_array().cloned().unwrap_or_default();
        if candidates.is_empty() {
            self.note("This doesn't look like any encoding.");
        }
        for candidate in candidates {
            let shown = candidate["text"]
                .as_str()
                .or_else(|| candidate["hex"].as_str())
                .unwrap_or_default();
            self.out(&format!(
                "{}  {}%  {shown}",
                text_of(&candidate, "format"),
                candidate["confidence"]
            ))?;
        }
        Ok(None)
    }

    // ---------- Random data ----------

    async fn random(&mut self, command: RandomCommand) -> Result<Option<i32>> {
        let result = match command {
            RandomCommand::Bytes { length, format } => self.call(
                "random.bytes",
                &json!({ "length": length, "format": format }),
            )?,
            RandomCommand::Uuid { version, count } => self.call(
                "random.uuid",
                &json!({ "version": version, "count": count }),
            )?,
            RandomCommand::Ulid { count } => {
                self.call("random.ulid", &json!({ "count": count }))?
            }
            RandomCommand::Token {
                shape,
                length,
                prefix,
                alphabet,
                save,
                title,
                vault,
            } => {
                let result = self.call(
                    "random.token",
                    &json!({ "shape": shape, "length": length, "prefix": prefix, "alphabet": alphabet }),
                )?;
                if result["entropyBits"]
                    .as_f64()
                    .is_some_and(|bits| bits < toolkit::random::MIN_TOKEN_BITS)
                {
                    self.note(&format!(
                        "Warning: this has about {:.0} bits of randomness. Use at least 128 for a secret.",
                        result["entropyBits"].as_f64().unwrap_or(0.0)
                    ));
                }
                if save {
                    let draft = json!({
                        "overview": { "schemaVersion": 1, "type": "apiCredential", "title": title.unwrap_or_else(|| "API key".to_owned()) },
                        "details": { "schemaVersion": 1, "key": result["value"] },
                    });
                    let item = self.save_draft(&draft, vault.as_deref()).await?;
                    if self.global.json {
                        return self
                            .out_json(&json!({ "id": item.id, "title": item.title() }))
                            .map(|()| None);
                    }
                    self.note(&format!("Saved “{}”.", item.title()));
                    return Ok(None);
                }
                result
            }
        };
        if self.global.json {
            return self.out_json(&result).map(|()| None);
        }
        if let Some(values) = result["values"].as_array() {
            for value in values {
                self.out(value.as_str().unwrap_or_default())?;
            }
            return Ok(None);
        }
        self.out(text_of(&result, "value")).map(|()| None)
    }

    fn password_input(&mut self, prompt: &str) -> Result<Zeroizing<String>> {
        if self.context.terminal.interactive() {
            return self
                .context
                .terminal
                .ask_hidden(prompt)
                .map_err(|error| CliError::other(format!("Couldn't read the password: {error}")));
        }
        let mut line = Zeroizing::new(String::new());
        self.context
            .stdin
            .read_line(&mut line)
            .map_err(|error| CliError::usage(format!("Couldn't read stdin: {error}")))?;
        Ok(Zeroizing::new(
            line.trim_end_matches(['\r', '\n']).to_owned(),
        ))
    }

    fn pwhash(&mut self, command: PwhashCommand) -> Result<Option<i32>> {
        match command {
            PwhashCommand::Hash {
                scheme,
                memory,
                iterations,
                parallelism,
                cost,
                log_n,
                digest,
            } => {
                let password = self.password_input("Password to hash: ")?;
                let result = self.call(
                    "password.hash",
                    &json!({
                        "scheme": scheme,
                        "password": password.as_str(),
                        "options": {
                            "memoryKib": memory,
                            "iterations": iterations,
                            "parallelism": parallelism,
                            "cost": cost,
                            "logN": log_n,
                            "digest": digest,
                        },
                    }),
                )?;
                if self.global.json {
                    return self.out_json(&result).map(|()| None);
                }
                self.out(text_of(&result, "hash")).map(|()| None)
            }
            PwhashCommand::Verify { hash } => {
                let password = self.password_input("Password to check: ")?;
                let result = self.call(
                    "password.verify",
                    &json!({ "password": password.as_str(), "hash": hash }),
                )?;
                let matches = result["matches"] == true;
                if self.global.json {
                    self.out_json(&result)?;
                } else {
                    self.out(if matches { "Match." } else { "No match." })?;
                }
                Ok((!matches).then_some(Exit::Error as i32))
            }
        }
    }

    async fn totp_secret(&mut self, args: TotpSecretArgs) -> Result<Option<i32>> {
        let result = self.call(
            "totp.secret",
            &json!({
                "issuer": args.issuer,
                "account": args.account,
                "algorithm": args.algorithm,
                "digits": args.digits,
                "period": args.period,
            }),
        )?;
        if args.save {
            let title = args
                .title
                .or(args.issuer)
                .unwrap_or_else(|| "One-time code".to_owned());
            let draft = json!({
                "overview": { "schemaVersion": 1, "type": "login", "title": title },
                "details": { "schemaVersion": 1, "username": args.account, "totp": result["uri"] },
            });
            let item = self.save_draft(&draft, args.vault.as_deref()).await?;
            self.note(&format!("Saved “{}”.", item.title()));
        }
        if self.global.json {
            return self.out_json(&result).map(|()| None);
        }
        self.out_secret(text_of(&result, "secret"), true, true)?;
        self.out_secret(text_of(&result, "uri"), true, true)?;
        Ok(None)
    }
}

/// Each algorithm with its digest.
type Hashes = Vec<(Algorithm, Vec<u8>)>;

/// Reads to the end in chunks: files can be bigger than memory.
fn hash_all(algorithms: &[Algorithm], reader: &mut dyn Read) -> Result<Hashes> {
    let mut hashers: Vec<(Algorithm, Hasher)> = algorithms
        .iter()
        .map(|algorithm| (*algorithm, Hasher::new(*algorithm)))
        .collect();
    let mut buffer = vec![0u8; HASH_CHUNK];
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|error| CliError::other(format!("Couldn't read: {error}")))?;
        if read == 0 {
            break;
        }
        for (_, hasher) in &mut hashers {
            hasher.update(&buffer[..read]);
        }
    }
    Ok(hashers
        .into_iter()
        .map(|(algorithm, hasher)| (algorithm, hasher.finalize()))
        .collect())
}

fn hash_algorithms(names: &[String]) -> Result<Vec<Algorithm>> {
    if names.is_empty() {
        return Ok(vec![Algorithm::Sha256]);
    }
    if names.iter().any(|name| name == "all") {
        return Ok(Algorithm::ALL.to_vec());
    }
    names
        .iter()
        .map(|name| {
            Algorithm::parse(name)
                .map_err(|_| CliError::usage(format!("“{name}” isn't a hash this tool knows.")))
        })
        .collect()
}

fn kind_of(key_type: ToolKeyType) -> KeyKind {
    match key_type {
        ToolKeyType::Rsa2048 => KeyKind::Rsa2048,
        ToolKeyType::Rsa3072 => KeyKind::Rsa3072,
        ToolKeyType::Rsa4096 => KeyKind::Rsa4096,
        ToolKeyType::P256 => KeyKind::P256,
        ToolKeyType::P384 => KeyKind::P384,
        ToolKeyType::Ed25519 => KeyKind::Ed25519,
    }
}

fn key_description(value: &Value) -> String {
    match (text_of(value, "keyType"), value["curve"].as_str()) {
        ("rsa", _) => format!(
            "RSA {}",
            value["keyBits"]
                .as_u64()
                .or(value["bits"].as_u64())
                .unwrap_or(0)
        ),
        (_, Some(curve)) => format!("ECDSA {curve}"),
        ("ed25519", _) => "Ed25519".to_owned(),
        (other, _) => other.to_owned(),
    }
}

fn severity_label(problem: &Value) -> &'static str {
    match text_of(problem, "severity") {
        "error" => "Problem",
        "warning" => "Warning",
        _ => "Note",
    }
}

/// The reader's problem codes in words. Apps have the same table in their languages.
fn problem_text(code: &str) -> &str {
    match code {
        "expired" => "it has expired",
        "notYetValid" => "it isn't valid yet",
        "expiresSoon" => "it expires within 30 days",
        "weakKey" => "the key is too small",
        "weakSignature" => "it's signed with a broken hash",
        "noSubjectAltName" => "it lists no names, and browsers ignore the common name",
        "validityTooLong" => "it's valid for over 825 days, which Apple devices refuse",
        "selfSigned" => "it's self-signed: only trusted where it's installed",
        "chainOutOfOrder" => "the certificates aren't in chain order",
        "chainSignatureInvalid" => "a signature in the chain doesn't verify",
        "hostMismatch" => "it doesn't cover this host name",
        other => other,
    }
}

fn warning_text(code: &str) -> &str {
    match code {
        "algNone" => "alg is none: this token has no signature and proves nothing",
        "expired" => "it has expired",
        "notYetValid" => "it isn't valid yet",
        "issuedInFuture" => "it says it was issued in the future",
        "noExpiry" => "it never expires",
        "unknownCritical" => "it has a critical header this tool doesn't understand",
        other => other,
    }
}

/// `exp` in plain words: "Expires in 12 minutes".
fn claim_line(claim: &Value) -> Option<String> {
    let value = &claim["value"];
    let text = value
        .as_str()
        .map_or_else(|| value.to_string(), str::to_owned);
    let moment = claim["secondsFromNow"].as_i64();
    Some(match (text_of(claim, "name"), moment) {
        ("iss", _) => format!("Issued by {text}"),
        ("sub", _) => format!("Subject: {text}"),
        ("aud", _) => format!("For: {text}"),
        ("jti", _) => format!("Token id: {text}"),
        ("exp", Some(seconds)) if seconds > 0 => format!("Expires in {}", span(seconds)),
        ("exp", Some(seconds)) => format!("Expired {} ago", span(-seconds)),
        ("nbf", Some(seconds)) if seconds > 0 => format!("Valid in {}", span(seconds)),
        ("nbf", Some(seconds)) => format!("Valid since {} ago", span(-seconds)),
        ("iat", Some(seconds)) if seconds > 0 => format!("Issued {} from now", span(seconds)),
        ("iat", Some(seconds)) => format!("Issued {} ago", span(-seconds)),
        _ => return None,
    })
}

fn span(seconds: i64) -> String {
    match seconds {
        ..120 => format!("{seconds} seconds"),
        120..7200 => format!("{} minutes", seconds / 60),
        7200..172_800 => format!("{} hours", seconds / 3600),
        _ => format!("{} days", seconds / 86_400),
    }
}

/// Prints the record and waits for Enter on the terminal, because the provider is a person.
struct ManualDns;

impl DnsProvider for ManualDns {
    fn publish(&self, name: &str, value: &str) -> octapass_net_tools::Result<String> {
        eprintln!("Add this TXT record, then press Enter:\n  {name}  TXT  \"{value}\"");
        let mut line = String::new();
        std::io::stdin()
            .read_line(&mut line)
            .map_err(|error| NetError::System(error.to_string()))?;
        Ok(String::new())
    }

    fn remove(&self, name: &str, _value: &str, _handle: &str) -> octapass_net_tools::Result<()> {
        eprintln!("You can delete the TXT record at {name} now.");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spans_read_naturally() {
        assert_eq!(span(45), "45 seconds");
        assert_eq!(span(720), "12 minutes");
        assert_eq!(span(10_800), "3 hours");
        assert_eq!(span(864_000), "10 days");
    }

    #[test]
    fn hash_defaults_and_names() {
        assert_eq!(hash_algorithms(&[]).unwrap(), [Algorithm::Sha256]);
        assert_eq!(
            hash_algorithms(&["all".into()]).unwrap().len(),
            Algorithm::ALL.len()
        );
        assert_eq!(
            hash_algorithms(&["SHA-256".into()]).unwrap(),
            [Algorithm::Sha256]
        );
        assert!(hash_algorithms(&["nope".into()]).is_err());
    }
}
