//! The developer toolkit in the desktop app (plan 16). Tools run in the Rust core here rather than
//! in the web view; the commands below are the ones that need more than the core: a live
//! certificate, a JWKS and the system trust store.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use octapass_core::tools::toolkit::digest::{Algorithm, Hasher};
use octapass_core::tools::toolkit::{self, HashResult};
use octapass_desktop_vault::{ErrorCode, VaultError};
use octapass_net_tools::{NetError, fetch, tls, trust};
use rand_core::OsRng;
use serde_json::{Value, json};
use tauri::State;
use zeroize::Zeroizing;

type Result<T, E = VaultError> = std::result::Result<T, E>;

fn tool_error(error: octapass_core::Error) -> VaultError {
    // The core's code travels in the message: the web view translates it.
    VaultError::new(ErrorCode::ToolFailed, error.code())
}

fn net_error(error: NetError) -> VaultError {
    VaultError::unexpected(error.to_string())
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_millis() as u64)
}

/// Runs off the UI thread: RSA key generation takes seconds.
#[tauri::command]
pub async fn toolkit_run(op: String, input: String) -> Result<String> {
    tauri::async_runtime::spawn_blocking(move || {
        let input = Zeroizing::new(input);
        toolkit::run(&op, &input, now_ms(), &mut OsRng)
            .map(|output| output.to_string())
            .map_err(tool_error)
    })
    .await
    .map_err(|error| VaultError::unexpected(error.to_string()))?
}

/// Hashes in progress, for files the web view feeds in chunks.
#[derive(Default)]
pub struct Hashing(
    Mutex<HashMap<u64, Vec<(Algorithm, Hasher)>>>,
    std::sync::atomic::AtomicU64,
);

#[tauri::command]
pub fn toolkit_hash_begin(state: State<'_, Hashing>, algorithms: Vec<String>) -> Result<u64> {
    let chosen = if algorithms.is_empty() {
        Algorithm::ALL.to_vec()
    } else {
        algorithms
            .iter()
            .map(|name| Algorithm::parse(name))
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(tool_error)?
    };
    let id = state.1.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let hashers = chosen
        .into_iter()
        .map(|algorithm| (algorithm, Hasher::new(algorithm)))
        .collect();
    state
        .0
        .lock()
        .map_err(|_| VaultError::unexpected("hash state"))?
        .insert(id, hashers);
    Ok(id)
}

#[tauri::command]
pub fn toolkit_hash_update(state: State<'_, Hashing>, id: u64, chunk: String) -> Result<()> {
    let bytes = STANDARD
        .decode(chunk)
        .map_err(|_| VaultError::unexpected("hash chunk"))?;
    let mut running = state
        .0
        .lock()
        .map_err(|_| VaultError::unexpected("hash state"))?;
    let hashers = running
        .get_mut(&id)
        .ok_or_else(|| VaultError::unexpected("no such hash"))?;
    for (_, hasher) in hashers {
        hasher.update(&bytes);
    }
    Ok(())
}

#[tauri::command]
pub fn toolkit_hash_finish(state: State<'_, Hashing>, id: u64) -> Result<Vec<HashResult>> {
    let hashers = state
        .0
        .lock()
        .map_err(|_| VaultError::unexpected("hash state"))?
        .remove(&id)
        .ok_or_else(|| VaultError::unexpected("no such hash"))?;
    Ok(hashers
        .into_iter()
        .map(|(algorithm, hasher)| toolkit::hash_result(algorithm, &hasher.finalize()))
        .collect())
}

#[tauri::command]
pub async fn toolkit_fetch_jwks(url: String) -> Result<String> {
    tauri::async_runtime::spawn_blocking(move || fetch::jwks(&url).map_err(net_error))
        .await
        .map_err(|error| VaultError::unexpected(error.to_string()))?
}

#[tauri::command]
pub async fn toolkit_fetch_host(target: String) -> Result<tls::Probe> {
    tauri::async_runtime::spawn_blocking(move || {
        let (host, port) = tls::parse_target(&target).map_err(net_error)?;
        tls::probe(&host, port).map_err(net_error)
    })
    .await
    .map_err(|error| VaultError::unexpected(error.to_string()))?
}

/// Installs or removes a private CA. Only its public certificate reaches the system's tools, and
/// the web view has already asked the user.
#[tauri::command]
pub async fn toolkit_set_ca_trust(certificate: String, trusted: bool) -> Result<()> {
    tauri::async_runtime::spawn_blocking(move || {
        let report = toolkit::run(
            "cert.read",
            &json!({ "text": certificate }).to_string(),
            now_ms(),
            &mut OsRng,
        )
        .map_err(tool_error)?;
        let report: Value = serde_json::from_str(&report)
            .map_err(|_| VaultError::unexpected("certificate report"))?;
        let info = &report["certificates"][0];
        if info["isCa"] != true {
            return Err(tool_error(octapass_core::Error::InvalidCertificate));
        }
        let text = |name: &str| info[name].as_str().unwrap_or_default();
        let name = trust::entry_name(text("sha256"));
        let store = trust::detect(&name, text("sha1"), text("serial")).map_err(net_error)?;
        let folder = std::env::temp_dir().join(format!("{name}-{}", std::process::id()));
        std::fs::create_dir_all(&folder)
            .map_err(|error| VaultError::unexpected(error.to_string()))?;
        let file = folder.join(format!("{name}.pem"));
        std::fs::write(&file, &certificate)
            .map_err(|error| VaultError::unexpected(error.to_string()))?;
        let action = if trusted {
            trust::Action::Install
        } else {
            trust::Action::Remove
        };
        let outcome = trust::run(&trust::plan(action, &store, &file)).map_err(net_error);
        let _ = std::fs::remove_dir_all(&folder);
        outcome
    })
    .await
    .map_err(|error| VaultError::unexpected(error.to_string()))?
}
