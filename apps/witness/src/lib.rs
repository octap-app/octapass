//! The Octa Pass witness: a C2SP tlog-witness (<https://c2sp.org/tlog-witness>) that cosigns a
//! log's checkpoints, each only if it extends the last one it cosigned for that log. Running one
//! for someone else's Octa Pass server is how the server's key log stops being able to show
//! different people different logs (plan 03, "Witnesses").
//!
//! It speaks the standard protocol, so it can witness any log with Ed25519 checkpoints, and an
//! Octa Pass server can use any other witness that speaks it.
//!
//! - `POST /add-checkpoint`: tlog-witness's submission endpoint.
//! - `GET /<hex SHA-256 of the origin>/checkpoint`: the newest checkpoint it cosigned for a log.
//! - `GET /`: this witness's verifier key, for operators to configure.
//!
//! State is one JSON file. The size check and the write happen under one lock, and the file is
//! on disk before the cosignature leaves, as the spec requires.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::Body;
use axum::extract::{DefaultBodyLimit, Path as UrlPath, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use ed25519_dalek::SigningKey;
use octapass_core::transparency::note::{
    self, COSIGNATURE_V1, Note, NoteSignature, Verifier, cosign,
};
use octapass_core::transparency::witness::{AddCheckpoint, Refusal, WitnessedState, check_add};
use sha2::{Digest, Sha256};

/// Bigger than any checkpoint with 63 proof lines and a few dozen signatures.
pub const MAX_BODY: usize = 128 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum WitnessError {
    #[error("{0}")]
    Io(#[from] std::io::Error),
    #[error("{0} is not valid JSON: {1}")]
    State(PathBuf, serde_json::Error),
    #[error("{0}")]
    Config(String),
}

pub struct Config {
    /// The cosigner name, a schema-less URL such as `witness.example.com/octapass`.
    pub name: String,
    pub key: SigningKey,
    /// The logs this witness accepts: Ed25519 (type 0x01) verifier keys named by their origin.
    pub logs: Vec<String>,
    /// Holds `state.json`.
    pub data_dir: PathBuf,
}

pub struct Witness {
    name: String,
    key: SigningKey,
    verifier: Verifier,
    logs: BTreeMap<String, Verifier>,
    path: PathBuf,
    state: Mutex<BTreeMap<String, WitnessedState>>,
}

/// What `add-checkpoint` answers: cosignature lines, or a refusal.
pub type Answer = Result<String, Refusal>;

impl Witness {
    pub fn open(config: Config) -> Result<Self, WitnessError> {
        let verifier = Verifier::new(&config.name, COSIGNATURE_V1, config.key.verifying_key())
            .map_err(|_| {
                WitnessError::Config(format!(
                    "{:?} isn't a valid witness name: no spaces, no +, at most 255 bytes",
                    config.name
                ))
            })?;
        let mut logs = BTreeMap::new();
        for vkey in &config.logs {
            let log = Verifier::from_vkey(vkey)
                .ok()
                .filter(|log| log.kind == note::ED25519)
                .ok_or_else(|| {
                    WitnessError::Config(format!("{vkey:?} isn't an Ed25519 log verifier key"))
                })?;
            if logs.insert(log.name.clone(), log).is_some() {
                return Err(WitnessError::Config(format!(
                    "two logs share the origin in {vkey:?}"
                )));
            }
        }
        std::fs::create_dir_all(&config.data_dir)?;
        let path = config.data_dir.join("state.json");
        let state = match std::fs::read(&path) {
            Ok(bytes) => {
                serde_json::from_slice(&bytes).map_err(|e| WitnessError::State(path.clone(), e))?
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
            Err(error) => return Err(error.into()),
        };
        Ok(Self {
            name: config.name,
            key: config.key,
            verifier,
            logs,
            path,
            state: Mutex::new(state),
        })
    }

    pub fn vkey(&self) -> String {
        self.verifier.vkey()
    }

    pub fn origins(&self) -> impl Iterator<Item = &str> {
        self.logs.keys().map(String::as_str)
    }

    /// tlog-witness's `add-checkpoint`. Blocking: it writes the state file before answering.
    pub fn add_checkpoint(&self, body: &str, now_s: u64) -> Result<Answer, WitnessError> {
        let Ok(request) = AddCheckpoint::parse(body) else {
            return Ok(Err(Refusal::BadRequest));
        };
        let origin = request.checkpoint.origin.clone();
        let mut state = self.state.lock().expect("the state lock isn't poisoned");
        if let Err(refusal) = check_add(&request, self.logs.get(&origin), state.get(&origin)) {
            return Ok(Err(refusal));
        }
        let signature = cosign(&self.key, &self.name, &request.note.text, now_s)
            .expect("the name was checked at start");
        // Keep the log's signature this witness verified, and its own, for monitors.
        let log = &self.logs[&origin];
        let mut cosigned = Note {
            text: request.note.text.clone(),
            signatures: request
                .note
                .signatures
                .iter()
                .filter(|sig| sig.name == log.name && sig.id == log.id)
                .cloned()
                .collect(),
        };
        cosigned.add([signature.clone()]);
        let mut next = state.clone();
        next.insert(
            origin,
            WitnessedState {
                size: request.checkpoint.size,
                root: note::b64_std_encode(&request.checkpoint.root),
                checkpoint: cosigned.encode(),
            },
        );
        write_atomically(
            &self.path,
            &serde_json::to_vec_pretty(&next).expect("state serializes"),
        )?;
        *state = next;
        Ok(Ok(NoteSignature::to_lines(&[signature])))
    }

    /// The newest checkpoint cosigned for the log whose origin hashes to `origin_hash`.
    pub fn latest(&self, origin_hash: &str) -> Option<String> {
        let state = self.state.lock().expect("the state lock isn't poisoned");
        state
            .iter()
            .find(|(origin, _)| origin_hash_hex(origin) == origin_hash)
            .map(|(_, witnessed)| witnessed.checkpoint.clone())
    }
}

pub fn origin_hash_hex(origin: &str) -> String {
    Sha256::digest(origin.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Writes `path` so that a crash leaves the old file or the new one, never half of either.
fn write_atomically(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("json.tmp");
    {
        let mut file = std::fs::File::create(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    if let Some(dir) = path.parent() {
        // Makes the rename itself durable. Not possible on every platform; best effort there.
        if let Ok(dir) = std::fs::File::open(dir) {
            let _ = dir.sync_all();
        }
    }
    Ok(())
}

fn now_s() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

fn text(status: StatusCode, content_type: &'static str, body: String) -> Response {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, content_type)
        .body(Body::from(body))
        .expect("static headers are valid")
}

async fn add_checkpoint(State(witness): State<Arc<Witness>>, body: String) -> Response {
    let answer = tokio::task::spawn_blocking(move || witness.add_checkpoint(&body, now_s())).await;
    match answer {
        Ok(Ok(Ok(lines))) => text(StatusCode::OK, "text/plain; charset=utf-8", lines),
        Ok(Ok(Err(Refusal::Conflict(size)))) => text(
            StatusCode::CONFLICT,
            "text/x.tlog.size",
            format!("{size}\n"),
        ),
        Ok(Ok(Err(refusal))) => {
            let status = StatusCode::from_u16(refusal.status()).expect("statuses are valid");
            let reason = match refusal {
                Refusal::BadRequest => "malformed request, or old size beyond the checkpoint",
                Refusal::Forbidden => "no valid signature from the log's key",
                Refusal::UnknownOrigin => "this witness doesn't witness that log",
                Refusal::Inconsistent => "the checkpoint doesn't extend the last one cosigned",
                Refusal::Conflict(_) => unreachable!("handled above"),
            };
            text(status, "text/plain; charset=utf-8", format!("{reason}\n"))
        }
        Ok(Err(error)) => {
            tracing::error!(%error, "couldn't save the witness state");
            text(
                StatusCode::INTERNAL_SERVER_ERROR,
                "text/plain; charset=utf-8",
                "couldn't save the witness state\n".into(),
            )
        }
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

async fn checkpoint(
    State(witness): State<Arc<Witness>>,
    UrlPath(origin_hash): UrlPath<String>,
) -> Response {
    match witness.latest(&origin_hash) {
        Some(note) => text(StatusCode::OK, "text/plain; charset=utf-8", note),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn index(State(witness): State<Arc<Witness>>) -> Response {
    text(
        StatusCode::OK,
        "text/plain; charset=utf-8",
        format!("{}\n", witness.vkey()),
    )
}

pub fn router(witness: Arc<Witness>) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/add-checkpoint", post(add_checkpoint))
        .route("/{origin_hash}/checkpoint", get(checkpoint))
        .layer(DefaultBodyLimit::max(MAX_BODY))
        .with_state(witness)
}

/// The witness's signing key: 32 random bytes in `path`, made on first start and readable only
/// by its owner.
pub fn load_or_create_key(path: &Path) -> std::io::Result<SigningKey> {
    match std::fs::read(path) {
        Ok(bytes) => {
            let seed: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
                std::io::Error::other(format!("{} must hold exactly 32 bytes", path.display()))
            })?;
            Ok(SigningKey::from_bytes(&seed))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut seed = zeroize::Zeroizing::new([0u8; 32]);
            rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, seed.as_mut());
            if let Some(dir) = path.parent() {
                std::fs::create_dir_all(dir)?;
            }
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
            let mut file = options.open(path)?;
            file.write_all(seed.as_ref())?;
            file.sync_all()?;
            Ok(SigningKey::from_bytes(&seed))
        }
        Err(error) => Err(error),
    }
}
