//! Sends the key log's checkpoints to its witnesses (plan 03, "Witnesses"), over C2SP
//! tlog-witness, and keeps the newest checkpoint a quorum of them cosigned for clients.
//!
//! A round signs a checkpoint of the whole tree and posts it to every witness at once, with a
//! consistency proof from the size that witness last cosigned. A witness that answers 409 says
//! which size it holds; the round tries again once from there. Rounds repeat every
//! `OCTAPASS_KEY_LOG_WITNESS_INTERVAL`, even when the tree hasn't grown: a cosignature's age is
//! what tells clients the log is still being witnessed.

use std::time::Duration;

use octapass_core::transparency::merkle::{Hash, consistency_ranges};
use octapass_core::transparency::note::{self, NoteSignature, Verifier};
use octapass_core::transparency::witness::AddCheckpoint;
use tokio::task::JoinSet;

use crate::config::{KeyLogWitness, KeyLogWitnesses};
use crate::db::key_log;
use crate::state::AppState;

const TIMEOUT: Duration = Duration::from_secs(15);
/// A witness's answer is a few signature lines.
const MAX_RESPONSE: usize = 64 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum WitnessError {
    #[error("database: {0}")]
    Db(#[from] sqlx::Error),
    #[error("couldn't reach the witness: {0}")]
    Http(#[from] reqwest::Error),
    #[error("the witness answered {status}: {body}")]
    Refused { status: u16, body: String },
    #[error("the witness's answer isn't a valid cosignature from its key")]
    BadCosignature,
    #[error(
        "the witness has cosigned {theirs} entries but this log has {ours}: was the data restored \
         from an older backup? Witnesses never accept a log that shrinks"
    )]
    Ahead { theirs: u64, ours: u64 },
    #[error("the witness kept changing its size")]
    Conflicts,
}

/// What a round did.
#[derive(Debug)]
pub struct Round {
    pub size: u64,
    /// Witnesses that cosigned, by verifier key.
    pub cosigned: Vec<String>,
    /// Witnesses that didn't, and why.
    pub failed: Vec<(String, WitnessError)>,
    /// Whether a quorum cosigned, so clients now get this checkpoint.
    pub stored: bool,
}

pub fn spawn(state: AppState) {
    let Some(config) = state.config.key_log_witnesses.clone() else {
        return;
    };
    tracing::info!(
        origin = %state.key_log.origin,
        vkey = %state.key_log.vkey(),
        witnesses = config.witnesses.len(),
        quorum = config.quorum,
        "key log witnesses on"
    );
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(config.interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            match round(&state, &config).await {
                Ok(round) => {
                    for (witness, error) in &round.failed {
                        tracing::warn!(%witness, %error, "key log witness didn't cosign");
                    }
                    if !round.stored {
                        tracing::error!(
                            size = round.size,
                            cosigned = round.cosigned.len(),
                            quorum = config.quorum,
                            "too few key log witnesses cosigned: clients holding this log to its \
                             witnesses will refuse it once the last checkpoint is a week old"
                        );
                    }
                }
                Err(error) => tracing::error!(%error, "key log witness round failed"),
            }
        }
    });
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("the HTTP client's settings are valid")
}

async fn root(state: &AppState, size: u64) -> Result<Hash, sqlx::Error> {
    let mut conn = state.db.acquire().await?;
    crate::routes::transparency::subtree_hash(&mut conn, 0..size).await
}

async fn consistency(state: &AppState, old: u64, new: u64) -> Result<Vec<Hash>, sqlx::Error> {
    let mut conn = state.db.acquire().await?;
    let mut proof = Vec::new();
    for range in consistency_ranges(old, new) {
        proof.push(crate::routes::transparency::subtree_hash(&mut conn, range).await?);
    }
    Ok(proof)
}

/// One round: a checkpoint of the current tree to every witness.
pub async fn round(state: &AppState, config: &KeyLogWitnesses) -> Result<Round, WitnessError> {
    let size = key_log::size(&state.db).await?;
    let root = root(state, size).await?;
    let mut note = state.key_log.sign_checkpoint(size, &root);
    let http = client();
    let mut tasks = JoinSet::new();
    for witness in config.witnesses.clone() {
        let (state, http, note) = (state.clone(), http.clone(), note.clone());
        tasks.spawn(async move {
            let result = submit(&state, &http, &witness, &note, size).await;
            (witness.vkey, result)
        });
    }
    let (mut cosigned, mut failed, mut signatures) = (Vec::new(), Vec::new(), Vec::new());
    while let Some(joined) = tasks.join_next().await {
        let (vkey, result) = joined.expect("witness submissions don't panic");
        match result {
            Ok(signature) => {
                signatures.push(signature);
                cosigned.push(vkey);
            }
            Err(error) => failed.push((vkey, error)),
        }
    }
    // Same order every time, whichever witness answered first.
    signatures.sort_by(|a, b| (&a.name, a.id).cmp(&(&b.name, b.id)));
    note.add(signatures);
    let stored = cosigned.len() >= config.quorum as usize;
    if stored {
        key_log::set_witnessed(&state.db, size, &note.encode()).await?;
    }
    Ok(Round {
        size,
        cosigned,
        failed,
        stored,
    })
}

async fn submit(
    state: &AppState,
    http: &reqwest::Client,
    witness: &KeyLogWitness,
    note: &note::Note,
    size: u64,
) -> Result<NoteSignature, WitnessError> {
    let verifier = Verifier::from_vkey(&witness.vkey).map_err(|_| WitnessError::BadCosignature)?;
    let known = key_log::witness_size(&state.db, &witness.vkey).await?;
    // A size beyond ours can't take a proof; asking from 0 makes the witness say what it holds.
    let mut old = known.filter(|known| *known <= size).unwrap_or(0);
    for _ in 0..3 {
        let proof = if old == 0 {
            Vec::new()
        } else {
            consistency(state, old, size).await?
        };
        let response = http
            .post(format!("{}/add-checkpoint", witness.url))
            .body(AddCheckpoint::encode(old, &proof, note))
            .send()
            .await?;
        let status = response.status().as_u16();
        let body = read_capped(response).await?;
        match status {
            200 => {
                let signatures =
                    NoteSignature::parse_lines(&body).map_err(|_| WitnessError::BadCosignature)?;
                let signature = signatures
                    .into_iter()
                    .find(|sig| sig.name == verifier.name && sig.id == verifier.id)
                    .ok_or(WitnessError::BadCosignature)?;
                verifier
                    .verify(&note.text, &signature)
                    .map_err(|_| WitnessError::BadCosignature)?;
                key_log::set_witness_size(&state.db, &witness.vkey, size).await?;
                return Ok(signature);
            }
            409 => {
                let theirs = note::decimal(body.trim_end_matches('\n'))
                    .map_err(|_| WitnessError::Refused { status, body })?;
                if theirs > size {
                    return Err(WitnessError::Ahead { theirs, ours: size });
                }
                key_log::set_witness_size(&state.db, &witness.vkey, theirs).await?;
                old = theirs;
            }
            _ => {
                let body: String = body.chars().take(200).collect();
                return Err(WitnessError::Refused { status, body });
            }
        }
    }
    Err(WitnessError::Conflicts)
}

async fn read_capped(mut response: reqwest::Response) -> Result<String, WitnessError> {
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        body.extend_from_slice(&chunk);
        if body.len() > MAX_RESPONSE {
            return Err(WitnessError::BadCosignature);
        }
    }
    Ok(String::from_utf8_lossy(&body).into_owned())
}

/// `octapass-server admin key-log`: what a witness operator needs, and how witnessing stands.
pub async fn describe(state: &AppState) -> Result<String, sqlx::Error> {
    let mut out = format!(
        "origin   {}\nvkey     {}\n",
        state.key_log.origin,
        state.key_log.vkey()
    );
    let size = key_log::size(&state.db).await?;
    out.push_str(&format!("entries  {size}\n"));
    let Some(config) = &state.config.key_log_witnesses else {
        out.push_str("witnesses none (OCTAPASS_KEY_LOG_WITNESSES isn't set)\n");
        return Ok(out);
    };
    out.push_str(&format!(
        "witnesses {} (quorum {})\n",
        config.witnesses.len(),
        config.quorum
    ));
    for witness in &config.witnesses {
        let known = key_log::witness_size(&state.db, &witness.vkey).await?;
        let known = known.map_or("never cosigned".to_owned(), |size| format!("at {size}"));
        out.push_str(&format!("  {} {} ({known})\n", witness.url, witness.vkey));
    }
    match key_log::witnessed(&state.db).await? {
        Some((size, _)) => out.push_str(&format!("witnessed checkpoint at {size}\n")),
        None => out.push_str("witnessed checkpoint none yet: clients aren't offered witnesses\n"),
    }
    Ok(out)
}

/// `octapass-server admin key-log witness`: one round now, reported.
pub async fn run_once(state: &AppState) -> Result<String, String> {
    let config = state
        .config
        .key_log_witnesses
        .as_ref()
        .ok_or("OCTAPASS_KEY_LOG_WITNESSES isn't set")?;
    let round = round(state, config).await.map_err(|e| e.to_string())?;
    let mut out = format!("checkpoint at {}\n", round.size);
    for vkey in &round.cosigned {
        out.push_str(&format!("  cosigned  {vkey}\n"));
    }
    for (vkey, error) in &round.failed {
        out.push_str(&format!("  failed    {vkey}: {error}\n"));
    }
    if round.stored {
        out.push_str("quorum reached: clients get this checkpoint\n");
        Ok(out)
    } else {
        Err(format!(
            "{out}only {} of the {} needed cosigned",
            round.cosigned.len(),
            config.quorum
        ))
    }
}
