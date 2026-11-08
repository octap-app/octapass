//! The witness over HTTP on 127.0.0.1, as a log would use it.

use std::sync::Arc;

use ed25519_dalek::SigningKey;
use octapass_core::transparency::merkle::{
    Frontier, Hash, consistency_ranges, fold_nodes, leaf_hash, range_nodes,
};
use octapass_core::transparency::note::{
    COSIGNATURE_V1, Checkpoint, Note, NoteSignature, Verifier, log_verifier, sign_checkpoint,
};
use octapass_core::transparency::witness::AddCheckpoint;
use octapass_witness::{Config, Witness, origin_hash_hex, router};

const ORIGIN: &str = "octapass-key-log/test";

/// A log in miniature: leaf `i` is 64 bytes of `seed + i`.
struct Log {
    key: SigningKey,
    seed: u8,
}

impl Log {
    fn leaf(&self, i: u64) -> Hash {
        leaf_hash(&[self.seed.wrapping_add(i as u8); 64])
    }

    fn hash(&self, range: std::ops::Range<u64>) -> Hash {
        let nodes: Vec<Hash> = range_nodes(range)
            .into_iter()
            .map(|node| {
                let start = node.index << node.level;
                let mut sub = Frontier::default();
                for i in start..start + (1 << node.level) {
                    sub.push(self.leaf(i));
                }
                sub.root()
            })
            .collect();
        fold_nodes(&nodes).unwrap_or_else(octapass_core::transparency::merkle::empty_root)
    }

    fn note(&self, size: u64) -> Note {
        let checkpoint = Checkpoint::new(ORIGIN, size, self.hash(0..size));
        Note {
            text: checkpoint.text(),
            signatures: vec![sign_checkpoint(&self.key, &checkpoint)],
        }
    }

    fn body(&self, old: u64, size: u64) -> String {
        let proof: Vec<Hash> = if old == 0 {
            Vec::new()
        } else {
            consistency_ranges(old, size)
                .into_iter()
                .map(|range| self.hash(range))
                .collect()
        };
        AddCheckpoint::encode(old, &proof, &self.note(size))
    }

    fn vkey(&self) -> String {
        log_verifier(ORIGIN, self.key.verifying_key()).vkey()
    }
}

struct Running {
    url: String,
    http: reqwest::Client,
    witness: Verifier,
    _dir: tempfile::TempDir,
}

fn open(dir: &std::path::Path, log: &Log) -> Witness {
    Witness::open(Config {
        name: "witness.test/w1".into(),
        key: SigningKey::from_bytes(&[7; 32]),
        logs: vec![log.vkey()],
        data_dir: dir.to_owned(),
    })
    .unwrap()
}

async fn serve(witness: Witness) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        axum::serve(listener, router(Arc::new(witness)))
            .await
            .unwrap();
    });
    url
}

async fn start(log: &Log) -> Running {
    let dir = tempfile::tempdir().unwrap();
    let url = serve(open(dir.path(), log)).await;
    Running {
        url,
        http: reqwest::Client::new(),
        witness: Verifier::new(
            "witness.test/w1",
            COSIGNATURE_V1,
            SigningKey::from_bytes(&[7; 32]).verifying_key(),
        )
        .unwrap(),
        _dir: dir,
    }
}

impl Running {
    async fn add(&self, body: String) -> (u16, String, String) {
        let response = self
            .http
            .post(format!("{}/add-checkpoint", self.url))
            .body(body)
            .send()
            .await
            .unwrap();
        let status = response.status().as_u16();
        let kind = response
            .headers()
            .get("content-type")
            .map(|v| v.to_str().unwrap().to_owned())
            .unwrap_or_default();
        (status, kind, response.text().await.unwrap())
    }
}

fn log() -> Log {
    Log {
        key: SigningKey::from_bytes(&[1; 32]),
        seed: 0,
    }
}

#[tokio::test]
async fn cosigns_a_log_that_grows_and_refuses_one_that_forks() {
    let log = log();
    let witness = start(&log).await;

    let (status, _, body) = witness.add(log.body(0, 3)).await;
    assert_eq!(status, 200, "{body}");
    let sigs = NoteSignature::parse_lines(&body).unwrap();
    assert_eq!(sigs.len(), 1);
    assert!(
        witness
            .witness
            .verify(&log.note(3).text, &sigs[0])
            .unwrap()
            .is_some()
    );

    // Wrong old size: 409 with the size it holds.
    let (status, kind, body) = witness.add(log.body(0, 5)).await;
    assert_eq!(
        (status, kind.as_str(), body.as_str()),
        (409, "text/x.tlog.size", "3\n")
    );

    let (status, _, _) = witness.add(log.body(3, 5)).await;
    assert_eq!(status, 200);
    // The same tree again is cosigned again (a fresh timestamp).
    let (status, _, _) = witness.add(log.body(5, 5)).await;
    assert_eq!(status, 200);

    // A fork of the same log: same key, other leaves.
    let fork = Log {
        key: SigningKey::from_bytes(&[1; 32]),
        seed: 50,
    };
    let (status, _, _) = witness.add(fork.body(5, 5)).await;
    assert_eq!(status, 422);
    let (status, _, _) = witness.add(fork.body(5, 8)).await;
    assert_eq!(status, 422);

    // Old size beyond the checkpoint.
    let (status, _, _) = witness
        .add(log.body(5, 4).replacen("old 5", "old 9", 1))
        .await;
    assert_eq!(status, 400);
}

#[tokio::test]
async fn refuses_unknown_logs_and_forged_checkpoints() {
    let log = log();
    let witness = start(&log).await;
    let stranger = Log {
        key: SigningKey::from_bytes(&[2; 32]),
        seed: 0,
    };
    // Signed by another key under the same origin: 403.
    let (status, _, _) = witness.add(stranger.body(0, 3)).await;
    assert_eq!(status, 403);

    // Another origin: 404.
    let checkpoint = Checkpoint::new("example.com/other", 1, log.hash(0..1));
    let note = Note {
        text: checkpoint.text(),
        signatures: vec![sign_checkpoint(&log.key, &checkpoint)],
    };
    let (status, _, _) = witness.add(AddCheckpoint::encode(0, &[], &note)).await;
    assert_eq!(status, 404);

    let (status, _, _) = witness.add("not a request".into()).await;
    assert_eq!(status, 400);
}

#[tokio::test]
async fn state_survives_a_restart_and_is_served_to_monitors() {
    let log = log();
    let dir = tempfile::tempdir().unwrap();
    let url = serve(open(dir.path(), &log)).await;
    let http = reqwest::Client::new();
    let response = http
        .post(format!("{url}/add-checkpoint"))
        .body(log.body(0, 4))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);

    // A second witness process on the same data: it remembers size 4.
    let url = serve(open(dir.path(), &log)).await;
    let response = http
        .post(format!("{url}/add-checkpoint"))
        .body(log.body(0, 6))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 409);
    assert_eq!(response.text().await.unwrap(), "4\n");

    let monitored = http
        .get(format!("{url}/{}/checkpoint", origin_hash_hex(ORIGIN)))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let note = Note::parse(&monitored).unwrap();
    assert_eq!(Checkpoint::parse(&note.text).unwrap().size, 4);
    assert_eq!(note.signatures.len(), 2);
    let missing = http
        .get(format!("{url}/{}/checkpoint", origin_hash_hex("nope")))
        .send()
        .await
        .unwrap();
    assert_eq!(missing.status(), 404);

    let index = http.get(&url).send().await.unwrap().text().await.unwrap();
    assert!(index.starts_with("witness.test/w1+"));
}

#[test]
fn configuration_is_checked() {
    let dir = tempfile::tempdir().unwrap();
    let config = |name: &str, logs: Vec<String>| Config {
        name: name.into(),
        key: SigningKey::from_bytes(&[7; 32]),
        logs,
        data_dir: dir.path().to_owned(),
    };
    assert!(Witness::open(config("bad name", vec![])).is_err());
    assert!(Witness::open(config("w", vec!["nope".into()])).is_err());
    let cosigner = Verifier::new(
        "x",
        COSIGNATURE_V1,
        SigningKey::from_bytes(&[3; 32]).verifying_key(),
    )
    .unwrap()
    .vkey();
    assert!(
        Witness::open(config("w", vec![cosigner])).is_err(),
        "a cosigner key isn't a log key"
    );
    assert!(Witness::open(config("w", vec![log().vkey(), log().vkey()])).is_err());
}

#[test]
fn the_key_is_made_once_and_kept() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("keys/witness.key");
    let first = octapass_witness::load_or_create_key(&path).unwrap();
    let again = octapass_witness::load_or_create_key(&path).unwrap();
    assert_eq!(first.to_bytes(), again.to_bytes());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    std::fs::write(&path, b"short").unwrap();
    assert!(octapass_witness::load_or_create_key(&path).is_err());
}
