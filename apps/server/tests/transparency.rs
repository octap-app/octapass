//! The key log end to end: real records, labels and proofs from `octapass-core`, checked the way
//! clients check them.

use crate::common;

use axum::http::{Method, StatusCode};
use common::people::{Person, grant_from_record, now_ms};
use common::*;
use octapass_core::encoding::b64_decode_array;
use octapass_core::sharing::Role;
use octapass_core::transparency::client::{KeyStatus, LabelProof, LogPage, LogState};
use octapass_core::transparency::label::{self, EvaluatedLabel};
use octapass_core::transparency::publish::PublishKeys;
use octapass_core::transparency::record::{KeyRecord, OfferedKeys};
use octapass_server::config::Bucket;
use rand_core::OsRng;
use serde_json::{Value, json};

/// A server that lets one test sign up many accounts from one address.
async fn roomy_server() -> TestServer {
    TestServer::with_config(|config| {
        config.rate_limits.per_ip = Bucket {
            burst: 10_000,
            refill: std::time::Duration::from_millis(1),
        };
    })
    .await
}

fn from<T: serde::de::DeserializeOwned>(body: &Value) -> T {
    serde_json::from_value(body.clone()).unwrap()
}

async fn pin(server: &TestServer, person: &Person, state: &mut LogState) {
    let head = server
        .get_as(
            person,
            &format!("/v1/transparency/head?since={}", state.pinned_size()),
        )
        .await;
    assert_eq!(head.status, StatusCode::OK, "{:?}", head.body);
    state.accept_head(&from(&head.body), now_ms()).unwrap();
}

async fn label_of(server: &TestServer, person: &Person, state: &LogState, email: &str) -> [u8; 32] {
    let blinded = label::blind(email, &mut OsRng).unwrap();
    let answer = server
        .send_as(
            person,
            Method::POST,
            "/v1/transparency/label",
            Some(json!({ "blinded": blinded.blinded })),
        )
        .await;
    assert_eq!(answer.status, StatusCode::OK, "{:?}", answer.body);
    let evaluated: EvaluatedLabel = from(&answer.body);
    let oprf_key = &state.log.as_ref().unwrap().oprf_key;
    label::finish(email, &blinded.state, &evaluated, oprf_key).unwrap()
}

async fn prepare(server: &TestServer, person: &Person, state: &mut LogState) -> PublishKeys {
    pin(server, person, state).await;
    let label = label_of(server, person, state, &person.email).await;
    let log_id = state.log.as_ref().unwrap().log_id_b64().unwrap();
    person
        .session
        .prepare_key_record(&log_id, &label, now_ms(), &mut OsRng)
        .unwrap()
}

async fn send_keys(server: &TestServer, person: &Person, keys: &PublishKeys) -> Response {
    let body = serde_json::to_value(keys).unwrap();
    server
        .send_as(person, Method::POST, "/v1/transparency/publish", Some(body))
        .await
}

/// What every client does after unlocking. Returns the record's leaf.
async fn publish(server: &TestServer, person: &mut Person) -> u64 {
    let mut state = LogState::default();
    let keys = prepare(server, person, &mut state).await;
    let published = send_keys(server, person, &keys).await;
    assert_eq!(published.status, StatusCode::OK, "{:?}", published.body);
    person.session.adopt_key_record(keys).unwrap();
    published.body["leafIndex"].as_u64().unwrap()
}

async fn proof(server: &TestServer, person: &Person, label: &str, since: u64) -> LabelProof {
    let path = format!("/v1/transparency/proof?label={label}&since={since}");
    let answer = server.get_as(person, &path).await;
    assert_eq!(answer.status, StatusCode::OK, "{:?}", answer.body);
    from(&answer.body)
}

async fn lookup(server: &TestServer, by: &Person, email: &str) -> Value {
    let found = server
        .get_as(by, &format!("/v1/accounts/lookup?email={email}"))
        .await;
    assert_eq!(found.status, StatusCode::OK, "{:?}", found.body);
    found.body
}

/// As a client does before sealing to `email`.
async fn verify(
    server: &TestServer,
    by: &Person,
    state: &mut LogState,
    email: &str,
) -> (Value, KeyStatus) {
    let found = lookup(server, by, email).await;
    pin(server, by, state).await;
    let label = octapass_core::encoding::b64_encode(&label_of(server, by, state, email).await);
    let answer = proof(server, by, &label, state.pinned_size()).await;
    let record: Option<KeyRecord> = found
        .get("keyRecord")
        .map(|record| serde_json::from_value(record.clone()).unwrap());
    let offered = OfferedKeys {
        account_id: found["accountId"].as_str().unwrap(),
        public_enc_key: found["publicEncKey"].as_str().unwrap(),
        public_sign_key: found["publicSignKey"].as_str().unwrap(),
    };
    let status = state
        .verify_account(&offered, record.as_ref(), &label, &answer, now_ms())
        .unwrap();
    (found, status)
}

#[tokio::test]
async fn a_published_key_verifies_and_a_hybrid_grant_opens() {
    let server = TestServer::new().await;
    let mut alice = server.person("alice@example.com").await;
    let mut bob = server.person("bob@example.com").await;
    publish(&server, &mut alice).await;
    let vault_id = server.shared_vault(&mut alice).await;

    // Bob hasn't published: nothing to check, and a version 1 grant.
    let mut state = LogState::default();
    let (_, status) = verify(&server, &alice, &mut state, &bob.email).await;
    assert_eq!(status, KeyStatus::NotLogged);
    let invited = server.invite(&alice, &vault_id, &bob, Role::Read).await;
    assert_eq!(invited.status, StatusCode::ACCEPTED);
    let record = server.vault_record(&bob, &vault_id).await.unwrap();
    let (classical, granter) = grant_from_record(&record, &bob.account_id);
    bob.session.open_shared_vault(&classical, &granter).unwrap();

    publish(&server, &mut bob).await;
    let (found, status) = verify(&server, &alice, &mut state, &bob.email).await;
    assert_eq!(status, KeyStatus::Verified);
    assert!(found["keyRecord"]["publicPqKey"].is_string());

    // A hybrid grant goes through the server's checks, and the old one still opens.
    let invited = server.invite(&alice, &vault_id, &bob, Role::Write).await;
    assert_eq!(invited.status, StatusCode::ACCEPTED, "{:?}", invited.body);
    let record = server.vault_record(&bob, &vault_id).await.unwrap();
    let (hybrid, granter) = grant_from_record(&record, &bob.account_id);
    assert_ne!(
        hybrid.wrapped_vault_key.len(),
        classical.wrapped_vault_key.len()
    );
    bob.session.open_shared_vault(&hybrid, &granter).unwrap();
    bob.session.open_shared_vault(&classical, &granter).unwrap();
}

#[tokio::test]
async fn the_account_bundle_carries_the_key_to_other_devices() {
    let server = TestServer::new().await;
    let mut alice = server.person("alice@example.com").await;
    publish(&server, &mut alice).await;
    let account = server.get_as(&alice, "/v1/account").await;
    assert_eq!(account.status, StatusCode::OK);
    assert!(account.body["wrappedPqPrivateKey"].is_string());
    assert_eq!(
        account.body["keyRecord"]["publicPqKey"],
        alice.session.pq_keys().unwrap().public_key().to_b64()
    );
}

#[tokio::test]
async fn a_second_record_is_refused_and_the_same_one_answers_the_same() {
    let server = TestServer::new().await;
    let mut alice = server.person("alice@example.com").await;
    let mut state = LogState::default();
    let first = prepare(&server, &alice, &mut state).await;
    let second = prepare(&server, &alice, &mut state).await;

    let published = send_keys(&server, &alice, &first).await;
    let index = published.body["leafIndex"].as_u64().unwrap();
    let again = send_keys(&server, &alice, &first).await;
    assert_eq!(again.status, StatusCode::OK);
    assert_eq!(again.body["leafIndex"].as_u64(), Some(index));
    let raced = send_keys(&server, &alice, &second).await;
    assert_eq!(raced.status, StatusCode::CONFLICT);
    assert!(raced.is_problem("already-exists"));
    alice.session.adopt_key_record(first).unwrap();
}

#[tokio::test]
async fn records_that_are_not_the_accounts_own_are_refused() {
    let server = TestServer::new().await;
    let alice = server.person("alice@example.com").await;
    let bob = server.person("bob@example.com").await;
    let mut state = LogState::default();
    let good = prepare(&server, &alice, &mut state).await;

    // Bob's device sends Alice's record.
    assert_eq!(
        send_keys(&server, &bob, &good).await.status,
        StatusCode::BAD_REQUEST
    );

    // Under another email's label.
    let other = label_of(&server, &alice, &state, &bob.email).await;
    let log_id = state.log.as_ref().unwrap().log_id_b64().unwrap();
    let wrong_label = alice
        .session
        .prepare_key_record(&log_id, &other, now_ms(), &mut OsRng)
        .unwrap();
    assert_eq!(
        send_keys(&server, &alice, &wrong_label).await.status,
        StatusCode::BAD_REQUEST
    );

    // For another log.
    let mine: [u8; 32] = b64_decode_array(&good.record.label).unwrap();
    let wrong_log = alice
        .session
        .prepare_key_record(&b64([9u8; 32]), &mine, now_ms(), &mut OsRng)
        .unwrap();
    assert_eq!(
        send_keys(&server, &alice, &wrong_log).await.status,
        StatusCode::BAD_REQUEST
    );

    // With a changed field, so the signature no longer covers it.
    let mut forged = good.clone();
    forged.record.created_at += 1;
    assert_eq!(
        send_keys(&server, &alice, &forged).await.status,
        StatusCode::BAD_REQUEST
    );
    let empty = server.get_as(&alice, "/v1/transparency/head").await;
    assert_eq!(empty.body["head"]["treeSize"], 0);
}

#[tokio::test]
async fn heads_stay_consistent_as_the_log_grows() {
    let server = roomy_server().await;
    let mut watcher = server.person("watcher@example.com").await;
    let mut state = LogState::default();
    pin(&server, &watcher, &mut state).await;
    publish(&server, &mut watcher).await;
    for i in 0..9 {
        let mut person = server.person(&format!("p{i}@example.com")).await;
        publish(&server, &mut person).await;
        pin(&server, &watcher, &mut state).await;
        assert_eq!(state.pinned_size(), i + 2);
    }
    assert_eq!(state.alert, None);
}

async fn scan(server: &TestServer, person: &Person, state: &mut LogState) {
    while let Some((start, end)) = state.scan_range() {
        let path = format!("/v1/transparency/entries?start={start}&end={end}");
        let page = server.get_as(person, &path).await;
        assert_eq!(page.status, StatusCode::OK, "{:?}", page.body);
        let page: LogPage = from(&page.body);
        state.apply_page(&page, now_ms()).unwrap();
    }
}

#[tokio::test]
async fn a_monitor_reads_the_log_and_finds_only_its_own_record() {
    let server = roomy_server().await;
    for i in 0..3 {
        let mut early = server.person(&format!("early{i}@example.com")).await;
        publish(&server, &mut early).await;
    }
    let mut alice = server.person("alice@example.com").await;
    let index = publish(&server, &mut alice).await;
    assert_eq!(index, 3);
    let record = alice.session.bundle().key_record.clone().unwrap();

    let mut state = LogState::default();
    let answer = proof(&server, &alice, &record.label, 0).await;
    state.check_own(&record, &answer, now_ms()).unwrap();
    scan(&server, &alice, &mut state).await;
    assert_eq!(state.alert, None);

    for i in 0..4 {
        let mut late = server.person(&format!("late{i}@example.com")).await;
        publish(&server, &mut late).await;
    }
    let answer = proof(&server, &alice, &record.label, state.pinned_size()).await;
    state.check_own(&record, &answer, now_ms()).unwrap();
    assert_eq!(state.scan_range(), Some((4, 8)));
    scan(&server, &alice, &mut state).await;
    assert_eq!(state.alert, None);
    assert_ne!(state.checked_at, 0);
}

#[tokio::test]
async fn pages_stay_inside_the_log() {
    let server = TestServer::new().await;
    let mut alice = server.person("alice@example.com").await;
    publish(&server, &mut alice).await;
    let beyond = server
        .get_as(&alice, "/v1/transparency/entries?start=0&end=2")
        .await;
    assert_eq!(beyond.status, StatusCode::BAD_REQUEST);
    let reversed = server
        .get_as(&alice, "/v1/transparency/entries?start=1&end=0")
        .await;
    assert_eq!(reversed.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn deleting_an_account_keeps_the_leaf_and_drops_the_record() {
    let server = TestServer::new().await;
    let mut alice = server.person("alice@example.com").await;
    let mut bob = server.person("bob@example.com").await;
    publish(&server, &mut bob).await;
    publish(&server, &mut alice).await;
    let label = alice.session.bundle().key_record.clone().unwrap().label;

    let mut state = LogState::default();
    pin(&server, &bob, &mut state).await;
    let device = server.login(&bob.email, "Phone").await;
    let reauth = reauth_token(&server, &device).await;
    assert_eq!(
        delete_account(&server, &device, Some(&reauth), &bob.email)
            .await
            .status,
        StatusCode::NO_CONTENT
    );

    let answer = proof(&server, &alice, &label, state.pinned_size()).await;
    state.accept_head(&answer.update, now_ms()).unwrap();
    assert_eq!(state.pinned_size(), 2, "leaves are never removed");
    let leaves = server
        .get_as(&alice, "/v1/transparency/entries?start=0&end=2")
        .await;
    assert_eq!(leaves.status, StatusCode::OK);
    let answer = proof(&server, &alice, &label, 2).await;
    assert_eq!(answer.entry.unwrap().leaf_index, 1);
}

#[tokio::test]
async fn labels_are_rate_limited_per_account() {
    let server = TestServer::with_config(|config| {
        config.rate_limits.key_log_label_per_account = Bucket {
            burst: 2,
            refill: std::time::Duration::from_secs(3600),
        };
    })
    .await;
    let alice = server.person("alice@example.com").await;
    let mut limited = None;
    for _ in 0..3 {
        let blinded = label::blind("someone@example.com", &mut OsRng).unwrap();
        let answer = server
            .send_as(
                &alice,
                Method::POST,
                "/v1/transparency/label",
                Some(json!({ "blinded": blinded.blinded })),
            )
            .await;
        limited = Some(answer.status);
    }
    assert_eq!(limited, Some(StatusCode::TOO_MANY_REQUESTS));
}

#[tokio::test]
async fn the_log_needs_a_signed_in_account() {
    let server = TestServer::new().await;
    for path in [
        "/v1/transparency/head",
        "/v1/transparency/entries?start=0&end=0",
    ] {
        assert_eq!(
            server.get(path, "not-a-token").await.status,
            StatusCode::UNAUTHORIZED
        );
    }
}

/// Witnesses (plan 03, "Witnesses"): real `octapass-witness` instances on 127.0.0.1, the server
/// sending them checkpoints, and clients holding the log to what they cosigned.
mod witnesses {
    use std::sync::Arc;

    use ed25519_dalek::SigningKey;
    use octapass_core::transparency::head::LogIdentity;
    use octapass_core::transparency::note::{COSIGNATURE_V1, Verifier};
    use octapass_core::transparency::witness;
    use octapass_server::config::{KeyLogWitness, KeyLogWitnesses};
    use octapass_server::key_log_witnesses::{WitnessError, round};

    use super::*;

    fn witness_vkey(seed: u8) -> String {
        let key = SigningKey::from_bytes(&[seed; 32]).verifying_key();
        Verifier::new(&format!("witness.test/{seed}"), COSIGNATURE_V1, key)
            .unwrap()
            .vkey()
    }

    struct Witnesses {
        listeners: Vec<tokio::net::TcpListener>,
        dirs: Vec<tempfile::TempDir>,
    }

    /// Two live witnesses (seeds 1 and 2) and a third (3) whose port is closed, quorum 2.
    async fn server_with_witnesses() -> (TestServer, Witnesses) {
        let mut listeners = Vec::new();
        for _ in 0..2 {
            listeners.push(tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap());
        }
        // Port 1: nothing listens there, and unlike a freed ephemeral port another test running
        // at the same time can't be given it.
        let closed_url = "http://127.0.0.1:1".to_owned();
        let mut witnesses: Vec<KeyLogWitness> = listeners
            .iter()
            .zip([1u8, 2])
            .map(|(listener, seed)| KeyLogWitness {
                url: format!("http://{}", listener.local_addr().unwrap()),
                vkey: witness_vkey(seed),
            })
            .collect();
        witnesses.push(KeyLogWitness {
            url: closed_url,
            vkey: witness_vkey(3),
        });
        let server = TestServer::with_config(|config| {
            config.rate_limits.per_ip = Bucket {
                burst: 10_000,
                refill: std::time::Duration::from_millis(1),
            };
            config.key_log_witnesses = Some(KeyLogWitnesses {
                witnesses,
                quorum: 2,
                interval: std::time::Duration::from_secs(600),
            });
        })
        .await;
        (
            server,
            Witnesses {
                listeners,
                dirs: Vec::new(),
            },
        )
    }

    /// Starts the witnesses for this server's log, which they learn the way an operator would:
    /// from its verifier key.
    async fn start(server: &TestServer, person: &Person, witnesses: &mut Witnesses) {
        let head = server.get_as(person, "/v1/transparency/head").await;
        let log: LogIdentity = from(&head.body["log"]);
        let log_vkey = witness::log_verifier(&log).unwrap().vkey();
        for (listener, seed) in witnesses.listeners.drain(..).zip([1u8, 2]) {
            let dir = tempfile::tempdir().unwrap();
            let witness = octapass_witness::Witness::open(octapass_witness::Config {
                name: format!("witness.test/{seed}"),
                key: SigningKey::from_bytes(&[seed; 32]),
                logs: vec![log_vkey.clone()],
                data_dir: dir.path().to_owned(),
            })
            .unwrap();
            witnesses.dirs.push(dir);
            tokio::spawn(async move {
                axum::serve(listener, octapass_witness::router(Arc::new(witness)))
                    .await
                    .unwrap();
            });
        }
    }

    fn config(server: &TestServer) -> &KeyLogWitnesses {
        server.state.config.key_log_witnesses.as_ref().unwrap()
    }

    #[tokio::test]
    async fn clients_pin_the_witnesses_and_check_every_head_against_them() {
        let (server, mut witnesses) = server_with_witnesses().await;
        let mut alice = server.person("alice@example.com").await;
        let mut bob = server.person("bob@example.com").await;

        // Before any witness has cosigned, clients aren't offered witnesses at all.
        let head = server.get_as(&alice, "/v1/transparency/head").await;
        assert!(head.body.get("witnesses").is_none(), "{:?}", head.body);
        publish(&server, &mut alice).await;

        start(&server, &alice, &mut witnesses).await;
        let first = round(&server.state, config(&server)).await.unwrap();
        assert_eq!(
            (first.size, first.cosigned.len(), first.stored),
            (1, 2, true)
        );
        assert!(
            matches!(first.failed.as_slice(), [(vkey, WitnessError::Http(_))] if *vkey == witness_vkey(3)),
            "{:?}",
            first.failed
        );

        let mut state = LogState::default();
        pin(&server, &alice, &mut state).await;
        let pinned = state.witnesses.clone().unwrap();
        assert_eq!(pinned.quorum, 2);
        assert_eq!(pinned.witnesses.len(), 3);

        // Bob's record goes in after the witnessed checkpoint: the head extends it, with a proof.
        publish(&server, &mut bob).await;
        let (_, status) = verify(&server, &alice, &mut state, &bob.email).await;
        assert_eq!(status, KeyStatus::Verified);
        let head = server.get_as(&alice, "/v1/transparency/head?since=0").await;
        assert_eq!(head.body["head"]["treeSize"], 2);
        assert!(
            head.body["witnessed"]["checkpoint"]
                .as_str()
                .unwrap()
                .contains("\n1\n")
        );

        // The next round extends what each witness cosigned.
        let second = round(&server.state, config(&server)).await.unwrap();
        assert_eq!((second.size, second.cosigned.len()), (2, 2));
        pin(&server, &alice, &mut state).await;
    }

    #[tokio::test]
    async fn a_server_that_forgot_what_its_witnesses_hold_catches_up() {
        let (server, mut witnesses) = server_with_witnesses().await;
        let mut alice = server.person("alice@example.com").await;
        publish(&server, &mut alice).await;
        start(&server, &alice, &mut witnesses).await;
        round(&server.state, config(&server)).await.unwrap();
        let mut bob = server.person("bob@example.com").await;
        publish(&server, &mut bob).await;

        // As after restoring a database without this table's rows: the witnesses answer 409 with
        // the size they hold, and the server sends the right proof from there.
        sqlx::query("DELETE FROM key_log_witness_sizes")
            .execute(&server.state.db)
            .await
            .unwrap();
        let caught_up = round(&server.state, config(&server)).await.unwrap();
        assert_eq!((caught_up.size, caught_up.cosigned.len()), (2, 2));
    }

    #[tokio::test]
    async fn without_a_quorum_clients_keep_the_last_witnessed_checkpoint() {
        let (server, mut witnesses) = server_with_witnesses().await;
        let mut alice = server.person("alice@example.com").await;
        publish(&server, &mut alice).await;
        // Only witness 1 runs; 2 and 3 can't be reached: no quorum, nothing offered.
        witnesses.listeners.truncate(1);
        start(&server, &alice, &mut witnesses).await;
        let lonely = round(&server.state, config(&server)).await.unwrap();
        assert_eq!((lonely.cosigned.len(), lonely.stored), (1, false));
        let head = server.get_as(&alice, "/v1/transparency/head").await;
        assert!(head.body.get("witnesses").is_none());
        assert!(head.body.get("witnessed").is_none());
    }
}
