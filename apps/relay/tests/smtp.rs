//! The relay end to end: real SMTP in, real SMTP out, real SPF, DKIM and DMARC checks over fixed
//! DNS answers.

mod common;

use std::sync::Arc;

use common::{ACCOUNT, Answer, Client, DOMAIN, Harness, HostMode, SENDER, USER, at, plain};
use mail_auth::crypto::{RsaKey, Sha256};
use mail_auth::dkim::DkimSigner;
use mail_auth::headers::HeaderWriter;
use mail_auth::{AuthenticatedMessage, DkimResult};
use octapass_relay::auth::Peer;
use octapass_relay::db::Alias;
use octapass_relay::pipeline::{LOOP, NO_SUCH_RECIPIENT};
use octapass_relay::smtp::command::ReversePath;
use octapass_relay::srs::{self, Kind};
use rustls_pki_types::PrivateKeyDer;
use rustls_pki_types::pem::PemObject;
use tokio::net::TcpStream;

fn refused(answer: &Answer, code: u16) {
    assert_eq!(answer.code, code, "{answer:?}");
}

fn srs_address(harness: &Harness, kind: Kind, alias: &Alias) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    at(&srs::encode(
        &harness.running.relay.keys,
        kind,
        &alias.local,
        now,
    ))
}

fn header_value(message: &str, name: &str) -> Option<String> {
    let head = message.split("\r\n\r\n").next().unwrap();
    head.split("\r\n")
        .find_map(|line| line.strip_prefix(&format!("{name}: ")).map(str::to_owned))
}

#[tokio::test]
async fn a_message_to_an_alias_reaches_the_mailbox_rewritten_and_signed() {
    let harness = Harness::start().await;
    let alias = harness.alias().await;
    let to = at(&alias.local);
    let message = format!(
        "From: Jane Doe <{SENDER}>\r\n\
         To: {to}\r\n\
         Cc: friend@sender.example\r\n\
         Subject: The plan\r\n\
         Date: Mon, 2 Nov 2026 10:00:00 +0000\r\n\
         Message-ID: <1@sender.example>\r\n\
         Disposition-Notification-To: {SENDER}\r\n\
         \r\n\
         Secret plan: .dots stay\r\n\
         .a line starting with a dot\r\n"
    );
    let answer = harness.send(SENDER, &to, &message).await;
    assert_eq!(answer.code, 250, "{answer:?}");

    let sent = harness.sent();
    assert_eq!(sent.len(), 1);
    let out = &sent[0];
    assert_eq!(out.to, USER);
    assert!(out.from.starts_with("srs0="), "{}", out.from);
    assert!(out.from.ends_with(&format!("@{DOMAIN}")), "{}", out.from);
    assert!(
        !out.from.contains("jane"),
        "the return path holds no sender: {}",
        out.from
    );

    let text = out.text();
    let reverse = harness
        .running
        .relay
        .store()
        .contact(&alias.local, SENDER, 10)
        .await
        .unwrap()
        .unwrap();
    let reverse = at(&reverse);
    assert_eq!(
        header_value(&text, "From").as_deref(),
        Some(format!("\"Jane Doe\" <{reverse}>").as_str())
    );
    assert_eq!(
        header_value(&text, "Reply-To").as_deref(),
        Some(format!("<{reverse}>").as_str())
    );
    assert_eq!(
        header_value(&text, "To").as_deref(),
        Some(format!("<{to}>").as_str())
    );
    assert_eq!(
        header_value(&text, "X-Original-From").as_deref(),
        Some(format!("<{SENDER}>").as_str())
    );
    assert_eq!(header_value(&text, "Cc"), None);
    assert_eq!(header_value(&text, "Disposition-Notification-To"), None);
    assert!(
        text.contains("Authentication-Results: mx.relay.example"),
        "{text}"
    );
    assert!(text.contains("spf=pass"), "{text}");
    assert!(text.contains("dmarc=pass"), "{text}");
    assert!(
        // Stuffed on the way in and out, unstuffed at each end: the line is unchanged.
        text.ends_with("\r\n\r\nSecret plan: .dots stay\r\n.a line starting with a dot\r\n"),
        "the body arrives as written: {text}"
    );
    assert!(text.contains("ARC-Seal: i=1;"), "{text}");

    // The relay's DKIM signature verifies with the real verifier, with the key in DNS.
    let parsed = AuthenticatedMessage::parse(&out.data).unwrap();
    let checked = harness
        .running
        .relay
        .verifier
        .check(
            &parsed,
            &Peer {
                ip: "127.0.0.1".parse().unwrap(),
                helo: "mx.relay.example",
                mail_from: &ReversePath::Null,
            },
        )
        .await;
    assert!(
        checked.dkim.iter().any(
            |d| d.result() == &DkimResult::Pass && d.signature().is_some_and(|s| s.d == DOMAIN)
        ),
        "the relay's signature verifies"
    );
    assert!(checked.aligned_with(DOMAIN));

    let stored = harness
        .running
        .relay
        .store()
        .alias(&alias.local)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.forwarded, 1);
}

#[tokio::test]
async fn nothing_about_a_message_reaches_the_database_file() {
    let harness = Harness::start().await;
    let alias = harness.alias().await;
    let to = at(&alias.local);
    let answer = harness
        .send(
            SENDER,
            &to,
            &plain(SENDER, &to, "Unmistakable-subject-words"),
        )
        .await;
    assert_eq!(answer.code, 250, "{answer:?}");
    harness.running.relay.db.close().await;
    for entry in std::fs::read_dir(harness.dir.path()).unwrap() {
        let bytes = std::fs::read(entry.unwrap().path()).unwrap();
        let text = String::from_utf8_lossy(&bytes);
        for private in ["Unmistakable-subject-words", "Hello there", SENDER, USER] {
            assert!(!text.contains(private), "{private} is on disk");
        }
    }
}

#[tokio::test]
async fn replies_go_out_from_the_alias_with_the_user_scrubbed() {
    let harness = Harness::start().await;
    let alias = harness.alias().await;
    let reverse = harness.first_contact(&alias, SENDER).await;
    let reply = format!(
        "Received: from laptop.home ([203.0.113.9]) by mail.example\r\n\
         From: Real Person <{USER}>\r\n\
         To: <{reverse}>\r\n\
         Subject: Re: Hello\r\n\
         Date: Mon, 2 Nov 2026 13:00:00 +0300\r\n\
         Message-ID: <reply@laptop.home>\r\n\
         In-Reply-To: <1@x.example>\r\n\
         User-Agent: Thunderbird/128\r\n\
         X-Originating-IP: [203.0.113.9]\r\n\
         DKIM-Signature: v=1; a=rsa-sha256; d=mail.example; s=x; h=from; bh=x; b=x\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\
         \r\n\
         Thanks!\r\n"
    );
    let answer = harness.send(USER, &reverse, &reply).await;
    assert_eq!(answer.code, 250, "{answer:?}");

    let sent = harness.sent();
    assert_eq!(sent.len(), 2);
    let out = &sent[1];
    assert_eq!(out.to, SENDER);
    assert!(out.from.starts_with("srs0="), "{}", out.from);
    assert!(out.from.contains("=r="), "marked as a reply: {}", out.from);
    let text = out.text();
    assert_eq!(
        header_value(&text, "From").as_deref(),
        Some(format!("<{}>", at(&alias.local)).as_str())
    );
    assert_eq!(
        header_value(&text, "To").as_deref(),
        Some(format!("<{SENDER}>").as_str())
    );
    assert_eq!(header_value(&text, "Subject").as_deref(), Some("Re: Hello"));
    assert_eq!(
        header_value(&text, "In-Reply-To").as_deref(),
        Some("<1@x.example>")
    );
    assert!(text.ends_with("\r\n\r\nThanks!\r\n"), "{text}");
    for leak in [
        USER,
        "Real Person",
        "laptop.home",
        "203.0.113.9",
        "Thunderbird",
        "X-Originating-IP",
        "Received:",
        "d=mail.example",
        "+0300",
    ] {
        assert!(!text.contains(leak), "{leak} leaked: {text}");
    }
    assert!(
        text.contains(&format!("d={DOMAIN}")),
        "signed by the relay: {text}"
    );
    let stored = harness
        .running
        .relay
        .store()
        .alias(&alias.local)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.replied, 1);
}

#[tokio::test]
async fn a_reply_proved_by_dkim_alone_passes_and_an_unproved_one_does_not() {
    let harness = Harness::start().await;
    let store = harness.running.relay.store();
    store
        .sync_account(ACCOUNT, "me@dkim.example")
        .await
        .unwrap();
    let alias = store
        .create_alias(ACCOUNT, &harness.running.relay.config.limits)
        .await
        .unwrap();
    let reverse = harness.first_contact(&alias, SENDER).await;
    let message = format!(
        "From: <me@dkim.example>\r\nTo: <{reverse}>\r\nSubject: Re\r\n\
         Date: Mon, 2 Nov 2026 13:00:00 +0300\r\nMessage-ID: <2@dkim.example>\r\n\r\nYes\r\n"
    );

    // The domain's SPF doesn't list this machine, and nothing is signed.
    let answer = harness.send("me@dkim.example", &reverse, &message).await;
    refused(&answer, 550);
    assert_eq!(harness.sent().len(), 1, "nothing went out");

    let key = RsaKey::<Sha256>::from_key_der(
        PrivateKeyDer::from_pem_slice(common::SENDER_DKIM_KEY.as_bytes()).unwrap(),
    )
    .unwrap();
    let signature = DkimSigner::from_key(key)
        .domain("dkim.example")
        .selector("key")
        .headers(["From", "To", "Subject"])
        .sign(message.as_bytes())
        .unwrap();
    let signed = format!("{}{message}", signature.to_header());
    let answer = harness.send("me@dkim.example", &reverse, &signed).await;
    assert_eq!(answer.code, 250, "{answer:?}");
    assert_eq!(harness.sent().len(), 2);
}

#[tokio::test]
async fn only_the_owner_can_use_a_reverse_alias() {
    let harness = Harness::start().await;
    let alias = harness.alias().await;
    let reverse = harness.first_contact(&alias, SENDER).await;

    // A stranger, and the original sender, get the same refusal as an address that doesn't exist.
    for stranger in ["stranger@sender.example", SENDER] {
        let answer = harness
            .send(stranger, &reverse, &plain(stranger, &reverse, "Hi"))
            .await;
        refused(&answer, 550);
        assert_eq!(answer.text, format!("5.1.1 {}", NO_SUCH_RECIPIENT.text));
    }
    let made_up = at("r-abcdefghijklmnopqrstuvwxyz");
    let answer = harness
        .send(USER, &made_up, &plain(USER, &made_up, "Hi"))
        .await;
    refused(&answer, 550);

    // The owner's address in the envelope, written by someone else: SPF fails at the end of DATA.
    let forged = "real.person@strict.example";
    let store = harness.running.relay.store();
    store.sync_account("account-2", forged).await.unwrap();
    let their_alias = store
        .create_alias("account-2", &harness.running.relay.config.limits)
        .await
        .unwrap();
    let their_reverse = harness.first_contact(&their_alias, SENDER).await;
    let answer = harness
        .send(forged, &their_reverse, &plain(forged, &their_reverse, "Hi"))
        .await;
    refused(&answer, 550);

    // The envelope is the owner's but the From header isn't.
    let message = plain("someone@mail.example", &reverse, "Hi");
    let answer = harness.send(USER, &reverse, &message).await;
    refused(&answer, 550);

    let out = harness.sent();
    assert_eq!(out.len(), 2, "only the two first contacts went anywhere");
    assert!(out.iter().all(|sent| sent.to == USER || sent.to == forged));
}

#[tokio::test]
async fn disabled_and_blocked_look_exactly_like_nothing_there() {
    let harness = Harness::start().await;
    let alias = harness.alias().await;
    let to = at(&alias.local);
    let unknown = at("abcdefghijkl");
    let baseline = harness
        .send(SENDER, &unknown, &plain(SENDER, &unknown, "x"))
        .await;
    refused(&baseline, 550);

    let store = harness.running.relay.store();
    assert!(
        store
            .set_enabled(ACCOUNT, &alias.local, false)
            .await
            .unwrap()
    );
    let disabled = harness.send(SENDER, &to, &plain(SENDER, &to, "x")).await;
    assert_eq!(disabled, baseline, "a disabled alias says nothing more");

    assert!(
        store
            .set_enabled(ACCOUNT, &alias.local, true)
            .await
            .unwrap()
    );
    assert!(
        store
            .set_blocked(ACCOUNT, &alias.local, SENDER, true)
            .await
            .unwrap()
    );
    let blocked = harness.send(SENDER, &to, &plain(SENDER, &to, "x")).await;
    assert_eq!(blocked, baseline, "a block says nothing more");
    assert_eq!(store.alias(&alias.local).await.unwrap().unwrap().blocked, 1);

    // The same sender in the From header only, with another envelope.
    let other = "other@sender.example";
    let answer = harness.send(other, &to, &plain(SENDER, &to, "x")).await;
    refused(&answer, 550);

    assert!(
        store
            .set_blocked(ACCOUNT, &alias.local, SENDER, false)
            .await
            .unwrap()
    );
    let answer = harness.send(SENDER, &to, &plain(SENDER, &to, "x")).await;
    assert_eq!(answer.code, 250, "{answer:?}");
    assert_eq!(harness.sent().len(), 1);

    assert!(store.delete_alias(ACCOUNT, &alias.local).await.unwrap());
    let gone = harness.send(SENDER, &to, &plain(SENDER, &to, "x")).await;
    assert_eq!(gone, baseline);
}

#[tokio::test]
async fn bounces_are_counted_never_forwarded_and_pause_with_one_notice() {
    let harness = Harness::start().await;
    let alias = harness.alias().await;
    let reverse = harness.first_contact(&alias, SENDER).await;
    let path = srs_address(&harness, Kind::Forward, &alias);
    let to = at(&alias.local);
    let before = harness.sent().len();

    // A temporary problem counts as nothing that pauses.
    for _ in 0..5 {
        let answer = harness
            .send("", &path, &common::dsn("delayed", "4.4.1"))
            .await;
        assert_eq!(answer.code, 250, "{answer:?}");
    }
    // Refused for its content: says nothing about the mailbox.
    let answer = harness
        .send("", &path, &common::dsn("failed", "5.7.1"))
        .await;
    assert_eq!(answer.code, 250, "{answer:?}");
    assert_eq!(harness.sent().len(), before, "nothing was passed on");
    let answer = harness
        .send(SENDER, &to, &plain(SENDER, &to, "still on"))
        .await;
    assert_eq!(answer.code, 250, "{answer:?}");
    let before = harness.sent().len();

    for _ in 0..2 {
        harness
            .send("", &path, &common::dsn("failed", "5.1.1"))
            .await;
    }
    assert_eq!(harness.sent().len(), before, "not at the limit yet");
    harness
        .send("", &path, &common::dsn("failed", "5.1.1"))
        .await;
    let sent = harness.sent();
    assert_eq!(sent.len(), before + 1, "the notice");
    let notice = sent.last().unwrap();
    assert_eq!(notice.to, USER);
    assert_eq!(notice.from, "", "a notice can't bounce");
    let text = notice.text();
    assert!(text.contains(&to), "{text}");
    assert!(text.contains("Auto-Submitted: auto-generated"), "{text}");
    assert!(text.contains(&format!("d={DOMAIN}")), "signed: {text}");
    assert!(!text.contains(SENDER), "{text}");

    // More bounces, no more notices.
    for _ in 0..3 {
        harness
            .send("", &path, &common::dsn("failed", "5.1.1"))
            .await;
    }
    assert_eq!(harness.sent().len(), before + 1, "one notice per pause");

    // It reads as gone to senders, and the user's replies stop too.
    let unknown = at("abcdefghijkl");
    let baseline = harness
        .send(SENDER, &unknown, &plain(SENDER, &unknown, "x"))
        .await;
    assert_eq!(
        harness.send(SENDER, &to, &plain(SENDER, &to, "x")).await,
        baseline
    );
    refused(
        &harness
            .send(USER, &reverse, &plain(USER, &reverse, "x"))
            .await,
        550,
    );

    // Turning it back on clears the pause.
    let store = harness.running.relay.store();
    assert!(
        store
            .set_enabled(ACCOUNT, &alias.local, true)
            .await
            .unwrap()
    );
    let answer = harness.send(SENDER, &to, &plain(SENDER, &to, "back")).await;
    assert_eq!(answer.code, 250, "{answer:?}");
}

#[tokio::test]
async fn invalid_return_paths_are_refused() {
    let harness = Harness::start().await;
    let alias = harness.alias().await;
    let good = srs_address(&harness, Kind::Forward, &alias);
    let tampered = good.replace(&alias.local, "zzzzzzzzzzzz");
    let other_key = srs::encode(
        &octapass_relay::keys::Keys::derive(&[1; 32]),
        Kind::Forward,
        &alias.local,
        1_793_000_000,
    );
    for path in [
        tampered,
        at(&other_key),
        at("srs0=aaaaaaaaaa=aa=f=abcdefghijkl"),
        at("srs0=broken"),
    ] {
        let answer = harness
            .send("", &path, &common::dsn("failed", "5.1.1"))
            .await;
        refused(&answer, 550);
    }
    assert!(
        harness.sent().is_empty(),
        "nothing goes out, so nothing can backscatter"
    );
    let stored = harness
        .running
        .relay
        .store()
        .alias(&alias.local)
        .await
        .unwrap()
        .unwrap();
    assert!(stored.forwards());
}

#[tokio::test]
async fn complaints_pause_too_and_can_arrive_at_abuse() {
    let harness = Harness::with(|config| {
        config.operator =
            Some(octapass_relay::address::Address::parse("ops@operator.example").unwrap());
    })
    .await;
    let alias = harness.alias().await;
    let path = srs_address(&harness, Kind::Forward, &alias);
    let local = path.split('@').next().unwrap().to_owned();
    for _ in 0..2 {
        let answer = harness
            .send("fbl@mail.example", &path, &common::abuse_report(&path))
            .await;
        assert_eq!(answer.code, 250, "{answer:?}");
    }
    let abuse = at("abuse");
    let answer = harness
        .send(
            "fbl@mail.example",
            &abuse,
            &common::abuse_report(&format!("{local}@{DOMAIN}")),
        )
        .await;
    assert_eq!(answer.code, 250, "{answer:?}");
    let sent = harness.sent();
    assert_eq!(
        sent.len(),
        2,
        "the notice and the operator's copy: {sent:?}"
    );
    assert!(
        sent.iter()
            .any(|s| s.to == USER && s.text().contains("masked email"))
    );
    let copy = sent
        .iter()
        .find(|s| s.to == "ops@operator.example")
        .unwrap();
    assert_eq!(copy.from, "");
    let stored = harness
        .running
        .relay
        .store()
        .alias(&alias.local)
        .await
        .unwrap()
        .unwrap();
    assert!(stored.paused);
}

#[tokio::test]
async fn too_many_bounces_across_aliases_pause_the_account() {
    let harness = Harness::start().await;
    let aliases = [
        harness.alias().await,
        harness.alias().await,
        harness.alias().await,
        harness.alias().await,
    ];
    let mut bounced = 0;
    for alias in &aliases {
        let path = srs_address(&harness, Kind::Forward, alias);
        for _ in 0..3 {
            harness
                .send("", &path, &common::dsn("failed", "5.1.1"))
                .await;
            bounced += 1;
        }
    }
    assert_eq!(bounced, 12);
    let store = harness.running.relay.store();
    let aside = store
        .create_alias(ACCOUNT, &harness.running.relay.config.limits)
        .await
        .unwrap();
    assert!(aside.account_paused, "a new alias is under the same pause");
    let to = at(&aside.local);
    refused(
        &harness.send(SENDER, &to, &plain(SENDER, &to, "x")).await,
        550,
    );
    let notices = harness.sent();
    assert_eq!(
        notices
            .iter()
            .filter(|s| s.text().contains("all your masked emails"))
            .count(),
        1
    );
}

#[tokio::test]
async fn a_bounced_reply_says_nothing_about_the_user() {
    let harness = Harness::start().await;
    let alias = harness.alias().await;
    let path = srs_address(&harness, Kind::Reply, &alias);
    for _ in 0..5 {
        let answer = harness
            .send("", &path, &common::dsn("failed", "5.1.1"))
            .await;
        assert_eq!(answer.code, 250, "{answer:?}");
    }
    let stored = harness
        .running
        .relay
        .store()
        .alias(&alias.local)
        .await
        .unwrap()
        .unwrap();
    assert!(stored.forwards());
    assert!(harness.sent().is_empty());
}

#[tokio::test]
async fn messages_are_held_to_the_limits() {
    use octapass_relay::limits::Bucket;
    use std::time::Duration;
    let slow = |burst| Bucket {
        burst,
        refill: Duration::from_secs(3600),
    };
    let harness = Harness::with(|config| config.limits.messages_per_alias = slow(2)).await;
    let alias = harness.alias().await;
    let to = at(&alias.local);
    for _ in 0..2 {
        let answer = harness.send(SENDER, &to, &plain(SENDER, &to, "x")).await;
        assert_eq!(answer.code, 250, "{answer:?}");
    }
    let answer = harness.send(SENDER, &to, &plain(SENDER, &to, "x")).await;
    refused(&answer, 451);

    let harness = Harness::with(|config| config.limits.messages_per_sender = slow(1)).await;
    let (first, second) = (harness.alias().await, harness.alias().await);
    let to = at(&first.local);
    assert_eq!(
        harness
            .send(SENDER, &to, &plain(SENDER, &to, "x"))
            .await
            .code,
        250
    );
    let to = at(&second.local);
    refused(
        &harness.send(SENDER, &to, &plain(SENDER, &to, "x")).await,
        451,
    );

    let harness = Harness::with(|config| config.limits.messages_per_account = slow(1)).await;
    let (first, second) = (harness.alias().await, harness.alias().await);
    let to = at(&first.local);
    assert_eq!(
        harness
            .send(SENDER, &to, &plain(SENDER, &to, "x"))
            .await
            .code,
        250
    );
    let to = at(&second.local);
    let other = "other@sender.example";
    refused(
        &harness.send(other, &to, &plain(other, &to, "x")).await,
        451,
    );

    let harness = Harness::with(|config| config.limits.connections_per_ip = slow(2)).await;
    for _ in 0..2 {
        let stream = TcpStream::connect(harness.running.smtp).await.unwrap();
        assert_eq!(Client::new(stream).reply().await.code, 220);
    }
    let stream = TcpStream::connect(harness.running.smtp).await.unwrap();
    assert_eq!(Client::new(stream).reply().await.code, 421);
}

#[tokio::test]
async fn it_is_not_an_open_relay() {
    let harness = Harness::start().await;
    let alias = harness.alias().await;
    let mut client = harness.client().await;
    let local = &alias.local;
    let attempts = [
        // Another domain, however the relay's name is dressed up.
        "RCPT TO:<victim@evil.example>".to_owned(),
        format!("RCPT TO:<{local}@evil.example>"),
        format!("RCPT TO:<{local}@{DOMAIN}.evil.example>"),
        format!("RCPT TO:<{local}@sub.{DOMAIN}>"),
        format!("RCPT TO:<{local}@evil{DOMAIN}>"),
        format!("RCPT TO:<{DOMAIN}@evil.example>"),
        // Source routes.
        format!("RCPT TO:<@{DOMAIN}:victim@evil.example>"),
        format!("RCPT TO:<@{DOMAIN},@mx.evil.example:victim@evil.example>"),
        // The percent hack and bang paths.
        format!("RCPT TO:<victim%evil.example@{DOMAIN}>"),
        format!("RCPT TO:<{local}%evil.example@{DOMAIN}>"),
        format!("RCPT TO:<evil.example!victim@{DOMAIN}>"),
        format!("RCPT TO:<victim%evil.example%{DOMAIN}@{DOMAIN}>"),
        // Quoted local parts.
        format!("RCPT TO:<\"victim@evil.example\"@{DOMAIN}>"),
        format!("RCPT TO:<\"{local}\"@{DOMAIN}>"),
        format!("RCPT TO:<\"{local}@{DOMAIN}\">"),
        // Address literals, trailing dots, nothing at all.
        "RCPT TO:<victim@[192.0.2.1]>".to_owned(),
        format!("RCPT TO:<{local}@[127.0.0.1]>"),
        format!("RCPT TO:<{local}@{DOMAIN}.>"),
        "RCPT TO:<victim>".to_owned(),
        "RCPT TO:<>".to_owned(),
        "RCPT TO:victim@evil.example".to_owned(),
        // Names the relay doesn't issue on its own domain.
        format!("RCPT TO:<{local}+tag@{DOMAIN}>"),
        format!("RCPT TO:<admin@{DOMAIN}>"),
        format!("RCPT TO:<postmaster@{DOMAIN}>"),
        format!("RCPT TO:<{USER}@{DOMAIN}>"),
    ];
    for attempt in attempts {
        client.ok(&format!("MAIL FROM:<{SENDER}>")).await;
        let answer = client.command(&attempt).await;
        assert!(answer.code >= 500, "{attempt}: {answer:?}");
        // A fresh connection each time: the session limit on errors isn't what's tested here.
        client = harness.client().await;
    }
    // Case folding reaches the right alias, never a different one.
    client = harness.client().await;
    client.ok(&format!("MAIL FROM:<{SENDER}>")).await;
    let shouting = format!(
        "RCPT TO:<{}@{}>",
        local.to_uppercase(),
        DOMAIN.to_uppercase()
    );
    client.ok(&shouting).await;
    let answer = client.data(&plain(SENDER, &at(local), "x")).await;
    assert_eq!(answer.code, 250, "{answer:?}");
    let sent = harness.sent();
    assert_eq!(sent.len(), 1);
    assert_eq!(
        sent[0].to, USER,
        "only the account's own mailbox ever receives"
    );
}

#[tokio::test]
async fn errors_end_a_scanning_session() {
    let harness = Harness::start().await;
    let mut client = harness.client().await;
    client.ok(&format!("MAIL FROM:<{SENDER}>")).await;
    let mut last = Answer {
        code: 0,
        text: String::new(),
    };
    for _ in 0..10 {
        last = client
            .command(&format!("RCPT TO:<abcdefghijkl@{DOMAIN}>"))
            .await;
    }
    assert_eq!(last.code, 550);
    assert_eq!(client.reply().await.code, 421);
    assert!(client.closed().await);
}

#[tokio::test]
async fn oversized_messages_are_refused() {
    let harness = Harness::with(|config| config.limits.max_message_bytes = 2048).await;
    let alias = harness.alias().await;
    let to = at(&alias.local);

    let mut client = harness.client().await;
    let answer = client
        .command(&format!("MAIL FROM:<{SENDER}> SIZE=2049"))
        .await;
    refused(&answer, 552);

    let mut client = harness.client().await;
    client.ok(&format!("MAIL FROM:<{SENDER}> SIZE=100")).await;
    client.ok(&format!("RCPT TO:<{to}>")).await;
    let padding = format!("{}\r\n", "x".repeat(70)).repeat(40);
    let message = format!("{}{padding}", plain(SENDER, &to, "big"));
    let answer = client.data(&message).await;
    refused(&answer, 552);

    // The connection goes on, and a message that fits still works.
    client.ok(&format!("MAIL FROM:<{SENDER}>")).await;
    client.ok(&format!("RCPT TO:<{to}>")).await;
    let answer = client.data(&plain(SENDER, &to, "small")).await;
    assert_eq!(answer.code, 250, "{answer:?}");
    assert_eq!(harness.sent().len(), 1);
}

#[tokio::test]
async fn dmarc_decides_for_senders_that_ask_it_to() {
    let harness = Harness::start().await;
    let alias = harness.alias().await;
    let to = at(&alias.local);

    // Fails SPF, unsigned, and the domain says to reject that.
    let forged = "ceo@strict.example";
    let answer = harness
        .send(forged, &to, &plain(forged, &to, "Wire money"))
        .await;
    refused(&answer, 550);
    assert!(answer.text.contains("DMARC"), "{answer:?}");

    // A forged From with a passing envelope is what DMARC is for: the header decides.
    let answer = harness
        .send(SENDER, &to, &plain(forged, &to, "Wire money"))
        .await;
    refused(&answer, 550);
    assert!(harness.sent().is_empty());
    assert_eq!(
        harness
            .running
            .relay
            .store()
            .alias(&alias.local)
            .await
            .unwrap()
            .unwrap()
            .blocked,
        2
    );

    // Two From addresses would dodge the policy.
    let doubled =
        format!("From: <ceo@strict.example>, <{SENDER}>\r\nTo: {to}\r\nSubject: x\r\n\r\nx\r\n");
    refused(&harness.send(SENDER, &to, &doubled).await, 550);
    let twice = format!(
        "From: <{SENDER}>\r\nFrom: <ceo@strict.example>\r\nTo: {to}\r\nSubject: x\r\n\r\nx\r\n"
    );
    refused(&harness.send(SENDER, &to, &twice).await, 550);
    let missing = format!("To: {to}\r\nSubject: x\r\n\r\nx\r\n");
    refused(&harness.send(SENDER, &to, &missing).await, 550);
    assert!(harness.sent().is_empty());

    // Failing DMARC at p=none is forwarded, and the result is shown.
    let watched = "news@relaxed.example";
    let answer = harness
        .send(watched, &to, &plain(watched, &to, "News"))
        .await;
    assert_eq!(answer.code, 250, "{answer:?}");
    let text = harness.sent()[0].text();
    assert!(text.contains("dmarc=fail"), "{text}");
    assert!(text.contains("spf=fail"), "{text}");

    // No DMARC record at all.
    let plain_sender = "someone@nothing.example";
    let answer = harness
        .send(plain_sender, &to, &plain(plain_sender, &to, "Hi"))
        .await;
    assert_eq!(answer.code, 250, "{answer:?}");
}

#[tokio::test]
async fn the_reply_tells_the_truth_about_the_smart_host() {
    let harness = Harness::start().await;
    let alias = harness.alias().await;
    let to = at(&alias.local);

    harness.set_host(HostMode::TemporaryFailure);
    refused(
        &harness.send(SENDER, &to, &plain(SENDER, &to, "x")).await,
        451,
    );
    harness.set_host(HostMode::PermanentFailure);
    refused(
        &harness.send(SENDER, &to, &plain(SENDER, &to, "x")).await,
        550,
    );
    harness.set_host(HostMode::Accept);
    let store = harness.running.relay.store();
    assert_eq!(
        store.alias(&alias.local).await.unwrap().unwrap().forwarded,
        0
    );

    let answer = harness.send(SENDER, &to, &plain(SENDER, &to, "x")).await;
    assert_eq!(answer.code, 250, "{answer:?}");
    assert_eq!(
        store.alias(&alias.local).await.unwrap().unwrap().forwarded,
        1
    );
}

#[tokio::test]
async fn an_unreachable_smart_host_means_try_again() {
    let harness = Harness::with(|config| config.smart_host = "smtp://127.0.0.1:1".into()).await;
    let alias = harness.alias().await;
    let to = at(&alias.local);
    refused(
        &harness.send(SENDER, &to, &plain(SENDER, &to, "x")).await,
        451,
    );
}

#[tokio::test]
async fn smuggled_messages_never_become_messages() {
    let harness = Harness::start().await;
    let alias = harness.alias().await;
    let to = at(&alias.local);
    for ending in [
        &b"\n.\r\n"[..],
        b"\r.\r\n",
        b"\n.\n",
        b"\r\n.\n",
        b"\r\n.\r",
    ] {
        let mut client = harness.client().await;
        client.ok(&format!("MAIL FROM:<{SENDER}>")).await;
        client.ok(&format!("RCPT TO:<{to}>")).await;
        assert_eq!(client.command("DATA").await.code, 354);
        client.raw(plain(SENDER, &to, "first").as_bytes()).await;
        client.raw(ending).await;
        client
            .raw(format!("MAIL FROM:<{SENDER}>\r\nRCPT TO:<{to}>\r\nDATA\r\nSubject: smuggled\r\n\r\nx\r\n").as_bytes())
            .await;
        client.raw(b"\r\n.\r\n").await;
        let answer = client.reply().await;
        refused(&answer, 550);
    }
    assert!(harness.sent().is_empty());

    // A bare LF inside a header counts the same.
    let bare = "From: <a@sender.example>\nBcc: x\r\nSubject: y\r\n\r\nz\r\n";
    refused(&harness.send(SENDER, &to, bare).await, 550);
}

#[tokio::test]
async fn loops_stop() {
    let harness = Harness::start().await;
    let alias = harness.alias().await;
    let reverse = harness.first_contact(&alias, SENDER).await;
    let to = at(&alias.local);

    // The user's mailbox forwards a message straight back to the alias.
    let forwarded = harness.sent()[0].text();
    let answer = harness.send(USER, &to, &forwarded).await;
    refused(&answer, 550);
    assert_eq!(answer.text, format!("5.4.6 {}", LOOP.text));

    let hops = "Received: from a by b\r\n".repeat(26);
    let long = format!("{hops}{}", plain(SENDER, &to, "x"));
    refused(&harness.send(SENDER, &to, &long).await, 550);

    // An out-of-office reply must not tell the stranger anything.
    let vacation = format!(
        "Auto-Submitted: auto-replied\r\n{}",
        plain(USER, &reverse, "Away")
    );
    refused(&harness.send(USER, &reverse, &vacation).await, 550);
    let bulk = format!("Precedence: bulk\r\n{}", plain(USER, &reverse, "Away"));
    refused(&harness.send(USER, &reverse, &bulk).await, 550);
    let human = format!("Auto-Submitted: no\r\n{}", plain(USER, &reverse, "Back"));
    assert_eq!(harness.send(USER, &reverse, &human).await.code, 250);

    // Bounce-shaped mail to an alias has no one to reverse to.
    refused(
        &harness.send("", &to, &common::dsn("failed", "5.1.1")).await,
        550,
    );
    assert_eq!(harness.sent().len(), 2);
}

#[tokio::test]
async fn one_recipient_per_transaction() {
    let harness = Harness::start().await;
    let (first, second) = (harness.alias().await, harness.alias().await);
    let mut client = harness.client().await;
    client.ok(&format!("MAIL FROM:<{SENDER}>")).await;
    client.ok(&format!("RCPT TO:<{}>", at(&first.local))).await;
    let answer = client
        .command(&format!("RCPT TO:<{}>", at(&second.local)))
        .await;
    assert_eq!(answer.code, 452, "{answer:?}");
    let answer = client.data(&plain(SENDER, &at(&first.local), "x")).await;
    assert_eq!(answer.code, 250, "{answer:?}");
    assert_eq!(harness.sent().len(), 1);
}

#[tokio::test]
async fn commands_are_checked_in_order() {
    let harness = Harness::start().await;
    let stream = TcpStream::connect(harness.running.smtp).await.unwrap();
    let mut client = Client::new(stream);
    client.reply().await;
    refused(&client.command(&format!("MAIL FROM:<{SENDER}>")).await, 503);
    client.ok("HELO mx.sender.example").await;
    refused(&client.command("DATA").await, 503);
    refused(&client.command("RCPT TO:<a@relay.example>").await, 503);
    refused(&client.command("VRFY jane").await, 502);
    refused(&client.command("EXPN list").await, 502);
    refused(&client.command("SMTPUTF8 yes").await, 500);
    refused(
        &client
            .command(&format!("MAIL FROM:<{SENDER}> SMTPUTF8"))
            .await,
        555,
    );
    client.ok(&format!("MAIL FROM:<{SENDER}>")).await;
    refused(&client.command(&format!("MAIL FROM:<{SENDER}>")).await, 503);
    client.ok("RSET").await;
    client.ok("NOOP").await;
    client
        .raw(format!("{}\r\n", "x".repeat(5000)).as_bytes())
        .await;
    assert!(client.reply().await.code >= 500);
    assert_eq!(client.command("QUIT").await.code, 221);
}

mod tls {
    use tokio_rustls::TlsConnector;
    use tokio_rustls::rustls::crypto::ring;
    use tokio_rustls::rustls::pki_types::ServerName;
    use tokio_rustls::rustls::{ClientConfig, RootCertStore};
    use zeroize::Zeroizing;

    use super::*;
    use rustls_pki_types::CertificateDer;

    const CA: &[u8] = include_bytes!("fixtures/tls-ca.pem");
    const CERT: &[u8] = include_bytes!("fixtures/tls-cert.pem");
    const KEY: &[u8] = include_bytes!("fixtures/tls-key.pem");

    async fn harness() -> Harness {
        Harness::with(|config| {
            config.tls = Some((CERT.to_vec(), Zeroizing::new(KEY.to_vec())));
        })
        .await
    }

    #[tokio::test]
    async fn mail_goes_through_starttls() {
        let harness = harness().await;
        let alias = harness.alias().await;
        let to = at(&alias.local);

        let stream = TcpStream::connect(harness.running.smtp).await.unwrap();
        let mut client = Client::new(stream);
        client.reply().await;
        let hello = client.command("EHLO mx.sender.example").await;
        assert!(hello.text.contains("STARTTLS"), "{hello:?}");
        assert_eq!(client.command("STARTTLS").await.code, 220);

        let mut roots = RootCertStore::empty();
        for certificate in CertificateDer::pem_slice_iter(CA) {
            roots.add(certificate.unwrap()).unwrap();
        }
        let config = ClientConfig::builder_with_provider(Arc::new(ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let stream = TlsConnector::from(Arc::new(config))
            .connect(
                ServerName::try_from("mx.relay.example").unwrap(),
                client.reader.into_inner(),
            )
            .await
            .unwrap();

        // RFC 3207: start over, and STARTTLS is no longer offered.
        let mut client = Client::new(stream);
        refused(&client.command(&format!("MAIL FROM:<{SENDER}>")).await, 503);
        let hello = client.command("EHLO mx.sender.example").await;
        assert!(!hello.text.contains("STARTTLS"), "{hello:?}");
        refused(&client.command("STARTTLS").await, 454);
        client.ok(&format!("MAIL FROM:<{SENDER}>")).await;
        client.ok(&format!("RCPT TO:<{to}>")).await;
        let answer = client.data(&plain(SENDER, &to, "over tls")).await;
        assert_eq!(answer.code, 250, "{answer:?}");
        assert_eq!(harness.sent().len(), 1);
    }

    #[tokio::test]
    async fn commands_sent_with_starttls_are_not_carried_into_tls() {
        let harness = harness().await;
        let stream = TcpStream::connect(harness.running.smtp).await.unwrap();
        let mut client = Client::new(stream);
        client.reply().await;
        client.ok("EHLO mx.sender.example").await;
        client
            .raw(b"STARTTLS\r\nMAIL FROM:<a@evil.example>\r\n")
            .await;
        let answer = client.reply().await;
        assert_eq!(answer.code, 501, "{answer:?}");
        assert!(client.closed().await);
    }

    #[tokio::test]
    async fn without_a_certificate_tls_is_not_offered() {
        let harness = Harness::start().await;
        let stream = TcpStream::connect(harness.running.smtp).await.unwrap();
        let mut client = Client::new(stream);
        client.reply().await;
        let hello = client.command("EHLO mx.sender.example").await;
        assert!(!hello.text.contains("STARTTLS"), "{hello:?}");
        refused(&client.command("STARTTLS").await, 454);
    }
}

#[tokio::test]
async fn postmaster_is_refused_until_an_operator_is_set() {
    let harness = Harness::start().await;
    let to = at("postmaster");
    refused(
        &harness.send(SENDER, &to, &plain(SENDER, &to, "x")).await,
        550,
    );

    let harness = Harness::with(|config| {
        config.operator =
            Some(octapass_relay::address::Address::parse("ops@operator.example").unwrap());
    })
    .await;
    assert_eq!(
        harness
            .send(SENDER, &to, &plain(SENDER, &to, "x"))
            .await
            .code,
        250
    );
    let sent = harness.sent();
    assert_eq!(
        (sent[0].to.as_str(), sent[0].from.as_str()),
        ("ops@operator.example", "")
    );
}
