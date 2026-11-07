//! The host binary as a browser runs it: framed JSON on stdin and stdout. A copy of the
//! `fake-browser` example stands in for the browser (development builds accept it by its path).

#![cfg(unix)]

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::process::{Child, Command, Stdio};

use octapass_native_host::framing::{read_message, write_message};
use octapass_native_host::ipc::{DATA_DIR_ENV, endpoint};
use octapass_native_host::manifests::DEV_CHROME_ID;
use octapass_native_host::protocol::{Forwarded, Reply};
use octapass_native_host::testing::fake_browser;
use serde_json::{Value, json};

/// The host, started by a browser in `dir` (or by this test itself).
fn host(dir: &Path, origin: &str, by_browser: bool) -> Child {
    let host = env!("CARGO_BIN_EXE_octapass-native-host");
    let mut command = if by_browser {
        let mut command = Command::new(fake_browser(dir));
        command.arg(host);
        command
    } else {
        Command::new(host)
    };
    command
        .arg(origin)
        .env(DATA_DIR_ENV, dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap()
}

fn exchange(child: &mut Child, message: Value) -> Value {
    write_message(
        child.stdin.as_mut().unwrap(),
        &serde_json::to_vec(&message).unwrap(),
    )
    .unwrap();
    let reply = read_message(child.stdout.as_mut().unwrap())
        .unwrap()
        .unwrap();
    serde_json::from_slice(&reply).unwrap()
}

fn chrome_origin() -> String {
    format!("chrome-extension://{DEV_CHROME_ID}/")
}

#[test]
fn requests_are_relayed_to_the_app_with_the_callers_origin() {
    let dir = tempfile::tempdir().unwrap();
    let listener = UnixListener::bind(endpoint(dir.path())).unwrap();
    let app = std::thread::spawn(move || {
        for _ in 0..2 {
            let (stream, _) = listener.accept().unwrap();
            let mut line = String::new();
            BufReader::new(&stream).read_line(&mut line).unwrap();
            let forwarded: Forwarded = serde_json::from_str(&line).unwrap();
            let reply = Reply::ok(
                forwarded.message.id.clone(),
                json!({ "origin": forwarded.origin, "request": forwarded.message.request }),
            );
            (&stream)
                .write_all(format!("{}\n", serde_json::to_string(&reply).unwrap()).as_bytes())
                .unwrap();
        }
    });

    let mut child = host(dir.path(), &chrome_origin(), true);
    let reply = exchange(&mut child, json!({ "id": 1, "type": "unlock-status" }));
    assert_eq!(
        reply,
        json!({ "id": 1, "ok": true, "result": { "origin": chrome_origin(), "request": { "type": "unlock-status" } } })
    );
    let reply = exchange(
        &mut child,
        json!({ "id": "b", "type": "get-session-key-wrap", "publicKey": "k" }),
    );
    assert_eq!(
        reply["result"]["request"],
        json!({ "type": "get-session-key-wrap", "publicKey": "k" })
    );
    app.join().unwrap();

    // Bad JSON and unknown requests never reach the app.
    let reply = exchange(&mut child, json!({ "id": 9, "type": "export-vault" }));
    assert_eq!(reply["error"]["code"], "invalidRequest");
    assert_eq!(reply["id"], 9);
    drop(child.stdin.take());
    assert!(
        child.wait().unwrap().success(),
        "exits when the extension disconnects"
    );
}

#[test]
fn the_apps_refusal_reaches_the_extension_with_the_requests_id() {
    // The app refuses a connection before reading it, so its reply has no id; the host fills it in.
    let dir = tempfile::tempdir().unwrap();
    let listener = UnixListener::bind(endpoint(dir.path())).unwrap();
    let app = std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let reply = Reply::error(
            Value::Null,
            "browserNotTrusted",
            "Octa Pass can't unlock through this browser: this copy of Google Chrome isn't signed by its vendor.",
        );
        (&stream)
            .write_all(format!("{}\n", serde_json::to_string(&reply).unwrap()).as_bytes())
            .unwrap();
    });
    let mut child = host(dir.path(), &chrome_origin(), true);
    let reply = exchange(&mut child, json!({ "id": 7, "type": "unlock-status" }));
    app.join().unwrap();
    assert_eq!(reply["id"], 7);
    assert_eq!(reply["error"]["code"], "browserNotTrusted");
    drop(child.stdin.take());
    child.wait().unwrap();
}

#[test]
fn without_the_app_status_says_so_and_other_requests_fail() {
    let dir = tempfile::tempdir().unwrap();
    let mut child = host(dir.path(), &chrome_origin(), true);
    assert_eq!(
        exchange(&mut child, json!({ "id": 1, "type": "unlock-status" })),
        json!({ "id": 1, "ok": true, "result": { "appRunning": false } })
    );
    assert_eq!(
        exchange(&mut child, json!({ "id": 2, "type": "unlock" }))["error"]["code"],
        "appNotRunning"
    );
    drop(child.stdin.take());
    child.wait().unwrap();
}

#[test]
fn other_extensions_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let mut child = host(
        dir.path(),
        "chrome-extension://abcdefghijklmnopabcdefghijklmnop/",
        true,
    );
    assert!(!child.wait().unwrap().success());
}

#[test]
fn a_host_not_started_by_a_browser_relays_nothing() {
    // Any program can run the host with a forged origin; it answers every request with an error
    // the extension can show, and never connects to the app.
    let dir = tempfile::tempdir().unwrap();
    let listener = UnixListener::bind(endpoint(dir.path())).unwrap();
    listener.set_nonblocking(true).unwrap();

    let mut child = host(dir.path(), &chrome_origin(), false);
    for (id, request) in [(1, "unlock-status"), (2, "get-session-key-wrap")] {
        let reply = exchange(
            &mut child,
            json!({ "id": id, "type": request, "publicKey": "k" }),
        );
        assert_eq!(reply["id"], id);
        assert_eq!(reply["ok"], false);
        assert_eq!(reply["error"]["code"], "browserNotTrusted");
        let message = reply["error"]["message"].as_str().unwrap();
        assert!(
            message.starts_with("Octa Pass can't unlock through this browser: only a supported browser may start the host"),
            "{message}"
        );
    }
    drop(child.stdin.take());
    assert!(child.wait().unwrap().success());
    assert!(listener.accept().is_err(), "the app was never contacted");
}
