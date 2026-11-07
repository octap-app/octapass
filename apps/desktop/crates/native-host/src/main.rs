//! `octapass-native-host`: started by the browser, speaks native messaging on stdin/stdout.

use std::io::{self, Write};
use std::process::ExitCode;

use octapass_native_host::caller::Caller;
use octapass_native_host::protocol::{BROWSER_NOT_TRUSTED, Forwarded, Message, Reply, Request};
use octapass_native_host::system::OsSystem;
use octapass_native_host::trust::{self, Refusal, Vouching};
use octapass_native_host::{framing, ipc};
use serde_json::{Value, json};

fn main() -> ExitCode {
    let Some(caller) = Caller::from_args(std::env::args().skip(1)).filter(Caller::is_allowed)
    else {
        eprintln!(
            "octapass-native-host is started by the Octa Pass browser extension, not directly."
        );
        return ExitCode::FAILURE;
    };
    let Some(endpoint) = ipc::data_dir().map(|dir| ipc::endpoint(&dir)) else {
        eprintln!("octapass-native-host: no data folder for this user");
        return ExitCode::FAILURE;
    };
    // The origin argument is only worth believing if a browser passed it.
    let vouching = Vouching::for_this_build();
    let result = match trust::launching_browser(&OsSystem, vouching, std::process::id()) {
        Ok(browser) => {
            if vouching == Vouching::Nothing {
                eprintln!(
                    "octapass-native-host: development build, so {}'s signature isn't checked",
                    browser.name
                );
            }
            serve(|bytes| relay(&caller, &endpoint, bytes))
        }
        Err(refusal) => {
            eprintln!("octapass-native-host: refusing to relay: {refusal}");
            serve(|bytes| refuse(&refusal, bytes))
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("octapass-native-host: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Answers messages until the extension disconnects.
fn serve(answer: impl Fn(&[u8]) -> Reply) -> io::Result<()> {
    let mut input = io::stdin().lock();
    let mut output = io::stdout().lock();
    while let Some(bytes) = framing::read_message(&mut input)? {
        let reply = answer(&bytes);
        framing::write_message(
            &mut output,
            &serde_json::to_vec(&reply).expect("replies serialize"),
        )?;
        output.flush()?;
    }
    Ok(())
}

/// The message's `id`, even when the rest of it is invalid.
fn message_id(bytes: &[u8]) -> Value {
    serde_json::from_slice::<Value>(bytes)
        .ok()
        .and_then(|value| value.get("id").cloned())
        .unwrap_or(Value::Null)
}

/// Every request gets the same error, so the extension can tell the user why. Whoever started
/// the host is what's refused here, whatever the reason, so it's always [`BROWSER_NOT_TRUSTED`].
fn refuse(refusal: &Refusal, bytes: &[u8]) -> Reply {
    Reply::error(
        message_id(bytes),
        BROWSER_NOT_TRUSTED,
        format!("Octa Pass can't unlock through this browser: {refusal}."),
    )
}

fn relay(caller: &Caller, endpoint: &std::path::Path, bytes: &[u8]) -> Reply {
    let message: Message = match serde_json::from_slice(bytes) {
        Ok(message) => message,
        Err(error) => return Reply::error(message_id(bytes), "invalidRequest", error.to_string()),
    };
    let id = message.id.clone();
    let is_status = matches!(message.request, Request::UnlockStatus);
    let forwarded = Forwarded {
        origin: caller.origin(),
        message,
    };
    match ipc::request(endpoint, &forwarded) {
        // The app refuses a connection before reading its request, so that reply has no id.
        Ok(reply) if reply.id.is_null() => Reply { id, ..reply },
        Ok(reply) => reply,
        // The app isn't running: that's a status, not a failure.
        Err(_) if is_status => Reply::ok(id, json!({ "appRunning": false })),
        Err(_) => Reply::error(
            id,
            "appNotRunning",
            "Open the Octa Pass app to unlock from the browser.",
        ),
    }
}
