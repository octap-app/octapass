//! Stands in for a browser in tests: starts the program named by its first argument with the
//! rest, sharing its stdin and stdout, and exits with its status. Tests copy it to where a known
//! browser's executable would be (`octapass_native_host::testing`).

use std::process::{Command, ExitCode};

fn main() -> ExitCode {
    let mut args = std::env::args_os().skip(1);
    let Some(program) = args.next() else {
        eprintln!("usage: fake-browser <program> [arguments…]");
        return ExitCode::FAILURE;
    };
    match Command::new(program).args(args).status() {
        Ok(status) if status.success() => ExitCode::SUCCESS,
        Ok(status) => ExitCode::from(
            status
                .code()
                .and_then(|code| u8::try_from(code).ok())
                .unwrap_or(1),
        ),
        Err(error) => {
            eprintln!("fake-browser: {error}");
            ExitCode::FAILURE
        }
    }
}
