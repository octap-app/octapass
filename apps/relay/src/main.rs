//! `octapass-relay`. Off unless configured: without `OCTAPASS_RELAY_*` it says so and stops.

use std::process::ExitCode;

use octapass_relay::Config;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();
    let config = match Config::from_env() {
        Ok(config) => config,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::FAILURE;
        }
    };
    let running = match octapass_relay::start(config).await {
        Ok(running) => running,
        Err(error) => {
            eprintln!("the relay couldn't start: {error}");
            return ExitCode::FAILURE;
        }
    };
    tracing::info!(smtp = %running.smtp, api = %running.api, "relay running");
    tokio::select! {
        () = running.wait() => ExitCode::FAILURE,
        _ = tokio::signal::ctrl_c() => ExitCode::SUCCESS,
    }
}
