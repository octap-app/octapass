use std::io::IsTerminal;
use std::net::SocketAddr;
use std::path::Path;
use std::process::ExitCode;

use octapass_server::{AppState, Config, admin, openapi, router, spawn_maintenance};
use tracing_subscriber::EnvFilter;

const USAGE: &str = "\
Usage:
  octapass-server                               Run the server
  octapass-server openapi                       Print the OpenAPI document
  octapass-server admin invite <email>          Allow an email to sign up (OCTAPASS_SIGNUPS=invite)
  octapass-server admin delete-account <email>  Permanently delete an account and everything in it
  octapass-server admin reset-two-step <email>  Turn off two-step sign-in for someone who lost every method
  octapass-server admin backup <folder>         Write a backup of the database, secrets and attachments (SQLite)
  octapass-server admin restore <backup>        Put a backup in place of the data (stop the server first)
  octapass-server admin key-log                 The key log's origin and verifier key, for witnesses, and how witnessing stands
  octapass-server admin key-log witness         Send a checkpoint to the witnesses now and report
  octapass-server healthcheck                   Exit 0 when the server on OCTAPASS_BIND answers /healthz

Configuration comes from OCTAPASS_* environment variables; see docs/self-hosting/configuration.md.";

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_env("OCTAPASS_LOG").unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_ansi(std::io::stdout().is_terminal())
        .init();

    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let result = match args.as_slice() {
        [] => serve().await,
        ["openapi"] => {
            print!("{}", openapi::json());
            Ok(())
        }
        ["admin", "invite", email] => {
            with_state(|state| async move { admin::invite(&state, email).await }).await
        }
        ["admin", "reset-two-step", email] => {
            with_state(|state| async move { admin::reset_two_step(&state, email).await }).await
        }
        ["admin", "delete-account", email] => {
            with_state(|state| async move { admin::delete_account(&state, email).await }).await
        }
        ["admin", "backup", dir] => {
            with_state(|state| async move {
                let path = admin::backup(&state, Path::new(dir)).await?;
                println!("{}", path.display());
                Ok::<_, admin::AdminError>(())
            })
            .await
        }
        ["admin", "restore", dir] => restore(dir),
        ["admin", "key-log"] => {
            with_state(|state| async move {
                let described = octapass_server::key_log_witnesses::describe(&state).await;
                print!(
                    "{}",
                    described.map_err(|e| admin::AdminError::Failed(e.to_string()))?
                );
                Ok::<_, admin::AdminError>(())
            })
            .await
        }
        ["admin", "key-log", "witness"] => {
            with_state(|state| async move {
                let report = octapass_server::key_log_witnesses::run_once(&state).await;
                print!("{}", report.map_err(admin::AdminError::Failed)?);
                Ok::<_, admin::AdminError>(())
            })
            .await
        }
        ["healthcheck"] => healthcheck(),
        ["--help" | "-h" | "help"] => {
            println!("{USAGE}");
            Ok(())
        }
        _ => Err(format!("unknown command\n\n{USAGE}")),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn state() -> Result<AppState, String> {
    let config = Config::from_env().map_err(|e| e.to_string())?;
    AppState::new(config).await.map_err(|e| e.to_string())
}

async fn with_state<F, Fut, E>(command: F) -> Result<(), String>
where
    F: FnOnce(AppState) -> Fut,
    Fut: Future<Output = Result<(), E>>,
    E: std::fmt::Display,
{
    let state = state().await?;
    command(state).await.map_err(|e| e.to_string())?;
    println!("done");
    Ok(())
}

fn restore(dir: &str) -> Result<(), String> {
    let config = Config::from_env().map_err(|e| e.to_string())?;
    let aside = admin::restore(&config, Path::new(dir)).map_err(|e| e.to_string())?;
    println!("restored; the data it replaced is in {}", aside.display());
    Ok(())
}

/// For container health checks: the image has no shell or curl.
fn healthcheck() -> Result<(), String> {
    use std::io::{Read, Write};
    let config = Config::from_env().map_err(|e| e.to_string())?;
    let mut addr = config.bind;
    if addr.ip().is_unspecified() {
        addr.set_ip(std::net::Ipv4Addr::LOCALHOST.into());
    }
    let timeout = std::time::Duration::from_secs(5);
    let mut stream =
        std::net::TcpStream::connect_timeout(&addr, timeout).map_err(|e| e.to_string())?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|e| e.to_string())?;
    stream
        .write_all(b"GET /healthz HTTP/1.0\r\nHost: localhost\r\n\r\n")
        .map_err(|e| e.to_string())?;
    let mut reply = [0; 12];
    stream.read_exact(&mut reply).map_err(|e| e.to_string())?;
    if reply.ends_with(b" 200") {
        Ok(())
    } else {
        Err(format!("unhealthy: {}", String::from_utf8_lossy(&reply)))
    }
}

async fn serve() -> Result<(), String> {
    let state = state().await?;
    admin::invite_configured(&state)
        .await
        .map_err(|e| format!("OCTAPASS_INVITES: {e}"))?;
    let bind = state.config.bind;
    spawn_maintenance(state.clone());
    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .map_err(|e| format!("bind {bind}: {e}"))?;
    tracing::info!(%bind, "Octa Pass server listening");
    axum::serve(
        listener,
        router(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .map_err(|e| e.to_string())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(_) => std::future::pending().await,
        }
    };
    tokio::select! {
        () = ctrl_c => {}
        () = terminate => {}
    }
    tracing::info!("shutting down");
}
