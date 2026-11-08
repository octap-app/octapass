//! `octapass-push-relay` serves the relay; `octapass-push-relay admin list|revoke <id>` manages
//! installations.

use std::net::SocketAddr;
use std::process::ExitCode;

use octapass_push_relay::{AppState, Config, db, router};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let config = match Config::from_env() {
        Ok(config) => config,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::FAILURE;
        }
    };
    if args.first().map(String::as_str) == Some("admin") {
        return admin(&config, &args[1..]).await;
    }
    if !args.is_empty() {
        eprintln!("usage: octapass-push-relay [admin list | admin revoke <installation id>]");
        return ExitCode::FAILURE;
    }
    let state = match AppState::new(config).await {
        Ok(state) => state,
        Err(error) => {
            eprintln!("the push relay couldn't start: {error}");
            return ExitCode::FAILURE;
        }
    };
    let listener = match tokio::net::TcpListener::bind(state.config.bind).await {
        Ok(listener) => listener,
        Err(error) => {
            eprintln!("{}: {error}", state.config.bind);
            return ExitCode::FAILURE;
        }
    };
    let pruning = state.clone();
    tokio::spawn(async move {
        let mut every = tokio::time::interval(std::time::Duration::from_secs(300));
        loop {
            every.tick().await;
            pruning.prune();
        }
    });
    tracing::info!(bind = %state.config.bind, "push relay running");
    let service = router(state).into_make_service_with_connect_info::<SocketAddr>();
    tokio::select! {
        result = axum::serve(listener, service) => {
            if let Err(error) = result {
                eprintln!("{error}");
            }
            ExitCode::FAILURE
        }
        _ = tokio::signal::ctrl_c() => ExitCode::SUCCESS,
    }
}

async fn admin(config: &Config, args: &[String]) -> ExitCode {
    let db = match db::connect(&config.database_url).await {
        Ok(db) => db,
        Err(error) => {
            eprintln!("database: {error}");
            return ExitCode::FAILURE;
        }
    };
    match args {
        [command] if command == "list" => match db::list(&db).await {
            Ok(installations) => {
                for installation in installations {
                    let state = if installation.revoked_at.is_some() {
                        "revoked"
                    } else {
                        "active"
                    };
                    let used = installation
                        .last_used_at
                        .map_or_else(|| "never".to_owned(), |at| at.to_string());
                    println!(
                        "{}\t{state}\tcreated {}\tlast used {used}",
                        installation.id, installation.created_at
                    );
                }
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("{error}");
                ExitCode::FAILURE
            }
        },
        [command, id] if command == "revoke" => match db::revoke(&db, id, db::now()).await {
            Ok(true) => ExitCode::SUCCESS,
            Ok(false) => {
                eprintln!("no active installation {id}");
                ExitCode::FAILURE
            }
            Err(error) => {
                eprintln!("{error}");
                ExitCode::FAILURE
            }
        },
        _ => {
            eprintln!("usage: octapass-push-relay admin list | admin revoke <installation id>");
            ExitCode::FAILURE
        }
    }
}
