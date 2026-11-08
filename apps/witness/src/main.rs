use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use octapass_witness::{Config, Witness, load_or_create_key, router};

const HELP: &str = "\
octapass-witness: cosigns Octa Pass key log checkpoints (C2SP tlog-witness)

Usage:
  octapass-witness         Run the witness
  octapass-witness vkey    Print this witness's verifier key, for log operators
  octapass-witness help    Show this help

Environment:
  OCTAPASS_WITNESS_NAME      Cosigner name, a schema-less URL (required), e.g. witness.example.com/octapass
  OCTAPASS_WITNESS_LOGS      Log verifier keys to witness, separated by commas or newlines
                             (each server prints its own: octapass-server admin key-log)
  OCTAPASS_WITNESS_DATA_DIR  Holds state.json and witness.key (default ./witness-data)
  OCTAPASS_WITNESS_KEY_FILE  The 32-byte signing key, made on first start (default <data dir>/witness.key)
  OCTAPASS_WITNESS_BIND      Address to listen on (default 127.0.0.1:8090)
";

fn env(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
}

fn config() -> Result<(Config, SocketAddr), String> {
    let name = env("OCTAPASS_WITNESS_NAME").ok_or("OCTAPASS_WITNESS_NAME is required")?;
    let data_dir = PathBuf::from(env("OCTAPASS_WITNESS_DATA_DIR").unwrap_or("witness-data".into()));
    let key_file = env("OCTAPASS_WITNESS_KEY_FILE")
        .map(PathBuf::from)
        .unwrap_or_else(|| data_dir.join("witness.key"));
    let key = load_or_create_key(&key_file).map_err(|e| format!("{}: {e}", key_file.display()))?;
    let logs = env("OCTAPASS_WITNESS_LOGS")
        .unwrap_or_default()
        .split([',', '\n'])
        .map(str::trim)
        .filter(|vkey| !vkey.is_empty())
        .map(str::to_owned)
        .collect();
    let bind = env("OCTAPASS_WITNESS_BIND")
        .unwrap_or("127.0.0.1:8090".into())
        .parse()
        .map_err(|e| format!("OCTAPASS_WITNESS_BIND: {e}"))?;
    Ok((
        Config {
            name: name.trim().to_owned(),
            key,
            logs,
            data_dir,
        },
        bind,
    ))
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "octapass_witness=info".into()),
        )
        .init();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let command = args.first().map(String::as_str);
    if matches!(command, Some("help" | "--help" | "-h")) {
        print!("{HELP}");
        return;
    }
    let run = async {
        let (config, bind) = config()?;
        let witness = Witness::open(config).map_err(|e| e.to_string())?;
        match command {
            Some("vkey") => {
                println!("{}", witness.vkey());
                Ok(())
            }
            None => {
                if witness.origins().next().is_none() {
                    tracing::warn!(
                        "OCTAPASS_WITNESS_LOGS is empty: every checkpoint will be refused"
                    );
                }
                for origin in witness.origins() {
                    tracing::info!(%origin, "witnessing");
                }
                tracing::info!(vkey = %witness.vkey(), %bind, "Octa Pass witness listening");
                let listener = tokio::net::TcpListener::bind(bind)
                    .await
                    .map_err(|e| format!("{bind}: {e}"))?;
                axum::serve(listener, router(Arc::new(witness)))
                    .with_graceful_shutdown(async {
                        let _ = tokio::signal::ctrl_c().await;
                    })
                    .await
                    .map_err(|e| e.to_string())
            }
            Some(other) => Err(format!("unknown command {other:?}\n\n{HELP}")),
        }
    };
    if let Err(error) = run.await {
        eprintln!("octapass-witness: {error}");
        std::process::exit(1);
    }
}
