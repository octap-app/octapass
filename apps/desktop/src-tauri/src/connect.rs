//! Octa Pass Connect in the desktop app: off until the person turns it on on this device, and then
//! running whenever the app is. It reads the unlocked vault in this process, so locking the app
//! stops it handing anything out; approvals are a native dialog. Windows uses loopback.

use std::path::PathBuf;
use std::sync::Arc;

use octapass_connect::clients::{Client, Clients};
use octapass_connect::server::{self, Approval, Backend};
use octapass_connect::vault_backend::{Ask, VaultBackend};
use octapass_desktop_vault::VaultError;
use serde::Serialize;
use tauri::{AppHandle, Manager};
use tauri_plugin_dialog::{DialogExt, MessageDialogButtons, MessageDialogKind};
use tokio::sync::Mutex;
use tokio::sync::oneshot;

use crate::commands::AppState;
use crate::menu::{Language, MenuLanguage};

type Result<T> = std::result::Result<T, VaultError>;

const ENABLED_FILE: &str = "desktop-enabled";

/// The running service; dropping `stop` ends it.
#[derive(Default)]
pub struct ConnectState {
    stop: Mutex<Option<oneshot::Sender<()>>>,
}

fn folder() -> Option<PathBuf> {
    octapass_native_host::ipc::data_dir()
        .and_then(|dir| dir.parent().map(PathBuf::from))
        .map(octapass_connect::folder)
}

fn failed(error: impl ToString) -> VaultError {
    VaultError::unexpected(error.to_string())
}

fn is_enabled() -> bool {
    folder().is_some_and(|dir| dir.join(ENABLED_FILE).exists())
}

/// The approval dialog's words, in the app's language.
struct Prompt {
    title: &'static str,
    unknown_loopback: &'static str,
    unknown: &'static str,
    allow: &'static str,
    deny: &'static str,
    body: fn(&str, &str) -> String,
}

fn prompt(language: Language) -> Prompt {
    match language {
        Language::English => Prompt {
            title: "Allow this program to read secrets?",
            unknown_loopback: "Unknown: over 127.0.0.1 the system can't say which program this is.",
            unknown: "Unknown",
            allow: "Allow",
            deny: "Don't allow",
            body: |name, program| {
                format!(
                    "It calls itself: {name}\nAnyone can claim any name.\n\nProgram: {program}\n\nIt will be able to read secrets by reference for 30 days. Each one is recorded in your security log."
                )
            },
        },
        Language::Arabic => Prompt {
            title: "هل تسمح لهذا البرنامج بقراءة الأسرار؟",
            unknown_loopback: "غير معروف: عبر 127.0.0.1 لا يستطيع النظام معرفة البرنامج.",
            unknown: "غير معروف",
            allow: "السماح",
            deny: "عدم السماح",
            body: |name, program| {
                format!(
                    "يسمّي نفسه: {name}\nيستطيع أي برنامج أن يدّعي أي اسم.\n\nالبرنامج: {program}\n\nسيستطيع قراءة الأسرار عبر المراجع لمدة 30 يومًا، ويُسجَّل كل سر في سجل الأمان."
                )
            },
        },
    }
}

/// A native dialog, off the UI thread, naming what connected, in the app's language.
fn ask(app: AppHandle) -> Ask {
    Arc::new(move |approval: Approval| {
        let app = app.clone();
        Box::pin(async move {
            let language = *app.state::<MenuLanguage>().0.lock().expect("language lock");
            let words = prompt(language);
            let program = match (&approval.peer.program, approval.peer.loopback) {
                (Some(program), _) => program.clone(),
                (None, true) => words.unknown_loopback.to_owned(),
                (None, false) => words.unknown.to_owned(),
            };
            let message = (words.body)(&approval.name, &program);
            let (reply, answer) = oneshot::channel();
            app.dialog()
                .message(message)
                .title(words.title)
                .kind(MessageDialogKind::Warning)
                .buttons(MessageDialogButtons::OkCancelCustom(
                    words.allow.into(),
                    words.deny.into(),
                ))
                .show(move |allowed| {
                    let _ = reply.send(allowed);
                });
            answer.await.unwrap_or(false)
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_prompt_comes_in_both_languages() {
        let (en, ar) = (prompt(Language::English), prompt(Language::Arabic));
        assert_ne!(en.title, ar.title);
        assert_ne!(en.allow, ar.allow);
        let body = (ar.body)("VS Code", "/usr/bin/code");
        assert!(body.contains("VS Code") && body.contains("/usr/bin/code"));
    }
}

async fn start(app: &AppHandle) -> Result<()> {
    let state = app.state::<ConnectState>();
    let mut running = state.stop.lock().await;
    if running.is_some() {
        return Ok(());
    }
    let dir = folder().ok_or_else(|| failed("no data folder for this user"))?;
    server::private_folder(&dir).map_err(failed)?;
    let vault = app.state::<AppState>().vault.clone();
    let backend: Arc<dyn Backend> =
        Arc::new(VaultBackend::new(vault, dir.clone(), ask(app.clone())));
    let (stop, stopped) = oneshot::channel::<()>();
    let until = async move {
        let _ = stopped.await;
    };
    #[cfg(unix)]
    {
        let listener = server::bind_socket(&dir).await.map_err(failed)?;
        tauri::async_runtime::spawn(async move {
            let _ = server::serve_socket(listener, &dir, backend, until).await;
        });
    }
    #[cfg(not(unix))]
    {
        let listener = server::bind_loopback(0).await.map_err(failed)?;
        tauri::async_runtime::spawn(async move {
            let _ = server::serve_loopback(listener, &dir, backend, until).await;
        });
    }
    *running = Some(stop);
    Ok(())
}

/// At launch, when it's on for this device. Another Connect already running isn't an error.
pub fn start_if_enabled(app: &AppHandle) {
    if !is_enabled() {
        return;
    }
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        let _ = start(&app).await;
    });
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectView {
    enabled: bool,
    clients: Vec<Client>,
}

#[tauri::command]
pub fn connect_state() -> Result<ConnectView> {
    let dir = folder().ok_or_else(|| failed("no data folder for this user"))?;
    Ok(ConnectView {
        enabled: is_enabled(),
        clients: Clients::open(&dir).list(),
    })
}

#[tauri::command]
pub async fn set_connect_enabled(app: AppHandle, enabled: bool) -> Result<()> {
    let dir = folder().ok_or_else(|| failed("no data folder for this user"))?;
    server::private_folder(&dir).map_err(failed)?;
    let flag = dir.join(ENABLED_FILE);
    if enabled {
        start(&app).await?;
        std::fs::write(flag, b"").map_err(failed)?;
    } else {
        let state = app.state::<ConnectState>();
        if let Some(stop) = state.stop.lock().await.take() {
            let _ = stop.send(());
        }
        match std::fs::remove_file(flag) {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
                return Err(failed(error));
            }
            _ => {}
        }
    }
    Ok(())
}

#[tauri::command]
pub fn connect_revoke_client(id: String) -> Result<()> {
    let dir = folder().ok_or_else(|| failed("no data folder for this user"))?;
    Clients::open(&dir).revoke(&id).map_err(failed)?;
    Ok(())
}
