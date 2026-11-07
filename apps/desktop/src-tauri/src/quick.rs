//! The quick-access window: a small search box on a global shortcut, to copy a username,
//! password or one-time code, or auto-type a login, without opening the vault window.

use tauri::{AppHandle, Emitter, Manager, WebviewWindow, WindowEvent};
use tauri_plugin_global_shortcut::{Shortcut, ShortcutEvent, ShortcutState};

use crate::autotype::{self, AutoTypeState, Opened};

pub const LABEL: &str = "quick";
pub const SHORTCUT: &str = "CommandOrControl+Shift+Space";

fn window(app: &AppHandle) -> Option<WebviewWindow> {
    app.get_webview_window(LABEL)
}

/// The window hides itself when it loses focus, like Spotlight.
pub fn setup(app: &AppHandle) {
    if let Some(window) = window(app) {
        let hidden = window.clone();
        window.on_window_event(move |event| {
            if let WindowEvent::Focused(false) = event {
                let _ = hidden.hide();
            }
        });
    }
}

/// Both global shortcuts: quick access, and auto-type.
pub fn on_shortcut(app: &AppHandle, shortcut: &Shortcut, event: ShortcutEvent) {
    if event.state() != ShortcutState::Pressed {
        return;
    }
    if autotype::SHORTCUT
        .parse::<Shortcut>()
        .is_ok_and(|auto| &auto == shortcut)
    {
        autotype::on_shortcut(app);
    } else {
        toggle(app);
    }
}

pub fn toggle(app: &AppHandle) {
    if is_visible(app) {
        hide(app);
        return;
    }
    // Before quick access takes focus: auto-type goes back to this window.
    app.state::<AutoTypeState>().remember_target();
    open(app, Opened::default());
}

pub fn is_visible(app: &AppHandle) -> bool {
    window(app).is_some_and(|window| window.is_visible().unwrap_or(false))
}

/// Shows the window and tells the page to start over: clear the last search, focus the box, and
/// for the auto-type shortcut, list the logins for the window.
pub fn open(app: &AppHandle, opened: Opened) {
    reveal(app);
    let _ = app.emit_to(LABEL, "quick://opened", opened);
}

/// Shows the window as it was, e.g. with the reason auto-type stopped.
pub fn reveal(app: &AppHandle) {
    let Some(window) = window(app) else { return };
    let _ = window.center();
    let _ = window.show();
    let _ = window.set_focus();
}

pub fn hide(app: &AppHandle) {
    if let Some(window) = window(app) {
        let _ = window.hide();
    }
}
