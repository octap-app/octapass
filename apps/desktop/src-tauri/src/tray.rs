//! The tray icon, for while the app runs in the background: show the vault window, quick access,
//! lock and quit. On by default; Settings hides it (`background.rs`). Its words follow the menu
//! bar's language, and Lock is only offered while the vault is unlocked.
//!
//! Windows opens the vault window on a left click and the menu on a right click,
//! as other apps there do. Linux shows the menu on any click (AppIndicator); GNOME needs the
//! AppIndicator extension to show tray icons at all.

use std::sync::Mutex;

use tauri::image::Image;
use tauri::menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIcon, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Manager, Wry};

use crate::commands::AppState;
use crate::menu::{self, Language};
use crate::quick;

const ID: &str = "main";
const SHOW: &str = "tray-show";
const QUICK_ACCESS: &str = "tray-quick-access";
const LOCK: &str = "tray-lock";
const QUIT: &str = "tray-quit";

/// The items whose words and state change. On Linux a tray menu can't be replaced once set, so
/// they're changed in place.
struct Items {
    show: MenuItem<Wry>,
    quick_access: MenuItem<Wry>,
    lock: MenuItem<Wry>,
    quit: MenuItem<Wry>,
}

#[derive(Default)]
pub struct TrayState(Mutex<Option<Items>>);

fn icon() -> Image<'static> {
    tauri::include_image!("icons/32x32.png")
}

/// Makes the tray icon, shown or not. The vault is locked when the app starts.
pub fn create(app: &AppHandle, visible: bool) -> tauri::Result<()> {
    let text = menu::strings(menu::current_language(app));
    let items = Items {
        show: MenuItem::with_id(app, SHOW, text.show, true, None::<&str>)?,
        quick_access: MenuItem::with_id(app, QUICK_ACCESS, text.quick_access, true, None::<&str>)?,
        lock: MenuItem::with_id(app, LOCK, text.lock, false, None::<&str>)?,
        quit: MenuItem::with_id(app, QUIT, text.quit, true, None::<&str>)?,
    };
    let tray_menu = Menu::with_items(
        app,
        &[
            &items.show,
            &items.quick_access,
            &PredefinedMenuItem::separator(app)?,
            &items.lock,
            &PredefinedMenuItem::separator(app)?,
            &items.quit,
        ],
    )?;
    let tray = TrayIconBuilder::with_id(ID)
        .icon(icon())
        .tooltip("Octa Pass")
        .menu(&tray_menu)
        .show_menu_on_left_click(!cfg!(windows))
        .on_menu_event(on_menu_event)
        .on_tray_icon_event(on_icon_event)
        .build(app)?;
    tray.set_visible(visible)?;
    *app.state::<TrayState>().0.lock().unwrap() = Some(items);
    Ok(())
}

pub fn set_visible(app: &AppHandle, visible: bool) {
    if let Some(tray) = app.tray_by_id(ID) {
        let _ = tray.set_visible(visible);
    }
}

/// Lock is offered only while there's something to lock. Session events can come before the tray
/// exists.
pub fn session_changed(app: &AppHandle, unlocked: bool) {
    let Some(state) = app.try_state::<TrayState>() else {
        return;
    };
    if let Some(items) = state.0.lock().unwrap().as_ref() {
        let _ = items.lock.set_enabled(unlocked);
    }
}

pub fn set_language(app: &AppHandle, language: Language) {
    let text = menu::strings(language);
    let Some(state) = app.try_state::<TrayState>() else {
        return;
    };
    if let Some(items) = state.0.lock().unwrap().as_ref() {
        let _ = items.show.set_text(text.show);
        let _ = items.quick_access.set_text(text.quick_access);
        let _ = items.lock.set_text(text.lock);
        let _ = items.quit.set_text(text.quit);
    }
}

/// Every menu event reaches this handler, the menu bar's too; only the tray's own are handled.
fn on_menu_event(app: &AppHandle, event: MenuEvent) {
    match event.id().as_ref() {
        SHOW => crate::show_main(app),
        QUICK_ACCESS => quick::toggle(app),
        LOCK => app.state::<AppState>().vault.lock(),
        QUIT => app.exit(0),
        _ => {}
    }
}

fn on_icon_event(tray: &TrayIcon, event: TrayIconEvent) {
    if cfg!(windows)
        && let TrayIconEvent::Click {
            button: MouseButton::Left,
            button_state: MouseButtonState::Up,
            ..
        } = event
    {
        crate::show_main(tray.app_handle());
    }
}
