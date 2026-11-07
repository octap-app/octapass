//! The app menu: the platform's standard menus plus Vault (quick access, lock, and on Linux, which
//! has no File menu, quit) and Browser (connect or disconnect the browser extension). The tray menu
//! (`tray.rs`) uses the same words. All of it follows the language the vault window shows
//! (`set_language`), the standard Edit, Window and other menus included: the system would otherwise
//! show them in its own language next to ours. The standard items keep their system roles and
//! shortcuts; only their words change.

use std::sync::Mutex;

use tauri::menu::{
    AboutMetadata, HELP_SUBMENU_ID, Menu, MenuEvent, MenuItem, PredefinedMenuItem, Submenu,
    WINDOW_SUBMENU_ID,
};
use tauri::{AppHandle, Manager, Wry};
use tauri_plugin_dialog::{DialogExt, MessageDialogKind};

use crate::commands::AppState;
use crate::{integration, quick, tray};

const VAULT: &str = "vault";
const BROWSER: &str = "browser";
const QUICK_ACCESS: &str = "quick-access";
const LOCK: &str = "lock";
const QUIT: &str = "quit";
const CONNECT_BROWSERS: &str = "connect-browsers";
const DISCONNECT_BROWSERS: &str = "disconnect-browsers";

/// The languages the app's own words come in, as the web UI names them (`en`, `ar`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Language {
    #[default]
    English,
    Arabic,
}

impl Language {
    pub fn from_tag(tag: &str) -> Self {
        if tag == "ar" {
            Self::Arabic
        } else {
            Self::English
        }
    }
}

/// The language the menus are in now.
pub fn current_language(app: &AppHandle) -> Language {
    *app.state::<MenuLanguage>().0.lock().unwrap()
}

/// Every string the menus and their dialogs show.
pub struct Strings {
    pub vault: &'static str,
    /// Shows the vault window, from the tray.
    pub show: &'static str,
    pub quick_access: &'static str,
    pub lock: &'static str,
    pub quit: &'static str,
    pub browser: &'static str,
    pub connect: &'static str,
    pub disconnect: &'static str,
    pub dialog_title: &'static str,
    /// Followed by the system's own description of what failed.
    pub failed: &'static str,
}

pub fn strings(language: Language) -> Strings {
    match language {
        Language::English => Strings {
            vault: "Vault",
            show: "Show Octa Pass",
            quick_access: "Quick access",
            lock: "Lock",
            quit: "Quit Octa Pass",
            browser: "Browser",
            connect: "Connect browser extension",
            disconnect: "Disconnect browser extension",
            dialog_title: "Browser extension",
            failed: "Couldn't change the browser integration:",
        },
        Language::Arabic => Strings {
            vault: "الخزنة",
            show: "إظهار Octa Pass",
            quick_access: "الوصول السريع",
            lock: "قفل",
            quit: "إنهاء Octa Pass",
            browser: "المتصفح",
            connect: "ربط إضافة المتصفح",
            disconnect: "فصل إضافة المتصفح",
            dialog_title: "إضافة المتصفح",
            failed: "تعذّر تغيير الربط مع المتصفح:",
        },
    }
}

/// The standard menus' words. The items are `None` in English, where the system's own words stay.
/// Linux has no File menu.
#[cfg_attr(target_os = "linux", allow(dead_code))]
pub struct StandardStrings {
    pub file: &'static str,
    pub edit: &'static str,
    pub window: &'static str,
    pub help: &'static str,
    pub about: Option<&'static str>,
    pub quit: Option<&'static str>,
    pub close_window: Option<&'static str>,
    pub undo: Option<&'static str>,
    pub redo: Option<&'static str>,
    pub cut: Option<&'static str>,
    pub copy: Option<&'static str>,
    pub paste: Option<&'static str>,
    pub select_all: Option<&'static str>,
    pub minimize: Option<&'static str>,
    pub maximize: Option<&'static str>,
}

pub fn standard_strings(language: Language) -> StandardStrings {
    match language {
        Language::English => StandardStrings {
            file: "File",
            edit: "Edit",
            window: "Window",
            help: "Help",
            about: None,
            quit: None,
            close_window: None,
            undo: None,
            redo: None,
            cut: None,
            copy: None,
            paste: None,
            select_all: None,
            minimize: None,
            maximize: None,
        },
        Language::Arabic => StandardStrings {
            file: "ملف",
            edit: "تحرير",
            window: "نافذة",
            help: "مساعدة",
            about: Some("حول Octa Pass"),
            quit: Some("إنهاء Octa Pass"),
            close_window: Some("إغلاق النافذة"),
            undo: Some("تراجع"),
            redo: Some("إعادة"),
            cut: Some("قص"),
            copy: Some("نسخ"),
            paste: Some("لصق"),
            select_all: Some("تحديد الكل"),
            minimize: Some("تصغير"),
            maximize: Some("تكبير"),
        },
    }
}

/// The language the menus are in now, for the dialogs they open.
#[derive(Default)]
pub struct MenuLanguage(pub Mutex<Language>);

impl MenuLanguage {
    /// The language the vault window shows.
    #[cfg_attr(not(windows), allow(dead_code))]
    pub fn get(&self) -> Language {
        *self.0.lock().unwrap()
    }
}

pub fn build(app: &AppHandle) -> tauri::Result<Menu<Wry>> {
    build_in(app, Language::English)
}

/// The same menus as `Menu::default`, on each platform, plus ours after the app and File menus.
fn build_in(app: &AppHandle, language: Language) -> tauri::Result<Menu<Wry>> {
    let text = strings(language);
    let standard = standard_strings(language);
    let info = app.package_info();
    let about = AboutMetadata {
        name: Some(info.name.clone()),
        version: Some(info.version.to_string()),
        copyright: app.config().bundle.copyright.clone(),
        authors: app.config().bundle.publisher.clone().map(|p| vec![p]),
        ..Default::default()
    };
    let vault = Submenu::with_id_and_items(
        app,
        VAULT,
        text.vault,
        true,
        &[
            &MenuItem::with_id(app, QUICK_ACCESS, text.quick_access, true, None::<&str>)?,
            &MenuItem::with_id(app, LOCK, text.lock, true, Some("CmdOrCtrl+L"))?,
            // Closing the window keeps the app running; this is the way out besides the tray.
            #[cfg(target_os = "linux")]
            &PredefinedMenuItem::separator(app)?,
            #[cfg(target_os = "linux")]
            &MenuItem::with_id(app, QUIT, text.quit, true, Some("CmdOrCtrl+Q"))?,
        ],
    )?;
    let browser = Submenu::with_id_and_items(
        app,
        BROWSER,
        text.browser,
        true,
        &[
            &MenuItem::with_id(app, CONNECT_BROWSERS, text.connect, true, None::<&str>)?,
            &MenuItem::with_id(
                app,
                DISCONNECT_BROWSERS,
                text.disconnect,
                true,
                None::<&str>,
            )?,
        ],
    )?;
    let window = Submenu::with_id_and_items(
        app,
        WINDOW_SUBMENU_ID,
        standard.window,
        true,
        &[
            &PredefinedMenuItem::minimize(app, standard.minimize)?,
            &PredefinedMenuItem::maximize(app, standard.maximize)?,
            &PredefinedMenuItem::close_window(app, standard.close_window)?,
        ],
    )?;
    let help = Submenu::with_id_and_items(
        app,
        HELP_SUBMENU_ID,
        standard.help,
        true,
        &[&PredefinedMenuItem::about(
            app,
            standard.about,
            Some(about),
        )?],
    )?;
    let edit = Submenu::with_items(
        app,
        standard.edit,
        true,
        &[
            &PredefinedMenuItem::undo(app, standard.undo)?,
            &PredefinedMenuItem::redo(app, standard.redo)?,
            &PredefinedMenuItem::separator(app)?,
            &PredefinedMenuItem::cut(app, standard.cut)?,
            &PredefinedMenuItem::copy(app, standard.copy)?,
            &PredefinedMenuItem::paste(app, standard.paste)?,
            &PredefinedMenuItem::select_all(app, standard.select_all)?,
        ],
    )?;
    Menu::with_items(
        app,
        &[
            #[cfg(not(any(
                target_os = "linux",
                target_os = "dragonfly",
                target_os = "freebsd",
                target_os = "netbsd",
                target_os = "openbsd"
            )))]
            &Submenu::with_items(
                app,
                standard.file,
                true,
                &[
                    &PredefinedMenuItem::close_window(app, standard.close_window)?,
                    &PredefinedMenuItem::quit(app, standard.quit)?,
                ],
            )?,
            &vault,
            &browser,
            &edit,
            &window,
            &help,
        ],
    )
}

/// Puts the whole menu bar in `language`.
pub fn set_language(app: &AppHandle, language: Language) -> tauri::Result<()> {
    let state = app.state::<MenuLanguage>();
    let previous = std::mem::replace(&mut *state.0.lock().unwrap(), language);
    if previous == language {
        return Ok(());
    }
    app.set_menu(build_in(app, language)?)?;
    tray::set_language(app, language);
    Ok(())
}

pub fn on_event(app: &AppHandle, event: MenuEvent) {
    match event.id().as_ref() {
        QUICK_ACCESS => quick::toggle(app),
        LOCK => app.state::<AppState>().vault.lock(),
        QUIT => app.exit(0),
        CONNECT_BROWSERS => report(app, integration::install()),
        DISCONNECT_BROWSERS => report(app, integration::uninstall()),
        _ => {}
    }
}

fn report(app: &AppHandle, result: Result<integration::Change, String>) {
    let language = *app.state::<MenuLanguage>().0.lock().unwrap();
    let text = strings(language);
    let (message, kind) = match result {
        Ok(change) => (change.message(language), MessageDialogKind::Info),
        Err(error) => (format!("{} {error}", text.failed), MessageDialogKind::Error),
    };
    app.dialog()
        .message(message)
        .title(text.dialog_title)
        .kind(kind)
        .show(|_| {});
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_web_ui_language_tags() {
        assert_eq!(Language::from_tag("ar"), Language::Arabic);
        assert_eq!(Language::from_tag("en"), Language::English);
        assert_eq!(Language::from_tag("fr"), Language::English);
    }

    #[test]
    fn every_language_names_every_menu() {
        for language in [Language::English, Language::Arabic] {
            let text = strings(language);
            for label in [
                text.vault,
                text.show,
                text.quick_access,
                text.lock,
                text.quit,
                text.browser,
                text.connect,
                text.disconnect,
                text.dialog_title,
                text.failed,
            ] {
                assert!(!label.is_empty());
            }
        }
        assert_ne!(
            strings(Language::Arabic).lock,
            strings(Language::English).lock
        );
        assert_ne!(
            strings(Language::Arabic).quit,
            strings(Language::English).quit
        );
    }

    #[test]
    fn the_standard_menus_are_translated_and_english_stays_the_systems() {
        let english = standard_strings(Language::English);
        let arabic = standard_strings(Language::Arabic);
        for (one, other) in [
            (english.file, arabic.file),
            (english.edit, arabic.edit),
            (english.window, arabic.window),
            (english.help, arabic.help),
        ] {
            assert_ne!(one, other);
        }
        for (english, arabic) in [
            (english.about, arabic.about),
            (english.quit, arabic.quit),
            (english.close_window, arabic.close_window),
            (english.undo, arabic.undo),
            (english.redo, arabic.redo),
            (english.cut, arabic.cut),
            (english.copy, arabic.copy),
            (english.paste, arabic.paste),
            (english.select_all, arabic.select_all),
            (english.minimize, arabic.minimize),
            (english.maximize, arabic.maximize),
        ] {
            assert_eq!(english, None);
            assert!(arabic.is_some_and(|text| !text.is_empty()));
        }
    }
}
