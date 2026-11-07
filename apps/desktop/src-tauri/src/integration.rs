//! Browser integration: installs the native messaging manifests that point the browsers at the
//! `octapass-native-host` shipped next to the app, or removes them. From the app's Browser menu,
//! or from the command line for installers and uninstallers.

use std::path::PathBuf;

use octapass_native_host::manifests::{self, Browser, Locations};

use crate::menu::Language;

const HOST_BINARY: &str = if cfg!(windows) {
    "octapass-native-host.exe"
} else {
    "octapass-native-host"
};

/// Where the host binary belongs: next to the app's own executable.
pub fn bundled_host() -> Result<PathBuf, String> {
    let exe = std::env::current_exe().map_err(|error| error.to_string())?;
    Ok(exe.with_file_name(HOST_BINARY))
}

/// The host binary, which must exist.
pub fn host_path() -> Result<PathBuf, String> {
    let host = bundled_host()?;
    if host.is_file() {
        Ok(host)
    } else {
        Err(format!("{} is missing", host.display()))
    }
}

fn locations() -> Result<Locations, String> {
    Locations::for_user().ok_or_else(|| "no home folder for this user".to_owned())
}

fn names(browsers: &[Browser]) -> String {
    browsers
        .iter()
        .map(|browser| browser.name())
        .collect::<Vec<_>>()
        .join(", ")
}

/// What connecting or disconnecting the browsers did.
#[derive(Debug, PartialEq, Eq)]
pub enum Change {
    Installed(Vec<Browser>),
    Removed(Vec<Browser>),
}

impl Change {
    pub fn message(&self, language: Language) -> String {
        match (self, language) {
            (Self::Installed(browsers), _) if browsers.is_empty() => match language {
                Language::English => "No supported browser was found. Install Chrome, Edge, Brave or Firefox, then try again.".into(),
                Language::Arabic => "لم يُعثر على متصفح مدعوم. ثبّت Chrome أو Edge أو Brave أو Firefox، ثم حاول مرة أخرى.".into(),
            },
            (Self::Installed(browsers), Language::English) => {
                format!("The Octa Pass extension can now unlock through this app in {}.", names(browsers))
            }
            (Self::Installed(browsers), Language::Arabic) => {
                format!("أصبح بإمكان إضافة Octa Pass فتح القفل عبر هذا التطبيق في {}.", names(browsers))
            }
            (Self::Removed(browsers), _) if browsers.is_empty() => match language {
                Language::English => "Browser integration wasn't installed.".into(),
                Language::Arabic => "لم يكن الربط مع المتصفح مثبّتًا.".into(),
            },
            (Self::Removed(browsers), Language::English) => {
                format!("Removed browser integration from {}.", names(browsers))
            }
            (Self::Removed(browsers), Language::Arabic) => {
                format!("أُزيل الربط مع المتصفح من {}.", names(browsers))
            }
        }
    }
}

pub fn install() -> Result<Change, String> {
    let installed =
        manifests::install(&locations()?, &host_path()?).map_err(|error| error.to_string())?;
    Ok(Change::Installed(installed))
}

pub fn uninstall() -> Result<Change, String> {
    let removed = manifests::uninstall(&locations()?).map_err(|error| error.to_string())?;
    Ok(Change::Removed(removed))
}

/// `--install-browser-integration` and `--uninstall-browser-integration` run without the UI.
/// Returns the exit code when one of them was given.
pub fn run_cli(args: &[String]) -> Option<i32> {
    let result = match args.first().map(String::as_str) {
        Some("--install-browser-integration") => install(),
        Some("--uninstall-browser-integration") => uninstall(),
        _ => return None,
    };
    Some(match result {
        Ok(change) => {
            println!("{}", change.message(Language::English));
            0
        }
        Err(error) => {
            eprintln!("error: {error}");
            1
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn says_what_changed_in_each_language() {
        let none = Change::Installed(vec![]);
        assert!(
            none.message(Language::English)
                .starts_with("No supported browser")
        );
        assert!(none.message(Language::Arabic).starts_with("لم يُعثر"));
        assert_eq!(
            Change::Removed(vec![]).message(Language::English),
            "Browser integration wasn't installed."
        );
    }
}
