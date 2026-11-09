//! Opening the Octa Pass desktop app when the person signs in to the computer, in the background:
//! the system starts it with [`HIDDEN_ARG`], so the tray icon, quick access, the browser bridge and
//! the agents are there, and the vault window isn't.
//!
//! - **macOS:** a launch agent in `~/Library/LaunchAgents` that runs the app's executable. It's
//!   listed in System Settings → General → Login Items → Allow in the Background.
//! - **Windows:** a value under `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`. Task
//!   Manager's Startup apps page turns it off with an entry of its own (`StartupApproved`), which
//!   counts here as off.
//! - **Linux:** an XDG autostart entry in `~/.config/autostart`. `Hidden=true` and
//!   `X-GNOME-Autostart-enabled=false`, which desktop settings write to turn it off, count as off.
//!
//! The files and values are written and read by plain functions in each module, compiled and tested
//! everywhere; only the registry calls are behind `cfg(windows)`.
//!
//! [`watchdog`] keeps it there for the rest of the session: started again with [`HIDDEN_ARG`]
//! when it's force quit or crashes, until it's quit on purpose.

use std::io;
use std::path::{Path, PathBuf};

pub mod linux;
pub mod macos;
pub mod watchdog;
pub mod windows;

/// The argument the system starts the app with at login: stay in the background.
pub const HIDDEN_ARG: &str = "--hidden";

/// What the system starts at login.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registered {
    /// The program, started with [`HIDDEN_ARG`].
    pub program: PathBuf,
    /// `false` when the person turned it off in the system's own settings.
    pub enabled: bool,
}

/// This user's login item for the app, on one system.
pub trait LoginItem {
    /// What's registered now, if anything.
    fn registered(&self) -> io::Result<Option<Registered>>;
    /// Starts `program --hidden` at login, replacing what was registered, and turns it back on
    /// where the system's own settings had turned it off.
    fn register(&self, program: &Path) -> io::Result<()>;
    /// Removes it. Nothing registered is fine.
    fn unregister(&self) -> io::Result<()>;
}

/// Whether the app opens at login.
pub fn is_on(item: &dyn LoginItem) -> io::Result<bool> {
    Ok(item.registered()?.is_some_and(|found| found.enabled))
}

/// The login item for this user on this system; `None` without a home folder.
pub fn system() -> Option<Box<dyn LoginItem + Send + Sync>> {
    #[cfg(target_os = "macos")]
    {
        Some(Box::new(macos::LaunchAgent::for_user(&dirs::home_dir()?)))
    }
    #[cfg(windows)]
    {
        Some(Box::new(windows::RunKey))
    }
    #[cfg(not(any(target_os = "macos", windows)))]
    {
        Some(Box::new(linux::Autostart::for_user(&dirs::config_dir()?)))
    }
}

/// The program to register: this executable, or on Linux the AppImage it was started from (the
/// executable itself is inside the AppImage's temporary mount).
pub fn current_program() -> io::Result<PathBuf> {
    if cfg!(target_os = "linux")
        && let Some(appimage) = std::env::var_os("APPIMAGE").filter(|path| !path.is_empty())
    {
        return Ok(PathBuf::from(appimage));
    }
    std::env::current_exe()
}

/// Whether `program` will still be there after a restart: not on a mounted disk image, inside
/// macOS's App Translocation copy (an app opened from Downloads before it was moved) or inside an
/// AppImage's temporary mount.
pub fn is_installed(program: &Path) -> bool {
    let path = program.to_string_lossy();
    !(path.contains("/AppTranslocation/")
        || path.starts_with("/Volumes/")
        || path.starts_with("/tmp/.mount_"))
}

/// What [`at_startup`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Startup {
    Unchanged,
    /// The first start turned it on.
    Registered,
    /// The app is somewhere else now, and the login item follows it.
    Moved,
}

/// At each start of an installed app. The first time (`first_time`), it turns opening at login on:
/// it's on by default. After that it only follows the app to where it is now, if it's on: a login
/// item the person removed or turned off in the system stays that way.
pub fn at_startup(item: &dyn LoginItem, program: &Path, first_time: bool) -> io::Result<Startup> {
    match item.registered()? {
        None if first_time => {
            item.register(program)?;
            Ok(Startup::Registered)
        }
        Some(found) if found.enabled && found.program != program => {
            item.register(program)?;
            Ok(Startup::Moved)
        }
        _ => Ok(Startup::Unchanged),
    }
}

/// Writes `text` to `path` through a temporary file next to it, so a crash never leaves half an
/// entry the system would try to start.
pub(crate) fn write_file(path: &Path, text: &str) -> io::Result<()> {
    let folder = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no parent folder"))?;
    std::fs::create_dir_all(folder)?;
    let temporary = path.with_extension("tmp");
    std::fs::write(&temporary, text)?;
    std::fs::rename(&temporary, path)
}

/// Removes `path`; a missing file is fine.
pub(crate) fn remove_file(path: &Path) -> io::Result<()> {
    match std::fs::remove_file(path) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error),
        _ => Ok(()),
    }
}

/// Reads `path`; a missing file is `None`.
pub(crate) fn read_file(path: &Path) -> io::Result<Option<String>> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(Some(text)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;

    #[derive(Default)]
    struct Fake {
        entry: RefCell<Option<Registered>>,
        writes: RefCell<usize>,
    }

    impl LoginItem for Fake {
        fn registered(&self) -> io::Result<Option<Registered>> {
            Ok(self.entry.borrow().clone())
        }
        fn register(&self, program: &Path) -> io::Result<()> {
            *self.writes.borrow_mut() += 1;
            *self.entry.borrow_mut() = Some(Registered {
                program: program.into(),
                enabled: true,
            });
            Ok(())
        }
        fn unregister(&self) -> io::Result<()> {
            *self.entry.borrow_mut() = None;
            Ok(())
        }
    }

    fn with(program: &str, enabled: bool) -> Fake {
        Fake {
            entry: RefCell::new(Some(Registered {
                program: program.into(),
                enabled,
            })),
            ..Fake::default()
        }
    }

    #[test]
    fn the_first_start_turns_it_on() {
        let item = Fake::default();
        let program = Path::new("/Applications/Octa Pass.app/Contents/MacOS/octapass-desktop");
        assert_eq!(
            at_startup(&item, program, true).unwrap(),
            Startup::Registered
        );
        assert!(is_on(&item).unwrap());
        assert_eq!(item.registered().unwrap().unwrap().program, program);
    }

    #[test]
    fn later_starts_leave_a_removed_login_item_off() {
        let item = Fake::default();
        assert_eq!(
            at_startup(&item, Path::new("/usr/bin/octapass-desktop"), false).unwrap(),
            Startup::Unchanged
        );
        assert!(!is_on(&item).unwrap());
    }

    #[test]
    fn it_follows_the_app_when_it_moved() {
        let item = with("/home/ada/Downloads/Octa_Pass.AppImage", true);
        let program = Path::new("/home/ada/Apps/Octa_Pass.AppImage");
        assert_eq!(at_startup(&item, program, false).unwrap(), Startup::Moved);
        assert_eq!(item.registered().unwrap().unwrap().program, program);
    }

    #[test]
    fn it_leaves_an_entry_alone_when_nothing_changed() {
        let item = with("/usr/bin/octapass-desktop", true);
        let program = Path::new("/usr/bin/octapass-desktop");
        assert_eq!(
            at_startup(&item, program, true).unwrap(),
            Startup::Unchanged
        );
        assert_eq!(*item.writes.borrow(), 0);
    }

    #[test]
    fn it_never_turns_back_on_what_the_system_turned_off() {
        let item = with("/old/octapass-desktop", false);
        assert_eq!(
            at_startup(&item, Path::new("/usr/bin/octapass-desktop"), true).unwrap(),
            Startup::Unchanged
        );
        assert!(!is_on(&item).unwrap());
        assert_eq!(*item.writes.borrow(), 0);
    }

    #[test]
    fn disk_images_and_translocated_apps_are_not_installed() {
        for path in [
            "/private/var/folders/xy/T/AppTranslocation/1234/d/Octa Pass.app/Contents/MacOS/octapass-desktop",
            "/Volumes/Octa Pass/Octa Pass.app/Contents/MacOS/octapass-desktop",
            "/tmp/.mount_OpenPaXyz/usr/bin/octapass-desktop",
        ] {
            assert!(!is_installed(Path::new(path)), "{path}");
        }
        for path in [
            "/Applications/Octa Pass.app/Contents/MacOS/octapass-desktop",
            "/usr/bin/octapass-desktop",
            r"C:\Users\Ada\AppData\Local\Octa Pass\octapass-desktop.exe",
        ] {
            assert!(is_installed(Path::new(path)), "{path}");
        }
    }

    #[test]
    fn files_are_replaced_whole_and_removing_nothing_is_fine() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("deeper").join("entry");
        write_file(&path, "one").unwrap();
        write_file(&path, "two").unwrap();
        assert_eq!(read_file(&path).unwrap().as_deref(), Some("two"));
        remove_file(&path).unwrap();
        remove_file(&path).unwrap();
        assert_eq!(read_file(&path).unwrap(), None);
    }
}
