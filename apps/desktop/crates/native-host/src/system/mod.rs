//! [`crate::trust::System`] for this OS, and the process on the other end of the app's socket
//! or pipe.

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(windows)]
mod windows;

#[cfg(target_os = "linux")]
pub use linux::{OsSystem, peer};
#[cfg(target_os = "macos")]
pub use macos::{OsSystem, own_team, peer};
#[cfg(windows)]
pub use windows::{OsSystem, peer};

/// The Unix session a process belongs to: one terminal window or tab.
#[cfg(unix)]
pub fn session(pid: u32) -> Option<u32> {
    // SAFETY: plain call.
    let session = unsafe { libc::getsid(pid as libc::pid_t) };
    u32::try_from(session).ok()
}

#[cfg(windows)]
pub fn session(_pid: u32) -> Option<u32> {
    None
}

/// Owned by root, as is its folder, and neither writable by anyone else.
#[cfg(unix)]
fn root_owned(path: &std::path::Path) -> std::io::Result<bool> {
    use std::os::unix::fs::MetadataExt;
    let only_root = |path: &std::path::Path| {
        std::fs::metadata(path).map(|metadata| metadata.uid() == 0 && metadata.mode() & 0o022 == 0)
    };
    let folder = path.parent().unwrap_or(path);
    Ok(only_root(path)? && only_root(folder)?)
}

#[cfg(all(test, unix))]
mod tests {
    use std::path::Path;

    use super::*;

    #[test]
    fn system_files_are_root_owned_and_ours_are_not() {
        assert!(root_owned(Path::new("/bin/sh")).unwrap());
        let file = tempfile::NamedTempFile::new().unwrap();
        assert!(!root_owned(file.path()).unwrap());
        assert!(root_owned(Path::new("/nonexistent/x")).is_err());
    }
}
