//! Octa Pass on the file system (plan 16 §4), shared by the CLI, the desktop app and the phones.
//!
//! - [`files`]: `octapass encrypt` and `decrypt`: files and folders in the age format.
//! - [`shred`]: secure delete, honest about what the disk underneath can promise.
//! - [`menu`]: the right-click menus of Finder, Explorer, Nautilus and Dolphin.
//! - [`safe`]: Octa Pass Safe, the encrypted drive: the blob store, the file tree, writes, sync.
//! - [`safe::fuse`] mounts a Safe on Linux, and on macOS with macFUSE.
//!
//! The cryptography itself is in `octapass-core` (`tools::age`, `safe`): this crate does the I/O.

#[cfg(feature = "age-files")]
pub mod files;
pub mod menu;
pub mod safe;
pub mod shred;
