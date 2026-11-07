//! The Tools → Files screen: encrypting and decrypting files, secure delete, Safes and the
//! right-click menus. The work is in `octapass-files`.
//!
//! **The web view can only name paths the user handed over**: dropped on the window, chosen in a
//! dialog, or sent from a right-click menu. It has no file system access of its own (see the
//! capability file), and these commands read, write and delete, so they check every path against
//! that list. A script in the page can't reach the rest of the disk through them.
//!
//! Right-click menus start this same program with `--files <action> <paths>`. A second copy of the
//! app can't take over the window, so it drops the request in a folder and leaves, starting the app
//! when it isn't running; the running app picks requests up every second.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use octapass_core::tools::age::{self, Keys, Target};
use octapass_desktop_vault::vault::safes::{FileRecipient, SafeInfo};
use octapass_desktop_vault::{ErrorCode, Vault, VaultError};
use octapass_files::files::{self, FilesError};
use octapass_files::menu::{self, Language, Launcher, Locations, Surface};
use octapass_files::safe::sync::SyncReport;
use octapass_files::safe::{Entry, Safe, SafeError, Warning};
use octapass_files::shred::{self, Guarantee, Storage};
use octapass_native_host::ipc;
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager, State};
use tauri_plugin_dialog::DialogExt;
use zeroize::Zeroizing;

use crate::commands::AppState;

const REQUESTS: &str = "file-requests";
const SAFES: &str = "safes";
/// Under the home folder: where an unlocked Safe shows as a folder.
#[cfg(any(windows, all(target_os = "linux", feature = "fuse")))]
const MOUNTS: &str = "Octa Pass Safe";
const POLL: Duration = Duration::from_secs(1);

type Result<T> = std::result::Result<T, VaultError>;

#[cfg(all(target_os = "linux", feature = "fuse"))]
type SafeMount = octapass_files::safe::fuse::Mount;
#[cfg(windows)]
type SafeMount = octapass_files::safe::cloud_files::CloudFilesMount;

/// What a page may call a path, and the open Safes.
#[derive(Default)]
pub struct FilesState {
    granted: Mutex<HashSet<PathBuf>>,
    safes: Mutex<HashMap<String, Arc<Safe>>>,
    #[cfg(any(windows, all(target_os = "linux", feature = "fuse")))]
    mounts: Mutex<HashMap<String, SafeMount>>,
    /// What went wrong the last time Safes locked (a file Windows kept open, an edit that couldn't
    /// be saved), shown on the Files screen the next time it opens.
    lock_problems: Mutex<Vec<String>>,
}

impl FilesState {
    pub fn grant(&self, paths: &[PathBuf]) {
        let mut granted = self.granted.lock().unwrap_or_else(|e| e.into_inner());
        granted.extend(paths.iter().cloned());
    }

    fn allowed(&self, path: &Path) -> bool {
        let granted = self.granted.lock().unwrap_or_else(|e| e.into_inner());
        path.ancestors().any(|one| granted.contains(one))
    }

    fn check(&self, paths: &[String]) -> Result<Vec<PathBuf>> {
        paths
            .iter()
            .map(PathBuf::from)
            .map(|path| {
                if self.allowed(&path) {
                    Ok(path)
                } else {
                    Err(ErrorCode::NotAllowed.into())
                }
            })
            .collect()
    }

    pub(crate) fn open(&self, item_id: &str) -> Option<Arc<Safe>> {
        self.safes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(item_id)
            .cloned()
    }

    /// Everything goes when the vault locks: mounts first, so nothing reads while keys are dropped.
    pub fn lock_all(&self) {
        let mut problems = Vec::new();
        #[cfg(windows)]
        for (_, mut mount) in self
            .mounts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .drain()
        {
            if let Err(error) = mount.lock() {
                problems.push(error.to_string());
            }
        }
        #[cfg(all(target_os = "linux", feature = "fuse"))]
        self.mounts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        let safes = std::mem::take(&mut *self.safes.lock().unwrap_or_else(|e| e.into_inner()));
        for safe in safes.values() {
            if let Err(error) = safe.lock() {
                problems.push(error.to_string());
            }
        }
        if !problems.is_empty() {
            self.lock_problems
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .extend(problems);
        }
    }

    /// The Safes open now, for the background sync.
    pub fn open_safes(&self) -> Vec<(String, Arc<Safe>)> {
        self.safes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .map(|(id, safe)| (id.clone(), Arc::clone(safe)))
            .collect()
    }
}

fn storage_failure(message: impl std::fmt::Display) -> VaultError {
    VaultError::unexpected(message.to_string())
}

fn files_failure(error: FilesError) -> VaultError {
    match error {
        FilesError::Exists(_) => ErrorCode::AlreadyExists.into(),
        FilesError::NotFound(_) => ErrorCode::NotFound.into(),
        FilesError::Age(age::AgeError::WrongPassphrase) => ErrorCode::WrongPassphrase.into(),
        other => storage_failure(other),
    }
}

fn safe_failure(error: SafeError) -> VaultError {
    match error {
        SafeError::Locked => ErrorCode::Locked.into(),
        SafeError::NotFound => ErrorCode::NotFound.into(),
        SafeError::Exists => ErrorCode::AlreadyExists.into(),
        other => storage_failure(other),
    }
}

// ---------- The files on the page ----------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalFile {
    path: String,
    name: String,
    size: u64,
    folder: bool,
    /// An age file, by its first bytes.
    encrypted: bool,
    /// What deleting it securely can promise here.
    storage: Storage,
    guarantee: Guarantee,
}

fn describe_one(path: &Path) -> Result<LocalFile> {
    let metadata = fs::metadata(path).map_err(|_| VaultError::from(ErrorCode::NotFound))?;
    let mut head = [0u8; age::ARMOR_MAGIC.len()];
    let read = if metadata.is_file() {
        use std::io::Read;
        fs::File::open(path)
            .and_then(|mut file| file.read(&mut head))
            .unwrap_or(0)
    } else {
        0
    };
    let storage = shred::storage_of(path);
    Ok(LocalFile {
        path: path.display().to_string(),
        name: path
            .file_name()
            .map_or_else(String::new, |name| name.to_string_lossy().into_owned()),
        size: metadata.len(),
        folder: metadata.is_dir(),
        encrypted: age::looks_encrypted(&head[..read]),
        storage,
        guarantee: storage.guarantee(),
    })
}

#[tauri::command]
pub fn describe_files(state: State<'_, FilesState>, paths: Vec<String>) -> Result<Vec<LocalFile>> {
    state
        .check(&paths)?
        .iter()
        .map(|path| describe_one(path))
        .collect()
}

/// The system's file or folder dialog. What's chosen becomes usable by the page.
#[tauri::command]
pub async fn choose_files(
    app: AppHandle,
    state: State<'_, FilesState>,
    folder: bool,
) -> Result<Vec<String>> {
    let dialog = app.dialog().file();
    let (sender, receiver) = tokio::sync::oneshot::channel();
    if folder {
        dialog.pick_folder(move |picked| {
            let _ = sender.send(picked.into_iter().collect::<Vec<_>>());
        });
    } else {
        dialog.pick_files(move |picked| {
            let _ = sender.send(picked.unwrap_or_default());
        });
    }
    let picked = receiver.await.unwrap_or_default();
    let paths: Vec<PathBuf> = picked
        .into_iter()
        .filter_map(|path| path.into_path().ok())
        .collect();
    state.grant(&paths);
    Ok(paths
        .iter()
        .map(|path| path.display().to_string())
        .collect())
}

// ---------- Encrypting ----------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", tag = "kind")]
pub enum FileTarget {
    /// The account's own file key.
    Yourself,
    /// Octa Pass accounts' emails, or `age1…` keys. `yourself` keeps a way in for you too.
    People {
        to: Vec<String>,
        yourself: bool,
    },
    Passphrase {
        passphrase: String,
    },
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FileResult {
    source: String,
    output: String,
    bytes: u64,
    skipped: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    shredded: Option<Guarantee>,
    #[serde(skip_serializing_if = "Option::is_none")]
    storage: Option<Storage>,
}

#[tauri::command]
pub async fn encrypt_files(
    state: State<'_, AppState>,
    files_state: State<'_, FilesState>,
    paths: Vec<String>,
    target: FileTarget,
    armor: bool,
    shred_originals: bool,
) -> Result<Vec<FileResult>> {
    let paths = files_state.check(&paths)?;
    let mut recipients = Vec::new();
    let passphrase = match target {
        FileTarget::Yourself => {
            recipients.push(state.vault.file_keys()?.file_recipient.clone());
            None
        }
        FileTarget::People { to, yourself } => {
            if yourself {
                recipients.push(state.vault.file_keys()?.file_recipient.clone());
            }
            for who in to {
                if who.starts_with("age1") {
                    recipients.push(age::check_recipient(&who).map_err(|_| ErrorCode::NotAllowed)?);
                } else {
                    recipients.push(state.vault.file_recipient(&who).await?.recipient);
                }
            }
            None
        }
        FileTarget::Passphrase { passphrase } => Some(Zeroizing::new(passphrase)),
    };
    tauri::async_runtime::spawn_blocking(move || {
        let target = match &passphrase {
            Some(passphrase) => Target::Passphrase(passphrase),
            None => Target::Recipients(&recipients),
        };
        paths
            .iter()
            .map(|path| {
                let output = files::encrypted_name(path, path.is_dir());
                let done = files::encrypt_path(path, &target, armor, &output, false)
                    .map_err(files_failure)?;
                let report = if shred_originals {
                    Some(shred::shred(path).map_err(storage_failure)?)
                } else {
                    None
                };
                Ok(FileResult {
                    source: path.display().to_string(),
                    output: done.output.display().to_string(),
                    bytes: done.bytes,
                    skipped: done
                        .skipped
                        .iter()
                        .map(|path| path.display().to_string())
                        .collect(),
                    shredded: report.as_ref().map(|report| report.guarantee),
                    storage: report.as_ref().map(|report| report.storage),
                })
            })
            .collect::<Result<Vec<_>>>()
    })
    .await
    .map_err(storage_failure)?
}

#[tauri::command]
pub async fn decrypt_files(
    state: State<'_, AppState>,
    files_state: State<'_, FilesState>,
    paths: Vec<String>,
    passphrase: Option<String>,
) -> Result<Vec<FileResult>> {
    let paths = files_state.check(&paths)?;
    let needs: Vec<bool> = paths
        .iter()
        .map(|path| files::needs_passphrase(path).map_err(files_failure))
        .collect::<Result<_>>()?;
    let identities = if needs.iter().all(|needed| *needed) {
        Vec::new()
    } else {
        state.vault.file_keys()?.identities()
    };
    let keys = Keys {
        identities,
        passphrase: passphrase.map(Zeroizing::new),
    };
    if needs.iter().any(|needed| *needed) && keys.passphrase.is_none() {
        return Err(ErrorCode::PasswordRequired.into());
    }
    tauri::async_runtime::spawn_blocking(move || {
        paths
            .iter()
            .map(|path| {
                let Some((output, folder)) = files::decrypted_name(path) else {
                    return Err(ErrorCode::NotAllowed.into());
                };
                let done = if folder {
                    files::decrypt_folder(path, &keys, &output)
                } else {
                    files::decrypt_file(path, &keys, &output, false)
                }
                .map_err(files_failure)?;
                Ok(FileResult {
                    source: path.display().to_string(),
                    output: done.output.display().to_string(),
                    bytes: done.bytes,
                    skipped: Vec::new(),
                    shredded: None,
                    storage: None,
                })
            })
            .collect::<Result<Vec<_>>>()
    })
    .await
    .map_err(storage_failure)?
}

#[tauri::command]
pub async fn find_file_recipient(
    state: State<'_, AppState>,
    email: String,
) -> Result<FileRecipient> {
    state.vault.file_recipient(&email).await
}

/// `age1…`: what other age tools encrypt to, to reach this account.
#[tauri::command]
pub fn own_file_recipient(state: State<'_, AppState>) -> Result<String> {
    Ok(state.vault.file_keys()?.file_recipient.clone())
}

// ---------- Right-click menus ----------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MenuStatus {
    surface: Surface,
    installed: bool,
}

fn locations() -> Result<Locations> {
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .ok_or(ErrorCode::NotFound)?;
    let mut locations = Locations::under(&home);
    if let Some(data) = std::env::var_os("XDG_DATA_HOME") {
        locations.data = PathBuf::from(data);
    }
    Ok(locations)
}

#[tauri::command]
pub fn context_menu_status() -> Result<Vec<MenuStatus>> {
    let locations = locations()?;
    Ok(menu::surfaces()
        .iter()
        .map(|surface| MenuStatus {
            surface: *surface,
            installed: menu::installed(*surface, &locations),
        })
        .collect())
}

#[tauri::command]
pub fn install_context_menu(language: String) -> Result<()> {
    let program = std::env::current_exe().map_err(storage_failure)?;
    let language = if language == "ar" {
        Language::Arabic
    } else {
        Language::English
    };
    menu::install(
        menu::surfaces(),
        &Launcher::Desktop(program),
        &locations()?,
        language,
    )
    .map_err(storage_failure)
}

#[tauri::command]
pub fn remove_context_menu() -> Result<()> {
    menu::remove(menu::surfaces(), &locations()?).map_err(storage_failure)
}

// ---------- Requests from right-click menus ----------

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileRequest {
    action: String,
    paths: Vec<String>,
}

/// The `--files <action> <paths>` a right-click menu starts. Returns the exit code if this run was
/// one, after leaving the request for the app.
pub fn run_cli(args: &[String]) -> Option<i32> {
    let [flag, action, paths @ ..] = args else {
        return None;
    };
    if flag != "--files" {
        return None;
    }
    if !matches!(action.as_str(), "encrypt" | "decrypt") || paths.is_empty() {
        return Some(2);
    }
    let Some(data_dir) = ipc::data_dir() else {
        return Some(1);
    };
    let request = FileRequest {
        action: action.clone(),
        paths: paths.to_vec(),
    };
    Some(match leave_request(&data_dir, &request) {
        Ok(()) => {
            bring_up_the_app(&data_dir);
            0
        }
        Err(_) => 1,
    })
}

fn leave_request(data_dir: &Path, request: &FileRequest) -> std::io::Result<()> {
    let folder = data_dir.join(REQUESTS);
    fs::create_dir_all(&folder)?;
    let file = tempfile::NamedTempFile::new_in(&folder)?;
    serde_json::to_writer(&file, request).map_err(std::io::Error::other)?;
    // Under its final name only once it's whole.
    let name = format!("{}.json", uuid_like());
    file.persist(folder.join(name))
        .map_err(|error| error.error)?;
    Ok(())
}

fn uuid_like() -> String {
    use rand_core::{OsRng, RngCore};
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn bring_up_the_app(data_dir: &Path) {
    {
        // The browser bridge's socket answers when the app is up.
        let endpoint = ipc::endpoint(data_dir);
        #[cfg(unix)]
        let running = std::os::unix::net::UnixStream::connect(&endpoint).is_ok();
        #[cfg(windows)]
        let running = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&endpoint)
            .is_ok();
        if !running && let Ok(program) = std::env::current_exe() {
            let _ = std::process::Command::new(program).spawn();
        }
    }
}

/// Hands requests from right-click menus to the window.
pub fn watch_requests(app: AppHandle) {
    #[cfg(windows)]
    let _ = tauri::async_runtime::spawn_blocking(clean_mount_leftovers);
    tauri::async_runtime::spawn(async move {
        let Some(data_dir) = ipc::data_dir() else {
            return;
        };
        let folder = data_dir.join(REQUESTS);
        loop {
            tokio::time::sleep(POLL).await;
            for request in take_requests(&folder) {
                let paths: Vec<PathBuf> = request.paths.iter().map(PathBuf::from).collect();
                if let Some(state) = app.try_state::<FilesState>() {
                    state.grant(&paths);
                }
                crate::show_main(&app);
                let _ = app.emit("files://request", request);
            }
        }
    });
}

fn take_requests(folder: &Path) -> Vec<FileRequest> {
    let Ok(entries) = fs::read_dir(folder) else {
        return Vec::new();
    };
    let mut merged: Vec<FileRequest> = Vec::new();
    for path in entries.flatten().map(|entry| entry.path()) {
        if path.extension().is_none_or(|extension| extension != "json") {
            continue;
        }
        let request = fs::read(&path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<FileRequest>(&bytes).ok());
        let _ = fs::remove_file(&path);
        let Some(request) = request else { continue };
        // Explorer starts one copy per selected file: they arrive as one request.
        match merged.iter_mut().find(|one| one.action == request.action) {
            Some(one) => one.paths.extend(request.paths),
            None => merged.push(request),
        }
    }
    merged
}

// ---------- Safes ----------

fn safes_folder() -> Result<PathBuf> {
    Ok(ipc::data_dir().ok_or(ErrorCode::NotFound)?.join(SAFES))
}

fn open_handle(vault: &Vault, files: &FilesState, info: &SafeInfo) -> Result<Arc<Safe>> {
    if let Some(safe) = files.open(&info.item_id) {
        return Ok(safe);
    }
    let key = vault.safe_key(&info.item_id)?;
    let folder = safes_folder()?.join(&info.safe_id);
    let safe = if folder.join("safe.json").exists() {
        Safe::open(&folder, &key)
    } else {
        Safe::create(&folder, &info.safe_id, &key)
    }
    .map_err(safe_failure)?;
    let safe = Arc::new(safe);
    files
        .safes
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(info.item_id.clone(), Arc::clone(&safe));
    Ok(safe)
}

fn safe_info(vault: &Vault, item_id: &str) -> Result<SafeInfo> {
    vault
        .list_safes()?
        .into_iter()
        .find(|safe| safe.item_id == item_id)
        .ok_or_else(|| ErrorCode::NotFound.into())
}

fn handle(vault: &Vault, files: &FilesState, item_id: &str) -> Result<Arc<Safe>> {
    open_handle(vault, files, &safe_info(vault, item_id)?)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SafeView {
    #[serde(flatten)]
    info: SafeInfo,
    open: bool,
    mounted: bool,
    can_mount: bool,
    warnings: Vec<Warning>,
}

fn can_mount() -> bool {
    cfg!(any(windows, all(target_os = "linux", feature = "fuse")))
}

fn view(files: &FilesState, info: SafeInfo) -> SafeView {
    let open = files.open(&info.item_id);
    #[cfg(any(windows, all(target_os = "linux", feature = "fuse")))]
    let mounted = files
        .mounts
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .contains_key(&info.item_id);
    #[cfg(not(any(windows, all(target_os = "linux", feature = "fuse"))))]
    let mounted = false;
    SafeView {
        open: open.is_some(),
        mounted,
        can_mount: can_mount(),
        warnings: open
            .and_then(|safe| safe.warnings().ok())
            .unwrap_or_default(),
        info,
    }
}

#[tauri::command]
pub fn list_safes(
    state: State<'_, AppState>,
    files: State<'_, FilesState>,
) -> Result<Vec<SafeView>> {
    Ok(state
        .vault
        .list_safes()?
        .into_iter()
        .map(|info| view(&files, info))
        .collect())
}

#[tauri::command]
pub async fn create_safe(
    state: State<'_, AppState>,
    files: State<'_, FilesState>,
    name: String,
    sync: bool,
) -> Result<SafeView> {
    let info = state.vault.create_safe(&name, sync).await?;
    open_handle(&state.vault, &files, &info)?;
    Ok(view(&files, info))
}

#[tauri::command]
pub async fn set_safe_sync(
    state: State<'_, AppState>,
    files: State<'_, FilesState>,
    item_id: String,
    sync: bool,
) -> Result<SafeView> {
    let info = state.vault.set_safe_sync(&item_id, sync).await?;
    Ok(view(&files, info))
}

#[tauri::command]
pub async fn sync_safe(
    state: State<'_, AppState>,
    files: State<'_, FilesState>,
    item_id: String,
) -> Result<SyncReport> {
    let safe = handle(&state.vault, &files, &item_id)?;
    let remote = state
        .vault
        .safe_remote(&item_id)?
        .with_server_limit()
        .await?;
    let report = safe.sync(&remote).await.map_err(safe_failure)?;
    Ok(report)
}

#[tauri::command]
pub fn safe_entries(
    state: State<'_, AppState>,
    files: State<'_, FilesState>,
    item_id: String,
    folder: String,
) -> Result<Vec<Entry>> {
    handle(&state.vault, &files, &item_id)?
        .list(&folder)
        .map_err(safe_failure)
}

fn add_one(safe: &Safe, folder: &str, source: &Path) -> Result<()> {
    let name = source
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(ErrorCode::NotAllowed)?
        .to_owned();
    let metadata = fs::symlink_metadata(source).map_err(storage_failure)?;
    if metadata.is_dir() {
        let inner = safe
            .lookup(folder, &name)
            .or_else(|_| safe.create_folder(folder, &name))
            .map_err(safe_failure)?;
        for entry in fs::read_dir(source).map_err(storage_failure)? {
            add_one(safe, &inner.id, &entry.map_err(storage_failure)?.path())?;
        }
    } else if metadata.is_file() {
        let entry = match safe.lookup(folder, &name) {
            Ok(entry) => entry,
            Err(SafeError::NotFound) => safe.create_file(folder, &name).map_err(safe_failure)?,
            Err(error) => return Err(safe_failure(error)),
        };
        let mut input = fs::File::open(source).map_err(storage_failure)?;
        safe.import(&entry.id, &mut input).map_err(safe_failure)?;
    }
    Ok(())
}

#[tauri::command]
pub async fn safe_add_files(
    state: State<'_, AppState>,
    files: State<'_, FilesState>,
    item_id: String,
    folder: String,
    paths: Vec<String>,
) -> Result<()> {
    let paths = files.check(&paths)?;
    let safe = handle(&state.vault, &files, &item_id)?;
    tauri::async_runtime::spawn_blocking(move || {
        paths
            .iter()
            .try_for_each(|path| add_one(&safe, &folder, path))
    })
    .await
    .map_err(storage_failure)?
}

#[tauri::command]
pub fn safe_create_folder(
    state: State<'_, AppState>,
    files: State<'_, FilesState>,
    item_id: String,
    folder: String,
    name: String,
) -> Result<Entry> {
    let entry = handle(&state.vault, &files, &item_id)?
        .create_folder(&folder, &name)
        .map_err(safe_failure)?;
    Ok(entry)
}

#[tauri::command]
pub fn safe_rename(
    state: State<'_, AppState>,
    files: State<'_, FilesState>,
    item_id: String,
    id: String,
    folder: String,
    name: String,
) -> Result<()> {
    handle(&state.vault, &files, &item_id)?
        .rename(&id, &folder, &name)
        .map_err(safe_failure)?;
    Ok(())
}

#[tauri::command]
pub fn safe_delete(
    state: State<'_, AppState>,
    files: State<'_, FilesState>,
    item_id: String,
    id: String,
) -> Result<()> {
    handle(&state.vault, &files, &item_id)?
        .remove_all(&id)
        .map_err(safe_failure)?;
    Ok(())
}

/// Saves a file from a Safe where the user says, in the system's save dialog. Writing plaintext
/// out of a Safe is the point here, so the dialog is the confirmation.
#[tauri::command]
pub async fn safe_save_file(
    app: AppHandle,
    state: State<'_, AppState>,
    files: State<'_, FilesState>,
    item_id: String,
    id: String,
) -> Result<bool> {
    let safe = handle(&state.vault, &files, &item_id)?;
    let entry = safe.entry(&id).map_err(safe_failure)?;
    let (sender, receiver) = tokio::sync::oneshot::channel();
    app.dialog()
        .file()
        .set_file_name(&entry.name)
        .save_file(move |path| {
            let _ = sender.send(path);
        });
    let Some(target) = receiver
        .await
        .ok()
        .flatten()
        .and_then(|path| path.into_path().ok())
    else {
        return Ok(false);
    };
    tauri::async_runtime::spawn_blocking(move || {
        let folder = target.parent().unwrap_or(Path::new("."));
        let mut temporary = tempfile::NamedTempFile::new_in(folder).map_err(storage_failure)?;
        safe.export(&id, temporary.as_file_mut())
            .map_err(safe_failure)?;
        temporary.persist(&target).map_err(storage_failure)?;
        Ok(true)
    })
    .await
    .map_err(storage_failure)?
}

/// A crash leaves opened files behind in plaintext, so they go at the next start.
#[cfg(windows)]
fn clean_mount_leftovers() {
    let Some(home) = std::env::var_os("USERPROFILE") else {
        return;
    };
    let Ok(folders) = fs::read_dir(PathBuf::from(home).join(MOUNTS)) else {
        return;
    };
    for folder in folders.flatten() {
        let _ = octapass_files::safe::cloud_files::clean_leftovers(&folder.path());
    }
}

#[cfg(any(windows, all(target_os = "linux", feature = "fuse")))]
fn mount_folder(name: &str) -> Result<PathBuf> {
    #[cfg(windows)]
    let home = std::env::var_os("USERPROFILE");
    #[cfg(not(windows))]
    let home = std::env::var_os("HOME");
    let home = PathBuf::from(home.ok_or(ErrorCode::NotFound)?);
    // A Safe's name is whatever the user typed: this keeps it one folder, under `MOUNTS`.
    let name = octapass_files::safe::cloud_files::local_name(name);
    Ok(home.join(MOUNTS).join(name))
}

#[cfg(windows)]
fn mount_at(
    safe: Arc<Safe>,
    folder: &Path,
    _name: &str,
) -> octapass_files::safe::Result<SafeMount> {
    octapass_files::safe::cloud_files::mount(safe, folder)
}

#[cfg(all(target_os = "linux", feature = "fuse"))]
fn mount_at(safe: Arc<Safe>, folder: &Path, name: &str) -> octapass_files::safe::Result<SafeMount> {
    fs::create_dir_all(folder)?;
    octapass_files::safe::fuse::mount(safe, folder, name)
}

/// Shows a Safe as a folder until it locks, and returns the folder: FUSE on Linux, Cloud Files on
/// Windows. On Windows, what's opened from it sits on the disk in plaintext until then.
#[cfg_attr(
    not(any(windows, all(target_os = "linux", feature = "fuse"))),
    allow(unused_variables)
)]
#[tauri::command]
pub async fn safe_mount(
    state: State<'_, AppState>,
    files: State<'_, FilesState>,
    item_id: String,
) -> Result<String> {
    #[cfg(any(windows, all(target_os = "linux", feature = "fuse")))]
    {
        let info = safe_info(&state.vault, &item_id)?;
        let folder = mount_folder(&info.name)?;
        let shown = folder.display().to_string();
        let mounts = || files.mounts.lock().unwrap_or_else(|e| e.into_inner());
        if mounts().contains_key(&item_id) {
            return Ok(shown);
        }
        let safe = open_handle(&state.vault, &files, &info)?;
        let mount =
            tauri::async_runtime::spawn_blocking(move || mount_at(safe, &folder, &info.name))
                .await
                .map_err(storage_failure)?
                .map_err(safe_failure)?;
        mounts().insert(item_id.clone(), mount);
        // It locked while this was mounting, after `lock_all` went through the mounts.
        if files.open(&item_id).is_none() {
            mounts().remove(&item_id);
            return Err(ErrorCode::Locked.into());
        }
        Ok(shown)
    }
    #[cfg(not(any(windows, all(target_os = "linux", feature = "fuse"))))]
    Err(ErrorCode::NotAllowed.into())
}

/// What went wrong when Safes last locked, once.
#[tauri::command]
pub fn safe_lock_problems(files: State<'_, FilesState>) -> Vec<String> {
    std::mem::take(
        &mut *files
            .lock_problems
            .lock()
            .unwrap_or_else(|e| e.into_inner()),
    )
}

/// Deletes a Safe: locked and unmounted first, then its item (and key) to the trash, then its
/// folder on this device.
#[tauri::command]
pub async fn delete_safe(
    state: State<'_, AppState>,
    files: State<'_, FilesState>,
    item_id: String,
) -> Result<()> {
    let info = safe_info(&state.vault, &item_id)?;
    safe_lock(files, item_id.clone())?;
    state.vault.delete_safe(&item_id).await?;
    let folder = safes_folder()?.join(&info.safe_id);
    if folder.exists() {
        fs::remove_dir_all(&folder).map_err(storage_failure)?;
    }
    Ok(())
}

/// Syncs the synced Safes that are open, as the vault itself syncs in the background. Errors wait
/// for the next round: offline is normal.
pub async fn sync_open_safes(vault: &Arc<Vault>, files: &FilesState) {
    for (item_id, safe) in files.open_safes() {
        let Ok(info) = safe_info(vault, &item_id) else {
            continue;
        };
        if !info.sync {
            continue;
        }
        let Ok(remote) = vault.safe_remote(&item_id) else {
            continue;
        };
        let Ok(remote) = remote.with_server_limit().await else {
            continue;
        };
        if let Err(error) = safe.sync(&remote).await {
            eprintln!("Safe sync failed: {error}");
        }
    }
}

/// Locks one Safe now. The next use opens it again while the vault is unlocked.
#[tauri::command]
pub fn safe_lock(files: State<'_, FilesState>, item_id: String) -> Result<()> {
    #[cfg(any(windows, all(target_os = "linux", feature = "fuse")))]
    files
        .mounts
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&item_id);
    let safe = files
        .safes
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&item_id);
    if let Some(safe) = safe {
        safe.lock().map_err(safe_failure)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(action: &str, path: &str) -> FileRequest {
        FileRequest {
            action: action.into(),
            paths: vec![path.into()],
        }
    }

    #[test]
    fn requests_from_one_selection_arrive_merged_and_are_taken_once() {
        let dir = tempfile::tempdir().unwrap();
        leave_request(dir.path(), &request("encrypt", "/a")).unwrap();
        leave_request(dir.path(), &request("encrypt", "/b")).unwrap();
        leave_request(dir.path(), &request("decrypt", "/c")).unwrap();
        fs::write(dir.path().join(REQUESTS).join("rubbish.json"), b"{").unwrap();
        fs::write(dir.path().join(REQUESTS).join("partial.tmp"), b"{").unwrap();

        let mut taken = take_requests(&dir.path().join(REQUESTS));
        taken.sort_by(|a, b| b.action.cmp(&a.action));
        assert_eq!(taken.len(), 2);
        let mut paths = taken[0].paths.clone();
        paths.sort();
        assert_eq!(paths, ["/a", "/b"]);
        assert_eq!(taken[1].paths, ["/c"]);
        assert!(take_requests(&dir.path().join(REQUESTS)).is_empty());
    }

    #[test]
    fn a_run_without_the_flag_is_the_app_itself() {
        assert_eq!(run_cli(&[]), None);
        assert_eq!(run_cli(&["--other".to_owned(), "x".to_owned()]), None);
        assert_eq!(
            run_cli(&["--files".to_owned(), "wipe".to_owned(), "/a".to_owned()]),
            Some(2)
        );
        assert_eq!(
            run_cli(&["--files".to_owned(), "encrypt".to_owned()]),
            Some(2)
        );
    }

    #[test]
    fn only_paths_the_user_handed_over_are_allowed() {
        let state = FilesState::default();
        state.grant(&[PathBuf::from("/home/u/docs")]);
        assert!(state.allowed(Path::new("/home/u/docs")));
        assert!(state.allowed(Path::new("/home/u/docs/inner/file")));
        assert!(!state.allowed(Path::new("/home/u/other")));
        assert!(!state.allowed(Path::new("/etc/passwd")));
        assert!(state.check(&["/etc/passwd".to_owned()]).is_err());
    }

    #[test]
    fn describes_an_age_file_by_its_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let plain = dir.path().join("a.txt");
        fs::write(&plain, b"hello").unwrap();
        assert!(!describe_one(&plain).unwrap().encrypted);
        let sealed = dir.path().join("b");
        fs::write(&sealed, age::MAGIC).unwrap();
        assert!(describe_one(&sealed).unwrap().encrypted);
    }
}
