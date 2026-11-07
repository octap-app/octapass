//! Windows: process snapshots and `QueryFullProcessImageNameW` for processes,
//! `GetNamedPipeClientProcessId` for the pipe's client, Authenticode (`WinVerifyTrust`) for
//! signatures.

use std::ffi::OsString;
use std::io;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};

use windows::Win32::Foundation::{CloseHandle, FILETIME, HANDLE, HWND};
use windows::Win32::Security::Cryptography::{CERT_NAME_SIMPLE_DISPLAY_TYPE, CertGetNameStringW};
use windows::Win32::Security::WinTrust::{
    WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0, WINTRUST_FILE_INFO,
    WTD_CHOICE_FILE, WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE,
    WTHelperGetProvSignerFromChain, WTHelperProvDataFromStateData, WinVerifyTrust,
};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Pipes::GetNamedPipeClientProcessId;
use windows::Win32::System::SystemInformation::GetSystemDirectoryW;
use windows::Win32::System::Threading::{
    GetProcessTimes, OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
    QueryFullProcessImageNameW,
};
use windows::core::{PCWSTR, PWSTR};

use crate::trust::{Process, System};

pub struct OsSystem;

impl System for OsSystem {
    fn executable(&self, pid: u32) -> io::Result<PathBuf> {
        let process = Handle::open(pid)?;
        let mut buffer = vec![0u16; 32 * 1024];
        let mut length = buffer.len() as u32;
        // SAFETY: the buffer holds `length` UTF-16 units; the call writes back how many it used.
        unsafe {
            QueryFullProcessImageNameW(
                process.0,
                PROCESS_NAME_WIN32,
                PWSTR(buffer.as_mut_ptr()),
                &mut length,
            )
        }
        .map_err(io::Error::from)?;
        buffer.truncate(length as usize);
        std::fs::canonicalize(OsString::from_wide(&buffer))
    }

    /// Windows doesn't re-parent orphans, so a parent PID may since have been reused: the
    /// parent must have started before the child.
    fn parent(&self, pid: u32) -> io::Result<Option<u32>> {
        let Some(parent) = parent_pid(pid)? else {
            return Ok(None);
        };
        let (Ok(child_started), Ok(parent_started)) = (started(pid), started(parent)) else {
            return Ok(None);
        };
        Ok((parent_started <= child_started).then_some(parent))
    }

    fn signed_by(&self, _: &Process, path: &Path, signer: &str) -> io::Result<bool> {
        Ok(authenticode_signer(path).as_deref() == Some(signer))
    }

    fn root_owned(&self, _: &Path) -> io::Result<bool> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Windows browsers are checked by signature",
        ))
    }

    fn is_system_shell(&self, path: &Path) -> bool {
        let mut buffer = [0u16; 260];
        // SAFETY: the call writes at most the buffer's length.
        let length = unsafe { GetSystemDirectoryW(Some(&mut buffer)) } as usize;
        if length == 0 || length > buffer.len() {
            return false;
        }
        let shell = PathBuf::from(OsString::from_wide(&buffer[..length])).join("cmd.exe");
        std::fs::canonicalize(shell).is_ok_and(|shell| shell == path)
    }
}

/// The process on the client end of a named pipe.
pub fn peer(pipe: &impl AsRawHandle) -> io::Result<Process> {
    let mut pid = 0u32;
    // SAFETY: the handle is a connected pipe server owned by the caller.
    unsafe { GetNamedPipeClientProcessId(HANDLE(pipe.as_raw_handle()), &mut pid) }
        .map_err(io::Error::from)?;
    Ok(Process::pid(pid))
}

struct Handle(HANDLE);

impl Handle {
    fn open(pid: u32) -> io::Result<Self> {
        // SAFETY: plain call; the handle is closed on drop.
        unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }
            .map(Handle)
            .map_err(io::Error::from)
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: we own the handle.
        let _ = unsafe { CloseHandle(self.0) };
    }
}

fn parent_pid(pid: u32) -> io::Result<Option<u32>> {
    // SAFETY: plain call; the snapshot handle is closed on drop.
    let snapshot = Handle(
        unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }.map_err(io::Error::from)?,
    );
    let mut entry = PROCESSENTRY32W {
        dwSize: size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };
    // SAFETY: `entry` is initialised with its size, as the walk requires.
    let mut found = unsafe { Process32FirstW(snapshot.0, &mut entry) };
    while found.is_ok() {
        if entry.th32ProcessID == pid {
            return Ok(Some(entry.th32ParentProcessID).filter(|parent| *parent != 0));
        }
        // SAFETY: as above.
        found = unsafe { Process32NextW(snapshot.0, &mut entry) };
    }
    Err(io::Error::new(io::ErrorKind::NotFound, "no such process"))
}

fn started(pid: u32) -> io::Result<u64> {
    let process = Handle::open(pid)?;
    let (mut created, mut exited, mut kernel, mut user) = Default::default();
    // SAFETY: four out-parameters owned here.
    unsafe { GetProcessTimes(process.0, &mut created, &mut exited, &mut kernel, &mut user) }
        .map_err(io::Error::from)?;
    let created: FILETIME = created;
    Ok((u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime))
}

/// The name of whoever signed the file, if its Authenticode signature is valid and trusted.
fn authenticode_signer(path: &Path) -> Option<String> {
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain([0]).collect();
    let mut file = WINTRUST_FILE_INFO {
        cbStruct: size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: PCWSTR(wide.as_ptr()),
        ..Default::default()
    };
    let mut data = WINTRUST_DATA {
        cbStruct: size_of::<WINTRUST_DATA>() as u32,
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwUnionChoice: WTD_CHOICE_FILE,
        Anonymous: WINTRUST_DATA_0 { pFile: &mut file },
        dwStateAction: WTD_STATEACTION_VERIFY,
        ..Default::default()
    };
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    // SAFETY: `data` points at `file`, which points at `wide`; all outlive both calls. The
    // state opened by VERIFY is closed by CLOSE below whatever the outcome.
    let status = unsafe { WinVerifyTrust(HWND(-1isize as _), &mut action, (&raw mut data).cast()) };
    let signer = (status == 0).then(|| {
        // SAFETY: the state data is valid until CLOSE; each pointer is checked before use.
        unsafe {
            let provider = WTHelperProvDataFromStateData(data.hWVTStateData);
            let signer = WTHelperGetProvSignerFromChain(provider, 0, false, 0);
            if signer.is_null() || (*signer).csCertChain == 0 || (*signer).pasCertChain.is_null() {
                return None;
            }
            let certificate = (*(*signer).pasCertChain).pCert;
            if certificate.is_null() {
                return None;
            }
            let mut name = [0u16; 512];
            let length = CertGetNameStringW(
                certificate,
                CERT_NAME_SIMPLE_DISPLAY_TYPE,
                0,
                None,
                Some(&mut name),
            ) as usize;
            (length > 1).then(|| String::from_utf16_lossy(&name[..length - 1]))
        }
    });
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    // SAFETY: closes the state opened above.
    unsafe { WinVerifyTrust(HWND(-1isize as _), &mut action, (&raw mut data).cast()) };
    signer.flatten()
}
