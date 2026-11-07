//! macOS: `libproc` for processes, Security's code signing API for signatures. Signatures are
//! checked on the running process (`SecCode`), not on the file at its path, so swapping the file
//! after launch doesn't help an impostor; a socket peer is named by its audit token, so a reused
//! PID doesn't either.

use std::ffi::{OsString, c_void};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStringExt;
use std::path::{Path, PathBuf};
use std::ptr;

use core_foundation::base::{CFType, TCFType};
use core_foundation::data::CFData;
use core_foundation::dictionary::{CFDictionary, CFDictionaryRef};
use core_foundation::number::CFNumber;
use core_foundation::string::{CFString, CFStringRef};
use core_foundation::url::{CFURL, CFURLRef};
use security_framework_sys::base::errSecSuccess;
use security_framework_sys::code_signing::{
    SecCSFlags, SecCodeCheckValidity, SecCodeCopyGuestWithAttributes, SecCodeCopySelf, SecCodeRef,
    SecRequirementCreateWithString, SecRequirementRef, SecStaticCodeRef, kSecGuestAttributeAudit,
    kSecGuestAttributePid,
};

use crate::trust::{Process, System};

#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    fn SecCodeCopySigningInformation(
        code: SecStaticCodeRef,
        flags: SecCSFlags,
        information: *mut CFDictionaryRef,
    ) -> i32;
    static kSecCodeInfoMainExecutable: CFStringRef;
    static kSecCodeInfoTeamIdentifier: CFStringRef;
}

const DEFAULT_FLAGS: SecCSFlags = 0;
/// `kSecCSSigningInformation`: include the certificate details, such as the team.
const SIGNING_INFORMATION: SecCSFlags = 1 << 1;

pub struct OsSystem;

impl System for OsSystem {
    fn executable(&self, pid: u32) -> io::Result<PathBuf> {
        let mut buffer = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
        // SAFETY: the buffer is as long as we say.
        let length = unsafe {
            libc::proc_pidpath(pid_t(pid)?, buffer.as_mut_ptr().cast(), buffer.len() as u32)
        };
        if length <= 0 {
            return Err(io::Error::last_os_error());
        }
        buffer.truncate(length as usize);
        std::fs::canonicalize(OsString::from_vec(buffer))
    }

    fn parent(&self, pid: u32) -> io::Result<Option<u32>> {
        let child = bsd_info(pid)?;
        let parent = match child.pbi_ppid {
            0 => return Ok(None),
            ppid => ppid,
        };
        let Ok(info) = bsd_info(parent) else {
            return Ok(None);
        };
        let started = |info: &libc::proc_bsdinfo| (info.pbi_start_tvsec, info.pbi_start_tvusec);
        Ok((started(&info) <= started(&child)).then_some(parent))
    }

    fn signed_by(&self, process: &Process, path: &Path, team: &str) -> io::Result<bool> {
        let code = Code::of(process)?;
        if code.main_executable()?.as_deref() != Some(path) {
            return Ok(false);
        }
        code.satisfies(&format!(
            "anchor apple generic and certificate leaf[subject.OU] = \"{team}\""
        ))
    }

    fn root_owned(&self, path: &Path) -> io::Result<bool> {
        super::root_owned(path)
    }

    fn is_system_shell(&self, _: &Path) -> bool {
        false
    }
}

/// The process on the other end of a Unix socket, by its audit token.
pub fn peer(socket: &impl AsRawFd) -> io::Result<Process> {
    let mut token = [0u32; 8];
    let mut length = size_of_val(&token) as libc::socklen_t;
    // SAFETY: `LOCAL_PEERTOKEN` writes an `audit_token_t` (eight `u32`s) into the buffer.
    let result = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_LOCAL,
            libc::LOCAL_PEERTOKEN,
            token.as_mut_ptr().cast::<c_void>(),
            &mut length,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    // `audit_token_to_pid`: the PID is the sixth word.
    Ok(Process {
        pid: token[5],
        audit_token: Some(token),
    })
}

/// The team that signed this program, or `None` when it's unsigned or ad hoc signed.
pub fn own_team() -> Option<String> {
    let mut code: SecCodeRef = ptr::null_mut();
    // SAFETY: on success we own the returned reference.
    if unsafe { SecCodeCopySelf(DEFAULT_FLAGS, &mut code) } != errSecSuccess {
        return None;
    }
    let code = Code(code);
    let information = code.information(SIGNING_INFORMATION).ok()?;
    // SAFETY: a static key from the Security framework.
    let key = unsafe { CFString::wrap_under_get_rule(kSecCodeInfoTeamIdentifier) };
    information
        .find(&key)
        .and_then(|team| team.downcast::<CFString>())
        .map(|team| team.to_string())
}

fn pid_t(pid: u32) -> io::Result<libc::pid_t> {
    libc::pid_t::try_from(pid).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))
}

fn bsd_info(pid: u32) -> io::Result<libc::proc_bsdinfo> {
    // SAFETY: plain data, filled in by the kernel.
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let size = size_of::<libc::proc_bsdinfo>() as libc::c_int;
    // SAFETY: the buffer is a `proc_bsdinfo`, as `PROC_PIDTBSDINFO` expects.
    let written = unsafe {
        libc::proc_pidinfo(
            pid_t(pid)?,
            libc::PROC_PIDTBSDINFO,
            0,
            (&raw mut info).cast(),
            size,
        )
    };
    if written != size {
        return Err(io::Error::last_os_error());
    }
    Ok(info)
}

/// A running process's code, owned (released on drop).
struct Code(SecCodeRef);

impl Drop for Code {
    fn drop(&mut self) {
        // SAFETY: we own this reference.
        unsafe { core_foundation::base::CFRelease(self.0 as *const c_void) };
    }
}

impl Code {
    fn of(process: &Process) -> io::Result<Self> {
        // SAFETY: static keys from the Security framework.
        let (key, value) = match process.audit_token {
            Some(token) => {
                let bytes: Vec<u8> = token.iter().flat_map(|word| word.to_ne_bytes()).collect();
                let key = unsafe { CFString::wrap_under_get_rule(kSecGuestAttributeAudit) };
                (key, CFData::from_buffer(&bytes).as_CFType())
            }
            None => {
                let key = unsafe { CFString::wrap_under_get_rule(kSecGuestAttributePid) };
                (key, CFNumber::from(pid_t(process.pid)?).as_CFType())
            }
        };
        let attributes = CFDictionary::from_CFType_pairs(&[(key, value)]);
        let mut code: SecCodeRef = ptr::null_mut();
        // SAFETY: on success we own the returned reference.
        let status = unsafe {
            SecCodeCopyGuestWithAttributes(
                ptr::null_mut(),
                attributes.as_concrete_TypeRef(),
                DEFAULT_FLAGS,
                &mut code,
            )
        };
        if status != errSecSuccess {
            return Err(os_status("no code object for the process", status));
        }
        Ok(Code(code))
    }

    fn information(&self, flags: SecCSFlags) -> io::Result<CFDictionary<CFString, CFType>> {
        let mut information: CFDictionaryRef = ptr::null();
        // SAFETY: a dynamic code object is accepted wherever a static one is; on success we own
        // the dictionary.
        let status =
            unsafe { SecCodeCopySigningInformation(self.0.cast(), flags, &mut information) };
        if status != errSecSuccess {
            return Err(os_status("no signing information", status));
        }
        // SAFETY: created above, owned by us.
        Ok(unsafe { CFDictionary::wrap_under_create_rule(information) })
    }

    /// The executable the process runs, as a canonical path.
    fn main_executable(&self) -> io::Result<Option<PathBuf>> {
        let information = self.information(DEFAULT_FLAGS)?;
        // SAFETY: a static key from the Security framework.
        let key = unsafe { CFString::wrap_under_get_rule(kSecCodeInfoMainExecutable) };
        let Some(url) = information.find(&key) else {
            return Ok(None);
        };
        // SAFETY: the value for this key is a CFURL.
        let url = unsafe { CFURL::wrap_under_get_rule(url.as_CFTypeRef() as CFURLRef) };
        url.to_path().map(std::fs::canonicalize).transpose()
    }

    /// The signature is valid, the process hasn't been tampered with, and it meets `requirement`.
    fn satisfies(&self, requirement: &str) -> io::Result<bool> {
        let text = CFString::new(requirement);
        let mut compiled: SecRequirementRef = ptr::null_mut();
        // SAFETY: on success we own the returned requirement.
        let status = unsafe {
            SecRequirementCreateWithString(text.as_concrete_TypeRef(), DEFAULT_FLAGS, &mut compiled)
        };
        if status != errSecSuccess {
            return Err(os_status("invalid code requirement", status));
        }
        // SAFETY: both references are valid; the requirement is released once checked.
        let status = unsafe {
            let status = SecCodeCheckValidity(self.0, DEFAULT_FLAGS, compiled);
            core_foundation::base::CFRelease(compiled as *const c_void);
            status
        };
        Ok(status == errSecSuccess)
    }
}

fn os_status(what: &str, status: i32) -> io::Error {
    io::Error::other(format!("{what} (OSStatus {status})"))
}

#[cfg(test)]
mod tests {
    use std::os::unix::net::UnixStream;
    use std::process::Command;

    use super::*;

    #[test]
    fn processes_have_an_executable_and_a_parent() {
        let me = std::process::id();
        assert_eq!(
            OsSystem.executable(me).unwrap(),
            std::fs::canonicalize(std::env::current_exe().unwrap()).unwrap()
        );
        let mut child = Command::new("/bin/sleep").arg("5").spawn().unwrap();
        assert_eq!(OsSystem.parent(child.id()).unwrap(), Some(me));
        assert_eq!(
            OsSystem.executable(child.id()).unwrap(),
            Path::new("/bin/sleep")
        );
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(OsSystem.executable(child.id()).is_err(), "gone");
    }

    #[test]
    fn a_socket_peer_is_named_by_its_audit_token() {
        let (ours, theirs) = UnixStream::pair().unwrap();
        let peer = peer(&ours).unwrap();
        assert_eq!(peer.pid, std::process::id());
        assert!(peer.audit_token.is_some());
        drop(theirs);
    }

    #[test]
    fn apple_signed_programs_check_out_by_team_and_path() {
        // `/bin/sleep` is Apple's own: it meets `anchor apple`, but carries no team ID, so
        // check the requirement mechanics with a process we start.
        let mut child = Command::new("/bin/sleep").arg("5").spawn().unwrap();
        let process = Process::pid(child.id());
        let code = Code::of(&process).unwrap();
        assert_eq!(
            code.main_executable().unwrap().as_deref(),
            Some(Path::new("/bin/sleep"))
        );
        assert!(code.satisfies("anchor apple").unwrap());
        assert!(
            !code
                .satisfies("anchor apple generic and certificate leaf[subject.OU] = \"EQHXZ8M8AV\"")
                .unwrap()
        );
        assert!(
            !OsSystem
                .signed_by(&process, Path::new("/bin/sleep"), "EQHXZ8M8AV")
                .unwrap()
        );
        child.kill().unwrap();
        child.wait().unwrap();
    }

    #[test]
    fn a_running_chrome_is_googles() {
        let chrome = Path::new("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome");
        if !chrome.is_file() {
            eprintln!("Google Chrome isn't installed; skipped");
            return;
        }
        let profile = tempfile::tempdir().unwrap();
        let mut child = Command::new(chrome)
            .args(["--headless=new", "--use-mock-keychain", "--no-first-run"])
            .arg(format!("--user-data-dir={}", profile.path().display()))
            .arg("about:blank")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let process = Process::pid(child.id());
        let path = OsSystem.executable(child.id()).unwrap();
        let browser = crate::browsers::identify(&path).unwrap();
        assert!(
            OsSystem
                .signed_by(&process, &path, browser.signer.unwrap())
                .unwrap()
        );
        assert!(
            !OsSystem.signed_by(&process, &path, "43AQ936H96").unwrap(),
            "not Mozilla's"
        );
        assert!(
            !OsSystem
                .signed_by(&process, Path::new("/bin/sleep"), browser.signer.unwrap())
                .unwrap()
        );
        child.kill().unwrap();
        child.wait().unwrap();
    }

    #[test]
    fn a_test_build_has_no_team() {
        assert_eq!(own_team(), None);
    }
}
