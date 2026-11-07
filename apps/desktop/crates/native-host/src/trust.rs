//! Who believes whom. The extension's origin is only an argument the host was started with, and
//! any program can start the host with any arguments, or connect to the app's socket itself. So:
//!
//! - the host believes its origin argument only when a known browser started it, and
//! - the app answers only the host binary bundled with it, started by a known browser,
//!
//! where release builds also check the browser's code signature (macOS, Windows) or that it is a
//! root-owned system install (Linux), and on macOS that the host carries the app's own team's
//! signature. The checks read the processes through [`System`], so they're tested with fakes.

use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

use crate::browsers::{self, KnownBrowser};
use crate::protocol::BROWSER_NOT_TRUSTED;

/// A running process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Process {
    pub pid: u32,
    /// macOS: the socket peer's audit token, which names this exact process (PIDs get reused).
    pub audit_token: Option<[u32; 8]>,
}

impl Process {
    pub fn pid(pid: u32) -> Self {
        Self {
            pid,
            audit_token: None,
        }
    }
}

/// What the checks need to know about processes and files.
pub trait System {
    /// The process's executable, as a canonical path.
    fn executable(&self, pid: u32) -> io::Result<PathBuf>;
    /// The process that started this one, or `None` when it's gone (or its PID was reused).
    fn parent(&self, pid: u32) -> io::Result<Option<u32>>;
    /// The process runs `path`, whose code signature is valid and from `signer`: an Apple team
    /// ID on macOS, the Authenticode signer's name on Windows.
    fn signed_by(&self, process: &Process, path: &Path, signer: &str) -> io::Result<bool>;
    /// Only root can change `path` or its folder (Linux, which has no code signatures).
    fn root_owned(&self, path: &Path) -> io::Result<bool>;
    /// Windows' own `cmd.exe`: Chromium starts native messaging hosts through it.
    fn is_system_shell(&self, path: &Path) -> bool;
}

/// What vouches for a browser binary beyond its name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Vouching {
    /// Development builds: the name is enough.
    Nothing,
    /// macOS and Windows release builds: the vendor's code signature.
    Signature,
    /// Linux release builds: a root-owned system install.
    RootOwnership,
}

impl Vouching {
    pub fn for_this_build() -> Self {
        if cfg!(debug_assertions) {
            Vouching::Nothing
        } else if cfg!(any(target_os = "macos", windows)) {
            Vouching::Signature
        } else {
            Vouching::RootOwnership
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// A process couldn't be inspected.
    Inspect(String),
    NoParent,
    NotABrowser(PathBuf),
    UnsignedBrowser(&'static str),
    BadBrowserSignature(&'static str),
    NotSystemBrowser(&'static str),
    NotTheHost(PathBuf),
    BadHostSignature,
}

impl Refusal {
    /// The reply's error code: [`BROWSER_NOT_TRUSTED`] when the browser is what's refused, so the
    /// extension can say so, and `forbidden` for anything else.
    pub fn code(&self) -> &'static str {
        match self {
            Refusal::NoParent
            | Refusal::NotABrowser(_)
            | Refusal::UnsignedBrowser(_)
            | Refusal::BadBrowserSignature(_)
            | Refusal::NotSystemBrowser(_) => BROWSER_NOT_TRUSTED,
            Refusal::Inspect(_) | Refusal::NotTheHost(_) | Refusal::BadHostSignature => "forbidden",
        }
    }
}

impl From<io::Error> for Refusal {
    fn from(error: io::Error) -> Self {
        Refusal::Inspect(error.to_string())
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Refusal::Inspect(error) => write!(f, "couldn't check which program this is: {error}"),
            Refusal::NoParent => f.write_str("the program that started the host has quit"),
            Refusal::NotABrowser(path) => write!(
                f,
                "only a supported browser may start the host, not {}",
                path.display()
            ),
            Refusal::UnsignedBrowser(name) => {
                write!(
                    f,
                    "{name} isn't signed by its vendor, so it can't unlock Octa Pass"
                )
            }
            Refusal::BadBrowserSignature(name) => {
                write!(f, "this copy of {name} isn't signed by its vendor")
            }
            Refusal::NotSystemBrowser(name) => write!(
                f,
                "{name} must be installed system-wide (owned by root) to unlock Octa Pass"
            ),
            Refusal::NotTheHost(path) => write!(
                f,
                "only Octa Pass's own native host may connect, not {}",
                path.display()
            ),
            Refusal::BadHostSignature => {
                f.write_str("the native host isn't signed by the same developer as the app")
            }
        }
    }
}

/// The browser that started process `pid`: its parent, or on Windows the parent of the
/// `cmd.exe` in between.
pub fn launching_browser(
    system: &impl System,
    vouching: Vouching,
    pid: u32,
) -> Result<&'static KnownBrowser, Refusal> {
    let mut parent = system.parent(pid)?.ok_or(Refusal::NoParent)?;
    let mut path = system.executable(parent)?;
    if system.is_system_shell(&path) {
        parent = system.parent(parent)?.ok_or(Refusal::NoParent)?;
        path = system.executable(parent)?;
    }
    let browser = browsers::identify(&path).ok_or_else(|| Refusal::NotABrowser(path.clone()))?;
    match vouching {
        Vouching::Nothing => {}
        Vouching::Signature => {
            let signer = browser
                .signer
                .ok_or(Refusal::UnsignedBrowser(browser.name))?;
            if !system.signed_by(&Process::pid(parent), &path, signer)? {
                return Err(Refusal::BadBrowserSignature(browser.name));
            }
        }
        Vouching::RootOwnership => {
            if !system.root_owned(&path)? {
                return Err(Refusal::NotSystemBrowser(browser.name));
            }
        }
    }
    Ok(browser)
}

/// The app's check of a process on its socket.
#[derive(Debug, Clone)]
pub struct HostCheck {
    /// The host binary bundled with the app, canonical.
    pub host: PathBuf,
    /// The team that must have signed the host (macOS release builds); `None` skips the check.
    pub team: Option<String>,
    pub vouching: Vouching,
}

impl HostCheck {
    /// The peer must run the bundled host, signed by `team`, started by a known browser. Returns
    /// that browser.
    pub fn check(
        &self,
        system: &impl System,
        peer: &Process,
    ) -> Result<&'static KnownBrowser, Refusal> {
        let executable = system.executable(peer.pid)?;
        if executable != self.host {
            return Err(Refusal::NotTheHost(executable));
        }
        if let Some(team) = &self.team
            && !system.signed_by(peer, &executable, team)?
        {
            return Err(Refusal::BadHostSignature);
        }
        launching_browser(system, self.vouching, peer.pid)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};

    use super::*;
    use crate::browsers::KNOWN;

    const HOST: u32 = 10;
    const BROWSER: u32 = 20;
    const SHELL: u32 = 15;

    /// Processes by PID: executable and parent. Signatures and root ownership by path.
    #[derive(Default)]
    struct Fake {
        processes: HashMap<u32, (PathBuf, Option<u32>)>,
        signed: HashMap<PathBuf, &'static str>,
        root_owned: HashSet<PathBuf>,
        shell: Option<PathBuf>,
    }

    impl Fake {
        fn process(mut self, pid: u32, path: &Path, parent: Option<u32>) -> Self {
            self.processes.insert(pid, (path.to_owned(), parent));
            self
        }

        fn signed(mut self, path: &Path, signer: &'static str) -> Self {
            self.signed.insert(path.to_owned(), signer);
            self
        }
    }

    impl System for Fake {
        fn executable(&self, pid: u32) -> io::Result<PathBuf> {
            self.processes
                .get(&pid)
                .map(|(path, _)| path.clone())
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no such process"))
        }

        fn parent(&self, pid: u32) -> io::Result<Option<u32>> {
            Ok(self.processes.get(&pid).and_then(|(_, parent)| *parent))
        }

        fn signed_by(&self, process: &Process, path: &Path, signer: &str) -> io::Result<bool> {
            Ok(self.executable(process.pid)? == path && self.signed.get(path) == Some(&signer))
        }

        fn root_owned(&self, path: &Path) -> io::Result<bool> {
            Ok(self.root_owned.contains(path))
        }

        fn is_system_shell(&self, path: &Path) -> bool {
            self.shell.as_deref() == Some(path)
        }
    }

    fn host_path() -> PathBuf {
        PathBuf::from("/Applications/Octa Pass.app/Contents/MacOS/octapass-native-host")
    }

    /// Where a known browser's executable would be on this platform.
    fn browser_path(browser: &KnownBrowser) -> PathBuf {
        if cfg!(target_os = "macos") {
            Path::new("/Applications")
                .join(format!("{}.app", browser.name))
                .join("Contents/MacOS")
                .join(browser.executable)
        } else {
            Path::new("/opt/browser").join(browser.executable)
        }
    }

    #[cfg(any(target_os = "macos", windows))]
    fn signed_browser() -> &'static KnownBrowser {
        KNOWN
            .iter()
            .find(|browser| browser.signer.is_some())
            .unwrap()
    }

    /// The host started by `browser`, which is signed by its vendor.
    fn started_by(browser: &KnownBrowser) -> Fake {
        let fake = Fake::default()
            .process(HOST, &host_path(), Some(BROWSER))
            .process(BROWSER, &browser_path(browser), Some(1));
        match browser.signer {
            Some(signer) => fake.signed(&browser_path(browser), signer),
            None => fake,
        }
    }

    fn app_check(team: Option<&str>, vouching: Vouching) -> HostCheck {
        HostCheck {
            host: host_path(),
            team: team.map(str::to_owned),
            vouching,
        }
    }

    #[test]
    fn every_known_browser_may_start_the_host() {
        for browser in KNOWN {
            assert_eq!(
                launching_browser(&started_by(browser), Vouching::Nothing, HOST),
                Ok(browser)
            );
        }
    }

    #[test]
    fn other_programs_may_not() {
        let fake = Fake::default()
            .process(HOST, &host_path(), Some(30))
            .process(30, Path::new("/tmp/evil"), Some(1));
        assert_eq!(
            launching_browser(&fake, Vouching::Nothing, HOST),
            Err(Refusal::NotABrowser("/tmp/evil".into()))
        );
        let orphan = Fake::default().process(HOST, &host_path(), None);
        assert_eq!(
            launching_browser(&orphan, Vouching::Nothing, HOST),
            Err(Refusal::NoParent)
        );
        let gone = Fake::default().process(HOST, &host_path(), Some(99));
        assert!(matches!(
            launching_browser(&gone, Vouching::Nothing, HOST),
            Err(Refusal::Inspect(_))
        ));
    }

    // Needs a browser with a code signer, which only macOS and Windows have.
    #[cfg(any(target_os = "macos", windows))]
    #[test]
    fn release_builds_need_the_vendors_signature() {
        let browser = signed_browser();
        assert_eq!(
            launching_browser(&started_by(browser), Vouching::Signature, HOST),
            Ok(browser)
        );

        let mut forged = started_by(browser);
        forged.signed.clear();
        assert_eq!(
            launching_browser(&forged, Vouching::Signature, HOST),
            Err(Refusal::BadBrowserSignature(browser.name))
        );
        let other_vendor = Fake {
            signed: HashMap::new(),
            ..started_by(browser)
        }
        .signed(&browser_path(browser), "SOMEONEELSE");
        assert_eq!(
            launching_browser(&other_vendor, Vouching::Signature, HOST),
            Err(Refusal::BadBrowserSignature(browser.name))
        );

        if let Some(unsigned) = KNOWN.iter().find(|browser| browser.signer.is_none()) {
            assert_eq!(
                launching_browser(&started_by(unsigned), Vouching::Signature, HOST),
                Err(Refusal::UnsignedBrowser(unsigned.name))
            );
        }
    }

    #[test]
    fn linux_release_builds_need_a_root_owned_browser() {
        let browser = &KNOWN[0];
        let mut fake = started_by(browser);
        assert_eq!(
            launching_browser(&fake, Vouching::RootOwnership, HOST),
            Err(Refusal::NotSystemBrowser(browser.name))
        );
        fake.root_owned.insert(browser_path(browser));
        assert_eq!(
            launching_browser(&fake, Vouching::RootOwnership, HOST),
            Ok(browser)
        );
    }

    #[test]
    fn the_system_shell_in_between_is_skipped_once() {
        let browser = &KNOWN[0];
        let shell = PathBuf::from(r"C:\Windows\System32\cmd.exe");
        let mut fake = started_by(browser)
            .process(HOST, &host_path(), Some(SHELL))
            .process(SHELL, &shell, Some(BROWSER));
        fake.shell = Some(shell.clone());
        assert_eq!(
            launching_browser(&fake, Vouching::Nothing, HOST),
            Ok(browser)
        );

        // A shell started by a shell (or by anything else) is not a browser.
        let fake = Fake {
            shell: Some(shell.clone()),
            ..Fake::default()
        }
        .process(HOST, &host_path(), Some(SHELL))
        .process(SHELL, &shell, Some(16))
        .process(16, &shell, Some(BROWSER))
        .process(BROWSER, &browser_path(browser), None);
        assert_eq!(
            launching_browser(&fake, Vouching::Nothing, HOST),
            Err(Refusal::NotABrowser(shell))
        );
    }

    // Needs a browser with a code signer, which only macOS and Windows have.
    #[cfg(any(target_os = "macos", windows))]
    #[test]
    fn the_app_answers_only_its_own_host() {
        let browser = signed_browser();
        let fake = started_by(browser).signed(&host_path(), "OURTEAM");
        let check = app_check(Some("OURTEAM"), Vouching::Signature);
        assert_eq!(check.check(&fake, &Process::pid(HOST)), Ok(browser));

        // Any other program on the socket, even one a browser started.
        let impostor = fake.process(30, Path::new("/tmp/evil"), Some(BROWSER));
        assert_eq!(
            check.check(&impostor, &Process::pid(30)),
            Err(Refusal::NotTheHost("/tmp/evil".into()))
        );
        // A copy of the host elsewhere.
        let copy = Path::new("/tmp/octapass-native-host");
        let fake = started_by(browser).process(HOST, copy, Some(BROWSER));
        assert_eq!(
            check.check(&fake, &Process::pid(HOST)),
            Err(Refusal::NotTheHost(copy.into()))
        );
    }

    // Needs a browser with a code signer, which only macOS and Windows have.
    #[cfg(any(target_os = "macos", windows))]
    #[test]
    fn the_host_must_carry_the_apps_signature_when_it_has_one() {
        let browser = signed_browser();
        let unsigned_host = started_by(browser);
        assert_eq!(
            app_check(Some("OURTEAM"), Vouching::Signature)
                .check(&unsigned_host, &Process::pid(HOST)),
            Err(Refusal::BadHostSignature)
        );
        let other_team = started_by(browser).signed(&host_path(), "THEIRTEAM");
        assert_eq!(
            app_check(Some("OURTEAM"), Vouching::Signature).check(&other_team, &Process::pid(HOST)),
            Err(Refusal::BadHostSignature)
        );
        // Development (unsigned) builds check the path only.
        assert_eq!(
            app_check(None, Vouching::Nothing).check(&unsigned_host, &Process::pid(HOST)),
            Ok(browser)
        );
    }

    #[test]
    fn the_genuine_host_started_by_another_program_is_refused() {
        // Running the real host with a forged origin argument doesn't get past the app either.
        let fake = Fake::default()
            .signed(&host_path(), "OURTEAM")
            .process(HOST, &host_path(), Some(30))
            .process(30, Path::new("/tmp/evil"), Some(1));
        assert_eq!(
            app_check(Some("OURTEAM"), Vouching::Signature).check(&fake, &Process::pid(HOST)),
            Err(Refusal::NotABrowser("/tmp/evil".into()))
        );
    }

    #[test]
    fn refusals_explain_themselves() {
        let message = Refusal::NotABrowser("/tmp/evil".into()).to_string();
        assert_eq!(
            message,
            "only a supported browser may start the host, not /tmp/evil"
        );
        assert!(Refusal::BadHostSignature.to_string().contains("signed"));
    }

    #[test]
    fn refusals_of_the_browser_have_their_own_code() {
        for refusal in [
            Refusal::NoParent,
            Refusal::NotABrowser("/tmp/evil".into()),
            Refusal::UnsignedBrowser("Chromium"),
            Refusal::BadBrowserSignature("Google Chrome"),
            Refusal::NotSystemBrowser("Firefox"),
        ] {
            assert_eq!(refusal.code(), "browserNotTrusted", "{refusal}");
        }
        for refusal in [
            Refusal::Inspect("gone".into()),
            Refusal::NotTheHost("/tmp/evil".into()),
            Refusal::BadHostSignature,
        ] {
            assert_eq!(refusal.code(), "forbidden", "{refusal}");
        }
    }

    #[cfg(debug_assertions)]
    #[test]
    fn development_builds_check_names_only() {
        assert_eq!(Vouching::for_this_build(), Vouching::Nothing);
    }
}
