//! Installing a private CA in the system's trust store (plan 16 §1), the way mkcert does. Only the
//! public certificate is touched. Installing changes what this device trusts, so callers ask first;
//! [`plan`] says exactly what will run, which is what they show.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::{NetError, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Install,
    Remove,
}

/// One command to run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {
    pub program: String,
    pub args: Vec<String>,
}

impl Step {
    fn new(program: &str, args: &[&str]) -> Self {
        Self {
            program: program.to_owned(),
            args: args.iter().map(|arg| (*arg).to_owned()).collect(),
        }
    }

    pub fn display(&self) -> String {
        format!("{} {}", self.program, self.args.join(" "))
    }
}

/// Which operating system's store to use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Store {
    /// The user's login keychain, trusted as a root for this user.
    MacOs { keychain: PathBuf, sha1: String },
    /// The current user's Root store.
    Windows { serial: String },
    /// `update-ca-certificates` (Debian, Ubuntu) and the user's NSS database for Chromium and Firefox.
    LinuxDebian { name: String, nss: Option<PathBuf> },
    /// `update-ca-trust` (Fedora, RHEL).
    LinuxFedora { name: String, nss: Option<PathBuf> },
    /// `trust` (Arch).
    LinuxP11Kit { name: String, nss: Option<PathBuf> },
}

/// The system this runs on, with `name` (a file name) for its entry and the certificate's SHA-1
/// fingerprint and serial, which macOS and Windows find it by.
pub fn detect(name: &str, sha1: &str, serial: &str) -> Result<Store> {
    let home = std::env::var_os("HOME").map(PathBuf::from);
    if cfg!(target_os = "macos") {
        let home = home.ok_or_else(|| NetError::System("No home folder.".to_owned()))?;
        return Ok(Store::MacOs {
            keychain: home.join("Library/Keychains/login.keychain-db"),
            sha1: sha1.replace(':', ""),
        });
    }
    if cfg!(target_os = "windows") {
        return Ok(Store::Windows {
            serial: serial.to_owned(),
        });
    }
    let name = name.to_owned();
    let nss = home
        .map(|home| home.join(".pki/nssdb"))
        .filter(|path| path.is_dir() && has_program("certutil"));
    if Path::new("/usr/sbin/update-ca-certificates").exists()
        || has_program("update-ca-certificates")
    {
        return Ok(Store::LinuxDebian { name, nss });
    }
    if has_program("update-ca-trust") {
        return Ok(Store::LinuxFedora { name, nss });
    }
    if has_program("trust") {
        return Ok(Store::LinuxP11Kit { name, nss });
    }
    Err(NetError::System(
        "Couldn't find this system's certificate tools.".to_owned(),
    ))
}

fn has_program(name: &str) -> bool {
    std::env::var_os("PATH")
        .is_some_and(|paths| std::env::split_paths(&paths).any(|path| path.join(name).is_file()))
}

fn nss_steps(action: Action, name: &str, nss: &Option<PathBuf>, certificate: &str) -> Vec<Step> {
    let Some(nss) = nss else {
        return Vec::new();
    };
    let database = format!("sql:{}", nss.display());
    vec![match action {
        Action::Install => Step::new(
            "certutil",
            &[
                "-A",
                "-d",
                &database,
                "-t",
                "C,,",
                "-n",
                name,
                "-i",
                certificate,
            ],
        ),
        Action::Remove => Step::new("certutil", &["-D", "-d", &database, "-n", name]),
    }]
}

/// What will run for `action` with the PEM file at `certificate`.
pub fn plan(action: Action, store: &Store, certificate: &Path) -> Vec<Step> {
    let file = certificate.display().to_string();
    match store {
        Store::MacOs { keychain, sha1 } => {
            let keychain = keychain.display().to_string();
            match action {
                Action::Install => vec![Step::new(
                    "security",
                    &[
                        "add-trusted-cert",
                        "-r",
                        "trustRoot",
                        "-k",
                        &keychain,
                        &file,
                    ],
                )],
                Action::Remove => vec![
                    Step::new("security", &["remove-trusted-cert", &file]),
                    Step::new("security", &["delete-certificate", "-Z", sha1, &keychain]),
                ],
            }
        }
        Store::Windows { serial } => vec![match action {
            Action::Install => Step::new("certutil", &["-user", "-addstore", "Root", &file]),
            Action::Remove => Step::new("certutil", &["-user", "-delstore", "Root", serial]),
        }],
        Store::LinuxDebian { name, nss } => {
            let target = format!("/usr/local/share/ca-certificates/{name}.crt");
            let mut steps = match action {
                Action::Install => vec![
                    Step::new("sudo", &["cp", &file, &target]),
                    Step::new("sudo", &["update-ca-certificates"]),
                ],
                Action::Remove => vec![
                    Step::new("sudo", &["rm", "-f", &target]),
                    Step::new("sudo", &["update-ca-certificates", "--fresh"]),
                ],
            };
            steps.extend(nss_steps(action, name, nss, &file));
            steps
        }
        Store::LinuxFedora { name, nss } => {
            let target = format!("/etc/pki/ca-trust/source/anchors/{name}.pem");
            let mut steps = match action {
                Action::Install => vec![
                    Step::new("sudo", &["cp", &file, &target]),
                    Step::new("sudo", &["update-ca-trust", "extract"]),
                ],
                Action::Remove => vec![
                    Step::new("sudo", &["rm", "-f", &target]),
                    Step::new("sudo", &["update-ca-trust", "extract"]),
                ],
            };
            steps.extend(nss_steps(action, name, nss, &file));
            steps
        }
        Store::LinuxP11Kit { name, nss } => {
            let mut steps = vec![match action {
                Action::Install => Step::new("sudo", &["trust", "anchor", "--store", &file]),
                Action::Remove => Step::new("sudo", &["trust", "anchor", "--remove", &file]),
            }];
            steps.extend(nss_steps(action, name, nss, &file));
            steps
        }
    }
}

/// Runs `steps` in order and stops at the first that fails.
pub fn run(steps: &[Step]) -> Result<()> {
    for step in steps {
        let status = Command::new(&step.program)
            .args(&step.args)
            .status()
            .map_err(|error| NetError::System(format!("Can't run {}: {error}", step.program)))?;
        if !status.success() {
            return Err(NetError::System(format!(
                "{} failed ({status}).",
                step.display()
            )));
        }
    }
    Ok(())
}

/// A file name for a CA's entry, from its fingerprint, so two CAs never share one.
pub fn entry_name(sha256: &str) -> String {
    let compact: String = sha256
        .chars()
        .filter(char::is_ascii_hexdigit)
        .take(16)
        .collect();
    format!("octapass-ca-{}", compact.to_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(steps: Vec<Step>) -> Vec<String> {
        steps.iter().map(Step::display).collect()
    }

    #[test]
    fn macos_plan_uses_the_login_keychain_and_never_the_system_one() {
        let store = Store::MacOs {
            keychain: "/Users/ada/Library/Keychains/login.keychain-db".into(),
            sha1: "ABC".into(),
        };
        assert_eq!(
            lines(plan(Action::Install, &store, Path::new("/tmp/ca.pem"))),
            [
                "security add-trusted-cert -r trustRoot -k /Users/ada/Library/Keychains/login.keychain-db /tmp/ca.pem"
            ]
        );
        assert_eq!(
            lines(plan(Action::Remove, &store, Path::new("/tmp/ca.pem"))),
            [
                "security remove-trusted-cert /tmp/ca.pem",
                "security delete-certificate -Z ABC /Users/ada/Library/Keychains/login.keychain-db"
            ]
        );
    }

    #[test]
    fn windows_plan_is_per_user() {
        let store = Store::Windows {
            serial: "01".into(),
        };
        assert_eq!(
            lines(plan(Action::Install, &store, Path::new("ca.pem"))),
            ["certutil -user -addstore Root ca.pem"]
        );
        assert_eq!(
            lines(plan(Action::Remove, &store, Path::new("ca.pem"))),
            ["certutil -user -delstore Root 01"]
        );
    }

    #[test]
    fn linux_plans_include_nss_when_there_is_a_database() {
        let store = Store::LinuxDebian {
            name: "octapass-ca-1234".into(),
            nss: Some("/home/ada/.pki/nssdb".into()),
        };
        assert_eq!(
            lines(plan(Action::Install, &store, Path::new("/tmp/ca.pem"))),
            [
                "sudo cp /tmp/ca.pem /usr/local/share/ca-certificates/octapass-ca-1234.crt",
                "sudo update-ca-certificates",
                "certutil -A -d sql:/home/ada/.pki/nssdb -t C,, -n octapass-ca-1234 -i /tmp/ca.pem"
            ]
        );
        let fedora = Store::LinuxFedora {
            name: "octapass-ca-1234".into(),
            nss: None,
        };
        assert_eq!(
            lines(plan(Action::Remove, &fedora, Path::new("/tmp/ca.pem"))),
            [
                "sudo rm -f /etc/pki/ca-trust/source/anchors/octapass-ca-1234.pem",
                "sudo update-ca-trust extract"
            ]
        );
    }

    #[test]
    fn entry_names_are_safe_file_names() {
        assert_eq!(
            entry_name("AB:CD:EF:01:23:45:67:89:AA:BB"),
            "octapass-ca-abcdef0123456789"
        );
    }
}
