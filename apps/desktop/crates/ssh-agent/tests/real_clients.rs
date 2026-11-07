//! The agent against the real OpenSSH tools, where they're installed: `ssh-add`, `ssh-keygen`
//! (what Git runs to sign) and a full `ssh` login to a private `sshd`.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use octapass_core::tools::ssh::{self, SshKey, SshKeyKind, authorized_keys_line, generate};
use octapass_ssh_agent::wire::{Purpose, purpose};
use octapass_ssh_agent::{Backend, Identity, Peer, server};
use rand_core::OsRng;

struct Keys {
    keys: Vec<SshKey>,
    approve: bool,
    asked: AtomicUsize,
    purposes: Mutex<Vec<Purpose>>,
}

impl Backend for Keys {
    async fn identities(&self, _peer: &Peer) -> Vec<Identity> {
        self.keys
            .iter()
            .map(|key| Identity {
                blob: ssh::public_key_blob(&key.info.public_key).unwrap(),
                comment: key.info.comment.clone(),
            })
            .collect()
    }

    async fn sign(
        &self,
        _peer: &Peer,
        blob: Vec<u8>,
        data: Vec<u8>,
        flags: u32,
    ) -> Option<Vec<u8>> {
        self.asked.fetch_add(1, Ordering::SeqCst);
        self.purposes.lock().unwrap().push(purpose(&data));
        if !self.approve {
            return None;
        }
        let key = self
            .keys
            .iter()
            .find(|key| ssh::public_key_blob(&key.info.public_key).unwrap() == blob)?;
        ssh::sign(&key.private_key, &data, flags).ok()
    }
}

fn have(tool: &str) -> bool {
    Command::new(tool)
        .arg("-V")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

/// `tempfile` under the system's temporary folder can be too long for a socket on macOS.
fn short_dir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("opa")
        .tempdir_in("/tmp")
        .unwrap()
}

async fn agent(dir: &Path, keys: Arc<Keys>) -> PathBuf {
    let socket = dir.join("agent.sock");
    tokio::spawn(server::serve(keys, socket.clone(), |_| Peer::default()));
    while !socket.exists() {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    socket
}

async fn run(mut command: Command) -> Output {
    tokio::task::spawn_blocking(move || command.output().unwrap())
        .await
        .unwrap()
}

fn keys(kinds: &[SshKeyKind], approve: bool) -> Arc<Keys> {
    Arc::new(Keys {
        keys: kinds
            .iter()
            .map(|kind| generate(*kind, "vault-key", &mut OsRng).unwrap())
            .collect(),
        approve,
        asked: AtomicUsize::new(0),
        purposes: Mutex::new(Vec::new()),
    })
}

#[tokio::test(flavor = "multi_thread")]
async fn ssh_add_lists_the_keys_and_cannot_change_them() {
    if !have("ssh-add") {
        return;
    }
    let dir = short_dir();
    let keys = keys(&[SshKeyKind::Ed25519, SshKeyKind::EcdsaP256], true);
    let socket = agent(dir.path(), keys.clone()).await;
    let mut list = Command::new("ssh-add");
    list.arg("-l").env("SSH_AUTH_SOCK", &socket);
    let output = run(list).await;
    let text = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(output.status.success(), "{output:?}");
    for key in &keys.keys {
        assert!(text.contains(&key.info.fingerprint), "{text}");
    }
    let mut clear = Command::new("ssh-add");
    clear.arg("-D").env("SSH_AUTH_SOCK", &socket);
    assert!(
        !run(clear).await.status.success(),
        "the vault owns the keys"
    );
}

/// What Git does for `gpg.format = ssh`: `ssh-keygen -Y sign` with only the public key, through the
/// agent. Every key type, RSA included.
#[tokio::test(flavor = "multi_thread")]
async fn ssh_keygen_signs_through_the_agent() {
    if !have("ssh-add") {
        return;
    }
    let dir = short_dir();
    let kinds = [
        SshKeyKind::Ed25519,
        SshKeyKind::EcdsaP256,
        SshKeyKind::EcdsaP384,
        SshKeyKind::Rsa3072,
    ];
    let keys = keys(&kinds, true);
    let socket = agent(dir.path(), keys.clone()).await;
    let message = dir.path().join("commit");
    std::fs::write(&message, "tree 0\n\nA commit\n").unwrap();
    for (index, key) in keys.keys.iter().enumerate() {
        let public = dir.path().join(format!("key{index}.pub"));
        std::fs::write(&public, format!("{}\n", key.info.public_key)).unwrap();
        let mut sign = Command::new("ssh-keygen");
        sign.args(["-Y", "sign", "-n", "git", "-U", "-f"])
            .arg(&public)
            .arg(&message)
            .env("SSH_AUTH_SOCK", &socket);
        let output = run(sign).await;
        assert!(
            output.status.success(),
            "{:?}: {output:?}",
            key.info.key_type
        );

        let allowed = dir.path().join("allowed");
        std::fs::write(&allowed, format!("me {}\n", key.info.public_key)).unwrap();
        let signature = dir.path().join("commit.sig");
        let mut verify = Command::new("sh");
        verify.arg("-c").arg(format!(
            "ssh-keygen -Y verify -n git -I me -f {} -s {} < {}",
            allowed.display(),
            signature.display(),
            message.display()
        ));
        let output = run(verify).await;
        assert!(
            output.status.success(),
            "{:?}: {output:?}",
            key.info.key_type
        );
        std::fs::remove_file(signature).unwrap();
    }
    assert_eq!(keys.asked.load(Ordering::SeqCst), kinds.len());
    assert!(matches!(
        &keys.purposes.lock().unwrap()[0],
        Purpose::Signature { namespace } if namespace == "git"
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refused_approval_fails_the_signature() {
    if !have("ssh-add") {
        return;
    }
    let dir = short_dir();
    let keys = keys(&[SshKeyKind::Ed25519], false);
    let socket = agent(dir.path(), keys.clone()).await;
    let message = dir.path().join("commit");
    std::fs::write(&message, "x").unwrap();
    let public = dir.path().join("key.pub");
    std::fs::write(&public, &keys.keys[0].info.public_key).unwrap();
    let mut sign = Command::new("ssh-keygen");
    sign.args(["-Y", "sign", "-n", "git", "-U", "-f"])
        .arg(&public)
        .arg(&message)
        .env("SSH_AUTH_SOCK", &socket);
    assert!(!run(sign).await.status.success());
    assert!(!dir.path().join("commit.sig").exists());
    assert_eq!(keys.asked.load(Ordering::SeqCst), 1);
}

/// A real login: `ssh` to an unprivileged `sshd` on a free port, with the key only in the agent.
#[tokio::test(flavor = "multi_thread")]
async fn ssh_logs_in_with_a_key_from_the_agent() {
    let sshd = Path::new("/usr/sbin/sshd");
    if !have("ssh") || !sshd.exists() {
        eprintln!("skipped: no ssh or sshd");
        return;
    }
    let dir = short_dir();
    let keys = keys(&[SshKeyKind::Ed25519, SshKeyKind::Rsa3072], true);
    let socket = agent(dir.path(), keys.clone()).await;

    let host_key = generate(SshKeyKind::Ed25519, "host", &mut OsRng).unwrap();
    let host_path = dir.path().join("host_key");
    let host_text =
        ssh::write_private_key(&host_key.private_key, "host", None, &mut OsRng).unwrap();
    std::fs::write(&host_path, host_text.as_bytes()).unwrap();
    std::os::unix::fs::PermissionsExt::set_mode(
        &mut std::fs::metadata(&host_path).unwrap().permissions(),
        0o600,
    );
    let mut perms = std::fs::metadata(&host_path).unwrap().permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o600);
    std::fs::set_permissions(&host_path, perms).unwrap();
    let authorized = dir.path().join("authorized");
    let lines: Vec<String> = keys
        .keys
        .iter()
        .rev()
        .take(1)
        .map(|key| authorized_keys_line(&key.info.public_key, "vault"))
        .collect();
    std::fs::write(&authorized, lines.join("\n") + "\n").unwrap();
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let user = std::env::var("USER").unwrap();
    let config = dir.path().join("sshd_config");
    std::fs::write(
        &config,
        format!(
            "Port {port}\nListenAddress 127.0.0.1\nHostKey {}\nAuthorizedKeysFile {}\nPidFile {}/sshd.pid\nStrictModes no\nUsePAM no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nPubkeyAuthentication yes\nAllowUsers {user}\n",
            host_path.display(),
            authorized.display(),
            dir.path().display()
        ),
    )
    .unwrap();
    let mut daemon = match Command::new(sshd)
        .args(["-D", "-e", "-f"])
        .arg(&config)
        .stderr(std::fs::File::create(dir.path().join("sshd.log")).unwrap())
        .spawn()
    {
        Ok(daemon) => daemon,
        Err(error) => {
            eprintln!("skipped: sshd won't start: {error}");
            return;
        }
    };
    let mut up = false;
    for _ in 0..100 {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            up = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    if !up {
        let _ = daemon.kill();
        let log = std::fs::read_to_string(dir.path().join("sshd.log")).unwrap_or_default();
        eprintln!("skipped: sshd didn't come up: {log}");
        return;
    }
    let mut login = Command::new("ssh");
    login
        .args([
            "-F",
            "/dev/null",
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "IdentitiesOnly=no",
            "-o",
        ])
        .arg(format!("IdentityAgent={}", socket.display()))
        .arg("-p")
        .arg(port.to_string())
        .arg(format!("{user}@127.0.0.1"))
        .arg("echo logged-in-through-the-agent");
    let output = run(login).await;
    let _ = daemon.kill();
    let _ = daemon.wait();
    let log = std::fs::read_to_string(dir.path().join("sshd.log")).unwrap_or_default();
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("logged-in-through-the-agent"),
        "{output:?}\n{log}"
    );
    // One approval, for the key the server accepted: an RSA key, with a SHA-2 signature.
    assert_eq!(keys.asked.load(Ordering::SeqCst), 1);
    assert!(matches!(
        &keys.purposes.lock().unwrap()[0],
        Purpose::Login { user: asked } if *asked == user
    ));
}
