//! The toolkit's files against the real tools people use them with: `openssl`, `ssh-keygen` and
//! `gpg`. A round trip through our own reader proves little; these read what we write, and we read
//! what they write. A tool that isn't installed skips its test with a note on stderr.

#![cfg(feature = "toolkit")]

use std::path::Path;
use std::process::{Command, Stdio};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use octapass_core::tools::toolkit::run;
use rand_core::OsRng;
use serde_json::{Value, json};

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn call(op: &str, input: Value) -> Value {
    serde_json::from_str(&run(op, &input.to_string(), now_ms(), &mut OsRng).unwrap()).unwrap()
}

fn installed(tool: &str) -> bool {
    let found = Command::new(tool)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok();
    if !found {
        eprintln!("skipped: {tool} isn't installed");
    }
    found
}

/// Runs a tool that must succeed, and returns stdout.
fn tool(program: &str, args: &[&str], dir: &Path) -> String {
    let output = Command::new(program)
        .args(args)
        .current_dir(dir)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{program} {args:?}: {}\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn write(dir: &Path, name: &str, text: &Value) {
    std::fs::write(dir.join(name), text.as_str().unwrap()).unwrap();
}

#[test]
fn openssl_verifies_a_local_ca_chain_with_its_name_constraints() {
    if !installed("openssl") {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let dir = dir.path();
    for key_type in ["p256", "p384", "ed25519", "rsa2048"] {
        let ca = call("cert.caCreate", json!({ "keyType": "p256" }));
        let leaf = call(
            "cert.issue",
            json!({
                "sans": ["app.test", "localhost", "127.0.0.1"],
                "keyType": key_type,
                "caCertificate": ca["certificate"],
                "caKey": ca["privateKey"],
            }),
        );
        write(dir, "ca.pem", &ca["certificate"]);
        write(dir, "leaf.pem", &leaf["certificate"]);
        write(dir, "leaf.key", &leaf["privateKey"]);
        let verified = tool(
            "openssl",
            &[
                "verify",
                "-x509_strict",
                "-CAfile",
                "ca.pem",
                "-verify_hostname",
                "app.test",
                "-purpose",
                "sslserver",
                "leaf.pem",
            ],
            dir,
        );
        assert!(verified.contains("leaf.pem: OK"), "{verified}");
        let text = tool(
            "openssl",
            &["x509", "-in", "ca.pem", "-noout", "-text"],
            dir,
        );
        assert!(text.contains("Name Constraints: critical"), "{text}");
        // The certificate and the key belong together, as openssl sees them.
        let from_cert = tool(
            "openssl",
            &["x509", "-in", "leaf.pem", "-noout", "-pubkey"],
            dir,
        );
        let from_key = tool("openssl", &["pkey", "-in", "leaf.key", "-pubout"], dir);
        assert_eq!(from_cert, from_key, "{key_type}");
    }
}

#[test]
fn openssl_refuses_a_public_name_under_a_constrained_ca() {
    if !installed("openssl") {
        return;
    }
    // Our issuer refuses this; an unconstrained leaf signed outside it shows a verifier would too.
    let dir = tempfile::tempdir().unwrap();
    let dir = dir.path();
    let ca = call("cert.caCreate", json!({}));
    write(dir, "ca.pem", &ca["certificate"]);
    write(dir, "ca.key", &ca["privateKey"]);
    tool(
        "openssl",
        &[
            "req",
            "-new",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-nodes",
            "-keyout",
            "evil.key",
            "-out",
            "evil.csr",
            "-subj",
            "/CN=example.com",
            "-addext",
            "subjectAltName=DNS:example.com",
        ],
        dir,
    );
    tool(
        "openssl",
        &[
            "x509",
            "-req",
            "-in",
            "evil.csr",
            "-CA",
            "ca.pem",
            "-CAkey",
            "ca.key",
            "-CAcreateserial",
            "-days",
            "10",
            "-copy_extensions",
            "copy",
            "-out",
            "evil.pem",
        ],
        dir,
    );
    let output = Command::new("openssl")
        .args(["verify", "-CAfile", "ca.pem", "evil.pem"])
        .current_dir(dir)
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "a constrained CA must not vouch for example.com"
    );
    let said = String::from_utf8_lossy(&output.stderr).to_string()
        + &String::from_utf8_lossy(&output.stdout);
    assert!(
        said.contains("name constraint") || said.contains("permitted subtree"),
        "{said}"
    );
}

#[test]
fn openssl_reads_our_csr_and_we_read_its_certificate() {
    if !installed("openssl") {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let dir = dir.path();
    let made = call(
        "cert.csr",
        json!({ "sans": ["a.test", "10.0.0.1"], "subject": { "organization": "Ünï Acme", "country": "EG" } }),
    );
    write(dir, "a.csr", &made["csr"]);
    let verified = tool(
        "openssl",
        &["req", "-in", "a.csr", "-noout", "-verify", "-text"],
        dir,
    );
    assert!(verified.contains("DNS:a.test"), "{verified}");
    assert!(verified.contains("IP Address:10.0.0.1"), "{verified}");

    tool(
        "openssl",
        &[
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            "o.key",
            "-out",
            "o.pem",
            "-days",
            "30",
            "-subj",
            "/CN=openssl.test/O=Acme",
            "-addext",
            "subjectAltName=DNS:openssl.test",
        ],
        dir,
    );
    let pem = std::fs::read_to_string(dir.join("o.pem")).unwrap();
    let report = call("cert.read", json!({ "text": pem, "host": "openssl.test" }));
    let info = &report["certificates"][0];
    assert_eq!(info["commonName"], "openssl.test");
    assert_eq!(info["keyType"], "rsa");
    assert_eq!(info["keyBits"], 2048);
    assert_eq!(report["problems"], json!([]));
    let expected = tool(
        "openssl",
        &["x509", "-in", "o.pem", "-noout", "-fingerprint", "-sha256"],
        dir,
    );
    assert_eq!(expected.trim().rsplit('=').next().unwrap(), info["sha256"]);
}

#[test]
fn pkcs12_both_ways_with_openssl() {
    if !installed("openssl") {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let dir = dir.path();
    let ca = call("cert.caCreate", json!({}));
    let leaf = call(
        "cert.issue",
        json!({ "sans": ["a.test"], "caCertificate": ca["certificate"], "caKey": ca["privateKey"] }),
    );
    let ours = call(
        "cert.p12Write",
        json!({ "certificate": leaf["certificate"], "chain": leaf["chain"], "privateKey": leaf["privateKey"], "password": "pässword", "friendlyName": "Test" }),
    );
    std::fs::write(
        dir.join("ours.p12"),
        STANDARD.decode(ours["base64"].as_str().unwrap()).unwrap(),
    )
    .unwrap();
    let out = tool(
        "openssl",
        &[
            "pkcs12",
            "-in",
            "ours.p12",
            "-passin",
            "pass:pässword",
            "-nodes",
        ],
        dir,
    );
    assert!(out.contains("friendlyName: Test"), "{out}");
    assert_eq!(out.matches("BEGIN CERTIFICATE").count(), 2, "{out}");
    assert!(out.contains("BEGIN PRIVATE KEY"), "{out}");

    // OpenSSL's default, and the legacy format old Windows and macOS exports use.
    write(dir, "leaf.pem", &leaf["certificate"]);
    write(dir, "leaf.key", &leaf["privateKey"]);
    write(dir, "ca.pem", &ca["certificate"]);
    for (name, extra) in [
        ("modern.p12", vec![]),
        (
            "legacy.p12",
            vec![
                "-keypbe",
                "PBE-SHA1-3DES",
                "-certpbe",
                "PBE-SHA1-3DES",
                "-macalg",
                "sha1",
            ],
        ),
    ] {
        let mut args = vec![
            "pkcs12",
            "-export",
            "-in",
            "leaf.pem",
            "-inkey",
            "leaf.key",
            "-certfile",
            "ca.pem",
            "-passout",
            "pass:pw",
            "-out",
            name,
        ];
        args.extend(extra);
        tool("openssl", &args, dir);
        let file = std::fs::read(dir.join(name)).unwrap();
        let read = call(
            "cert.p12Read",
            json!({ "base64": STANDARD.encode(file), "password": "pw" }),
        );
        assert_eq!(read["certificate"], leaf["certificate"], "{name}");
        assert_eq!(read["chain"], ca["certificate"], "{name}");
        assert_eq!(read["info"]["commonName"], "a.test", "{name}");
        assert!(read["privateKey"].as_str().is_some(), "{name}");
    }
}

#[test]
fn key_formats_with_openssl() {
    if !installed("openssl") {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let dir = dir.path();
    for key_type in ["p256", "p384", "ed25519", "rsa2048"] {
        let made = call("key.generate", json!({ "type": key_type }));
        write(dir, "key.pem", &made["privateKey"]);
        let public = tool("openssl", &["pkey", "-in", "key.pem", "-pubout"], dir);
        assert_eq!(public, made["publicPem"].as_str().unwrap(), "{key_type}");

        // Encrypted PKCS#8 we write, openssl opens.
        let protected = call(
            "key.convert",
            json!({ "key": made["privateKey"], "to": "pkcs8-pem", "toPassphrase": "hunter2" }),
        );
        write(dir, "enc.pem", &protected["value"]);
        // Compared by public key: OpenSSL drops the public half PKCS#8 v2 Ed25519 keys carry.
        let opened = tool(
            "openssl",
            &[
                "pkey",
                "-in",
                "enc.pem",
                "-passin",
                "pass:hunter2",
                "-pubout",
            ],
            dir,
        );
        assert_eq!(opened, made["publicPem"].as_str().unwrap(), "{key_type}");

        // And what openssl encrypts, we open.
        tool(
            "openssl",
            &[
                "pkey",
                "-in",
                "key.pem",
                "-aes-256-cbc",
                "-passout",
                "pass:hunter2",
                "-out",
                "theirs.pem",
            ],
            dir,
        );
        let theirs = std::fs::read_to_string(dir.join("theirs.pem")).unwrap();
        let read = call(
            "key.inspect",
            json!({ "key": theirs, "passphrase": "hunter2" }),
        );
        assert_eq!(read["fingerprints"], made["fingerprints"], "{key_type}");

        if key_type != "ed25519" {
            let traditional = call(
                "key.convert",
                json!({ "key": made["privateKey"], "to": "traditional-pem" }),
            );
            write(dir, "t.pem", &traditional["value"]);
            let public = tool("openssl", &["pkey", "-in", "t.pem", "-pubout"], dir);
            assert_eq!(public, made["publicPem"].as_str().unwrap(), "{key_type}");
        }
    }
}

#[test]
fn signatures_with_openssl() {
    if !installed("openssl") {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let dir = dir.path();
    // A token's signature is over `header.payload`: openssl checks it from the public PEM alone.
    for (algorithm, digest) in [("RS256", Some("-sha256")), ("PS384", None), ("EdDSA", None)] {
        let key = call(
            "jwt.generateKey",
            json!({ "algorithm": algorithm, "bits": 2048 }),
        );
        let signed = call(
            "jwt.sign",
            json!({ "payload": { "sub": "ada" }, "algorithm": algorithm, "key": key["privateKey"] }),
        );
        let token = signed["token"].as_str().unwrap();
        let (input, signature) = token.rsplit_once('.').unwrap();
        std::fs::write(dir.join("input"), input).unwrap();
        std::fs::write(
            dir.join("sig"),
            octapass_core::encoding::b64_decode(signature).unwrap(),
        )
        .unwrap();
        write(dir, "pub.pem", &key["publicKey"]);
        let out = match (algorithm, digest) {
            ("EdDSA", _) => tool(
                "openssl",
                &[
                    "pkeyutl", "-verify", "-pubin", "-inkey", "pub.pem", "-rawin", "-in", "input",
                    "-sigfile", "sig",
                ],
                dir,
            ),
            ("PS384", _) => tool(
                "openssl",
                &[
                    "dgst",
                    "-sha384",
                    "-verify",
                    "pub.pem",
                    "-sigopt",
                    "rsa_padding_mode:pss",
                    "-sigopt",
                    "rsa_pss_saltlen:48",
                    "-signature",
                    "sig",
                    "input",
                ],
                dir,
            ),
            (_, Some(digest)) => tool(
                "openssl",
                &[
                    "dgst",
                    digest,
                    "-verify",
                    "pub.pem",
                    "-signature",
                    "sig",
                    "input",
                ],
                dir,
            ),
            _ => unreachable!(),
        };
        assert!(
            out.contains("Verified OK") || out.contains("Signature Verified Successfully"),
            "{algorithm}: {out}"
        );
    }
}

#[test]
fn ssh_keygen_reads_our_openssh_output() {
    if Command::new("ssh-keygen").arg("-h").output().is_err() {
        eprintln!("skipped: ssh-keygen isn't installed");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let dir = dir.path();
    for key_type in ["ed25519", "p256"] {
        let made = call("key.generate", json!({ "type": key_type }));
        let private = call(
            "key.convert",
            json!({ "key": made["privateKey"], "to": "openssh-private", "comment": "me" }),
        );
        let path = dir.join("id");
        std::fs::write(&path, private["value"].as_str().unwrap()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let public = tool("ssh-keygen", &["-y", "-f", "id"], dir);
        assert!(
            public.starts_with(made["publicOpenssh"].as_str().unwrap()),
            "{public}"
        );
        let fingerprint = tool("ssh-keygen", &["-l", "-E", "sha256", "-f", "id"], dir);
        assert!(
            fingerprint.contains(made["fingerprints"]["sshSha256"].as_str().unwrap()),
            "{fingerprint}"
        );
    }
}

#[cfg(feature = "pgp")]
#[test]
fn gpg_imports_and_uses_our_key() {
    if !installed("gpg") {
        return;
    }
    let home = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(home.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let dir = home.path();
    let made = call(
        "key.gpg",
        json!({ "userId": "Ada Lovelace <ada@example.test>" }),
    );
    write(dir, "secret.asc", &made["privateKey"]);
    let gpg = |args: &[&str]| {
        let mut all = vec![
            "--homedir",
            dir.to_str().unwrap(),
            "--batch",
            "--yes",
            "--pinentry-mode",
            "loopback",
            "--passphrase",
            "",
        ];
        all.extend_from_slice(args);
        tool("gpg", &all, dir)
    };
    gpg(&["--import", "secret.asc"]);
    let listed = gpg(&["--with-colons", "--fingerprint", "--list-secret-keys"]);
    assert!(
        listed.contains(made["fingerprint"].as_str().unwrap()),
        "{listed}"
    );
    assert!(listed.contains("Ada Lovelace"), "{listed}");

    // Sign with the primary key, encrypt to the subkey: both halves work in real gpg.
    std::fs::write(dir.join("m.txt"), "hello").unwrap();
    gpg(&["--armor", "--output", "m.sig", "--detach-sign", "m.txt"]);
    let output = Command::new("gpg")
        .args([
            "--homedir",
            dir.to_str().unwrap(),
            "--batch",
            "--verify",
            "m.sig",
            "m.txt",
        ])
        .current_dir(dir)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    gpg(&[
        "--trust-model",
        "always",
        "--armor",
        "--output",
        "m.gpg",
        "--recipient",
        "ada@example.test",
        "--encrypt",
        "m.txt",
    ]);
    gpg(&["--output", "m.out", "--decrypt", "m.gpg"]);
    assert_eq!(std::fs::read_to_string(dir.join("m.out")).unwrap(), "hello");
    let _ = Command::new("gpgconf")
        .args(["--homedir", dir.to_str().unwrap(), "--kill", "all"])
        .status();
}

#[test]
fn digests_match_openssl() {
    if !installed("openssl") {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let dir = dir.path();
    std::fs::write(dir.join("f"), "the quick brown fox").unwrap();
    let digests = call("hash.digest", json!({ "text": "the quick brown fox" }));
    for (ours, theirs) in [
        ("sha1", "-sha1"),
        ("sha224", "-sha224"),
        ("sha256", "-sha256"),
        ("sha384", "-sha384"),
        ("sha512", "-sha512"),
        ("sha3-224", "-sha3-224"),
        ("sha3-256", "-sha3-256"),
        ("sha3-384", "-sha3-384"),
        ("sha3-512", "-sha3-512"),
        ("blake2b", "-blake2b512"),
        ("blake2s", "-blake2s256"),
    ] {
        let expected = tool("openssl", &["dgst", theirs, "-r", "f"], dir);
        let hash = digests["hashes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|hash| hash["algorithm"] == ours)
            .unwrap();
        assert_eq!(
            expected.split_whitespace().next().unwrap(),
            hash["hex"],
            "{ours}"
        );
    }
}
