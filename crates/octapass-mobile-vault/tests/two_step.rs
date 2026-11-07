//! Two-step sign-in against the real sync server, over HTTP: turning it on with an authenticator
//! app, the second step on a new phone (code, recovery code, wrong codes), trusted phones skipping
//! it, and the settings.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use octapass_ffi::DeviceInfo;
use octapass_mobile_vault::model::{SessionStatus, SignInResult, TwoStepMethod, TwoStepProof};
use octapass_mobile_vault::native::fake::FakeNative;
use octapass_mobile_vault::{Config, ErrorCode, Vault};
use tempfile::TempDir;
use zeroize::Zeroizing;

const EMAIL: &str = "ada@example.com";
const PASSWORD: &str = "correct horse battery staple";

struct Server {
    url: String,
    state: octapass_server::AppState,
    _data: TempDir,
    _runtime: tokio::runtime::Runtime,
}

impl Server {
    fn start() -> Self {
        let data = tempfile::tempdir().unwrap();
        let data_dir = data.path().to_str().unwrap().to_owned();
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let (url, state) = runtime.block_on(async {
            let config = octapass_server::Config::from_lookup(|name| match name {
                "OCTAPASS_DATA_DIR" => Some(data_dir.clone()),
                "OCTAPASS_DEV_MODE" => Some("true".into()),
                "OCTAPASS_RATE_LIMITS" => Some("off".into()),
                _ => None,
            })
            .unwrap();
            let state = octapass_server::AppState::new(config).await.unwrap();
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
            let app = octapass_server::router(state.clone())
                .into_make_service_with_connect_info::<SocketAddr>();
            tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
            (url, state)
        });
        Self {
            url,
            state,
            _data: data,
            _runtime: runtime,
        }
    }

    /// The current code of the authenticator app with base32 `secret`, by the server's clock.
    /// Each code works once, so the clock then moves on to the next 30 seconds.
    fn totp(&self, secret: &str) -> String {
        let now = u64::try_from(self.state.clock.now()).unwrap() / 1000;
        let code = octapass_core::tools::totp::totp_code(secret, now)
            .unwrap()
            .code;
        self.state.clock.advance(Duration::from_secs(30));
        code
    }
}

struct Phone {
    vault: Arc<Vault>,
    native: Arc<FakeNative>,
    _dir: TempDir,
}

impl Phone {
    fn new(server: &Server) -> Self {
        let native = Arc::new(FakeNative::default());
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::new(
            Config {
                data_dir: dir.path().to_owned(),
                temp_dir: dir.path().join("tmp"),
                device: DeviceInfo {
                    name: "Test iPhone".into(),
                    platform: "ios".into(),
                },
                pwned_passwords_url: server.url.clone(),
            },
            native.clone(),
            Box::new(|_| {}),
        )
        .unwrap();
        Self {
            vault,
            native,
            _dir: dir,
        }
    }

    fn status(&self) -> SessionStatus {
        self.vault.snapshot().session.status
    }

    /// Signs up and returns the Secret Key.
    fn sign_up(&self, server: &Server) -> String {
        let started = self
            .vault
            .start_signup(&server.url, EMAIL, secret(PASSWORD))
            .unwrap();
        let code = started.dev_verification_code.unwrap();
        self.vault
            .finish_signup(&started.signup_id, &code)
            .unwrap()
            .secret_key
    }

    fn sign_in(&self, server: &Server, secret_key: Option<&str>) -> SignInResult {
        self.vault
            .sign_in(&server.url, EMAIL, secret(PASSWORD), secret_key.map(secret))
            .unwrap()
    }

    fn finish(&self, proof: TwoStepProof) -> Option<ErrorCode> {
        self.vault
            .finish_two_step(proof)
            .err()
            .map(|error| error.code)
    }

    /// Turns two-step sign-in on. Returns the authenticator secret and the recovery codes.
    fn enable(&self, server: &Server) -> (String, Vec<String>) {
        let setup = self.vault.start_totp_setup(secret(PASSWORD)).unwrap();
        assert!(setup.otpauth_uri.starts_with("otpauth://totp/"));
        let confirmed = self
            .vault
            .confirm_totp_setup(&server.totp(&setup.secret))
            .unwrap();
        (setup.secret, confirmed.recovery_codes.unwrap())
    }

    fn trusted_device_token(&self) -> Option<String> {
        self.native
            .secret_names()
            .into_iter()
            .find(|name| name.starts_with("trustedDevice."))
            .and_then(|name| self.native.secrets.lock().unwrap().get(&name).cloned())
    }
}

fn secret(text: &str) -> Zeroizing<String> {
    Zeroizing::new(text.to_owned())
}

fn totp(code: String) -> TwoStepProof {
    TwoStepProof::Totp { code }
}

fn recovery(code: &str) -> TwoStepProof {
    TwoStepProof::RecoveryCode { code: code.into() }
}

/// A code that isn't `code`.
fn wrong(code: &str) -> TwoStepProof {
    let other = (code.parse::<u32>().unwrap() + 1) % 1_000_000;
    totp(format!("{other:06}"))
}

fn two_step_required() -> SignInResult {
    SignInResult::TwoStepRequired {
        methods: vec![TwoStepMethod::Totp, TwoStepMethod::RecoveryCode],
    }
}

#[test]
fn a_new_phone_finishes_with_an_authenticator_code_then_is_trusted() {
    let server = Server::start();
    let first = Phone::new(&server);
    let secret_key = first.sign_up(&server);
    assert!(first.trusted_device_token().is_some());
    let status = first.vault.two_step_status().unwrap();
    assert!(!status.enabled && !status.security_keys_supported);

    assert_eq!(
        first
            .vault
            .start_totp_setup(secret("wrong"))
            .unwrap_err()
            .code,
        ErrorCode::InvalidCredentials
    );
    assert_eq!(
        first.vault.confirm_totp_setup("123456").unwrap_err().code,
        ErrorCode::TwoStepExpired,
        "no setup started"
    );
    let setup = first.vault.start_totp_setup(secret(PASSWORD)).unwrap();
    let code = server.totp(&setup.secret);
    let TwoStepProof::Totp { code: wrong_code } = wrong(&code) else {
        unreachable!()
    };
    assert_eq!(
        first
            .vault
            .confirm_totp_setup(&wrong_code)
            .unwrap_err()
            .code,
        ErrorCode::InvalidTwoStepCode
    );
    let confirmed = first.vault.confirm_totp_setup(&code).unwrap();
    assert_eq!(confirmed.recovery_codes.unwrap().len(), 10);
    let status = first.vault.two_step_status().unwrap();
    assert!(status.enabled && !status.security_keys_supported);
    assert_eq!(status.recovery_codes_left, 10);

    let second = Phone::new(&server);
    assert_eq!(
        second.sign_in(&server, Some(&secret_key)),
        two_step_required()
    );
    assert_eq!(second.status(), SessionStatus::SignedOut);
    let code = server.totp(&setup.secret);
    assert_eq!(
        second.finish(wrong(&code)),
        Some(ErrorCode::InvalidTwoStepCode)
    );
    assert_eq!(
        second.finish(TwoStepProof::SecurityKey),
        Some(ErrorCode::SecurityKeyUnsupported)
    );
    assert_eq!(second.finish(totp(code)), None);
    assert_eq!(second.status(), SessionStatus::Unlocked);
    assert!(second.trusted_device_token().is_some());
    assert_eq!(
        second.finish(totp(server.totp(&setup.secret))),
        Some(ErrorCode::TwoStepExpired),
        "the sign-in is over"
    );

    // Signing in again on either phone skips the second step.
    second.vault.lock();
    assert_eq!(second.sign_in(&server, None), SignInResult::SignedIn);
    assert_eq!(first.sign_in(&server, None), SignInResult::SignedIn);

    // Signing out ends the trust.
    second.vault.sign_out().unwrap();
    assert!(second.trusted_device_token().is_none());
    assert_eq!(
        second.sign_in(&server, Some(&secret_key)),
        two_step_required()
    );
}

#[test]
fn recovery_codes_wrong_codes_and_the_settings() {
    let server = Server::start();
    let first = Phone::new(&server);
    let secret_key = first.sign_up(&server);
    let (authenticator, codes) = first.enable(&server);

    // A recovery code works once.
    let second = Phone::new(&server);
    second.sign_in(&server, Some(&secret_key));
    assert_eq!(second.finish(recovery(&codes[0].to_lowercase())), None);
    let third = Phone::new(&server);
    third.sign_in(&server, Some(&secret_key));
    assert_eq!(
        third.finish(recovery(&codes[0])),
        Some(ErrorCode::InvalidTwoStepCode)
    );

    // Five wrong codes end the challenge; starting over works.
    let code = server.totp(&authenticator);
    for _ in 0..4 {
        assert_eq!(
            third.finish(wrong(&code)),
            Some(ErrorCode::InvalidTwoStepCode)
        );
    }
    assert_eq!(third.finish(totp(code)), Some(ErrorCode::TwoStepExpired));
    assert_eq!(
        third.sign_in(&server, Some(&secret_key)),
        two_step_required()
    );
    assert_eq!(third.finish(totp(server.totp(&authenticator))), None);
    assert_eq!(
        first.vault.two_step_status().unwrap().recovery_codes_left,
        9
    );

    // New recovery codes replace the old ones.
    assert_eq!(
        first
            .vault
            .renew_recovery_codes(secret("wrong"))
            .unwrap_err()
            .code,
        ErrorCode::InvalidCredentials
    );
    let renewed = first.vault.renew_recovery_codes(secret(PASSWORD)).unwrap();
    assert_eq!(renewed.len(), 10);
    assert!(renewed.iter().all(|code| !codes.contains(code)));
    let fourth = Phone::new(&server);
    fourth.sign_in(&server, Some(&secret_key));
    assert_eq!(
        fourth.finish(recovery(&codes[1])),
        Some(ErrorCode::InvalidTwoStepCode)
    );
    assert_eq!(fourth.finish(recovery(&renewed[0])), None);

    // A new authenticator replaces the old one, without new recovery codes.
    let setup = first.vault.start_totp_setup(secret(PASSWORD)).unwrap();
    let confirmed = first
        .vault
        .confirm_totp_setup(&server.totp(&setup.secret))
        .unwrap();
    assert!(confirmed.recovery_codes.is_none());
    let fifth = Phone::new(&server);
    fifth.sign_in(&server, Some(&secret_key));
    assert_eq!(
        fifth.finish(totp(server.totp(&authenticator))),
        Some(ErrorCode::InvalidTwoStepCode)
    );
    assert_eq!(fifth.finish(totp(server.totp(&setup.secret))), None);

    // No security keys to remove; ids that can't be one never reach the server.
    for id in ["0190b3a2-0000-7000-8000-000000000000", "../../account"] {
        assert_eq!(
            first
                .vault
                .remove_security_key(id, secret(PASSWORD))
                .unwrap_err()
                .code,
            ErrorCode::NotFound,
            "{id}"
        );
    }

    // Turning it off.
    assert_eq!(
        first
            .vault
            .disable_two_step(secret("wrong"))
            .unwrap_err()
            .code,
        ErrorCode::InvalidCredentials
    );
    first.vault.disable_two_step(secret(PASSWORD)).unwrap();
    let status = first.vault.two_step_status().unwrap();
    assert!(!status.enabled && status.security_keys.is_empty());
    assert_eq!(
        Phone::new(&server).sign_in(&server, Some(&secret_key)),
        SignInResult::SignedIn
    );
    first.vault.lock();
    assert_eq!(
        first.vault.two_step_status().unwrap_err().code,
        ErrorCode::Locked
    );
}
