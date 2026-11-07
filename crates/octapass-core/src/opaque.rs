//! OPAQUE (RFC 9807) client flows, with every message as base64url for the HTTP API.
//!
//! Ciphersuite: ristretto255 OPRF, `TripleDh<Ristretto255, Sha512>` key exchange and an identity
//! key-stretching function, because Argon2id already ran on the client before OPAQUE sees the
//! password. The OPAQUE password is `auth_secret`; the credential identifier is the normalised
//! email; client and server identities are the defaults (their public keys) and there is no
//! context string.

use opaque_ke::ciphersuite::CipherSuite;
use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialResponse, RegistrationResponse, Ristretto255,
    TripleDh,
};
use rand_core::CryptoRngCore;

use crate::encoding::{b64_decode, b64_encode};
use crate::error::{Error, Result};
use crate::keys::SymmetricKey;

/// The Octa Pass OPAQUE ciphersuite. Servers must use exactly this one.
pub struct OctaPassCipherSuite;

impl CipherSuite for OctaPassCipherSuite {
    type OprfCs = Ristretto255;
    type KeyExchange = TripleDh<Ristretto255, sha2::Sha512>;
    type Ksf = opaque_ke::ksf::Identity;
}

type Suite = OctaPassCipherSuite;

/// Client state between `register/start` and `register/finish`.
pub struct RegistrationClient {
    state: ClientRegistration<Suite>,
}

impl RegistrationClient {
    /// Returns the client state and `registrationRequest`.
    pub fn start(
        auth_secret: &SymmetricKey,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self, String)> {
        let result = ClientRegistration::<Suite>::start(rng, auth_secret.as_bytes())
            .map_err(|_| Error::OpaqueProtocol)?;
        Ok((
            Self {
                state: result.state,
            },
            b64_encode(&result.message.serialize()),
        ))
    }

    /// Takes `registrationResponse` and returns `registrationUpload`.
    pub fn finish(
        self,
        auth_secret: &SymmetricKey,
        registration_response: &str,
        rng: &mut impl CryptoRngCore,
    ) -> Result<String> {
        let response =
            RegistrationResponse::<Suite>::deserialize(&b64_decode(registration_response)?)
                .map_err(|_| Error::InvalidOpaqueMessage)?;
        let result = self
            .state
            .finish(
                rng,
                auth_secret.as_bytes(),
                response,
                ClientRegistrationFinishParameters::default(),
            )
            .map_err(|_| Error::OpaqueProtocol)?;
        Ok(b64_encode(&result.message.serialize()))
    }
}

/// Client state between `login/start` and `login/finish`.
pub struct LoginClient {
    state: ClientLogin<Suite>,
}

impl LoginClient {
    /// Returns the client state and `credentialRequest`.
    pub fn start(
        auth_secret: &SymmetricKey,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self, String)> {
        let result = ClientLogin::<Suite>::start(rng, auth_secret.as_bytes())
            .map_err(|_| Error::OpaqueProtocol)?;
        Ok((
            Self {
                state: result.state,
            },
            b64_encode(&result.message.serialize()),
        ))
    }

    /// Takes `credentialResponse` and returns `credentialFinalization`.
    ///
    /// A wrong password (or Secret Key) and a server that doesn't know the account fail the same
    /// way, with [`Error::LoginFailed`].
    pub fn finish(
        self,
        auth_secret: &SymmetricKey,
        credential_response: &str,
        rng: &mut impl CryptoRngCore,
    ) -> Result<String> {
        let response = CredentialResponse::<Suite>::deserialize(&b64_decode(credential_response)?)
            .map_err(|_| Error::InvalidOpaqueMessage)?;
        let result = self
            .state
            .finish(
                rng,
                auth_secret.as_bytes(),
                response,
                ClientLoginFinishParameters::default(),
            )
            .map_err(|_| Error::LoginFailed)?;
        Ok(b64_encode(&result.message.serialize()))
    }
}

/// Re-authentication before a dangerous action such as deleting the account
/// (`/v1/auth/reauth/start` and `/finish`). It is an ordinary OPAQUE login with the master
/// password, but the server answers with a single-use reauth token, so the current session and
/// its keys stay exactly as they are.
pub struct ReauthClient(LoginClient);

impl ReauthClient {
    /// Returns the client state and `credentialRequest`.
    pub fn start(
        auth_secret: &SymmetricKey,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self, String)> {
        let (login, request) = LoginClient::start(auth_secret, rng)?;
        Ok((Self(login), request))
    }

    /// Takes `credentialResponse` and returns `credentialFinalization`.
    pub fn finish(
        self,
        auth_secret: &SymmetricKey,
        credential_response: &str,
        rng: &mut impl CryptoRngCore,
    ) -> Result<String> {
        self.0.finish(auth_secret, credential_response, rng)
    }
}

/// The server half, for tests, fixtures and servers that want this crate's exact ciphersuite.
#[cfg(any(test, feature = "opaque-server"))]
pub mod server {
    use opaque_ke::{
        CredentialFinalization, CredentialRequest, RegistrationRequest, RegistrationUpload,
        ServerLogin, ServerLoginParameters, ServerRegistration, ServerSetup,
    };
    use zeroize::Zeroizing;

    use super::*;
    use crate::kdf::normalize_email;

    /// The server's long-term OPAQUE state (OPRF seed and key-exchange keypair). It must persist
    /// across restarts, or every registered account stops working.
    pub struct OpaqueServer {
        setup: ServerSetup<Suite>,
    }

    impl OpaqueServer {
        pub fn generate(rng: &mut impl CryptoRngCore) -> Self {
            Self {
                setup: ServerSetup::<Suite>::new(rng),
            }
        }

        pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
            let setup = ServerSetup::<Suite>::deserialize(bytes).map_err(|_| Error::InvalidKey)?;
            Ok(Self { setup })
        }

        pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
            Zeroizing::new(self.setup.serialize().to_vec())
        }

        /// Takes `registrationRequest`, returns `registrationResponse`.
        pub fn registration_start(
            &self,
            email: &str,
            registration_request: &str,
        ) -> Result<String> {
            let request =
                RegistrationRequest::<Suite>::deserialize(&b64_decode(registration_request)?)
                    .map_err(|_| Error::InvalidOpaqueMessage)?;
            let result = ServerRegistration::<Suite>::start(
                &self.setup,
                request,
                normalize_email(email).as_bytes(),
            )
            .map_err(|_| Error::OpaqueProtocol)?;
            Ok(b64_encode(&result.message.serialize()))
        }

        /// Takes `registrationUpload`, returns the password file to store (base64url).
        pub fn registration_finish(registration_upload: &str) -> Result<String> {
            let upload =
                RegistrationUpload::<Suite>::deserialize(&b64_decode(registration_upload)?)
                    .map_err(|_| Error::InvalidOpaqueMessage)?;
            Ok(b64_encode(
                &ServerRegistration::<Suite>::finish(upload).serialize(),
            ))
        }

        /// Takes `credentialRequest` and the stored password file, returns the login state and
        /// `credentialResponse`. Pass `None` for unknown accounts: OPAQUE then answers with a
        /// fake response that is indistinguishable from a real one.
        pub fn login_start(
            &self,
            email: &str,
            password_file: Option<&str>,
            credential_request: &str,
            rng: &mut impl CryptoRngCore,
        ) -> Result<(ServerLoginState, String)> {
            let password_file = password_file
                .map(|file| {
                    ServerRegistration::<Suite>::deserialize(&b64_decode(file)?)
                        .map_err(|_| Error::InvalidOpaqueMessage)
                })
                .transpose()?;
            let request = CredentialRequest::<Suite>::deserialize(&b64_decode(credential_request)?)
                .map_err(|_| Error::InvalidOpaqueMessage)?;
            let result = ServerLogin::start(
                rng,
                &self.setup,
                password_file,
                request,
                normalize_email(email).as_bytes(),
                ServerLoginParameters::default(),
            )
            .map_err(|_| Error::OpaqueProtocol)?;
            Ok((
                ServerLoginState {
                    state: result.state,
                },
                b64_encode(&result.message.serialize()),
            ))
        }
    }

    /// Server state between `login/start` and `login/finish`.
    pub struct ServerLoginState {
        state: ServerLogin<Suite>,
    }

    impl ServerLoginState {
        /// Takes `credentialFinalization`. Succeeds only if the client knew `auth_secret`.
        pub fn finish(self, credential_finalization: &str) -> Result<()> {
            let message =
                CredentialFinalization::<Suite>::deserialize(&b64_decode(credential_finalization)?)
                    .map_err(|_| Error::LoginFailed)?;
            self.state
                .finish(message, ServerLoginParameters::default())
                .map(|_| ())
                .map_err(|_| Error::LoginFailed)
        }
    }
}

#[cfg(test)]
mod tests {
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    use super::server::OpaqueServer;
    use super::*;

    fn register(server: &OpaqueServer, secret: &SymmetricKey, rng: &mut ChaCha20Rng) -> String {
        let (client, request) = RegistrationClient::start(secret, rng).unwrap();
        let response = server
            .registration_start("A@example.com ", &request)
            .unwrap();
        let upload = client.finish(secret, &response, rng).unwrap();
        OpaqueServer::registration_finish(&upload).unwrap()
    }

    fn login(
        server: &OpaqueServer,
        file: Option<&str>,
        secret: &SymmetricKey,
        rng: &mut ChaCha20Rng,
    ) -> Result<()> {
        let (client, request) = LoginClient::start(secret, rng)?;
        let (state, response) = server.login_start("a@example.com", file, &request, rng)?;
        let finalization = client.finish(secret, &response, rng)?;
        state.finish(&finalization)
    }

    #[test]
    fn register_then_login() {
        let mut rng = ChaCha20Rng::seed_from_u64(7);
        let server = OpaqueServer::generate(&mut rng);
        let secret = SymmetricKey::from_bytes([3; 32]);
        let file = register(&server, &secret, &mut rng);

        login(&server, Some(&file), &secret, &mut rng).unwrap();

        let wrong = SymmetricKey::from_bytes([4; 32]);
        assert_eq!(
            login(&server, Some(&file), &wrong, &mut rng).unwrap_err(),
            Error::LoginFailed
        );
        assert_eq!(
            login(&server, None, &secret, &mut rng).unwrap_err(),
            Error::LoginFailed
        );
    }

    #[test]
    fn server_setup_survives_a_restart() {
        let mut rng = ChaCha20Rng::seed_from_u64(8);
        let server = OpaqueServer::generate(&mut rng);
        let secret = SymmetricKey::from_bytes([3; 32]);
        let file = register(&server, &secret, &mut rng);

        let restarted = OpaqueServer::from_bytes(&server.to_bytes()).unwrap();
        login(&restarted, Some(&file), &secret, &mut rng).unwrap();
    }

    #[test]
    fn garbage_messages_are_rejected() {
        let mut rng = ChaCha20Rng::seed_from_u64(9);
        let secret = SymmetricKey::from_bytes([3; 32]);
        let (client, _) = LoginClient::start(&secret, &mut rng).unwrap();
        assert_eq!(
            client.finish(&secret, "AAAA", &mut rng).unwrap_err(),
            Error::InvalidOpaqueMessage
        );
        assert_eq!(
            OpaqueServer::registration_finish("not base64!").unwrap_err(),
            Error::InvalidBase64
        );
    }
}
