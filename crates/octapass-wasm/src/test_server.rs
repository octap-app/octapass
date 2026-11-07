//! An OPAQUE server inside WASM, so Node tests can run the real client flows end to end without
//! the sync server. Only built with the `test-server` feature.

use octapass_core::opaque::server::{OpaqueServer, ServerLoginState};
use rand_core::OsRng;
use wasm_bindgen::prelude::*;

use crate::{flow_finished, js_error};

#[wasm_bindgen]
pub struct TestOpaqueServer {
    server: OpaqueServer,
}

#[wasm_bindgen]
impl TestOpaqueServer {
    #[wasm_bindgen(constructor)]
    pub fn new() -> TestOpaqueServer {
        TestOpaqueServer {
            server: OpaqueServer::generate(&mut OsRng),
        }
    }

    /// `register/start`: returns `registrationResponse`.
    #[wasm_bindgen(js_name = registrationStart)]
    pub fn registration_start(
        &self,
        email: String,
        #[wasm_bindgen(js_name = registrationRequest)] registration_request: String,
    ) -> Result<String, JsValue> {
        self.server
            .registration_start(&email, &registration_request)
            .map_err(js_error)
    }

    /// `register/finish`: returns the password file to store.
    #[wasm_bindgen(js_name = registrationFinish)]
    pub fn registration_finish(
        &self,
        #[wasm_bindgen(js_name = registrationUpload)] registration_upload: String,
    ) -> Result<String, JsValue> {
        OpaqueServer::registration_finish(&registration_upload).map_err(js_error)
    }

    /// `login/start` (and `reauth/start`). Pass no password file for an unknown account.
    #[wasm_bindgen(js_name = loginStart)]
    pub fn login_start(
        &self,
        email: String,
        #[wasm_bindgen(js_name = passwordFile)] password_file: Option<String>,
        #[wasm_bindgen(js_name = credentialRequest)] credential_request: String,
    ) -> Result<TestServerLogin, JsValue> {
        let (state, credential_response) = self
            .server
            .login_start(
                &email,
                password_file.as_deref(),
                &credential_request,
                &mut OsRng,
            )
            .map_err(js_error)?;
        Ok(TestServerLogin {
            state: Some(state),
            credential_response,
        })
    }
}

impl Default for TestOpaqueServer {
    fn default() -> Self {
        Self::new()
    }
}

#[wasm_bindgen]
pub struct TestServerLogin {
    state: Option<ServerLoginState>,
    credential_response: String,
}

#[wasm_bindgen]
impl TestServerLogin {
    #[wasm_bindgen(getter, js_name = credentialResponse)]
    pub fn credential_response(&self) -> String {
        self.credential_response.clone()
    }

    /// `login/finish`: throws `login_failed` unless the client knew the password.
    pub fn finish(
        &mut self,
        #[wasm_bindgen(js_name = credentialFinalization)] credential_finalization: String,
    ) -> Result<(), JsValue> {
        let state = self.state.take().ok_or_else(flow_finished)?;
        state.finish(&credential_finalization).map_err(js_error)
    }
}
