//! Android only. The HTTPS clients check certificates with Android's own verifier
//! (`rustls-platform-verifier`), as `HttpsURLConnection` would, so user and enterprise CAs and
//! revocation apply. The verifier calls into the JVM, so the app hands it its context once,
//! before the first request: `app.octap.vault.PlatformVerifier.init(context)`.

use jni::EnvUnowned;
use jni::errors::ThrowRuntimeExAndDefault;
use jni::objects::{JClass, JObject};

#[unsafe(no_mangle)]
pub extern "system" fn Java_app_octapass_vault_PlatformVerifier_init<'caller>(
    mut env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    context: JObject<'caller>,
) {
    env.with_env(|env| rustls_platform_verifier::android::init_with_env(env, context))
        .resolve::<ThrowRuntimeExAndDefault>()
}
