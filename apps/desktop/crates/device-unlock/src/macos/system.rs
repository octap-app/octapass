//! The real LocalAuthentication and Keychain calls.
//!
//! Items go to the data protection keychain, which is what honours `SecAccessControl`. That
//! keychain needs the app to be signed with an application identifier; an unsigned development
//! build gets `errSecMissingEntitlement`, and then the item is kept in the login keychain instead,
//! where only this app can read it without a macOS prompt. Either way it is only read after
//! LocalAuthentication succeeded (see the module above), so the user-facing behaviour is the same.

use std::sync::mpsc;

use block2::RcBlock;
use core_foundation::base::{CFType, CFTypeRef, TCFType, kCFAllocatorDefault};
use core_foundation::boolean::CFBoolean;
use core_foundation::data::{CFData, CFDataRef};
use core_foundation::dictionary::{CFDictionary, CFDictionaryRef};
use core_foundation::error::{CFError, CFErrorRef};
use core_foundation::number::CFNumber;
use core_foundation::string::{CFString, CFStringRef};
use objc2::rc::Retained;
use objc2::runtime::Bool;
use objc2_foundation::{NSError, NSString};
use objc2_local_authentication::{LAContext, LAError, LAPolicy};
use security_framework_sys::access_control::{
    SecAccessControlCreateWithFlags, kSecAccessControlBiometryCurrentSet,
    kSecAccessControlDevicePasscode, kSecAccessControlOr,
    kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
    kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
};
use security_framework_sys::item::{
    kSecAttrAccessControl, kSecAttrAccount, kSecAttrService, kSecClass, kSecClassGenericPassword,
    kSecMatchLimit, kSecReturnData, kSecUseAuthenticationContext, kSecUseDataProtectionKeychain,
    kSecValueData,
};
use security_framework_sys::keychain_item::{SecItemAdd, SecItemCopyMatching, SecItemDelete};
use zeroize::Zeroizing;

use super::{ItemKind, MacApi};
use crate::{Capabilities, Error, Method, Result, platform_error};

#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    static kSecAttrAccessible: CFStringRef;
    static kSecMatchLimitOne: CFStringRef;
    static kSecAttrAccessibleWhenUnlockedThisDeviceOnly: CFStringRef;
    static kSecClassKey: CFStringRef;
    static kSecAttrKeyType: CFStringRef;
    static kSecAttrKeyTypeECSECPrimeRandom: CFStringRef;
    static kSecAttrKeySizeInBits: CFStringRef;
    static kSecAttrKeyClass: CFStringRef;
    static kSecAttrKeyClassPublic: CFStringRef;
    static kSecAttrKeyClassPrivate: CFStringRef;
    static kSecAttrTokenID: CFStringRef;
    static kSecAttrTokenIDSecureEnclave: CFStringRef;
    static kSecAttrIsPermanent: CFStringRef;
    static kSecAttrApplicationTag: CFStringRef;
    static kSecPrivateKeyAttrs: CFStringRef;
    static kSecReturnRef: CFStringRef;
    static kSecKeyAlgorithmECDHKeyExchangeStandard: CFStringRef;

    fn SecKeyCreateRandomKey(parameters: CFDictionaryRef, error: *mut CFErrorRef) -> CFTypeRef;
    fn SecKeyCreateWithData(
        data: CFDataRef,
        attributes: CFDictionaryRef,
        error: *mut CFErrorRef,
    ) -> CFTypeRef;
    fn SecKeyCopyPublicKey(key: CFTypeRef) -> CFTypeRef;
    fn SecKeyCopyExternalRepresentation(key: CFTypeRef, error: *mut CFErrorRef) -> CFDataRef;
    fn SecKeyCopyKeyExchangeResult(
        private_key: CFTypeRef,
        algorithm: CFStringRef,
        public_key: CFTypeRef,
        parameters: CFDictionaryRef,
        error: *mut CFErrorRef,
    ) -> CFDataRef;
}

/// `kSecAccessControlPrivateKeyUsage`: the key may be used, with no user-presence check.
const PRIVATE_KEY_USAGE: usize = 1 << 30;
/// What identifies this app's chip keys in the keychain, before the hashed name.
const CHIP_TAG: &str = "app.octap.desktop.chip.";

const ERR_SEC_USER_CANCELED: i32 = -128;
const ERR_SEC_AUTH_FAILED: i32 = -25293;
const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;
const ERR_SEC_INTERACTION_NOT_ALLOWED: i32 = -25308;
const ERR_SEC_MISSING_ENTITLEMENT: i32 = -34018;

pub struct SystemApi;

/// A context that passed `deviceOwnerAuthentication`. Handing it to the Keychain read means the
/// user isn't asked twice.
pub struct Auth(Retained<LAContext>);

impl MacApi for SystemApi {
    type Auth = Auth;

    fn capabilities(&self) -> Result<Capabilities> {
        // SAFETY: plain Objective-C calls on a context owned here.
        let context = unsafe { LAContext::new() };
        match unsafe { context.canEvaluatePolicy_error(LAPolicy::DeviceOwnerAuthentication) } {
            Ok(()) => {
                let biometrics = unsafe {
                    context
                        .canEvaluatePolicy_error(LAPolicy::DeviceOwnerAuthenticationWithBiometrics)
                }
                .is_ok();
                Ok(Capabilities {
                    method: Some(if biometrics {
                        Method::TouchId
                    } else {
                        Method::MacPassword
                    }),
                    device_lock: true,
                })
            }
            Err(error) if error.code() == LAError::PasscodeNotSet.0 => Ok(Capabilities {
                method: None,
                device_lock: false,
            }),
            Err(error) => Err(platform_error("canEvaluatePolicy", error.code())),
        }
    }

    fn authenticate(&self, reason: &str) -> Result<Auth> {
        let context = unsafe { LAContext::new() };
        let (sender, receiver) = mpsc::channel();
        let reply = RcBlock::new(move |success: Bool, error: *mut NSError| {
            let outcome = if success.as_bool() {
                Ok(())
            } else {
                // SAFETY: LocalAuthentication passes a valid NSError or nil.
                Err(unsafe { error.as_ref() }.map_or(LAError::AuthenticationFailed.0, |e| e.code()))
            };
            let _ = sender.send(outcome);
        });
        // The reply runs on a private queue; this thread (never the main thread: callers use a
        // blocking worker) waits for it.
        unsafe {
            context.evaluatePolicy_localizedReason_reply(
                LAPolicy::DeviceOwnerAuthentication,
                &NSString::from_str(reason),
                &reply,
            )
        };
        match receiver.recv() {
            Ok(Ok(())) => Ok(Auth(context)),
            Ok(Err(code)) => Err(la_error(code)),
            Err(_) => Err(Error::Platform("LocalAuthentication never replied".into())),
        }
    }

    fn store(&self, kind: ItemKind, tag: &str, secret: &[u8]) -> Result<()> {
        self.delete(kind, tag)?;
        let mut attributes = item_query(kind, tag);
        attributes.push((
            key(unsafe { kSecValueData }),
            CFData::from_buffer(secret).into_CFType(),
        ));
        let protection = match kind {
            ItemKind::Protected => {
                let mut error = std::ptr::null_mut();
                // SAFETY: valid constants; the result is owned (create rule) below.
                let access = unsafe {
                    SecAccessControlCreateWithFlags(
                        kCFAllocatorDefault,
                        kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly as CFTypeRef,
                        kSecAccessControlBiometryCurrentSet
                            | kSecAccessControlOr
                            | kSecAccessControlDevicePasscode,
                        &mut error,
                    )
                };
                if access.is_null() {
                    return Err(Error::Platform(
                        "SecAccessControlCreateWithFlags failed".into(),
                    ));
                }
                let access = unsafe { CFType::wrap_under_create_rule(access as CFTypeRef) };
                (key(unsafe { kSecAttrAccessControl }), access)
            }
            ItemKind::Unprotected => (
                key(unsafe { kSecAttrAccessible }),
                key(unsafe { kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly }).into_CFType(),
            ),
        };

        let mut protected = attributes.clone();
        protected.push(protection);
        protected.push(data_protection_keychain());
        match add(&protected) {
            ERR_SEC_MISSING_ENTITLEMENT => match add(&attributes) {
                0 => Ok(()),
                status => Err(keychain_error("SecItemAdd", status)),
            },
            0 => Ok(()),
            status => Err(keychain_error("SecItemAdd", status)),
        }
    }

    fn load(
        &self,
        kind: ItemKind,
        tag: &str,
        auth: Option<&Auth>,
    ) -> Result<Option<Zeroizing<Vec<u8>>>> {
        let mut query = item_query(kind, tag);
        query.push((
            key(unsafe { kSecReturnData }),
            CFBoolean::true_value().into_CFType(),
        ));
        query.push((
            key(unsafe { kSecMatchLimit }),
            key(unsafe { kSecMatchLimitOne }).into_CFType(),
        ));
        if let Some(Auth(context)) = auth {
            // SAFETY: an LAContext is an Objective-C object, toll-free usable as a CFType.
            let context = unsafe {
                CFType::wrap_under_get_rule(Retained::as_ptr(context).cast::<std::ffi::c_void>())
            };
            query.push((key(unsafe { kSecUseAuthenticationContext }), context));
        }
        let mut protected = query.clone();
        protected.push(data_protection_keychain());
        match copy_data(&protected) {
            Err(ERR_SEC_ITEM_NOT_FOUND | ERR_SEC_MISSING_ENTITLEMENT) => match copy_data(&query) {
                Err(ERR_SEC_ITEM_NOT_FOUND) => Ok(None),
                other => other
                    .map(Some)
                    .map_err(|status| keychain_error("SecItemCopyMatching", status)),
            },
            other => other
                .map(Some)
                .map_err(|status| keychain_error("SecItemCopyMatching", status)),
        }
    }

    fn delete(&self, kind: ItemKind, tag: &str) -> Result<()> {
        let query = item_query(kind, tag);
        let mut protected = query.clone();
        protected.push(data_protection_keychain());
        for query in [protected, query] {
            match unsafe { SecItemDelete(dictionary(&query).as_concrete_TypeRef()) } {
                0 | ERR_SEC_ITEM_NOT_FOUND | ERR_SEC_MISSING_ENTITLEMENT => {}
                status => return Err(keychain_error("SecItemDelete", status)),
            }
        }
        Ok(())
    }

    fn enclave_available(&self) -> bool {
        const PROBE: &str = "availability-probe";
        match create_enclave_key(PROBE) {
            Ok(_) => {
                let _ = delete_enclave_key(PROBE);
                true
            }
            Err(_) => false,
        }
    }

    fn enclave_create(&self, tag: &str) -> Result<Option<Vec<u8>>> {
        // No Enclave, or a build that may not keep keys there: the vault goes without.
        if create_enclave_key(tag).is_err() {
            return Ok(None);
        }
        match throwaway_public_key() {
            Ok(peer) => Ok(Some(peer)),
            Err(error) => {
                let _ = delete_enclave_key(tag);
                Err(error)
            }
        }
    }

    fn enclave_agree(&self, tag: &str, peer: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let key = find_enclave_key(tag)?;
        let peer = public_key_from(peer)?;
        let parameters: Pairs = Vec::new();
        let mut error: CFErrorRef = std::ptr::null_mut();
        // SAFETY: both keys are alive for the call; the result is a CFData we own.
        let secret = unsafe {
            SecKeyCopyKeyExchangeResult(
                key.as_CFTypeRef(),
                kSecKeyAlgorithmECDHKeyExchangeStandard,
                peer.as_CFTypeRef(),
                dictionary(&parameters).as_concrete_TypeRef(),
                &mut error,
            )
        };
        if secret.is_null() {
            return Err(cf_error("SecKeyCopyKeyExchangeResult", error));
        }
        // SAFETY: not null, and owned by us ("Copy" in the name).
        let data = unsafe { CFData::wrap_under_create_rule(secret) };
        Ok(Zeroizing::new(data.bytes().to_vec()))
    }

    fn enclave_delete(&self, tag: &str) -> Result<()> {
        delete_enclave_key(tag)
    }
}

fn chip_tag(tag: &str) -> CFData {
    CFData::from_buffer(format!("{CHIP_TAG}{tag}").as_bytes())
}

fn ec_type() -> Pairs {
    vec![
        (
            key(unsafe { kSecAttrKeyType }),
            key(unsafe { kSecAttrKeyTypeECSECPrimeRandom }).into_CFType(),
        ),
        (
            key(unsafe { kSecAttrKeySizeInBits }),
            CFNumber::from(256i32).into_CFType(),
        ),
    ]
}

/// A permanent P-256 key inside the Secure Enclave, replacing one with this tag. Its use needs
/// no prompt, on this device only and while it's unlocked.
fn create_enclave_key(tag: &str) -> Result<()> {
    delete_enclave_key(tag)?;
    let mut error: CFErrorRef = std::ptr::null_mut();
    // SAFETY: constants from the Security framework; the result is a SecAccessControl we own.
    let access = unsafe {
        SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly.cast(),
            PRIVATE_KEY_USAGE as _,
            &mut error,
        )
    };
    if access.is_null() {
        return Err(cf_error("SecAccessControlCreateWithFlags", error));
    }
    // SAFETY: not null, and owned by us ("Create" in the name).
    let access = unsafe { CFType::wrap_under_create_rule(access.cast()) };
    let private: Pairs = vec![
        (
            key(unsafe { kSecAttrIsPermanent }),
            CFBoolean::true_value().into_CFType(),
        ),
        (
            key(unsafe { kSecAttrApplicationTag }),
            chip_tag(tag).into_CFType(),
        ),
        (key(unsafe { kSecAttrAccessControl }), access),
    ];
    let mut attributes = ec_type();
    attributes.push((
        key(unsafe { kSecAttrTokenID }),
        key(unsafe { kSecAttrTokenIDSecureEnclave }).into_CFType(),
    ));
    attributes.push((
        key(unsafe { kSecPrivateKeyAttrs }),
        dictionary(&private).into_CFType(),
    ));
    attributes.push(data_protection_keychain());
    let mut error: CFErrorRef = std::ptr::null_mut();
    // SAFETY: the dictionary lives for the call.
    let created =
        unsafe { SecKeyCreateRandomKey(dictionary(&attributes).as_concrete_TypeRef(), &mut error) };
    if created.is_null() {
        return Err(cf_error("SecKeyCreateRandomKey", error));
    }
    // SAFETY: not null, and owned by us: dropping it releases our reference, the key stays.
    drop(unsafe { CFType::wrap_under_create_rule(created) });
    Ok(())
}

fn enclave_query(tag: &str) -> Pairs {
    vec![
        (
            key(unsafe { kSecClass }),
            key(unsafe { kSecClassKey }).into_CFType(),
        ),
        (
            key(unsafe { kSecAttrApplicationTag }),
            chip_tag(tag).into_CFType(),
        ),
        (
            key(unsafe { kSecAttrKeyClass }),
            key(unsafe { kSecAttrKeyClassPrivate }).into_CFType(),
        ),
        (
            key(unsafe { kSecAttrKeyType }),
            key(unsafe { kSecAttrKeyTypeECSECPrimeRandom }).into_CFType(),
        ),
        data_protection_keychain(),
    ]
}

fn find_enclave_key(tag: &str) -> Result<CFType> {
    let mut query = enclave_query(tag);
    query.push((
        key(unsafe { kSecReturnRef }),
        CFBoolean::true_value().into_CFType(),
    ));
    query.push((
        key(unsafe { kSecMatchLimit }),
        key(unsafe { kSecMatchLimitOne }).into_CFType(),
    ));
    let mut result: CFTypeRef = std::ptr::null();
    match unsafe { SecItemCopyMatching(dictionary(&query).as_concrete_TypeRef(), &mut result) } {
        // SAFETY: kSecReturnRef with a match limit of one returns a SecKey we own.
        0 if !result.is_null() => Ok(unsafe { CFType::wrap_under_create_rule(result) }),
        0 | ERR_SEC_ITEM_NOT_FOUND | ERR_SEC_MISSING_ENTITLEMENT => Err(Error::NotEnrolled),
        status => Err(keychain_error("SecItemCopyMatching", status)),
    }
}

fn delete_enclave_key(tag: &str) -> Result<()> {
    match unsafe { SecItemDelete(dictionary(&enclave_query(tag)).as_concrete_TypeRef()) } {
        0 | ERR_SEC_ITEM_NOT_FOUND | ERR_SEC_MISSING_ENTITLEMENT => Ok(()),
        status => Err(keychain_error("SecItemDelete", status)),
    }
}

/// The public half (X9.63) of a software P-256 key whose private half never leaves this call:
/// nobody knows the other side's secret, so what the agreement gives can't be worked out from
/// the Enclave key's public half.
fn throwaway_public_key() -> Result<Vec<u8>> {
    let mut error: CFErrorRef = std::ptr::null_mut();
    // SAFETY: the dictionary lives for the call.
    let private =
        unsafe { SecKeyCreateRandomKey(dictionary(&ec_type()).as_concrete_TypeRef(), &mut error) };
    if private.is_null() {
        return Err(cf_error("SecKeyCreateRandomKey", error));
    }
    // SAFETY: not null, and owned by us.
    let private = unsafe { CFType::wrap_under_create_rule(private) };
    // SAFETY: a valid key; the result is a SecKey we own, or null.
    let public = unsafe { SecKeyCopyPublicKey(private.as_CFTypeRef()) };
    if public.is_null() {
        return Err(platform_error("SecKeyCopyPublicKey", "null"));
    }
    // SAFETY: not null, and owned by us.
    let public = unsafe { CFType::wrap_under_create_rule(public) };
    let mut error: CFErrorRef = std::ptr::null_mut();
    // SAFETY: a valid key; the result is a CFData we own, or null.
    let bytes = unsafe { SecKeyCopyExternalRepresentation(public.as_CFTypeRef(), &mut error) };
    if bytes.is_null() {
        return Err(cf_error("SecKeyCopyExternalRepresentation", error));
    }
    // SAFETY: not null, and owned by us.
    Ok(unsafe { CFData::wrap_under_create_rule(bytes) }
        .bytes()
        .to_vec())
}

fn public_key_from(bytes: &[u8]) -> Result<CFType> {
    let mut attributes = ec_type();
    attributes.push((
        key(unsafe { kSecAttrKeyClass }),
        key(unsafe { kSecAttrKeyClassPublic }).into_CFType(),
    ));
    let mut error: CFErrorRef = std::ptr::null_mut();
    // SAFETY: both CF objects live for the call.
    let peer = unsafe {
        SecKeyCreateWithData(
            CFData::from_buffer(bytes).as_concrete_TypeRef(),
            dictionary(&attributes).as_concrete_TypeRef(),
            &mut error,
        )
    };
    if peer.is_null() {
        return Err(cf_error("SecKeyCreateWithData", error));
    }
    // SAFETY: not null, and owned by us.
    Ok(unsafe { CFType::wrap_under_create_rule(peer) })
}

/// A Security framework failure; the error object is ours to release.
fn cf_error(call: &str, error: CFErrorRef) -> Error {
    if error.is_null() {
        return platform_error(call, "no error given");
    }
    // SAFETY: not null, and ours: the "Create rule" for out-parameters of these calls.
    let error = unsafe { CFError::wrap_under_create_rule(error) };
    platform_error(call, error.code())
}

type Pairs = Vec<(CFString, CFType)>;

fn key(name: CFStringRef) -> CFString {
    // SAFETY: Security framework constants are valid, immortal CFStrings.
    unsafe { CFString::wrap_under_get_rule(name) }
}

fn item_query(kind: ItemKind, tag: &str) -> Pairs {
    vec![
        (
            key(unsafe { kSecClass }),
            key(unsafe { kSecClassGenericPassword }).into_CFType(),
        ),
        (
            key(unsafe { kSecAttrService }),
            CFString::new(kind.service()).into_CFType(),
        ),
        (
            key(unsafe { kSecAttrAccount }),
            CFString::new(tag).into_CFType(),
        ),
    ]
}

fn data_protection_keychain() -> (CFString, CFType) {
    (
        key(unsafe { kSecUseDataProtectionKeychain }),
        CFBoolean::true_value().into_CFType(),
    )
}

fn dictionary(pairs: &Pairs) -> CFDictionary<CFString, CFType> {
    CFDictionary::from_CFType_pairs(pairs)
}

fn add(attributes: &Pairs) -> i32 {
    unsafe {
        SecItemAdd(
            dictionary(attributes).as_concrete_TypeRef(),
            std::ptr::null_mut(),
        )
    }
}

fn copy_data(query: &Pairs) -> std::result::Result<Zeroizing<Vec<u8>>, i32> {
    let mut result: CFTypeRef = std::ptr::null();
    match unsafe { SecItemCopyMatching(dictionary(query).as_concrete_TypeRef(), &mut result) } {
        0 if !result.is_null() => {
            // SAFETY: kSecReturnData with a match limit of one returns a CFData we own.
            let data = unsafe { CFData::wrap_under_create_rule(result as CFDataRef) };
            Ok(Zeroizing::new(data.bytes().to_vec()))
        }
        0 => Err(ERR_SEC_ITEM_NOT_FOUND),
        status => Err(status),
    }
}

fn keychain_error(call: &str, status: i32) -> Error {
    match status {
        ERR_SEC_USER_CANCELED => Error::Cancelled,
        ERR_SEC_AUTH_FAILED | ERR_SEC_INTERACTION_NOT_ALLOWED => Error::Denied,
        status => platform_error(call, status),
    }
}

fn la_error(code: isize) -> Error {
    match LAError(code) {
        LAError::UserCancel
        | LAError::SystemCancel
        | LAError::AppCancel
        | LAError::UserFallback => Error::Cancelled,
        LAError::PasscodeNotSet => Error::NoDeviceLock,
        LAError::AuthenticationFailed | LAError::BiometryLockout => Error::Denied,
        _ => platform_error("evaluatePolicy", code),
    }
}
