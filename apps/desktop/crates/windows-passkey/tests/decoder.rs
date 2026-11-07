//! Whatever bytes arrive, the decoders answer: they never panic, and they only accept what they
//! can fully read. `tests/provider.rs` covers what happens after them.

use octapass_windows_passkey::ctap::{
    AttestationParts, decode_get_assertion, decode_make_credential, encode_get_assertion,
    encode_make_credential, split_attestation_object,
};
use octapass_windows_passkey::signature::{PublicKey, request_hash};
use proptest::prelude::*;

/// A well-formed `authenticatorGetAssertion`, for mutating.
fn valid_request() -> Vec<u8> {
    let mut bytes = vec![0xa3, 0x01, 0x61, b'a', 0x02, 0x58, 0x20];
    bytes.extend_from_slice(&[7; 32]);
    bytes.extend_from_slice(&[0x05, 0xa1, 0x62, b'u', b'p', 0xf4]);
    bytes
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1024))]

    #[test]
    fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
        let _ = decode_make_credential(&bytes);
        let _ = decode_get_assertion(&bytes);
        let _ = split_attestation_object(&bytes);
        let _ = PublicKey::from_blob(&bytes);
    }

    #[test]
    fn maps_of_cbor_shaped_bytes_never_panic(
        tail in proptest::collection::vec(prop_oneof![
            Just(0xa1u8), Just(0x81), Just(0x41), Just(0x61), Just(0xf5), Just(0x01), Just(0x02),
            Just(0x03), Just(0x05), Just(0x58), Just(0x98), Just(0xbf), Just(0x9f), Just(0xff),
            any::<u8>(),
        ], 0..256),
    ) {
        let mut bytes = vec![0xa4];
        bytes.extend(tail);
        let _ = decode_make_credential(&bytes);
        let _ = decode_get_assertion(&bytes);
    }

    #[test]
    fn mutated_requests_never_panic(at in 0usize..45, value in any::<u8>()) {
        let mut bytes = valid_request();
        let at = at % bytes.len();
        bytes[at] = value;
        let _ = decode_get_assertion(&bytes);
        bytes.truncate(at);
        let _ = decode_get_assertion(&bytes);
    }

    #[test]
    fn signing_something_else_changes_the_hash(a in any::<Vec<u8>>(), b in any::<Vec<u8>>()) {
        prop_assume!(a != b);
        prop_assert_ne!(request_hash(&a), request_hash(&b));
    }

    #[test]
    fn assertion_responses_stay_cbor(
        id in proptest::collection::vec(any::<u8>(), 1..64),
        data in proptest::collection::vec(any::<u8>(), 37..128),
        signature in proptest::collection::vec(any::<u8>(), 0..128),
        name in proptest::collection::vec(any::<char>(), 0..32),
    ) {
        let name: String = name.into_iter().collect();
        let bytes = encode_get_assertion(&id, &data, &signature, &id, &name);
        let _: ciborium::value::Value = ciborium::de::from_reader(bytes.as_slice()).unwrap();
    }

    #[test]
    fn attestation_objects_round_trip(data in proptest::collection::vec(any::<u8>(), 1..128)) {
        let parts = AttestationParts {
            format: "none".into(),
            statement: vec![0xa0],
            authenticator_data: data,
        };
        let encoded = encode_make_credential(&parts).unwrap();
        let _: ciborium::value::Value = ciborium::de::from_reader(encoded.as_slice()).unwrap();
    }
}

#[test]
fn the_mutated_vector_is_valid_to_begin_with() {
    assert_eq!(decode_get_assertion(&valid_request()).unwrap().rp_id, "a");
}
