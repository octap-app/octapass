//! CTAP2 messages (FIDO Client to Authenticator Protocol 2.1, sections 6.1, 6.2 and 6.4). Requests
//! are untrusted even after their signature checks out, so everything is bounded and every field
//! is type-checked; anything malformed is refused with [`CtapError`], never panics.

use std::io::Cursor;

use ciborium::value::{Integer, Value};

/// `authenticatorMakeCredential`'s command byte.
pub const MAKE_CREDENTIAL: u8 = 0x01;
/// `authenticatorGetAssertion`'s command byte.
pub const GET_ASSERTION: u8 = 0x02;

/// CTAP's own messages are small; this leaves room for long allow lists and refuses memory abuse.
pub const MAX_REQUEST: usize = 1024 * 1024;
const MAX_CREDENTIAL_ID: usize = 1023;
const MAX_CREDENTIALS: usize = 4096;
const MAX_ALGORITHMS: usize = 64;
const MAX_USER_ID: usize = 64;
const MAX_TEXT: usize = 2048;
const PUBLIC_KEY: &str = "public-key";

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("malformed CTAP2 message: {0}")]
pub struct CtapError(pub &'static str);

/// The `options` map: `None` where the request doesn't say. Octa Pass reads neither to skip a
/// check: every operation asks for Windows Hello, whatever these say.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Options {
    pub resident_key: Option<bool>,
    pub user_presence: Option<bool>,
    pub user_verification: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MakeCredentialRequest {
    pub client_data_hash: [u8; 32],
    pub rp_id: String,
    pub rp_name: Option<String>,
    pub user_id: Vec<u8>,
    pub user_name: Option<String>,
    pub user_display_name: Option<String>,
    /// COSE algorithms, the site's preference first; only `public-key` entries.
    pub algorithms: Vec<i64>,
    pub exclude_list: Vec<Vec<u8>>,
    pub options: Options,
}

impl MakeCredentialRequest {
    /// The name to show and store: `name`, else `displayName`, else nothing.
    pub fn account_name(&self) -> &str {
        self.user_name
            .as_deref()
            .or(self.user_display_name.as_deref())
            .unwrap_or_default()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetAssertionRequest {
    pub rp_id: String,
    pub client_data_hash: [u8; 32],
    /// Empty: any discoverable credential for the site.
    pub allow_list: Vec<Vec<u8>>,
    pub options: Options,
}

pub fn decode_make_credential(bytes: &[u8]) -> Result<MakeCredentialRequest, CtapError> {
    let map = decode_map(bytes, MAKE_CREDENTIAL)?;
    let (rp_id, rp_name) = rp_entity(required(&map, 2)?)?;
    let (user_id, user_name, user_display_name) = user_entity(required(&map, 3)?)?;
    let algorithms = algorithms(required(&map, 4)?)?;
    Ok(MakeCredentialRequest {
        client_data_hash: client_data_hash(required(&map, 1)?)?,
        rp_id,
        rp_name,
        user_id,
        user_name,
        user_display_name,
        algorithms,
        exclude_list: optional(&map, 5).map_or(Ok(vec![]), descriptors)?,
        options: optional(&map, 7).map_or(Ok(Options::default()), options)?,
    })
}

pub fn decode_get_assertion(bytes: &[u8]) -> Result<GetAssertionRequest, CtapError> {
    let map = decode_map(bytes, GET_ASSERTION)?;
    Ok(GetAssertionRequest {
        rp_id: rp_id(required(&map, 1)?)?,
        client_data_hash: client_data_hash(required(&map, 2)?)?,
        allow_list: optional(&map, 3).map_or(Ok(vec![]), descriptors)?,
        options: optional(&map, 5).map_or(Ok(Options::default()), options)?,
    })
}

/// `webauthnplugin.h` hands the bytes to `WebAuthNDecode*Request`, and Microsoft doesn't say
/// whether they keep CTAP's leading command byte, so both are read: a map starts with major type
/// 5 (`0xa0..=0xbf`), which no command byte is. A different command's byte is refused.
fn decode_map(bytes: &[u8], command: u8) -> Result<Vec<(Value, Value)>, CtapError> {
    if bytes.len() > MAX_REQUEST {
        return Err(CtapError("too long"));
    }
    let body = match bytes.first() {
        Some(&byte) if byte == command => &bytes[1..],
        Some(0xa0..=0xbf) => bytes,
        Some(_) => return Err(CtapError("not this command")),
        None => return Err(CtapError("empty")),
    };
    let mut reader = Cursor::new(body);
    // ciborium limits nesting (256 levels) by itself.
    let value: Value = ciborium::de::from_reader(&mut reader).map_err(|_| CtapError("not CBOR"))?;
    if reader.position() as usize != body.len() {
        return Err(CtapError("bytes after the message"));
    }
    let Value::Map(map) = value else {
        return Err(CtapError("not a map"));
    };
    for (index, (key, _)) in map.iter().enumerate() {
        if map[..index].iter().any(|(other, _)| other == key) {
            return Err(CtapError("repeated key"));
        }
    }
    Ok(map)
}

fn optional(map: &[(Value, Value)], key: u8) -> Option<&Value> {
    map.iter()
        .find(|(k, _)| k.as_integer() == Some(Integer::from(key)))
        .map(|(_, value)| value)
}

fn required(map: &[(Value, Value)], key: u8) -> Result<&Value, CtapError> {
    optional(map, key).ok_or(CtapError("required field missing"))
}

fn field<'a>(map: &'a [(Value, Value)], name: &str) -> Option<&'a Value> {
    map.iter()
        .find(|(k, _)| k.as_text() == Some(name))
        .map(|(_, value)| value)
}

fn text(value: &Value) -> Result<String, CtapError> {
    let text = value.as_text().ok_or(CtapError("text expected"))?;
    if text.len() > MAX_TEXT {
        return Err(CtapError("text too long"));
    }
    Ok(text.to_owned())
}

fn client_data_hash(value: &Value) -> Result<[u8; 32], CtapError> {
    value
        .as_bytes()
        .and_then(|bytes| <[u8; 32]>::try_from(bytes.as_slice()).ok())
        .ok_or(CtapError("clientDataHash is not 32 bytes"))
}

fn rp_id(value: &Value) -> Result<String, CtapError> {
    let id = text(value)?;
    if id.is_empty() {
        return Err(CtapError("empty rpId"));
    }
    Ok(id)
}

fn rp_entity(value: &Value) -> Result<(String, Option<String>), CtapError> {
    let map = value.as_map().ok_or(CtapError("rp is not a map"))?;
    let id = rp_id(field(map, "id").ok_or(CtapError("rp has no id"))?)?;
    let name = field(map, "name").map(text).transpose()?;
    Ok((id, name))
}

type User = (Vec<u8>, Option<String>, Option<String>);

fn user_entity(value: &Value) -> Result<User, CtapError> {
    let map = value.as_map().ok_or(CtapError("user is not a map"))?;
    let id = field(map, "id")
        .and_then(Value::as_bytes)
        .ok_or(CtapError("user has no id"))?;
    if id.is_empty() || id.len() > MAX_USER_ID {
        return Err(CtapError("user id is not 1 to 64 bytes"));
    }
    Ok((
        id.clone(),
        field(map, "name").map(text).transpose()?,
        field(map, "displayName").map(text).transpose()?,
    ))
}

fn algorithms(value: &Value) -> Result<Vec<i64>, CtapError> {
    let list = value
        .as_array()
        .ok_or(CtapError("pubKeyCredParams is not a list"))?;
    if list.is_empty() || list.len() > MAX_ALGORITHMS {
        return Err(CtapError("pubKeyCredParams has a bad length"));
    }
    let mut found = Vec::new();
    for entry in list {
        let map = entry
            .as_map()
            .ok_or(CtapError("pubKeyCredParams entry is not a map"))?;
        let kind = field(map, "type")
            .and_then(Value::as_text)
            .ok_or(CtapError("pubKeyCredParams entry has no type"))?;
        let alg = field(map, "alg")
            .and_then(Value::as_integer)
            .and_then(|alg| i64::try_from(alg).ok())
            .ok_or(CtapError("pubKeyCredParams entry has no alg"))?;
        // CTAP 2.1, 6.1.2: entries of unknown types are skipped.
        if kind == PUBLIC_KEY {
            found.push(alg);
        }
    }
    Ok(found)
}

fn descriptors(value: &Value) -> Result<Vec<Vec<u8>>, CtapError> {
    let list = value
        .as_array()
        .ok_or(CtapError("credential list is not a list"))?;
    if list.len() > MAX_CREDENTIALS {
        return Err(CtapError("credential list too long"));
    }
    let mut found = Vec::new();
    for entry in list {
        let map = entry.as_map().ok_or(CtapError("credential is not a map"))?;
        let kind = field(map, "type")
            .and_then(Value::as_text)
            .ok_or(CtapError("credential has no type"))?;
        let id = field(map, "id")
            .and_then(Value::as_bytes)
            .ok_or(CtapError("credential has no id"))?;
        if id.is_empty() || id.len() > MAX_CREDENTIAL_ID {
            return Err(CtapError("credential id has a bad length"));
        }
        if kind == PUBLIC_KEY {
            found.push(id.clone());
        }
    }
    Ok(found)
}

fn options(value: &Value) -> Result<Options, CtapError> {
    let map = value.as_map().ok_or(CtapError("options is not a map"))?;
    let flag = |name| {
        field(map, name)
            .map(|value| value.as_bool().ok_or(CtapError("option is not a boolean")))
            .transpose()
    };
    Ok(Options {
        resident_key: flag("rk")?,
        user_presence: flag("up")?,
        user_verification: flag("uv")?,
    })
}

fn int(value: i64) -> Value {
    Value::Integer(Integer::from(value))
}

fn key(value: u8) -> Value {
    Value::Integer(Integer::from(value))
}

fn encode(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::ser::into_writer(value, &mut out).expect("writing CBOR to memory can't fail");
    out
}

/// What an attestation object (`{ fmt, attStmt, authData }`, as the core writes it) holds, which
/// `WEBAUTHN_CREDENTIAL_ATTESTATION` and the CTAP response carry apart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationParts {
    pub format: String,
    pub statement: Vec<u8>,
    pub authenticator_data: Vec<u8>,
}

pub fn split_attestation_object(object: &[u8]) -> Result<AttestationParts, CtapError> {
    let value: Value =
        ciborium::de::from_reader(object).map_err(|_| CtapError("not an attestation object"))?;
    let map = value
        .as_map()
        .ok_or(CtapError("attestation object is not a map"))?;
    let format = field(map, "fmt")
        .and_then(Value::as_text)
        .ok_or(CtapError("attestation object has no fmt"))?;
    let statement = field(map, "attStmt").ok_or(CtapError("attestation object has no attStmt"))?;
    let authenticator_data = field(map, "authData")
        .and_then(Value::as_bytes)
        .ok_or(CtapError("attestation object has no authData"))?;
    Ok(AttestationParts {
        format: format.to_owned(),
        statement: encode(statement),
        authenticator_data: authenticator_data.clone(),
    })
}

/// `authenticatorMakeCredential`'s response: `{ 1: fmt, 2: authData, 3: attStmt }`.
pub fn encode_make_credential(parts: &AttestationParts) -> Result<Vec<u8>, CtapError> {
    let statement: Value = ciborium::de::from_reader(parts.statement.as_slice())
        .map_err(|_| CtapError("attestation statement is not CBOR"))?;
    Ok(encode(&Value::Map(vec![
        (key(1), Value::Text(parts.format.clone())),
        (key(2), Value::Bytes(parts.authenticator_data.clone())),
        (key(3), statement),
    ])))
}

/// `authenticatorGetAssertion`'s response for one credential: `{ 1: credential, 2: authData,
/// 3: signature, 4: user }`, then `5: 1` as Microsoft's sample sets it.
pub fn encode_get_assertion(
    credential_id: &[u8],
    authenticator_data: &[u8],
    signature: &[u8],
    user_id: &[u8],
    user_name: &str,
) -> Vec<u8> {
    let mut user = vec![(Value::Text("id".into()), Value::Bytes(user_id.to_vec()))];
    if !user_name.is_empty() {
        user.push((Value::Text("name".into()), Value::Text(user_name.into())));
        user.push((
            Value::Text("displayName".into()),
            Value::Text(user_name.into()),
        ));
    }
    encode(&Value::Map(vec![
        (
            key(1),
            Value::Map(vec![
                (
                    Value::Text("id".into()),
                    Value::Bytes(credential_id.to_vec()),
                ),
                (Value::Text("type".into()), Value::Text(PUBLIC_KEY.into())),
            ]),
        ),
        (key(2), Value::Bytes(authenticator_data.to_vec())),
        (key(3), Value::Bytes(signature.to_vec())),
        (key(4), Value::Map(user)),
        (key(5), int(1)),
    ]))
}

/// `authenticatorGetInfo`, which `WebAuthNPluginAddAuthenticator` takes. No extensions: Windows
/// uses them to filter authenticators, and the core's hash-based passkeys here answer none.
pub fn authenticator_info(aaguid: &[u8; 16], algorithms: &[i64]) -> Vec<u8> {
    let text = |value: &str| Value::Text(value.into());
    let params = algorithms
        .iter()
        .map(|&alg| {
            Value::Map(vec![
                (text("alg"), int(alg)),
                (text("type"), text(PUBLIC_KEY)),
            ])
        })
        .collect();
    encode(&Value::Map(vec![
        (
            key(1),
            Value::Array(vec![text("FIDO_2_0"), text("FIDO_2_1")]),
        ),
        (key(3), Value::Bytes(aaguid.to_vec())),
        (
            key(4),
            Value::Map(vec![
                (text("rk"), Value::Bool(true)),
                (text("up"), Value::Bool(true)),
                (text("uv"), Value::Bool(true)),
            ]),
        ),
        (key(9), Value::Array(vec![text("internal")])),
        (key(10), Value::Array(params)),
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(text: &str) -> Vec<u8> {
        let text: String = text.split_whitespace().collect();
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Written byte by byte from the CTAP 2.1 tables, so they don't depend on the encoder.
    const MAKE_CREDENTIAL_VECTOR: &str = "
        a6
        01 5820 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
        02 a2 62 6964 6b 6578616d706c652e636f6d
              64 6e616d65 67 4578616d706c65
        03 a3 62 6964 44 01020304
              64 6e616d65 63 616461
              6b 646973706c61794e616d65 63 416461
        04 82 a2 63 616c67 26
                 64 74797065 6a 7075626c69632d6b6579
              a2 63 616c67 27
                 64 74797065 6a 7075626c69632d6b6579
        05 81 a2 62 6964 42 aabb
                 64 74797065 6a 7075626c69632d6b6579
        07 a2 62 726b f5  62 7576 f5";

    const GET_ASSERTION_VECTOR: &str = "
        a4
        01 6b 6578616d706c652e636f6d
        02 5820 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
        03 81 a2 62 6964 42 aabb
                 64 74797065 6a 7075626c69632d6b6579
        05 a1 62 7570 f4";

    fn hash() -> [u8; 32] {
        std::array::from_fn(|i| i as u8)
    }

    #[test]
    fn reads_a_make_credential_request() {
        let request = decode_make_credential(&hex(MAKE_CREDENTIAL_VECTOR)).unwrap();
        assert_eq!(
            request,
            MakeCredentialRequest {
                client_data_hash: hash(),
                rp_id: "example.com".into(),
                rp_name: Some("Example".into()),
                user_id: vec![1, 2, 3, 4],
                user_name: Some("ada".into()),
                user_display_name: Some("Ada".into()),
                algorithms: vec![-7, -8],
                exclude_list: vec![vec![0xaa, 0xbb]],
                options: Options {
                    resident_key: Some(true),
                    user_presence: None,
                    user_verification: Some(true),
                },
            }
        );
        assert_eq!(request.account_name(), "ada");
    }

    #[test]
    fn reads_a_get_assertion_request() {
        let request = decode_get_assertion(&hex(GET_ASSERTION_VECTOR)).unwrap();
        assert_eq!(
            request,
            GetAssertionRequest {
                rp_id: "example.com".into(),
                client_data_hash: hash(),
                allow_list: vec![vec![0xaa, 0xbb]],
                options: Options {
                    user_presence: Some(false),
                    ..Options::default()
                },
            }
        );
    }

    #[test]
    fn reads_requests_with_or_without_the_command_byte() {
        let mut framed = vec![MAKE_CREDENTIAL];
        framed.extend(hex(MAKE_CREDENTIAL_VECTOR));
        assert_eq!(
            decode_make_credential(&framed).unwrap(),
            decode_make_credential(&hex(MAKE_CREDENTIAL_VECTOR)).unwrap()
        );
        let mut framed = vec![GET_ASSERTION];
        framed.extend(hex(GET_ASSERTION_VECTOR));
        assert!(decode_get_assertion(&framed).is_ok());
    }

    #[test]
    fn refuses_the_other_commands_byte() {
        let mut framed = vec![GET_ASSERTION];
        framed.extend(hex(MAKE_CREDENTIAL_VECTOR));
        assert_eq!(
            decode_make_credential(&framed),
            Err(CtapError("not this command"))
        );
    }

    #[test]
    fn skips_credentials_of_other_types() {
        let bytes = hex("a3 01 61 61
                         02 5820 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
                         03 81 a2 62 6964 41 01  64 74797065 61 78");
        assert!(decode_get_assertion(&bytes).unwrap().allow_list.is_empty());
    }

    #[test]
    fn refuses_malformed_requests() {
        let hash = "5820 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        for (bytes, why) in [
            ("", "empty"),
            ("ff", "not this command"),
            ("a0", "required field missing"),
            ("a1 01 61 61", "required field missing"),
            ("a2 01 61 61 02 4101", "clientDataHash is not 32 bytes"),
            (&format!("a2 01 60 02 {hash}"), "empty rpId"),
            (&format!("a2 01 01 02 {hash}"), "text expected"),
            (
                &format!("a2 01 61 61 02 {hash} 00"),
                "bytes after the message",
            ),
            (&format!("a3 01 61 61 01 61 61 02 {hash}"), "repeated key"),
            (
                &format!("a3 01 61 61 02 {hash} 03 00"),
                "credential list is not a list",
            ),
            (
                &format!("a3 01 61 61 02 {hash} 03 81 00"),
                "credential is not a map",
            ),
            (
                &format!("a3 01 61 61 02 {hash} 05 a1 62 7570 00"),
                "option is not a boolean",
            ),
            ("a1 01", "not CBOR"),
        ] {
            let got = decode_get_assertion(&hex(bytes));
            let expected = format!("{:?}", Err::<(), _>(CtapError(why)));
            assert_eq!(format!("{:?}", got.map(|_| ())), expected, "{bytes}");
        }
    }

    #[test]
    fn refuses_oversized_requests_and_bad_user_ids() {
        assert_eq!(
            decode_get_assertion(&vec![0xa0; MAX_REQUEST + 1]),
            Err(CtapError("too long"))
        );
        let empty_user = MAKE_CREDENTIAL_VECTOR.replace("62 6964 44 01020304", "62 6964 40");
        assert_eq!(
            decode_make_credential(&hex(&empty_user)),
            Err(CtapError("user id is not 1 to 64 bytes"))
        );
        let no_algorithms = hex("a4
            01 5820 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
            02 a1 62 6964 61 61
            03 a1 62 6964 41 01
            04 80");
        assert_eq!(
            decode_make_credential(&no_algorithms),
            Err(CtapError("pubKeyCredParams has a bad length"))
        );
    }

    #[test]
    fn deep_nesting_is_refused_not_a_crash() {
        let mut bytes = hex("a1 01");
        bytes.extend(std::iter::repeat_n(0x81, 100_000));
        bytes.push(0x00);
        assert!(decode_get_assertion(&bytes).is_err());
    }

    #[test]
    fn writes_the_make_credential_response() {
        let parts = AttestationParts {
            format: "none".into(),
            statement: vec![0xa0],
            authenticator_data: vec![1, 2, 3],
        };
        assert_eq!(
            encode_make_credential(&parts).unwrap(),
            hex("a3 01 64 6e6f6e65 02 43 010203 03 a0")
        );
    }

    #[test]
    fn splits_an_attestation_object() {
        let object = hex("a3 63 666d74 64 6e6f6e65
                             67 61747453746d74 a0
                             68 6175746844617461 42 0102");
        assert_eq!(
            split_attestation_object(&object).unwrap(),
            AttestationParts {
                format: "none".into(),
                statement: vec![0xa0],
                authenticator_data: vec![1, 2],
            }
        );
        assert!(split_attestation_object(&hex("a0")).is_err());
        assert!(split_attestation_object(&hex("00")).is_err());
    }

    #[test]
    fn writes_the_get_assertion_response() {
        assert_eq!(
            encode_get_assertion(&[0xaa], &[1], &[2], &[3], "ada"),
            hex("a5
                 01 a2 62 6964 41 aa  64 74797065 6a 7075626c69632d6b6579
                 02 41 01
                 03 41 02
                 04 a3 62 6964 41 03  64 6e616d65 63 616461  6b 646973706c61794e616d65 63 616461
                 05 01")
        );
        assert_eq!(
            encode_get_assertion(&[0xaa], &[1], &[2], &[3], ""),
            hex("a5
                 01 a2 62 6964 41 aa  64 74797065 6a 7075626c69632d6b6579
                 02 41 01
                 03 41 02
                 04 a1 62 6964 41 03
                 05 01")
        );
    }

    #[test]
    fn writes_authenticator_get_info() {
        // The shape of Microsoft's sample (`PluginRegistrationManager.cpp`), without extensions.
        assert_eq!(
            authenticator_info(&[0x11; 16], &[-7, -8]),
            hex("a5
                 01 82 68 4649444f5f325f30 68 4649444f5f325f31
                 03 50 11111111111111111111111111111111
                 04 a3 62 726b f5 62 7570 f5 62 7576 f5
                 09 81 68 696e7465726e616c
                 0a 82 a2 63 616c67 26 64 74797065 6a 7075626c69632d6b6579
                       a2 63 616c67 27 64 74797065 6a 7075626c69632d6b6579")
        );
    }
}
