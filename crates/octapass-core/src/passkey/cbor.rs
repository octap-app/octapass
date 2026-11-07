//! The few CBOR (RFC 8949) items WebAuthn needs: integers, byte and text strings, and maps.
//!
//! Callers write map entries in CTAP2 canonical order themselves (shorter encoded keys first,
//! then bytewise), so the output is deterministic without sorting here.

const UNSIGNED: u8 = 0;
const NEGATIVE: u8 = 1;
const BYTES: u8 = 2;
const TEXT: u8 = 3;
const MAP: u8 = 5;

fn head(out: &mut Vec<u8>, major: u8, value: u64) {
    let major = major << 5;
    match value {
        0..=23 => out.push(major | value as u8),
        24..=0xff => out.extend_from_slice(&[major | 24, value as u8]),
        0x100..=0xffff => {
            out.push(major | 25);
            out.extend_from_slice(&(value as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(major | 26);
            out.extend_from_slice(&(value as u32).to_be_bytes());
        }
        _ => {
            out.push(major | 27);
            out.extend_from_slice(&value.to_be_bytes());
        }
    }
}

pub(crate) fn int(out: &mut Vec<u8>, value: i64) {
    if value >= 0 {
        head(out, UNSIGNED, value as u64);
    } else {
        // -1 - n, computed without overflow for i64::MIN.
        head(out, NEGATIVE, !value as u64);
    }
}

pub(crate) fn bytes(out: &mut Vec<u8>, value: &[u8]) {
    head(out, BYTES, value.len() as u64);
    out.extend_from_slice(value);
}

pub(crate) fn text(out: &mut Vec<u8>, value: &str) {
    head(out, TEXT, value.len() as u64);
    out.extend_from_slice(value.as_bytes());
}

/// The header of a map with `entries` key/value pairs; write the pairs right after it.
pub(crate) fn map(out: &mut Vec<u8>, entries: usize) {
    head(out, MAP, entries as u64);
}

#[cfg(test)]
mod tests {
    use ciborium::Value;

    use super::*;

    fn encoded(write: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
        let mut out = Vec::new();
        write(&mut out);
        out
    }

    #[test]
    fn rfc_8949_appendix_a() {
        for (value, hex) in [
            (0, "00"),
            (23, "17"),
            (24, "1818"),
            (100, "1864"),
            (1000, "1903e8"),
            (1_000_000, "1a000f4240"),
            (1_000_000_000_000, "1b000000e8d4a51000"),
            (-1, "20"),
            (-10, "29"),
            (-100, "3863"),
            (-1000, "3903e7"),
            (i64::MIN, "3b7fffffffffffffff"),
        ] {
            assert_eq!(hex_encode(&encoded(|out| int(out, value))), hex, "{value}");
        }
        assert_eq!(
            hex_encode(&encoded(|out| bytes(out, &[1, 2, 3, 4]))),
            "4401020304"
        );
        assert_eq!(hex_encode(&encoded(|out| text(out, "IETF"))), "6449455446");
        assert_eq!(hex_encode(&encoded(|out| map(out, 0))), "a0");
    }

    #[test]
    fn decodes_with_an_independent_parser() {
        let long = vec![7u8; 300];
        let out = encoded(|out| {
            map(out, 3);
            int(out, 1);
            text(out, "fmt");
            int(out, -2);
            bytes(out, &long);
            text(out, "x");
            map(out, 0);
        });
        let value: Value = ciborium::from_reader(out.as_slice()).unwrap();
        assert_eq!(
            value,
            Value::Map(vec![
                (Value::from(1), Value::from("fmt")),
                (Value::from(-2), Value::Bytes(long)),
                (Value::from("x"), Value::Map(vec![])),
            ])
        );
    }

    fn hex_encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}
