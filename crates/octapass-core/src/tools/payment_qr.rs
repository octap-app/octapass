//! Payment QR codes (plan 01): EPC QR for bank accounts and `bitcoin:` / `ethereum:` address URIs
//! for wallets. Only receiving details ever go in: never a PIN, a seed phrase or a passphrase.
//!
//! The web vault has the same functions in `packages/vault-client/src/paymentQr.ts`; both are checked
//! against `tests/vectors/payment-qr.json`.

use crate::item_fields::{is_iban, is_swift, normalize_iban};

/// What an EPC QR code asks a banking app to pay. Optional parts are empty when left out.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EpcPayment<'a> {
    pub name: &'a str,
    pub iban: &'a str,
    pub bic: &'a str,
    /// In euros, like `12.50`.
    pub amount: &'a str,
    /// Free text for the payee, at most 140 characters.
    pub reference: &'a str,
}

/// Countries in the SEPA schemes. An EPC QR code means nothing to a bank outside them.
const SEPA_COUNTRIES: [&str; 41] = [
    "AD", "AL", "AT", "BE", "BG", "CH", "CY", "CZ", "DE", "DK", "EE", "ES", "FI", "FR", "GB", "GI",
    "GR", "HR", "HU", "IE", "IS", "IT", "LI", "LT", "LU", "LV", "MC", "MD", "ME", "MK", "MT", "NL",
    "NO", "PL", "PT", "RO", "RS", "SE", "SI", "SK", "SM",
];

/// Whether this IBAN can be paid with an EPC QR code: valid, and in a SEPA country.
pub fn is_sepa_iban(iban: &str) -> bool {
    let iban = normalize_iban(iban);
    is_iban(&iban) && SEPA_COUNTRIES.contains(&&iban[..2])
}

/// An amount in euros as EPC writes it (`EUR12.5`), or `None` when it isn't 0.01 to 999999999.99
/// with at most two decimals.
fn epc_amount(amount: &str) -> Option<String> {
    let (whole, decimals) = amount.split_once('.').unwrap_or((amount, ""));
    let digits = |text: &str| text.bytes().all(|b| b.is_ascii_digit());
    if whole.is_empty()
        || whole.len() > 9
        || decimals.len() > 2
        || !digits(whole)
        || !digits(decimals)
    {
        return None;
    }
    let whole = whole.trim_start_matches('0');
    let decimals = decimals.trim_end_matches('0');
    if whole.is_empty() && decimals.is_empty() {
        return None;
    }
    let whole = if whole.is_empty() { "0" } else { whole };
    Some(if decimals.is_empty() {
        format!("EUR{whole}.00")
    } else {
        format!("EUR{whole}.{decimals:0<2}")
    })
}

/// A line break or a control character would start another EPC line, so they become spaces.
fn epc_text(text: &str, limit: usize) -> Option<String> {
    let clean: String = text
        .trim()
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    (clean.chars().count() <= limit).then_some(clean)
}

/// The EPC QR text (EPC069-12 version 002, UTF-8, SEPA credit transfer). `None` when the IBAN isn't
/// a SEPA one, there's no payee name, or a value doesn't fit the format.
pub fn epc_qr_text(payment: &EpcPayment<'_>) -> Option<String> {
    if !is_sepa_iban(payment.iban) {
        return None;
    }
    let name = epc_text(payment.name, 70).filter(|name| !name.is_empty())?;
    let bic = payment.bic.trim();
    if !bic.is_empty() && !is_swift(bic) {
        return None;
    }
    let amount = match payment.amount.trim() {
        "" => String::new(),
        amount => epc_amount(amount)?,
    };
    let reference = epc_text(payment.reference, 140)?;
    let lines = [
        "BCD",
        "002",
        "1",
        "SCT",
        &bic.to_uppercase(),
        &name,
        &normalize_iban(payment.iban),
        &amount,
        "",
        "",
        &reference,
    ];
    // Empty lines at the end are left out.
    let used = lines
        .iter()
        .rposition(|line| !line.is_empty())
        .unwrap_or_default();
    Some(lines[..=used].join("\n"))
}

/// One word of letters and digits: what any chain's address looks like, and what a seed phrase,
/// which is several words, doesn't.
pub fn looks_like_address(address: &str) -> bool {
    (16..=128).contains(&address.len())
        && address
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, ':' | '_' | '-'))
}

fn is_bitcoin_address(address: &str) -> bool {
    let bech32 = address.to_lowercase();
    let is_bech32 = (bech32.starts_with("bc1") && address == bech32
        || address.starts_with("BC1") && address == address.to_uppercase())
        && (14..=74).contains(&bech32.len())
        && bech32[3..]
            .chars()
            .all(|c| "qpzry9x8gf2tvdw0s3jn54khce6mua7l".contains(c));
    let is_base58 = address.starts_with(['1', '3'])
        && (26..=35).contains(&address.len())
        && address
            .chars()
            .all(|c| c.is_ascii_alphanumeric() && !"0OIl".contains(c));
    is_bech32 || is_base58
}

fn is_ethereum_address(address: &str) -> bool {
    address.len() == 42
        && address.starts_with("0x")
        && address[2..].bytes().all(|b| b.is_ascii_hexdigit())
}

/// The URI a wallet app opens to pay `address`: `bitcoin:<address>` (BIP 21) or
/// `ethereum:<address>` (EIP-681). `None` for another network, or a value that isn't an address.
pub fn address_uri(network: &str, address: &str) -> Option<String> {
    let address = address.trim();
    match network.trim().to_lowercase().as_str() {
        "bitcoin" | "btc" if is_bitcoin_address(address) => Some(format!("bitcoin:{address}")),
        "ethereum" | "eth" if is_ethereum_address(address) => Some(format!("ethereum:{address}")),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::*;

    #[test]
    fn the_vectors_hold() {
        let vectors: Value =
            serde_json::from_str(include_str!("../../tests/vectors/payment-qr.json")).unwrap();
        for case in vectors["epc"].as_array().unwrap() {
            let get = |key: &str| case[key].as_str().unwrap_or_default();
            let text = epc_qr_text(&EpcPayment {
                name: get("name"),
                iban: get("iban"),
                bic: get("bic"),
                amount: get("amount"),
                reference: get("reference"),
            });
            assert_eq!(text.as_deref(), case["text"].as_str(), "{case}");
        }
        for case in vectors["address"].as_array().unwrap() {
            let uri = address_uri(
                case["network"].as_str().unwrap(),
                case["address"].as_str().unwrap(),
            );
            assert_eq!(uri.as_deref(), case["uri"].as_str(), "{case}");
        }
        for case in vectors["looksLikeAddress"].as_array().unwrap() {
            assert_eq!(
                looks_like_address(case["address"].as_str().unwrap()),
                case["ok"].as_bool().unwrap(),
                "{case}"
            );
        }
    }

    #[test]
    fn a_seed_phrase_is_never_an_address() {
        let seed = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        assert!(!looks_like_address(seed));
        assert_eq!(address_uri("bitcoin", seed), None);
        assert_eq!(address_uri("ethereum", seed), None);
    }
}
