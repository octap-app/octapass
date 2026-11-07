//! Key fingerprints: a short code two people compare out of band (in person, on a call) to
//! know the public keys the server gave them are really each other's.
//!
//! ```text
//! digest = SHA-256("octapass/v1/fingerprint" ‖ 0x00 ‖ public_enc_key ‖ public_sign_key)
//! digits = for i in 0..6: (digest[5i..5i+5] as a big-endian 40-bit number) mod 10000, 4 digits each
//! emoji  = for i in 0..8: EMOJI[bits 6i..6i+6 of digest] (64 emoji, each with a name)
//! ```
//!
//! The digits carry about 80 bits; the emoji, 48 bits, are the quicker form to read aloud.

use serde::Serialize;
use sha2::{Digest, Sha256};

/// One fingerprint emoji and the word to say for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct FingerprintEmoji {
    pub emoji: &'static str,
    pub name: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Fingerprint {
    /// Six groups of four digits separated by spaces, like `0412 8873 1290 5531 0078 6620`.
    pub digits: String,
    pub emoji: Vec<FingerprintEmoji>,
}

const GROUPS: usize = 6;
const EMOJI_COUNT: usize = 8;

/// Easy to tell apart and to name (the list Matrix uses for emoji verification).
#[rustfmt::skip]
const EMOJI: [(&str, &str); 64] = [
    ("🐶", "Dog"), ("🐱", "Cat"), ("🦁", "Lion"), ("🐎", "Horse"),
    ("🦄", "Unicorn"), ("🐷", "Pig"), ("🐘", "Elephant"), ("🐰", "Rabbit"),
    ("🐼", "Panda"), ("🐓", "Rooster"), ("🐧", "Penguin"), ("🐢", "Turtle"),
    ("🐟", "Fish"), ("🐙", "Octopus"), ("🦋", "Butterfly"), ("🌷", "Flower"),
    ("🌳", "Tree"), ("🌵", "Cactus"), ("🍄", "Mushroom"), ("🌏", "Globe"),
    ("🌙", "Moon"), ("☁️", "Cloud"), ("🔥", "Fire"), ("🍌", "Banana"),
    ("🍎", "Apple"), ("🍓", "Strawberry"), ("🌽", "Corn"), ("🍕", "Pizza"),
    ("🎂", "Cake"), ("❤️", "Heart"), ("😀", "Smiley"), ("🤖", "Robot"),
    ("🎩", "Hat"), ("👓", "Glasses"), ("🔧", "Spanner"), ("🎅", "Santa"),
    ("👍", "Thumbs up"), ("☂️", "Umbrella"), ("⌛", "Hourglass"), ("⏰", "Clock"),
    ("🎁", "Gift"), ("💡", "Light bulb"), ("📕", "Book"), ("✏️", "Pencil"),
    ("📎", "Paperclip"), ("✂️", "Scissors"), ("🔒", "Lock"), ("🔑", "Key"),
    ("🔨", "Hammer"), ("☎️", "Telephone"), ("🏁", "Flag"), ("🚂", "Train"),
    ("🚲", "Bicycle"), ("✈️", "Aeroplane"), ("🚀", "Rocket"), ("🏆", "Trophy"),
    ("⚽", "Ball"), ("🎸", "Guitar"), ("🎺", "Trumpet"), ("🔔", "Bell"),
    ("⚓", "Anchor"), ("🎧", "Headphones"), ("📁", "Folder"), ("📌", "Pin"),
];

pub fn fingerprint(public_enc_key: &[u8; 32], public_sign_key: &[u8; 32]) -> Fingerprint {
    let digest = Sha256::new()
        .chain_update(b"octapass/v1/fingerprint\0")
        .chain_update(public_enc_key)
        .chain_update(public_sign_key)
        .finalize();

    let digits = (0..GROUPS)
        .map(|i| {
            let value = digest[5 * i..5 * i + 5]
                .iter()
                .fold(0u64, |acc, &byte| (acc << 8) | u64::from(byte));
            format!("{:04}", value % 10_000)
        })
        .collect::<Vec<_>>()
        .join(" ");

    let bits = digest[..6]
        .iter()
        .fold(0u64, |acc, &byte| (acc << 8) | u64::from(byte));
    let emoji = (0..EMOJI_COUNT)
        .map(|i| {
            let index = (bits >> (42 - 6 * i)) & 63;
            let (emoji, name) = EMOJI[index as usize];
            FingerprintEmoji { emoji, name }
        })
        .collect();

    Fingerprint { digits, emoji }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn shape() {
        let print = fingerprint(&[1; 32], &[2; 32]);
        assert_eq!(print.digits.len(), 6 * 4 + 5);
        assert!(
            print
                .digits
                .split(' ')
                .all(|group| group.len() == 4 && group.bytes().all(|b| b.is_ascii_digit()))
        );
        assert_eq!(print.emoji.len(), 8);
        assert_eq!(print, fingerprint(&[1; 32], &[2; 32]));
    }

    #[test]
    fn both_keys_count() {
        let print = fingerprint(&[1; 32], &[2; 32]);
        assert_ne!(print.digits, fingerprint(&[1; 32], &[3; 32]).digits);
        assert_ne!(print.digits, fingerprint(&[3; 32], &[2; 32]).digits);
        assert_ne!(print.digits, fingerprint(&[2; 32], &[1; 32]).digits);
    }

    #[test]
    fn emoji_and_names_are_distinct() {
        assert_eq!(EMOJI.iter().map(|e| e.0).collect::<HashSet<_>>().len(), 64);
        assert_eq!(EMOJI.iter().map(|e| e.1).collect::<HashSet<_>>().len(), 64);
    }
}
