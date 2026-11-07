//! X11 keysyms, which both X11's XTest and Wayland's RemoteDesktop portal take. Any Unicode
//! character has one: Latin-1 characters are their own code, everything else is
//! `0x0100_0000 + code point` (X11 protocol, appendix A).

use crate::sequence::Key;

pub const TAB: u32 = 0xff09;
pub const RETURN: u32 = 0xff0d;

pub fn for_char(c: char) -> u32 {
    let code = c as u32;
    match code {
        0x20..=0x7e | 0xa0..=0xff => code,
        _ => 0x0100_0000 + code,
    }
}

pub fn for_key(key: Key) -> u32 {
    match key {
        Key::Tab => TAB,
        Key::Enter => RETURN,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn characters_have_keysyms() {
        assert_eq!(for_char('a'), 0x61);
        assert_eq!(for_char('~'), 0x7e);
        assert_eq!(for_char('é'), 0xe9);
        assert_eq!(for_char('€'), 0x0100_20ac);
        assert_eq!(for_char('ب'), 0x0100_0628);
        assert_eq!(for_char('😀'), 0x0101_f600);
        assert_eq!(for_key(Key::Tab), 0xff09);
        assert_eq!(for_key(Key::Enter), 0xff0d);
    }
}
