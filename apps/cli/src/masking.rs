//! Output masking for `octapass run`: the command's stdout and stderr pass through a filter that
//! replaces every secret it was given. A convenience for logs and shared screens, not a boundary:
//! a program can always encode a value so it doesn't match.

use zeroize::Zeroizing;

/// What a secret turns into.
pub const MASK: &[u8] = b"<concealed by Octa Pass>";
/// Shorter values aren't masked: `1` or `true` would turn all the output into noise.
pub const MIN_LENGTH: usize = 4;

/// The text a secret may appear as: the whole value, and each line of a multi-line one, since
/// programs often print those a line at a time.
fn patterns(values: impl IntoIterator<Item = String>) -> Vec<Zeroizing<Vec<u8>>> {
    let mut patterns: Vec<Zeroizing<Vec<u8>>> = Vec::new();
    for value in values {
        let value = Zeroizing::new(value);
        let lines: Vec<&str> = value.lines().map(str::trim).collect();
        let parts = std::iter::once(value.as_str())
            .chain(lines.into_iter().filter(|_| value.contains('\n')));
        for part in parts {
            if part.len() >= MIN_LENGTH {
                patterns.push(Zeroizing::new(part.as_bytes().to_vec()));
            }
        }
    }
    // Longest first: a secret that contains another one is masked whole.
    patterns.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
    patterns.dedup();
    patterns
}

/// A streaming filter for one output. Bytes that could be the start of a secret are held back
/// until the next chunk decides, so a secret split across two writes is still masked.
pub struct Masker {
    patterns: Vec<Zeroizing<Vec<u8>>>,
    pending: Zeroizing<Vec<u8>>,
}

impl Masker {
    pub fn new(values: impl IntoIterator<Item = String>) -> Self {
        Self {
            patterns: patterns(values),
            pending: Zeroizing::new(Vec::new()),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }

    /// Filters `bytes`, appending what's safe to show to `out`.
    pub fn feed(&mut self, bytes: &[u8], out: &mut Vec<u8>) {
        self.pending.extend_from_slice(bytes);
        self.drain(out, false);
    }

    /// The output ended: whatever was held back isn't a secret after all.
    pub fn finish(&mut self, out: &mut Vec<u8>) {
        self.drain(out, true);
    }

    fn drain(&mut self, out: &mut Vec<u8>, last: bool) {
        let mut at = 0;
        'bytes: while at < self.pending.len() {
            let rest = &self.pending[at..];
            for pattern in &self.patterns {
                if rest.starts_with(pattern) {
                    out.extend_from_slice(MASK);
                    at += pattern.len();
                    continue 'bytes;
                }
                if !last && rest.len() < pattern.len() && pattern.starts_with(rest) {
                    break 'bytes;
                }
            }
            out.push(rest[0]);
            at += 1;
        }
        self.pending.drain(..at);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mask(values: &[&str], chunks: &[&str]) -> String {
        let mut masker = Masker::new(values.iter().map(|value| (*value).to_owned()));
        let mut out = Vec::new();
        for chunk in chunks {
            masker.feed(chunk.as_bytes(), &mut out);
        }
        masker.finish(&mut out);
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn secrets_are_replaced_and_the_rest_is_kept() {
        assert_eq!(
            mask(&["hunter2"], &["pw=hunter2; again hunter2\n"]),
            "pw=<concealed by Octa Pass>; again <concealed by Octa Pass>\n"
        );
    }

    #[test]
    fn a_secret_split_across_chunks_is_still_masked() {
        assert_eq!(
            mask(&["hunter2"], &["pw=hun", "te", "r2!"]),
            "pw=<concealed by Octa Pass>!"
        );
        // Byte by byte, too.
        let text = "xhunter2y";
        let bytes: Vec<String> = text.chars().map(String::from).collect();
        let chunks: Vec<&str> = bytes.iter().map(String::as_str).collect();
        assert_eq!(mask(&["hunter2"], &chunks), "x<concealed by Octa Pass>y");
    }

    #[test]
    fn a_false_start_comes_through_unchanged() {
        assert_eq!(mask(&["hunter2"], &["hunter", "3 hunt"]), "hunter3 hunt");
        assert_eq!(mask(&["aaab"], &["aaaaab"]), "aa<concealed by Octa Pass>");
    }

    #[test]
    fn nothing_is_held_back_that_cannot_be_a_secret() {
        let mut masker = Masker::new(["hunter2".to_owned()]);
        let mut out = Vec::new();
        masker.feed(b"Continue? [y/N] ", &mut out);
        assert_eq!(out, b"Continue? [y/N] ");
        masker.feed(b"h", &mut out);
        assert_eq!(out, b"Continue? [y/N] ", "could be the start of the secret");
    }

    #[test]
    fn the_longest_secret_wins() {
        assert_eq!(
            mask(&["token", "token-with-more"], &["token-with-more token"]),
            "<concealed by Octa Pass> <concealed by Octa Pass>"
        );
    }

    #[test]
    fn multi_line_values_are_masked_line_by_line_too() {
        let key = "-----BEGIN KEY-----\nabcdefgh\n-----END KEY-----";
        assert_eq!(mask(&[key], &[key]), "<concealed by Octa Pass>");
        assert_eq!(
            mask(&[key], &["line: abcdefgh\n"]),
            "line: <concealed by Octa Pass>\n"
        );
    }

    #[test]
    fn very_short_values_are_left_alone() {
        assert_eq!(mask(&["abc", "1"], &["abc 1"]), "abc 1");
        assert!(Masker::new(["abc".to_owned()]).is_empty());
    }

    #[test]
    fn binary_output_passes_through() {
        let mut masker = Masker::new(["hunter2".to_owned()]);
        let mut out = Vec::new();
        masker.feed(&[0xff, 0x00, 0xfe], &mut out);
        masker.finish(&mut out);
        assert_eq!(out, [0xff, 0x00, 0xfe]);
    }
}
