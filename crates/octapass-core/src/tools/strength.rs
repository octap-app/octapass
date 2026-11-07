//! Password strength, estimated with zxcvbn (dictionaries, patterns, keyboard walks, dates …).

use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Strength {
    /// 0 (too guessable) to 4 (very unguessable).
    pub score: u8,
    pub guesses_log10: f64,
    /// The most useful single hint, if there is one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub feedback: Option<String>,
}

/// Estimates strength. `user_inputs` are words specific to this user (email, name, site) that
/// make a password weaker if it contains them.
pub fn estimate(password: &str, user_inputs: &[&str]) -> Strength {
    if password.is_empty() {
        return Strength {
            score: 0,
            guesses_log10: 0.0,
            feedback: None,
        };
    }
    let entropy = zxcvbn::zxcvbn(password, user_inputs);
    let feedback = entropy.feedback().and_then(|feedback| {
        feedback
            .warning()
            .map(|warning| warning.to_string())
            .or_else(|| feedback.suggestions().first().map(|s| s.to_string()))
    });
    Strength {
        score: u8::from(entropy.score()),
        guesses_log10: entropy.guesses_log10(),
        feedback,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn weak_and_strong() {
        let weak = estimate("password1", &[]);
        assert_eq!(weak.score, 0);
        assert!(weak.feedback.is_some());

        let strong = estimate("correct-horse-battery-staple-orbit", &[]);
        assert_eq!(strong.score, 4);
        assert!(strong.guesses_log10 > 12.0);
    }

    #[test]
    fn user_inputs_count_against_the_password() {
        let plain = estimate("alice2026!", &[]);
        let personal = estimate("alice2026!", &["alice"]);
        assert!(personal.guesses_log10 < plain.guesses_log10);
    }

    #[test]
    fn empty() {
        assert_eq!(estimate("", &[]).score, 0);
    }
}
