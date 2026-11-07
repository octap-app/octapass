//! `.env` files for `octapass run --env-file`, read by the core's parser
//! (`octapass_core::environment`), which every app shares.

use octapass_core::environment::{self, EnvError};

use crate::error::{CliError, Result};

/// The `KEY=value` pairs of a file, in order; a name used twice is there twice (the later wins).
pub fn parse(text: &str, name: &str) -> Result<Vec<(String, String)>> {
    let vars = environment::parse(text).map_err(|error| invalid(name, &error))?;
    Ok(vars.into_iter().map(|var| (var.key, var.value)).collect())
}

/// `name, line 2: expected KEY=value`.
pub fn invalid(name: &str, error: &EnvError) -> CliError {
    CliError::usage(format!("{name}, {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_usual_dotenv_lines() {
        let text = "\
# database
DATABASE_PASSWORD=octapass://Work/Postgres/password
export STRIPE_KEY = octapass://Work/Stripe/api key   # the live key
GREETING=\"hello \\\"world\\\"\\n\"
RAW='a # not a comment'
EMPTY=
";
        let vars = parse(text, ".env").unwrap();
        let expected = [
            ("DATABASE_PASSWORD", "octapass://Work/Postgres/password"),
            ("STRIPE_KEY", "octapass://Work/Stripe/api key"),
            ("GREETING", "hello \"world\"\n"),
            ("RAW", "a # not a comment"),
            ("EMPTY", ""),
        ]
        .map(|(key, value)| (key.to_owned(), value.to_owned()));
        assert_eq!(vars, expected);
    }

    #[test]
    fn says_which_line_is_wrong() {
        let error = parse("A=1\nnot a line\n", "app.env").unwrap_err();
        assert_eq!(error.message, "app.env, line 2: expected KEY=value");
        assert!(parse("1A=x", "f").is_err());
        assert!(parse("A=\"open", "f").is_err());
        assert!(parse("A='x' y", "f").is_err());
    }
}
