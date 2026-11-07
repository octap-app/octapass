//! Environments: `.env` files and environment variables kept in the vault (plan 16, §3).
//!
//! One parser and one writer for every client. [`parse`] reads `KEY=value` lines, `#` comments,
//! an optional `export `, single-quoted values (taken as written), double-quoted values (with
//! `\n`, `\t`, `\r`, `\"` and `\\` escapes, and real line breaks for multi-line values such as
//! PEM keys) and unquoted values (a `#` after a space starts a comment). [`write`] turns variables
//! back into a dotenv file that [`parse`] reads to the same values, or into JSON, POSIX shell,
//! PowerShell or Docker's `--env-file` format.
//!
//! An environment can belong to a **project** (`shop-api`) and a **stage** (`production`). A
//! project's environment without a stage is its shared set: [`layer`] loads it first and lets the
//! stage's variables override it.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::item::{EnvironmentDetails, EnvironmentVariable};

/// Variable names: letters, digits and `_`, not starting with a digit.
pub fn valid_key(key: &str) -> bool {
    let mut chars = key.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Why a variable list or a `.env` file can't be used. `line` is 1-based, 0 when it's about the
/// list rather than a line of a file. Never contains a value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EnvError {
    pub problem: EnvProblem,
    pub line: usize,
    /// The variable the problem is about, when there is one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum EnvProblem {
    /// A line that isn't `KEY=value`.
    ExpectedKeyValue,
    InvalidKey,
    DuplicateKey,
    UnclosedQuote,
    TextAfterQuote,
    /// Docker's `--env-file` has no quoting, so a value with a line break can't be written to it.
    MultilineValue,
    InvalidProject,
    InvalidStage,
}

impl EnvProblem {
    pub fn message(self) -> &'static str {
        match self {
            EnvProblem::ExpectedKeyValue => "expected KEY=value",
            EnvProblem::InvalidKey => {
                "names are letters, digits and _, and don't start with a digit"
            }
            EnvProblem::DuplicateKey => "this name is already used",
            EnvProblem::UnclosedQuote => "a quote isn't closed",
            EnvProblem::TextAfterQuote => "unexpected text after the closing quote",
            EnvProblem::MultilineValue => {
                "Docker's env file format can't hold a value with a line break: use dotenv or run the command with `octapass run`"
            }
            EnvProblem::InvalidProject => {
                "a project is up to 64 letters, digits, - and _, like shop-api"
            }
            EnvProblem::InvalidStage => {
                "a stage is up to 32 letters, digits, - and _, like production"
            }
        }
    }
}

impl fmt::Display for EnvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (&self.key, self.line) {
            (Some(key), 0) => write!(f, "{key}: {}", self.problem.message()),
            (Some(key), line) => write!(f, "line {line} ({key}): {}", self.problem.message()),
            (None, 0) => f.write_str(self.problem.message()),
            (None, line) => write!(f, "line {line}: {}", self.problem.message()),
        }
    }
}

impl std::error::Error for EnvError {}

fn at(problem: EnvProblem, line: usize, key: Option<&str>) -> EnvError {
    EnvError {
        problem,
        line,
        key: key.map(str::to_owned),
    }
}

/// One `KEY=value` from a file, with the line it starts on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ParsedVariable {
    pub key: String,
    pub value: String,
    pub line: usize,
}

/// Reads a `.env` file. A name used twice is kept twice (the later one wins when the file is
/// loaded into an environment); [`variables_from_dotenv`] rejects that instead.
pub fn parse(text: &str) -> Result<Vec<ParsedVariable>, EnvError> {
    let lines: Vec<&str> = text.lines().collect();
    let mut vars = Vec::new();
    let mut index = 0;
    while index < lines.len() {
        let number = index + 1;
        let line = lines[index].trim();
        index += 1;
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line).trim_start();
        let (key, raw) = line
            .split_once('=')
            .ok_or_else(|| at(EnvProblem::ExpectedKeyValue, number, None))?;
        let key = key.trim();
        if !valid_key(key) {
            return Err(at(EnvProblem::InvalidKey, number, None));
        }
        let fail = |problem| at(problem, number, Some(key));
        let raw = raw.trim();
        let value = if let Some(rest) = raw.strip_prefix('\'') {
            let end = rest
                .find('\'')
                .ok_or_else(|| fail(EnvProblem::UnclosedQuote))?;
            trailing(&rest[end + 1..]).map_err(fail)?;
            rest[..end].to_owned()
        } else if let Some(first) = raw.strip_prefix('"') {
            // A double-quoted value may go on over the next lines, up to its closing quote.
            let mut text = first.to_owned();
            loop {
                match double_quoted(&text) {
                    Some((value, rest)) => {
                        trailing(rest).map_err(fail)?;
                        break value;
                    }
                    None if index < lines.len() => {
                        text.push('\n');
                        // The rest of the value is taken as written, indentation included.
                        text.push_str(lines[index].trim_end_matches('\r'));
                        index += 1;
                    }
                    None => return Err(fail(EnvProblem::UnclosedQuote)),
                }
            }
        } else {
            unquoted(raw).to_owned()
        };
        vars.push(ParsedVariable {
            key: key.to_owned(),
            value,
            line: number,
        });
    }
    Ok(vars)
}

/// The value inside a double-quoted string (after its opening quote) and the text after the
/// closing quote, or `None` when the quote isn't closed.
fn double_quoted(text: &str) -> Option<(String, &str)> {
    let mut value = String::new();
    let mut chars = text.char_indices();
    while let Some((at, c)) = chars.next() {
        match c {
            '"' => return Some((value, &text[at + 1..])),
            '\\' => match chars.next().map(|(_, c)| c) {
                Some('n') => value.push('\n'),
                Some('t') => value.push('\t'),
                Some('r') => value.push('\r'),
                Some(other) => value.push(other),
                None => return None,
            },
            c => value.push(c),
        }
    }
    None
}

/// An unquoted value, without a ` #` comment after it.
fn unquoted(raw: &str) -> &str {
    let comment = raw
        .char_indices()
        .find(|&(at, c)| c == '#' && at > 0 && raw[..at].ends_with([' ', '\t']))
        .map(|(at, _)| at);
    comment.map_or(raw, |at| &raw[..at]).trim_end()
}

fn trailing(rest: &str) -> Result<(), EnvProblem> {
    let rest = rest.trim();
    if rest.is_empty() || rest.starts_with('#') {
        Ok(())
    } else {
        Err(EnvProblem::TextAfterQuote)
    }
}

/// A `.env` file as an environment's variables: concealed, in file order. A name used twice is
/// an error, as in an environment item.
pub fn variables_from_dotenv(text: &str) -> Result<Vec<EnvironmentVariable>, EnvError> {
    let parsed = parse(text)?;
    for (i, var) in parsed.iter().enumerate() {
        if parsed[..i].iter().any(|earlier| earlier.key == var.key) {
            return Err(at(EnvProblem::DuplicateKey, var.line, Some(&var.key)));
        }
    }
    Ok(parsed
        .into_iter()
        .map(|var| EnvironmentVariable::new(var.key, var.value))
        .collect())
}

/// Checks an environment's variables: valid names, each used once.
pub fn validate(variables: &[EnvironmentVariable]) -> Result<(), EnvError> {
    for (i, var) in variables.iter().enumerate() {
        if !valid_key(&var.key) {
            return Err(at(EnvProblem::InvalidKey, 0, Some(&var.key)));
        }
        if variables[..i].iter().any(|earlier| earlier.key == var.key) {
            return Err(at(EnvProblem::DuplicateKey, 0, Some(&var.key)));
        }
    }
    Ok(())
}

/// The stages apps know by name, translate and colour. Any other valid name is a custom stage.
pub const KNOWN_STAGES: [&str; 6] = [
    "development",
    "staging",
    "production",
    "testing",
    "preview",
    "local",
];

fn identifier(text: &str, max: usize) -> bool {
    (1..=max).contains(&text.len())
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// A project identifier: 1-64 letters, digits, `-` and `_`.
pub fn valid_project(project: &str) -> bool {
    identifier(project, 64)
}

/// A stage name: 1-32 letters, digits, `-` and `_`.
pub fn valid_stage(stage: &str) -> bool {
    identifier(stage, 32)
}

/// Production needs a confirmation before a command runs with it. Matched without case, so
/// `Production` and `prod` count too.
pub fn is_production(stage: &str) -> bool {
    matches!(stage.to_ascii_lowercase().as_str(), "production" | "prod")
}

/// The list subtitle apps show for an environment: `shop-api · production`, either part alone, or
/// none.
pub fn subtitle(details: &EnvironmentDetails) -> Option<String> {
    let parts: Vec<&str> = [details.project.as_deref(), details.stage.as_deref()]
        .into_iter()
        .flatten()
        .filter(|part| !part.is_empty())
        .collect();
    (!parts.is_empty()).then(|| parts.join(" · "))
}

/// Checks a whole environment: its variables, project and stage.
pub fn validate_details(details: &EnvironmentDetails) -> Result<(), EnvError> {
    validate(&details.variables)?;
    if let Some(project) = &details.project
        && !valid_project(project)
    {
        return Err(at(EnvProblem::InvalidProject, 0, None));
    }
    if let Some(stage) = &details.stage
        && !valid_stage(stage)
    {
        return Err(at(EnvProblem::InvalidStage, 0, None));
    }
    Ok(())
}

/// The variables of several environments loaded together, later ones winning: a project's shared
/// set first, then its stage, then any further environments, in that order.
pub fn layer<'a>(
    environments: impl IntoIterator<Item = &'a [EnvironmentVariable]>,
) -> Vec<EnvironmentVariable> {
    let mut out = Vec::new();
    for variables in environments {
        for var in variables {
            match out
                .iter_mut()
                .find(|existing: &&mut EnvironmentVariable| existing.key == var.key)
            {
                Some(existing) => *existing = var.clone(),
                None => out.push(var.clone()),
            }
        }
    }
    out
}

/// How a name differs between two environments. Values are compared, never shown.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum DiffKind {
    OnlyInFirst,
    OnlyInSecond,
    Different,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiffEntry {
    pub key: String,
    pub kind: DiffKind,
}

/// The names missing from one side or holding different values, in the first environment's order
/// and then the second's. Names with the same value on both sides are left out.
pub fn diff(first: &[EnvironmentVariable], second: &[EnvironmentVariable]) -> Vec<DiffEntry> {
    let find = |list: &'_ [EnvironmentVariable], key: &str| {
        list.iter()
            .find(|var| var.key == key)
            .map(|var| var.value.clone())
    };
    let mut out = Vec::new();
    for var in first {
        let kind = match find(second, &var.key) {
            None => DiffKind::OnlyInFirst,
            Some(value) if value != var.value => DiffKind::Different,
            Some(_) => continue,
        };
        out.push(DiffEntry {
            key: var.key.clone(),
            kind,
        });
    }
    for var in second {
        if find(first, &var.key).is_none() {
            out.push(DiffEntry {
                key: var.key.clone(),
                kind: DiffKind::OnlyInSecond,
            });
        }
    }
    out
}

/// Adds or replaces variables by name, keeping the order of those already there and adding new
/// ones at the end. A replaced variable keeps its concealed flag and note.
pub fn merge(variables: &mut Vec<EnvironmentVariable>, new: Vec<EnvironmentVariable>) {
    for var in new {
        match variables
            .iter_mut()
            .find(|existing| existing.key == var.key)
        {
            Some(existing) => existing.value = var.value,
            None => variables.push(var),
        }
    }
}

/// The formats [`write`] can produce.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum EnvFormat {
    /// A `.env` file, quoted only where needed.
    Dotenv,
    /// `{ "KEY": "value" }`, in the environment's order.
    Json,
    /// `export KEY='value'` lines for sh, bash and zsh.
    Shell,
    /// `$env:KEY = 'value'` lines.
    Powershell,
    /// `KEY=value` lines for `docker run --env-file`: no quotes, so no line breaks.
    Docker,
}

impl EnvFormat {
    pub fn parse(name: &str) -> Option<Self> {
        match name.trim().to_ascii_lowercase().as_str() {
            "dotenv" | "env" | ".env" => Some(Self::Dotenv),
            "json" => Some(Self::Json),
            "shell" | "sh" | "bash" | "zsh" | "posix" => Some(Self::Shell),
            "powershell" | "pwsh" | "ps1" => Some(Self::Powershell),
            "docker" => Some(Self::Docker),
            _ => None,
        }
    }
}

/// Writes `(key, value)` pairs in `format`. Every format ends with a newline when it has lines.
pub fn write<'a>(
    variables: impl IntoIterator<Item = (&'a str, &'a str)>,
    format: EnvFormat,
) -> Result<String, EnvError> {
    let variables: Vec<(&str, &str)> = variables.into_iter().collect();
    for (key, _) in &variables {
        if !valid_key(key) {
            return Err(at(EnvProblem::InvalidKey, 0, Some(key)));
        }
    }
    if format == EnvFormat::Json {
        let entries: Vec<String> = variables
            .iter()
            .map(|(key, value)| {
                format!(
                    "  {}: {}",
                    serde_json::to_string(key).expect("strings serialize"),
                    serde_json::to_string(value).expect("strings serialize")
                )
            })
            .collect();
        return Ok(if entries.is_empty() {
            "{}\n".into()
        } else {
            format!("{{\n{}\n}}\n", entries.join(",\n"))
        });
    }
    let mut out = String::new();
    for (key, value) in variables {
        let line = match format {
            EnvFormat::Dotenv => format!("{key}={}", dotenv_value(value)),
            EnvFormat::Shell => format!("export {key}='{}'", value.replace('\'', "'\\''")),
            EnvFormat::Powershell => format!("$env:{key} = '{}'", value.replace('\'', "''")),
            EnvFormat::Docker => {
                if value.contains(['\n', '\r']) {
                    return Err(at(EnvProblem::MultilineValue, 0, Some(key)));
                }
                format!("{key}={value}")
            }
            EnvFormat::Json => unreachable!("written above"),
        };
        out.push_str(&line);
        out.push('\n');
    }
    Ok(out)
}

/// A value as a dotenv file writes it: bare when that reads back the same, else in single quotes
/// (nothing inside is expanded by any dotenv reader), else in double quotes with escapes.
fn dotenv_value(value: &str) -> String {
    let bare = |c: char| c.is_ascii_alphanumeric() || "_-./:@%+,=^~".contains(c);
    if value.chars().all(bare) {
        return value.to_owned();
    }
    if !value.contains(['\'', '\n', '\r']) {
        return format!("'{value}'");
    }
    let mut out = String::from("\"");
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            // Line breaks stay real, so a PEM key reads as one.
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pairs(text: &str) -> Vec<(String, String)> {
        parse(text)
            .unwrap()
            .into_iter()
            .map(|var| (var.key, var.value))
            .collect()
    }

    fn owned(list: &[(&str, &str)]) -> Vec<(String, String)> {
        list.iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

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
        assert_eq!(
            pairs(text),
            owned(&[
                ("DATABASE_PASSWORD", "octapass://Work/Postgres/password"),
                ("STRIPE_KEY", "octapass://Work/Stripe/api key"),
                ("GREETING", "hello \"world\"\n"),
                ("RAW", "a # not a comment"),
                ("EMPTY", ""),
            ])
        );
    }

    #[test]
    fn equals_signs_hashes_and_quotes_inside_values() {
        let text = "\
URL=postgres://u:p@db/app?sslmode=require&a=b
TOKEN=abc==
COLOR=#ff0000
TAG=a#b # comment
TABBED=x\t# tab comment
QUOTE=it's
SINGLE='say \"hi\"'
";
        assert_eq!(
            pairs(text),
            owned(&[
                ("URL", "postgres://u:p@db/app?sslmode=require&a=b"),
                ("TOKEN", "abc=="),
                ("COLOR", "#ff0000"),
                ("TAG", "a#b"),
                ("TABBED", "x"),
                ("QUOTE", "it's"),
                ("SINGLE", "say \"hi\""),
            ])
        );
    }

    #[test]
    fn double_quoted_values_can_span_lines() {
        let text = "\
KEY=\"-----BEGIN PRIVATE KEY-----
  abc
-----END PRIVATE KEY-----\" # the key
NEXT=1
";
        let vars = parse(text).unwrap();
        assert_eq!(
            vars[0].value,
            "-----BEGIN PRIVATE KEY-----\n  abc\n-----END PRIVATE KEY-----"
        );
        assert_eq!((vars[1].key.as_str(), vars[1].line), ("NEXT", 4));
        assert_eq!(
            parse("A=\"open\nB=2\n").unwrap_err(),
            at(EnvProblem::UnclosedQuote, 1, Some("A"))
        );
    }

    #[test]
    fn says_which_line_is_wrong() {
        let error = parse("A=1\nnot a line\n").unwrap_err();
        assert_eq!(error.to_string(), "line 2: expected KEY=value");
        assert_eq!(parse("1A=x").unwrap_err().problem, EnvProblem::InvalidKey);
        assert_eq!(parse("A-B=x").unwrap_err().problem, EnvProblem::InvalidKey);
        assert_eq!(parse("=x").unwrap_err().problem, EnvProblem::InvalidKey);
        assert_eq!(
            parse("A='x").unwrap_err().problem,
            EnvProblem::UnclosedQuote
        );
        assert_eq!(
            parse("A='x' y").unwrap_err().to_string(),
            "line 1 (A): unexpected text after the closing quote"
        );
        assert_eq!(
            parse("A=\"x\" y").unwrap_err().problem,
            EnvProblem::TextAfterQuote
        );
    }

    #[test]
    fn duplicates_are_kept_by_parse_and_rejected_for_an_environment() {
        assert_eq!(parse("A=1\nA=2\n").unwrap().len(), 2);
        let error = variables_from_dotenv("A=1\n\nA=2\n").unwrap_err();
        assert_eq!(error, at(EnvProblem::DuplicateKey, 3, Some("A")));
        let vars = variables_from_dotenv("A=1\nB=2\n").unwrap();
        assert!(vars.iter().all(|var| var.concealed));
        assert_eq!(vars[1].key, "B");
    }

    #[test]
    fn keys() {
        for good in ["A", "_", "a_b", "_1", "PATH2"] {
            assert!(valid_key(good), "{good}");
        }
        for bad in ["", "1A", "A-B", "A B", "É", "A.B"] {
            assert!(!valid_key(bad), "{bad}");
        }
        let var = |key: &str| EnvironmentVariable::new(key.into(), "v".into());
        assert!(validate(&[var("A"), var("B")]).is_ok());
        assert_eq!(
            validate(&[var("A"), var("A")]).unwrap_err().problem,
            EnvProblem::DuplicateKey
        );
        assert_eq!(
            validate(&[var("9")]).unwrap_err().to_string(),
            "9: names are letters, digits and _, and don't start with a digit"
        );
    }

    const TRICKY: &[(&str, &str)] = &[
        ("PLAIN", "abc123"),
        ("URL", "https://example.com/a?b=c&d=e"),
        ("EMPTY", ""),
        ("SPACES", "  padded  "),
        ("HASH", "a #b"),
        ("SINGLE", "it's"),
        ("DOUBLE", "say \"hi\""),
        ("BOTH", "it's \"x\" \\ back"),
        ("DOLLAR", "$HOME and ${PATH}"),
        ("MULTI", "line 1\nline 2\n"),
        ("CRLF", "a\r\nb"),
        ("TAB", "a\tb"),
        ("UNICODE", "مرحبا ✓"),
    ];

    #[test]
    fn dotenv_round_trips() {
        let text = write(TRICKY.iter().copied(), EnvFormat::Dotenv).unwrap();
        assert_eq!(pairs(&text), owned(TRICKY));
        // Importing a file and exporting it again gives an equivalent file.
        let original = "A=1\n# c\nexport B = \"two\\nlines\"\nC='x y'\n";
        let again = write(
            parse(original)
                .unwrap()
                .iter()
                .map(|v| (v.key.as_str(), v.value.as_str())),
            EnvFormat::Dotenv,
        )
        .unwrap();
        assert_eq!(pairs(&again), pairs(original));
        assert_eq!(again, "A=1\nB=\"two\nlines\"\nC='x y'\n");
    }

    #[test]
    fn dotenv_quotes_only_where_needed() {
        let one = |value| write([("K", value)], EnvFormat::Dotenv).unwrap();
        assert_eq!(one("abc"), "K=abc\n");
        assert_eq!(one("a=b"), "K=a=b\n");
        assert_eq!(one(""), "K=\n");
        assert_eq!(one("a b"), "K='a b'\n");
        assert_eq!(one("$X"), "K='$X'\n");
        assert_eq!(one("it's"), "K=\"it's\"\n");
        assert_eq!(one("a\nb"), "K=\"a\nb\"\n");
    }

    #[test]
    fn json() {
        let text = write([("B", "1"), ("A", "x\"y\n")], EnvFormat::Json).unwrap();
        assert_eq!(text, "{\n  \"B\": \"1\",\n  \"A\": \"x\\\"y\\n\"\n}\n");
        let back: serde_json::Map<String, serde_json::Value> = serde_json::from_str(&text).unwrap();
        assert_eq!(back["A"], "x\"y\n");
        assert_eq!(write([], EnvFormat::Json).unwrap(), "{}\n");
    }

    #[test]
    fn shell_and_powershell_quote_everything() {
        let vars = [("A", "it's $HOME"), ("B", "x\ny")];
        assert_eq!(
            write(vars, EnvFormat::Shell).unwrap(),
            "export A='it'\\''s $HOME'\nexport B='x\ny'\n"
        );
        assert_eq!(
            write(vars, EnvFormat::Powershell).unwrap(),
            "$env:A = 'it''s $HOME'\n$env:B = 'x\ny'\n"
        );
    }

    #[test]
    fn docker_has_no_quotes_and_refuses_line_breaks() {
        assert_eq!(
            write([("A", "it's \"raw\" # here"), ("B", "")], EnvFormat::Docker).unwrap(),
            "A=it's \"raw\" # here\nB=\n"
        );
        let error = write([("OK", "1"), ("KEY", "a\nb")], EnvFormat::Docker).unwrap_err();
        assert_eq!(error, at(EnvProblem::MultilineValue, 0, Some("KEY")));
        assert!(
            error
                .to_string()
                .starts_with("KEY: Docker's env file format")
        );
    }

    #[test]
    fn writers_refuse_invalid_names() {
        for format in [
            EnvFormat::Dotenv,
            EnvFormat::Json,
            EnvFormat::Shell,
            EnvFormat::Powershell,
            EnvFormat::Docker,
        ] {
            assert_eq!(
                write([("BAD-KEY", "v")], format).unwrap_err().problem,
                EnvProblem::InvalidKey
            );
        }
    }

    #[test]
    fn merge_replaces_by_name_and_appends_new_ones() {
        let var = |key: &str, value: &str| EnvironmentVariable::new(key.into(), value.into());
        let mut list = vec![var("A", "1"), var("B", "2")];
        list[0].concealed = false;
        merge(&mut list, vec![var("C", "3"), var("A", "9")]);
        let keys: Vec<(&str, &str, bool)> = list
            .iter()
            .map(|v| (v.key.as_str(), v.value.as_str(), v.concealed))
            .collect();
        assert_eq!(
            keys,
            [("A", "9", false), ("B", "2", true), ("C", "3", true)]
        );
    }

    #[test]
    fn projects_and_stages() {
        for good in ["shop-api", "a", "Shop_API_2"] {
            assert!(valid_project(good), "{good}");
        }
        for bad in ["", "shop api", "shop:api", "é", &"x".repeat(65)] {
            assert!(!valid_project(bad), "{bad}");
        }
        assert!(KNOWN_STAGES.iter().all(|stage| valid_stage(stage)));
        assert!(valid_stage("qa-2"));
        assert!(!valid_stage("prod:eu") && !valid_stage("") && !valid_stage(&"s".repeat(33)));
        assert!(is_production("Production") && is_production("prod"));
        assert!(!is_production("staging"));

        let mut details: EnvironmentDetails =
            serde_json::from_value(serde_json::json!({ "project": "shop-api", "stage": "qa" }))
                .unwrap();
        assert!(validate_details(&details).is_ok());
        details.stage = Some("q a".into());
        assert_eq!(
            validate_details(&details).unwrap_err().problem,
            EnvProblem::InvalidStage
        );
        details.stage = Some("production".into());
        assert_eq!(subtitle(&details).as_deref(), Some("shop-api · production"));
        details.project = None;
        assert_eq!(subtitle(&details).as_deref(), Some("production"));
        details.stage = None;
        assert_eq!(subtitle(&details), None);
        details.project = Some("shop/api".into());
        assert_eq!(
            validate_details(&details).unwrap_err().problem,
            EnvProblem::InvalidProject
        );
    }

    #[test]
    fn the_stage_overrides_the_shared_set_and_later_environments_win() {
        let var = |key: &str, value: &str| EnvironmentVariable::new(key.into(), value.into());
        let shared = [var("LOG", "info"), var("DB", "shared"), var("REGION", "eu")];
        let production = [var("DB", "prod"), var("SENTRY", "on")];
        let extra = [var("LOG", "debug")];
        let layered = layer([&shared[..], &production[..], &extra[..]]);
        let pairs: Vec<(&str, &str)> = layered
            .iter()
            .map(|v| (v.key.as_str(), v.value.as_str()))
            .collect();
        assert_eq!(
            pairs,
            [
                ("LOG", "debug"),
                ("DB", "prod"),
                ("REGION", "eu"),
                ("SENTRY", "on")
            ]
        );
    }

    #[test]
    fn diff_lists_missing_and_different_names() {
        let var = |key: &str, value: &str| EnvironmentVariable::new(key.into(), value.into());
        let staging = [var("A", "1"), var("B", "2"), var("ONLY_STAGING", "x")];
        let production = [var("B", "3"), var("A", "1"), var("ONLY_PROD", "y")];
        let entry = |key: &str, kind| DiffEntry {
            key: key.into(),
            kind,
        };
        assert_eq!(
            diff(&staging, &production),
            [
                entry("B", DiffKind::Different),
                entry("ONLY_STAGING", DiffKind::OnlyInFirst),
                entry("ONLY_PROD", DiffKind::OnlyInSecond),
            ]
        );
        assert!(diff(&staging, &staging).is_empty());
    }

    #[test]
    fn format_names() {
        assert_eq!(EnvFormat::parse("PWSH"), Some(EnvFormat::Powershell));
        assert_eq!(EnvFormat::parse(".env"), Some(EnvFormat::Dotenv));
        assert_eq!(EnvFormat::parse("yaml"), None);
    }
}
