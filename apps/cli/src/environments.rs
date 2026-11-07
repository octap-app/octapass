//! Environments on this computer (plan 16, §3): the `octapass.toml` project file, the shell
//! hook and its allow list, `inject` templates and the files `env export` and `run
//! --env-file-out` write. The commands themselves are in `env_commands`.

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::cli::Shell;
use crate::error::{CliError, Result};
use crate::items::{Reference, SCHEME};

pub const PROJECT_FILE: &str = "octapass.toml";
/// Overrides the project file's `stage`, as `--stage` does.
pub const STAGE_ENV: &str = "OCTAPASS_STAGE";
/// What the shell hook loaded, kept in the shell's own environment between prompts.
pub const HOOK_STATE_ENV: &str = "OCTAPASS_ENV_STATE";
const ALLOW_FILE: &str = "env-allowed.json";

/// `octapass.toml`: which environments `octapass run` and the shell hook load in this folder.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectFile {
    /// Environments by title, id, `vault/title` or `project:stage`, loaded in order.
    #[serde(default)]
    pub env: Vec<String>,
    /// A project whose shared variables, and `stage`'s, are loaded before `env`.
    pub project: Option<String>,
    pub stage: Option<String>,
    /// Look for the environments in this vault only.
    pub vault: Option<String>,
}

/// A project file found on disk, with the SHA-256 of its bytes (the allow list is keyed by it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoundProject {
    pub path: PathBuf,
    pub file: ProjectFile,
    pub sha256: String,
}

impl FoundProject {
    pub fn dir(&self) -> &Path {
        self.path.parent().unwrap_or(Path::new("/"))
    }
}

/// The project file in `start` or the closest parent that has one, looking no further up than the
/// repository root (a folder with `.git`) or the filesystem root.
pub fn find_project(start: &Path) -> Result<Option<FoundProject>> {
    let mut dir = Some(start);
    while let Some(current) = dir {
        let path = current.join(PROJECT_FILE);
        if path.is_file() {
            return read_project(&path).map(Some);
        }
        if current.join(".git").exists() {
            break;
        }
        dir = current.parent();
    }
    Ok(None)
}

pub fn read_project(path: &Path) -> Result<FoundProject> {
    let bytes = fs::read(path)
        .map_err(|error| CliError::usage(format!("Can't read {}: {error}", path.display())))?;
    let text = String::from_utf8_lossy(&bytes);
    let file: ProjectFile = toml::from_str(&text)
        .map_err(|error| CliError::usage(format!("{}: {}", path.display(), error.message())))?;
    Ok(FoundProject {
        path: path.to_owned(),
        file,
        sha256: hex(&Sha256::digest(&bytes)),
    })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ---------- The allow list ----------

/// Project files the user allowed the shell hook to load, by path and contents: a changed file
/// has to be allowed again, as with direnv.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct AllowList {
    #[serde(default)]
    pub allowed: Vec<Allowed>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Allowed {
    pub path: PathBuf,
    pub sha256: String,
}

impl AllowList {
    pub fn load(data_dir: &Path) -> Self {
        fs::read(data_dir.join(ALLOW_FILE))
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, data_dir: &Path) -> io::Result<()> {
        let text = serde_json::to_string_pretty(self).expect("allow lists serialize");
        crate::write_private(&data_dir.join(ALLOW_FILE), text.as_bytes())
    }

    pub fn allows(&self, project: &FoundProject) -> bool {
        self.allowed
            .iter()
            .any(|entry| entry.path == project.path && entry.sha256 == project.sha256)
    }

    pub fn allow(&mut self, project: &FoundProject) {
        self.deny(&project.path);
        self.allowed.push(Allowed {
            path: project.path.clone(),
            sha256: project.sha256.clone(),
        });
    }

    /// `true` when the file was on the list.
    pub fn deny(&mut self, path: &Path) -> bool {
        let before = self.allowed.len();
        self.allowed.retain(|entry| entry.path != path);
        before != self.allowed.len()
    }
}

// ---------- The shell hook ----------

/// What `octapass env hook <shell>` prints, for the shell's startup file.
pub fn hook_script(shell: Shell) -> &'static str {
    match shell {
        Shell::Zsh => {
            r#"# Octa Pass: load this folder's octapass.toml environments (see `octapass env allow`).
_octapass_hook() {
  trap -- '' SIGINT
  eval "$(command octapass env hook-env zsh)"
  trap - SIGINT
}
typeset -ag precmd_functions chpwd_functions
if (( ! ${precmd_functions[(I)_octapass_hook]} )); then
  precmd_functions=(_octapass_hook $precmd_functions)
fi
if (( ! ${chpwd_functions[(I)_octapass_hook]} )); then
  chpwd_functions=(_octapass_hook $chpwd_functions)
fi
"#
        }
        Shell::Bash => {
            r#"# Octa Pass: load this folder's octapass.toml environments (see `octapass env allow`).
_octapass_hook() {
  local previous_exit_status=$?
  trap -- '' SIGINT
  eval "$(command octapass env hook-env bash)"
  trap - SIGINT
  return $previous_exit_status
}
if [[ ";${PROMPT_COMMAND[*]:-};" != *";_octapass_hook;"* ]]; then
  PROMPT_COMMAND="_octapass_hook${PROMPT_COMMAND:+;$PROMPT_COMMAND}"
fi
"#
        }
        Shell::Fish => {
            r#"# Octa Pass: load this folder's octapass.toml environments (see `octapass env allow`).
function __octapass_hook --on-variable PWD --on-event fish_prompt
    command octapass env hook-env fish | source
end
"#
        }
        Shell::Powershell => {
            r#"# Octa Pass: load this folder's octapass.toml environments (see `octapass env allow`).
if (-not $global:OctaPassPrompt) {
  $global:OctaPassPrompt = $function:prompt
  function global:prompt {
    $hook = (& octapass env hook-env powershell) -join "`n"
    if ($hook) { Invoke-Expression $hook }
    & $global:OctaPassPrompt
  }
}
"#
        }
    }
}

/// What the hook loaded, so the next prompt knows whether to do anything and how to undo it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HookState {
    /// The project file's path and hash.
    pub path: PathBuf,
    pub sha256: String,
    /// `loaded`, or why not: `blocked` (not allowed), `locked`, `declined` (production).
    pub status: String,
    /// Each loaded variable's value from before, `None` when it wasn't set.
    #[serde(default)]
    pub previous: BTreeMap<String, Option<String>>,
}

impl HookState {
    pub fn from_env(value: Option<&str>) -> Option<Self> {
        serde_json::from_str(value?).ok()
    }

    pub fn is_for(&self, project: &FoundProject) -> bool {
        self.path == project.path && self.sha256 == project.sha256
    }
}

/// Shell commands that set and unset variables.
#[derive(Debug, Default)]
pub struct ShellScript {
    lines: Vec<String>,
}

impl ShellScript {
    pub fn set(&mut self, shell: Shell, key: &str, value: &str) {
        self.lines.push(match shell {
            Shell::Zsh | Shell::Bash => format!("export {key}={}", sh_quote(value)),
            Shell::Fish => format!("set -gx {key} {}", fish_quote(value)),
            Shell::Powershell => format!("$env:{key} = {}", ps_quote(value)),
        });
    }

    pub fn unset(&mut self, shell: Shell, key: &str) {
        self.lines.push(match shell {
            Shell::Zsh | Shell::Bash => format!("unset {key}"),
            Shell::Fish => format!("set -e {key}"),
            Shell::Powershell => format!("Remove-Item Env:{key} -ErrorAction SilentlyContinue"),
        });
    }

    /// Puts back what `state` replaced, and forgets the state.
    pub fn undo(&mut self, shell: Shell, state: &HookState) {
        for (key, previous) in &state.previous {
            match previous {
                Some(value) => self.set(shell, key, value),
                None => self.unset(shell, key),
            }
        }
        self.unset(shell, HOOK_STATE_ENV);
    }

    pub fn remember(&mut self, shell: Shell, state: &HookState) {
        let json = serde_json::to_string(state).expect("hook state serializes");
        self.set(shell, HOOK_STATE_ENV, &json);
    }

    pub fn text(&self) -> String {
        self.lines.iter().map(|line| format!("{line}\n")).collect()
    }
}

fn sh_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

/// Inside fish's single quotes only `\` and `'` are special.
fn fish_quote(value: &str) -> String {
    format!("'{}'", value.replace('\\', "\\\\").replace('\'', "\\'"))
}

fn ps_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

// ---------- inject ----------

/// A piece of an `inject` template: text as it is, or a reference to replace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Piece<'a> {
    Text(&'a str),
    Reference { text: &'a str, reference: String },
}

/// Splits a template at its references: `{{ octapass://vault/item/field }}` (any characters, so
/// names with spaces work), or a bare `octapass://vault/item/field` that ends at a space, a quote
/// or a bracket.
pub fn template_pieces(template: &str) -> Vec<Piece<'_>> {
    let mut pieces = Vec::new();
    let mut rest = template;
    while let Some(at) = rest.find(SCHEME) {
        let before = &rest[..at];
        let braced = before
            .trim_end_matches([' ', '\t'])
            .strip_suffix("{{")
            .map(|open| open.len());
        if let Some(open) = braced
            && let Some(close) = rest[at..].find("}}")
        {
            let inner = rest[at..at + close].trim_end();
            pieces.push(Piece::Text(&rest[..open]));
            pieces.push(Piece::Reference {
                text: &rest[open..at + close + 2],
                reference: inner.to_owned(),
            });
            rest = &rest[at + close + 2..];
            continue;
        }
        let end = rest[at..]
            .find(|c: char| c.is_whitespace() || "\"'`<>()[]{},;".contains(c))
            .map_or(rest.len(), |len| at + len);
        // A sentence's full stop isn't part of the reference.
        let end = at + rest[at..end].trim_end_matches(['.', ':']).len();
        pieces.push(Piece::Text(before));
        pieces.push(Piece::Reference {
            text: &rest[at..end],
            reference: rest[at..end].to_owned(),
        });
        rest = &rest[end..];
    }
    pieces.push(Piece::Text(rest));
    pieces.retain(|piece| !matches!(piece, Piece::Text("")));
    pieces
}

/// Checks a reference for `inject`, so a template with a typo fails before anything is written.
pub fn parse_template_reference(text: &str) -> Result<Reference> {
    crate::items::parse_reference(text)
}

// ---------- Files ----------

/// Writes a file readable only by the user, refusing to replace one unless `force`.
pub fn write_secret_file(path: &Path, bytes: &[u8], force: bool) -> Result<()> {
    if !force && path.exists() {
        return Err(CliError::usage(format!(
            "{} already exists. Pass --force to replace it.",
            path.display()
        )));
    }
    crate::write_private(path, bytes)
        .map_err(|error| CliError::other(format!("Can't write {}: {error}", path.display())))
}

/// Creates a new file readable only by the user; fails if it exists.
pub fn create_secret_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options.open(path)?;
    crate::restrict_to_owner(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn found(path: &str, sha256: &str) -> FoundProject {
        FoundProject {
            path: path.into(),
            file: ProjectFile::default(),
            sha256: sha256.into(),
        }
    }

    #[test]
    fn the_project_file_is_found_up_to_the_repository_root() {
        let root = tempfile::tempdir().unwrap();
        let repo = root.path().join("repo");
        let deep = repo.join("services/api/src");
        fs::create_dir_all(&deep).unwrap();
        fs::create_dir(repo.join(".git")).unwrap();
        assert_eq!(find_project(&deep).unwrap(), None);

        // Above the repository root it isn't looked for.
        fs::write(root.path().join(PROJECT_FILE), "env = [\"Outside\"]\n").unwrap();
        assert_eq!(find_project(&deep).unwrap(), None);

        fs::write(
            repo.join("services/api").join(PROJECT_FILE),
            "project = \"shop-api\"\nstage = \"development\"\nenv = [\"Personal/Shop API (dev)\"]\n",
        )
        .unwrap();
        let project = find_project(&deep).unwrap().unwrap();
        assert_eq!(project.dir(), repo.join("services/api"));
        assert_eq!(project.file.project.as_deref(), Some("shop-api"));
        assert_eq!(project.file.stage.as_deref(), Some("development"));
        assert_eq!(project.file.env, ["Personal/Shop API (dev)"]);
        assert_eq!(project.sha256.len(), 64);

        fs::write(repo.join(PROJECT_FILE), "envs = []\n").unwrap();
        let error = find_project(&repo).unwrap_err();
        assert!(error.message.contains("unknown field"), "{}", error.message);
    }

    #[test]
    fn the_allow_list_is_keyed_by_path_and_contents() {
        let dir = tempfile::tempdir().unwrap();
        let mut list = AllowList::load(dir.path());
        let project = found("/w/app/octapass.toml", "aaa");
        assert!(!list.allows(&project));
        list.allow(&project);
        list.allow(&project);
        assert_eq!(list.allowed.len(), 1);
        list.save(dir.path()).unwrap();
        let list = AllowList::load(dir.path());
        assert!(list.allows(&project));
        assert!(!list.allows(&found("/w/app/octapass.toml", "changed")));
        assert!(!list.allows(&found("/w/other/octapass.toml", "aaa")));
        let mut list = list;
        assert!(list.deny(&project.path));
        assert!(!list.deny(&project.path));
    }

    #[test]
    fn hooks_for_each_shell() {
        assert!(hook_script(Shell::Zsh).contains("precmd_functions"));
        assert!(hook_script(Shell::Zsh).contains("chpwd_functions"));
        assert!(hook_script(Shell::Bash).contains("PROMPT_COMMAND"));
        assert!(hook_script(Shell::Fish).contains("--on-variable PWD"));
        assert!(hook_script(Shell::Powershell).contains("function global:prompt"));
        for shell in [Shell::Zsh, Shell::Bash, Shell::Fish, Shell::Powershell] {
            assert!(hook_script(shell).contains("octapass env hook-env"));
        }
    }

    #[test]
    fn shell_scripts_quote_for_each_shell() {
        let value = "it's $HOME \\ \"x\"";
        let line = |shell| {
            let mut script = ShellScript::default();
            script.set(shell, "A", value);
            script.unset(shell, "B");
            script.text()
        };
        assert_eq!(
            line(Shell::Bash),
            "export A='it'\\''s $HOME \\ \"x\"'\nunset B\n"
        );
        assert_eq!(line(Shell::Zsh), line(Shell::Bash));
        assert_eq!(
            line(Shell::Fish),
            "set -gx A 'it\\'s $HOME \\\\ \"x\"'\nset -e B\n"
        );
        assert_eq!(
            line(Shell::Powershell),
            "$env:A = 'it''s $HOME \\ \"x\"'\nRemove-Item Env:B -ErrorAction SilentlyContinue\n"
        );
    }

    #[test]
    fn undo_puts_back_what_was_there() {
        let state = HookState {
            previous: BTreeMap::from([
                ("A".to_owned(), Some("before".to_owned())),
                ("B".to_owned(), None),
            ]),
            ..HookState::default()
        };
        let mut script = ShellScript::default();
        script.undo(Shell::Bash, &state);
        assert_eq!(
            script.text(),
            "export A='before'\nunset B\nunset OCTAPASS_ENV_STATE\n"
        );
        let json = serde_json::to_string(&state).unwrap();
        assert_eq!(HookState::from_env(Some(&json)), Some(state));
        assert_eq!(HookState::from_env(Some("not json")), None);
    }

    #[test]
    fn templates_split_at_references() {
        let template = "url: postgres://app:{{ octapass://Work/Postgres/password }}@db\nkey = \"octapass://Work/Stripe/key\"\nname: {{ octapass://Work/Stripe/api key }}.\nSee octapass://Work/Docs/url.\n";
        let refs: Vec<(&str, String)> = template_pieces(template)
            .into_iter()
            .filter_map(|piece| match piece {
                Piece::Reference { text, reference } => Some((text, reference)),
                Piece::Text(_) => None,
            })
            .collect();
        assert_eq!(
            refs,
            [
                (
                    "{{ octapass://Work/Postgres/password }}",
                    "octapass://Work/Postgres/password".to_owned()
                ),
                (
                    "octapass://Work/Stripe/key",
                    "octapass://Work/Stripe/key".to_owned()
                ),
                (
                    "{{ octapass://Work/Stripe/api key }}",
                    "octapass://Work/Stripe/api key".to_owned()
                ),
                (
                    "octapass://Work/Docs/url",
                    "octapass://Work/Docs/url".to_owned()
                ),
            ]
        );
        let text: String = template_pieces(template)
            .into_iter()
            .map(|piece| match piece {
                Piece::Text(text) => text.to_owned(),
                Piece::Reference { .. } => "<>".into(),
            })
            .collect();
        assert_eq!(
            text,
            "url: postgres://app:<>@db\nkey = \"<>\"\nname: <>.\nSee <>.\n"
        );
        assert_eq!(template_pieces("no refs"), [Piece::Text("no refs")]);
    }

    #[test]
    fn secret_files_are_private_and_not_replaced_without_force() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.env");
        write_secret_file(&path, b"A=1\n", false).unwrap();
        assert!(write_secret_file(&path, b"A=2\n", false).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"A=1\n");
        write_secret_file(&path, b"A=2\n", true).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"A=2\n");
        assert!(create_secret_file(&path, b"x").is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }
}
