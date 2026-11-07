//! `octapass env …`, `octapass inject`, and the environments `octapass run` loads (plan 16, §3).
//! Values are decrypted here on the device and handed only to the command, a file the user
//! asked for, or stdout.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};

use octapass_core::environment::{self, DiffKind, EnvFormat, EnvProblem};
use octapass_core::item::{EnvironmentDetails, EnvironmentVariable};
use octapass_desktop_vault::model::{Item, ItemDraft};
use serde_json::{Value, json};

use super::*;
use crate::cli::{EnvCommand, EnvFormatArg, Shell};
use crate::environments::{
    self as envs, AllowList, FoundProject, HookState, Piece, STAGE_ENV, ShellScript,
};

/// An environment item with its details read.
pub(crate) struct Env {
    pub item: Item,
    pub details: EnvironmentDetails,
    pub vault: String,
}

impl Env {
    fn title(&self) -> &str {
        self.item.title()
    }

    fn is_production(&self) -> bool {
        self.details
            .stage
            .as_deref()
            .is_some_and(environment::is_production)
    }
}

/// Environments to load, in order, and whether the user named each on the command line (an
/// implicit production stage asks first).
#[derive(Debug, Default)]
pub(crate) struct Plan {
    pub sources: Vec<Source>,
    pub vault: Option<String>,
}

#[derive(Debug)]
pub(crate) enum Source {
    Named {
        spec: String,
        explicit: bool,
    },
    Project {
        project: String,
        stage: Option<String>,
        explicit: bool,
    },
}

impl Plan {
    pub fn is_empty(&self) -> bool {
        self.sources.is_empty()
    }
}

fn read_details(item: &Item) -> Option<EnvironmentDetails> {
    serde_json::from_value(item.details.clone()).ok()
}

fn stage_rank(stage: Option<&str>) -> (usize, String) {
    match stage {
        None => (0, String::new()),
        Some(stage) => match environment::KNOWN_STAGES
            .iter()
            .position(|known| known.eq_ignore_ascii_case(stage))
        {
            Some(at) => (1 + at, String::new()),
            None => (100, stage.to_lowercase()),
        },
    }
}

fn env_error(error: &environment::EnvError) -> CliError {
    CliError::usage(error.to_string())
}

impl App {
    // ---------- Finding environments ----------

    /// Every environment not in the trash, in `vault_query` when given.
    fn environments(&self, opened: &Opened, vault_query: Option<&str>) -> Result<Vec<Env>> {
        let vaults = opened.vaults()?;
        let only = vault_query
            .map(|query| items::find_vault(&vaults, query).map(|vault| vault.id.clone()))
            .transpose()?;
        let mut out = Vec::new();
        for item in opened.live_items()? {
            if !items::is_environment(&item) || only.as_ref().is_some_and(|id| &item.vault_id != id)
            {
                continue;
            }
            let Some(details) = read_details(&item) else {
                continue;
            };
            out.push(Env {
                vault: items::vault_name(&vaults, &item.vault_id).to_owned(),
                item,
                details,
            });
        }
        out.sort_by(|a, b| {
            let project = |env: &Env| {
                (
                    env.details.project.is_none(),
                    env.details
                        .project
                        .clone()
                        .unwrap_or_default()
                        .to_lowercase(),
                )
            };
            project(a)
                .cmp(&project(b))
                .then_with(|| {
                    stage_rank(a.details.stage.as_deref())
                        .cmp(&stage_rank(b.details.stage.as_deref()))
                })
                .then_with(|| a.title().to_lowercase().cmp(&b.title().to_lowercase()))
                .then_with(|| a.item.id.cmp(&b.item.id))
        });
        Ok(out)
    }

    /// The one environment `spec` names: an id, a title, `vault/title`, or `project:stage`
    /// (`project:` alone is the project's shared set).
    fn find_env(&self, opened: &Opened, spec: &str, vault_query: Option<&str>) -> Result<Env> {
        let all = self.environments(opened, vault_query)?;
        let one = |mut matches: Vec<Env>, what: &str| -> Result<Option<Env>> {
            match matches.len() {
                0 => Ok(None),
                1 => Ok(matches.pop()),
                n => {
                    let ids: Vec<&str> = matches.iter().map(|env| env.item.id.as_str()).collect();
                    Err(CliError::new(
                        Exit::Ambiguous,
                        format!(
                            "{n} environments are {what}. Use an id instead: {}",
                            ids.join(", ")
                        ),
                    ))
                }
            }
        };
        let spec = spec.trim();
        let (by_id, rest): (Vec<Env>, Vec<Env>) =
            all.into_iter().partition(|env| env.item.id == spec);
        if let Some(env) = one(by_id, "that id")? {
            return Ok(env);
        }
        let (titled, rest): (Vec<Env>, Vec<Env>) = rest
            .into_iter()
            .partition(|env| env.title().eq_ignore_ascii_case(spec));
        if let Some(env) = one(titled, &format!("called \"{spec}\""))? {
            return Ok(env);
        }
        if let Some((vault, title)) = spec.split_once('/')
            && vault_query.is_none()
        {
            let vaults = opened.vaults()?;
            if let Ok(vault) = items::find_vault(&vaults, vault) {
                let (in_vault, _): (Vec<Env>, Vec<Env>) = rest.into_iter().partition(|env| {
                    env.item.vault_id == vault.id && env.title().eq_ignore_ascii_case(title.trim())
                });
                if let Some(env) = one(in_vault, &format!("called \"{spec}\""))? {
                    return Ok(env);
                }
            }
            return Err(CliError::not_found(format!(
                "No environment called \"{spec}\"."
            )));
        }
        if let Some((project, stage)) = spec.split_once(':') {
            let stage = Some(stage.trim()).filter(|stage| !stage.is_empty());
            let staged: Vec<Env> = rest
                .into_iter()
                .filter(|env| {
                    env.details
                        .project
                        .as_deref()
                        .is_some_and(|p| p.eq_ignore_ascii_case(project.trim()))
                        && match (&env.details.stage, stage) {
                            (None, None) => true,
                            (Some(have), Some(want)) => have.eq_ignore_ascii_case(want),
                            _ => false,
                        }
                })
                .collect();
            if let Some(env) = one(staged, spec)? {
                return Ok(env);
            }
        }
        Err(CliError::not_found(format!(
            "No environment called \"{spec}\"."
        )))
    }

    /// A project's shared set (if it has one) and then `stage`'s environment.
    fn project_envs(
        &self,
        opened: &Opened,
        project: &str,
        stage: Option<&str>,
        vault_query: Option<&str>,
    ) -> Result<Vec<Env>> {
        let has_project = self.environments(opened, vault_query)?.iter().any(|env| {
            env.details
                .project
                .as_deref()
                .is_some_and(|p| p.eq_ignore_ascii_case(project))
        });
        if !has_project {
            return Err(CliError::not_found(format!(
                "No environments in a project called \"{project}\"."
            )));
        }
        let mut out = Vec::new();
        match self.find_env(opened, &format!("{project}:"), vault_query) {
            Ok(shared) => out.push(shared),
            Err(error) if error.exit == Exit::NotFound => {}
            Err(error) => return Err(error),
        }
        if let Some(stage) = stage {
            out.push(
                self.find_env(opened, &format!("{project}:{stage}"), vault_query)
                    .map_err(|error| match error.exit {
                        Exit::NotFound => CliError::not_found(format!(
                            "The {project} project has no {stage} stage."
                        )),
                        _ => error,
                    })?,
            );
        }
        Ok(out)
    }

    /// `spec` as `run` loads it: `project:stage` is the shared set plus the stage.
    fn expand(&self, opened: &Opened, spec: &str, vault_query: Option<&str>) -> Result<Vec<Env>> {
        match self.find_env(opened, spec, vault_query) {
            Ok(env) if env.details.stage.is_some() && spec.contains(':') => {
                let project = env.details.project.clone().unwrap_or_default();
                self.project_envs(opened, &project, env.details.stage.as_deref(), vault_query)
            }
            Ok(env) => Ok(vec![env]),
            Err(error) => Err(error),
        }
    }

    /// What `octapass run` (or the shell hook) loads: the command line's `--env` and `--project`,
    /// or else the project file of this folder or a parent.
    pub(crate) fn plan(
        &mut self,
        env: Vec<String>,
        project: Option<String>,
        stage: Option<String>,
    ) -> Result<Plan> {
        let stage_flag = stage.is_some();
        let stage = stage.or_else(|| self.context.var(STAGE_ENV));
        if !env.is_empty() || project.is_some() {
            let mut sources = Vec::new();
            if let Some(project) = project {
                sources.push(Source::Project {
                    project,
                    stage,
                    explicit: stage_flag,
                });
            } else if stage_flag {
                return Err(CliError::usage(
                    "--stage needs --project, or an octapass.toml with a project.",
                ));
            }
            sources.extend(env.into_iter().map(|spec| Source::Named {
                spec,
                explicit: true,
            }));
            return Ok(Plan {
                sources,
                vault: None,
            });
        }
        let Some(found) = envs::find_project(&self.context.cwd)? else {
            if stage_flag {
                return Err(CliError::usage(
                    "--stage needs --project, or an octapass.toml with a project.",
                ));
            }
            return Ok(Plan::default());
        };
        Ok(Self::plan_for(&found, stage, stage_flag))
    }

    fn plan_for(found: &FoundProject, stage: Option<String>, stage_flag: bool) -> Plan {
        let mut sources = Vec::new();
        if let Some(project) = &found.file.project {
            sources.push(Source::Project {
                project: project.clone(),
                stage: stage.or_else(|| found.file.stage.clone()),
                explicit: stage_flag,
            });
        }
        sources.extend(found.file.env.iter().map(|spec| Source::Named {
            spec: spec.clone(),
            explicit: false,
        }));
        Plan {
            sources,
            vault: found.file.vault.clone(),
        }
    }

    /// The plan's environments, and the names of the production ones nobody asked for by name.
    fn load_plan(&self, opened: &Opened, plan: &Plan) -> Result<(Vec<Env>, Vec<String>)> {
        let mut loaded = Vec::new();
        let mut unasked = Vec::new();
        for source in &plan.sources {
            let (envs, explicit) = match source {
                Source::Named { spec, explicit } => {
                    (self.expand(opened, spec, plan.vault.as_deref())?, *explicit)
                }
                Source::Project {
                    project,
                    stage,
                    explicit,
                } => (
                    self.project_envs(opened, project, stage.as_deref(), plan.vault.as_deref())?,
                    *explicit,
                ),
            };
            for env in envs {
                if env.is_production() && !explicit {
                    unasked.push(env.title().to_owned());
                }
                loaded.push(env);
            }
        }
        Ok((loaded, unasked))
    }

    /// Loads the plan into `vars` (later environments win). Asks before production variables the
    /// user didn't name, unless `yes`.
    pub(crate) fn load_environments(
        &mut self,
        opened: &Opened,
        plan: &Plan,
        yes: bool,
    ) -> Result<Vec<EnvironmentVariable>> {
        let (loaded, unasked) = self.load_plan(opened, plan)?;
        if !unasked.is_empty() && !yes {
            self.confirm_production(&unasked)?;
        }
        Ok(environment::layer(
            loaded.iter().map(|env| env.details.variables.as_slice()),
        ))
    }

    fn confirm_production(&mut self, titles: &[String]) -> Result<()> {
        let names = titles.join(", ");
        if !self.context.terminal.interactive() {
            return Err(CliError::usage(format!(
                "This would run with production variables ({names}). Pass --stage production or --yes."
            )));
        }
        let answer = self
            .context
            .terminal
            .ask(&format!("Run with production variables ({names})? [y/N] "))
            .map_err(input_error)?;
        if matches!(answer.trim().to_lowercase().as_str(), "y" | "yes") {
            Ok(())
        } else {
            Err(CliError::other("Stopped: production wasn't confirmed."))
        }
    }

    // ---------- Saving ----------

    async fn save_env(
        &self,
        opened: &Opened,
        base: Option<&Item>,
        vault_id: String,
        title: &str,
        details: &EnvironmentDetails,
    ) -> Result<Item> {
        environment::validate_details(details).map_err(|error| env_error(&error))?;
        let mut overview = base.map_or_else(
            || json!({ "schemaVersion": 1, "type": "environment" }),
            |item| item.overview.clone(),
        );
        overview["title"] = json!(title);
        match environment::subtitle(details) {
            Some(subtitle) => overview["subtitle"] = json!(subtitle),
            None => {
                if let Some(map) = overview.as_object_mut() {
                    map.remove("subtitle");
                }
            }
        }
        let draft = ItemDraft {
            id: base.map(|item| item.id.clone()),
            vault_id,
            revision: base.map(|item| item.revision),
            overview,
            details: serde_json::to_value(details).expect("details serialize"),
        };
        Ok(opened.vault.save_item(draft).await?)
    }

    pub(crate) fn target_vault(
        &self,
        opened: &Opened,
        vault_query: Option<&str>,
    ) -> Result<String> {
        let vaults = opened.vaults()?;
        let vault = match vault_query {
            Some(query) => items::find_vault(&vaults, query)?,
            None => vaults
                .iter()
                .find(|vault| vault.vault_type == VaultType::Personal)
                .ok_or_else(|| CliError::not_found("No Personal vault. Pass --vault."))?,
        };
        if vault.role == VaultRole::Read {
            return Err(CliError::other(format!(
                "You can only read the {} vault, not change it.",
                vault.name
            )));
        }
        Ok(vault.id.clone())
    }

    fn new_details(project: Option<String>, stage: Option<String>) -> EnvironmentDetails {
        serde_json::from_value(json!({ "project": project, "stage": stage, "variables": [] }))
            .expect("empty environments parse")
    }

    // ---------- Commands ----------

    pub(crate) async fn env_command(&mut self, command: EnvCommand) -> Result<Option<i32>> {
        match command {
            EnvCommand::Hook { shell } => {
                let script = envs::hook_script(shell);
                self.context
                    .stdout
                    .write_all(script.as_bytes())
                    .map_err(output_error)?;
                Ok(None)
            }
            EnvCommand::Allow { path } => self.env_allow(path, true),
            EnvCommand::Deny { path } => self.env_allow(path, false),
            EnvCommand::HookEnv { shell } => self.hook_env(shell).await,
            command => {
                let opened = self.open(DEFAULT_IDLE)?;
                self.unlocked(&opened).await?;
                self.env_vault_command(&opened, command).await
            }
        }
    }

    async fn env_vault_command(
        &mut self,
        opened: &Opened,
        command: EnvCommand,
    ) -> Result<Option<i32>> {
        match command {
            EnvCommand::List { vault, project } => self.env_list(opened, vault, project),
            EnvCommand::Show { env, reveal } => self.env_show(opened, &env, reveal),
            EnvCommand::Set {
                env,
                variables,
                plain,
            } => self.env_set(opened, &env, variables, plain).await,
            EnvCommand::Unset { env, keys } => self.env_unset(opened, &env, keys).await,
            EnvCommand::Create {
                title,
                vault,
                project,
                stage,
            } => {
                let vault_id = self.target_vault(opened, vault.as_deref())?;
                let details = Self::new_details(project, stage);
                let item = self
                    .save_env(opened, None, vault_id, &title, &details)
                    .await?;
                self.saved(&item, "Created", 0)
            }
            EnvCommand::Import {
                file,
                into,
                new,
                vault,
                project,
                stage,
            } => {
                let text = fs::read_to_string(&file).map_err(|error| {
                    CliError::usage(format!("Can't read {}: {error}", file.display()))
                })?;
                let variables = environment::variables_from_dotenv(&text)
                    .map_err(|error| env_file::invalid(&file.display().to_string(), &error))?;
                let count = variables.len();
                let item = match (into, new) {
                    (Some(spec), _) => {
                        let mut env = self.find_env(opened, &spec, None)?;
                        environment::merge(&mut env.details.variables, variables);
                        let title = env.title().to_owned();
                        self.save_env(
                            opened,
                            Some(&env.item),
                            env.item.vault_id.clone(),
                            &title,
                            &env.details,
                        )
                        .await?
                    }
                    (None, Some(title)) => {
                        let vault_id = self.target_vault(opened, vault.as_deref())?;
                        let mut details = Self::new_details(project, stage);
                        details.variables = variables;
                        self.save_env(opened, None, vault_id, &title, &details)
                            .await?
                    }
                    (None, None) => return Err(CliError::usage("Pass --into or --new.")),
                };
                self.saved(&item, "Imported into", count)
            }
            EnvCommand::Export {
                env,
                format,
                output,
                force,
                keep_references,
            } => {
                let env = self.find_env(opened, &env, None)?;
                let mut variables = env.details.variables.clone();
                if !keep_references {
                    self.resolve_values(opened, &mut variables)?;
                }
                self.write_variables(&variables, format, output.as_deref(), force)
            }
            EnvCommand::Diff { names } => self.env_diff(opened, &names),
            EnvCommand::Hook { .. }
            | EnvCommand::Allow { .. }
            | EnvCommand::Deny { .. }
            | EnvCommand::HookEnv { .. } => unreachable!("handled without the vault"),
        }
    }

    fn saved(&mut self, item: &Item, verb: &str, count: usize) -> Result<Option<i32>> {
        if self.global.json {
            self.out_json(&json!({ "id": item.id, "title": item.title(), "variables": count }))?;
        } else if count > 0 {
            self.note(&format!(
                "{verb} \"{}\": {count} {}.",
                item.title(),
                plural(count, "variable")
            ));
        } else {
            self.note(&format!("{verb} \"{}\".", item.title()));
        }
        Ok(None)
    }

    fn env_list(
        &mut self,
        opened: &Opened,
        vault: Option<String>,
        project: Option<String>,
    ) -> Result<Option<i32>> {
        let envs: Vec<Env> = self
            .environments(opened, vault.as_deref())?
            .into_iter()
            .filter(|env| {
                project.as_deref().is_none_or(|want| {
                    env.details
                        .project
                        .as_deref()
                        .is_some_and(|p| p.eq_ignore_ascii_case(want))
                })
            })
            .collect();
        if self.global.json {
            let rows: Vec<Value> = envs
                .iter()
                .map(|env| {
                    let keys: Vec<&str> = env
                        .details
                        .variables
                        .iter()
                        .map(|var| var.key.as_str())
                        .collect();
                    json!({
                        "id": env.item.id,
                        "title": env.title(),
                        "vault": env.vault,
                        "project": env.details.project,
                        "projectName": env.details.project_name,
                        "stage": env.details.stage,
                        "keys": keys,
                    })
                })
                .collect();
            return self.out_json(&Value::Array(rows)).map(|()| None);
        }
        if envs.is_empty() {
            self.note("No environments. Create one with `octapass env create <title>`.");
            return Ok(None);
        }
        let mut current: Option<Option<String>> = None;
        let mut groups: Vec<(String, Vec<[String; 4]>)> = Vec::new();
        for env in &envs {
            if current.as_ref() != Some(&env.details.project) {
                current = Some(env.details.project.clone());
                let heading = match (&env.details.project, &env.details.project_name) {
                    (Some(id), Some(name)) if name != id => format!("{name} ({id})"),
                    (Some(id), _) => id.clone(),
                    (None, _) => "No project".into(),
                };
                groups.push((heading, Vec::new()));
            }
            let count = env.details.variables.len();
            let stage = match (&env.details.project, &env.details.stage) {
                (_, Some(stage)) => stage.clone(),
                (Some(_), None) => "(shared)".into(),
                (None, None) => String::new(),
            };
            groups.last_mut().expect("pushed above").1.push([
                stage,
                env.title().to_owned(),
                format!("{count} {}", plural(count, "variable")),
                env.vault.clone(),
            ]);
        }
        let all: Vec<[String; 4]> = groups.iter().flat_map(|(_, rows)| rows.clone()).collect();
        let lines = format_table(["STAGE", "TITLE", "VARIABLES", "VAULT"], &all);
        self.out(&format!("  {}", lines[0]))?;
        let mut at = 1;
        for (heading, rows) in &groups {
            self.out(heading)?;
            for _ in rows {
                self.out(&format!("  {}", lines[at]))?;
                at += 1;
            }
        }
        Ok(None)
    }

    fn env_show(&mut self, opened: &Opened, spec: &str, reveal: bool) -> Result<Option<i32>> {
        let env = self.find_env(opened, spec, None)?;
        let concealed = env.details.variables.iter().any(|var| var.concealed);
        if reveal && concealed && self.context.stdout_is_terminal {
            self.note("Warning: showing secrets in the terminal.");
        }
        let shown =
            |var: &EnvironmentVariable| (reveal || !var.concealed).then(|| var.value.clone());
        if self.global.json {
            let variables: Vec<Value> = env
                .details
                .variables
                .iter()
                .map(|var| {
                    json!({ "key": var.key, "value": shown(var), "concealed": var.concealed, "note": var.note })
                })
                .collect();
            return self
                .out_json(&json!({
                    "id": env.item.id,
                    "title": env.title(),
                    "vault": env.vault,
                    "project": env.details.project,
                    "projectName": env.details.project_name,
                    "stage": env.details.stage,
                    "variables": variables,
                    "notes": env.details.notes,
                }))
                .map(|()| None);
        }
        self.out(env.title())?;
        let mut about = vec![format!("Vault: {}", env.vault)];
        if let Some(project) = &env.details.project {
            about.push(format!("Project: {project}"));
        }
        about.push(format!(
            "Stage: {}",
            env.details
                .stage
                .as_deref()
                .unwrap_or(if env.details.project.is_some() {
                    "shared"
                } else {
                    "none"
                })
        ));
        self.out(&about.join("  "))?;
        if env.details.variables.is_empty() {
            self.note("No variables yet. Add some with `octapass env set`.");
            return Ok(None);
        }
        let rows: Vec<[String; 3]> = env
            .details
            .variables
            .iter()
            .map(|var| {
                [
                    var.key.clone(),
                    shown(var).map_or_else(
                        || "hidden (--reveal shows it)".into(),
                        |value| {
                            // One line per variable; a multi-line value shows its first line.
                            let mut lines = value.lines();
                            let first = lines.next().unwrap_or_default().to_owned();
                            if lines.next().is_some() {
                                format!("{first} …")
                            } else {
                                first
                            }
                        },
                    ),
                    var.note.clone().unwrap_or_default(),
                ]
            })
            .collect();
        for line in format_table(["KEY", "VALUE", "NOTE"], &rows) {
            self.out(&line)?;
        }
        Ok(None)
    }

    async fn env_set(
        &mut self,
        opened: &Opened,
        spec: &str,
        assignments: Vec<String>,
        plain: bool,
    ) -> Result<Option<i32>> {
        let mut env = self.find_env(opened, spec, None)?;
        let mut new = Vec::new();
        for assignment in assignments {
            let (key, value) = match assignment.split_once('=') {
                Some((key, value)) => (key.trim().to_owned(), value.to_owned()),
                None => {
                    let key = assignment.trim().to_owned();
                    let value = self.ask_value(&key)?;
                    (key, value)
                }
            };
            if !environment::valid_key(&key) {
                return Err(CliError::usage(format!(
                    "\"{key}\": {}",
                    EnvProblem::InvalidKey.message()
                )));
            }
            new.push(EnvironmentVariable::new(key, value));
        }
        let keys: Vec<String> = new.iter().map(|var| var.key.clone()).collect();
        for var in &mut new {
            var.concealed = !plain;
        }
        environment::merge(&mut env.details.variables, new);
        if plain {
            for var in &mut env.details.variables {
                if keys.contains(&var.key) {
                    var.concealed = false;
                }
            }
        }
        let title = env.title().to_owned();
        let vault_id = env.item.vault_id.clone();
        let item = self
            .save_env(opened, Some(&env.item), vault_id, &title, &env.details)
            .await?;
        if self.global.json {
            return self
                .out_json(&json!({ "id": item.id, "title": item.title(), "set": keys }))
                .map(|()| None);
        }
        self.note(&format!("Set {} in \"{}\".", keys.join(", "), item.title()));
        Ok(None)
    }

    /// A value typed without it showing, or the next line of stdin.
    fn ask_value(&mut self, key: &str) -> Result<String> {
        if self.context.terminal.interactive() && !self.global.password_stdin {
            return Ok(self
                .context
                .terminal
                .ask_hidden(&format!("{key}: "))
                .map_err(input_error)?
                .to_string());
        }
        let mut line = String::new();
        self.context
            .stdin
            .read_line(&mut line)
            .map_err(|error| CliError::usage(format!("Couldn't read stdin: {error}")))?;
        Ok(line.trim_end_matches(['\r', '\n']).to_owned())
    }

    async fn env_unset(
        &mut self,
        opened: &Opened,
        spec: &str,
        keys: Vec<String>,
    ) -> Result<Option<i32>> {
        let mut env = self.find_env(opened, spec, None)?;
        let missing: Vec<&str> = keys
            .iter()
            .filter(|key| !env.details.variables.iter().any(|var| &var.key == *key))
            .map(String::as_str)
            .collect();
        if !missing.is_empty() {
            return Err(CliError::not_found(format!(
                "\"{}\" has no {}.",
                env.title(),
                missing.join(", ")
            )));
        }
        env.details.variables.retain(|var| !keys.contains(&var.key));
        let title = env.title().to_owned();
        let vault_id = env.item.vault_id.clone();
        let item = self
            .save_env(opened, Some(&env.item), vault_id, &title, &env.details)
            .await?;
        if self.global.json {
            return self
                .out_json(&json!({ "id": item.id, "title": item.title(), "unset": keys }))
                .map(|()| None);
        }
        self.note(&format!(
            "Removed {} from \"{}\".",
            keys.join(", "),
            item.title()
        ));
        Ok(None)
    }

    fn env_diff(&mut self, opened: &Opened, names: &[String]) -> Result<Option<i32>> {
        let (first_name, second_name, first, second) = match names {
            [project, a, b] => (
                a.clone(),
                b.clone(),
                self.project_envs(opened, project, Some(a), None)?,
                self.project_envs(opened, project, Some(b), None)?,
            ),
            [a, b] => (
                a.clone(),
                b.clone(),
                self.expand(opened, a, None)?,
                self.expand(opened, b, None)?,
            ),
            _ => {
                return Err(CliError::usage(
                    "Name two environments, or a project and two stages.",
                ));
            }
        };
        let layered = |envs: &[Env]| {
            environment::layer(envs.iter().map(|env| env.details.variables.as_slice()))
        };
        let entries = environment::diff(&layered(&first), &layered(&second));
        if self.global.json {
            return self
                .out_json(&serde_json::to_value(&entries).expect("diffs serialize"))
                .map(|()| None);
        }
        if entries.is_empty() {
            self.note(&format!(
                "{first_name} and {second_name} have the same variables."
            ));
            return Ok(None);
        }
        let rows: Vec<[String; 2]> = entries
            .iter()
            .map(|entry| {
                let what = match entry.kind {
                    DiffKind::OnlyInFirst => format!("only in {first_name}"),
                    DiffKind::OnlyInSecond => format!("only in {second_name}"),
                    DiffKind::Different => "different values".into(),
                };
                [entry.key.clone(), what]
            })
            .collect();
        for line in format_table(["KEY", "DIFFERENCE"], &rows) {
            self.out(&line)?;
        }
        Ok(None)
    }

    /// Replaces values that are `octapass://` references with what they point to.
    pub(crate) fn resolve_values(
        &self,
        opened: &Opened,
        variables: &mut [EnvironmentVariable],
    ) -> Result<()> {
        for var in variables {
            if Reference::is_reference(&var.value) {
                let reference = items::parse_reference(&var.value).map_err(|error| {
                    CliError::new(error.exit, format!("{}: {}", var.key, error.message))
                })?;
                var.value = self
                    .resolve(opened, &reference)
                    .map_err(|error| {
                        CliError::new(error.exit, format!("{}: {}", var.key, error.message))
                    })?
                    .value;
            }
        }
        Ok(())
    }

    fn write_variables(
        &mut self,
        variables: &[EnvironmentVariable],
        format: EnvFormatArg,
        output: Option<&Path>,
        force: bool,
    ) -> Result<Option<i32>> {
        let format = match format {
            EnvFormatArg::Dotenv => EnvFormat::Dotenv,
            EnvFormatArg::Json => EnvFormat::Json,
            EnvFormatArg::Shell => EnvFormat::Shell,
            EnvFormatArg::Powershell => EnvFormat::Powershell,
            EnvFormatArg::Docker => EnvFormat::Docker,
        };
        let text = environment::write(
            variables
                .iter()
                .map(|var| (var.key.as_str(), var.value.as_str())),
            format,
        )
        .map_err(|error| env_error(&error))?;
        match output {
            Some(path) => {
                envs::write_secret_file(path, text.as_bytes(), force)?;
                self.note(&format!(
                    "Wrote {} {} to {}. It isn't encrypted: delete it when you're done.",
                    variables.len(),
                    plural(variables.len(), "variable"),
                    path.display()
                ));
            }
            None => {
                if self.context.stdout_is_terminal && !variables.is_empty() {
                    self.note(
                        "Warning: showing secrets in the terminal. Use --output to write a file.",
                    );
                }
                self.context
                    .stdout
                    .write_all(text.as_bytes())
                    .map_err(output_error)?;
            }
        }
        Ok(None)
    }

    fn env_allow(&mut self, path: Option<PathBuf>, allow: bool) -> Result<Option<i32>> {
        let start = path.unwrap_or_else(|| self.context.cwd.clone());
        let start = if start.is_relative() {
            self.context.cwd.join(start)
        } else {
            start
        };
        let found = if start.is_file() {
            envs::read_project(&start)?
        } else {
            envs::find_project(&start)?.ok_or_else(|| {
                CliError::not_found(format!(
                    "No {} in {} or the folders above it.",
                    envs::PROJECT_FILE,
                    start.display()
                ))
            })?
        };
        let dir = &self.context.data_dir;
        create_private_dir(dir)
            .map_err(|error| CliError::other(format!("Can't use {}: {error}", dir.display())))?;
        let mut list = AllowList::load(dir);
        if allow {
            list.allow(&found);
        } else {
            list.deny(&found.path);
        }
        list.save(dir)
            .map_err(|error| CliError::other(format!("Can't save the allow list: {error}")))?;
        self.note(&if allow {
            format!(
                "Allowed {}. The shell hook loads it while Octa Pass is unlocked, until the file changes.",
                found.path.display()
            )
        } else {
            format!("The shell hook no longer loads {}.", found.path.display())
        });
        Ok(None)
    }

    /// Whether the keyring session is open, without unlocking or extending it.
    fn session_open(&self) -> bool {
        self.open(DEFAULT_IDLE)
            .is_ok_and(|opened| Self::session_open_in(&opened))
    }

    fn session_open_in(opened: &Opened) -> bool {
        opened
            .account_id()
            .and_then(|account| opened.unlock.expires_at(&account))
            .is_some()
    }

    /// The shell hook, at each prompt: unloads the variables of a project the shell left (or that
    /// changed, or locked), loads the allowed project the shell is in, and prints nothing when
    /// nothing changed. Never asks for the master password.
    async fn hook_env(&mut self, shell: Shell) -> Result<Option<i32>> {
        let state = HookState::from_env(
            self.context
                .env
                .iter()
                .find(|(key, _)| key == envs::HOOK_STATE_ENV)
                .and_then(|(_, value)| value.to_str()),
        );
        let found = match envs::find_project(&self.context.cwd) {
            Ok(found) => found,
            Err(error) => {
                self.note(&format!("octapass: {}", error.message));
                None
            }
        };
        let mut script = ShellScript::default();
        // What the shell's variables are once the script has run so far.
        let mut view: BTreeMap<String, Option<String>> = BTreeMap::new();
        if let (Some(state), Some(found)) = (&state, &found)
            && state.is_for(found)
        {
            let open = self.session_open();
            match state.status.as_str() {
                "loaded" if open => return Ok(None),
                "loaded" => {
                    script.undo(shell, state);
                    let locked = HookState {
                        status: "locked".into(),
                        previous: BTreeMap::new(),
                        ..state.clone()
                    };
                    script.remember(shell, &locked);
                    self.note("octapass: locked, so this project's variables were unloaded.");
                    return self.print_script(&script);
                }
                "locked" if open => {}
                _ => return Ok(None),
            }
        }
        if let Some(state) = &state {
            script.undo(shell, state);
            view.extend(state.previous.clone());
        }
        if let Some(found) = &found {
            let state = self.hook_load(shell, found, &mut script, &view).await;
            script.remember(shell, &state);
        }
        self.print_script(&script)
    }

    fn print_script(&mut self, script: &ShellScript) -> Result<Option<i32>> {
        self.context
            .stdout
            .write_all(script.text().as_bytes())
            .map_err(output_error)?;
        Ok(None)
    }

    async fn hook_load(
        &mut self,
        shell: Shell,
        found: &FoundProject,
        script: &mut ShellScript,
        view: &BTreeMap<String, Option<String>>,
    ) -> HookState {
        let mut state = HookState {
            path: found.path.clone(),
            sha256: found.sha256.clone(),
            status: "blocked".into(),
            previous: BTreeMap::new(),
        };
        if !AllowList::load(&self.context.data_dir).allows(found) {
            self.note(&format!(
                "octapass: {} isn't allowed yet. Run `octapass env allow` to load it.",
                found.path.display()
            ));
            return state;
        }
        state.status = "locked".into();
        let Ok(opened) = self.open(DEFAULT_IDLE) else {
            return state;
        };
        if !Self::session_open_in(&opened) || opened.vault.unlock_with_device().await.is_err() {
            self.note("octapass: locked. Run `octapass unlock` to load this project's variables.");
            return state;
        }
        // Only when a project is entered, not at every prompt.
        if self.sync(&opened.vault).await.is_err() {
            return state;
        }
        let stage = self.context.var(STAGE_ENV);
        let plan = Self::plan_for(found, stage, false);
        let variables =
            match self
                .load_environments(&opened, &plan, false)
                .and_then(|mut variables| {
                    self.resolve_values(&opened, &mut variables)?;
                    Ok(variables)
                }) {
                Ok(variables) => variables,
                Err(error) => {
                    self.note(&format!("octapass: {}", error.message));
                    state.status = "declined".into();
                    return state;
                }
            };
        for var in &variables {
            let before = view.get(&var.key).cloned().unwrap_or_else(|| {
                self.context
                    .env
                    .iter()
                    .find(|(key, _)| key == var.key.as_str())
                    .and_then(|(_, value)| value.to_str().map(str::to_owned))
            });
            state.previous.insert(var.key.clone(), before);
            script.set(shell, &var.key, &var.value);
        }
        self.note(&format!(
            "octapass: loaded {} {} from {}.",
            variables.len(),
            plural(variables.len(), "variable"),
            found.path.display()
        ));
        state.status = "loaded".into();
        state
    }

    // ---------- inject ----------

    pub(crate) async fn inject(
        &mut self,
        input: Option<PathBuf>,
        output: Option<PathBuf>,
        force: bool,
    ) -> Result<Option<i32>> {
        let template = match &input {
            Some(path) => fs::read_to_string(path).map_err(|error| {
                CliError::usage(format!("Can't read {}: {error}", path.display()))
            })?,
            None => {
                let mut text = String::new();
                self.context
                    .stdin
                    .read_to_string(&mut text)
                    .map_err(|error| CliError::usage(format!("Couldn't read stdin: {error}")))?;
                text
            }
        };
        if let Some(path) = &output
            && !force
            && path.exists()
        {
            return Err(CliError::usage(format!(
                "{} already exists. Pass --force to replace it.",
                path.display()
            )));
        }
        let pieces = envs::template_pieces(&template);
        let mut references = Vec::new();
        for piece in &pieces {
            if let Piece::Reference { reference, .. } = piece {
                references.push(envs::parse_template_reference(reference)?);
            }
        }
        let mut values = Vec::new();
        if !references.is_empty() {
            let opened = self.open(DEFAULT_IDLE)?;
            self.unlocked(&opened).await?;
            for reference in &references {
                values.push(self.resolve(&opened, reference)?.value);
            }
        }
        let mut values = values.into_iter();
        let text: String = pieces
            .iter()
            .map(|piece| match piece {
                Piece::Text(text) => (*text).to_owned(),
                Piece::Reference { .. } => values.next().expect("one value per reference"),
            })
            .collect();
        match output {
            Some(path) => {
                envs::write_secret_file(&path, text.as_bytes(), true)?;
                self.note(&format!(
                    "Wrote {} with {} {} filled in.",
                    path.display(),
                    references.len(),
                    plural(references.len(), "reference")
                ));
            }
            None => {
                if self.context.stdout_is_terminal && !references.is_empty() {
                    self.note(
                        "Warning: showing secrets in the terminal. Use --output to write a file.",
                    );
                }
                self.context
                    .stdout
                    .write_all(text.as_bytes())
                    .map_err(output_error)?;
            }
        }
        Ok(None)
    }
}
