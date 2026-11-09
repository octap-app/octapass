//! Environments on the phones (plan 16): `.env` files and variables kept in the vault. The rules
//! and the `.env` reader and writer are the core's; the choices the screens show are the web
//! vault's (`Environment.tsx`, `ItemsPage.tsx`).

use octapass_core::environment as core_env;

use crate::error::{ErrorCode, Result, VaultError};
use crate::items::ItemSummary;

/// One variable. Shown in the order saved; each name is used once.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct EnvironmentVariable {
    /// Letters, digits and `_`, not starting with a digit.
    pub key: String,
    /// Kept exactly as typed.
    pub value: String,
    /// Hidden until revealed, like a password. New variables are concealed.
    pub concealed: bool,
    pub note: Option<String>,
}

/// One app's `.env` file for one stage. `project` groups the stages of an app; a project's
/// environment without a stage is its shared set, loaded first and overridden by each stage.
#[derive(Debug, Clone, Default, PartialEq, Eq, uniffi::Record)]
pub struct EnvironmentDetails {
    pub project: Option<String>,
    /// How the project is shown, when it isn't the identifier itself.
    pub project_name: Option<String>,
    pub stage: Option<String>,
    pub variables: Vec<EnvironmentVariable>,
    pub notes: Option<String>,
}

fn variables_for_core(
    variables: &[EnvironmentVariable],
) -> Vec<octapass_core::item::EnvironmentVariable> {
    variables
        .iter()
        .map(|variable| octapass_core::item::EnvironmentVariable {
            concealed: variable.concealed,
            note: variable.note.clone(),
            ..octapass_core::item::EnvironmentVariable::new(
                variable.key.clone(),
                variable.value.clone(),
            )
        })
        .collect()
}

pub(crate) fn details_from_core(
    details: octapass_core::item::EnvironmentDetails,
) -> EnvironmentDetails {
    EnvironmentDetails {
        project: details.project,
        project_name: details.project_name,
        stage: details.stage,
        variables: details
            .variables
            .into_iter()
            .map(|variable| EnvironmentVariable {
                key: variable.key,
                value: variable.value,
                concealed: variable.concealed,
                note: variable.note,
            })
            .collect(),
        notes: details.notes,
    }
}

/// A new, concealed variable in the editor.
#[uniffi::export]
pub fn new_environment_variable() -> EnvironmentVariable {
    EnvironmentVariable {
        key: String::new(),
        value: String::new(),
        concealed: true,
        note: None,
    }
}

/// `variables` with a `.env` file's added, and how many the file had. A name already there keeps
/// its place, note and concealed flag and takes the new value; new names come last, concealed.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct DotenvMerge {
    pub variables: Vec<EnvironmentVariable>,
    pub count: u32,
}

/// Reads a pasted or picked `.env` file. A file it can't read fails with `invalidInput` and a
/// reason safe to show (`env.importFailed`): it names a line and a variable, never a value.
#[uniffi::export]
pub fn merge_dotenv(variables: Vec<EnvironmentVariable>, text: String) -> Result<DotenvMerge> {
    let parsed = core_env::parse(&text)
        .map_err(|error| VaultError::new(ErrorCode::InvalidInput, error.to_string()))?;
    let count = parsed.len() as u32;
    let mut merged = variables;
    for variable in parsed {
        match merged.iter_mut().find(|one| one.key == variable.key) {
            Some(existing) => existing.value = variable.value,
            None => merged.push(EnvironmentVariable {
                key: variable.key,
                value: variable.value,
                concealed: true,
                note: None,
            }),
        }
    }
    Ok(DotenvMerge {
        variables: merged,
        count,
    })
}

/// The `.env` text of an environment's variables, for copying or saving.
#[uniffi::export]
pub fn environment_dotenv(details: EnvironmentDetails) -> Result<String> {
    let variables = variables_for_core(&details.variables);
    core_env::write(
        variables
            .iter()
            .map(|variable| (variable.key.as_str(), variable.value.as_str())),
        core_env::EnvFormat::Dotenv,
    )
    .map_err(|error| VaultError::new(ErrorCode::InvalidInput, error.to_string()))
}

/// The file an environment saves to: its title with anything odd as `-`, and `.env`.
#[uniffi::export]
pub fn environment_file_name(title: String) -> String {
    let mut base = String::new();
    let mut gap = false;
    for c in title.chars() {
        if c.is_alphanumeric() || matches!(c, '.' | '_' | '-') {
            base.push(c);
            gap = false;
        } else if !gap {
            base.push('-');
            gap = true;
        }
    }
    let base = base.strip_prefix('-').unwrap_or(&base);
    let base = base.strip_suffix('-').unwrap_or(base);
    format!("{}.env", if base.is_empty() { "environment" } else { base })
}

/// The stage's name in the catalog (`env.stages.<name>`) when apps know it by name; a custom
/// stage shows as typed.
#[uniffi::export]
pub fn known_environment_stage(stage: String) -> Option<String> {
    let stage = stage.to_lowercase();
    [
        "development",
        "staging",
        "production",
        "testing",
        "preview",
        "local",
    ]
    .contains(&stage.as_str())
    .then_some(stage)
}

/// Production asks to be careful: the item view says so.
#[uniffi::export]
pub fn is_production_stage(stage: Option<String>) -> bool {
    stage.is_some_and(|stage| core_env::is_production(&stage))
}

/// The filters an environment list offers: each project and stage once, in code point order as
/// on the web.
#[derive(Debug, Clone, Default, PartialEq, Eq, uniffi::Record)]
pub struct EnvironmentChoices {
    pub projects: Vec<String>,
    pub stages: Vec<String>,
}

#[uniffi::export]
pub fn environment_choices(items: Vec<ItemSummary>) -> EnvironmentChoices {
    let collect = |pick: fn(&ItemSummary) -> Option<&String>| {
        let mut names: Vec<String> = items.iter().filter_map(pick).cloned().collect();
        names.sort();
        names.dedup();
        names
    };
    EnvironmentChoices {
        projects: collect(|item| item.project.as_ref()),
        stages: collect(|item| item.stage.as_ref()),
    }
}

/// Names other stages of this project have but this environment doesn't, each once. `items` are
/// the environments to compare with; `item_id` is this one's. Empty without a project.
#[uniffi::export]
pub fn missing_environment_keys(
    item_id: String,
    details: EnvironmentDetails,
    items: Vec<ItemSummary>,
) -> Vec<String> {
    let Some(project) = details.project.as_deref() else {
        return Vec::new();
    };
    let mut missing: Vec<String> = Vec::new();
    for other in items.iter().filter(|other| {
        other.id != item_id
            && other.project.as_deref() == Some(project)
            && other.stage != details.stage
    }) {
        for key in &other.variable_keys {
            if !details.variables.iter().any(|one| one.key == *key) && !missing.contains(key) {
                missing.push(key.clone());
            }
        }
    }
    missing
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::items::ItemType;

    fn variable(key: &str, value: &str) -> EnvironmentVariable {
        EnvironmentVariable {
            key: key.into(),
            value: value.into(),
            concealed: false,
            note: Some("kept".into()),
        }
    }

    fn summary(id: &str, project: Option<&str>, stage: Option<&str>, keys: &[&str]) -> ItemSummary {
        ItemSummary {
            id: id.into(),
            vault_id: "v".into(),
            item_type: ItemType::Environment,
            title: id.into(),
            subtitle: None,
            urls: Vec::new(),
            tags: Vec::new(),
            favorite: false,
            has_totp: false,
            has_passkey: false,
            attachment_count: 0,
            created_at: String::new(),
            updated_at: String::new(),
            deleted_at: None,
            site: None,
            icon_domain: None,
            project: project.map(str::to_owned),
            stage: stage.map(str::to_owned),
            variable_keys: keys.iter().map(|k| (*k).to_owned()).collect(),
            pinned: false,
            places: Vec::new(),
        }
    }

    #[test]
    fn a_pasted_file_merges_by_name() {
        let merged = merge_dotenv(
            vec![variable("A", "old"), variable("B", "keep")],
            "# comment\nA=new\nexport C=\"two\\nlines\"\n".into(),
        )
        .unwrap();
        assert_eq!(merged.count, 2);
        let names: Vec<&str> = merged.variables.iter().map(|v| v.key.as_str()).collect();
        assert_eq!(names, ["A", "B", "C"]);
        assert_eq!(merged.variables[0].value, "new");
        assert!(!merged.variables[0].concealed, "keeps its flag");
        assert_eq!(merged.variables[0].note.as_deref(), Some("kept"));
        assert_eq!(merged.variables[2].value, "two\nlines");
        assert!(merged.variables[2].concealed, "new variables are concealed");
    }

    #[test]
    fn an_unreadable_file_never_shows_a_value() {
        let error = merge_dotenv(Vec::new(), "A=\"s3cret".into()).unwrap_err();
        assert_eq!(error.code(), ErrorCode::InvalidInput);
        assert!(!error.to_string().contains("s3cret"));
    }

    #[test]
    fn the_env_text_reads_back() {
        let details = EnvironmentDetails {
            variables: vec![variable("A", "two words"), variable("B", "x\ny")],
            ..EnvironmentDetails::default()
        };
        let text = environment_dotenv(details.clone()).unwrap();
        let back = merge_dotenv(Vec::new(), text).unwrap();
        assert_eq!(back.variables[0].value, "two words");
        assert_eq!(back.variables[1].value, "x\ny");
    }

    #[test]
    fn file_names_and_stages() {
        assert_eq!(
            environment_file_name("Shop API (prod)".into()),
            "Shop-API-prod.env"
        );
        assert_eq!(environment_file_name(" ".into()), "environment.env");
        assert_eq!(
            known_environment_stage("Production".into()).as_deref(),
            Some("production")
        );
        assert_eq!(known_environment_stage("canary".into()), None);
        assert!(is_production_stage(Some("PROD".into())));
        assert!(!is_production_stage(Some("staging".into())));
        assert!(!is_production_stage(None));
    }

    #[test]
    fn choices_are_unique_and_sorted() {
        let choices = environment_choices(vec![
            summary("a", Some("web"), Some("staging"), &[]),
            summary("b", Some("api"), Some("production"), &[]),
            summary("c", Some("web"), None, &[]),
        ]);
        assert_eq!(choices.projects, ["api", "web"]);
        assert_eq!(choices.stages, ["production", "staging"]);
    }

    #[test]
    fn missing_keys_come_from_the_projects_other_stages() {
        let details = EnvironmentDetails {
            project: Some("shop".into()),
            stage: Some("staging".into()),
            variables: vec![variable("A", "1")],
            ..EnvironmentDetails::default()
        };
        let items = vec![
            summary("me", Some("shop"), Some("staging"), &["A"]),
            summary("p", Some("shop"), Some("production"), &["A", "B", "C"]),
            summary("d", Some("shop"), Some("development"), &["B"]),
            summary("x", Some("other"), Some("production"), &["Z"]),
        ];
        assert_eq!(
            missing_environment_keys("me".into(), details.clone(), items.clone()),
            ["B", "C"]
        );
        let no_project = EnvironmentDetails {
            project: None,
            ..details
        };
        assert!(missing_environment_keys("me".into(), no_project, items).is_empty());
    }
}
