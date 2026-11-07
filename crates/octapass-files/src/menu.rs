//! The right-click menus: "Encrypt with Octa Pass" and "Decrypt with Octa Pass" in Finder (Quick
//! Actions), Explorer, Nautilus and Dolphin. All of it is per-user files or registry keys, written
//! here and removed here, and each entry only starts a program with the chosen paths: the app (so
//! that it can ask who to encrypt for, and unlock), or the CLI where there's no app.
//!
//! The menus themselves can only be seen on the system they're for, so these functions return
//! what they'd write, for tests on any system; [`install`] and [`remove`] do the writing.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::Serialize;

/// Written into every file, so [`remove`] only removes what it made.
const MARKER: &str = "Installed by Octa Pass";
const KDE_FILE: &str = "octapass.desktop";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Surface {
    Finder,
    Explorer,
    Nautilus,
    Dolphin,
}

impl Surface {
    pub fn name(self) -> &'static str {
        match self {
            Surface::Finder => "Finder",
            Surface::Explorer => "Explorer",
            Surface::Nautilus => "Nautilus",
            Surface::Dolphin => "Dolphin",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Language {
    English,
    Arabic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Encrypt,
    Decrypt,
}

impl Action {
    fn label(self, language: Language) -> &'static str {
        match (self, language) {
            (Action::Encrypt, Language::English) => "Encrypt with Octa Pass",
            (Action::Decrypt, Language::English) => "Decrypt with Octa Pass",
            (Action::Encrypt, Language::Arabic) => "تشفير باستخدام Octa Pass",
            (Action::Decrypt, Language::Arabic) => "فك التشفير باستخدام Octa Pass",
        }
    }

    fn id(self) -> &'static str {
        match self {
            Action::Encrypt => "Encrypt",
            Action::Decrypt => "Decrypt",
        }
    }
}

/// What a menu entry starts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Launcher {
    /// The desktop app: `<app> --files encrypt <paths>` hands the paths to its window.
    Desktop(PathBuf),
    /// The CLI, where there's no app: encrypts for yourself, and decrypts while a session is open,
    /// showing the result as a notification.
    Cli(PathBuf),
}

impl Launcher {
    fn program(&self) -> &Path {
        match self {
            Launcher::Desktop(path) | Launcher::Cli(path) => path,
        }
    }

    fn arguments(&self, action: Action) -> &'static [&'static str] {
        match (self, action) {
            (Launcher::Desktop(_), Action::Encrypt) => &["--files", "encrypt"],
            (Launcher::Desktop(_), Action::Decrypt) => &["--files", "decrypt"],
            (Launcher::Cli(_), Action::Encrypt) => &["encrypt", "--self", "--notify", "--"],
            (Launcher::Cli(_), Action::Decrypt) => &["decrypt", "--notify", "--"],
        }
    }
}

/// Where this user's menus live.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Locations {
    pub home: PathBuf,
    /// `XDG_DATA_HOME`, or `~/.local/share`.
    pub data: PathBuf,
}

impl Locations {
    pub fn under(home: &Path) -> Self {
        Self {
            data: home.join(".local/share"),
            home: home.to_owned(),
        }
    }
}

/// The menus this system has.
pub fn surfaces() -> &'static [Surface] {
    if cfg!(target_os = "macos") {
        &[Surface::Finder]
    } else if cfg!(windows) {
        &[Surface::Explorer]
    } else {
        &[Surface::Nautilus, Surface::Dolphin]
    }
}

/// One file to write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MenuFile {
    pub path: PathBuf,
    pub contents: String,
    pub executable: bool,
}

/// `'…'` for POSIX shells.
fn shell_quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', r"'\''"))
}

fn shell_command(launcher: &Launcher, action: Action) -> String {
    let mut parts = vec![shell_quote(&launcher.program().display().to_string())];
    parts.extend(launcher.arguments(action).iter().map(|part| (*part).to_owned()));
    parts.join(" ")
}

fn xml_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

// ---------- Finder ----------

fn workflow_name(action: Action) -> String {
    format!("{} with Octa Pass.workflow", action.id())
}

fn workflow_path(locations: &Locations, action: Action) -> PathBuf {
    locations
        .home
        .join("Library/Services")
        .join(workflow_name(action))
}

fn workflow_info(action: Action) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<!-- {MARKER} -->
<plist version="1.0">
<dict>
	<key>CFBundleName</key>
	<string>{name}</string>
	<key>NSServices</key>
	<array>
		<dict>
			<key>NSMenuItem</key>
			<dict>
				<key>default</key>
				<string>{name}</string>
			</dict>
			<key>NSMessage</key>
			<string>runWorkflowAsService</string>
			<key>NSRequiredContext</key>
			<dict>
				<key>NSApplicationIdentifier</key>
				<string>com.apple.finder</string>
			</dict>
			<key>NSSendFileTypes</key>
			<array>
				<string>public.item</string>
			</array>
		</dict>
	</array>
</dict>
</plist>
"#,
        name = action.label(Language::English),
    )
}

fn workflow_document(launcher: &Launcher, action: Action) -> String {
    let command = xml_escape(&format!("{} \"$@\"", shell_command(launcher, action)));
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<!-- {MARKER} -->
<plist version="1.0">
<dict>
	<key>AMApplicationBuild</key>
	<string>528</string>
	<key>AMApplicationVersion</key>
	<string>2.10</string>
	<key>AMDocumentVersion</key>
	<string>2</string>
	<key>actions</key>
	<array>
		<dict>
			<key>action</key>
			<dict>
				<key>AMAccepts</key>
				<dict>
					<key>Container</key>
					<string>List</string>
					<key>Optional</key>
					<true/>
					<key>Types</key>
					<array>
						<string>com.apple.cocoa.string</string>
					</array>
				</dict>
				<key>AMActionVersion</key>
				<string>2.0.3</string>
				<key>AMApplication</key>
				<array>
					<string>Automator</string>
				</array>
				<key>AMParameterProperties</key>
				<dict>
					<key>COMMAND_STRING</key>
					<dict/>
					<key>CheckedForUserDefaultShell</key>
					<dict/>
					<key>inputMethod</key>
					<dict/>
					<key>shell</key>
					<dict/>
					<key>source</key>
					<dict/>
				</dict>
				<key>AMProvides</key>
				<dict>
					<key>Container</key>
					<string>List</string>
					<key>Types</key>
					<array>
						<string>com.apple.cocoa.string</string>
					</array>
				</dict>
				<key>ActionBundlePath</key>
				<string>/System/Library/Automator/Run Shell Script.action</string>
				<key>ActionName</key>
				<string>Run Shell Script</string>
				<key>ActionParameters</key>
				<dict>
					<key>COMMAND_STRING</key>
					<string>{command}</string>
					<key>CheckedForUserDefaultShell</key>
					<true/>
					<key>inputMethod</key>
					<integer>1</integer>
					<key>shell</key>
					<string>/bin/bash</string>
					<key>source</key>
					<string></string>
				</dict>
				<key>BundleIdentifier</key>
				<string>com.apple.RunShellScript</string>
				<key>CFBundleVersion</key>
				<string>2.0.3</string>
				<key>CanShowSelectedItemsWhenRun</key>
				<false/>
				<key>CanShowWhenRun</key>
				<true/>
				<key>Category</key>
				<array>
					<string>AMCategoryUtilities</string>
				</array>
				<key>Class Name</key>
				<string>RunShellScriptAction</string>
				<key>InputUUID</key>
				<string>1E3C2F5A-7B42-4C7E-9A11-5D0E5A6B7C01</string>
				<key>Keywords</key>
				<array>
					<string>Shell</string>
					<string>Script</string>
				</array>
				<key>OutputUUID</key>
				<string>1E3C2F5A-7B42-4C7E-9A11-5D0E5A6B7C02</string>
				<key>UUID</key>
				<string>1E3C2F5A-7B42-4C7E-9A11-5D0E5A6B7C03</string>
				<key>UnlocalizedApplications</key>
				<array>
					<string>Automator</string>
				</array>
				<key>arguments</key>
				<dict/>
				<key>isViewVisible</key>
				<integer>1</integer>
				<key>location</key>
				<string>309.500000:253.000000</string>
				<key>nibPath</key>
				<string>/System/Library/Automator/Run Shell Script.action/Contents/Resources/Base.lproj/main.nib</string>
			</dict>
			<key>isViewVisible</key>
			<integer>1</integer>
		</dict>
	</array>
	<key>connectors</key>
	<dict/>
	<key>workflowMetaData</key>
	<dict>
		<key>applicationBundleIDsByPath</key>
		<dict/>
		<key>applicationPaths</key>
		<array/>
		<key>inputTypeIdentifier</key>
		<string>com.apple.Automator.fileSystemObject</string>
		<key>outputTypeIdentifier</key>
		<string>com.apple.Automator.nothing</string>
		<key>presentationMode</key>
		<integer>15</integer>
		<key>processesInput</key>
		<false/>
		<key>serviceApplicationBundleID</key>
		<string>com.apple.finder</string>
		<key>serviceApplicationPath</key>
		<string>/System/Library/CoreServices/Finder.app</string>
		<key>serviceInputTypeIdentifier</key>
		<string>com.apple.Automator.fileSystemObject</string>
		<key>serviceOutputTypeIdentifier</key>
		<string>com.apple.Automator.nothing</string>
		<key>serviceProcessesInput</key>
		<false/>
		<key>systemImageName</key>
		<string>NSTouchBarDocuments</string>
		<key>useAutomaticInputType</key>
		<false/>
		<key>workflowTypeIdentifier</key>
		<string>com.apple.Automator.servicesMenu</string>
	</dict>
</dict>
</plist>
"#
    )
}

fn finder_files(launcher: &Launcher, locations: &Locations) -> Vec<MenuFile> {
    [Action::Encrypt, Action::Decrypt]
        .into_iter()
        .flat_map(|action| {
            let root = workflow_path(locations, action);
            [
                MenuFile {
                    path: root.join("Contents/Info.plist"),
                    contents: workflow_info(action),
                    executable: false,
                },
                MenuFile {
                    path: root.join("Contents/document.wflow"),
                    contents: workflow_document(launcher, action),
                    executable: false,
                },
            ]
        })
        .collect()
}

// ---------- Nautilus ----------

fn nautilus_folder(locations: &Locations) -> PathBuf {
    locations.data.join("nautilus/scripts")
}

fn nautilus_files(launcher: &Launcher, locations: &Locations, language: Language) -> Vec<MenuFile> {
    [Action::Encrypt, Action::Decrypt]
        .into_iter()
        .map(|action| MenuFile {
            path: nautilus_folder(locations).join(action.label(language)),
            // Nautilus gives the selection as one variable, a path per line. Splitting on newlines
            // only, with globbing off, keeps spaces and asterisks in names intact.
            contents: format!(
                "#!/bin/sh\n# {MARKER}.\nset -f\nIFS='\n'\nexec {} $NAUTILUS_SCRIPT_SELECTED_FILE_PATHS\n",
                shell_command(launcher, action)
            ),
            executable: true,
        })
        .collect()
}

// ---------- Dolphin ----------

fn dolphin_path(locations: &Locations) -> PathBuf {
    locations.data.join("kio/servicemenus").join(KDE_FILE)
}

/// A value for `Exec=`, quoted as the Desktop Entry spec asks.
fn desktop_quote(text: &str) -> String {
    let escaped = text
        .replace('\\', r"\\\\")
        .replace('"', "\\\\\"")
        .replace('`', "\\\\`")
        .replace('$', "\\\\$")
        .replace('%', "%%");
    format!("\"{escaped}\"")
}

fn dolphin_files(launcher: &Launcher, locations: &Locations) -> Vec<MenuFile> {
    let mut contents = format!(
        "# {MARKER}.\n[Desktop Entry]\nType=Service\nMimeType=all/all;\nActions=octapassEncrypt;octapassDecrypt;\nX-KDE-Priority=TopLevel\n"
    );
    for action in [Action::Encrypt, Action::Decrypt] {
        let mut command = vec![desktop_quote(&launcher.program().display().to_string())];
        command.extend(launcher.arguments(action).iter().map(|part| (*part).to_owned()));
        command.push("%F".into());
        contents.push_str(&format!(
            "\n[Desktop Action octapass{id}]\nName={en}\nName[ar]={ar}\nIcon=octapass\nExec={exec}\n",
            id = action.id(),
            en = action.label(Language::English),
            ar = action.label(Language::Arabic),
            exec = command.join(" "),
        ));
    }
    vec![MenuFile {
        path: dolphin_path(locations),
        contents,
        // KDE Frameworks 6 only runs service menus marked executable.
        executable: true,
    }]
}

// ---------- Explorer ----------

/// One value under `HKEY_CURRENT_USER`. `name` is `None` for a key's default value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryValue {
    pub key: String,
    pub name: Option<&'static str>,
    pub value: String,
}

const REGISTRY_ROOTS: [(&str, Action); 3] = [
    (r"Software\Classes\*\shell\OctaPass.Encrypt", Action::Encrypt),
    (
        r"Software\Classes\Directory\shell\OctaPass.Encrypt",
        Action::Encrypt,
    ),
    (
        r"Software\Classes\SystemFileAssociations\.age\shell\OctaPass.Decrypt",
        Action::Decrypt,
    ),
];

/// A path or argument quoted for a Windows command line.
fn windows_quote(text: &str) -> String {
    format!("\"{}\"", text.replace('"', "\\\""))
}

/// The registry values of the Explorer menu.
pub fn explorer_values(launcher: &Launcher, language: Language) -> Vec<RegistryValue> {
    let program = launcher.program().display().to_string();
    let mut values = Vec::new();
    for (key, action) in REGISTRY_ROOTS {
        let mut command = vec![windows_quote(&program)];
        command.extend(launcher.arguments(action).iter().map(|part| (*part).to_owned()));
        command.push("\"%1\"".to_owned());
        values.push(RegistryValue {
            key: key.to_owned(),
            name: None,
            value: action.label(language).to_owned(),
        });
        values.push(RegistryValue {
            key: key.to_owned(),
            name: Some("Icon"),
            value: program.clone(),
        });
        values.push(RegistryValue {
            key: format!(r"{key}\command"),
            name: None,
            value: command.join(" "),
        });
    }
    values
}

/// `reg.exe` argument lists that write those values.
pub fn explorer_commands(values: &[RegistryValue]) -> Vec<Vec<String>> {
    values
        .iter()
        .map(|value| {
            let mut arguments = vec!["add".to_owned(), format!(r"HKCU\{}", value.key)];
            match value.name {
                Some(name) => arguments.extend(["/v".to_owned(), name.to_owned()]),
                None => arguments.push("/ve".to_owned()),
            }
            arguments.extend(["/d".to_owned(), value.value.clone(), "/f".to_owned()]);
            arguments
        })
        .collect()
}

#[cfg(windows)]
fn run_reg(arguments: &[String]) -> io::Result<bool> {
    let status = std::process::Command::new("reg.exe")
        .args(arguments)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()?;
    Ok(status.success())
}

// ---------- Install ----------

/// What this system's menus need written.
pub fn planned_files(
    surface: Surface,
    launcher: &Launcher,
    locations: &Locations,
    language: Language,
) -> Vec<MenuFile> {
    match surface {
        Surface::Finder => finder_files(launcher, locations),
        Surface::Nautilus => nautilus_files(launcher, locations, language),
        Surface::Dolphin => dolphin_files(launcher, locations),
        Surface::Explorer => Vec::new(),
    }
}

fn write_menu_file(file: &MenuFile) -> io::Result<()> {
    if let Some(parent) = file.path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&file.path, &file.contents)?;
    #[cfg(unix)]
    if file.executable {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&file.path, fs::Permissions::from_mode(0o755))?;
    }
    Ok(())
}

/// Adds the menus to `surfaces`.
pub fn install(
    surfaces: &[Surface],
    launcher: &Launcher,
    locations: &Locations,
    language: Language,
) -> io::Result<()> {
    for surface in surfaces {
        for file in planned_files(*surface, launcher, locations, language) {
            write_menu_file(&file)?;
        }
        #[cfg(windows)]
        if *surface == Surface::Explorer {
            for arguments in explorer_commands(&explorer_values(launcher, language)) {
                if !run_reg(&arguments)? {
                    return Err(io::Error::other("reg.exe refused the Explorer menu"));
                }
            }
        }
    }
    Ok(())
}

fn ours(path: &Path) -> bool {
    fs::read_to_string(path).is_ok_and(|text| text.contains(MARKER))
}

fn installed_paths(surface: Surface, locations: &Locations) -> Vec<PathBuf> {
    match surface {
        Surface::Finder => [Action::Encrypt, Action::Decrypt]
            .into_iter()
            .map(|action| workflow_path(locations, action).join("Contents/document.wflow"))
            .filter(|path| ours(path))
            .collect(),
        Surface::Nautilus => [Language::English, Language::Arabic]
            .into_iter()
            .flat_map(|language| {
                [Action::Encrypt, Action::Decrypt]
                    .map(|action| nautilus_folder(locations).join(action.label(language)))
            })
            .filter(|path| ours(path))
            .collect(),
        Surface::Dolphin => Some(dolphin_path(locations))
            .filter(|path| ours(path))
            .into_iter()
            .collect(),
        Surface::Explorer => Vec::new(),
    }
}

/// Whether a surface's menu is there.
pub fn installed(surface: Surface, locations: &Locations) -> bool {
    #[cfg(windows)]
    if surface == Surface::Explorer {
        return std::process::Command::new("reg.exe")
            .args(["query", &format!(r"HKCU\{}", REGISTRY_ROOTS[0].0)])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|status| status.success());
    }
    !installed_paths(surface, locations).is_empty()
}

/// Removes the menus from `surfaces`: only files this module wrote.
pub fn remove(surfaces: &[Surface], locations: &Locations) -> io::Result<()> {
    for surface in surfaces {
        for path in installed_paths(*surface, locations) {
            match surface {
                Surface::Finder => {
                    if let Some(bundle) = path.parent().and_then(Path::parent) {
                        fs::remove_dir_all(bundle)?;
                    }
                }
                _ => fs::remove_file(path)?,
            }
        }
        #[cfg(windows)]
        if *surface == Surface::Explorer {
            for (key, _) in REGISTRY_ROOTS {
                let _ = run_reg(&[
                    "delete".to_owned(),
                    format!(r"HKCU\{key}"),
                    "/f".to_owned(),
                ]);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app() -> Launcher {
        Launcher::Desktop(PathBuf::from("/Applications/Octa Pass.app/Contents/MacOS/it's"))
    }

    #[test]
    fn nautilus_scripts_keep_spaces_and_globs_in_names() {
        let locations = Locations::under(Path::new("/home/u"));
        let files = planned_files(Surface::Nautilus, &app(), &locations, Language::English);
        assert_eq!(files.len(), 2);
        assert!(files[0].executable);
        assert_eq!(
            files[0].path,
            Path::new("/home/u/.local/share/nautilus/scripts/Encrypt with Octa Pass")
        );
        assert!(files[0].contents.contains("set -f\nIFS='\n'\n"));
        assert!(files[0].contents.contains(r"'/Applications/Octa Pass.app/Contents/MacOS/it'\''s' --files encrypt $NAUTILUS_SCRIPT_SELECTED_FILE_PATHS"));
        let arabic = planned_files(Surface::Nautilus, &app(), &locations, Language::Arabic);
        assert!(arabic[0].path.ends_with("تشفير باستخدام Octa Pass"));
    }

    #[cfg(unix)]
    #[test]
    fn a_nautilus_script_really_splits_like_that() {
        // Runs the script's shell lines with `printf` in the program's place.
        let dir = tempfile::tempdir().unwrap();
        let printer = dir.path().join("print args");
        fs::write(&printer, "#!/bin/sh\nfor a in \"$@\"; do echo \"[$a]\"; done\n").unwrap();
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&printer, fs::Permissions::from_mode(0o755)).unwrap();
        let locations = Locations::under(dir.path());
        let files = planned_files(
            Surface::Nautilus,
            &Launcher::Desktop(printer),
            &locations,
            Language::English,
        );
        write_menu_file(&files[0]).unwrap();
        let output = std::process::Command::new(&files[0].path)
            .env(
                "NAUTILUS_SCRIPT_SELECTED_FILE_PATHS",
                "/tmp/a b.txt\n/tmp/*.c\n",
            )
            .output()
            .unwrap();
        assert_eq!(
            String::from_utf8(output.stdout).unwrap(),
            "[--files]\n[encrypt]\n[/tmp/a b.txt]\n[/tmp/*.c]\n"
        );
    }

    #[test]
    fn dolphin_gets_one_executable_service_menu_in_both_languages() {
        let locations = Locations::under(Path::new("/home/u"));
        let files = planned_files(Surface::Dolphin, &app(), &locations, Language::English);
        assert_eq!(files.len(), 1);
        assert!(files[0].executable);
        let text = &files[0].contents;
        assert!(text.contains("Actions=octapassEncrypt;octapassDecrypt;"));
        assert!(text.contains("Name[ar]=تشفير باستخدام Octa Pass"));
        assert!(text.contains("--files decrypt %F"));
        assert_eq!(
            files[0].path,
            Path::new("/home/u/.local/share/kio/servicemenus/octapass.desktop")
        );
        // Exec= escaping per the Desktop Entry spec.
        assert_eq!(desktop_quote("/a b/$x"), r#""/a b/\\$x""#);
    }

    #[test]
    fn finder_gets_two_quick_actions_that_pass_arguments() {
        let locations = Locations::under(Path::new("/Users/u"));
        let files = planned_files(Surface::Finder, &app(), &locations, Language::English);
        assert_eq!(files.len(), 4);
        assert!(files[0].path.ends_with(
            "Library/Services/Encrypt with Octa Pass.workflow/Contents/Info.plist"
        ));
        assert!(files[1].contents.contains("--files encrypt &quot;$@&quot;") || files[1].contents.contains("--files encrypt \"$@\""));
    }

    #[test]
    fn the_cli_launcher_encrypts_for_yourself_and_notifies() {
        let cli = Launcher::Cli(PathBuf::from("/usr/local/bin/octapass"));
        assert_eq!(
            cli.arguments(Action::Encrypt),
            ["encrypt", "--self", "--notify", "--"]
        );
        let locations = Locations::under(Path::new("/home/u"));
        let files = planned_files(Surface::Dolphin, &cli, &locations, Language::English);
        assert!(files[0].contents.contains("decrypt --notify -- %F"));
    }

    #[test]
    fn explorer_values_cover_files_folders_and_age_files() {
        let launcher = Launcher::Desktop(PathBuf::from(r"C:\Program Files\Octa Pass\octapass.exe"));
        let values = explorer_values(&launcher, Language::English);
        assert_eq!(values.len(), 9);
        assert_eq!(values[0].value, "Encrypt with Octa Pass");
        assert_eq!(values[1].name, Some("Icon"));
        assert_eq!(
            values[2].key,
            r"Software\Classes\*\shell\OctaPass.Encrypt\command"
        );
        assert_eq!(
            values[2].value,
            r#""C:\Program Files\Octa Pass\octapass.exe" --files encrypt "%1""#
        );
        assert!(values[6].key.contains(r"SystemFileAssociations\.age"));
        let commands = explorer_commands(&values);
        assert_eq!(commands[0][..3], ["add".to_owned(), format!(r"HKCU\{}", values[0].key), "/ve".to_owned()]);
        assert_eq!(commands[1][2..4], ["/v".to_owned(), "Icon".to_owned()]);
    }

    #[test]
    fn install_status_remove() {
        let dir = tempfile::tempdir().unwrap();
        let locations = Locations::under(dir.path());
        let surfaces = [Surface::Finder, Surface::Nautilus, Surface::Dolphin];
        for surface in surfaces {
            assert!(!installed(surface, &locations));
        }
        install(&surfaces, &app(), &locations, Language::English).unwrap();
        for surface in surfaces {
            assert!(installed(surface, &locations), "{surface:?}");
        }
        // Not ours, so it stays.
        let other = nautilus_folder(&locations).join("Someone else's script");
        fs::write(&other, "#!/bin/sh\n").unwrap();
        remove(&surfaces, &locations).unwrap();
        for surface in surfaces {
            assert!(!installed(surface, &locations), "{surface:?}");
        }
        assert!(other.exists());
        assert!(!workflow_path(&locations, Action::Encrypt).exists());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn workflow_files_are_valid_property_lists() {
        let dir = tempfile::tempdir().unwrap();
        let locations = Locations::under(dir.path());
        install(&[Surface::Finder], &app(), &locations, Language::English).unwrap();
        for file in planned_files(Surface::Finder, &app(), &locations, Language::English) {
            let status = std::process::Command::new("plutil")
                .arg("-lint")
                .arg(&file.path)
                .stdout(std::process::Stdio::null())
                .status()
                .unwrap();
            assert!(status.success(), "{}", file.path.display());
        }
    }
}
