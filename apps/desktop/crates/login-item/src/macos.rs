//! macOS: a launch agent, `~/Library/LaunchAgents/app.octap.desktop.login.plist`, that runs the
//! app's executable with `--hidden` when the person logs in. launchd reads the folder at login, so
//! writing or removing the file is all it takes. `AssociatedBundleIdentifiers` makes System Settings
//! list it under the app's name in Login Items → Allow in the Background, where it can be turned off
//! too (that switch isn't readable by apps, so it isn't reflected here).

use std::io;
use std::path::{Path, PathBuf};

use crate::{HIDDEN_ARG, LoginItem, Registered, read_file, remove_file, write_file};

/// The launch agent's label and file name. Not the bundle identifier itself: launchd names the app's
/// own job after that.
pub const LABEL: &str = "app.octap.desktop.login";
/// The app's bundle identifier, which owns the agent in System Settings.
pub const BUNDLE_ID: &str = "app.octap.desktop";

/// The launch agent's file.
pub struct LaunchAgent {
    path: PathBuf,
}

impl LaunchAgent {
    pub fn for_user(home: &Path) -> Self {
        Self::at(
            home.join("Library")
                .join("LaunchAgents")
                .join(format!("{LABEL}.plist")),
        )
    }

    pub fn at(path: PathBuf) -> Self {
        Self { path }
    }
}

impl LoginItem for LaunchAgent {
    fn registered(&self) -> io::Result<Option<Registered>> {
        Ok(read_file(&self.path)?.and_then(|text| parse(&text)))
    }

    fn register(&self, program: &Path) -> io::Result<()> {
        write_file(&self.path, &plist(program))
    }

    fn unregister(&self) -> io::Result<()> {
        remove_file(&self.path)
    }
}

/// The launch agent: run `program --hidden` once at login, only in the graphical session.
pub fn plist(program: &Path) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>{LABEL}</string>
	<key>AssociatedBundleIdentifiers</key>
	<string>{BUNDLE_ID}</string>
	<key>ProgramArguments</key>
	<array>
		<string>{}</string>
		<string>{HIDDEN_ARG}</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>LimitLoadToSessionType</key>
	<string>Aqua</string>
	<key>ProcessType</key>
	<string>Interactive</string>
</dict>
</plist>
"#,
        escape(&program.to_string_lossy())
    )
}

/// The program a launch agent runs, and whether launchd is told to skip it (`Disabled`).
pub fn parse(text: &str) -> Option<Registered> {
    let after_key = &text[text.find("<key>ProgramArguments</key>")?..];
    let array = &after_key[after_key.find("<array>")?..];
    let start = array.find("<string>")? + "<string>".len();
    let end = start + array[start..].find("</string>")?;
    let disabled = text.find("<key>Disabled</key>").is_some_and(|at| {
        text[at..]
            .trim_start_matches("<key>Disabled</key>")
            .trim_start()
            .starts_with("<true/>")
    });
    Some(Registered {
        program: PathBuf::from(unescape(&array[start..end])),
        enabled: !disabled,
    })
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn unescape(text: &str) -> String {
    text.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::is_on;

    const PROGRAM: &str = "/Applications/Octa Pass.app/Contents/MacOS/octapass-desktop";

    #[test]
    fn the_agent_runs_the_app_hidden_once_at_login() {
        let text = plist(Path::new(PROGRAM));
        assert!(text.contains(&format!(
            "<string>{PROGRAM}</string>\n\t\t<string>--hidden</string>"
        )));
        assert!(text.contains("<key>RunAtLoad</key>\n\t<true/>"));
        assert!(text.contains("<string>app.octap.desktop.login</string>"));
        assert!(text.contains("<string>Aqua</string>"));
        assert!(!text.contains("KeepAlive"));
    }

    #[test]
    fn reads_back_what_it_wrote_with_awkward_paths() {
        let program = Path::new(
            "/Users/ada/Apps & <Tools>/\"Open\" Pass.app/Contents/MacOS/octapass-desktop",
        );
        assert_eq!(
            parse(&plist(program)),
            Some(Registered {
                program: program.into(),
                enabled: true
            })
        );
    }

    #[test]
    fn a_disabled_agent_is_off() {
        let text = plist(Path::new(PROGRAM)).replace(
            "<key>RunAtLoad</key>",
            "<key>Disabled</key>\n\t<true/>\n\t<key>RunAtLoad</key>",
        );
        assert!(!parse(&text).unwrap().enabled);
        assert!(parse("<plist><dict></dict></plist>").is_none());
    }

    #[test]
    fn writes_and_removes_the_file() {
        let home = tempfile::tempdir().unwrap();
        let agent = LaunchAgent::for_user(home.path());
        assert!(!is_on(&agent).unwrap());
        agent.register(Path::new(PROGRAM)).unwrap();
        let file = home
            .path()
            .join("Library/LaunchAgents/app.octap.desktop.login.plist");
        assert!(file.is_file());
        assert_eq!(
            agent.registered().unwrap().unwrap().program,
            Path::new(PROGRAM)
        );
        agent.unregister().unwrap();
        assert!(!file.exists());
        assert!(!is_on(&agent).unwrap());
    }
}
