//! Linux: an XDG autostart entry, `~/.config/autostart/app.octap.desktop.desktop`, which the
//! desktop (GNOME, KDE, Xfce, …) starts at login. Desktop settings turn an entry off by writing
//! `Hidden=true` or `X-GNOME-Autostart-enabled=false` into it, or by removing it.

use std::io;
use std::path::{Path, PathBuf};

use crate::{HIDDEN_ARG, LoginItem, Registered, read_file, remove_file, write_file};

/// The entry's file name: the app's identifier.
pub const FILE_NAME: &str = "app.octap.desktop.desktop";

/// The autostart entry's file.
pub struct Autostart {
    path: PathBuf,
}

impl Autostart {
    /// In `config_dir` (`$XDG_CONFIG_HOME`, or `~/.config`).
    pub fn for_user(config_dir: &Path) -> Self {
        Self::at(config_dir.join("autostart").join(FILE_NAME))
    }

    pub fn at(path: PathBuf) -> Self {
        Self { path }
    }
}

impl LoginItem for Autostart {
    fn registered(&self) -> io::Result<Option<Registered>> {
        Ok(read_file(&self.path)?.and_then(|text| parse(&text)))
    }

    fn register(&self, program: &Path) -> io::Result<()> {
        write_file(&self.path, &entry(program)?)
    }

    fn unregister(&self) -> io::Result<()> {
        remove_file(&self.path)
    }
}

/// The entry: start `program --hidden` at login. `Icon` is the name the packages install the
/// app's icon under.
pub fn entry(program: &Path) -> io::Result<String> {
    Ok(format!(
        "[Desktop Entry]
Type=Application
Version=1.0
Name=Octa Pass
Comment=Opens Octa Pass in the background when you sign in
Exec={} {HIDDEN_ARG}
Icon=octapass-desktop
Terminal=false
X-GNOME-Autostart-enabled=true
",
        quote(&program.to_string_lossy())?
    ))
}

/// The program an entry starts, and whether it's turned off.
pub fn parse(text: &str) -> Option<Registered> {
    let mut in_entry = false;
    let mut exec = None;
    let mut enabled = true;
    for line in text.lines().map(str::trim) {
        if line.starts_with('[') {
            in_entry = line == "[Desktop Entry]";
            continue;
        }
        if !in_entry {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        match (key.trim(), value.trim()) {
            ("Exec", value) => exec = Some(value.to_owned()),
            ("Hidden", "true") | ("X-GNOME-Autostart-enabled", "false") => enabled = false,
            _ => {}
        }
    }
    Some(Registered {
        program: PathBuf::from(first_argument(&exec?)?),
        enabled,
    })
}

/// One `Exec` argument: always in double quotes, with the characters the spec reserves inside
/// quotes escaped, then the backslashes escaped again for the file's string rules, and `%` doubled
/// so it isn't a field code. A line break can't be written, so it's refused.
fn quote(argument: &str) -> io::Result<String> {
    if argument.contains(['\n', '\r']) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the app's path has a line break, which an autostart entry can't hold",
        ));
    }
    let mut quoted = String::from("\"");
    for character in argument.chars() {
        match character {
            '"' | '`' | '$' => {
                quoted.push_str("\\\\");
                quoted.push(character);
            }
            '\\' => quoted.push_str("\\\\\\\\"),
            '%' => quoted.push_str("%%"),
            _ => quoted.push(character),
        }
    }
    quoted.push('"');
    Ok(quoted)
}

/// The first argument of an `Exec` value, undoing the string rules, then the quoting rules, then
/// the doubled `%`.
fn first_argument(exec: &str) -> Option<String> {
    let mut unescaped = String::new();
    let mut characters = exec.chars();
    while let Some(character) = characters.next() {
        if character != '\\' {
            unescaped.push(character);
            continue;
        }
        match characters.next() {
            Some('s') => unescaped.push(' '),
            Some('t') => unescaped.push('\t'),
            Some('n') => unescaped.push('\n'),
            Some('r') => unescaped.push('\r'),
            Some(other) => unescaped.push(other),
            None => unescaped.push('\\'),
        }
    }
    let mut argument = String::new();
    let mut characters = unescaped.trim_start().chars();
    if unescaped.trim_start().starts_with('"') {
        characters.next();
        loop {
            match characters.next()? {
                '"' => break,
                '\\' => argument.push(characters.next()?),
                other => argument.push(other),
            }
        }
    } else {
        argument.extend(characters.take_while(|character| !character.is_whitespace()));
    }
    let argument = argument.replace("%%", "%");
    (!argument.is_empty()).then_some(argument)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::is_on;

    #[test]
    fn the_entry_starts_the_app_hidden() {
        let text = entry(Path::new("/usr/bin/octapass-desktop")).unwrap();
        assert!(text.starts_with("[Desktop Entry]\n"));
        assert!(text.contains("\nExec=\"/usr/bin/octapass-desktop\" --hidden\n"));
        assert!(text.contains("\nType=Application\n"));
    }

    #[test]
    fn reads_back_what_it_wrote_with_awkward_paths() {
        for path in [
            "/home/ada/Apps/Octa Pass.AppImage",
            "/home/ada/100% \"real\" $HOME `x` \\ Pass/Octa_Pass.AppImage",
            "/opt/octa-pass/octapass-desktop",
        ] {
            let found = parse(&entry(Path::new(path)).unwrap()).unwrap();
            assert_eq!(found.program, Path::new(path));
            assert!(found.enabled);
        }
        assert!(entry(Path::new("/home/ada/two\nlines")).is_err());
    }

    #[test]
    fn follows_the_spec_for_quoting() {
        let text = entry(Path::new("/a\"b$c`d\\e%f")).unwrap();
        assert!(
            text.contains(r#"Exec="/a\\"b\\$c\\`d\\\\e%%f" --hidden"#),
            "{text}"
        );
    }

    #[test]
    fn reads_entries_written_by_other_tools() {
        let found =
            parse("[Desktop Entry]\nName=Octa Pass\nExec=/usr/bin/octapass-desktop --hidden\n")
                .unwrap();
        assert_eq!(found.program, Path::new("/usr/bin/octapass-desktop"));
        let spaced = parse("[Desktop Entry]\nExec=\"/home/ada/My Apps/op\" --hidden\n").unwrap();
        assert_eq!(spaced.program, Path::new("/home/ada/My Apps/op"));
        assert!(parse("[Desktop Entry]\nName=Octa Pass\n").is_none());
        assert!(parse("[Desktop Action x]\nExec=/bin/elsewhere\n").is_none());
    }

    #[test]
    fn hidden_or_gnome_disabled_entries_are_off() {
        let base = entry(Path::new("/usr/bin/octapass-desktop")).unwrap();
        let hidden = format!("{base}Hidden=true\n");
        assert!(!parse(&hidden).unwrap().enabled);
        let gnome = base.replace(
            "X-GNOME-Autostart-enabled=true",
            "X-GNOME-Autostart-enabled=false",
        );
        assert!(!parse(&gnome).unwrap().enabled);
    }

    #[test]
    fn writes_and_removes_the_file() {
        let config = tempfile::tempdir().unwrap();
        let autostart = Autostart::for_user(config.path());
        assert!(!is_on(&autostart).unwrap());
        autostart
            .register(Path::new("/usr/bin/octapass-desktop"))
            .unwrap();
        let file = config.path().join("autostart/app.octap.desktop.desktop");
        assert!(file.is_file());
        assert!(is_on(&autostart).unwrap());
        // Turning it on again rewrites an entry the desktop turned off.
        std::fs::write(
            &file,
            "[Desktop Entry]\nExec=/usr/bin/octapass-desktop\nHidden=true\n",
        )
        .unwrap();
        assert!(!is_on(&autostart).unwrap());
        autostart
            .register(Path::new("/usr/bin/octapass-desktop"))
            .unwrap();
        assert!(is_on(&autostart).unwrap());
        autostart.unregister().unwrap();
        assert!(!file.exists());
    }
}
