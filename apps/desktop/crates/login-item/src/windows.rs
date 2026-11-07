//! Windows: the value `Octa Pass` under `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, a
//! command line Windows runs when the person signs in. Task Manager's Startup apps page (and
//! Settings → Apps → Startup) turn it off without removing it, with a value of the same name under
//! `…\Explorer\StartupApproved\Run` whose first byte is odd; turning it on here removes that value.

use std::path::{Path, PathBuf};

/// The value's name, which Task Manager shows.
pub const VALUE: &str = "Octa Pass";
pub const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
pub const APPROVED_KEY: &str =
    r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run";

/// The command line: the program in quotes (Windows paths can't contain `"`), then `--hidden`.
pub fn command(program: &Path) -> String {
    format!("\"{}\" {}", program.display(), crate::HIDDEN_ARG)
}

/// The program a Run command line starts.
pub fn program_in(command: &str) -> Option<PathBuf> {
    let command = command.trim_start();
    let program = match command.strip_prefix('"') {
        Some(rest) => &rest[..rest.find('"')?],
        None => command.split_whitespace().next()?,
    };
    (!program.is_empty()).then(|| PathBuf::from(program))
}

/// Whether Task Manager's entry leaves it on: none, or a first byte that's even (2 and 6 are on,
/// 3 and 7 are off).
pub fn approved(entry: Option<&[u8]>) -> bool {
    entry
        .and_then(|bytes| bytes.first())
        .is_none_or(|first| first % 2 == 0)
}

#[cfg(windows)]
pub use system::RunKey;

#[cfg(windows)]
mod system {
    use std::io;
    use std::path::Path;

    use winreg::RegKey;
    use winreg::enums::{HKEY_CURRENT_USER, KEY_READ, KEY_SET_VALUE};

    use super::{APPROVED_KEY, RUN_KEY, VALUE, approved, command, program_in};
    use crate::{LoginItem, Registered};

    /// This user's Run key.
    pub struct RunKey;

    fn missing_is_none<T>(result: io::Result<T>) -> io::Result<Option<T>> {
        match result {
            Ok(value) => Ok(Some(value)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }

    fn delete(path: &str) -> io::Result<()> {
        let user = RegKey::predef(HKEY_CURRENT_USER);
        let Some(key) = missing_is_none(user.open_subkey_with_flags(path, KEY_SET_VALUE))? else {
            return Ok(());
        };
        missing_is_none(key.delete_value(VALUE)).map(drop)
    }

    impl LoginItem for RunKey {
        fn registered(&self) -> io::Result<Option<Registered>> {
            let user = RegKey::predef(HKEY_CURRENT_USER);
            let Some(run) = missing_is_none(user.open_subkey_with_flags(RUN_KEY, KEY_READ))? else {
                return Ok(None);
            };
            let Some(line) = missing_is_none(run.get_value::<String, _>(VALUE))? else {
                return Ok(None);
            };
            let Some(program) = program_in(&line) else {
                return Ok(None);
            };
            let entry = missing_is_none(user.open_subkey_with_flags(APPROVED_KEY, KEY_READ))?
                .map(|key| missing_is_none(key.get_raw_value(VALUE)))
                .transpose()?
                .flatten();
            Ok(Some(Registered {
                program,
                enabled: approved(entry.as_ref().map(|value| &value.bytes[..])),
            }))
        }

        fn register(&self, program: &Path) -> io::Result<()> {
            let (run, _) = RegKey::predef(HKEY_CURRENT_USER).create_subkey(RUN_KEY)?;
            run.set_value(VALUE, &command(program))?;
            delete(APPROVED_KEY)
        }

        fn unregister(&self) -> io::Result<()> {
            delete(RUN_KEY)?;
            delete(APPROVED_KEY)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_command_quotes_the_program() {
        let program = Path::new(r"C:\Users\Ada\AppData\Local\Octa Pass\octapass-desktop.exe");
        let line = command(program);
        assert_eq!(
            line,
            r#""C:\Users\Ada\AppData\Local\Octa Pass\octapass-desktop.exe" --hidden"#
        );
        assert_eq!(program_in(&line).as_deref(), Some(program));
    }

    #[test]
    fn reads_unquoted_and_broken_commands() {
        assert_eq!(
            program_in(r"C:\Tools\octapass-desktop.exe --hidden").as_deref(),
            Some(Path::new(r"C:\Tools\octapass-desktop.exe"))
        );
        assert_eq!(program_in(r#""C:\no end"#), None);
        assert_eq!(program_in(""), None);
    }

    #[test]
    fn task_manager_turns_it_off_with_an_odd_first_byte() {
        assert!(approved(None));
        assert!(approved(Some(&[])));
        assert!(approved(Some(&[2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])));
        assert!(approved(Some(&[6, 0, 0])));
        assert!(!approved(Some(&[3, 0, 0, 0, 0x10, 0x20, 0, 0, 0, 0, 0, 0])));
        assert!(!approved(Some(&[7])));
    }
}
