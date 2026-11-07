//! Typing a sequence into the focused window, with every check first: the permission, the screen
//! lock, that the window isn't Octa Pass and that it belongs to the item. Focus is checked again
//! before every keystroke group, so a window that pops up in the middle gets nothing more.

use std::fmt;
use std::time::Duration;

use serde::Serialize;

use crate::sequence::{Action, Field, Key};
use crate::window::{FocusedWindow, ItemRules, Reason};

/// How this platform types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Backend {
    /// macOS: `CGEvent`, with the Accessibility permission.
    Accessibility,
    /// Windows: `SendInput`.
    SendInput,
    /// Linux on X11: the XTest extension.
    XTest,
    /// Linux on Wayland: the `xdg-desktop-portal` RemoteDesktop portal.
    Portal,
    /// Nothing can type here (Wayland without the portal): the app copies instead.
    Clipboard,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(
    tag = "status",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum Permission {
    Granted,
    /// The user must allow typing in the system's settings, which `settings_url` opens.
    Missing {
        settings_url: &'static str,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformError(pub String);

impl fmt::Display for PlatformError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for PlatformError {}

pub type PlatformResult<T> = Result<T, PlatformError>;

/// What the engine needs from the operating system. Implemented per platform in this crate, and
/// by [`crate::fake::FakePlatform`] in tests.
pub trait Platform: Send + Sync {
    fn backend(&self) -> Backend;
    fn permission(&self) -> Permission;
    fn screen_locked(&self) -> bool;
    /// `None` when the platform can't tell (Wayland).
    fn focused_window(&self) -> PlatformResult<Option<FocusedWindow>>;
    /// Brings `window` back to the front, after the quick-access window was over it.
    fn activate(&self, window: &FocusedWindow) -> PlatformResult<()>;
    /// Shift, Control, Option/Alt or Command/Windows is down, which would turn typing into
    /// shortcuts (the global shortcut's keys may still be held).
    fn modifiers_held(&self) -> bool;
    /// Types one character, whatever the keyboard layout (Unicode key events).
    fn type_char(&self, c: char) -> PlatformResult<()>;
    fn press(&self, key: Key) -> PlatformResult<()>;
    fn pause(&self, duration: Duration) {
        std::thread::sleep(duration);
    }
    /// Called once typing is over, whether it worked or not: X11 puts its keyboard map back, the
    /// portal closes its session.
    fn finish(&self) {}
}

/// Waits for apps that need a moment.
pub const START_DELAY: Duration = Duration::from_millis(150);
pub const CHAR_DELAY: Duration = Duration::from_millis(6);
/// After Tab and Enter, which move focus or submit.
pub const KEY_DELAY: Duration = Duration::from_millis(80);
const FOCUS_TIMEOUT: Duration = Duration::from_secs(2);
const KEYS_TIMEOUT: Duration = Duration::from_secs(3);
const POLL: Duration = Duration::from_millis(25);

pub struct Request<'a> {
    /// This app's process: its windows never get keystrokes.
    pub own_pid: u32,
    pub item: &'a ItemRules,
    pub actions: &'a [Action],
    /// The window the quick-access window was opened over. It's brought back first, and typing
    /// stops if anything else has focus.
    pub target: Option<&'a FocusedWindow>,
    /// The user picked this item in the quick-access window. Only where the platform can't see the
    /// focused window (Wayland) does that stand in for the window check.
    pub picked: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Typed {
    /// The window, as [`FocusedWindow::describe`] names it; `None` on Wayland.
    pub window: Option<String>,
    pub reason: Option<Reason>,
}

/// Why nothing (or not everything) was typed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(
    tag = "code",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum Refusal {
    PermissionRequired {
        settings_url: &'static str,
    },
    ScreenLocked,
    /// Nothing else is focused, or the platform couldn't say what is.
    NoWindow,
    OwnWindow,
    /// Focus moved to another window, before or while typing.
    FocusChanged {
        window: String,
    },
    NoMatch {
        window: String,
    },
    /// Modifier keys stayed down.
    KeysHeld,
    /// This platform can't type: copy instead.
    Unsupported,
    MissingField {
        field: Field,
    },
    Failed {
        message: String,
    },
}

impl From<PlatformError> for Refusal {
    fn from(error: PlatformError) -> Self {
        Refusal::Failed { message: error.0 }
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PermissionRequired { .. } => write!(f, "Octa Pass isn't allowed to type"),
            Self::ScreenLocked => write!(f, "the screen is locked"),
            Self::NoWindow => write!(f, "no window to type into"),
            Self::OwnWindow => write!(f, "Octa Pass never types into itself"),
            Self::FocusChanged { window } => write!(f, "focus moved to {window}"),
            Self::NoMatch { window } => write!(f, "{window} doesn't match the login"),
            Self::KeysHeld => write!(f, "modifier keys are held down"),
            Self::Unsupported => write!(f, "auto-type isn't available here"),
            Self::MissingField { field } => write!(f, "the login has no {field:?}"),
            Self::Failed { message } => write!(f, "{message}"),
        }
    }
}

impl std::error::Error for Refusal {}

/// Checks, then types. See the module docs.
pub fn run(platform: &dyn Platform, request: &Request<'_>) -> Result<Typed, Refusal> {
    if platform.backend() == Backend::Clipboard {
        return Err(Refusal::Unsupported);
    }
    if let Permission::Missing { settings_url } = platform.permission() {
        return Err(Refusal::PermissionRequired { settings_url });
    }
    if platform.screen_locked() {
        return Err(Refusal::ScreenLocked);
    }
    if let Some(target) = request.target {
        if target.pid == request.own_pid {
            return Err(Refusal::OwnWindow);
        }
        platform.activate(target)?;
        wait_for(
            platform,
            FOCUS_TIMEOUT,
            || matches!(platform.focused_window(), Ok(Some(focused)) if focused.same_window(target)),
        );
    }
    if !wait_for(platform, KEYS_TIMEOUT, || !platform.modifiers_held()) {
        return Err(Refusal::KeysHeld);
    }

    let focused = platform.focused_window()?;
    let reason = match &focused {
        None if request.picked && platform.backend() == Backend::Portal => None,
        None => return Err(Refusal::NoWindow),
        Some(focused) => Some(check(focused, request)?),
    };

    platform.pause(START_DELAY);
    let typed = send(platform, request.actions, focused.as_ref());
    platform.finish();
    typed?;
    Ok(Typed {
        window: focused.as_ref().map(FocusedWindow::describe),
        reason,
    })
}

fn send(
    platform: &dyn Platform,
    actions: &[Action],
    focused: Option<&FocusedWindow>,
) -> Result<(), Refusal> {
    for action in actions {
        if let Action::Delay(duration) = action {
            platform.pause(*duration);
            continue;
        }
        still_focused(platform, focused)?;
        match action {
            Action::Text(text) => {
                for c in text.chars() {
                    match c {
                        '\t' => press(platform, Key::Tab)?,
                        '\n' => press(platform, Key::Enter)?,
                        '\r' => {}
                        c => {
                            platform.type_char(c)?;
                            platform.pause(CHAR_DELAY);
                        }
                    }
                }
            }
            Action::Key(key) => press(platform, *key)?,
            Action::Delay(_) => unreachable!("handled above"),
        }
    }
    Ok(())
}

fn check(focused: &FocusedWindow, request: &Request<'_>) -> Result<Reason, Refusal> {
    if focused.pid == request.own_pid {
        return Err(Refusal::OwnWindow);
    }
    if let Some(target) = request.target
        && !focused.same_window(target)
    {
        return Err(Refusal::FocusChanged {
            window: focused.describe(),
        });
    }
    request
        .item
        .matches(focused)
        .ok_or_else(|| Refusal::NoMatch {
            window: focused.describe(),
        })
}

fn still_focused(platform: &dyn Platform, focused: Option<&FocusedWindow>) -> Result<(), Refusal> {
    if platform.screen_locked() {
        return Err(Refusal::ScreenLocked);
    }
    let Some(focused) = focused else {
        return Ok(());
    };
    match platform.focused_window()? {
        Some(now) if now.same_window(focused) => Ok(()),
        Some(now) => Err(Refusal::FocusChanged {
            window: now.describe(),
        }),
        None => Err(Refusal::NoWindow),
    }
}

fn press(platform: &dyn Platform, key: Key) -> Result<(), Refusal> {
    platform.press(key)?;
    platform.pause(KEY_DELAY);
    Ok(())
}

/// Polls `done` until it's true or about `timeout` has passed; returns the last answer. Counts
/// polls rather than reading the clock, so a fake platform's pauses can be instant.
fn wait_for(platform: &dyn Platform, timeout: Duration, mut done: impl FnMut() -> bool) -> bool {
    let polls = timeout.as_millis() / POLL.as_millis();
    for _ in 0..polls {
        if done() {
            return true;
        }
        platform.pause(POLL);
    }
    done()
}

#[cfg(test)]
mod tests {
    use zeroize::Zeroizing;

    use super::*;
    use crate::fake::{Event, FakePlatform};
    use crate::sequence::Sequence;

    const OWN_PID: u32 = 1;

    fn editor(pid: u32) -> FocusedWindow {
        FocusedWindow {
            pid,
            app_name: "TextEdit".into(),
            app_id: "com.apple.textedit".into(),
            title: "Acme login".into(),
            url: None,
            handle: 0,
        }
    }

    fn acme() -> ItemRules {
        ItemRules {
            id: "item".into(),
            title: "Acme".into(),
            ..Default::default()
        }
    }

    fn actions(sequence: &str) -> Vec<Action> {
        Sequence::parse(sequence)
            .unwrap()
            .actions(&|field| {
                Some(Zeroizing::new(
                    match field {
                        Field::Username => "ada@example.com",
                        Field::Password => "pässwörd ب😀",
                        Field::Totp => "123456",
                    }
                    .to_owned(),
                ))
            })
            .unwrap()
    }

    fn request<'a>(
        item: &'a ItemRules,
        actions: &'a [Action],
        target: Option<&'a FocusedWindow>,
    ) -> Request<'a> {
        Request {
            own_pid: OWN_PID,
            item,
            actions,
            target,
            picked: true,
        }
    }

    #[test]
    fn types_the_sequence_into_a_matching_window() {
        let platform = FakePlatform::new(Some(editor(7)));
        let (item, actions) = (acme(), actions(crate::DEFAULT_SEQUENCE));
        let typed = run(&platform, &request(&item, &actions, None)).unwrap();
        assert_eq!(platform.typed(), "ada@example.com\tpässwörd ب😀\n");
        assert_eq!(typed.window.as_deref(), Some("Acme login — TextEdit"));
        assert_eq!(
            typed.reason,
            Some(Reason::Name {
                name: "Acme".into()
            })
        );
        assert!(platform.paused() >= START_DELAY + KEY_DELAY * 2);
    }

    #[test]
    fn delays_and_control_characters() {
        let platform = FakePlatform::new(Some(editor(7)));
        let (item, actions) = (acme(), actions("a{DELAY 700}b\tc\r\n"));
        run(&platform, &request(&item, &actions, None)).unwrap();
        assert_eq!(platform.typed(), "ab\tc\n");
        assert!(
            platform
                .state()
                .events
                .contains(&Event::Pause(Duration::from_millis(700)))
        );
    }

    #[test]
    fn refuses_before_typing_anything() {
        let item = acme();
        let actions = actions("{PASSWORD}");
        type Setup = Box<dyn Fn(&FakePlatform)>;
        let cases: Vec<(Setup, Refusal)> = vec![
            (
                Box::new(|p| {
                    p.state().permission = Permission::Missing {
                        settings_url: "x-apple.systempreferences:",
                    }
                }),
                Refusal::PermissionRequired {
                    settings_url: "x-apple.systempreferences:",
                },
            ),
            (Box::new(|p| p.state().locked = true), Refusal::ScreenLocked),
            (
                Box::new(|p| p.state().focused = Some(editor(OWN_PID))),
                Refusal::OwnWindow,
            ),
            (Box::new(|p| p.state().focused = None), Refusal::NoWindow),
            (
                Box::new(|p| p.state().backend = Backend::Clipboard),
                Refusal::Unsupported,
            ),
            (
                Box::new(|p| p.state().modifiers_held_for = usize::MAX),
                Refusal::KeysHeld,
            ),
            (
                Box::new(|p| p.state().focused.as_mut().unwrap().title = "Untitled".into()),
                Refusal::NoMatch {
                    window: "Untitled — TextEdit".into(),
                },
            ),
        ];
        for (setup, refusal) in cases {
            let platform = FakePlatform::new(Some(editor(7)));
            setup(&platform);
            assert_eq!(
                run(&platform, &request(&item, &actions, None)),
                Err(refusal.clone())
            );
            assert_eq!(platform.typed(), "", "{refusal:?}");
        }
    }

    #[test]
    fn waits_for_the_shortcut_keys_to_be_released() {
        let platform = FakePlatform::new(Some(editor(7)));
        platform.state().modifiers_held_for = 10;
        let (item, actions) = (acme(), actions("{USERNAME}"));
        run(&platform, &request(&item, &actions, None)).unwrap();
        assert_eq!(platform.typed(), "ada@example.com");
    }

    #[test]
    fn brings_the_target_back_and_types_only_there() {
        let target = editor(7);
        let item = acme();
        let actions = actions("{USERNAME}");

        // Quick access had focus; the target comes back.
        let platform = FakePlatform::new(Some(editor(OWN_PID)));
        run(&platform, &request(&item, &actions, Some(&target))).unwrap();
        assert_eq!(platform.state().events[0], Event::Activate(7));
        assert_eq!(platform.typed(), "ada@example.com");

        // It doesn't: another app took focus.
        let platform = FakePlatform::new(Some(editor(9)));
        platform.state().activate_focuses = false;
        assert_eq!(
            run(&platform, &request(&item, &actions, Some(&target))),
            Err(Refusal::FocusChanged {
                window: "Acme login — TextEdit".into()
            })
        );
        assert_eq!(platform.typed(), "");

        // The target is Octa Pass itself.
        let platform = FakePlatform::new(Some(editor(7)));
        let own = editor(OWN_PID);
        assert_eq!(
            run(&platform, &request(&item, &actions, Some(&own))),
            Err(Refusal::OwnWindow)
        );
    }

    #[test]
    fn stops_when_focus_moves_while_typing() {
        let platform = FakePlatform::new(Some(editor(7)));
        let mut popup = editor(8);
        popup.title = "Software Update".into();
        platform.state().focus_moves = Some((3, popup));
        let (item, actions) = (acme(), actions(crate::DEFAULT_SEQUENCE));
        assert_eq!(
            run(&platform, &request(&item, &actions, None)),
            Err(Refusal::FocusChanged {
                window: "Software Update — TextEdit".into()
            })
        );
        // The username went out (focus moved after its third character), the password didn't.
        assert_eq!(platform.typed(), "ada@example.com");
    }

    #[test]
    fn stops_when_the_screen_locks_while_typing() {
        struct LocksAfterFirstKey(FakePlatform);
        impl Platform for LocksAfterFirstKey {
            fn backend(&self) -> Backend {
                self.0.backend()
            }
            fn permission(&self) -> Permission {
                self.0.permission()
            }
            fn screen_locked(&self) -> bool {
                self.0.typed().contains('\t')
            }
            fn focused_window(&self) -> PlatformResult<Option<FocusedWindow>> {
                self.0.focused_window()
            }
            fn activate(&self, window: &FocusedWindow) -> PlatformResult<()> {
                self.0.activate(window)
            }
            fn modifiers_held(&self) -> bool {
                false
            }
            fn type_char(&self, c: char) -> PlatformResult<()> {
                self.0.type_char(c)
            }
            fn press(&self, key: Key) -> PlatformResult<()> {
                self.0.press(key)
            }
            fn pause(&self, _: Duration) {}
        }
        let platform = LocksAfterFirstKey(FakePlatform::new(Some(editor(7))));
        let (item, actions) = (acme(), actions(crate::DEFAULT_SEQUENCE));
        assert_eq!(
            run(&platform, &request(&item, &actions, None)),
            Err(Refusal::ScreenLocked)
        );
        assert_eq!(platform.0.typed(), "ada@example.com\t");
    }

    #[test]
    fn wayland_types_only_what_the_user_picked() {
        let platform = FakePlatform::new(None);
        platform.state().backend = Backend::Portal;
        let item = acme();
        let actions = actions("{USERNAME}");
        let mut picked = request(&item, &actions, None);
        picked.picked = false;
        assert_eq!(run(&platform, &picked), Err(Refusal::NoWindow));
        picked.picked = true;
        assert_eq!(
            run(&platform, &picked),
            Ok(Typed {
                window: None,
                reason: None
            })
        );
        assert_eq!(platform.typed(), "ada@example.com");
    }

    #[test]
    fn platform_failures_are_reported() {
        let platform = FakePlatform::new(Some(editor(7)));
        platform.state().fail_typing = true;
        let (item, actions) = (acme(), actions("{USERNAME}"));
        assert_eq!(
            run(&platform, &request(&item, &actions, None)),
            Err(Refusal::Failed {
                message: "the fake refused".into()
            })
        );
    }

    #[test]
    fn refusals_serialize_with_a_code() {
        let json = serde_json::to_value(Refusal::NoMatch { window: "w".into() }).unwrap();
        assert_eq!(
            json,
            serde_json::json!({ "code": "noMatch", "window": "w" })
        );
        let json = serde_json::to_value(Refusal::MissingField { field: Field::Totp }).unwrap();
        assert_eq!(
            json,
            serde_json::json!({ "code": "missingField", "field": "totp" })
        );
    }
}
