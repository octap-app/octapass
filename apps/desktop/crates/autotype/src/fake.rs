//! A platform that records keystrokes instead of sending them, for tests.

use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use crate::engine::{Backend, Permission, Platform, PlatformError, PlatformResult};
use crate::sequence::Key;
use crate::window::FocusedWindow;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    Char(char),
    Key(Key),
    Pause(Duration),
    Activate(u32),
}

#[derive(Debug)]
pub struct FakeState {
    pub backend: Backend,
    pub permission: Permission,
    pub locked: bool,
    pub focused: Option<FocusedWindow>,
    /// Focus moves to this window once this many characters were typed.
    pub focus_moves: Option<(usize, FocusedWindow)>,
    /// `activate` focuses the window it's given.
    pub activate_focuses: bool,
    /// Modifiers stay held for this many checks.
    pub modifiers_held_for: usize,
    pub fail_typing: bool,
    pub events: Vec<Event>,
}

pub struct FakePlatform(Mutex<FakeState>);

impl FakePlatform {
    pub fn new(focused: Option<FocusedWindow>) -> Self {
        Self(Mutex::new(FakeState {
            backend: Backend::Accessibility,
            permission: Permission::Granted,
            locked: false,
            focused,
            focus_moves: None,
            activate_focuses: true,
            modifiers_held_for: 0,
            fail_typing: false,
            events: Vec::new(),
        }))
    }

    pub fn state(&self) -> MutexGuard<'_, FakeState> {
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// What reached the window: characters, with Tab as `\t` and Enter as `\n`.
    pub fn typed(&self) -> String {
        self.state()
            .events
            .iter()
            .filter_map(|event| match event {
                Event::Char(c) => Some(*c),
                Event::Key(Key::Tab) => Some('\t'),
                Event::Key(Key::Enter) => Some('\n'),
                _ => None,
            })
            .collect()
    }

    pub fn paused(&self) -> Duration {
        self.state()
            .events
            .iter()
            .filter_map(|event| match event {
                Event::Pause(duration) => Some(*duration),
                _ => None,
            })
            .sum()
    }

    fn sent(&self, event: Event) -> PlatformResult<()> {
        let mut state = self.state();
        if state.fail_typing {
            return Err(PlatformError("the fake refused".into()));
        }
        state.events.push(event);
        let typed = state
            .events
            .iter()
            .filter(|e| matches!(e, Event::Char(_)))
            .count();
        if state
            .focus_moves
            .as_ref()
            .is_some_and(|(after, _)| typed >= *after)
        {
            let (_, window) = state.focus_moves.take().expect("checked");
            state.focused = Some(window);
        }
        Ok(())
    }
}

impl Platform for FakePlatform {
    fn backend(&self) -> Backend {
        self.state().backend
    }

    fn permission(&self) -> Permission {
        self.state().permission
    }

    fn screen_locked(&self) -> bool {
        self.state().locked
    }

    fn focused_window(&self) -> PlatformResult<Option<FocusedWindow>> {
        Ok(self.state().focused.clone())
    }

    fn activate(&self, window: &FocusedWindow) -> PlatformResult<()> {
        let mut state = self.state();
        state.events.push(Event::Activate(window.pid));
        if state.activate_focuses {
            state.focused = Some(window.clone());
        }
        Ok(())
    }

    fn modifiers_held(&self) -> bool {
        let mut state = self.state();
        if state.modifiers_held_for == 0 {
            return false;
        }
        state.modifiers_held_for -= 1;
        true
    }

    fn type_char(&self, c: char) -> PlatformResult<()> {
        self.sent(Event::Char(c))
    }

    fn press(&self, key: Key) -> PlatformResult<()> {
        self.sent(Event::Key(key))
    }

    fn pause(&self, duration: Duration) {
        self.state().events.push(Event::Pause(duration));
    }
}
