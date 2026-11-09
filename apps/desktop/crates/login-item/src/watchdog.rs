//! Starting the app again, in the tray, when it's force quit or crashes (Windows and Linux; the Mac
//! app has its own watchdog app, `apps/macos/Watchdog`).
//!
//! As it starts, the app runs its own program again with [`WATCHDOG_ARG`]: the watchdog, a second
//! process that holds the read end of a pipe whose write end only the app has. The watchdog reads
//! until the pipe closes, which happens however the app ends, a kill or a crash included, because
//! the system closes a dead process's handles. Quitting in order (the tray's Quit Octa Pass, the
//! menu's Quit) first writes [`QUIT`] down the pipe ([`Watchdog::quitting`]), and the watchdog ends
//! with it. Without that, it starts the app again with [`HIDDEN_ARG`], the way opening at login
//! does: the tray icon, no window. The new app starts a new watchdog.
//!
//! An app that keeps ending soon after it starts is started again at most [`MAX_QUICK_RESTARTS`]
//! times in a row: the count travels to the new app, and from it to its watchdog, in
//! [`RESTARTS_VAR`].
//!
//! Only `std`: the waiting and the decision are plain functions, compiled and tested everywhere.

use std::io::{self, Read, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::HIDDEN_ARG;

/// The argument the app starts its watchdog with.
pub const WATCHDOG_ARG: &str = "--watchdog";
/// What the app writes down the pipe when it quits on purpose.
pub const QUIT: &[u8] = b"quit\n";
/// How many restarts in a row came quickly, for the app the watchdog watches.
pub const RESTARTS_VAR: &str = "OCTAPASS_WATCHDOG_RESTARTS";
/// An app that ran this long ended for a reason of its own, not at every start.
pub const QUICK: Duration = Duration::from_secs(120);
/// Ended this many times in a row within [`QUICK`] of starting: something's wrong, and starting it
/// again won't help.
pub const MAX_QUICK_RESTARTS: u32 = 3;
/// Before starting it again: logging out or shutting down ends the watchdog too in this time, so
/// nothing is started while the session ends.
const DELAY: Duration = Duration::from_secs(2);

/// The app's end of the pipe. Keep it for as long as the app runs.
pub struct Watchdog {
    pipe: Mutex<Option<ChildStdin>>,
    // Kept so the watchdog isn't waited for; dropping a `Child` never ends the process.
    _child: Child,
}

impl Watchdog {
    /// Starts `program --watchdog`, in a process group of its own on Linux, so a signal to the
    /// app's group (a terminal closing) doesn't end it with the app.
    pub fn spawn(program: &Path) -> io::Result<Self> {
        let mut command = Command::new(program);
        command
            .arg(WATCHDOG_ARG)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        detach(&mut command);
        let mut child = command.spawn()?;
        let pipe = child
            .stdin
            .take()
            .ok_or_else(|| io::Error::other("no pipe to the watchdog"))?;
        Ok(Self {
            pipe: Mutex::new(Some(pipe)),
            _child: child,
        })
    }

    /// The app is quitting on purpose: the watchdog ends without starting it again. The pipe is
    /// closed here, so this happens once.
    pub fn quitting(&self) {
        if let Some(mut pipe) = self.pipe.lock().unwrap_or_else(|e| e.into_inner()).take() {
            let _ = pipe.write_all(QUIT);
            let _ = pipe.flush();
        }
    }
}

/// What the watchdog does once the app has ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// It quit on purpose: nothing.
    Quit,
    /// Start it again; `restarts` is the count of quick restarts in a row, this one included.
    Restart { restarts: u32 },
    /// It ended quickly too many times in a row.
    GiveUp,
}

/// Reads `pipe` until the app closes it, or it ends. `true` when the app said it was quitting.
/// A read error is the app gone too.
pub fn wait(mut pipe: impl Read) -> bool {
    let mut received = Vec::new();
    let mut buffer = [0u8; 64];
    loop {
        match pipe.read(&mut buffer) {
            Ok(0) | Err(_) => break,
            Ok(read) => received.extend_from_slice(&buffer[..read]),
        }
        // The app only ever writes a few bytes; keep no more than could still end in QUIT.
        if received.len() > 1024 {
            received.drain(..received.len() - QUIT.len());
        }
    }
    received.windows(QUIT.len()).any(|part| part == QUIT)
}

/// What to do once the app has ended, after running for `ran_for`, when `previous` quick restarts
/// in a row led up to it.
pub fn decide(quit: bool, ran_for: Duration, previous: u32) -> Outcome {
    if quit {
        Outcome::Quit
    } else if ran_for >= QUICK {
        Outcome::Restart { restarts: 1 }
    } else if previous < MAX_QUICK_RESTARTS {
        Outcome::Restart {
            restarts: previous + 1,
        }
    } else {
        Outcome::GiveUp
    }
}

/// The quick restarts that led up to this app, from [`RESTARTS_VAR`].
pub fn previous_restarts(value: Option<&str>) -> u32 {
    value.and_then(|text| text.trim().parse().ok()).unwrap_or(0)
}

/// The watchdog process, started with [`WATCHDOG_ARG`]: waits on its standard input for the app
/// to end, then starts `program --hidden` again unless it quit. Returns the exit code.
pub fn serve(program: &Path) -> i32 {
    let started = Instant::now();
    let quit = wait(io::stdin().lock());
    let previous = previous_restarts(std::env::var(RESTARTS_VAR).ok().as_deref());
    let restarts = match decide(quit, started.elapsed(), previous) {
        Outcome::Restart { restarts } => restarts,
        Outcome::Quit | Outcome::GiveUp => return 0,
    };
    std::thread::sleep(DELAY);
    let mut command = Command::new(program);
    command
        .arg(HIDDEN_ARG)
        .env(RESTARTS_VAR, restarts.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    detach(&mut command);
    match command.spawn() {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

#[cfg(unix)]
fn detach(command: &mut Command) {
    use std::os::unix::process::CommandExt;
    command.process_group(0);
}

#[cfg(not(unix))]
fn detach(_command: &mut Command) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_closed_pipe_without_quit_is_a_crash() {
        assert!(!wait(&b""[..]));
        assert!(!wait(&b"something else"[..]));
        assert!(wait(QUIT));
    }

    #[test]
    fn a_read_error_is_the_app_gone() {
        struct Broken;
        impl Read for Broken {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::ErrorKind::BrokenPipe.into())
            }
        }
        assert!(!wait(Broken));
    }

    #[test]
    fn quit_arriving_in_pieces_still_counts() {
        struct Bytes(Vec<u8>);
        impl Read for Bytes {
            fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
                if self.0.is_empty() || buffer.is_empty() {
                    return Ok(0);
                }
                buffer[0] = self.0.remove(0);
                Ok(1)
            }
        }
        assert!(wait(Bytes(QUIT.to_vec())));
    }

    #[test]
    fn quitting_on_purpose_never_restarts() {
        assert_eq!(decide(true, Duration::ZERO, 0), Outcome::Quit);
        assert_eq!(decide(true, QUICK * 10, 0), Outcome::Quit);
    }

    #[test]
    fn a_crash_restarts_and_a_crash_loop_gives_up() {
        let soon = Duration::from_secs(5);
        assert_eq!(decide(false, soon, 0), Outcome::Restart { restarts: 1 });
        assert_eq!(decide(false, soon, 2), Outcome::Restart { restarts: 3 });
        assert_eq!(decide(false, soon, MAX_QUICK_RESTARTS), Outcome::GiveUp);
        // Ran a while: counting starts over.
        assert_eq!(
            decide(false, QUICK, MAX_QUICK_RESTARTS),
            Outcome::Restart { restarts: 1 }
        );
    }

    /// The Tauri app keeps it in its state (`app.manage`).
    #[test]
    fn the_app_can_keep_it() {
        fn kept<T: Send + Sync + 'static>() {}
        kept::<Watchdog>();
    }

    #[test]
    fn the_count_comes_from_the_environment() {
        assert_eq!(previous_restarts(None), 0);
        assert_eq!(previous_restarts(Some("2")), 2);
        assert_eq!(previous_restarts(Some("nonsense")), 0);
    }

    /// The real thing, with `cat` standing in for the watchdog: what `quitting` writes is what
    /// `wait` reads. Unix only, where `cat` is everywhere.
    #[cfg(unix)]
    #[test]
    fn quitting_writes_down_the_pipe() {
        let mut child = Command::new("cat")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let watchdog = Watchdog {
            pipe: Mutex::new(child.stdin.take()),
            _child: child,
        };
        watchdog.quitting();
        watchdog.quitting();
        assert!(wait(stdout));
    }

    /// The pipe closes when the app's end is dropped, as when the app dies.
    #[cfg(unix)]
    #[test]
    fn the_pipe_closing_without_quit_reads_as_a_crash() {
        let mut child = Command::new("cat")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        drop(child.stdin.take());
        assert!(!wait(stdout));
        let _ = child.wait();
    }
}
