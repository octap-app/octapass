//! Copying secrets with auto-clear (plan 03: limit exposure on an unlocked device).

use std::time::Duration;

use zeroize::Zeroizing;

pub const CLEAR_AFTER: Duration = Duration::from_secs(30);

/// Puts `value` on the clipboard and clears it after [`CLEAR_AFTER`], unless something else was
/// copied in the meantime.
pub fn copy_and_clear(value: Zeroizing<String>) -> Result<(), String> {
    arboard::Clipboard::new()
        .and_then(|mut clipboard| clipboard.set_text(value.as_str()))
        .map_err(|error| error.to_string())?;
    std::thread::spawn(move || {
        std::thread::sleep(CLEAR_AFTER);
        if let Ok(mut clipboard) = arboard::Clipboard::new()
            && clipboard
                .get_text()
                .is_ok_and(|current| Zeroizing::new(current).as_str() == value.as_str())
        {
            let _ = clipboard.clear();
        }
    });
    Ok(())
}
