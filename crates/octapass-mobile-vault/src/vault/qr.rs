//! Reading QR codes on the phone (`octapass_core::tools::qr`): from an image the web view hands
//! over, or from a photo the user picks in the photo library, which never reaches the web view.
//! Only the codes' text goes back; the import review turns one-time codes into items.

use std::fs;

use octapass_core::tools::qr::{self, QrScan};
use zeroize::Zeroizing;

use super::Vault;
use super::attachments::{PICKED, io_error, random_name, remove_dir};
use crate::error::{ErrorCode, Result, VaultError};

/// The text of every QR code in a PNG, JPEG, WebP or GIF image. `invalidImage` for anything else.
pub fn read_qr_codes(image: &[u8]) -> Result<Vec<String>> {
    qr::read_image(image).map_err(|error| match error {
        octapass_core::Error::InvalidImage => VaultError::new(
            ErrorCode::InvalidImage,
            "not a PNG, JPEG, WebP or GIF image",
        ),
        other => VaultError::unexpected(other.code()),
    })
}

/// What scanned QR texts hold: one-time codes, parts of a Google Authenticator export, others.
pub fn summarize_qr_scans<S: AsRef<str>>(texts: &[S]) -> QrScan {
    qr::summarize(texts)
}

impl Vault {
    /// Lets the user pick a photo (a screenshot of a site's setup page, a picture of another
    /// phone's export screen) and reads its QR codes. The copy the picker made is deleted
    /// straight away. `None` when the user cancels.
    pub fn scan_qr_photo(&self) -> Result<Option<Vec<String>>> {
        self.unlocked()?;
        let into = self.config.temp_dir.join(PICKED).join(random_name());
        fs::create_dir_all(&into).map_err(io_error)?;
        let read = self.native.pick_image(&into).and_then(|picked| {
            let Some(file) = picked else {
                return Ok(None);
            };
            // Only what the picker copied where it was asked to.
            if file.path.parent() != Some(into.as_path()) {
                return Err(VaultError::unexpected("the picker wrote somewhere else"));
            }
            let image = Zeroizing::new(fs::read(&file.path).map_err(io_error)?);
            read_qr_codes(&image).map(Some)
        });
        remove_dir(&into);
        read
    }
}
