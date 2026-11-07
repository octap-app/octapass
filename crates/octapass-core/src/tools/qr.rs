//! Reading QR codes from images on the device: a screenshot of a site's two-step setup page, a
//! photo, or a picture of Google Authenticator's export screen. Nothing is sent anywhere.
//!
//! [`read_image`] decodes PNG, JPEG, WebP or GIF bytes and returns the text of every QR code it
//! finds; [`read_luma`] does the same for pixels the caller already has. [`summarize`] then says
//! what the codes are: one-time codes (`otpauth://`), parts of a Google Authenticator export
//! (`otpauth-migration://`, which may be split over several QR codes), or something else.

#[cfg(feature = "qr-images")]
use std::io::Cursor;

#[cfg(feature = "qr-images")]
use image::{DynamicImage, ImageReader, Limits};
use serde::Serialize;
use zeroize::Zeroizing;

use super::otpauth::{OtpKind, OtpParams, parse_migration_export};
#[cfg(feature = "qr-images")]
use crate::error::{Error, Result};

/// Bigger images are scaled down first: a QR code a person can scan from a full-screen
/// screenshot still has a few pixels per module at this size, and reading stays fast.
const MAX_SIDE: u32 = 2048;
/// Refuses images that would need more memory than this to decode (decompression bombs).
#[cfg(feature = "qr-images")]
const MAX_DECODE_BYTES: u64 = 256 * 1024 * 1024;
#[cfg(feature = "qr-images")]
const MAX_DIMENSION: u32 = 16_384;
/// More than this many codes in one image is not something to import from.
const MAX_CODES: usize = 32;

/// Reads every QR code in a PNG, JPEG, WebP or GIF image (the first frame of an animation).
/// An image with no QR code gives an empty list; bytes that aren't such an image are
/// [`Error::InvalidImage`]. Needs the `qr-images` feature.
#[cfg(feature = "qr-images")]
pub fn read_image(bytes: &[u8]) -> Result<Vec<String>> {
    let mut reader = ImageReader::new(Cursor::new(bytes))
        .with_guessed_format()
        .map_err(|_| Error::InvalidImage)?;
    let mut limits = Limits::default();
    limits.max_alloc = Some(MAX_DECODE_BYTES);
    limits.max_image_width = Some(MAX_DIMENSION);
    limits.max_image_height = Some(MAX_DIMENSION);
    reader.limits(limits);
    let image = reader.decode().map_err(|_| Error::InvalidImage)?;
    let (width, height, luma) = luminance(image);
    Ok(read_luma(width, height, &luma))
}

/// Reads every QR code in 8-bit greyscale pixels, row by row (`width * height` bytes).
pub fn read_luma(width: u32, height: u32, luma: &[u8]) -> Vec<String> {
    let (width, height) = (width as usize, height as usize);
    if width == 0 || height == 0 || luma.len() < width * height {
        return Vec::new();
    }
    let (width, height, scaled) = downscale(width, height, luma);
    let pixels = scaled.as_deref().unwrap_or(luma);
    // Both kinds of prepared image have the same (private) type.
    let decode_all = |mut image: rqrr::PreparedImage<_>| {
        let mut texts: Vec<String> = Vec::new();
        for grid in image.detect_grids().into_iter().take(MAX_CODES) {
            if let Ok((_, text)) = grid.decode()
                && !texts.contains(&text)
            {
                texts.push(text);
            }
        }
        texts
    };
    // The reader's own threshold is tight: fine for screenshots, but grain or dust in a photo
    // breaks it. Then a smoothed copy with a looser local threshold usually works. Last, the
    // same for light codes on a dark background (dark mode pages).
    let mut smooth = None;
    for inverted in [false, true] {
        let shade = |value: u8| if inverted { 255 - value } else { value };
        let found = decode_all(rqrr::PreparedImage::prepare_from_greyscale(
            width,
            height,
            |x, y| shade(pixels[y * width + x]),
        ));
        if !found.is_empty() {
            return found;
        }
        let smooth = smooth.get_or_insert_with(|| median(width, height, pixels));
        let dark = threshold(width, height, smooth, inverted);
        let found = decode_all(rqrr::PreparedImage::prepare_from_bitmap(
            width,
            height,
            |x, y| dark[y * width + x],
        ));
        if !found.is_empty() {
            return found;
        }
    }
    Vec::new()
}

/// Each pixel becomes the median of its 3×3 neighbourhood: removes specks, keeps edges.
fn median(width: usize, height: usize, pixels: &[u8]) -> Vec<u8> {
    let mut out = pixels.to_vec();
    for y in 1..height.saturating_sub(1) {
        for x in 1..width.saturating_sub(1) {
            let mut around = [0u8; 9];
            for (i, value) in around.iter_mut().enumerate() {
                *value = pixels[(y + i / 3 - 1) * width + x + i % 3 - 1];
            }
            around.sort_unstable();
            out[y * width + x] = around[4];
        }
    }
    out
}

/// Dark pixels: darker than 85% of the average around them (Bradley's adaptive threshold), so
/// uneven light in a photo doesn't matter.
fn threshold(width: usize, height: usize, pixels: &[u8], inverted: bool) -> Vec<bool> {
    let shade = |value: u8| u64::from(if inverted { 255 - value } else { value });
    // Sums of every rectangle from the top-left corner (an integral image).
    let stride = width + 1;
    let mut sums = vec![0u64; stride * (height + 1)];
    for y in 0..height {
        let mut row = 0u64;
        for x in 0..width {
            row += shade(pixels[y * width + x]);
            sums[(y + 1) * stride + x + 1] = sums[y * stride + x + 1] + row;
        }
    }
    let half = (width.max(height) / 16).max(4);
    let mut dark = Vec::with_capacity(width * height);
    for y in 0..height {
        let (top, bottom) = (y.saturating_sub(half), (y + half + 1).min(height));
        for x in 0..width {
            let (left, right) = (x.saturating_sub(half), (x + half + 1).min(width));
            let area = ((bottom - top) * (right - left)) as u64;
            let sum = sums[bottom * stride + right] + sums[top * stride + left]
                - sums[top * stride + right]
                - sums[bottom * stride + left];
            dark.push(shade(pixels[y * width + x]) * area * 100 < sum * 85);
        }
    }
    // Lone pixels left over from grain confuse the reader: each pixel takes the colour most of
    // its 3×3 neighbourhood has.
    let mut out = dark.clone();
    for y in 1..height.saturating_sub(1) {
        for x in 1..width.saturating_sub(1) {
            let count = (0..9)
                .filter(|i| dark[(y + i / 3 - 1) * width + x + i % 3 - 1])
                .count();
            out[y * width + x] = count >= 5;
        }
    }
    out
}

/// Greyscale, with transparent pixels over white (a dark code on a transparent PNG).
#[cfg(feature = "qr-images")]
fn luminance(image: DynamicImage) -> (u32, u32, Vec<u8>) {
    let (width, height) = (image.width(), image.height());
    if !image.color().has_alpha() {
        return (width, height, image.into_luma8().into_raw());
    }
    let rgba = image.into_rgba8();
    let luma = rgba
        .pixels()
        .map(|p| {
            let [r, g, b, a] = p.0.map(u32::from);
            let grey = (r * 299 + g * 587 + b * 114) / 1000;
            ((grey * a + 255 * (255 - a)) / 255) as u8
        })
        .collect();
    (width, height, luma)
}

/// Averages blocks of pixels so the longer side fits [`MAX_SIDE`]. `None` when it already does.
fn downscale(width: usize, height: usize, luma: &[u8]) -> (usize, usize, Option<Vec<u8>>) {
    let longest = width.max(height);
    if longest <= MAX_SIDE as usize {
        return (width, height, None);
    }
    let (new_width, new_height) = (
        (width * MAX_SIDE as usize / longest).max(1),
        (height * MAX_SIDE as usize / longest).max(1),
    );
    // Each output pixel averages the block of source pixels it covers.
    let span = |i: usize, size: usize, new_size: usize| {
        let start = i * size / new_size;
        (start, ((i + 1) * size / new_size).max(start + 1))
    };
    let mut out = Vec::with_capacity(new_width * new_height);
    for y in 0..new_height {
        let (top, bottom) = span(y, height, new_height);
        for x in 0..new_width {
            let (left, right) = span(x, width, new_width);
            let sum: u32 = (top..bottom)
                .flat_map(|row| &luma[row * width + left..row * width + right])
                .map(|&value| u32::from(value))
                .sum();
            out.push((sum / ((bottom - top) * (right - left)) as u32) as u8);
        }
    }
    (new_width, new_height, Some(out))
}

/// What a set of scanned QR codes holds.
#[derive(Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QrScan {
    /// Every one-time code found, without duplicates, as `otpauth://` links. These hold secrets.
    pub codes: Vec<ScannedCode>,
    /// Google Authenticator exports split over several QR codes that still miss some.
    pub incomplete: Vec<ExportBatch>,
    /// QR codes that aren't one-time codes (a website, Wi-Fi, a contact, …).
    pub other: usize,
    /// QR codes that look like one-time codes but can't be read.
    pub broken: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScannedCode {
    /// The canonical `otpauth://` link, as an item's `totp` field stores it.
    pub uri: Zeroizing<String>,
    pub issuer: Option<String>,
    pub account: Option<String>,
    /// Counter-based (HOTP): a code appears when the user asks for one, not on a timer.
    pub counter_based: bool,
}

/// A Google Authenticator export shown as several QR codes, one "batch" each.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportBatch {
    pub id: i64,
    pub size: u32,
    /// The parts scanned so far, counted from 1 as the app shows them ("2 of 3").
    pub scanned: Vec<u32>,
}

/// Says what scanned QR texts hold, joining the parts of a split Google Authenticator export.
/// Pass every text scanned so far: scanning the same code twice changes nothing.
pub fn summarize<S: AsRef<str>>(texts: &[S]) -> QrScan {
    let mut scan = QrScan::default();
    let mut batches: Vec<ExportBatch> = Vec::new();
    let mut seen: Vec<&str> = Vec::new();
    for text in texts.iter().map(|t| t.as_ref().trim()) {
        if text.is_empty() || seen.contains(&text) {
            continue;
        }
        seen.push(text);
        let lower = text.get(..20).unwrap_or(text).to_ascii_lowercase();
        if lower.starts_with("otpauth-migration:") {
            let Ok(export) = parse_migration_export(text) else {
                scan.broken += 1;
                continue;
            };
            if export.batch_size > 1 {
                let part = export.batch_index + 1;
                match batches.iter_mut().find(|b| b.id == export.batch_id) {
                    Some(batch) if batch.scanned.contains(&part) => {}
                    Some(batch) => batch.scanned.push(part),
                    None => batches.push(ExportBatch {
                        id: export.batch_id,
                        size: export.batch_size,
                        scanned: vec![part],
                    }),
                }
            }
            for params in export.accounts {
                add_code(&mut scan.codes, &params);
            }
        } else if lower.starts_with("otpauth:") {
            match OtpParams::parse(text) {
                Ok(params) => add_code(&mut scan.codes, &params),
                Err(_) => scan.broken += 1,
            }
        } else {
            scan.other += 1;
        }
    }
    for batch in &mut batches {
        batch.scanned.sort_unstable();
    }
    scan.incomplete = batches
        .into_iter()
        .filter(|b| (b.scanned.len() as u32) < b.size)
        .collect();
    scan
}

fn add_code(codes: &mut Vec<ScannedCode>, params: &OtpParams) {
    let uri = params.to_uri();
    if codes.iter().any(|code| code.uri == uri) {
        return;
    }
    codes.push(ScannedCode {
        uri,
        issuer: params.issuer.clone(),
        account: params.account.clone(),
        counter_based: matches!(params.kind, OtpKind::Hotp { .. }),
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summarizes_codes_exports_and_other_text() {
        let scan = summarize(&[
            "otpauth://totp/ACME:jane?secret=JBSWY3DPEHPK3PXP&issuer=ACME",
            "otpauth://totp/ACME:jane?secret=JBSWY3DPEHPK3PXP&issuer=ACME",
            "https://example.com",
            "WIFI:S:home;T:WPA;P:secret;;",
            "otpauth://totp/x",
            "otpauth-migration://offline?data=%%",
        ]);
        assert_eq!(scan.codes.len(), 1);
        assert_eq!(scan.codes[0].issuer.as_deref(), Some("ACME"));
        assert!(!scan.codes[0].counter_based);
        assert_eq!((scan.other, scan.broken), (2, 2));
        assert!(scan.incomplete.is_empty());
    }

    #[test]
    fn downscales_big_images() {
        let (w, h, out) = downscale(4096, 1024, &vec![200; 4096 * 1024]);
        assert_eq!((w, h), (2048, 512));
        assert!(out.unwrap().iter().all(|&p| p == 200));
        assert!(downscale(100, 100, &[0; 10_000]).2.is_none());
        assert!(read_luma(10, 10, &[0; 5]).is_empty());
        assert!(read_luma(0, 0, &[]).is_empty());
    }

    #[cfg(feature = "qr-images")]
    #[test]
    fn refuses_what_isnt_an_image() {
        assert_eq!(read_image(b"not an image"), Err(Error::InvalidImage));
        assert_eq!(read_image(&[]), Err(Error::InvalidImage));
        assert_eq!(
            read_image(b"\x89PNG\r\n\x1a\n\0\0"),
            Err(Error::InvalidImage)
        );
    }
}
