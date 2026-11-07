//! Reading QR codes from generated images: sizes, rotation, noise, several codes in one picture,
//! every image format, and a Google Authenticator export split over two QR codes.
#![cfg(feature = "qr-images")]

use std::io::Cursor;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use image::{DynamicImage, GrayImage, ImageFormat, Luma, Rgba, RgbaImage};
use octapass_core::Error;
use octapass_core::tools::qr::{ExportBatch, read_image, read_luma, summarize};
use qrcode::{Color, QrCode};
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::{RngCore, SeedableRng};

const LINK: &str = "otpauth://totp/GitHub:octo?secret=JBSWY3DPEHPK3PXP&issuer=GitHub";

/// A QR code drawn `module` pixels per module with a four-module quiet zone, dark on light.
fn qr_image(text: &str, module: u32) -> GrayImage {
    let code = QrCode::new(text.as_bytes()).unwrap();
    let width = code.width() as u32;
    let colors = code.to_colors();
    let side = (width + 8) * module;
    GrayImage::from_fn(side, side, |x, y| {
        let (mx, my) = ((x / module) as i64 - 4, (y / module) as i64 - 4);
        let dark = (0..width as i64).contains(&mx)
            && (0..width as i64).contains(&my)
            && colors[(my as u32 * width + mx as u32) as usize] == Color::Dark;
        Luma([if dark { 20 } else { 235 }])
    })
}

/// Places images on a light canvas, like a screenshot with QR codes here and there.
fn canvas(width: u32, height: u32, parts: &[(&GrayImage, u32, u32)]) -> GrayImage {
    let mut out = GrayImage::from_pixel(width, height, Luma([250]));
    for (part, left, top) in parts {
        image::imageops::overlay(&mut out, *part, i64::from(*left), i64::from(*top));
    }
    out
}

/// Rotates around the centre by `degrees` (nearest neighbour), on a light background.
fn rotate(image: &GrayImage, degrees: f64) -> GrayImage {
    let (w, h) = image.dimensions();
    let side = ((w.max(h) as f64) * 1.5) as u32;
    let (sin, cos) = degrees.to_radians().sin_cos();
    let (cx, cy, sc) = (w as f64 / 2.0, h as f64 / 2.0, side as f64 / 2.0);
    GrayImage::from_fn(side, side, |x, y| {
        let (dx, dy) = (x as f64 - sc, y as f64 - sc);
        let (sx, sy) = (dx * cos + dy * sin + cx, -dx * sin + dy * cos + cy);
        if sx >= 0.0 && sy >= 0.0 && (sx as u32) < w && (sy as u32) < h {
            *image.get_pixel(sx as u32, sy as u32)
        } else {
            Luma([235])
        }
    })
}

/// Sensor-like grain (every pixel off by up to `grain` either way), plus random speckles on
/// `speckles` percent of the pixels.
fn noisy(image: &GrayImage, speckles: u32, grain: i32) -> GrayImage {
    let mut rng = ChaCha20Rng::seed_from_u64(7);
    let mut out = image.clone();
    for pixel in out.pixels_mut() {
        if grain > 0 {
            let shift = (rng.next_u32() % (2 * grain as u32 + 1)) as i32 - grain;
            pixel.0[0] = (i32::from(pixel.0[0]) + shift).clamp(0, 255) as u8;
        }
        if rng.next_u32() % 100 < speckles {
            pixel.0[0] = (rng.next_u32() % 256) as u8;
        }
    }
    out
}

fn encode(image: DynamicImage, format: ImageFormat) -> Vec<u8> {
    let mut bytes = Cursor::new(Vec::new());
    image.write_to(&mut bytes, format).unwrap();
    bytes.into_inner()
}

fn png(image: &GrayImage) -> Vec<u8> {
    encode(DynamicImage::ImageLuma8(image.clone()), ImageFormat::Png)
}

#[test]
fn reads_codes_of_every_size() {
    for module in [2, 3, 6, 12] {
        assert_eq!(
            read_image(&png(&qr_image(LINK, module))).unwrap(),
            [LINK],
            "{module} px per module"
        );
    }
}

#[test]
fn reads_every_image_format() {
    let image = DynamicImage::ImageLuma8(qr_image(LINK, 4));
    for format in [
        ImageFormat::Png,
        ImageFormat::Jpeg,
        ImageFormat::WebP,
        ImageFormat::Gif,
    ] {
        let image = if format == ImageFormat::WebP || format == ImageFormat::Gif {
            DynamicImage::ImageRgba8(image.to_rgba8())
        } else {
            image.clone()
        };
        assert_eq!(
            read_image(&encode(image, format)).unwrap(),
            [LINK],
            "{format:?}"
        );
    }
}

#[test]
fn reads_rotated_and_noisy_codes() {
    for degrees in [90.0, 180.0, 17.0, -35.0] {
        let rotated = rotate(&qr_image(LINK, 6), degrees);
        assert_eq!(read_image(&png(&rotated)).unwrap(), [LINK], "{degrees}°");
    }
    for (speckles, grain) in [(2, 0), (5, 0), (0, 40), (0, 80), (3, 50)] {
        let photo = noisy(&qr_image(LINK, 6), speckles, grain);
        assert_eq!(
            read_image(&png(&photo)).unwrap(),
            [LINK],
            "{speckles}% specks, ±{grain} grain"
        );
    }
    // A tilted photo, darker on one side, with grain, saved as JPEG.
    let tilted = rotate(&qr_image(LINK, 5), 12.0);
    let shaded = GrayImage::from_fn(tilted.width(), tilted.height(), |x, y| {
        Luma([
            (u32::from(tilted.get_pixel(x, y).0[0]) * (100 - 50 * x / tilted.width()) / 100) as u8,
        ])
    });
    let photo = DynamicImage::ImageLuma8(noisy(&shaded, 1, 25));
    assert_eq!(
        read_image(&encode(photo, ImageFormat::Jpeg)).unwrap(),
        [LINK]
    );
}

#[test]
fn reads_light_codes_on_dark_pages_and_transparent_pngs() {
    let mut inverted = qr_image(LINK, 5);
    image::imageops::invert(&mut inverted);
    assert_eq!(read_image(&png(&inverted)).unwrap(), [LINK]);

    // A dark code on a transparent background: transparent pixels count as white.
    let code = qr_image(LINK, 5);
    let transparent = RgbaImage::from_fn(code.width(), code.height(), |x, y| {
        if code.get_pixel(x, y).0[0] < 128 {
            Rgba([0, 0, 0, 255])
        } else {
            Rgba([0, 0, 0, 0])
        }
    });
    assert_eq!(
        read_image(&encode(
            DynamicImage::ImageRgba8(transparent),
            ImageFormat::Png
        ))
        .unwrap(),
        [LINK]
    );
}

#[test]
fn finds_several_codes_anywhere_in_a_big_screenshot() {
    let other = "otpauth://totp/ACME:jane?secret=KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ&issuer=ACME";
    let (first, second, third) = (
        qr_image(LINK, 8),
        qr_image(other, 8),
        qr_image("https://example.com", 8),
    );
    // Wider than the 2048 pixels it's scaled down to.
    let screenshot = canvas(
        3200,
        1800,
        &[
            (&first, 150, 1200),
            (&second, 2700, 90),
            (&third, 1500, 800),
        ],
    );
    let mut found = read_image(&png(&screenshot)).unwrap();
    found.sort();
    assert_eq!(found, ["https://example.com", other, LINK]);
    let scan = summarize(&found);
    assert_eq!((scan.codes.len(), scan.other), (2, 1));
}

#[test]
fn nothing_found_and_not_an_image() {
    assert!(read_image(&png(&canvas(400, 300, &[]))).unwrap().is_empty());
    assert!(
        read_image(&png(&noisy(&canvas(400, 300, &[]), 50, 0)))
            .unwrap()
            .is_empty()
    );
    assert_eq!(read_image(b"GIF89a broken"), Err(Error::InvalidImage));
    let code = qr_image(LINK, 4);
    assert_eq!(
        read_luma(code.width(), code.height(), code.as_raw()),
        [LINK]
    );
}

/// One QR code of a Google Authenticator export that is split over `size` codes.
fn migration_part(accounts: &[(&[u8], &str, &str)], size: u8, index: u8, id: u8) -> String {
    fn field(number: u8, bytes: &[u8]) -> Vec<u8> {
        let mut out = vec![number << 3 | 2, bytes.len() as u8];
        out.extend_from_slice(bytes);
        out
    }
    let mut payload = Vec::new();
    for (secret, issuer, name) in accounts {
        let entry = [
            field(1, secret),
            field(2, name.as_bytes()),
            field(3, issuer.as_bytes()),
            vec![4 << 3, 1, 5 << 3, 1, 6 << 3, 2],
        ]
        .concat();
        payload.extend(field(1, &entry));
    }
    payload.extend([2 << 3, 1, 3 << 3, size, 4 << 3, index, 5 << 3, id]);
    let data = STANDARD
        .encode(payload)
        .replace('+', "%2B")
        .replace('/', "%2F")
        .replace('=', "%3D");
    format!("otpauth-migration://offline?data={data}")
}

#[test]
fn joins_a_google_authenticator_export_split_over_two_codes() {
    let first = migration_part(
        &[
            (b"12345678901234567890", "GitHub", "octo"),
            (b"abcdefghij", "ACME", "jane"),
        ],
        2,
        0,
        42,
    );
    let second = migration_part(&[(b"0123456789", "Example", "bob@example.com")], 2, 1, 42);

    // Each QR code is read from its own screenshot, as the user scans them one after another.
    let read_first = read_image(&png(&qr_image(&first, 4))).unwrap();
    assert_eq!(read_first, std::slice::from_ref(&first));
    let scan = summarize(&read_first);
    assert_eq!(scan.codes.len(), 2);
    assert_eq!(
        scan.incomplete,
        [ExportBatch {
            id: 42,
            size: 2,
            scanned: vec![1]
        }]
    );

    let read_second = read_image(&png(&qr_image(&second, 4))).unwrap();
    // The first one again (scanned twice) changes nothing.
    let all = [read_first.clone(), read_first, read_second].concat();
    let scan = summarize(&all);
    assert!(scan.incomplete.is_empty());
    let issuers: Vec<_> = scan
        .codes
        .iter()
        .map(|c| c.issuer.as_deref().unwrap())
        .collect();
    assert_eq!(issuers, ["GitHub", "ACME", "Example"]);
    assert_eq!(scan.codes[2].account.as_deref(), Some("bob@example.com"));
    assert!(
        scan.codes[0]
            .uri
            .starts_with("otpauth://totp/GitHub:octo?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
    );

    // Both parts in one picture.
    let both = canvas(
        1400,
        700,
        &[
            (&qr_image(&first, 4), 20, 20),
            (&qr_image(&second, 4), 760, 40),
        ],
    );
    let scan = summarize(&read_image(&png(&both)).unwrap());
    assert_eq!((scan.codes.len(), scan.incomplete.len()), (3, 0));
}

/// Writes the QR images the WASM, web and extension tests use (`tests/qr-fixtures/`). Run with
/// `cargo test -p octapass-core --test integration qr::write_fixtures -- --ignored` after changing them.
#[test]
#[ignore]
fn write_fixtures() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/qr-fixtures");
    std::fs::create_dir_all(&dir).unwrap();
    let save = |name: &str, image: &GrayImage| std::fs::write(dir.join(name), png(image)).unwrap();
    save("github.png", &qr_image(LINK, 6));
    let first = migration_part(
        &[
            (b"12345678901234567890", "GitHub", "octo"),
            (b"abcdefghij", "ACME", "jane"),
        ],
        2,
        0,
        42,
    );
    let second = migration_part(&[(b"0123456789", "Example", "bob@example.com")], 2, 1, 42);
    save("google-authenticator-1-of-2.png", &qr_image(&first, 5));
    save("google-authenticator-2-of-2.png", &qr_image(&second, 5));
    save("not-a-code.png", &qr_image("https://example.com/", 6));
}
