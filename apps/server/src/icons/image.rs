//! Turns whatever a site serves as its icon into a small PNG. The bytes are sniffed, never
//! trusted by their content type; every raster is decoded under size limits and encoded again,
//! and SVG is drawn to pixels, so nothing a site sends (scripts, metadata, oversized frames)
//! reaches clients.

use std::io::Cursor;

use image::{DynamicImage, ImageFormat, ImageReader, Limits};

/// The largest icon clients get, in pixels. Lists show 32 to 64 px at up to 2× density.
pub const MAX_SIZE: u32 = 128;
/// Smaller than this isn't worth showing over the initial.
const MIN_SIZE: u32 = 16;
/// Decoding stops beyond these, whatever the file claims: a decompression bomb can't take
/// more than a few megabytes.
const MAX_DIMENSION: u32 = 2048;
const MAX_ALLOC: u64 = 32 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Raster(ImageFormat),
    Svg,
}

/// What the bytes are, from their first bytes alone.
pub fn sniff(bytes: &[u8]) -> Option<Kind> {
    if let Ok(format) = image::guess_format(bytes) {
        return matches!(
            format,
            ImageFormat::Png
                | ImageFormat::Ico
                | ImageFormat::Gif
                | ImageFormat::Jpeg
                | ImageFormat::WebP
                | ImageFormat::Bmp
        )
        .then_some(Kind::Raster(format));
    }
    let text = std::str::from_utf8(&bytes[..bytes.len().min(1024)])
        .or_else(|e| std::str::from_utf8(&bytes[..e.valid_up_to()]))
        .ok()?;
    let head = text
        .trim_start_matches('\u{feff}')
        .trim_start()
        .to_ascii_lowercase();
    let svg = (head.starts_with("<?xml")
        || head.starts_with("<svg")
        || head.starts_with("<!--")
        || head.starts_with("<!doctype svg"))
        && head.contains("<svg");
    svg.then_some(Kind::Svg)
}

/// A PNG of at most `MAX_SIZE` px a side, or `None` when the bytes aren't a usable icon.
pub fn normalise(bytes: &[u8]) -> Option<Vec<u8>> {
    let image = match sniff(bytes)? {
        Kind::Raster(format) => decode(bytes, format)?,
        Kind::Svg => rasterise(bytes)?,
    };
    if image.width().min(image.height()) < MIN_SIZE {
        return None;
    }
    let image = if image.width().max(image.height()) > MAX_SIZE {
        image.resize(MAX_SIZE, MAX_SIZE, image::imageops::FilterType::Lanczos3)
    } else {
        image
    };
    let mut png = Vec::new();
    image
        .into_rgba8()
        .write_to(&mut Cursor::new(&mut png), ImageFormat::Png)
        .ok()?;
    Some(png)
}

fn decode(bytes: &[u8], format: ImageFormat) -> Option<DynamicImage> {
    let mut reader = ImageReader::with_format(Cursor::new(bytes), format);
    let mut limits = Limits::default();
    limits.max_image_width = Some(MAX_DIMENSION);
    limits.max_image_height = Some(MAX_DIMENSION);
    limits.max_alloc = Some(MAX_ALLOC);
    reader.limits(limits);
    // An animated GIF or WebP gives its first frame.
    reader.decode().ok()
}

/// Draws an SVG at `MAX_SIZE` px. External images and fonts are never loaded, and compressed
/// SVG (svgz) is refused rather than inflated.
fn rasterise(bytes: &[u8]) -> Option<DynamicImage> {
    let text = std::str::from_utf8(bytes).ok()?;
    let options = resvg::usvg::Options {
        resources_dir: None,
        image_href_resolver: resvg::usvg::ImageHrefResolver {
            resolve_data: Box::new(|_, _, _| None),
            resolve_string: Box::new(|_, _| None),
        },
        ..Default::default()
    };
    let tree = resvg::usvg::Tree::from_str(text, &options).ok()?;
    let size = tree.size();
    let scale = MAX_SIZE as f32 / size.width().max(size.height());
    let width = ((size.width() * scale).round() as u32).clamp(1, MAX_SIZE);
    let height = ((size.height() * scale).round() as u32).clamp(1, MAX_SIZE);
    let mut pixmap = resvg::tiny_skia::Pixmap::new(width, height)?;
    resvg::render(
        &tree,
        resvg::tiny_skia::Transform::from_scale(scale, scale),
        &mut pixmap.as_mut(),
    );
    // tiny-skia keeps premultiplied alpha; PNG wants it straight.
    let rgba: Vec<u8> = pixmap
        .pixels()
        .iter()
        .flat_map(|p| {
            let c = p.demultiply();
            [c.red(), c.green(), c.blue(), c.alpha()]
        })
        .collect();
    image::RgbaImage::from_raw(width, height, rgba).map(DynamicImage::ImageRgba8)
}

#[cfg(test)]
pub mod tests {
    use super::*;

    /// A solid square PNG, for tests here and in the fetcher's.
    pub fn png(size: u32) -> Vec<u8> {
        let image = image::RgbaImage::from_pixel(size, size, image::Rgba([36, 86, 240, 255]));
        let mut out = Vec::new();
        image
            .write_to(&mut Cursor::new(&mut out), ImageFormat::Png)
            .unwrap();
        out
    }

    /// An ICO holding one PNG entry, as most modern favicon.ico files are.
    pub fn ico(size: u32) -> Vec<u8> {
        let png = png(size);
        let mut out = vec![0, 0, 1, 0, 1, 0];
        let byte = if size >= 256 { 0 } else { size as u8 };
        out.extend([byte, byte, 0, 0, 1, 0, 32, 0]);
        out.extend((png.len() as u32).to_le_bytes());
        out.extend(22u32.to_le_bytes());
        out.extend(png);
        out
    }

    fn dimensions(png: &[u8]) -> (u32, u32) {
        let image = image::load_from_memory_with_format(png, ImageFormat::Png).unwrap();
        (image.width(), image.height())
    }

    #[test]
    fn sniffs_by_content_not_by_name() {
        assert_eq!(sniff(&png(32)), Some(Kind::Raster(ImageFormat::Png)));
        assert_eq!(sniff(&ico(32)), Some(Kind::Raster(ImageFormat::Ico)));
        assert_eq!(
            sniff(b"GIF89a\x01\x00"),
            Some(Kind::Raster(ImageFormat::Gif))
        );
        assert_eq!(
            sniff(b"\xef\xbb\xbf  <svg xmlns='http://www.w3.org/2000/svg'/>"),
            Some(Kind::Svg)
        );
        assert_eq!(sniff(b"<?xml version='1.0'?><svg/>"), Some(Kind::Svg));
        assert_eq!(
            sniff(b"<!doctype html><html><svg></svg>"),
            None,
            "an HTML page"
        );
        assert_eq!(sniff(b"<html>not found</html>"), None);
        assert_eq!(
            sniff(b"\x1f\x8b\x08\x00compressed"),
            None,
            "svgz or anything gzipped"
        );
        assert_eq!(sniff(b"%PDF-1.7"), None);
        assert_eq!(sniff(b""), None);
    }

    #[test]
    fn re_encodes_rasters_as_small_pngs() {
        assert_eq!(dimensions(&normalise(&png(64)).unwrap()), (64, 64));
        assert_eq!(dimensions(&normalise(&png(512)).unwrap()), (128, 128));
        assert_eq!(dimensions(&normalise(&ico(48)).unwrap()), (48, 48));
        assert_eq!(normalise(&png(8)), None, "too small to be worth showing");
        assert_eq!(normalise(b"\x89PNG\r\n\x1a\nbroken"), None);
    }

    #[test]
    fn refuses_decompression_bombs() {
        // A valid PNG header claiming 100 000 × 100 000 pixels: the limits stop it before any
        // pixel memory is allocated.
        let mut bomb = b"\x89PNG\r\n\x1a\n\x00\x00\x00\x0dIHDR".to_vec();
        let ihdr = [100_000u32.to_be_bytes(), 100_000u32.to_be_bytes()].concat();
        bomb.extend(&ihdr);
        bomb.extend([8, 6, 0, 0, 0]);
        let crc = crc32(&[b"IHDR".as_slice(), &ihdr, &[8, 6, 0, 0, 0]].concat());
        bomb.extend(crc.to_be_bytes());
        bomb.extend(b"\x00\x00\x00\x00IDAT\x35\xaf\x06\x1e");
        assert_eq!(normalise(&bomb), None);
    }

    fn crc32(data: &[u8]) -> u32 {
        let mut crc = !0u32;
        for byte in data {
            crc ^= u32::from(*byte);
            for _ in 0..8 {
                crc = if crc & 1 == 1 {
                    (crc >> 1) ^ 0xedb8_8320
                } else {
                    crc >> 1
                };
            }
        }
        !crc
    }

    #[test]
    fn draws_svg_without_its_scripts_or_links() {
        let svg = br##"<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 32 16">
            <script>alert(1)</script>
            <rect width="32" height="16" fill="#2456F0" onload="alert(2)"/>
            <image href="file:///etc/passwd" width="32" height="16"/>
            <image xlink:href="http://169.254.169.254/latest" width="32" height="16"/>
        </svg>"##;
        let png = normalise(svg).unwrap();
        assert_eq!(dimensions(&png), (128, 64));
        assert_eq!(
            sniff(&png),
            Some(Kind::Raster(ImageFormat::Png)),
            "served as pixels, never as SVG"
        );
        let image = image::load_from_memory(&png).unwrap().into_rgba8();
        assert_eq!(image.get_pixel(10, 10).0, [36, 86, 240, 255]);
        assert_eq!(
            normalise(b"<svg xmlns='http://www.w3.org/2000/svg'><unclosed"),
            None
        );
    }
}
