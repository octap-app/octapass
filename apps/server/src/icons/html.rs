//! Finds a home page's icons: its `<link rel="icon">` and `<link rel="apple-touch-icon">` tags.
//! A small tag scanner rather than an HTML parser: only `<base>` and `<link>` matter, and they
//! sit in the `<head>`.

/// One icon a page links to, with the sizes it claims.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Candidate {
    pub href: String,
    pub sizes: Vec<u32>,
    /// `sizes="any"` or an SVG type: it scales.
    pub scalable: bool,
    pub touch: bool,
}

/// The page's `<base href>` and icon links, in page order.
pub fn icon_links(html: &str) -> (Option<String>, Vec<Candidate>) {
    let mut base = None;
    let mut candidates = vec![];
    for (name, attrs) in tags(html) {
        let attr = |key: &str| {
            attrs
                .iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v.as_str())
        };
        match name.as_str() {
            "base" if base.is_none() => base = attr("href").map(str::to_owned),
            "link" => {
                let rel = attr("rel").unwrap_or_default().to_ascii_lowercase();
                let rels: Vec<&str> = rel.split_ascii_whitespace().collect();
                let touch = rels
                    .iter()
                    .any(|r| matches!(*r, "apple-touch-icon" | "apple-touch-icon-precomposed"));
                if !touch && !rels.contains(&"icon") {
                    continue;
                }
                let Some(href) = attr("href").map(str::trim).filter(|h| !h.is_empty()) else {
                    continue;
                };
                let sizes_attr = attr("sizes").unwrap_or_default().to_ascii_lowercase();
                let sizes = sizes_attr
                    .split_ascii_whitespace()
                    .filter_map(|size| {
                        let (w, h) = size.split_once('x')?;
                        Some(w.parse::<u32>().ok()?.max(h.parse::<u32>().ok()?))
                    })
                    .collect();
                let svg = attr("type").is_some_and(|t| t.eq_ignore_ascii_case("image/svg+xml"))
                    || href
                        .to_ascii_lowercase()
                        .split(['?', '#'])
                        .next()
                        .is_some_and(|p| p.ends_with(".svg"));
                candidates.push(Candidate {
                    href: href.to_owned(),
                    sizes,
                    scalable: svg || sizes_attr.split_ascii_whitespace().any(|s| s == "any"),
                    touch,
                });
            }
            _ => {}
        }
    }
    (base, candidates)
}

/// Best first: a size from 64 to 128 px, then scalable icons, then the smallest larger one,
/// then touch icons of unknown size (usually 180 px), then other unknown sizes, then the
/// largest of the small ones.
pub fn rank(mut candidates: Vec<Candidate>) -> Vec<Candidate> {
    fn score(c: &Candidate) -> (u8, u32) {
        let best = c.sizes.iter().copied().min_by_key(|s| {
            if (64..=128).contains(s) {
                0
            } else if *s > 128 {
                *s
            } else {
                10_000 - s
            }
        });
        match best {
            Some(s) if (64..=128).contains(&s) => (0, 128 - s),
            _ if c.scalable => (1, 0),
            Some(s) if s > 128 => (2, s),
            None if c.touch => (3, 0),
            None => (4, 0),
            Some(s) => (5, 128 - s),
        }
    }
    // Stable, so equally good icons keep page order.
    candidates.sort_by_key(score);
    candidates
}

/// Start tags with their lowercased name and attributes, skipping comments, scripts and styles.
/// Stops at `</head>` or `<body>`.
fn tags(html: &str) -> Vec<(String, Vec<(String, String)>)> {
    let bytes = html.as_bytes();
    let lower = html.to_ascii_lowercase();
    let mut out = vec![];
    let mut i = 0;
    while let Some(offset) = html[i..].find('<') {
        let start = i + offset;
        let rest = &lower[start..];
        if rest.starts_with("<!--") {
            i = lower[start..]
                .find("-->")
                .map_or(html.len(), |end| start + end + 3);
            continue;
        }
        if rest.starts_with("</head") || rest.starts_with("<body") {
            break;
        }
        let name_end = rest[1..]
            .find(|c: char| !c.is_ascii_alphanumeric())
            .map_or(rest.len(), |n| n + 1);
        let name = &rest[1..name_end];
        if name.is_empty() {
            i = start + 1;
            continue;
        }
        let (attrs, end) = attributes(html, start + name_end);
        if matches!(
            name,
            "script" | "style" | "template" | "noscript" | "textarea" | "title"
        ) {
            let close = format!("</{name}");
            i = lower[end..].find(&close).map_or(html.len(), |n| end + n);
        } else {
            i = end;
        }
        out.push((name.to_owned(), attrs));
        if i >= bytes.len() {
            break;
        }
    }
    out
}

/// Attributes from `from` up to the tag's `>`, and the position after it.
fn attributes(html: &str, from: usize) -> (Vec<(String, String)>, usize) {
    let bytes = html.as_bytes();
    let mut attrs = vec![];
    let mut i = from;
    loop {
        while i < bytes.len() && (bytes[i].is_ascii_whitespace() || bytes[i] == b'/') {
            i += 1;
        }
        if i >= bytes.len() {
            return (attrs, i);
        }
        if bytes[i] == b'>' {
            return (attrs, i + 1);
        }
        let key_start = i;
        while i < bytes.len()
            && !bytes[i].is_ascii_whitespace()
            && !matches!(bytes[i], b'=' | b'>' | b'/')
        {
            i += 1;
        }
        let key = html[key_start..i].to_ascii_lowercase();
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        let mut value = String::new();
        if i < bytes.len() && bytes[i] == b'=' {
            i += 1;
            while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            match bytes.get(i) {
                Some(&quote @ (b'"' | b'\'')) => {
                    let end = html[i + 1..]
                        .find(quote as char)
                        .map_or(html.len(), |n| i + 1 + n);
                    value = html[i + 1..end].to_owned();
                    i = (end + 1).min(html.len());
                }
                _ => {
                    let start = i;
                    while i < bytes.len() && !bytes[i].is_ascii_whitespace() && bytes[i] != b'>' {
                        i += 1;
                    }
                    value = html[start..i].to_owned();
                }
            }
        }
        if !key.is_empty() {
            attrs.push((key, decode_entities(&value)));
        }
    }
}

/// The few entities that show up in icon URLs.
fn decode_entities(value: &str) -> String {
    if !value.contains('&') {
        return value.to_owned();
    }
    value
        .replace("&amp;", "&")
        .replace("&#38;", "&")
        .replace("&quot;", "\"")
        .replace("&#x2F;", "/")
        .replace("&#47;", "/")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hrefs(candidates: &[Candidate]) -> Vec<&str> {
        candidates.iter().map(|c| c.href.as_str()).collect()
    }

    #[test]
    fn finds_icon_links() {
        let html = r#"<!doctype html><html><head>
            <meta charset=utf-8><title>Shop <link rel=icon href=/not-this.png></title>
            <!-- <link rel="icon" href="/commented.png"> -->
            <script>document.write('<link rel="icon" href="/script.png">')</script>
            <base href="https://cdn.example.com/">
            <LINK REL="Shortcut Icon" HREF="/favicon.ico">
            <link rel=apple-touch-icon sizes=180x180 href='/touch.png?v=2&amp;x=1'>
            <link rel="icon" type="image/svg+xml" href="/icon.svg">
            <link rel="icon" sizes="16x16 32x32" href="/small.png" />
            <link rel="stylesheet" href="/style.css">
            <link rel="mask-icon" href="/mask.svg">
            <link rel="icon" href="">
            </head><body><link rel="icon" href="/body.png"></body>"#;
        let (base, candidates) = icon_links(html);
        assert_eq!(base.as_deref(), Some("https://cdn.example.com/"));
        assert_eq!(
            hrefs(&candidates),
            [
                "/favicon.ico",
                "/touch.png?v=2&x=1",
                "/icon.svg",
                "/small.png"
            ]
        );
        assert_eq!(candidates[1].sizes, [180]);
        assert!(candidates[1].touch);
        assert!(candidates[2].scalable);
        assert_eq!(candidates[3].sizes, [16, 32]);
    }

    #[test]
    fn ranks_sizes_near_64_to_128_first() {
        let c = |href: &str, sizes: &[u32], scalable: bool, touch: bool| Candidate {
            href: href.into(),
            sizes: sizes.to_vec(),
            scalable,
            touch,
        };
        let ranked = rank(vec![
            c("small", &[16, 32], false, false),
            c("unknown", &[], false, false),
            c("touch", &[], false, true),
            c("big", &[512], false, false),
            c("bigger", &[1024], false, false),
            c("svg", &[], true, false),
            c("96", &[96], false, false),
            c("tiny", &[16], false, false),
            c("mixed", &[16, 128], false, false),
        ]);
        assert_eq!(
            hrefs(&ranked),
            [
                "mixed", "96", "svg", "big", "bigger", "touch", "unknown", "small", "tiny"
            ]
        );
    }

    #[test]
    fn survives_broken_markup() {
        for html in [
            "<",
            "<link",
            "<link rel=icon href=\"/a",
            "<!-- open",
            "<script>",
            "<<>>",
            "<link rel=icon href=x",
        ] {
            let _ = icon_links(html);
        }
        let (_, candidates) = icon_links("<link rel=icon href=x");
        assert_eq!(hrefs(&candidates), ["x"]);
    }
}
