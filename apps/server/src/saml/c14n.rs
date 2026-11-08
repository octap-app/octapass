//! Exclusive XML Canonicalization 1.0, without comments
//! (<https://www.w3.org/TR/xml-exc-c14n/>), of one element's subtree, optionally leaving out one
//! descendant (the enveloped-signature transform). Only what SAML signatures need.
//!
//! The parser has already normalised line endings and attribute values and resolved character
//! references, so this works on the data model, as the specification does. Prefixes come from the
//! source text, because a namespace can be bound to more than one prefix in scope.

use std::collections::BTreeMap;

use roxmltree::{Node, NodeId, NodeType};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("the XML can't be canonicalised")]
pub struct C14nError;

/// Prefixes the `InclusiveNamespaces PrefixList` names. `None` is `#default`.
pub type InclusivePrefixes = [Option<String>];

/// The canonical form of `root` and everything under it, without `skip`.
pub fn exclusive(
    root: Node<'_, '_>,
    skip: Option<NodeId>,
    inclusive: &InclusivePrefixes,
) -> Result<Vec<u8>, C14nError> {
    if !root.is_element() {
        return Err(C14nError);
    }
    let mut writer = Writer {
        out: Vec::with_capacity(4096),
        input: root.document().input_text(),
        skip,
        inclusive,
    };
    writer.element(root, &BTreeMap::new())?;
    Ok(writer.out)
}

struct Writer<'a> {
    out: Vec<u8>,
    input: &'a str,
    skip: Option<NodeId>,
    inclusive: &'a InclusivePrefixes,
}

/// The qualified name of an element as written: what follows `<`, up to whitespace, `/` or `>`.
fn element_qname<'i>(input: &'i str, node: Node<'_, '_>) -> Result<&'i str, C14nError> {
    let source = input.get(node.range()).ok_or(C14nError)?;
    let rest = source.strip_prefix('<').ok_or(C14nError)?;
    let end = rest
        .find(|c: char| c.is_ascii_whitespace() || c == '/' || c == '>')
        .ok_or(C14nError)?;
    Ok(&rest[..end])
}

fn prefix_of(qname: &str) -> &str {
    qname.split_once(':').map_or("", |(prefix, _)| prefix)
}

impl Writer<'_> {
    /// `rendered` holds the namespace declarations output ancestors rendered: prefix (`""` for
    /// the default namespace) to URI.
    fn element(
        &mut self,
        node: Node<'_, '_>,
        rendered: &BTreeMap<String, String>,
    ) -> Result<(), C14nError> {
        let qname = element_qname(self.input, node)?;
        let mut needed: BTreeMap<String, String> = BTreeMap::new();
        let mut consider = |prefix: &str, uri: &str| {
            if prefix == "xml" {
                return;
            }
            let current = rendered.get(prefix).map_or("", String::as_str);
            if current != uri {
                needed.insert(prefix.to_owned(), uri.to_owned());
            }
        };

        // Visibly utilised: the element's own prefix (or the default namespace) ...
        consider(
            prefix_of(qname),
            node.tag_name().namespace().unwrap_or_default(),
        );
        // ... and the prefix of each attribute. An attribute without one has no namespace.
        let mut attributes = Vec::new();
        for attribute in node.attributes() {
            let attr_qname = self.input.get(attribute.range_qname()).ok_or(C14nError)?;
            let prefix = prefix_of(attr_qname);
            if !prefix.is_empty() {
                let uri = attribute.namespace().ok_or(C14nError)?;
                consider(prefix, uri);
            }
            attributes.push((
                attribute.namespace().unwrap_or_default(),
                attribute.name(),
                attr_qname,
                attribute.value(),
            ));
        }
        // Prefixes on the InclusiveNamespaces list are rendered as inclusive canonicalisation
        // would: whenever they're in scope and not already rendered with that value.
        for prefix in self.inclusive {
            let uri = node.lookup_namespace_uri(prefix.as_deref());
            match (prefix.as_deref(), uri) {
                (Some(prefix), Some(uri)) => consider(prefix, uri),
                (None, uri) => consider("", uri.unwrap_or_default()),
                (Some(_), None) => {}
            }
        }

        attributes.sort_by(|a, b| (a.0, a.1).cmp(&(b.0, b.1)));
        self.out.push(b'<');
        self.out.extend_from_slice(qname.as_bytes());
        for (prefix, uri) in &needed {
            if prefix.is_empty() {
                self.out.extend_from_slice(b" xmlns=\"");
            } else {
                self.out.extend_from_slice(b" xmlns:");
                self.out.extend_from_slice(prefix.as_bytes());
                self.out.extend_from_slice(b"=\"");
            }
            escape_attribute(&mut self.out, uri);
            self.out.push(b'"');
        }
        for (_, _, attr_qname, value) in attributes {
            self.out.push(b' ');
            self.out.extend_from_slice(attr_qname.as_bytes());
            self.out.extend_from_slice(b"=\"");
            escape_attribute(&mut self.out, value);
            self.out.push(b'"');
        }
        self.out.push(b'>');

        let inner = if needed.is_empty() {
            None
        } else {
            let mut inner = rendered.clone();
            inner.extend(needed);
            Some(inner)
        };
        let inner = inner.as_ref().unwrap_or(rendered);
        for child in node.children() {
            if Some(child.id()) == self.skip {
                continue;
            }
            match child.node_type() {
                NodeType::Element => self.element(child, inner)?,
                NodeType::Text => escape_text(&mut self.out, child.text().unwrap_or_default()),
                NodeType::PI => {
                    let pi = child.pi().ok_or(C14nError)?;
                    self.out.extend_from_slice(b"<?");
                    self.out.extend_from_slice(pi.target.as_bytes());
                    if let Some(value) = pi.value {
                        self.out.push(b' ');
                        self.out.extend_from_slice(value.as_bytes());
                    }
                    self.out.extend_from_slice(b"?>");
                }
                NodeType::Comment | NodeType::Root => {}
            }
        }
        self.out.extend_from_slice(b"</");
        self.out.extend_from_slice(qname.as_bytes());
        self.out.push(b'>');
        Ok(())
    }
}

fn escape_text(out: &mut Vec<u8>, text: &str) {
    for c in text.chars() {
        match c {
            '&' => out.extend_from_slice(b"&amp;"),
            '<' => out.extend_from_slice(b"&lt;"),
            '>' => out.extend_from_slice(b"&gt;"),
            '\r' => out.extend_from_slice(b"&#xD;"),
            c => {
                let mut buf = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            }
        }
    }
}

fn escape_attribute(out: &mut Vec<u8>, text: &str) {
    for c in text.chars() {
        match c {
            '&' => out.extend_from_slice(b"&amp;"),
            '<' => out.extend_from_slice(b"&lt;"),
            '"' => out.extend_from_slice(b"&quot;"),
            '\t' => out.extend_from_slice(b"&#x9;"),
            '\n' => out.extend_from_slice(b"&#xA;"),
            '\r' => out.extend_from_slice(b"&#xD;"),
            c => {
                let mut buf = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use roxmltree::Document;

    fn c14n_of(xml: &str, path: &[&str], inclusive: &[Option<String>]) -> String {
        let doc = Document::parse(xml).unwrap();
        let mut node = doc.root_element();
        for name in path {
            node = node
                .children()
                .find(|child| child.tag_name().name() == *name)
                .unwrap();
        }
        String::from_utf8(exclusive(node, None, inclusive).unwrap()).unwrap()
    }

    #[test]
    fn a_whole_document_matches_libxml2() {
        // What `xmllint --exc-c14n` (libxml2 2.9.13) prints, less the comment it keeps.
        let xml = "<?xml version=\"1.0\"?>\n<a:root xmlns:a=\"urn:a\" xmlns:unused=\"urn:u\" \
                   z=\"1\" b=\"tab\there\" a:x=\"&lt;&amp;&quot;\"><empty/>\r\n<!-- gone -->\
                   <![CDATA[<raw> & ]]>&#13;<?pi data?><b:c xmlns:b=\"urn:b\" xmlns=\"urn:d\">\
                   <d>t&gt;</d></b:c></a:root>";
        assert_eq!(
            c14n_of(xml, &[], &[]),
            "<a:root xmlns:a=\"urn:a\" b=\"tab here\" z=\"1\" a:x=\"&lt;&amp;&quot;\"><empty></empty>\n\
             &lt;raw&gt; &amp; &#xD;<?pi data?><b:c xmlns:b=\"urn:b\"><d xmlns=\"urn:d\">t&gt;</d></b:c></a:root>"
        );
    }

    #[test]
    fn a_subtree_renders_only_the_namespaces_it_uses() {
        let xml = "<r:outer xmlns:r=\"urn:r\" xmlns:s=\"urn:s\" xmlns=\"urn:default\" \
                   xmlns:xs=\"urn:xs\"><s:inner r:at=\"v\"><plain/><s:deep/></s:inner></r:outer>";
        assert_eq!(
            c14n_of(xml, &["inner"], &[]),
            "<s:inner xmlns:r=\"urn:r\" xmlns:s=\"urn:s\" r:at=\"v\">\
             <plain xmlns=\"urn:default\"></plain><s:deep></s:deep></s:inner>"
        );
        // An InclusiveNamespaces prefix is rendered even though nothing visibly uses it.
        assert_eq!(
            c14n_of(xml, &["inner"], &[Some("xs".into())]),
            "<s:inner xmlns:r=\"urn:r\" xmlns:s=\"urn:s\" xmlns:xs=\"urn:xs\" r:at=\"v\">\
             <plain xmlns=\"urn:default\"></plain><s:deep></s:deep></s:inner>"
        );
    }

    #[test]
    fn an_undeclared_default_namespace_is_cleared_under_a_rendered_one() {
        let xml = "<a xmlns=\"urn:x\"><b xmlns=\"\"><c/></b></a>";
        assert_eq!(
            c14n_of(xml, &[], &[]),
            "<a xmlns=\"urn:x\"><b xmlns=\"\"><c></c></b></a>"
        );
        // Starting at b, nothing rendered a default namespace, so there's nothing to clear.
        assert_eq!(c14n_of(xml, &["b"], &[]), "<b><c></c></b>");
    }

    #[test]
    fn the_enveloped_signature_is_left_out() {
        let xml = "<a ID=\"x\"><s/> <b/></a>";
        let doc = Document::parse(xml).unwrap();
        let root = doc.root_element();
        let signature = root.first_element_child().unwrap();
        let out = exclusive(root, Some(signature.id()), &[]).unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "<a ID=\"x\"> <b></b></a>");
    }
}
