//! The SSH agent protocol (draft-miller-ssh-agent): a 32-bit length, a type byte, then SSH-encoded
//! fields. Only what an agent that lists keys and signs needs.

/// Far more than any request: a sign request carries a session hash or an SSHSIG digest.
pub const MAX_MESSAGE: usize = 256 * 1024;

const FAILURE: u8 = 5;
const REQUEST_IDENTITIES: u8 = 11;
const IDENTITIES_ANSWER: u8 = 12;
const SIGN_REQUEST: u8 = 13;
const SIGN_RESPONSE: u8 = 14;

/// A request's body, parsed.
#[derive(Debug, PartialEq, Eq)]
pub enum Request {
    Identities,
    Sign {
        key: Vec<u8>,
        data: Vec<u8>,
        flags: u32,
    },
    /// Everything this agent refuses: adding and removing keys, locking, extensions.
    Unsupported,
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, count: usize) -> Option<&'a [u8]> {
        if self.0.len() < count {
            return None;
        }
        let (taken, rest) = self.0.split_at(count);
        self.0 = rest;
        Some(taken)
    }

    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_be_bytes(self.take(4)?.try_into().ok()?))
    }

    fn string(&mut self) -> Option<&'a [u8]> {
        let count = self.u32()? as usize;
        self.take(count)
    }
}

/// Parses a message's body (type byte and fields). `None` for a malformed one.
pub fn parse(body: &[u8]) -> Option<Request> {
    let (kind, fields) = body.split_first()?;
    match *kind {
        REQUEST_IDENTITIES => Some(Request::Identities),
        SIGN_REQUEST => {
            let mut reader = Reader(fields);
            let key = reader.string()?.to_vec();
            let data = reader.string()?.to_vec();
            let flags = reader.u32()?;
            Some(Request::Sign { key, data, flags })
        }
        _ => Some(Request::Unsupported),
    }
}

fn put_string(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// A full message: the length, then `body`.
fn frame(body: Vec<u8>) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 4);
    put_string(&mut out, &body);
    out
}

pub fn failure() -> Vec<u8> {
    frame(vec![FAILURE])
}

pub fn identities(identities: &[crate::Identity]) -> Vec<u8> {
    let mut body = vec![IDENTITIES_ANSWER];
    body.extend_from_slice(&(identities.len() as u32).to_be_bytes());
    for identity in identities {
        put_string(&mut body, &identity.blob);
        put_string(&mut body, identity.comment.as_bytes());
    }
    frame(body)
}

pub fn signature(signature: &[u8]) -> Vec<u8> {
    let mut body = vec![SIGN_RESPONSE];
    put_string(&mut body, signature);
    frame(body)
}

/// What a signature is for, read from the data being signed, for the approval prompt. It comes
/// from the program asking, so it can't be trusted: the prompt says so by naming the program.
#[derive(Debug, PartialEq, Eq)]
pub enum Purpose {
    /// Logging in to a server, as this user.
    Login {
        user: String,
    },
    /// A file or Git object (`ssh-keygen -Y sign`), in this namespace.
    Signature {
        namespace: String,
    },
    Unknown,
}

/// RFC 4252's `SSH_MSG_USERAUTH_REQUEST` after the session id, or OpenSSH's SSHSIG preamble.
pub fn purpose(data: &[u8]) -> Purpose {
    if let Some(rest) = data.strip_prefix(b"SSHSIG") {
        let namespace = Reader(rest).string().map(String::from_utf8_lossy);
        return namespace.map_or(Purpose::Unknown, |namespace| Purpose::Signature {
            namespace: namespace.into_owned(),
        });
    }
    let mut reader = Reader(data);
    let login = (|| {
        reader.string()?;
        if reader.take(1)? != [50] {
            return None;
        }
        let user = String::from_utf8_lossy(reader.string()?).into_owned();
        let service = reader.string()?;
        let method = reader.string()?;
        // OpenSSH 8.9 and later use the host-bound method where the server offers it.
        let public_key = method == b"publickey" || method == b"publickey-hostbound-v00@openssh.com";
        (service == b"ssh-connection" && public_key).then_some(user)
    })();
    login.map_or(Purpose::Unknown, |user| Purpose::Login { user })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Identity;

    fn sign_request() -> Vec<u8> {
        let mut body = vec![SIGN_REQUEST];
        put_string(&mut body, b"key");
        put_string(&mut body, b"data");
        body.extend_from_slice(&4u32.to_be_bytes());
        body
    }

    #[test]
    fn requests() {
        assert_eq!(parse(&[REQUEST_IDENTITIES]), Some(Request::Identities));
        assert_eq!(
            parse(&sign_request()),
            Some(Request::Sign {
                key: b"key".to_vec(),
                data: b"data".to_vec(),
                flags: 4
            })
        );
        // Add identity, remove all, lock, extension.
        for kind in [17, 19, 22, 27] {
            assert_eq!(parse(&[kind]), Some(Request::Unsupported));
        }
    }

    #[test]
    fn malformed_requests_are_refused_without_panicking() {
        assert_eq!(parse(&[]), None);
        let whole = sign_request();
        for length in 1..whole.len() {
            assert_eq!(parse(&whole[..length]), None, "{length}");
        }
        let huge = [&[SIGN_REQUEST][..], &u32::MAX.to_be_bytes()].concat();
        assert_eq!(parse(&huge), None);
    }

    #[test]
    fn replies_are_framed() {
        assert_eq!(failure(), [0, 0, 0, 1, 5]);
        assert_eq!(identities(&[]), [0, 0, 0, 5, 12, 0, 0, 0, 0]);
        assert_eq!(
            identities(&[Identity {
                blob: vec![1, 2],
                comment: "a".into()
            }]),
            [
                0, 0, 0, 16, 12, 0, 0, 0, 1, 0, 0, 0, 2, 1, 2, 0, 0, 0, 1, b'a'
            ]
        );
        assert_eq!(signature(b"xy"), [0, 0, 0, 7, 14, 0, 0, 0, 2, b'x', b'y']);
    }

    #[test]
    fn purposes() {
        let mut login = Vec::new();
        put_string(&mut login, b"session id");
        login.push(50);
        put_string(&mut login, b"git");
        put_string(&mut login, b"ssh-connection");
        put_string(&mut login, b"publickey");
        login.push(1);
        assert_eq!(purpose(&login), Purpose::Login { user: "git".into() });
        let mut bound = Vec::new();
        put_string(&mut bound, b"session id");
        bound.push(50);
        put_string(&mut bound, b"git");
        put_string(&mut bound, b"ssh-connection");
        put_string(&mut bound, b"publickey-hostbound-v00@openssh.com");
        assert_eq!(purpose(&bound), Purpose::Login { user: "git".into() });

        let mut signature = b"SSHSIG".to_vec();
        put_string(&mut signature, b"git");
        assert_eq!(
            purpose(&signature),
            Purpose::Signature {
                namespace: "git".into()
            }
        );
        assert_eq!(purpose(b"other"), Purpose::Unknown);
        assert_eq!(purpose(&[]), Purpose::Unknown);
    }
}
