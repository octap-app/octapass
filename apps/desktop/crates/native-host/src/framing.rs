//! Native messaging framing: each message is UTF-8 JSON preceded by its length as a 32-bit
//! unsigned integer in native byte order.

use std::io::{self, Read, Write};

/// Browsers refuse messages from a host larger than 1 MB.
pub const MAX_TO_BROWSER: usize = 1024 * 1024;
/// Requests are tiny; anything this large is a broken or hostile peer.
pub const MAX_FROM_BROWSER: usize = 64 * 1024;

/// Reads one message. `None` when the browser closed the pipe (the extension disconnected).
pub fn read_message(reader: &mut impl Read) -> io::Result<Option<Vec<u8>>> {
    let mut length = [0u8; 4];
    match reader.read_exact(&mut length) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error),
    }
    let length = u32::from_ne_bytes(length) as usize;
    if length > MAX_FROM_BROWSER {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "message too large",
        ));
    }
    let mut message = vec![0u8; length];
    reader.read_exact(&mut message)?;
    Ok(Some(message))
}

pub fn write_message(writer: &mut impl Write, message: &[u8]) -> io::Result<()> {
    if message.len() > MAX_TO_BROWSER {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "reply too large",
        ));
    }
    let length = u32::try_from(message.len()).expect("checked above");
    writer.write_all(&length.to_ne_bytes())?;
    writer.write_all(message)?;
    writer.flush()
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn messages_round_trip() {
        let mut buffer = Vec::new();
        write_message(&mut buffer, br#"{"type":"unlock"}"#).unwrap();
        write_message(&mut buffer, b"{}").unwrap();
        assert_eq!(&buffer[..4], &17u32.to_ne_bytes());
        let mut reader = Cursor::new(buffer);
        assert_eq!(
            read_message(&mut reader).unwrap().unwrap(),
            br#"{"type":"unlock"}"#
        );
        assert_eq!(read_message(&mut reader).unwrap().unwrap(), b"{}");
        assert_eq!(read_message(&mut reader).unwrap(), None);
    }

    #[test]
    fn oversized_and_truncated_messages_are_errors() {
        let mut huge = Cursor::new((MAX_FROM_BROWSER as u32 + 1).to_ne_bytes().to_vec());
        assert_eq!(
            read_message(&mut huge).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        let mut truncated = Cursor::new([&5u32.to_ne_bytes()[..], b"ab"].concat());
        assert_eq!(
            read_message(&mut truncated).unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
        assert!(write_message(&mut Vec::new(), &vec![b' '; MAX_TO_BROWSER + 1]).is_err());
    }
}
