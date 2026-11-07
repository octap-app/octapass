//! The little binary encoding of the store file: fixed-width little-endian integers, and strings
//! and byte strings prefixed with their `u32` length.

use octapass_core::encoding::{b64_decode, b64_encode};
use uuid::Uuid;

use crate::error::{OctaPassError, Result};

#[derive(Default)]
pub(super) struct Writer(Vec<u8>);

impl Writer {
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    pub fn raw(&mut self, bytes: &[u8]) {
        self.0.extend_from_slice(bytes);
    }

    pub fn u8(&mut self, value: u8) {
        self.0.push(value);
    }

    pub fn u32(&mut self, value: u32) {
        self.raw(&value.to_le_bytes());
    }

    pub fn u64(&mut self, value: u64) {
        self.raw(&value.to_le_bytes());
    }

    pub fn len(&mut self, len: usize) -> Result<()> {
        self.u32(u32::try_from(len).map_err(|_| OctaPassError::InvalidStore)?);
        Ok(())
    }

    pub fn bytes(&mut self, bytes: &[u8]) -> Result<()> {
        self.len(bytes.len())?;
        self.raw(bytes);
        Ok(())
    }

    pub fn str(&mut self, text: &str) -> Result<()> {
        self.bytes(text.as_bytes())
    }

    pub fn opt_str(&mut self, text: Option<&str>) -> Result<()> {
        match text {
            Some(text) => {
                self.u8(1);
                self.str(text)
            }
            None => {
                self.u8(0);
                Ok(())
            }
        }
    }

    /// A base64url value (keys, envelopes) stored as its raw bytes.
    pub fn b64(&mut self, text: &str) -> Result<()> {
        self.bytes(&b64_decode(text).map_err(|_| OctaPassError::InvalidResponse)?)
    }

    /// A vault or item id, as its 16 bytes.
    pub fn id(&mut self, id: &str) -> Result<()> {
        let uuid = Uuid::try_parse(id).map_err(|_| OctaPassError::InvalidResponse)?;
        self.raw(uuid.as_bytes());
        Ok(())
    }
}

pub(super) struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self(bytes)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn raw(&mut self, len: usize) -> Result<&'a [u8]> {
        if self.0.len() < len {
            return Err(OctaPassError::InvalidStore);
        }
        let (head, tail) = self.0.split_at(len);
        self.0 = tail;
        Ok(head)
    }

    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.raw(1)?[0])
    }

    pub fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    pub fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    pub fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        Ok(self.raw(N)?.try_into().expect("raw returned N bytes"))
    }

    /// A count of entries that follow, each at least `min_size` bytes: a damaged count can't
    /// make the reader allocate more than the file holds.
    pub fn count(&mut self, min_size: usize) -> Result<usize> {
        let count = self.u32()? as usize;
        if count.saturating_mul(min_size) > self.0.len() {
            return Err(OctaPassError::InvalidStore);
        }
        Ok(count)
    }

    pub fn bytes(&mut self) -> Result<&'a [u8]> {
        let len = self.u32()? as usize;
        self.raw(len)
    }

    pub fn str(&mut self) -> Result<String> {
        String::from_utf8(self.bytes()?.to_vec()).map_err(|_| OctaPassError::InvalidStore)
    }

    pub fn opt_str(&mut self) -> Result<Option<String>> {
        match self.u8()? {
            0 => Ok(None),
            1 => self.str().map(Some),
            _ => Err(OctaPassError::InvalidStore),
        }
    }

    pub fn b64(&mut self) -> Result<String> {
        Ok(b64_encode(self.bytes()?))
    }

    pub fn id(&mut self) -> Result<String> {
        Ok(Uuid::from_bytes(self.array()?).hyphenated().to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_round_trip() {
        let id = "0192f0c8-0000-7000-8000-00000000000a";
        let mut writer = Writer::default();
        writer.u8(7);
        writer.u64(u64::MAX - 1);
        writer.str("héllo").unwrap();
        writer.opt_str(None).unwrap();
        writer.opt_str(Some("")).unwrap();
        writer.b64("AQID").unwrap();
        writer.id(&id.to_uppercase()).unwrap();
        let bytes = writer.into_bytes();

        let mut reader = Reader::new(&bytes);
        assert_eq!(reader.u8().unwrap(), 7);
        assert_eq!(reader.u64().unwrap(), u64::MAX - 1);
        assert_eq!(reader.str().unwrap(), "héllo");
        assert_eq!(reader.opt_str().unwrap(), None);
        assert_eq!(reader.opt_str().unwrap(), Some(String::new()));
        assert_eq!(reader.b64().unwrap(), "AQID");
        assert_eq!(reader.id().unwrap(), id, "ids come back canonical");
        assert!(reader.is_empty());
    }

    #[test]
    fn truncated_or_inflated_data_is_refused() {
        let mut writer = Writer::default();
        writer.str("abc").unwrap();
        let bytes = writer.into_bytes();
        assert_eq!(
            Reader::new(&bytes[..5]).str(),
            Err(OctaPassError::InvalidStore)
        );
        assert_eq!(
            Reader::new(&u32::MAX.to_le_bytes()).count(1),
            Err(OctaPassError::InvalidStore)
        );
    }

    #[test]
    fn values_from_the_server_are_checked_before_storing() {
        let mut writer = Writer::default();
        assert_eq!(writer.id("not-a-uuid"), Err(OctaPassError::InvalidResponse));
        assert_eq!(writer.b64("!!"), Err(OctaPassError::InvalidResponse));
    }
}
