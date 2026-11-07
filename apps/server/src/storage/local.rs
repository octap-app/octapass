//! Attachments as files in a directory, by default `<data dir>/attachments`.

use std::path::PathBuf;

use axum::body::Body;
use tokio_util::io::ReaderStream;

use super::{BoxFuture, Object, ObjectStorage, StorageError, Upload};

pub struct LocalStorage {
    dir: PathBuf,
}

impl LocalStorage {
    pub fn new(dir: PathBuf) -> Result<Self, StorageError> {
        std::fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }

    /// Keys are hex, so they're always plain file names.
    fn path(&self, key: &str) -> Result<PathBuf, StorageError> {
        if key.is_empty() || !key.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(StorageError::Remote(format!("invalid object key {key:?}")));
        }
        Ok(self.dir.join(key))
    }
}

impl ObjectStorage for LocalStorage {
    fn put<'a>(&'a self, key: &'a str, upload: Upload) -> BoxFuture<'a, Result<(), StorageError>> {
        Box::pin(async move {
            let path = self.path(key)?;
            // The spool directory is usually on the same file system, so this is a rename.
            if tokio::fs::rename(upload.path(), &path).await.is_err() {
                tokio::fs::copy(upload.path(), &path).await?;
            }
            Ok(())
        })
    }

    fn get<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<Option<Object>, StorageError>> {
        Box::pin(async move {
            let file = match tokio::fs::File::open(self.path(key)?).await {
                Ok(file) => file,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(error) => return Err(error.into()),
            };
            let len = file.metadata().await?.len();
            Ok(Some(Object {
                len,
                body: Body::from_stream(ReaderStream::with_capacity(file, 64 * 1024)),
            }))
        })
    }

    fn delete<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<(), StorageError>> {
        Box::pin(async move {
            match tokio::fs::remove_file(self.path(key)?).await {
                Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(error.into()),
                _ => Ok(()),
            }
        })
    }

    fn check(&self) -> BoxFuture<'_, Result<(), StorageError>> {
        Box::pin(async move {
            tokio::fs::metadata(&self.dir).await?;
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use http_body_util::BodyExt;

    use super::*;
    use crate::storage::spool;

    #[tokio::test]
    async fn stores_reads_and_deletes() {
        let dir = tempfile::tempdir().unwrap();
        let storage = LocalStorage::new(dir.path().join("files")).unwrap();
        let upload = spool(dir.path(), Body::from("ciphertext"), 10)
            .await
            .unwrap();
        storage.put("abc123", upload).await.unwrap();

        let object = storage.get("abc123").await.unwrap().unwrap();
        assert_eq!(object.len, 10);
        let bytes = object.body.collect().await.unwrap().to_bytes();
        assert_eq!(&bytes[..], b"ciphertext");

        storage.delete("abc123").await.unwrap();
        assert!(storage.get("abc123").await.unwrap().is_none());
        storage.delete("abc123").await.unwrap();
        assert!(storage.get("../secrets").await.is_err());
        storage.check().await.unwrap();
    }
}
