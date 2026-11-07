//! Attachments: files encrypted a chunk at a time. The file key stays inside the handles; JS gets
//! only the wrapped key (for the item's details) and the ciphertext or plaintext pieces.

use octapass_core::attachment::{self, Decryptor, Encryptor};
use rand_core::OsRng;
use wasm_bindgen::prelude::*;

use crate::account::Session;
use crate::{flow_finished, js_error};

/// The size of a file once encrypted: what the server stores and counts against the quota.
#[wasm_bindgen(js_name = attachmentEncryptedSize)]
pub fn attachment_encrypted_size(size: f64) -> Result<f64, JsValue> {
    if !(size >= 0.0 && size <= 2f64.powi(53) && size.fract() == 0.0) {
        return Err(crate::invalid_argument("size"));
    }
    Ok(attachment::encrypted_len(size as u64) as f64)
}

/// Encrypts one file. Feed it with `push` and end with `finish`; the outputs, in order, are the
/// body of `PUT /v1/vaults/{vaultId}/items/{itemId}/attachments/{attachmentId}`.
#[wasm_bindgen]
pub struct AttachmentEncryptor {
    inner: Option<Encryptor>,
    wrapped_key: String,
}

#[wasm_bindgen]
impl AttachmentEncryptor {
    /// The file key wrapped by the item key: the `key` of the attachment in the item's details.
    #[wasm_bindgen(getter, js_name = wrappedKey)]
    pub fn wrapped_key(&self) -> String {
        self.wrapped_key.clone()
    }

    /// Adds plaintext; returns the ciphertext ready so far (possibly empty).
    pub fn push(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, JsValue> {
        let inner = self.inner.as_mut().ok_or_else(flow_finished)?;
        inner.push(plaintext).map_err(js_error)
    }

    /// Returns the rest of the ciphertext. The handle can't be used afterwards.
    pub fn finish(&mut self) -> Result<Vec<u8>, JsValue> {
        let inner = self.inner.take().ok_or_else(flow_finished)?;
        inner.finish().map_err(js_error)
    }
}

/// Decrypts one file. Plaintext from `push` is verified, but the file is only known to be whole
/// once `finish` succeeds.
#[wasm_bindgen]
pub struct AttachmentDecryptor {
    inner: Option<Decryptor>,
}

#[wasm_bindgen]
impl AttachmentDecryptor {
    /// Adds ciphertext; returns the plaintext of the chunks completed so far (possibly empty).
    pub fn push(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, JsValue> {
        let inner = self.inner.as_mut().ok_or_else(flow_finished)?;
        inner.push(ciphertext).map(|p| p.to_vec()).map_err(js_error)
    }

    /// Returns the last plaintext. Throws `decryption_failed` if the file was cut short or changed.
    pub fn finish(&mut self) -> Result<Vec<u8>, JsValue> {
        let inner = self.inner.take().ok_or_else(flow_finished)?;
        inner.finish().map(|p| p.to_vec()).map_err(js_error)
    }
}

#[wasm_bindgen]
impl Session {
    /// A new attachment for an item: a fresh file key, wrapped by the item key (from the item's
    /// current `encryptedItemKey`), and the encryptor for the file.
    #[wasm_bindgen(js_name = newAttachment)]
    pub fn new_attachment(
        &self,
        #[wasm_bindgen(js_name = vaultId)] vault_id: String,
        #[wasm_bindgen(js_name = itemId)] item_id: String,
        #[wasm_bindgen(js_name = encryptedItemKey)] encrypted_item_key: String,
        #[wasm_bindgen(js_name = attachmentId)] attachment_id: String,
    ) -> Result<AttachmentEncryptor, JsValue> {
        let (wrapped_key, encryptor) = self
            .inner
            .new_attachment(
                &vault_id,
                &item_id,
                &encrypted_item_key,
                &attachment_id,
                &mut OsRng,
            )
            .map_err(js_error)?;
        Ok(AttachmentEncryptor {
            inner: Some(encryptor),
            wrapped_key,
        })
    }

    /// A decryptor for an attachment, from the `key` stored with it in the item's details.
    #[wasm_bindgen(js_name = openAttachment)]
    pub fn open_attachment(
        &self,
        #[wasm_bindgen(js_name = vaultId)] vault_id: String,
        #[wasm_bindgen(js_name = itemId)] item_id: String,
        #[wasm_bindgen(js_name = encryptedItemKey)] encrypted_item_key: String,
        #[wasm_bindgen(js_name = attachmentId)] attachment_id: String,
        #[wasm_bindgen(js_name = wrappedKey)] wrapped_key: String,
    ) -> Result<AttachmentDecryptor, JsValue> {
        let decryptor = self
            .inner
            .open_attachment(
                &vault_id,
                &item_id,
                &encrypted_item_key,
                &attachment_id,
                &wrapped_key,
            )
            .map_err(js_error)?;
        Ok(AttachmentDecryptor {
            inner: Some(decryptor),
        })
    }
}
