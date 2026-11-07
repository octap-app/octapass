//! Exporting a vault (plan 07): the Octa Pass JSON document, the encrypted export with every
//! attachment, and the FIDO Credential Exchange Format. Importing them back is in
//! [`crate::import`] (`octapass` and `cxf` sources).

mod archive;
pub mod cxf;
mod document;
mod zip;

pub use archive::{
    ArchiveEntry, ArchiveFiles, ArchiveReader, ArchiveWriter, CHUNK_LEN, EXPORT_KDF, HEADER_LEN,
    ITEMS_ENTRY, is_archive, read_archive,
};
pub use document::{ExportDocument, ExportItem, ExportVault, without_attachment_keys};
