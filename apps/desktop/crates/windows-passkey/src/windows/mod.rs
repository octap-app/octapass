//! The Windows side of the provider: only this module touches Windows' APIs, and only its calls
//! are `unsafe`.

mod api;
mod com;
mod ffi;
mod host;

pub use api::{Status, open_settings, register, replace_credentials, status, unregister};
pub use com::serve;
pub use host::Words;
