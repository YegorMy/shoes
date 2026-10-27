//! AnyTLS protocol implementation for shoes
//!
//! AnyTLS is a TLS-based proxy protocol with:
//! - Session multiplexing: Multiple proxy streams over a single TLS connection
//! - Configurable padding: First N packets are padded to obscure fingerprints
//! - Password authentication: SHA256-based user authentication

mod anytls_client_handler;
mod anytls_client_session;
mod anytls_padding;
mod anytls_server_handler;
mod anytls_server_session;
mod anytls_stream;
mod anytls_types;
mod write_eof;

pub use anytls_client_handler::AnyTlsClientHandler;
pub use anytls_client_session::AnyTlsClientSession;
pub use anytls_padding::PaddingFactory;
pub use anytls_server_handler::AnyTlsServerHandler;
pub use anytls_stream::AnyTlsStream;
pub use write_eof::{WriteEofClientSession, WriteEofError, WriteEofOptions};

#[cfg(test)]
mod uot_reply_tests;
#[cfg(test)]
mod write_eof_offer_tests;
#[cfg(test)]
mod write_eof_settlement_tests;
#[cfg(test)]
mod write_eof_tests;
