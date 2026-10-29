//! Re-export of the session name types: they are shared by both hops of the
//! protocol (the client resolves one, the daemon routes by it, `sp-serve`
//! re-validates it), so `sp-proto` owns the definition.

pub use sp_proto::session::{DEFAULT_NAME, MAX_LEN, SessionId, SessionNameError};
