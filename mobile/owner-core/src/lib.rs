//! Shared by the laptop CLI and the phone apps, so both sides compute the
//! same bytes and the same hashes (docs/MOBILE_OWNER_DESIGN.md §7).

pub mod abi;
pub mod enroll;
pub mod fingerprint;
pub mod kernel;
pub mod request;
pub mod user_op;

pub use hw_signer::{PublicKey, Signature};
