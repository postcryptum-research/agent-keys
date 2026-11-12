//! Shared by the laptop CLI and the phone apps, so both sides compute the
//! same bytes and the same hashes (docs/MOBILE_OWNER_DESIGN.md §7).

pub mod abi;
pub mod enroll;
#[cfg(feature = "ffi")]
pub mod ffi;
pub mod fingerprint;
pub mod kernel;
pub mod request;
pub mod review;
pub mod user_op;

pub use hw_signer::{PublicKey, Signature};

#[cfg(feature = "ffi")]
uniffi::setup_scaffolding!();
