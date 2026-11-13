//! Shared by the laptop CLI and the phone apps, so both sides compute the
//! same bytes and the same hashes (docs/MOBILE_OWNER_DESIGN.md §7).

pub mod abi;
pub mod enroll;
pub mod facts;
#[cfg(feature = "ffi")]
pub mod ffi;
pub mod fingerprint;
pub mod health;
pub mod kernel;
pub mod request;
pub mod review;
pub mod user_op;

pub use hw_signer::{PublicKey, Signature};

/// This crate's version, marked when the build carries the test chain's facts
/// (`facts.rs`): such a build is for development and says so wherever its
/// version is shown.
pub fn version() -> &'static str {
    if cfg!(feature = "test-chains") {
        concat!(env!("CARGO_PKG_VERSION"), "+test-chains")
    } else {
        env!("CARGO_PKG_VERSION")
    }
}

#[cfg(feature = "ffi")]
uniffi::setup_scaffolding!();
