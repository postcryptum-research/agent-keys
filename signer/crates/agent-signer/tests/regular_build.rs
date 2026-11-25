//! What a regular build (no test feature) does not contain.
#![cfg(not(feature = "insecure-software-keys"))]

use std::process::Command;

/// #178: the software backend holds a key in memory in the clear. It is
/// linked only into the test build; a regular build has no such code, and
/// `vector` says so in place of signing with a key it made in memory.
#[test]
fn the_software_backend_is_not_in_a_regular_build() {
    for args in [&["vector", "--message", "x"][..], &["vector", "--message", "x", "--backend", "software"][..]] {
        let out = Command::new(env!("CARGO_BIN_EXE_agent-signer")).args(args).output().expect("run agent-signer");
        let said = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
        assert!(!out.status.success(), "{said}");
        assert!(said.contains("the software backend is not in this build"), "{said}");
    }
}
