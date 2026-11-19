//! The CLI's TPM key commands against a real TPM 2.0, or a software one named
//! by `TPM2TOOLS_TCTI`.
//!
//! Run: `cargo test -p agent-signer --features tpm --test tpm_cli -- --ignored`
//! (`scripts/tpm-check.sh` does).
#![cfg(feature = "tpm")]

use std::process::{Command, Output};

fn cli(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_agent-signer")).args(args).output().expect("run agent-signer")
}

fn said(out: &Output) -> String {
    format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr))
}

/// #43: `key check` had no `--pcrs`, so a PCR-sealed key could be checked
/// only by an operation through a config. PCR 16 is the resettable debug
/// register: sealing to it binds the key to nothing that a reboot changes.
#[test]
#[ignore = "requires a TPM"]
fn key_check_checks_a_sealed_key_when_told_its_pcrs() {
    const HANDLE: &str = "0x8101ff12";
    let created = cli(&["key", "create", "--handle", HANDLE, "--pcrs", "16"]);
    assert!(created.status.success(), "{}", said(&created));

    let with_pcrs = cli(&["key", "check", "--handle", HANDLE, "--pcrs", "16"]);
    let without = cli(&["key", "check", "--handle", HANDLE]);
    let other_pcrs = cli(&["key", "check", "--handle", HANDLE, "--pcrs", "23"]);
    let both = cli(&["key", "check", "--handle", HANDLE, "--pcrs", "16", "--auth-file", "/dev/null"]);
    let evicted = cli(&["key", "evict", "--handle", HANDLE]);
    assert!(evicted.status.success(), "{}", said(&evicted));

    assert!(with_pcrs.status.success() && said(&with_pcrs).contains("OK: 0x8101ff12 signs"), "{}", said(&with_pcrs));
    // Opened plainly the TPM refuses it, and the refusal names what is missing (#49).
    assert!(!without.status.success() && said(&without).contains("sealed to PCRs and was opened without them"), "{}", said(&without));
    assert!(said(&without).contains("--pcrs"), "{}", said(&without));
    // A refusal for another reason keeps the TPM's words and gets no such line: here the
    // policy is given and is not the one the key was sealed to.
    assert!(!other_pcrs.status.success() && !said(&other_pcrs).contains("opened without them"), "{}", said(&other_pcrs));
    assert!(!both.status.success() && said(&both).contains("do not combine"), "{}", said(&both));
}

/// #43: what `key create` says when the storage parent is not there.
#[test]
#[ignore = "requires a TPM"]
fn key_create_names_a_missing_storage_parent() {
    let out = cli(&["key", "create", "--handle", "0x8101ff13", "--parent", "0x81ffff7e"]);
    assert!(!out.status.success(), "created a key under a parent that is not there");
    assert!(said(&out).contains("no storage parent at 0x81ffff7e"), "{}", said(&out));
}
