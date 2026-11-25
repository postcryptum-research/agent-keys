//! The CLI on a main thread with a 1 MiB stack, which is what a Windows
//! process gets. Tests build unoptimized, the build that needs the most.
#![cfg(unix)]

use std::process::Command;

/// A debug build overflowed a 1 MiB stack on every command before the work
/// moved to a thread with a stated stack. `ulimit -s` gives this process's
/// main thread the Windows size.
#[test]
fn a_command_runs_on_a_one_mebibyte_main_stack() {
    let bin = env!("CARGO_BIN_EXE_agent-signer");
    let out = Command::new("sh")
        .args(["-c", "ulimit -s 1024 && exec \"$0\" key show --keyfile /nonexistent/key.json", bin])
        .output()
        .expect("run agent-signer");
    let said = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    assert!(!said.contains("stack overflow") && !said.contains("overflowed its stack"), "{said}");
    assert!(said.contains("/nonexistent/key.json"), "{said}");
    assert_eq!(out.status.code(), Some(1), "{said}");
}
