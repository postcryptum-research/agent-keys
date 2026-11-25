//! Builds the Swift shim behind the Secure Enclave backend.
//!
//! Only with `--features secure-enclave` for a macOS target, and only on a
//! macOS host (it needs `swiftc` from the Xcode Command Line Tools). On any
//! other host the shim is skipped, so `cargo check --target
//! aarch64-apple-darwin` still type-checks the Rust side from Linux; linking
//! would fail there, as it should.

use std::env;
use std::path::PathBuf;
use std::process::Command;

const SHIM: &str = "swift/SecureEnclaveShim.swift";

fn main() {
    println!("cargo:rerun-if-changed={SHIM}");
    if env::var_os("CARGO_FEATURE_SECURE_ENCLAVE").is_none()
        || env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("macos")
    {
        return;
    }
    if !cfg!(target_os = "macos") {
        println!("cargo:warning=secure-enclave: not on macOS, Swift shim skipped (type-check only)");
        return;
    }

    let target = match env::var("CARGO_CFG_TARGET_ARCH").as_deref() {
        Ok("aarch64") => "arm64-apple-macosx13.0",
        Ok("x86_64") => "x86_64-apple-macosx13.0",
        other => panic!("secure-enclave: unsupported macOS architecture {other:?}"),
    };
    let out = PathBuf::from(env::var("OUT_DIR").unwrap());
    let lib = out.join("libtpmse.a");

    let status = Command::new("xcrun")
        .args(["swiftc", "-parse-as-library", "-emit-library", "-static", "-O"])
        .args(["-module-name", "TpmSignEnclave", "-target", target])
        .arg(SHIM)
        .arg("-o")
        .arg(&lib)
        .status()
        .expect("secure-enclave: cannot run `xcrun swiftc` — install the Xcode Command Line Tools (xcode-select --install)");
    assert!(status.success(), "secure-enclave: swiftc failed to compile {SHIM}");

    println!("cargo:rustc-link-search=native={}", out.display());
    println!("cargo:rustc-link-lib=static=tpmse");
    // The Swift object files autolink the Swift runtime libraries; tell the
    // linker where they are.
    for dir in swift_runtime_paths(target) {
        println!("cargo:rustc-link-search=native={dir}");
    }
    println!("cargo:rustc-link-arg=-Wl,-rpath,/usr/lib/swift");
    for framework in ["CryptoKit", "Foundation", "Security"] {
        println!("cargo:rustc-link-lib=framework={framework}");
    }
}

/// `runtimeLibraryPaths` from `swiftc -print-target-info` (a JSON document;
/// the list is simple enough to read without a JSON parser).
fn swift_runtime_paths(target: &str) -> Vec<String> {
    let output = Command::new("xcrun")
        .args(["swiftc", "-print-target-info", "-target", target])
        .output()
        .expect("secure-enclave: `xcrun swiftc -print-target-info` failed");
    let info = String::from_utf8_lossy(&output.stdout);
    let Some(start) = info.find("\"runtimeLibraryPaths\"") else { return Vec::new() };
    let rest = &info[start..];
    let (Some(open), Some(close)) = (rest.find('['), rest.find(']')) else { return Vec::new() };
    rest.get(open.saturating_add(1)..close)
        .unwrap_or("")
        .split(',')
        .map(|s| s.trim().trim_matches('"').to_string())
        .filter(|s| !s.is_empty())
        .collect()
}
