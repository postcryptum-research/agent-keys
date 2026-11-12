//! `cargo run --features cli --bin uniffi-bindgen -- generate --library <libowner_core.{dylib,so}> --language kotlin --out-dir <dir>`
fn main() {
    uniffi::uniffi_bindgen_main()
}
