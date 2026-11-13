#!/bin/sh
# Builds owner-core for the iPhone and its simulator, and generates its Swift
# bindings (docs/MOBILE_OWNER_DESIGN.md §7.3). Run before xcodegen.
#   Xcode, rustup targets aarch64-apple-ios and aarch64-apple-ios-sim (an
#   Apple-silicon Mac). Optional: CARGO="cargo +1.94".
#   OWNER_CORE_FEATURES (default "ffi"): "ffi,test-chains" for a development
#   build that signs on the CLI's local anvil chain — never for a build that
#   is handed to anyone; the app shows "+test-chains" at launch.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
core="$here/../owner-core"
out="$here/build/core"
: "${CARGO:=cargo}"
export IPHONEOS_DEPLOYMENT_TARGET=16.0
cd "$core"
# 1. the static libraries: the phone, and the simulator on this Mac
for target in aarch64-apple-ios aarch64-apple-ios-sim; do
  $CARGO rustc --release --features "${OWNER_CORE_FEATURES:-ffi}" --target "$target" --lib --crate-type staticlib
done
# 2. a host library for the bindings generator, and the Swift
$CARGO build --release --features ffi
rm -rf "$out"
mkdir -p "$out/headers"
$CARGO run --release --features cli --bin uniffi-bindgen -- generate --library target/release/libowner_core.dylib --language swift --out-dir "$out"
# 3. the C side of the bindings as a module, with both libraries, for Xcode
mv "$out/owner_coreFFI.h" "$out/headers/"
mv "$out/owner_coreFFI.modulemap" "$out/headers/module.modulemap"
xcodebuild -create-xcframework \
  -library target/aarch64-apple-ios/release/libowner_core.a -headers "$out/headers" \
  -library target/aarch64-apple-ios-sim/release/libowner_core.a -headers "$out/headers" \
  -output "$out/OwnerCoreFFI.xcframework" >/dev/null
echo "owner-core: $out/owner_core.swift and $out/OwnerCoreFFI.xcframework"
