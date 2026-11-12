#!/bin/sh
# Builds owner-core for the phone and generates its Kotlin bindings
# (docs/MOBILE_OWNER_DESIGN.md §7.3). Run before `./gradlew assembleDebug`.
#   cargo-ndk, the Android NDK (ANDROID_NDK_HOME or $ANDROID_HOME/ndk/<ver>),
#   rustup target aarch64-linux-android. Optional: CARGO=cargo +1.94.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
core="$here/../owner-core"
: "${CARGO:=cargo}"
if [ -z "${ANDROID_NDK_HOME:-}" ] && [ -n "${ANDROID_HOME:-}" ]; then
  ANDROID_NDK_HOME=$(ls -d "$ANDROID_HOME"/ndk/* | tail -1); export ANDROID_NDK_HOME
fi
cd "$core"
# 1. the phone library (arm64 only for the development builds; armeabi-v7a comes with P5)
$CARGO ndk -t arm64-v8a -o "$here/app/src/main/jniLibs" build --release --features ffi
# 2. a host library for the bindings generator, and the Kotlin
$CARGO build --release --features ffi
case "$(uname)" in Darwin) lib=target/release/libowner_core.dylib ;; *) lib=target/release/libowner_core.so ;; esac
$CARGO run --release --features cli --bin uniffi-bindgen -- generate --library "$lib" --language kotlin --out-dir "$here/app/build/generated/uniffi"
echo "owner-core: $(ls "$here"/app/src/main/jniLibs/arm64-v8a/) and $(find "$here/app/build/generated/uniffi" -name '*.kt')"
