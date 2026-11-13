#!/bin/sh
# The whole loop in the iOS simulator against the real CLI on a local anvil:
# enrollment, handover to the app's key, an agent permission reviewed and
# signed in the app, then the app signing a change of the root key itself
# (README.md). No phone and no Apple account.
#   Xcode with an iOS simulator, xcodegen, anvil; rustup targets as build-core.sh.
#   ROBOT=0     tap in the Simulator window yourself; by default a UI test taps
#               what a person would, checks that Sign waits for the end of the
#               review, and keeps the screens it saw in build/robot-screens.
#   SIMULATOR   the simulator's name (default "iPhone 17e").
#   CARGO       default "cargo" (CARGO="cargo +1.94" if needed).
set -eu
here=$(cd "$(dirname "$0")" && pwd)
: "${CARGO:=cargo}" "${SIMULATOR:=iPhone 17e}" "${ROBOT:=1}"
bundle=dev.tpmsign.owner.spike
xcode="-project OwnerApp.xcodeproj -scheme OwnerApp -derivedDataPath build/derived"
phone_test="-p agent-signer --features insecure-software-keys --test anvil_cli phone_owner_real_device"

cd "$here"
# the app must know the anvil chain's contracts to name them
OWNER_CORE_FEATURES=ffi,test-chains ./build-core.sh
xcodegen generate --quiet
xcodebuild build-for-testing -quiet $xcode -destination "platform=iOS Simulator,name=$SIMULATOR"
(cd ../../signer && $CARGO test $phone_test --no-run)

xcrun simctl boot "$SIMULATOR" 2>/dev/null || true
xcrun simctl bootstatus "$SIMULATOR" >/dev/null
# a clean app: a local anvil is recreated on every run, so its accounts recur with new owners
xcrun simctl uninstall "$SIMULATOR" "$bundle" 2>/dev/null || true
xcrun simctl install "$SIMULATOR" build/derived/Build/Products/Debug-iphonesimulator/OwnerApp.app
if [ "$ROBOT" = 1 ]; then
  rm -rf build/robot.xcresult build/robot-screens
  TEST_RUNNER_TPMSIGN_ROBOT_SECONDS=300 xcodebuild test-without-building $xcode -destination "platform=iOS Simulator,name=$SIMULATOR" \
    -resultBundlePath build/robot.xcresult >build/robot.log 2>&1 &
  robot=$!
  trap 'kill $robot 2>/dev/null || true' EXIT
else
  open -a Simulator
  xcrun simctl launch "$SIMULATOR" "$bundle"
fi
# the simulator has no camera: agent-signer writes each QR's text where the app looks for it,
# in the simulated device's tmp directory (the app's own log goes out the same way)
qr="$(xcrun simctl getenv "$SIMULATOR" SIMULATOR_SHARED_RESOURCES_DIRECTORY)/tmp/tpmsign-session.qr"
rm -f "$qr"
cd ../../signer
TPMSIGN_PHONE_QR_FILE="$qr" TPMSIGN_PHONE_NO_ATTESTATION=1 TPMSIGN_PHONE_HANDOVER_BACK=1 $CARGO test $phone_test -- --ignored --nocapture
if [ "$ROBOT" = 1 ]; then
  # the robot ends on the signature the laptop confirmed; its verdict is the screen's half of the run
  wait $robot || { grep -E "error:|XCTAssert|failed" "$here/build/robot.log" | head -20; echo "the robot's checks failed"; exit 1; }
  trap - EXIT
  xcrun xcresulttool export attachments --path "$here/build/robot.xcresult" --output-path "$here/build/robot-screens" >/dev/null
  echo "the robot's checks passed; the screens it saw are in $here/build/robot-screens"
fi
