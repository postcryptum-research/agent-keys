#!/bin/sh
# The whole loop in the iOS simulator against the real CLI on a local anvil:
# enrollment, the app showing that it holds the new key, the handover to that
# key, an agent permission reviewed and signed in the app, then the app
# signing a change of the root key itself (README.md). Twice: as it should
# go, and with a host on the path that replaces the laptop's confirmation of
# the enrollment. No phone and no Apple account.
#   Xcode with an iOS simulator, xcodegen, anvil; rustup targets as build-core.sh.
#   ROBOT=0     tap in the Simulator window yourself; by default a UI test taps
#               what a person would, checks that Sign waits for the end of the
#               review, and keeps the screens it saw in build/robot-screens-*.
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
# the simulator has no camera: agent-signer writes each QR's text where the app looks for it,
# in the simulated device's tmp directory, and the app's own log goes out the same way
exchange="$(xcrun simctl getenv "$SIMULATOR" SIMULATOR_SHARED_RESOURCES_DIRECTORY)/tmp"
qr="$exchange/tpmsign-session.qr"
applog="$exchange/tpmsign-app-log.json"

# One run of the loop. $1 names it; $2 is extra environment for the phone test.
pass() {
  cd "$here"
  # a clean app: a local anvil is recreated on every run, so its accounts recur with new owners
  xcrun simctl uninstall "$SIMULATOR" "$bundle" 2>/dev/null || true
  xcrun simctl install "$SIMULATOR" build/derived/Build/Products/Debug-iphonesimulator/OwnerApp.app
  rm -f "$qr" "$applog"
  if [ "$ROBOT" = 1 ]; then
    rm -rf "build/robot-$1.xcresult" "build/robot-screens-$1"
    TEST_RUNNER_TPMSIGN_ROBOT_SECONDS=300 xcodebuild test-without-building $xcode -destination "platform=iOS Simulator,name=$SIMULATOR" \
      -resultBundlePath "build/robot-$1.xcresult" >"build/robot-$1.log" 2>&1 &
    robot=$!
    trap 'kill $robot 2>/dev/null || true' EXIT
  else
    open -a Simulator
    xcrun simctl launch "$SIMULATOR" "$bundle"
  fi
  (cd ../../signer && env TPMSIGN_PHONE_QR_FILE="$qr" TPMSIGN_PHONE_NO_ATTESTATION=1 TPMSIGN_PHONE_HANDOVER_BACK=1 $2 \
    $CARGO test $phone_test -- --ignored --nocapture)
  if [ "$ROBOT" = 1 ]; then
    # the robot ends on the last signature the laptop confirmed; its verdict is the screen's half of the run
    wait $robot || { grep -E "error:|XCTAssert|failed" "build/robot-$1.log" | head -20; echo "$1: the robot's checks failed"; exit 1; }
    trap - EXIT
    xcrun xcresulttool export attachments --path "build/robot-$1.xcresult" --output-path "build/robot-screens-$1" >/dev/null
    echo "$1: the robot's checks passed; the screens it saw are in $here/build/robot-screens-$1"
  fi
}
said() { grep -q "$1" "$applog" || { echo "the app's log does not say: $1"; exit 1; }; }

# 1. the laptop's confirmation of the enrollment reaches the phone
pass confirmed ""
said "enrollment confirmed by the laptop"
[ "$ROBOT" != 1 ] || said "deleted the key"
# 2. a host on the path replaces it (issue #38): the laptop says "enrolled", the phone saw no
#    confirmation. The phone keeps its key, shows it when the handover asks, and the loop goes on.
pass lost-confirmation TPMSIGN_PHONE_PATH_ATTACKER=1
said "enrollment NOT confirmed"
said "showed the key"
[ "$ROBOT" != 1 ] || said "deleted the key"
[ "$ROBOT" != 1 ] || grep -q "the not-confirmed notice" build/robot-lost-confirmation.log || { echo "the app did not put its not-confirmed notice on screen"; exit 1; }
echo "both runs passed: with the laptop's confirmation, and with it replaced on the way"
