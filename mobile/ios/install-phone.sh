#!/bin/sh
# Builds the app for the iPhone connected to this Mac, signs it, installs it
# and starts it (README.md, "On an iPhone"). Run ./build-core.sh first, with
# OWNER_CORE_FEATURES=ffi,test-chains for a phone that signs on a local anvil.
#   DEVELOPMENT_TEAM  the id of the Xcode team that signs the app; a free
#                     Personal Team will do. It is yours: keep it out of the
#                     repository.
# Before the first run: an Apple Account in Xcode, the phone paired ("Trust
# This Computer") and its Developer Mode on. After the first install the phone
# must be told to trust the developer: Settings → General → VPN & Device
# Management.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
: "${DEVELOPMENT_TEAM:?set it to the id of your Xcode team (README.md, \"On an iPhone\")}"
bundle=dev.tpmsign.owner.spike
cd "$here"
[ -d build/core/OwnerCoreFFI.xcframework ] || { echo "run ./build-core.sh first"; exit 1; }
xcrun devicectl list devices --json-output build/devices.json >/dev/null
device=$(python3 -c 'import json,sys; print(next((d["hardwareProperties"]["udid"] for d in json.load(open(sys.argv[1]))["result"]["devices"] if d["hardwareProperties"].get("reality")=="physical" and d["connectionProperties"].get("tunnelState")=="connected"), ""))' build/devices.json)
rm -f build/devices.json
[ -n "$device" ] || { echo "no iPhone connected: plug it in, unlock it, and trust this Mac on it"; exit 1; }
xcodegen generate --quiet
# Xcode registers the phone with the team and makes the provisioning profile itself
xcodebuild build -quiet -project OwnerApp.xcodeproj -scheme OwnerApp -destination "id=$device" -derivedDataPath build/derived \
  -allowProvisioningUpdates -allowProvisioningDeviceRegistration DEVELOPMENT_TEAM="$DEVELOPMENT_TEAM" CODE_SIGN_STYLE=Automatic
xcrun devicectl device install app --device "$device" build/derived/Build/Products/Debug-iphoneos/OwnerApp.app >/dev/null
echo "installed"
xcrun devicectl device process launch --terminate-existing --device "$device" "$bundle" >/dev/null 2>&1 && echo "started on the phone" ||
  echo "it did not start: unlock the phone, and if this is the first install trust the developer there (Settings → General → VPN & Device Management)"
