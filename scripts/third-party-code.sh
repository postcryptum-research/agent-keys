#!/usr/bin/env bash
# The deployed Kernel v3.3 implementation and its factory against builds of
# their source (contracts/lib/kernel, tag v3.3), the way docs/DEPLOYMENTS.md
# compares this project's own instances.
#
#   scripts/third-party-code.sh [solc version ...]     # default: 0.8.29 0.8.28
#
# Kernel's repository pins no compiler (`pragma solidity ^0.8.0`, no `solc`
# in its foundry.toml), so the script tries the versions given, each with and
# without via-IR (its `deploy` profile turns via-IR on), for `prague` (its
# foundry.toml). ZeroDev deploys through the CREATE2 deployer with salt 0
# (contracts/lib/kernel/script/DeployKernel.s.sol), so a build whose CREATE2
# address is the deployed one has the deployed creation code exactly. For
# the build that matches, the runtime code on each chain is compared with
# the build's outside its immutable slots.
set -euo pipefail
cd "$(dirname "$0")/../contracts/lib/kernel"

DEPLOYER=0x4e59b44847b379578588920cA78FbF26c0B4956C
SALT=0x0000000000000000000000000000000000000000000000000000000000000000
ENTRY_POINT=0x0000000071727De22E5E9d8BAf0edAc6f37da032
KERNEL=0xd6CEDDe84be40893d153Be9d467CD6aD37875b28
FACTORY=0x2577507b78c2008Ff367261CB6285d44ba5eF2E9
RPCS=(https://sepolia.base.org https://ethereum-sepolia-rpc.publicnode.com)

versions=("$@")
[ ${#versions[@]} -eq 0 ] && versions=(0.8.29 0.8.28)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

create2() { # init code (hex) -> address
  # the first address printed; the salt follows it
  cast create2 --deployer "$DEPLOYER" --salt "$SALT" --init-code-hash "$(cast keccak "$1")" | grep -oE '0x[0-9a-fA-F]{40}' | head -1
}

match=""
for v in "${versions[@]}"; do
  for ir in true false; do
    out="$work/out-$v-$ir"
    flags=(--use "$v" --evm-version prague --optimize --optimizer-runs 200 --out "$out" --cache-path "$work/cache-$v-$ir")
    [ "$ir" = true ] && flags+=(--via-ir)
    if ! forge build "${flags[@]}" src/Kernel.sol src/factory/KernelFactory.sol >/dev/null 2>&1; then
      echo "solc $v via-ir=$ir: build failed"
      continue
    fi
    k=$(jq -r .bytecode.object "$out/Kernel.sol/Kernel.json")
    addr=$(create2 "${k}$(cast abi-encode 'f(address)' "$ENTRY_POINT" | cut -c3-)")
    f=$(jq -r .bytecode.object "$out/KernelFactory.sol/KernelFactory.json")
    faddr=$(create2 "${f}$(cast abi-encode 'f(address)' "$KERNEL" | cut -c3-)")
    k_ok=no; f_ok=no
    [ "$(echo "$addr" | tr A-F a-f)" = "$(echo "$KERNEL" | tr A-F a-f)" ] && k_ok=yes
    [ "$(echo "$faddr" | tr A-F a-f)" = "$(echo "$FACTORY" | tr A-F a-f)" ] && f_ok=yes
    echo "solc $v via-ir=$ir: Kernel at $addr (deployed: $k_ok), KernelFactory at $faddr (deployed: $f_ok)"
    [ "$k_ok" = yes ] && [ -z "$match" ] && match="$out"
  done
done

# FactoryStaker takes its owner; tried with the deployer DeployKernel.s.sol
# names. Its address is shown, not required.
if [ -n "$match" ] && forge build --use "${versions[0]}" --via-ir --evm-version prague --optimize --optimizer-runs 200 \
    --out "$work/staker" --cache-path "$work/staker-cache" src/factory/FactoryStaker.sol >/dev/null 2>&1; then
  s=$(jq -r .bytecode.object "$work/staker/FactoryStaker.sol/FactoryStaker.json")
  saddr=$(create2 "${s}$(cast abi-encode 'f(address)' 0x9775137314fE595c943712B0b336327dfa80aE8A | cut -c3-)")
  echo "FactoryStaker with that owner, salt 0: $saddr (deployed 0xd703aaE79538628d27099B8c4f621bE4CCd142d5: $([ "$(echo "$saddr" | tr A-F a-f)" = 0xd703aae79538628d27099b8c4f621be4ccd142d5 ] && echo yes || echo 'no: owner or salt not as tried'))"
fi

[ -z "$match" ] && { echo "no build reproduces the deployed Kernel"; exit 1; }

# The runtime code on each chain against the matching build, immutables masked
for rpc in "${RPCS[@]}"; do
  for pair in "Kernel.sol/Kernel.json:$KERNEL" "KernelFactory.sol/KernelFactory.json:$FACTORY"; do
    art="$match/${pair%%:*}"; a="${pair#*:}"
    cast code "$a" --rpc-url "$rpc" > "$work/chain.hex"
    python3 - "$art" "$work/chain.hex" "$a" "$rpc" <<'PY'
import json, sys
art = json.load(open(sys.argv[1]))
b = bytearray.fromhex(art["deployedBytecode"]["object"][2:])
c = bytearray.fromhex(open(sys.argv[2]).read().strip()[2:])
refs = [r for v in art["deployedBytecode"].get("immutableReferences", {}).values() for r in v]
for r in refs:
    b[r["start"]:r["start"] + r["length"]] = c[r["start"]:r["start"] + r["length"]]
same = len(b) == len(c) and b == c
print(f"  {sys.argv[3]} on {sys.argv[4]}: {len(c)} bytes, "
      + ("equal to the build outside its immutables" if same else "DIFFERS from the build"))
sys.exit(0 if same else 1)
PY
  done
done
