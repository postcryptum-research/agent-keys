#!/usr/bin/env bash
# The source of a deployed contract is the record of what is on chain
# (CLAUDE.md, house rule 3). This holds a change to that: it builds every
# contract of contracts/src at a base commit and at the working tree, and
# compares creation and runtime bytecode.
#
#   scripts/source-record.sh [base]        # base: a commit or ref, default origin/master
#
# - No bytecode differs: comments and blank lines changed at most. Passes.
# - A contract's bytecode differs and a deployments file changes that
#   contract's key (`agentPolicy` for AgentPolicy, a versioned `agentPolicyV2`
#   too): a change that redeploys it. Passes, and names the contract.
# - A contract's bytecode differs, some deployments file records it, and none
#   changes its key: fails.
# - A contract's bytecode differs and no deployments file records it (a
#   library, a contract not yet deployed): named only.
#
# A contract that is new since the base has no instance to keep true and is
# only named. The comparison means what it says while foundry.toml keeps
# compiler metadata out of the bytecode (bytecode_hash = "none"); the script
# refuses to run otherwise. It does not read a chain: that the recorded
# address holds this code is checked when the instance is recorded.
set -euo pipefail

base="${1:-origin/master}"
root="$(git rev-parse --show-toplevel)"
cd "$root"
merge_base="$(git merge-base "$base" HEAD)"

grep -Eq '^bytecode_hash *= *"none"' contracts/foundry.toml \
  || { echo "contracts/foundry.toml does not set bytecode_hash = \"none\": with metadata in the bytecode a comment changes it, and this comparison cannot stand"; exit 1; }

if git diff --quiet "$merge_base" -- contracts/src contracts/foundry.toml; then
  echo "contracts/src and foundry.toml are as at $merge_base: nothing to compare"
  exit 0
fi
if ! git diff --quiet "$merge_base" -- contracts/lib .gitmodules; then
  echo "contracts/lib changes since $merge_base: a dependency moved, compare by hand"
  exit 1
fi

# every contract, library and interface of contracts/src, as file:Name
names() {
  (cd "$1/contracts" && find src -name '*.sol' | sort | while read -r f; do
    sed -nE 's/^(abstract +)?(contract|library|interface) +([A-Za-z_][A-Za-z0-9_]*).*/\3/p' "$f" | while read -r n; do echo "$f:$n"; done
  done)
}
# file:Name, the hash of its creation code, the hash of its runtime code
table() {
  local dir="$1"
  (cd "$dir/contracts" && forge build >/dev/null 2>&1) || { echo "forge build failed in $dir/contracts"; exit 1; }
  names "$dir" | while read -r id; do
    local c r
    c="$(cd "$dir/contracts" && forge inspect "$id" bytecode 2>/dev/null)"
    r="$(cd "$dir/contracts" && forge inspect "$id" deployedBytecode 2>/dev/null)"
    # an interface has the code "0x"; nothing at all means the question was not answered
    [ -n "$c" ] && [ -n "$r" ] || { echo "forge inspect gave nothing for $id" >&2; exit 1; }
    echo "$id $(printf %s "$c" | sha256sum | cut -d' ' -f1) $(printf %s "$r" | sha256sum | cut -d' ' -f1)"
  done
}

work="$(mktemp -d)"
trap 'git worktree remove --force "$work/base" >/dev/null 2>&1 || true; rm -rf "$work"' EXIT
git worktree add --detach "$work/base" "$merge_base" >/dev/null 2>&1
# the same dependencies for both builds: the check above saw that they did not move
rmdir "$work/base/contracts/lib" 2>/dev/null || rm -rf "$work/base/contracts/lib"
ln -s "$root/contracts/lib" "$work/base/contracts/lib"

table "$work/base" > "$work/before"
table "$root" > "$work/after"
[ -s "$work/before" ] && [ -s "$work/after" ] || { echo "no contract was compared"; exit 1; }

# the key a deployments file records a contract under: its name, first letter small
key_of() { local n="${1##*:}"; printf '%s%s' "$(printf %s "${n:0:1}" | tr '[:upper:]' '[:lower:]')" "${n:1}"; }
recorded() { grep -Eqs "^ *\"$1(V[0-9]+)?\" *:" contracts/deployments/*.json; }
rekeyed() { git diff -U0 "$merge_base" -- contracts/deployments | grep -Eq "^[+-] *\"$1(V[0-9]+)?\" *:"; }

changed=0
failed=0
while read -r id c r; do
  was="$(grep -F "$id " "$work/before" || true)"
  if [ -z "$was" ]; then
    echo "new       $id"
  elif [ "$was" != "$id $c $r" ]; then
    key="$(key_of "$id")"
    changed=1
    if ! recorded "$key"; then
      echo "DIFFERS   $id (no deployments file records \"$key\")"
    elif rekeyed "$key"; then
      echo "DIFFERS   $id (\"$key\" changes in a deployments file: redeployed)"
    else
      echo "DIFFERS   $id and \"$key\" does not change in any deployments file"
      failed=1
    fi
  else
    echo "identical $id"
  fi
done < "$work/after"
while read -r id _; do
  grep -qF "$id " "$work/after" || echo "removed   $id"
done < "$work/before"

if [ "$changed" = 0 ]; then
  echo "No contract's bytecode differs from $merge_base: the source is still the record of what is on chain."
  exit 0
fi
if [ "$failed" = 1 ]; then
  echo "A contract's code changes only in a change that redeploys it and records the new instance (house rule 3)."
  exit 1
fi
echo "Every recorded contract whose bytecode differs has its key changed in a deployments file."
