#!/usr/bin/env bash
# A change to a contract's bytecode raises its VERSION (CLAUDE.md, house
# rules 3 and 9). This builds every contract of contracts/src at a base
# commit and at the working tree, and compares creation and runtime bytecode.
#
#   scripts/source-record.sh [base]        # base: a tag, commit or ref, default origin/master
#
# - No bytecode differs: comments and blank lines changed at most. Passes.
# - A contract's bytecode differs and its VERSION differs from the base's (a
#   contract that gains its first VERSION among them): passes, and names both.
# - A contract's bytecode differs and its VERSION is the base's: fails once
#   the repository has a release tag (v*). Before the first release every
#   contract stays at 0.1.0 (rule 9): the difference is named, and passes.
# - A contract's bytecode differs and it carries no VERSION: the rule from
#   before versions holds it. Some deployments file must change its key
#   (`agentPolicy` for AgentPolicy); a contract no deployments file records is
#   named only.
#
# Against a release tag or a recorded commit, "identical" for a contract
# means that commit still builds it as the working tree does.
#
# A contract's VERSION is read from its file, or from the file of a contract
# it inherits; one contract a file is assumed. Whether the new version is
# higher is not judged. The comparison means what it says while foundry.toml
# keeps compiler metadata out of the bytecode (bytecode_hash = "none"); the
# script refuses to run otherwise. It does not read a chain.
set -euo pipefail

base="${1:-origin/master}"
root="$(git rev-parse --show-toplevel)"
cd "$root"
merge_base="$(git merge-base "$base" HEAD)"
# versions are raised from the first release on (rule 9); before it they stay 0.1.0
released="$(git tag -l 'v[0-9]*' | head -1)"

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

# the VERSION a contract carries, in its own file or an inherited contract's; empty if none
version_of() {
  local dir="$1" f="${2%%:*}" n="${2##*:}" v p pf
  v="$(sed -nE 's/.*string +public +constant +VERSION *= *"([^"]*)".*/\1/p' "$dir/contracts/$f" 2>/dev/null | head -1)"
  if [ -n "$v" ]; then printf %s "$v"; return; fi
  for p in $(sed -nE "s/^(abstract +)?contract +$n +is +([^{]*).*/\2/p" "$dir/contracts/$f" 2>/dev/null | tr ',' ' '); do
    pf="$(cd "$dir/contracts" && grep -lE "^(abstract +)?contract +$p( |\{|$)" -r src | head -1 || true)"
    [ -n "$pf" ] || continue
    v="$(version_of "$dir" "$pf:$p")"
    if [ -n "$v" ]; then printf %s "$v"; return; fi
  done
}

changed=0
failed=0
while read -r id c r; do
  was="$(grep -F "$id " "$work/before" || true)"
  if [ -z "$was" ]; then
    echo "new       $id"
  elif [ "$was" != "$id $c $r" ]; then
    key="$(key_of "$id")"
    changed=1
    now="$(version_of "$root" "$id")"
    then_="$(version_of "$work/base" "$id")"
    if [ -n "$now" ] && [ "$now" != "$then_" ]; then
      echo "DIFFERS   $id (VERSION ${then_:-none} -> $now)"
    elif [ -n "$now" ] && [ -z "$released" ]; then
      echo "DIFFERS   $id (VERSION $now kept: no release tag yet, rule 9)"
      kept=1
    elif [ -n "$now" ]; then
      echo "DIFFERS   $id and its VERSION is still $now"
      failed=1
    elif ! recorded "$key"; then
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
  echo "No contract's bytecode differs from $merge_base."
  exit 0
fi
if [ "$failed" = 1 ]; then
  echo "A change to a contract's bytecode raises its VERSION; a contract without one changes only with its deployments record (house rules 3 and 9)."
  exit 1
fi
if [ "${kept:-0}" = 1 ]; then
  echo "No release tag yet: every contract stays at 0.1.0, and a fix waits for the next redeploy of the test networks (rule 9)."
else
  echo "Every contract whose bytecode differs has a new VERSION, or its key changed in a deployments file."
fi
