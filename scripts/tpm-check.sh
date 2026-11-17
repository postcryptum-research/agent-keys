#!/usr/bin/env bash
# Checks the `tpm` backend against the TPM 2.0 this machine offers: a chip, a
# virtual machine's vTPM or, with --swtpm, a throwaway software TPM. What the
# output means is in docs/SERVER_KEY_STORES.md.
#
#   scripts/tpm-check.sh             the TPM at /dev/tpmrm0 (or $TPM2TOOLS_TCTI)
#     --make-srk                     creates the storage parent if absent
#     --keep                         leaves the test key at 0x8101ff01
#   scripts/tpm-check.sh --again     only shows and checks that key: after a
#                                    restart, after a restore, or on a clone
#   scripts/tpm-check.sh --swtpm     a software TPM, then a copy of its state
#
# Needs tpm2-tools and what `cargo build --features tpm` needs (libtss2-dev,
# libclang-dev); --swtpm also needs swtpm. Uses the handles 0x8101ff01..03
# (the tests use 0x8101ff11..13) and refuses to start when one of its own is
# taken.
set -euo pipefail

SRK=0x81000001 KEY=0x8101ff01 SEALED=0x8101ff02 PROTECTED=0x8101ff03
export TSS2_LOG=all+NONE # the refusals below are expected; the CLI reports them itself
CARGO=${CARGO:-cargo}
keep='' srk='' mode=''
for arg in "$@"; do
    case "$arg" in
    --keep) keep=1 ;;
    --make-srk) srk=1 ;;
    --again | --swtpm) mode=$arg ;;
    *)
        sed -n '2,15p' "$0"
        exit 2
        ;;
    esac
done
cd "$(dirname "$0")/../signer"

say() { printf '\n== %s\n' "$*"; }
present() { tpm2_readpublic -c "$1" >/dev/null 2>&1; }
prop() { tpm2_getcap properties-variable | awk -v k="$1:" '$1 == k { print $2 }'; }
refused() { if "$@" >/dev/null 2>"$tmp/err"; then echo "NOT refused: $*"; exit 1; fi; echo "refused, as it must be: $(tail -1 "$tmp/err")"; }

tmp=$(mktemp -d)
pids=()
trap 'for p in "${pids[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null; done; rm -rf "$tmp"' EXIT

start_swtpm() { # state directory, port
    swtpm socket --tpm2 --tpmstate dir="$1" --server type=tcp,port="$2" --ctrl type=tcp,port=$(($2 + 1)) \
        --flags not-need-init,startup-clear --daemon --pid file="$tmp/pid"
    pids+=("$(cat "$tmp/pid")")
    export TPM2TOOLS_TCTI="swtpm:host=127.0.0.1,port=$2"
}

make_srk() { # docs/FAQ.md, question 1, step 3
    tpm2_createprimary -Q -C o -g sha256 -G ecc -c "$tmp/srk.ctx" && tpm2_evictcontrol -Q -C o -c "$tmp/srk.ctx" $SRK
    # A socket has no resource manager (the kernel is one for /dev/tpmrm0): the
    # tools' objects stay loaded and fill the TPM's three slots.
    tpm2_flushcontext -t
}

describe() {
    say "the TPM"
    tpm2_getcap properties-fixed | awk '
        /^TPM2_PT_/ { name = $1; keep = name ~ /^TPM2_PT_(FAMILY_INDICATOR|MANUFACTURER|VENDOR_STRING_[12]|FIRMWARE_VERSION_1):$/; next }
        keep && (/value:/ || (/raw:/ && name ~ /FIRMWARE/)) { print name, $2 }'
    echo "P-256: $(tpm2_getcap ecc-curves | grep -c NIST_P256) | PCR banks: $(tpm2_getcap pcrs | grep -oE 'sha[0-9]+' | tr '\n' ' ')"
    echo "persistent handles: $(tpm2_getcap handles-persistent | tr -d '\n' | tr -s ' ')"
    echo "NV indices: $(tpm2_getcap handles-nv-index | tr -d '\n' | tr -s ' ')"
    tpm2_pcrread sha256:0,2,4,7 | sed 's/^/  /'
    echo "dictionary-attack lockout: $(($(prop TPM2_PT_LOCKOUT_COUNTER))) failed of $(($(prop TPM2_PT_MAX_AUTH_FAIL))) allowed," \
        "one forgiven every $(($(prop TPM2_PT_LOCKOUT_INTERVAL))) s; lockoutAuthSet $(prop lockoutAuthSet), ownerAuthSet $(prop ownerAuthSet)"
}

build() {
    say "build"
    $CARGO build -q -p agent-signer --features tpm
    B=${CARGO_TARGET_DIR:-target}/debug/agent-signer
}

checks() {
    for h in $KEY $SEALED $PROTECTED; do
        if present $h; then echo "handle $h is taken: evict it, or use --again"; exit 1; fi
    done
    # The tests spend two failed authorizations. In lockout a key behind an
    # authValue does not sign, and none can be made under a parent that is
    # under the lockout itself.
    if [ $(($(prop TPM2_PT_MAX_AUTH_FAIL) - $(prop TPM2_PT_LOCKOUT_COUNTER))) -lt 3 ]; then
        echo "too close to the dictionary-attack lockout to run the tests: wait, or reset it (tpm2_dictionarylockout -c)"
        exit 1
    fi
    say "the backend's hardware tests, and the CLI's"
    $CARGO test -p hw-signer --features tpm -- --ignored --test-threads=1 2>&1 | grep -E '^test |^test result|panicked|^error'
    $CARGO test -p agent-signer --features tpm --test tpm_cli -- --ignored --test-threads=1 2>&1 | grep -E '^test |^test result|panicked|^error'
    say "the CLI: a plain key, a key sealed to PCRs 0,2,4,7, a key behind an authValue"
    "$B" key create --handle $KEY
    "$B" key check --handle $KEY
    "$B" key create --handle $SEALED --pcrs 0,2,4,7
    "$B" key check --handle $SEALED --pcrs 0,2,4,7
    printf 'a secret only root reads\n' >"$tmp/auth"
    "$B" key create --handle $PROTECTED --auth-file "$tmp/auth"
    "$B" key check --handle $PROTECTED --auth-file "$tmp/auth"
    "$B" key evict --handle $SEALED
    "$B" key evict --handle $PROTECTED
    # Forget the tests' two failures, where the lockout hierarchy has no password.
    if [ "$(prop lockoutAuthSet)" = 0 ]; then tpm2_dictionarylockout -Q -c; fi
    echo "failed authorizations counted now: $(($(prop TPM2_PT_LOCKOUT_COUNTER)))"
}

case "$mode" in
--again)
    build
    "$B" key show --handle $KEY
    "$B" key check --handle $KEY
    ;;
--swtpm)
    mkdir "$tmp/a"
    start_swtpm "$tmp/a" 2321
    describe
    build
    say "no storage parent yet: what the CLI says"
    refused "$B" key create --handle $KEY
    make_srk
    checks
    say "a copy of the state directory, opened by a second TPM"
    cp -a "$tmp/a" "$tmp/b"
    original=$("$B" key show --handle $KEY)
    start_swtpm "$tmp/b" 2331
    copy=$("$B" key show --handle $KEY)
    "$B" key check --handle $KEY
    [ "$original" = "$copy" ] && echo "the copy signs with the same key as the original: $(echo "$copy" | tr -d ' \n')"
    ;;
*)
    describe
    build
    if ! present $SRK; then
        if [ -z "$srk" ]; then
            echo "no storage parent at $SRK: run again with --make-srk (docs/FAQ.md, question 1, step 3)"
            exit 2
        fi
        make_srk
    fi
    checks
    if [ -n "$keep" ]; then echo "kept $KEY: run --again later"; else "$B" key evict --handle $KEY; fi
    ;;
esac
