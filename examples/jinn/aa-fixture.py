#!/usr/bin/env python3
"""This project's contracts in the Jinn loop's bytecode fixture are the current build.

    examples/jinn/aa-fixture.py /path/to/mono

The hermetic loop of the patch series (`full-loop-kernel-owner.test.ts`) installs
the ERC-4337 side with `anvil_setCode` from
`operator/test/_support/fixtures/tpm-sign-aa-code.json` in the Jinn checkout. A
change to a contract must reach that file, or the loop goes on running an
earlier contract and passes.

P256Validator, P256Signer, AgentPolicy and SafeNonceAssert are taken, address
and code, from the CLI's own test fixture
(`signer/crates/agent-signer/tests/fixtures/chain-code.json`), after
`scripts/test-fixtures.py` has built the contracts (`forge build --evm-version
osaka`) and confirmed that fixture is the build. The loop then runs the code
the CLI's tests run. Third-party code in the Jinn fixture (the EntryPoint,
Kernel and its factory, Solady's verifier), read from a chain, is not touched.
"""
import json
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
CLI_FIXTURE = ROOT / "signer" / "crates" / "agent-signer" / "tests" / "fixtures" / "chain-code.json"
JINN_FIXTURE = pathlib.Path("operator") / "test" / "_support" / "fixtures" / "tpm-sign-aa-code.json"
OURS = ("p256Validator", "p256Signer", "agentPolicy", "safeNonceAssert")


def git(*args):
    return subprocess.run(["git", *args], cwd=ROOT, check=True, capture_output=True, text=True).stdout.strip()


def main():
    if len(sys.argv) != 2 or sys.argv[1].startswith("-"):
        sys.exit(__doc__)
    path = pathlib.Path(sys.argv[1]) / JINN_FIXTURE
    if not path.is_file():
        sys.exit(f"{path} is missing: apply the patch series to that checkout first")
    # builds, and exits 1 when the CLI's fixture is behind the build
    subprocess.run([sys.executable, str(ROOT / "scripts" / "test-fixtures.py")], check=True)

    built = json.loads(CLI_FIXTURE.read_text())["contracts"]
    # runtime code has no constructor run: the policy's immutable is the address written into it
    if built["safeNonceAssert"]["address"][2:].lower() not in built["agentPolicy"]["code"].lower():
        sys.exit("agentPolicy's code does not carry safeNonceAssert's address: the two entries do not belong together")
    fixture = json.loads(path.read_text())
    behind = [key for key in OURS if fixture["contracts"].get(key) != {"address": built[key]["address"], "code": built[key]["code"]}]
    if not behind:
        # the file, its `_source` included, stays as it is
        print(f"{path}: this project's contracts are the current build already")
        return
    for key in behind:
        print("rewritten  " + key)
        fixture["contracts"][key] = {"address": built[key]["address"], "code": built[key]["code"]}
    # The last commit that changed what is built, not HEAD: it names the code whatever is
    # committed on top of it afterwards, and it is still there after a rebase.
    built_from = ("contracts/src", "contracts/foundry.toml")
    commit = git("log", "-1", "--format=%H", "--", *built_from) + (" with local changes" if git("status", "--porcelain", "--", *built_from) else "")
    fixture["_source"] = (
        "EntryPoint v0.7, Kernel v3.3 and its factory, Solady's P-256 verifier: runtime bytecode read from Base Sepolia "
        "(84532), chain-agnostic. p256Validator, p256Signer, agentPolicy, safeNonceAssert: agent-keys' contracts as "
        f"built (forge build --evm-version osaka) from its sources of commit {commit}, the last to change contracts/src or "
        "contracts/foundry.toml, at the addresses of its test fixture; agentPolicy carries safeNonceAssert's address as "
        "its immutable. Rewritten by agent-keys' examples/jinn/aa-fixture.py"
    )
    path.write_text(json.dumps(fixture, indent=1) + "\n")
    print(f"{path}: this project's contracts are the build of the sources of {commit}")


main()
