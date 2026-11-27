#!/usr/bin/env python3
"""The contract code in the CLI's local-chain test fixtures is the current build.

    scripts/test-fixtures.py            # compare; exit 1 naming each entry that is behind the build
    scripts/test-fixtures.py --write    # rewrite the entries from the build

`signer/crates/agent-signer/tests/fixtures/chain-code.json` and
`trading-code.json` hold this project's contracts as bytecode, so that the
Rust tests need no Solidity toolchain. A change to a contract must reach them,
or the tests (the review-to-install differential among them) go on running an
earlier contract and pass. CI runs the comparison on every pull request.

Third-party code in the fixtures (the EntryPoint, Kernel, Safe, Solady's
verifier), read from a chain, is not touched.
"""
import json
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "contracts" / "out"
FIXTURES = ROOT / "signer" / "crates" / "agent-signer" / "tests" / "fixtures"

# chain-code.json, `contracts.<key>.code`: runtime code, installed with anvil_setCode
RUNTIME = {
    "p256Validator": "P256Validator.sol/P256Validator",
    "p256RecoveryValidator": "P256RecoveryValidator.sol/P256RecoveryValidator",
    "p256Signer": "P256Signer.sol/P256Signer",
    "agentPolicy": "AgentPolicy.sol/AgentPolicy",
    "safeNonceAssert": "SafeNonceAssert.sol/SafeNonceAssert",
    "safeShapes": "SafeShapes.sol/SafeShapes",
    "demoCounter": "DemoCounter.sol/DemoCounter",
}
# runtime code has no constructor run: an immutable is written in by hand.
# AgentPolicy's one immutable is the SafeNonceAssert address it is deployed with.
IMMUTABLES = {"agentPolicy": {"NONCE_ASSERT": "safeNonceAssert", "SAFE_SHAPES": "safeShapes"}}
# creation code, by file and key
CREATION = {
    "chain-code.json": {
        "whitelistPaymasterInitCode": "WhitelistPaymaster.sol/WhitelistPaymaster",
        "mockUsdcInitCode": "AgentPermission.t.sol/MockUSDC",
    },
    "trading-code.json": {
        "agentPolicyInitCode": "AgentPolicy.sol/AgentPolicy",
        "cowSwapDecoderInitCode": "CowSwapDecoder.sol/CowSwapDecoder",
        "settlementInitCode": "Trading.t.sol/Settlement",
        "mockTokenInitCode": "AgentPermission.t.sol/MockToken",
        "oneInchLimitOrderDecoderInitCode": "OneInchLimitOrderDecoder.sol/OneInchLimitOrderDecoder",
        "routerStandInInitCode": "OneInchLimitOrderDecoder.t.sol/RouterStandIn",
        "relayerInitCode": "Trading.t.sol/Relayer",
        "swapRouter02DecoderInitCode": "SwapRouter02Decoder.sol/SwapRouter02Decoder",
        "swapRouterStandInInitCode": "SwapRouter02.t.sol/SwapRouterStandIn",
        "callRulesDecoderInitCode": "CallRulesDecoder.sol/CallRulesDecoder",
        "poolStandInInitCode": "CallRules.t.sol/PoolStandIn",
    },
}


def artifact(name):
    path = OUT / f"{name}.json"
    if not path.is_file():
        sys.exit(f"{path.relative_to(ROOT)} is missing: the build did not produce it")
    return json.loads(path.read_text())


def runtime(key, contracts):
    built = artifact(RUNTIME[key])["deployedBytecode"]
    code = built["object"].removeprefix("0x")
    refs = built.get("immutableReferences") or {}
    if refs and key not in IMMUTABLES:
        sys.exit(f"{key} has an immutable and this script does not know its value")
    if key in IMMUTABLES:
        # each immutable by its name: the build's syntax tree names the ids
        # that `immutableReferences` is keyed by
        names = immutable_names(RUNTIME[key])
        if sorted(names.get(ref_id, "?") for ref_id in refs) != sorted(IMMUTABLES[key]):
            sys.exit(f"{key}: immutables {sorted(IMMUTABLES[key])} expected, the build has {sorted(names.get(r, r) for r in refs)}")
        for ref_id, places in refs.items():
            word = contracts[IMMUTABLES[key][names[ref_id]]]["address"].removeprefix("0x").lower().rjust(64, "0")
            for ref in places:
                start, length = ref["start"] * 2, ref["length"] * 2
                if length != 64:
                    sys.exit(f"{key}: an immutable of {ref['length']} bytes")
                code = code[:start] + word + code[start + length :]
    return "0x" + code


def immutable_names(name):
    """The names of a contract's immutables, by the ids its code refers to them by."""
    found = {}

    def walk(node):
        if isinstance(node, dict):
            if node.get("nodeType") == "VariableDeclaration" and node.get("mutability") == "immutable":
                found[str(node["id"])] = node["name"]
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(artifact(name).get("ast") or {})
    return found


def main():
    write = sys.argv[1:] == ["--write"]
    if sys.argv[1:] and not write:
        sys.exit(__doc__)
    # --ast: the syntax tree names the immutables (immutable_names)
    subprocess.run(["forge", "build", "--evm-version", "osaka", "--ast"], cwd=ROOT / "contracts", check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    behind = []
    for file in ("chain-code.json", "trading-code.json"):
        path = FIXTURES / file
        fixture = json.loads(path.read_text())
        if file == "chain-code.json":
            for key in RUNTIME:
                now = runtime(key, fixture["contracts"])
                if fixture["contracts"][key]["code"].lower() != now.lower():
                    behind.append(f"{file}: contracts.{key}.code")
                    fixture["contracts"][key]["code"] = now
        for key, name in CREATION[file].items():
            now = artifact(name)["bytecode"]["object"]
            # a key the fixture does not have yet is behind like any other
            if fixture.get(key, "").lower() != now.lower():
                behind.append(f"{file}: {key}")
                fixture[key] = now
        if write:
            path.write_text(json.dumps(fixture, indent=2) + "\n")
    for entry in behind:
        print(("rewritten  " if write else "BEHIND     ") + entry)
    if not behind:
        print("Every entry of the test fixtures is the current build.")
    elif not write:
        print("The fixtures are behind the build: run scripts/test-fixtures.py --write and rerun the CLI's tests.")
        sys.exit(1)


main()
