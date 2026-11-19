#!/usr/bin/env python3
"""
Olas transaction_settlement_abci code path, 1-agent service, owner = agent-keys Kernel.

Reproduces, with open-autonomy's own code, what a 1-agent Olas service does to
settle one Safe transaction, and swaps only the two EOA-specific steps:

  Olas step (file in open-autonomy)                          | here
  -----------------------------------------------------------+------------------------------------------
  app skill: GnosisSafeContract.get_raw_safe_transaction_hash | same function (funds_forwarder_abci style)
  app skill: payload_tools.hash_payload_to_hex                | same function
  SignatureBehaviour: get_signature(safe_tx_hash, deprecated) | REPLACED: r=Kernel, s=0, v=1 (no signing)
  FinalizeBehaviour: get_raw_safe_transaction(sender=keeper)  | same function, sender = Kernel
  send_raw_transaction (EOA tx via decision maker + ledger)   | REPLACED: agent-signer op send --json,
                                                              | EntryPoint nonce pinned per Safe tx
  ValidateTransactionBehaviour: GnosisSafeContract.verify_tx  | upstream verify_tx (expected: False under
                                                              | 4337) + event-based verify (proposed patch)

Usage (read-only by default; --send submits one userOp signed in hardware):
  python olas_kernel_safe_demo.py                     # build + simulate (eth_estimateGas from Kernel)
  python olas_kernel_safe_demo.py --send              # + agent-signer op send + verify + replay check
  python olas_kernel_safe_demo.py --check-tx 0x...    # only run both verifiers on an existing tx

Env: OPEN_AUTONOMY_SRC (clone of valory-xyz/open-autonomy at v0.21.29), BASE_SEPOLIA_RPC_URL,
     AGENT_SIGNER_BIN, AGENT_CONFIG, AGENT_ENV_FILE, AGENT_SAFE, AGENT_KERNEL, DEMO_COUNTER.
     BASE_SEPOLIA_RPC_URL is read from AGENT_ENV_FILE (default: the project .env) if unset.
"""
import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

TPM = Path(os.environ.get("TPM_SIGN", Path(__file__).resolve().parents[2]))
ENV_FILE = Path(os.environ.get("AGENT_ENV_FILE", TPM.parent / ".env"))


def _load_env_file(path: Path) -> None:
    """KEY=VALUE lines (the project .env); the process environment wins."""
    if path.is_file():
        for line in path.read_text().splitlines():
            key, sep, value = line.strip().partition("=")
            if sep and not key.startswith("#"):
                os.environ.setdefault(key.strip(), value.strip().strip('"'))


_load_env_file(ENV_FILE)

from aea.contracts.base import Contract  # noqa: E402
from aea.helpers.base import load_module  # noqa: E402
from aea_ledger_ethereum import EthereumApi  # noqa: E402

CHAIN_ID = 84532
RPC = os.environ.get("BASE_SEPOLIA_RPC_URL", "https://sepolia.base.org")
SAFE = os.environ.get("AGENT_SAFE", "0xd0b972a8ee7D8AB91a2e3381Eb6F10550B80E52A")
KERNEL = os.environ.get("AGENT_KERNEL", "0xEdB645B14e2f952C5784e34949b58F0826fBc9E9")
COUNTER = os.environ.get("DEMO_COUNTER", "0xD2Adc331B867435b82Ceba1D4f7f715eeF9FdbC1")
INCREMENT = bytes.fromhex("d09de08a")  # increment()
OA = Path(os.environ.get("OPEN_AUTONOMY_SRC", Path(__file__).resolve().parent / "open-autonomy"))

# keccak256("ExecutionSuccess(bytes32,uint256)") — Safe 1.3.0, both fields non-indexed
EXECUTION_SUCCESS = "0x442e715f626346e8c54381002da614f62bee8d27386535b2521ec8540898556e"
EXECUTION_FAILURE = "0x23428b18acfb3ea64b08dc0c1d296ea9c09702c09083ca5272e64d115b687d23"


def load_olas():
    """Load open-autonomy packages exactly as the AEA runtime does (Contract.from_dir)."""
    contracts = OA / "packages/valory/contracts"
    Contract.from_dir(str(contracts / "gnosis_safe_proxy_factory"))  # imported by gnosis_safe/contract.py
    safe_cls = type(Contract.from_dir(str(contracts / "gnosis_safe")))
    tools = load_module(
        "packages.valory.skills.transaction_settlement_abci.payload_tools",
        OA / "packages/valory/skills/transaction_settlement_abci/payload_tools.py",
    )
    return safe_cls, tools


def prevalidated_signature(owner: str) -> str:
    """What SignaturePayload.signature would carry for a contract owner that is msg.sender.

    Same format as SignatureBehaviour._get_safe_tx_signature output: hex, no 0x, 65 bytes.
    Safe 1.3.0 checkNSignatures: v == 1 -> currentOwner = address(r); require(msg.sender == currentOwner || approvedHashes[..])
    """
    return owner[2:].lower().rjust(64, "0") + "00" * 32 + "01"


def verify_by_event(api: EthereumApi, tx_hash: str, safe: str, safe_tx_hash: str) -> dict:
    """Proposed verify_tx: transport-agnostic (EOA tx, 4337 bundle, relayer) — look for the Safe's own event."""
    receipt = api.api.eth.get_transaction_receipt(tx_hash)
    want = safe_tx_hash.lower().removeprefix("0x")
    hits = {"success": False, "failure": False}
    for log in receipt["logs"]:
        if log["address"].lower() != safe.lower() or not log["topics"]:
            continue
        topic = "0x" + log["topics"][0].hex().removeprefix("0x")
        data = log["data"].hex().removeprefix("0x")
        if data[:64] == want:
            hits["success"] |= topic == EXECUTION_SUCCESS
            hits["failure"] |= topic == EXECUTION_FAILURE
    return {"verified": bool(receipt["status"]) and hits["success"] and not hits["failure"], **hits}


def safe_tx_hash_from_receipt(api: EthereumApi, tx_hash: str, safe: str) -> str:
    receipt = api.api.eth.get_transaction_receipt(tx_hash)
    for log in receipt["logs"]:
        if log["address"].lower() == safe.lower() and log["topics"] and \
                "0x" + log["topics"][0].hex().removeprefix("0x") == EXECUTION_SUCCESS:
            return "0x" + log["data"].hex().removeprefix("0x")[:64]
    raise SystemExit(f"no ExecutionSuccess from {safe} in {tx_hash}")


def run_verifiers(S, api, tx_hash, safe_tx_hash, owners, sigs, to, value, data, operation):
    up = S.verify_tx(api, SAFE, tx_hash, owners=owners, to_address=to, value=value, data=data,
                     signatures_by_owner=sigs, operation=operation, safe_tx_gas=0)
    tx = api.api.eth.get_transaction(tx_hash)
    print(f"  outer tx: from {tx['from']} to {tx['to']} (EntryPoint v0.7 = 0x0000000071727De22E5E9d8BAf0edAc6f37da032)")
    print(f"  upstream GnosisSafeContract.verify_tx -> verified={up['verified']} status={up['status']}")
    print(f"  event-based verify (proposed)          -> {verify_by_event(api, tx_hash, SAFE, safe_tx_hash)}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--send", action="store_true")
    ap.add_argument("--check-tx")
    args = ap.parse_args()

    S, tools = load_olas()
    api = EthereumApi(address=RPC, chain_id=CHAIN_ID)
    owners = tuple(S.get_owners(api, SAFE)["owners"])
    sigs = {KERNEL: prevalidated_signature(KERNEL)}
    print(f"Safe {SAFE} owners={owners} threshold={api.api.eth.contract(address=SAFE, abi=S.contract_interface['ethereum']['abi']).functions.getThreshold().call()} nonce={S.get_safe_nonce(api, SAFE)['safe_nonce']}")

    if args.check_tx:
        sth = safe_tx_hash_from_receipt(api, args.check_tx, SAFE)
        print(f"check {args.check_tx}: safeTxHash from ExecutionSuccess = {sth}")
        run_verifiers(S, api, args.check_tx, sth, owners, sigs, COUNTER, 0, INCREMENT, 0)
        return

    # 1. App skill: safe tx hash (as funds_forwarder_abci._get_safe_tx_hash does)
    h = S.get_raw_safe_transaction_hash(api, SAFE, to_address=COUNTER, value=0, data=INCREMENT,
                                        operation=0, safe_tx_gas=0, chain_id=CHAIN_ID)["tx_hash"]
    nonce = S.get_safe_nonce(api, SAFE)["safe_nonce"]
    onchain = api.api.eth.contract(address=SAFE, abi=S.contract_interface["ethereum"]["abi"]).functions.getTransactionHash(
        COUNTER, 0, INCREMENT, 0, 0, 0, 0, "0x" + "0" * 40, "0x" + "0" * 40, nonce).call()
    print(f"1. safeTxHash (Olas encode_typed_data) {h}\n   Safe.getTransactionHash(nonce={nonce})   0x{onchain.hex().removeprefix('0x')}  match={h[2:] == onchain.hex().removeprefix('0x')}")

    # 2. App skill: most_voted_tx_hash payload, then decoded by Signature/FinalizeBehaviour
    payload = tools.hash_payload_to_hex(safe_tx_hash=h[2:], ether_value=0, safe_tx_gas=0,
                                        to_address=COUNTER, data=INCREMENT, operation=0)
    p = tools.skill_input_hex_to_payload(payload)
    print(f"2. hash_payload_to_hex -> {len(payload)} hex chars; decoded to={p['to_address']} op={p['operation']}")

    # 3. SignatureBehaviour replacement: no ECDSA, a pre-validated signature
    print(f"3. participant_to_signature[{KERNEL}] = {sigs[KERNEL]}")

    # 4. FinalizeBehaviour: get_raw_safe_transaction(sender_address=keeper) — keeper = Kernel.
    #    eth_estimateGas runs from=Kernel, so this is already an on-chain check that the Safe
    #    accepts v=1 from msg.sender == owner (a wrong owner -> GS025/GS026 and gas = fallback 0).
    raw = S.get_raw_safe_transaction(api, SAFE, sender_address=KERNEL, owners=owners,
                                     to_address=p["to_address"], value=p["ether_value"], data=p["data"],
                                     signatures_by_owner=sigs, operation=p["operation"],
                                     safe_tx_gas=p["safe_tx_gas"], fallback_gas=0)
    calldata = raw["data"] if isinstance(raw["data"], str) else "0x" + raw["data"].hex()
    print(f"4. execTransaction calldata {len(calldata) // 2 - 1} bytes, eth_estimateGas from Kernel = {raw['gas']}"
          f" ({'accepted' if raw['gas'] else 'REVERTED — Kernel is not owner / bad signature'})")
    if not raw["gas"]:
        sys.exit(1)
    # negative control: same signature, keeper != Kernel -> Safe rejects (GS025), estimate fails
    neg = S.get_raw_safe_transaction(api, SAFE, sender_address="0x000000000000000000000000000000000000dEaD",
                                     owners=owners, to_address=p["to_address"], value=0, data=p["data"],
                                     signatures_by_owner=sigs, operation=0, safe_tx_gas=0, fallback_gas=0)
    print(f"   control: same v=1 signature, sender 0x…dEaD -> gas {neg['gas']} (0 = estimate reverted, as expected)")

    cmd = [os.environ.get("AGENT_SIGNER_BIN", str(TPM / "signer/target/debug/agent-signer")), "op", "send",
           "--agent", os.environ.get("AGENT_CONFIG", str(TPM / "signer/agent.tropic01.base-sepolia.json")),
           "--env-file", str(ENV_FILE),
           "--target", SAFE, "--wei", "0", "--data", calldata, "--sponsored", "--json",
           # the Safe nonce the hash above was computed for: agent-signer
           # sends the Safe tx as a batch that asserts it on-chain first
           "--safe-nonce", str(nonce)]
    shown = [("0x…" if c == calldata else c) for c in cmd]
    print("5. keeper send:", " ".join(shown))
    if not args.send:
        print("   (dry run; pass --send to submit)")
        return

    # 5. send_raw_transaction replacement. The keeper records the EntryPoint nonce
    #    of its first attempt for this safeTxHash (Olas keeps the EOA nonce in
    #    mutable_params the same way) and resends only with that nonce.
    out = subprocess.run(cmd, check=True, stdout=subprocess.PIPE, text=True).stdout.strip().splitlines()[-1]
    res = json.loads(out)
    print(f"   userOpHash {res['userOpHash']} nonce {res['nonce']} tx {res['tx']} block {res['block']}")

    # 6. ValidateTransactionBehaviour
    run_verifiers(S, api, res["tx"], h, owners, sigs, p["to_address"], p["ether_value"], p["data"], p["operation"])
    print(f"   Safe nonce now {S.get_safe_nonce(api, SAFE)['safe_nonce']} (staking activity = Safe nonce delta)")

    # 7. A keeper retry of the same Safe tx (timeout, late message), sent
    #    WITHOUT pinning the EntryPoint nonce — what a naive or compromised
    #    host would do. A v = 1 signature does not commit to the Safe nonce,
    #    but the batch's on-chain assertion does: the retry is admitted by the
    #    mandate, then reverts on-chain instead of executing twice.
    retry = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    reason = next((l.strip() for l in retry.stderr.splitlines() if "reverted" in l), retry.stderr.strip()[-200:])
    after = S.get_safe_nonce(api, SAFE)["safe_nonce"]
    print(f"7. keeper retry, unpinned -> exit {retry.returncode}: {reason}")
    print(f"   Safe nonce still {after}: the call ran once")
    if retry.returncode == 0 or after != nonce + 1:
        sys.exit("the retry executed: double execution")


if __name__ == "__main__":
    main()
