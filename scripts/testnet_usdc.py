#!/usr/bin/env python3
"""Buy Base Sepolia test USDC with the gas wallet's ETH and send it to an address.

A testnet chore, not part of the signer: swaps ETH -> USDC on Uniswap v3
(SwapRouter02, WETH/USDC pool) with the recipient set directly, so the USDC
lands at --to without a second transfer. Needs Foundry's `cast` on PATH.

    python3 scripts/testnet_usdc.py --to 0xEdB6…c9E9 --eth 0.0005 [--env-file ../.env] [--dry-run]

Reads BASE_SEPOLIA_RPC_URL and GAS_WALLET_KEYFILE from the env file (or the
environment). The key is handed to `cast send --private-key` (as `forge script`
is run for Deploy.s.sol) and never printed.
"""
import argparse
import os
import subprocess
import sys
import time
from decimal import Decimal
from pathlib import Path

CHAIN_ID = 84532
USDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
WETH = "0x4200000000000000000000000000000000000006"
SWAP_ROUTER_02 = "0x94cC0AaC535CCDB3C01d6787D6413C739ae12bc4"
QUOTER_V2 = "0xC5290058841028F1614F3A6F0F5816cAd0df5E27"
FEES = (500, 3000, 10000)


def load_env(path):
    env = {}
    if path and Path(path).exists():
        for line in Path(path).read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip().strip('"').strip("'")
    return {**env, **{k: v for k, v in os.environ.items() if k in ("BASE_SEPOLIA_RPC_URL", "GAS_WALLET_KEYFILE")}}


def cast(*args, key=None):
    env = {**os.environ, "FOUNDRY_DISABLE_NIGHTLY_WARNING": "1"}
    argv = ["cast", *args] + (["--private-key", key] if key else [])
    r = subprocess.run(argv, capture_output=True, text=True, env=env)
    if r.returncode != 0:
        sys.exit(f"cast {args[0]} failed: {r.stderr.strip()}")
    return r.stdout.strip()


def first_word(out):
    return int(out.split()[0])


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--to", required=True, help="recipient of the USDC")
    ap.add_argument("--eth", default="0.0005", help="ETH to swap (default 0.0005)")
    ap.add_argument("--slippage", default="0.05", help="accepted shortfall vs. the quote (default 5%%)")
    ap.add_argument("--env-file", default=str(Path(__file__).resolve().parents[2] / ".env"))
    ap.add_argument("--dry-run", action="store_true", help="quote only")
    a = ap.parse_args()

    env = load_env(a.env_file)
    rpc = env.get("BASE_SEPOLIA_RPC_URL") or sys.exit("BASE_SEPOLIA_RPC_URL is not set")
    if int(cast("chain-id", "--rpc-url", rpc)) != CHAIN_ID:
        sys.exit("the RPC is not Base Sepolia")
    wei = int(Decimal(a.eth) * 10**18)

    quotes = {}
    for fee in FEES:
        out = subprocess.run(
            ["cast", "call", QUOTER_V2,
             "quoteExactInputSingle((address,address,uint256,uint24,uint160))(uint256,uint160,uint32,uint256)",
             f"({WETH},{USDC},{wei},{fee},0)", "--rpc-url", rpc],
            capture_output=True, text=True, env={**os.environ, "FOUNDRY_DISABLE_NIGHTLY_WARNING": "1"},
        )
        if out.returncode == 0:
            quotes[fee] = first_word(out.stdout)
    if not quotes:
        sys.exit("no WETH/USDC pool quotes on Base Sepolia")
    fee, quote = max(quotes.items(), key=lambda kv: kv[1])
    min_out = int(quote * (1 - Decimal(a.slippage)))
    print(f"quote: {a.eth} ETH -> {quote / 1e6} USDC (pool fee {fee / 1e4}%), minimum {min_out / 1e6}")
    if a.dry_run:
        return

    keyfile = env.get("GAS_WALLET_KEYFILE") or sys.exit("GAS_WALLET_KEYFILE is not set")
    keyfile = Path(keyfile)
    if not keyfile.is_absolute():
        keyfile = Path(a.env_file).resolve().parent / keyfile
    key = keyfile.read_text().strip()
    before = first_word(cast("call", USDC, "balanceOf(address)(uint256)", a.to, "--rpc-url", rpc))
    cast(
        "send", SWAP_ROUTER_02,
        "exactInputSingle((address,address,uint24,address,uint256,uint256,uint160))",
        f"({WETH},{USDC},{fee},{a.to},{wei},{min_out},0)",
        "--value", str(wei), "--rpc-url", rpc,
        key=key,
    )
    # public RPCs answer from replicas that may lag the block the swap landed in
    for _ in range(15):
        after = first_word(cast("call", USDC, "balanceOf(address)(uint256)", a.to, "--rpc-url", rpc))
        if after != before:
            break
        time.sleep(2)
    print(f"USDC at {a.to}: {before / 1e6} -> {after / 1e6}")


if __name__ == "__main__":
    main()
