// The ERC-7562 verdict for every operation the CLI's local-chain tests got
// included (signer/crates/agent-signer/tests/anvil_cli.rs, run with
// ERC7562_TRACER and ERC7562_TRACE_DIR set): each `handleOps` is traced again
// under the bundler's validation tracer and given to the bundler's rule
// checker, the same one check-traces.mjs uses.
//
//   node check-run.mjs <trace dir> [--gate] [--summary <markdown file>]
//
// Three verdicts per operation:
//   strict     the checker as it is, nobody staked
//   precompile the P-256 precompile (RIP-7212) not taken for an un-deployed
//              contract: a bundler set up for a network that has it
//   staked     the same, with the operation's factory and paymaster staked,
//              which ERC-7562 asks of them for what they do here
// --gate: exit 1 unless every operation passes as GATE (below) says.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { decodeFunctionData, parseAbi, size, slice, toHex } from "viem";

const here = path.dirname(fileURLToPath(import.meta.url));
const { tracerResultParserV07 } = await import(
  path.join(here, "node_modules/@pimlico/alto/esm/rpc/validation/TracerResultParserV07.js")
);
const ENTRY_POINT = "0x0000000071727de22e5e9d8baf0edac6f37da032";
const P256_PRECOMPILE = "0x0000000000000000000000000000000000000100";
const handleOps = parseAbi([
  "struct PackedUserOperation { address sender; uint256 nonce; bytes initCode; bytes callData; bytes32 accountGasLimits; uint256 preVerificationGas; bytes32 gasFees; bytes paymasterAndData; bytes signature; }",
  "function handleOps(PackedUserOperation[] ops, address beneficiary)",
]);
// Kernel v3: the second byte of the nonce says who validates
const PATHS = { "00": "root", "01": "validator", "02": "permission" };

function verdict(recorded, op, { precompile, staked }) {
  const trace = structuredClone(recorded);
  if (precompile) for (const level of trace.callsFromEntryPoint) delete level.contractSize?.[P256_PRECOMPILE];
  const stake = staked ? 1n : 0n;
  const entity = (addr) => (addr ? { addr, stake, unstakeDelaySec: stake } : undefined);
  const userOp = { sender: op.sender, nonce: op.nonce, callData: op.callData, signature: "0x", factory: op.factory, paymaster: op.paymaster };
  const validation = {
    returnInfo: {},
    senderInfo: { addr: op.sender, stake: 0n, unstakeDelaySec: 0n },
    factoryInfo: entity(op.factory),
    paymasterInfo: entity(op.paymaster),
  };
  try {
    tracerResultParserV07(userOp, trace, validation, ENTRY_POINT);
    return "PASSES";
  } catch (e) {
    return "REFUSED: " + String(e.message);
  }
}

const args = process.argv.slice(2);
const dir = args.find((a) => !a.startsWith("--") && args[args.indexOf(a) - 1] !== "--summary");
const gate = args.includes("--gate");
const summaryFile = args.includes("--summary") ? args[args.indexOf("--summary") + 1] : null;
if (!dir) {
  console.error("usage: node check-run.mjs <trace dir> [--gate] [--summary <markdown file>]");
  process.exit(2);
}

const rows = [];
for (const file of fs.readdirSync(dir).filter((f) => f.endsWith(".json")).sort()) {
  const run = JSON.parse(fs.readFileSync(path.join(dir, file), "utf8"));
  const { args: [ops] } = decodeFunctionData({ abi: handleOps, data: run.input });
  const name = file.replace(/\.json$/, "");
  if (ops.length !== 1) {
    rows.push({ name, path: "?", note: `a bundle of ${ops.length} operations: not checked` });
    continue;
  }
  const packed = ops[0];
  const op = {
    sender: packed.sender.toLowerCase(),
    nonce: packed.nonce,
    callData: packed.callData,
    factory: size(packed.initCode) >= 20 ? slice(packed.initCode, 0, 20).toLowerCase() : undefined,
    paymaster: size(packed.paymasterAndData) >= 20 ? slice(packed.paymasterAndData, 0, 20).toLowerCase() : undefined,
  };
  const kind = PATHS[toHex(packed.nonce, { size: 32 }).slice(4, 6)] ?? "?";
  rows.push({
    name,
    path: kind,
    factory: Boolean(op.factory),
    paymaster: Boolean(op.paymaster),
    strict: verdict(run.trace, op, { precompile: false, staked: false }),
    precompile: verdict(run.trace, op, { precompile: true, staked: false }),
    staked: verdict(run.trace, op, { precompile: true, staked: true }),
  });
}

// What must hold. An operation with neither factory nor paymaster has nobody
// to stake, so it must pass with the precompile allowed; one with either must
// pass once they are staked.
const GATE = (r) => (r.factory || r.paymaster ? r.staked : r.precompile) === "PASSES";

let failures = 0;
const lines = ["| Operation | Path | Factory | Paymaster | Strict | Precompile allowed | And entities staked | Gate |", "|---|---|---|---|---|---|---|---|"];
for (const r of rows) {
  if (r.note) {
    console.log(`${r.name}: ${r.note}`);
    lines.push(`| ${r.name} | | | | ${r.note} | | | |`);
    continue;
  }
  const ok = GATE(r);
  if (!ok) failures++;
  console.log(`${ok ? "ok  " : "FAIL"} ${r.name}  path=${r.path} factory=${r.factory} paymaster=${r.paymaster}\n      strict:     ${r.strict}\n      precompile: ${r.precompile}\n      staked:     ${r.staked}`);
  lines.push(`| ${r.name} | ${r.path} | ${r.factory ? "yes" : ""} | ${r.paymaster ? "yes" : ""} | ${r.strict} | ${r.precompile} | ${r.staked} | ${ok ? "ok" : "**FAIL**"} |`);
}
console.log(`\n${rows.length} operations, ${failures} outside the gate`);
if (summaryFile) fs.appendFileSync(summaryFile, `### ERC-7562: the operations of the local-chain tests\n\n${lines.join("\n")}\n\n${rows.length} operations, ${failures} outside the gate.\n`);
if (rows.length === 0) {
  console.error("no traces: the tests wrote none");
  process.exit(1);
}
process.exit(gate && failures > 0 ? 1 : 0);
