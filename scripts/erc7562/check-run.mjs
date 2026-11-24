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
//   staked     the same, with the operation's factory staked and nobody else:
//              ERC-7562 asks a stake of a factory for what ours does, and a
//              paymaster that came to need one must not pass the gate
// --gate: exit 1 unless every operation is as GATE (below) says. The
// directory should hold one run's traces only.
import fs from "node:fs";
import path from "node:path";
import { toHex } from "viem";
import { ENTRY_POINT, operations, verdict as ask } from "./checker.mjs";

// Kernel v3: the second byte of the nonce says who validates
const PATHS = { "00": "root", "01": "validator", "02": "permission" };


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
  const ops = operations(run.input);
  const name = file.replace(/\.json$/, "");
  if (ops.length !== 1) {
    rows.push({ name, path: "?", note: `a bundle of ${ops.length} operations: not checked` });
    continue;
  }
  const entryPoint = (run.entryPoint ?? ENTRY_POINT).toLowerCase();
  const op = ops[0];
  const kind = PATHS[toHex(op.nonce, { size: 32 }).slice(4, 6)] ?? "?";
  rows.push({
    name,
    path: kind,
    factory: Boolean(op.factory),
    paymaster: Boolean(op.paymaster),
    strict: ask(run.trace, { op, entryPoint }),
    precompile: ask(run.trace, { op, entryPoint, precompileAllowed: true }),
    staked: ask(run.trace, { op, entryPoint, precompileAllowed: true, staked: "factory" }),
  });
}

// What must hold, with the precompile allowed:
// - an operation without a factory passes with nobody staked (a paymaster of
//   ours does nothing that needs a stake);
// - a first operation (with a factory) is refused for the one known reason,
//   the factory's missing stake (issue #102), and passes once it is staked.
//   When the CLI goes through a staked factory this line becomes the first.
// An operation that could not be checked is outside the gate.
const KNOWN_FACTORY_REFUSAL = /^REFUSED: unstaked factory accessed /;
const GATE = (r) =>
  !r.note && (r.factory ? r.staked === "PASSES" && (r.precompile === "PASSES" || KNOWN_FACTORY_REFUSAL.test(r.precompile)) : r.precompile === "PASSES");

let failures = 0;
const lines = ["| Operation | Path | Factory | Paymaster | Strict | Precompile allowed | And the factory staked | Gate |", "|---|---|---|---|---|---|---|---|"];
for (const r of rows) {
  const ok = GATE(r);
  if (!ok) failures++;
  if (r.note) {
    console.log(`FAIL ${r.name}: ${r.note}`);
    lines.push(`| ${r.name} | | | | ${r.note} | | | **FAIL** |`);
    continue;
  }
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
