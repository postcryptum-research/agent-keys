// What the checker makes of traces in a form the recorded ones are not in:
// addresses in checksum case (#152), a first operation without its handleOps
// call (#153), files that are not traces (#154). Part of `npm run check`.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { getAddress } from "viem";
import { ENTRY_POINT, judge, load, verdict } from "./checker.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const expected = JSON.parse(fs.readFileSync(path.join(here, "expected.json"), "utf8"));
const recorded = (name) => fs.readFileSync(path.join(here, "traces", name + ".json"), "utf8");
// every address of a value, keys included, in EIP-55 checksum case
const checksummed = (v) =>
  typeof v === "string" ? (/^0x[0-9a-f]{40}$/.test(v) ? getAddress(v) : v)
  : Array.isArray(v) ? v.map(checksummed)
  : v && typeof v === "object" ? Object.fromEntries(Object.entries(v).map(([k, x]) => [checksummed(k), checksummed(x)]))
  : v;

test("#152: every recorded trace, its addresses in checksum case, gives the recorded verdicts", () => {
  for (const [name, want] of Object.entries(expected)) {
    const t = load(JSON.stringify(checksummed(JSON.parse(recorded(name)))));
    for (const [key, verdictWanted] of Object.entries(want)) {
      assert.equal(judge(t, key), verdictWanted, `${name} (${key})`);
      assert.equal(judge({ ...t, entryPoint: getAddress(ENTRY_POINT) }, key), verdictWanted, `${name} (${key}), the EntryPoint given in checksum case`);
    }
  }
});

test("#152: a call into the EntryPoint during validation is refused whatever the case (OP-054)", () => {
  const trace = JSON.parse(recorded("7-agent-policy-deployed-plain"));
  // the account's prefund to the EntryPoint made a handleOps call instead
  Object.assign(trace.calls.find((c) => c.to === ENTRY_POINT && c.method === "0x"), { method: "0x765e827f", value: "0" });
  for (const t of [trace, checksummed(trace)])
    assert.equal(verdict(t, { precompileAllowed: true }), "REFUSED: illegal call into EntryPoint during validation handleOps");
});

test("#152: a trace that names one address in two cases is refused", () => {
  const trace = JSON.parse(recorded("7-agent-policy-deployed-plain"));
  const access = trace.callsFromEntryPoint[0].access;
  const policy = "0x12b7e79974cc4f4181a40aa11f9d3170018ae0e2";
  access[getAddress(policy)] = access[policy];
  assert.throws(() => load(JSON.stringify(trace)), /named twice, in two cases/);
});

test("#153: a first operation is judged with its factory, from its handleOps call or from the trace alone", () => {
  const name = "9-cli-first-operation-sponsored";
  const withOp = load(recorded(name));
  const bare = load(JSON.stringify(JSON.parse(recorded(name)).trace));
  const { sender, factory, paymaster } = withOp.op;
  assert.deepEqual(bare.op, { sender, factory, paymaster });
  assert.equal(factory, "0xd703aae79538628d27099b8c4f621be4ccd142d5");
  for (const t of [withOp, bare]) {
    assert.equal(judge(t, "precompileAllowed"), expected[name].precompileAllowed);
    assert.equal(judge(t, "factoryStaked"), "PASSES");
    // a stake of the factory does not excuse the account: strict, it is still refused for the precompile
    assert.equal(verdict(t.trace, { op: t.op, staked: "factory" }), "REFUSED: account accesses un-deployed contract address 0x0000000000000000000000000000000000000100 with opcode STATICCALL");
  }
});

test("#154: a file that is not a trace gets one line on stderr and exit 1", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "erc7562-"));
  const level = JSON.parse(recorded("7-agent-policy-deployed-plain")).callsFromEntryPoint[0];
  const cases = {
    "empty.json": "",
    "cut.json": '{"callsFromEntryPoint": [',
    "object.json": "{}",
    "array.json": "[]",
    "null.json": "null",
    "no-levels.json": JSON.stringify({ callsFromEntryPoint: [], calls: [], keccak: [] }),
    "level-without-access.json": JSON.stringify({ callsFromEntryPoint: [{ ...level, access: undefined }], calls: [], keccak: [] }),
    "not-handleops.json": JSON.stringify({ input: "0x12345678", trace: {} }),
  };
  try {
    for (const [file, text] of Object.entries(cases)) {
      fs.writeFileSync(path.join(dir, file), text);
      const run = spawnSync(process.execPath, [path.join(here, "check-traces.mjs"), path.join(dir, file)], { encoding: "utf8" });
      assert.equal(run.status, 1, file);
      assert.equal(run.stdout, "", file);
      // what it is not, said by this kit or by the ABI decoder; not a TypeError from further in
      assert.match(run.stderr, /^\S+: (not JSON|not a validation trace|Encoded function signature)/, file);
      assert.equal(run.stderr.trimEnd().split("\n").length, 1, `${file}: ${run.stderr}`);
    }
  } finally {
    fs.rmSync(dir, { recursive: true });
  }
});
