// Feeds each validation trace in traces/ to the ERC-7562 rule checker of a
// rule-enforcing bundler (Pimlico's Alto, the version pinned in package.json)
// and compares its verdict with expected.json. Exits non-zero on a difference.
//
//   npm install && npm run check            the recorded traces
//   node check-traces.mjs my-trace.json     a trace of your own: prints its verdict
//
// Why by hand: Alto 0.0.21 in safe mode on an anvil fork traces an operation
// and then fails on an internal decoding error before it reaches this checker.
// A trace is the `tracerResult` object it logs at --log-level info.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
// the package's "exports" do not name the checker, so it is taken by path
const { tracerResultParserV07 } = await import(
  path.join(here, "node_modules/@pimlico/alto/esm/rpc/validation/TracerResultParserV07.js")
);
// lower case, as the traces have it: the checker compares addresses as text
const ENTRY_POINT = "0x0000000071727de22e5e9d8baf0edac6f37da032";

function verdict(trace) {
  const sender = trace.callsFromEntryPoint[0].topLevelTargetAddress;
  // an account that is not being deployed, with no stake and no paymaster
  const userOp = { sender, nonce: 0n, callData: "0x", signature: "0x" };
  const validation = { returnInfo: {}, senderInfo: { addr: sender, stake: 0n, unstakeDelaySec: 0n } };
  try {
    tracerResultParserV07(userOp, trace, validation, ENTRY_POINT);
    return "PASSES";
  } catch (e) {
    return "REFUSED: " + String(e.message);
  }
}

const given = process.argv.slice(2);
if (given.length > 0) {
  for (const file of given) console.log(`${file}\n    ${verdict(JSON.parse(fs.readFileSync(file, "utf8")))}`);
  process.exit(0);
}
const expected = JSON.parse(fs.readFileSync(path.join(here, "expected.json"), "utf8"));
let differences = 0;
for (const [name, want] of Object.entries(expected)) {
  const got = verdict(JSON.parse(fs.readFileSync(path.join(here, "traces", name + ".json"), "utf8")));
  const same = got === want;
  if (!same) differences++;
  console.log(`${same ? "as recorded" : "DIFFERENT  "}  ${name}\n    ${got}${same ? "" : "\n    recorded: " + want}`);
}
process.exit(differences === 0 ? 0 : 1);
