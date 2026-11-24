// Feeds each validation trace in traces/ to the ERC-7562 rule checker of a
// rule-enforcing bundler (Pimlico's Alto, the version pinned in package.json)
// and compares its verdicts with expected.json. Exits non-zero on a difference.
//
//   npm install && npm run check            the recorded traces, then test.mjs
//   node check-traces.mjs my-trace.json     a trace of your own: prints its verdicts
//
// Two verdicts per trace: the checker's as it is, and the one it gives when
// the P-256 precompile (RIP-7212, 0x0000000000000000000000000000000000000100)
// is not taken for an un-deployed contract, which is what a bundler set up for
// a network that has it does. A first operation gets a third: that, with its
// factory staked.
//
// Why by hand: Alto 0.0.21 in safe mode on an anvil fork traces an operation
// and then fails on an internal decoding error before it reaches this checker.
// A trace is the `tracerResult` object it logs at --log-level info, or a file
// of check-run.mjs's, which also carries the operation. The account, factory
// and paymaster are read from the operation when it is there, from the trace
// when not (checker.mjs). A file that is not a trace gets one line on stderr
// and exit 1.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { judge, load } from "./checker.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const LABELS = { asItIs: "as it is", precompileAllowed: "the precompile allowed", factoryStaked: "and the factory staked" };

const given = process.argv.slice(2);
if (given.length > 0) {
  let unreadable = 0;
  for (const file of given) {
    try {
      const t = load(fs.readFileSync(file, "utf8"));
      const names = t.op.factory ? Object.keys(LABELS) : ["asItIs", "precompileAllowed"];
      console.log(file + names.map((n) => `\n    ${(LABELS[n] + ":").padEnd(26)}${judge(t, n)}`).join(""));
    } catch (e) {
      unreadable++;
      console.error(`${file}: ${(e.shortMessage ?? e.message).split("\n")[0]}`);
    }
  }
  process.exit(unreadable === 0 ? 0 : 1);
}
const expected = JSON.parse(fs.readFileSync(path.join(here, "expected.json"), "utf8"));
let differences = 0;
for (const [name, want] of Object.entries(expected)) {
  const t = load(fs.readFileSync(path.join(here, "traces", name + ".json"), "utf8"));
  for (const [key, recorded] of Object.entries(want)) {
    const got = judge(t, key);
    const same = got === recorded;
    if (!same) differences++;
    console.log(`${same ? "as recorded" : "DIFFERENT  "}  ${name} (${key})\n    ${got}${same ? "" : "\n    recorded: " + recorded}`);
  }
}
process.exit(differences === 0 ? 0 : 1);
