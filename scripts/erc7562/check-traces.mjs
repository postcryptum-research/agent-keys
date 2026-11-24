// Feeds each validation trace in traces/ to the ERC-7562 rule checker of a
// rule-enforcing bundler (Pimlico's Alto, the version pinned in package.json)
// and compares its verdict with expected.json. Exits non-zero on a difference.
//
//   npm install && npm run check            the recorded traces
//   node check-traces.mjs my-trace.json     a trace of your own: prints its verdicts
//
// Two verdicts per trace: the checker's as it is, and the one it gives when
// the P-256 precompile (RIP-7212, 0x…0100) is not taken for an un-deployed
// contract, which is what a bundler set up for a network that has it does.
//
// Why by hand: Alto 0.0.21 in safe mode on an anvil fork traces an operation
// and then fails on an internal decoding error before it reaches this checker.
// A trace is the `tracerResult` object it logs at --log-level info.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { verdict as ask } from "./checker.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));

// an account that is not being deployed, with no stake and no paymaster
const verdict = (trace, precompileAllowed) => ask(trace, { precompileAllowed });

const given = process.argv.slice(2);
if (given.length > 0) {
  for (const file of given) {
    const trace = JSON.parse(fs.readFileSync(file, "utf8"));
    console.log(`${file}\n    as it is:                 ${verdict(trace, false)}\n    the precompile allowed:   ${verdict(trace, true)}`);
  }
  process.exit(0);
}
const expected = JSON.parse(fs.readFileSync(path.join(here, "expected.json"), "utf8"));
let differences = 0;
for (const [name, want] of Object.entries(expected)) {
  const trace = JSON.parse(fs.readFileSync(path.join(here, "traces", name + ".json"), "utf8"));
  for (const [key, allowed] of [["asItIs", false], ["precompileAllowed", true]]) {
    const got = verdict(trace, allowed);
    const same = got === want[key];
    if (!same) differences++;
    console.log(`${same ? "as recorded" : "DIFFERENT  "}  ${name} (${key})\n    ${got}${same ? "" : "\n    recorded: " + want[key]}`);
  }
}
process.exit(differences === 0 ? 0 : 1);
