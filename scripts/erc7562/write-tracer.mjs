// Writes the validation tracer of the pinned bundler (Pimlico's Alto) to a
// file, as the text `debug_traceCall` takes for its `tracer` option.
//
//   node write-tracer.mjs tracer.js
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const validation = path.join(here, "node_modules/@pimlico/alto/esm/rpc/validation");
const { bundlerCollectorTracer } = await import(path.join(validation, "BundlerCollectorTracerV07.js"));
const { getTracerBodyString } = await import(path.join(validation, "tracer.js"));

const out = process.argv[2];
if (!out) {
  console.error("usage: node write-tracer.mjs <file>");
  process.exit(2);
}
fs.writeFileSync(out, getTracerBodyString(bundlerCollectorTracer));
