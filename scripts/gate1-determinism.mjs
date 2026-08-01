#!/usr/bin/env node
// Gate 1 driver for external audit finding H-03.
//
// Every run below is a SEPARATE OS process that loads the same frozen key
// material from disk and recomputes the circuit. The digests are compared as
// exact bytes. There is no tolerance parameter anywhere in this file, by
// design: a tolerant comparison would hide precisely the failure this gate
// exists to detect.
import { execFileSync } from "node:child_process";
import { writeFileSync } from "node:fs";
import { resolve } from "node:path";

const HERE = process.env.GATE1_DIR ?? "/tmp/gate1";
const MATERIAL = process.env.GATE1_MATERIAL ?? "/tmp/gate1/material";

// Each entry is one separate process invocation.
const matrix = [];
for (const arch of ["arm64", "amd64"]) {
  for (const order of ["natural", "reverse", "element-sorted"]) {
    for (const procs of ["1", "4", "8"]) {
      matrix.push({ arch, order, procs });
    }
  }
}
// Repeat the baseline several times to catch flakiness across restarts rather
// than only across configurations.
for (let i = 0; i < 6; i += 1) {
  matrix.push({ arch: "arm64", order: "natural", procs: "8", tag: `restart-${i}` });
  matrix.push({ arch: "amd64", order: "natural", procs: "8", tag: `restart-${i}` });
}

const results = [];
for (const [index, entry] of matrix.entries()) {
  const binary = resolve(HERE, `probe-${entry.arch}`);
  const started = Date.now();
  const stdout = execFileSync(
    binary,
    ["evaluate", "-dir", MATERIAL, "-galois-order", entry.order, "-repeat", "2"],
    { env: { ...process.env, GOMAXPROCS: entry.procs }, encoding: "utf8", maxBuffer: 1 << 22 },
  );
  const report = JSON.parse(stdout.trim().split("\n").pop());
  results.push({ ...entry, wallMs: Date.now() - started, ...report });
  process.stderr.write(
    `[${index + 1}/${matrix.length}] ${entry.arch} ${entry.order} P=${entry.procs} ` +
      `pid=${report.pid} out=${report.output_digest.slice(0, 16)} ${report.recompute_ms}ms\n`,
  );
}

const outputDigests = new Set(results.map((r) => r.output_digest));
const inputDigests = new Set(results.map((r) => r.input_digest));
const keyDigests = new Set(results.map((r) => r.evaluation_key_digest));
const pids = new Set(results.map((r) => r.pid));

const verdict = {
  runs: results.length,
  distinctProcesses: pids.size,
  architectures: [...new Set(results.map((r) => r.goarch))].sort(),
  galoisOrders: [...new Set(results.map((r) => r.galois_order))].sort(),
  gomaxprocs: [...new Set(results.map((r) => r.gomaxprocs))].sort((a, b) => a - b),
  distinctInputDigests: [...inputDigests],
  distinctKeyDigests: [...keyDigests],
  distinctOutputDigests: [...outputDigests],
  deterministic: outputDigests.size === 1 && inputDigests.size === 1 && keyDigests.size === 1,
  recomputeMs: {
    min: Math.min(...results.map((r) => r.recompute_ms)),
    max: Math.max(...results.map((r) => r.recompute_ms)),
    median: results.map((r) => r.recompute_ms).sort((a, b) => a - b)[Math.floor(results.length / 2)],
  },
  keyLoadMs: {
    min: Math.min(...results.map((r) => r.key_load_ms)),
    max: Math.max(...results.map((r) => r.key_load_ms)),
  },
  sysMbMax: Math.max(...results.map((r) => r.sys_mb)),
};

writeFileSync(resolve(HERE, "gate1-results.json"), JSON.stringify({ verdict, results }, null, 2));
console.log(JSON.stringify(verdict, null, 2));
if (!verdict.deterministic) {
  console.error("\nGATE 1 FAILED: recomputation is not byte-identical across processes.");
  process.exit(1);
}
console.log("\nGATE 1 PASSED: byte-identical across every process, order and architecture.");
