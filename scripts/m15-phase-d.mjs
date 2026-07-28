#!/usr/bin/env node
/**
 * M-15 phase D. Selects one sub-action of the real engine and stops.
 *
 * Sub-actions: D.grant, D.mint, D.revokeGrant, D.bind
 *
 * Each is a separate deliberate command. None triggers the next, and none runs against Monad public
 * while PUBLIC_WRITES_AUTHORIZED is false in scripts/m15-engine.mjs.
 */
import { spawnSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const STEPS = ['D.grant', 'D.mint', 'D.revokeGrant', 'D.bind'];
const here = dirname(fileURLToPath(import.meta.url));
const argv = process.argv.slice(2);
const stepIndex = argv.indexOf("--step");
const step = stepIndex === -1 ? STEPS[0] : argv[stepIndex + 1];
if (!STEPS.includes(step)) {
  process.stderr.write(`STOP — --step must be one of ${STEPS.join(", ")} for phase D.\n`);
  process.exitCode = 1;
} else {
  const rest = stepIndex === -1 ? argv : [...argv.slice(0, stepIndex), ...argv.slice(stepIndex + 2)];
  const result = spawnSync(process.execPath,
    [join(here, "m15-phase-runner.mjs"), "--step", step, ...rest], { stdio: "inherit" });
  process.exitCode = result.status ?? 1;
}
