#!/usr/bin/env node
/** M-15 phase C2. A thin entry point; the gates and plan live in m15-phase-runner.mjs. */
import { spawnSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const result = spawnSync(process.execPath,
  [join(here, "m15-phase-runner.mjs"), "--phase", "C2", ...process.argv.slice(2)],
  { stdio: "inherit" });
process.exitCode = result.status ?? 1;
