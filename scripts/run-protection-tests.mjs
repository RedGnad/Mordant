#!/usr/bin/env node

import { existsSync, readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { join } from "node:path";

const ROOT = process.cwd();
const EVIDENCE = ["conflict", "no-conflict"].map((scenario) => join(
  ROOT,
  "docs",
  "evidence",
  "conflicting-pledge-protection",
  `${scenario}.json`,
));

function command(binary, args, options = {}) {
  const result = spawnSync(binary, args, { cwd: ROOT, encoding: "utf8", ...options });
  if (result.status !== 0) {
    if (result.stdout) process.stdout.write(result.stdout);
    if (result.stderr) process.stderr.write(result.stderr);
    process.exit(result.status ?? 1);
  }
  return typeof result.stdout === "string" ? result.stdout.trim() : "";
}

function sourcePin() {
  const present = EVIDENCE.map((path) => existsSync(path));
  if (present.some(Boolean) && !present.every(Boolean)) {
    throw new Error("Both retained protection scenarios must be present or absent together");
  }
  if (!present.every(Boolean)) {
    return command("git", ["rev-parse", "HEAD"]);
  }
  const pins = EVIDENCE.map((path) => JSON.parse(readFileSync(path, "utf8")).sourceCommit);
  if (!pins.every((pin) => typeof pin === "string" && /^[0-9a-f]{40}$/.test(pin) && !/^0{40}$/.test(pin))) {
    throw new Error("Retained evidence source pin is malformed");
  }
  if (pins[0] !== pins[1]) throw new Error("Retained scenarios disagree on their source commit");
  const parent = command("git", ["rev-parse", "HEAD^"]);
  if (pins[0] !== parent) {
    throw new Error("Retained evidence must pin the exact parent source commit of the artifact head");
  }
  return pins[0];
}

let pin;
try {
  pin = sourcePin();
} catch (error) {
  process.stderr.write(`${error instanceof Error ? error.message : "Protection test provenance failed"}\n`);
  process.exit(1);
}

const environment = {
  ...process.env,
  MORDANT_PROTECTION_SOURCE_COMMIT: pin,
  NODE_PATH: "./test/stubs",
};
command(join(ROOT, "node_modules", ".bin", "tsc"), ["-p", "tsconfig.product-tests.json"], { stdio: "inherit", env: environment });
command(process.execPath, [
  "--test",
  ".product-test-dist/src/lib/protection/protection-product.test.js",
  ".product-test-dist/src/lib/protection/protection-reconciliation.test.js",
  ".product-test-dist/src/lib/protection/supervised-pledge-windows.test.js",
  ".product-test-dist/src/lib/protection/custom-supervised-v2.test.js",
  ".product-test-dist/src/lib/protection/custom-supervised-view.test.js",
  "test/protection-experience-mounted.test.cjs",
  "scripts/protection-local-adapter.test.mjs",
], { stdio: "inherit", env: environment });
