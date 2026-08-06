#!/usr/bin/env node

import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { join } from "node:path";

const ROOT = process.cwd();

/**
 * Provenance anchors for the retained A8 evidence.
 *
 * These are immutable facts about one historical commit, not about whatever is checked
 * out now. The gate used to require the retained pin to equal `HEAD^`, which only ever
 * held while the artifact commit was the head: every later release head failed it, so
 * the suite could not run at a release head at all. Anchoring to the artifact commit
 * keeps the same guarantee and makes it hold at any descendant.
 */
const ARTIFACT_COMMIT = "0e03622241c862f13736229cf08106992520ddc6";
const ACCEPTED_SOURCE_COMMIT = "b5587f6489933c6dc462da7fda56e57bd5f9e31b";
const ENVELOPES = Object.freeze({
  conflict: "e24dfd8aebcda4802e66a4ac08c1b5e49b494e40aea26fedee16548103f9d635",
  "no-conflict": "844edf04d3b66fc691f817b0ee49856d94fe219ee7930b89b983fedb71f6c308",
});

const EVIDENCE = Object.keys(ENVELOPES).map((scenario) => join(
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

function optional(binary, args) {
  const result = spawnSync(binary, args, { cwd: ROOT, encoding: "utf8" });
  return { ok: result.status === 0, out: typeof result.stdout === "string" ? result.stdout.trim() : "" };
}

function sourcePin() {
  const present = EVIDENCE.map((path) => existsSync(path));
  if (present.some(Boolean) && !present.every(Boolean)) {
    throw new Error("Both retained protection scenarios must be present or absent together");
  }
  if (!present.every(Boolean)) {
    return command("git", ["rev-parse", "HEAD"]);
  }

  // 1. The retained bytes are exactly the validated A8 envelopes.
  for (const [scenario, expected] of Object.entries(ENVELOPES)) {
    const path = join(ROOT, "docs", "evidence", "conflicting-pledge-protection", `${scenario}.json`);
    const actual = createHash("sha256").update(readFileSync(path)).digest("hex");
    if (actual !== expected) {
      throw new Error(`Retained ${scenario} evidence is not the validated A8 envelope`);
    }
  }

  // 2. Both scenarios pin the one accepted source commit.
  const pins = EVIDENCE.map((path) => JSON.parse(readFileSync(path, "utf8")).sourceCommit);
  if (!pins.every((pin) => typeof pin === "string" && /^[0-9a-f]{40}$/u.test(pin) && !/^0{40}$/u.test(pin))) {
    throw new Error("Retained evidence source pin is malformed");
  }
  if (pins[0] !== pins[1]) throw new Error("Retained scenarios disagree on their source commit");
  if (pins[0] !== ACCEPTED_SOURCE_COMMIT) {
    throw new Error("Retained evidence does not pin the accepted A8 source commit");
  }

  // 3. This checkout really descends from the artifact commit, so the retained evidence
  //    belongs to this history rather than being copied into an unrelated tree.
  const artifact = optional("git", ["cat-file", "-e", `${ARTIFACT_COMMIT}^{commit}`]);
  if (!artifact.ok) {
    throw new Error("The A8 artifact commit is missing; check out with full history (fetch-depth 0)");
  }
  const descends = spawnSync("git", ["merge-base", "--is-ancestor", ARTIFACT_COMMIT, "HEAD"], { cwd: ROOT });
  if (descends.status !== 0) {
    throw new Error("This head does not descend from the validated A8 artifact commit");
  }

  // 4. The accepted source is the artifact commit's own parent. That is the durable form
  //    of the original rule: it is a fact about the artifact, not about the head.
  const artifactParent = command("git", ["rev-parse", `${ARTIFACT_COMMIT}^`]);
  if (artifactParent !== ACCEPTED_SOURCE_COMMIT) {
    throw new Error("The accepted source commit is not the parent of the A8 artifact commit");
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
// One invocation, one environment, every registered file exactly once: a file listed
// twice could pass in one run and be hidden by the other.
const TEST_FILES = Object.freeze([
  ".product-test-dist/src/lib/protection/protection-product.test.js",
  ".product-test-dist/src/lib/protection/protection-reconciliation.test.js",
  ".product-test-dist/src/lib/protection/supervised-pledge-windows.test.js",
  ".product-test-dist/src/lib/protection/custom-supervised-v2.test.js",
  ".product-test-dist/src/lib/protection/custom-supervised-view.test.js",
  ".product-test-dist/src/lib/protection/live-launch-token.test.js",
  ".product-test-dist/src/lib/protection/ccp-eligibility.test.js",
  ".product-test-dist/src/lib/protection/participant-authorization.test.js",
  ".product-test-dist/src/lib/protection/participant-admission.test.js",
  ".product-test-dist/src/lib/protection/participant-admission-engine.test.js",
  ".product-test-dist/src/lib/protection/governed-recourse-bridge.test.js",
  "test/protection-experience-mounted.test.cjs",
  "scripts/protection-local-adapter.test.mjs",
  "scripts/mordant-live-worker.test.mjs",
  "scripts/live-token-route.test.mjs",
]);

const duplicates = TEST_FILES.filter((file, index) => TEST_FILES.indexOf(file) !== index);
if (duplicates.length > 0) {
  process.stderr.write(`Duplicate registered test files: ${duplicates.join(", ")}\n`);
  process.exit(1);
}
const missing = TEST_FILES.filter((file) => !existsSync(join(ROOT, file)));
if (missing.length > 0) {
  process.stderr.write(`Registered test files are missing: ${missing.join(", ")}\n`);
  process.exit(1);
}

process.stdout.write(`Running ${TEST_FILES.length} registered protection test files\n`);
command(process.execPath, ["--test", ...TEST_FILES], { stdio: "inherit", env: environment });
