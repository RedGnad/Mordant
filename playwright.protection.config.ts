import { randomBytes } from "node:crypto";
import { copyFileSync, mkdirSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";

import { defineConfig, devices } from "@playwright/test";

const repositoryRoot = process.cwd();
const host = "127.0.0.1";
const applicationPort = Number(process.env.MORDANT_PROTECTION_E2E_PORT ?? "3112");
const adapterPort = Number(process.env.MORDANT_LOCAL_ADAPTER_PORT ?? "43125");
const baseURL = `http://${host}:${applicationPort}`;
const adapterOrigin = `http://${host}:${adapterPort}`;
const runRealLocalJourney = process.env.MORDANT_RUN_REAL_PROTECTION_E2E === "1";

function checkedInSourceCommit(): string {
  const paths = ["conflict.json", "no-conflict.json"].map((name) => join(
    repositoryRoot,
    "docs/evidence/conflicting-pledge-protection",
    name,
  ));
  const commits = paths.map((path) => {
    const value = JSON.parse(readFileSync(path, "utf8")) as { sourceCommit?: unknown };
    if (typeof value.sourceCommit !== "string" || !/^(?!0{40}$)[0-9a-f]{40}$/u.test(value.sourceCommit)) {
      throw new Error(`Protection manifest ${path} has no exact non-zero source commit`);
    }
    return value.sourceCommit;
  });
  if (commits[0] !== commits[1]) throw new Error("Protection manifests disagree on sourceCommit");
  return commits[0];
}

const sourceCommit = process.env.MORDANT_PROTECTION_SOURCE_COMMIT ?? checkedInSourceCommit();
const sharedEnvironment: Record<string, string> = {
  MORDANT_PROTECTION_SOURCE_COMMIT: sourceCommit,
};

if (runRealLocalJourney) {
  // Keep supervised-browser artifacts out of the checked-in evidence tree.
  // Imported review fixtures and create-only retention are distinct roots.
  const runtimeRoot = resolve(repositoryRoot, "test-results", `protection-runtime-${process.pid}`);
  const importedEvidenceRoot = join(runtimeRoot, "imported-evidence");
  const retentionRoot = join(runtimeRoot, "retained-evidence");
  mkdirSync(importedEvidenceRoot, { recursive: true });
  mkdirSync(retentionRoot, { recursive: true });
  for (const name of ["conflict.json", "no-conflict.json"]) {
    copyFileSync(
      join(repositoryRoot, "docs/evidence/conflicting-pledge-protection", name),
      join(importedEvidenceRoot, name),
    );
  }

  Object.assign(sharedEnvironment, {
    MORDANT_LOCAL_EXECUTION_ENABLED: "1",
    MORDANT_LOCAL_ADMIN_CAPABILITY: process.env.MORDANT_LOCAL_ADMIN_CAPABILITY ?? randomBytes(32).toString("hex"),
    MORDANT_LOCAL_ADAPTER_ORIGIN: `${adapterOrigin}/protection`,
    MORDANT_LOCAL_ADAPTER_PORT: String(adapterPort),
    MORDANT_LOCAL_BROWSER_ORIGIN: baseURL,
    MORDANT_LOCAL_DOWNSTREAM_ORIGIN: baseURL,
    MORDANT_PROTECTION_RUN_ROOT: join(runtimeRoot, "runs"),
    MORDANT_PROTECTION_EVIDENCE_ROOT: importedEvidenceRoot,
    MORDANT_PROTECTION_RETENTION_ROOT: retentionRoot,
  });
}

const webServer = [
  {
    command: `next dev --hostname ${host} --port ${applicationPort}`,
    url: baseURL,
    reuseExistingServer: false,
    timeout: 120_000,
    env: sharedEnvironment,
  },
  ...(runRealLocalJourney ? [{
    // Explicit opt-in starts the loopback-only adapter as a second process.
    // Equivalent external startup is:
    // MORDANT_RUN_REAL_PROTECTION_E2E=1 pnpm protection:adapter
    command: "node scripts/protection-local-adapter.mjs",
    url: `${adapterOrigin}/protection`,
    reuseExistingServer: false,
    timeout: 120_000,
    env: { ...sharedEnvironment, NODE_ENV: "development" },
  }] : []),
];

export default defineConfig({
  testDir: "./e2e",
  testMatch: /protection-product\.spec\.ts/u,
  outputDir: "test-results/protection-product",
  fullyParallel: false,
  workers: 1,
  forbidOnly: true,
  retries: 0,
  timeout: 180_000,
  expect: { timeout: 15_000 },
  reporter: "line",
  use: {
    ...devices["Desktop Chrome"],
    baseURL,
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    video: "retain-on-failure",
  },
  webServer,
});
