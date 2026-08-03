import { copyFileSync, mkdirSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { defineConfig, devices } from "@playwright/test";

const repositoryRoot = process.cwd();
const host = "127.0.0.1";
const port = Number(process.env.MORDANT_PROTECTION_REJECTION_E2E_PORT ?? "3114");
const baseURL = `http://${host}:${port}`;
const retainedRoot = join(repositoryRoot, "docs", "evidence", "conflicting-pledge-protection");
// Playwright evaluates its configuration in the runner and worker processes.
// Bind all of them, plus the web server, to one isolated root for this port.
const fixtureRoot = join(tmpdir(), `mordant-protection-rejection-${port}`);
mkdirSync(fixtureRoot, { recursive: true, mode: 0o700 });

for (const name of ["conflict.json", "no-conflict.json"]) {
  copyFileSync(join(retainedRoot, name), join(fixtureRoot, name));
}
const sourceCommit = (JSON.parse(readFileSync(join(fixtureRoot, "conflict.json"), "utf8")) as {
  sourceCommit?: unknown;
}).sourceCommit;
if (typeof sourceCommit !== "string" || !/^(?!0{40}$)[0-9a-f]{40}$/u.test(sourceCommit)) {
  throw new Error("Marker-rejection tests require an exact retained source commit");
}

// The worker mutates only this temporary fixture root. The checked-in
// envelopes remain untouched and the Next process receives no private path.
process.env.MORDANT_PROTECTION_REJECTION_FIXTURE_ROOT = fixtureRoot;

export default defineConfig({
  testDir: "./e2e",
  testMatch: /protection-evidence-rejection\.spec\.ts/u,
  outputDir: "test-results/protection-evidence-rejection",
  fullyParallel: false,
  workers: 1,
  retries: 0,
  forbidOnly: true,
  reporter: "line",
  use: {
    ...devices["Desktop Chrome"],
    baseURL,
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
  webServer: {
    command: `next dev --hostname ${host} --port ${port}`,
    url: baseURL,
    reuseExistingServer: false,
    timeout: 120_000,
    env: {
      MORDANT_PROTECTION_EVIDENCE_ROOT: fixtureRoot,
      MORDANT_PROTECTION_SOURCE_COMMIT: sourceCommit,
    },
  },
});
