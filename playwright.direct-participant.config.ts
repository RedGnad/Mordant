import { defineConfig, devices } from "@playwright/test";

const PORT = Number(process.env.MORDANT_DIRECT_E2E_PORT ?? "3222");
const baseURL = `http://127.0.0.1:${PORT}`;

/** Deterministic browser qualification for the dormant two-wallet controller. */
export default defineConfig({
  testDir: "./e2e",
  testMatch: /direct-participant\.spec\.ts/,
  fullyParallel: false,
  workers: 1,
  forbidOnly: true,
  retries: 0,
  reporter: "line",
  use: {
    baseURL,
    trace: "retain-on-failure",
    ...devices["Desktop Chrome"],
  },
  webServer: {
    command: `next dev --hostname 127.0.0.1 --port ${PORT}`,
    url: baseURL,
    // Never reuse a server this run did not start. A dev server left behind by
    // another checkout answers on the same port and the whole suite then grades a
    // foreign tree, which is a false green rather than a slow one.
    reuseExistingServer: false,
    timeout: 60_000,
  },
});
