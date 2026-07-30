import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: "./e2e",
  fullyParallel: false,
  workers: 1,
  forbidOnly: true,
  retries: 0,
  reporter: "line",
  use: {
    baseURL: "http://127.0.0.1:3100",
    trace: "retain-on-failure",
  },
  projects: [
    {
      name: "desktop-chromium",
      testMatch: /public-product\.spec\.ts/,
      use: { ...devices["Desktop Chrome"] },
    },
    {
      name: "mobile-chromium",
      testMatch: /public-product\.spec\.ts/,
      use: { ...devices["Pixel 7"] },
    },
    {
      // The deal room mutates one shared local chain, so it runs alone and in order.
      name: "transaction-run",
      testMatch: /(^|\/)deal-room\.spec\.ts$/,
      fullyParallel: false,
      workers: 1,
      use: { ...devices["Desktop Chrome"] },
    },
  ],
  webServer: [
    {
      // Deterministic local chain plus a fresh deployment for every run.
      command: "node scripts/localnet.mjs",
      url: "http://127.0.0.1:8545",
      reuseExistingServer: false,
      timeout: 120_000,
    },
    {
      command: "next dev --hostname 127.0.0.1 --port 3100",
      url: "http://127.0.0.1:3100",
      reuseExistingServer: true,
      timeout: 30_000,
    },
  ],
});
