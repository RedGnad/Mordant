import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: "./e2e",
  testMatch: /(m18nws-deal-room|m18r-benchmark|mordant-experience)\.spec\.ts/,
  fullyParallel: true,
  forbidOnly: true,
  retries: 0,
  reporter: "line",
  use: {
    baseURL: "http://127.0.0.1:3102",
    trace: "retain-on-failure",
    ...devices["Desktop Chrome"],
  },
  webServer: {
    command: "next dev --hostname 127.0.0.1 --port 3102",
    url: "http://127.0.0.1:3102",
    reuseExistingServer: true,
    timeout: 30_000,
  },
});
