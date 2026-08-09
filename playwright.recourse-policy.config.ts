import { defineConfig, devices } from "@playwright/test";

const externalBaseUrl = process.env.MORDANT_RECOURSE_E2E_BASE_URL;

export default defineConfig({
  testDir: "./e2e",
  testMatch: /governed-recourse-policy\.spec\.ts/,
  fullyParallel: false,
  workers: 1,
  forbidOnly: true,
  retries: 0,
  reporter: "line",
  use: {
    ...devices["Desktop Chrome"],
    baseURL: externalBaseUrl ?? "http://127.0.0.1:3117",
    trace: "retain-on-failure",
  },
  webServer: externalBaseUrl === undefined ? {
    command: "next dev --hostname 127.0.0.1 --port 3117",
    url: "http://127.0.0.1:3117/design-lab/governed-recourse-policy",
    reuseExistingServer: false,
    timeout: 30_000,
  } : undefined,
});
