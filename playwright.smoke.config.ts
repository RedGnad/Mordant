import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: "./e2e",
  testMatch: /public-product\.spec\.ts/,
  fullyParallel: false,
  workers: 1,
  forbidOnly: true,
  retries: 0,
  reporter: "line",
  use: {
    baseURL: "http://127.0.0.1:3101",
    trace: "retain-on-failure",
  },
  projects: [
    {
      name: "desktop-chromium",
      use: { ...devices["Desktop Chrome"] },
    },
    {
      name: "mobile-chromium",
      use: { ...devices["Pixel 7"] },
    },
  ],
  webServer: {
    command: "next dev --hostname 127.0.0.1 --port 3101",
    url: "http://127.0.0.1:3101",
    // Never reuse a server this run did not start. A dev server left behind by
    // another checkout answers on the same port and the whole suite then grades a
    // foreign tree, which is a false green rather than a slow one.
    reuseExistingServer: false,
    timeout: 30_000,
  },
});
