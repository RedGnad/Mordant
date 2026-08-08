import { defineConfig, devices } from "@playwright/test";

/**
 * Focused gate for the public product experience.
 *
 * Separate from `playwright.config.ts` on purpose: that config boots a local
 * chain for the deal-room suite, which this design work neither touches nor
 * needs. This one drives only the public surfaces, at every required viewport,
 * against deterministic fixtures and retained results.
 */

const PORT = Number(process.env.MORDANT_PUBLIC_E2E_PORT ?? "3210");
const baseURL = `http://127.0.0.1:${PORT}`;

const VIEWPORTS = [
  { name: "1440x900", width: 1440, height: 900, mobile: false },
  { name: "1280x800", width: 1280, height: 800, mobile: false },
  { name: "1024x768", width: 1024, height: 768, mobile: false },
  { name: "768x1024", width: 768, height: 1024, mobile: false },
  { name: "430x932", width: 430, height: 932, mobile: true },
  { name: "390x844", width: 390, height: 844, mobile: true },
  { name: "360x800", width: 360, height: 800, mobile: true },
] as const;

export default defineConfig({
  testDir: "./e2e",
  testMatch: /(public-product|public-experience|landing-experiment|live-product|live-product-model|verified-live-run|wallet-modal)\.spec\.ts/,
  fullyParallel: false,
  workers: 1,
  forbidOnly: true,
  retries: 0,
  reporter: "line",
  use: { baseURL, trace: "retain-on-failure" },
  projects: VIEWPORTS.map((viewport) => ({
    name: viewport.name,
    use: {
      ...(viewport.mobile ? devices["Pixel 7"] : devices["Desktop Chrome"]),
      viewport: { width: viewport.width, height: viewport.height },
      isMobile: viewport.mobile,
      hasTouch: viewport.mobile,
    },
  })),
  webServer: {
    command: `next dev --hostname 127.0.0.1 --port ${PORT}`,
    url: baseURL,
    env: {
      ...process.env,
      MORDANT_WORKER_TOKEN_SECRET: "public-e2e-token-secret-is-deterministic-only",
      NEXT_PUBLIC_MORDANT_WORKER_ORIGIN: "https://mordant-worker.test",
    },
    // Never reuse a server this run did not start. A dev server left behind by
    // another checkout answers on the same port and the whole suite then grades a
    // foreign tree, which is a false green rather than a slow one.
    reuseExistingServer: false,
    timeout: 60_000,
  },
});
