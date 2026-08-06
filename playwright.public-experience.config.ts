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
  testMatch: /(public-product|public-experience|live-product|live-product-model|wallet-modal)\.spec\.ts/,
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
    reuseExistingServer: true,
    timeout: 60_000,
  },
});
