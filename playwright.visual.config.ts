import { defineConfig, devices } from "@playwright/test";

/**
 * The visual freeze for the live product surfaces.
 *
 * Three viewports, one per layout regime the stylesheet actually defines. The
 * breakpoints are 1200px, 761px and 40.01rem, so each entry below sits inside a
 * regime rather than on its edge: 768 would be 7px above the 761 boundary and
 * would fail for rounding rather than for regression.
 *
 * These widths are taken from the public-experience matrix; no new dimension is
 * invented here.
 */

const PORT = Number(process.env.MORDANT_VISUAL_E2E_PORT ?? "3244");
const baseURL = `http://127.0.0.1:${PORT}`;

const VIEWPORTS = [
  { name: "1440x900", width: 1440, height: 900, mobile: false },
  { name: "1024x768", width: 1024, height: 768, mobile: false },
  { name: "360x800", width: 360, height: 800, mobile: true },
] as const;

export default defineConfig({
  testDir: "./e2e",
  testMatch: /live-visual-baseline\.spec\.ts/,
  fullyParallel: false,
  workers: 1,
  forbidOnly: true,
  retries: 0,
  reporter: "line",
  use: { baseURL, trace: "retain-on-failure" },
  // A reference is a fact about the current design, so a run that finds none
  // must fail rather than quietly mint one and report success.
  ignoreSnapshots: false,
  updateSnapshots: "none",
  expect: {
    toHaveScreenshot: {
      animations: "disabled",
      caret: "hide",
      scale: "css",
      // Zero, and measured rather than assumed: two consecutive comparison
      // passes against these references produced byte-identical renders, so any
      // tolerance here would only hide a real difference.
      maxDiffPixelRatio: 0,
    },
  },
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
    reuseExistingServer: false,
    timeout: 120_000,
    // Read by next.config.ts to drop the dev indicator, which is painted over
    // the page and would otherwise be captured as if it were the product.
    env: { MORDANT_VISUAL_E2E: "1" },
  },
});
