#!/usr/bin/env node

import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { chromium } from "@playwright/test";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const OUTPUT = join(ROOT, "docs/design/assets/m-ex1-review-film.webm");
const BASE_URL = process.env.MORDANT_REVIEW_BASE_URL ?? "http://127.0.0.1:3100";
const EXPERIENCE_URL = `${BASE_URL}/design-lab/mordant-experience`;
const VIEWPORT = { width: 1440, height: 900 };
const ACTIONS = [
  "Let the exception appear",
  "Isolate this deal",
  "See the holder view",
  "Advance to the deadline",
  "Show the modeled resolution",
];

async function main() {
  const temporaryDirectory = mkdtempSync(join(tmpdir(), "mordant-m-ex1-film-"));
  mkdirSync(dirname(OUTPUT), { recursive: true });

  const browser = await chromium.launch();
  const context = await browser.newContext({
    viewport: VIEWPORT,
    screen: VIEWPORT,
    deviceScaleFactor: 1,
    locale: "en-US",
    colorScheme: "light",
    reducedMotion: "no-preference",
    recordVideo: { dir: temporaryDirectory, size: VIEWPORT },
  });

  try {
    const page = await context.newPage();
    const video = page.video();

    await page.goto(EXPERIENCE_URL, { waitUntil: "networkidle" });
    await page.locator("#experience-title").waitFor({ state: "visible" });
    await page.waitForTimeout(3_500);

    for (const action of ACTIONS) {
      await page.getByRole("button", { name: action, exact: true }).click();
      await page.waitForTimeout(3_800);
    }

    await page.getByRole("button", { name: "Open retained record", exact: true }).click();
    await page.waitForTimeout(3_500);
    await page.getByTestId("experience-technical-record").locator("summary").click();
    await page.waitForTimeout(800);
    await page.getByTestId("experience-technical-record").scrollIntoViewIfNeeded();
    await page.waitForTimeout(4_700);

    await context.close();
    if (!video) throw new Error("Playwright did not create a review recording.");
    await video.saveAs(OUTPUT);
  } finally {
    await browser.close();
    rmSync(temporaryDirectory, { recursive: true, force: true });
  }

  process.stdout.write(`${OUTPUT}\n`);
}

main().catch((error) => {
  process.stderr.write(`Review film failed: ${error.message}\n`);
  process.exitCode = 1;
});
