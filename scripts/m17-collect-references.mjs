#!/usr/bin/env node
/**
 * M-17: capture the reference set.
 *
 * Homogeneous captures at fixed viewports so references can be compared rather than remembered.
 * A site that blocks, stalls or shows a consent wall is recorded as such: an honest gap is more
 * useful than a screenshot of a cookie banner presented as a design reference.
 *
 *   node scripts/m17-collect-references.mjs [--only <id>]
 *
 * Nothing here touches the product. It reads public pages and writes PNGs plus a manifest.
 */
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { chromium } from "@playwright/test";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const OUT = join(ROOT, "docs/design/m17/references");

const VIEWPORTS = Object.freeze([
  { id: "desktop", width: 1440, height: 900 },
  { id: "laptop", width: 1280, height: 800 },
]);
const MOBILE = Object.freeze({ id: "mobile", width: 390, height: 844 });

/**
 * The reference set. Deliberately mixed: landing pages alone would say nothing about how these
 * teams handle density, errors or operational state, so documentation and product surfaces are
 * included wherever they are reachable without an account.
 */
export const REFERENCES = Object.freeze([
  // --- raw systems / diagrammatic interfaces ---
  { id: "observable", territory: "raw-systems", name: "Observable",
    url: "https://observablehq.com/", surface: "product landing", mobile: true },
  { id: "observable-docs", territory: "raw-systems", name: "Observable Framework docs",
    url: "https://observablehq.com/framework/", surface: "documentation" },
  { id: "tldraw", territory: "raw-systems", name: "tldraw",
    url: "https://www.tldraw.com/", surface: "live product canvas" },
  { id: "excalidraw", territory: "raw-systems", name: "Excalidraw",
    url: "https://excalidraw.com/", surface: "live product canvas" },

  // --- scientific and laboratory visual systems ---
  { id: "benchling", territory: "scientific", name: "Benchling",
    url: "https://www.benchling.com/", surface: "enterprise landing" },
  { id: "plotly", territory: "scientific", name: "Plotly",
    url: "https://plotly.com/", surface: "data tooling landing" },
  { id: "deepnote", territory: "scientific", name: "Deepnote",
    url: "https://deepnote.com/", surface: "notebook product landing" },

  // --- expressive editorial enterprise ---
  { id: "stripe-docs", territory: "editorial-enterprise", name: "Stripe API reference",
    url: "https://docs.stripe.com/api", surface: "dense documentation", mobile: true },
  { id: "vercel", territory: "editorial-enterprise", name: "Vercel",
    url: "https://vercel.com/", surface: "product landing" },
  { id: "linear", territory: "editorial-enterprise", name: "Linear",
    url: "https://linear.app/", surface: "product landing", mobile: true },
  { id: "37signals", territory: "editorial-enterprise", name: "37signals",
    url: "https://37signals.com/", surface: "company site" },

  // --- tactile or post-digital identities ---
  { id: "teenage-engineering", territory: "tactile", name: "Teenage Engineering",
    url: "https://teenage.engineering/", surface: "product catalogue", mobile: true },
  { id: "panic", territory: "tactile", name: "Panic",
    url: "https://panic.com/", surface: "software studio" },
  { id: "area17", territory: "tactile", name: "AREA 17",
    url: "https://area17.com/", surface: "studio site" },

  // --- material or dimensional interfaces ---
  { id: "rive", territory: "material", name: "Rive",
    url: "https://rive.app/", surface: "runtime product landing" },
  { id: "spline", territory: "material", name: "Spline",
    url: "https://spline.design/", surface: "3D tool landing" },

  // --- strongly branded financial products ---
  { id: "mercury", territory: "financial", name: "Mercury",
    url: "https://mercury.com/", surface: "banking landing", mobile: true },
  { id: "ramp", territory: "financial", name: "Ramp",
    url: "https://ramp.com/", surface: "spend management landing" },
  { id: "monzo", territory: "financial", name: "Monzo",
    url: "https://monzo.com/", surface: "consumer banking", mobile: true },
  { id: "wise", territory: "financial", name: "Wise",
    url: "https://wise.com/", surface: "cross-border payments" },
]);

async function capture(browser, reference, viewport) {
  const context = await browser.newContext({
    viewport: { width: viewport.width, height: viewport.height },
    deviceScaleFactor: 1,
    reducedMotion: "reduce",
    locale: "en-US",
  });
  const page = await context.newPage();
  const file = join(OUT, `${reference.id}-${viewport.id}.png`);
  try {
    const response = await page.goto(reference.url, {
      waitUntil: "domcontentloaded", timeout: 45_000,
    });
    const status = response?.status() ?? null;
    // Give lazy hero content a moment, then settle. Networkidle stalls on analytics-heavy sites.
    await page.waitForTimeout(3_500);
    await page.screenshot({ path: file, fullPage: false });
    const title = await page.title();
    await context.close();
    return { ok: true, status, title, file: `docs/design/m17/references/${reference.id}-${viewport.id}.png` };
  } catch (error) {
    await context.close();
    return { ok: false, error: String(error.message).split("\n")[0].slice(0, 160) };
  }
}

async function main() {
  const argv = process.argv.slice(2);
  const onlyIndex = argv.indexOf("--only");
  const only = onlyIndex === -1 ? null : argv[onlyIndex + 1];
  const set = only ? REFERENCES.filter((entry) => entry.id === only) : REFERENCES;

  mkdirSync(OUT, { recursive: true });
  const browser = await chromium.launch();
  const manifest = [];

  for (const reference of set) {
    const shots = {};
    for (const viewport of VIEWPORTS) {
      shots[viewport.id] = await capture(browser, reference, viewport);
    }
    if (reference.mobile) shots.mobile = await capture(browser, reference, MOBILE);
    const captured = Object.values(shots).filter((entry) => entry.ok).length;
    manifest.push({ ...reference, shots, captured });
    process.stdout.write(
      `${reference.id.padEnd(22)} ${String(captured).padStart(2)}/${Object.keys(shots).length}`
      + ` ${shots.desktop.ok ? shots.desktop.title?.slice(0, 60) ?? "" : shots.desktop.error}\n`);
  }

  await browser.close();
  const total = manifest.reduce((sum, entry) => sum + entry.captured, 0);
  const usable = manifest.filter((entry) => entry.shots.desktop.ok);
  writeFileSync(join(ROOT, "docs/design/m17/reference-manifest.json"),
    `${JSON.stringify({
      generatedAt: new Date().toISOString(),
      viewports: [...VIEWPORTS, MOBILE],
      note: "Public pages captured for design comparison. A failed capture is recorded rather than"
        + " replaced: a screenshot of a consent wall is not a design reference.",
      referenceCount: manifest.length,
      usableCount: usable.length,
      captureCount: total,
      references: manifest,
    }, null, 2)}\n`, "utf8");
  process.stdout.write(`\n${usable.length}/${manifest.length} references usable, ${total} captures\n`);
}

const invokedDirectly = process.argv[1]?.endsWith("m17-collect-references.mjs");
if (invokedDirectly) {
  main().catch((error) => {
    process.stderr.write(`\nSTOPPED: ${error.message}\n`);
    process.exitCode = 1;
  });
}
