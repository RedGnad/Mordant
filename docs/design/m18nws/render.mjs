import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { chromium } from "@playwright/test";

const currentDirectory = path.dirname(fileURLToPath(import.meta.url));
const localBaseUrl = process.env.M18NWS_BASE_URL ?? "http://127.0.0.1:3100";
const lockInUrl = process.env.M18NWS_LOCK_IN_URL ?? "https://lock-in.quest";

const captures = [
  {
    label: "Lock-in",
    url: lockInUrl,
    file: "lock-in-reference-1280x800.png",
    width: 1280,
    height: 800,
  },
  {
    label: "Lock-in / grayscale",
    url: lockInUrl,
    file: "lock-in-reference-1280x800-grayscale.png",
    width: 1280,
    height: 800,
    grayscale: true,
  },
  {
    label: "M-18R",
    url: `${localBaseUrl}/design-lab/m18r-deal-room`,
    file: "m18r-deal-room-1280x800-reference.png",
    width: 1280,
    height: 800,
  },
  {
    label: "M-18R / grayscale",
    url: `${localBaseUrl}/design-lab/m18r-deal-room`,
    file: "m18r-deal-room-1280x800-grayscale.png",
    width: 1280,
    height: 800,
    grayscale: true,
  },
  {
    label: "M-18NWS",
    url: `${localBaseUrl}/design-lab/m18nws-deal-room`,
    file: "m18nws-deal-room-1280x800.png",
    width: 1280,
    height: 800,
  },
  {
    label: "M-18NWS / grayscale",
    url: `${localBaseUrl}/design-lab/m18nws-deal-room`,
    file: "m18nws-deal-room-1280x800-grayscale.png",
    width: 1280,
    height: 800,
    grayscale: true,
  },
  {
    label: "M-18NWS / mobile",
    url: `${localBaseUrl}/design-lab/m18nws-deal-room`,
    file: "m18nws-deal-room-390x844.png",
    width: 390,
    height: 844,
  },
  {
    label: "M-18NWS / mobile grayscale",
    url: `${localBaseUrl}/design-lab/m18nws-deal-room`,
    file: "m18nws-deal-room-390x844-grayscale.png",
    width: 390,
    height: 844,
    grayscale: true,
  },
];

async function capture(browser, definition) {
  const context = await browser.newContext({
    colorScheme: "light",
    reducedMotion: "reduce",
    viewport: { width: definition.width, height: definition.height },
  });
  const page = await context.newPage();

  await page.goto(definition.url, { waitUntil: "domcontentloaded", timeout: 45_000 });
  await page.waitForLoadState("networkidle", { timeout: 5_000 }).catch(() => undefined);
  await page.evaluate(() => document.fonts.ready);

  // The local renderer may target `next dev`; its tooling portal is not part of
  // the benchmark and does not exist in a production preview.
  await page.addStyleTag({ content: "nextjs-portal { display: none !important; }" });

  if (definition.url.startsWith(localBaseUrl)) {
    const benchmark = definition.url.includes("m18nws") ? "m18nws-benchmark" : "m18r-benchmark";
    await page.getByTestId(benchmark).waitFor({ state: "visible" });
  }

  if (definition.grayscale) {
    await page.addStyleTag({
      // Chromium may flatten a root-element filter differently between the
      // development and production servers. Filtering the body keeps the
      // captured geometry identical while producing a verifiable gray frame.
      content: `
        *, *::before, *::after { animation: none !important; transition: none !important; }
        body { filter: grayscale(1) !important; }
      `,
    });
    await page.evaluate(
      () => new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve))),
    );
    const filter = await page.evaluate(() => getComputedStyle(document.body).filter);
    if (filter !== "grayscale(1)") {
      throw new Error(`Grayscale filter was not applied for ${definition.label}: ${filter}`);
    }
  }

  await page.screenshot({ path: path.join(currentDirectory, definition.file) });
  console.log(`Captured ${definition.label}${definition.grayscale ? " [grayscale]" : ""}`);
  await context.close();
}

async function asDataUrl(file) {
  const bytes = await readFile(path.join(currentDirectory, file));
  return `data:image/png;base64,${bytes.toString("base64")}`;
}

async function renderComparison(browser) {
  const rows = [
    captures.filter(({ width, grayscale }) => width === 1280 && !grayscale),
    captures.filter(({ width, grayscale }) => width === 1280 && grayscale),
  ];
  const cards = [];

  for (const row of rows) {
    for (const definition of row) {
      cards.push(`
        <figure>
          <figcaption>${definition.label}</figcaption>
          <img src="${await asDataUrl(definition.file)}" alt="" />
        </figure>
      `);
    }
  }

  const page = await browser.newPage({ viewport: { width: 1536, height: 1110 } });
  await page.setContent(`
    <!doctype html>
    <html lang="en">
      <head>
        <meta charset="utf-8" />
        <style>
          * { box-sizing: border-box; }
          body { margin: 0; padding: 36px; background: #eceee9; color: #12141a; font-family: Arial, sans-serif; }
          header { display: flex; align-items: baseline; justify-content: space-between; margin-bottom: 24px; }
          h1 { margin: 0; font-size: 28px; }
          p { margin: 0; color: #555b64; font-size: 14px; }
          main { display: grid; grid-template-columns: repeat(3, 1fr); gap: 24px 16px; }
          figure { margin: 0; }
          figcaption { margin-bottom: 8px; font-size: 13px; font-weight: 700; }
          img { display: block; width: 100%; border: 1px solid #c8cbc5; background: white; }
        </style>
      </head>
      <body>
        <header>
          <h1>M-18NWS distance check</h1>
          <p>Same 1280 × 800 viewport · colour and grayscale</p>
        </header>
        <main>${cards.join("")}</main>
      </body>
    </html>
  `);
  await page.screenshot({ path: path.join(currentDirectory, "m18nws-distance-comparison.png") });
  await page.close();
}

async function assertGrayFramesDiffer() {
  const pairs = [
    ["lock-in-reference-1280x800.png", "lock-in-reference-1280x800-grayscale.png"],
    ["m18r-deal-room-1280x800-reference.png", "m18r-deal-room-1280x800-grayscale.png"],
    ["m18nws-deal-room-1280x800.png", "m18nws-deal-room-1280x800-grayscale.png"],
    ["m18nws-deal-room-390x844.png", "m18nws-deal-room-390x844-grayscale.png"],
  ];

  for (const [colourFile, grayFile] of pairs) {
    const [colour, gray] = await Promise.all([
      readFile(path.join(currentDirectory, colourFile)),
      readFile(path.join(currentDirectory, grayFile)),
    ]);
    if (colour.equals(gray)) throw new Error(`${grayFile} is identical to its colour source.`);
  }
}

const browser = await chromium.launch();

try {
  for (const definition of captures) await capture(browser, definition);
  await assertGrayFramesDiffer();
  await renderComparison(browser);
} finally {
  await browser.close();
}
