import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { chromium } from "@playwright/test";

const directory = path.dirname(fileURLToPath(import.meta.url));
const baseUrl = process.env.M18NWS_INTEGRATION_URL ?? "http://127.0.0.1:3100";
const captures = [
  { label: "Workspace / desktop", path: "/", file: "workspace-1440x960.png", width: 1440, height: 960 },
  { label: "Participant / desktop", path: "/participant", file: "participant-1440x960.png", width: 1440, height: 960 },
  { label: "Protocol / desktop", path: "/protocol", file: "protocol-1440x960.png", width: 1440, height: 960 },
  { label: "Workspace / mobile", path: "/", file: "workspace-390x844.png", width: 390, height: 844 },
  { label: "Participant / mobile", path: "/participant", file: "participant-390x844.png", width: 390, height: 844 },
  { label: "Protocol / mobile", path: "/protocol", file: "protocol-390x844.png", width: 390, height: 844 },
];

async function capture(browser, definition) {
  const context = await browser.newContext({
    colorScheme: "light",
    reducedMotion: "reduce",
    viewport: { width: definition.width, height: definition.height },
  });
  const page = await context.newPage();
  const failures = [];
  page.on("pageerror", (error) => failures.push(error.message));

  await page.goto(`${baseUrl}${definition.path}`, { waitUntil: "networkidle" });
  await page.evaluate(() => document.fonts.ready);
  await page.addStyleTag({ content: "nextjs-portal { display: none !important; }" });
  await page.locator(".product-shell").waitFor({ state: "visible" });
  await page.screenshot({ path: path.join(directory, definition.file) });

  if (failures.length > 0) throw new Error(`${definition.label}: ${failures.join("; ")}`);
  await context.close();
}

async function dataUrl(file) {
  return `data:image/png;base64,${(await readFile(path.join(directory, file))).toString("base64")}`;
}

async function contactSheet(browser) {
  const cards = [];
  for (const definition of captures) {
    cards.push(`<figure><figcaption>${definition.label}</figcaption><img src="${await dataUrl(definition.file)}" alt="" /></figure>`);
  }

  const page = await browser.newPage({ viewport: { width: 1640, height: 1460 } });
  await page.setContent(`<!doctype html><html><head><style>
    * { box-sizing: border-box; }
    body { margin: 0; padding: 32px; background: #e7e8e3; color: #12141a; font: 14px Arial, sans-serif; }
    header { display: flex; align-items: baseline; justify-content: space-between; margin-bottom: 22px; }
    h1, p, figure { margin: 0; } h1 { font-size: 26px; } p { color: #545965; }
    main { display: grid; grid-template-columns: repeat(3, 1fr); gap: 24px 16px; align-items: start; }
    figcaption { margin-bottom: 7px; font-weight: 700; }
    img { display: block; width: 100%; border: 1px solid rgb(18 20 26 / 28%); background: #f3f4ef; }
    figure:nth-child(n + 4) img { width: 68%; margin-inline: auto; }
  </style></head><body><header><h1>M-18NWS product integration</h1><p>First-view audit · 29 Jul 2026</p></header><main>${cards.join("")}</main></body></html>`);
  await page.screenshot({ path: path.join(directory, "integration-contact-sheet.png") });
  await page.close();
}

const browser = await chromium.launch();
try {
  for (const definition of captures) await capture(browser, definition);
  await contactSheet(browser);
} finally {
  await browser.close();
}
