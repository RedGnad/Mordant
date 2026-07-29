import { chromium } from "@playwright/test";
import { fileURLToPath, pathToFileURL } from "node:url";
import { dirname, join } from "node:path";

const directory = dirname(fileURLToPath(import.meta.url));
const compositions = [
  {
    name: "workspace",
    source: "workspace.html",
    screenshot: "workspace-1280x800.png",
    required: [
      ".queue-item:nth-of-type(5)",
      ".domain-pair",
      ".decision-block.gates",
      ".decision-block.action-block .btn",
      ".policy-boundary",
    ],
  },
  {
    name: "participant-critical",
    source: "participant-critical.html",
    screenshot: "participant-critical-1280x800.png",
    required: [
      ".critical-band",
      ".participant-domains",
      ".participant-proof",
      ".participant-side .gate-list",
      ".participant-actions .btn",
    ],
  },
  {
    name: "protocol-diagnostic",
    source: "protocol-diagnostic.html",
    screenshot: "protocol-diagnostic-1280x800.png",
    required: [
      ".event-item.is-selected",
      ".transition-bays",
      ".raw-proof",
      ".protocol-evidence",
      ".recovery-runbook .btn",
    ],
  },
];

const contrastPairs = [
  ["primary ink / paper", "#211923", "#EEF2EF"],
  ["secondary ink / paper", "#655D68", "#EEF2EF"],
  ["action / folio", "#49305C", "#FBFBF7"],
  ["receivable / folio", "#00696D", "#FBFBF7"],
  ["protection / folio", "#87506F", "#FBFBF7"],
  ["critical / folio", "#AF2858", "#FBFBF7"],
  ["attention / folio", "#945A30", "#FBFBF7"],
  ["positive / folio", "#276858", "#FBFBF7"],
  ["light ink / proof", "#FFFEF9", "#241A2A"],
  ["light ink / critical", "#FFFEF9", "#AF2858"],
];

function luminance(hex) {
  const channels = [1, 3, 5]
    .map((offset) => Number.parseInt(hex.slice(offset, offset + 2), 16) / 255)
    .map((channel) =>
      channel <= 0.04045 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4,
    );
  return 0.2126 * channels[0] + 0.7152 * channels[1] + 0.0722 * channels[2];
}

function contrast(foreground, background) {
  const values = [luminance(foreground), luminance(background)].sort((a, b) => b - a);
  return (values[0] + 0.05) / (values[1] + 0.05);
}

const browser = await chromium.launch();
let failed = false;

for (const composition of compositions) {
  const page = await browser.newPage({ viewport: { width: 1280, height: 800 } });
  const pageErrors = [];
  page.on("pageerror", (error) => pageErrors.push(error.message));
  await page.goto(pathToFileURL(join(directory, composition.source)).href, {
    waitUntil: "networkidle",
  });
  await page.evaluate(() => document.fonts.ready);

  const metrics = await page.evaluate((required) => {
    const artboard = document.querySelector(".artboard")?.getBoundingClientRect();
    const chrome = document.querySelector(".product-bar")?.getBoundingClientRect();
    const clipped = required.flatMap((selector) => {
      const element = document.querySelector(selector);
      if (!element) return [`${selector}: missing`];
      const box = element.getBoundingClientRect();
      return box.top < 0 || box.right > 1280 || box.bottom > 800 || box.left < 0
        ? [`${selector}: outside 1280x800 (${Math.round(box.left)},${Math.round(box.top)},${Math.round(box.right)},${Math.round(box.bottom)})`]
        : [];
    });
    const textSizes = [...document.querySelectorAll("body *")]
      .filter((element) => {
        const style = getComputedStyle(element);
        const directText = [...element.childNodes].some(
          (node) => node.nodeType === Node.TEXT_NODE && node.textContent.trim(),
        );
        return directText && style.display !== "none" && style.visibility !== "hidden";
      })
      .map((element) => Number.parseFloat(getComputedStyle(element).fontSize));
    const shortButtons = [...document.querySelectorAll("button")]
      .map((button) => button.getBoundingClientRect().height)
      .filter((height) => height < 44);
    return {
      artboard: artboard && [artboard.width, artboard.height],
      chrome: chrome?.height,
      viewport: [document.documentElement.scrollWidth, document.documentElement.scrollHeight],
      minText: Math.min(...textSizes),
      shortButtons,
      clipped,
    };
  }, composition.required);

  const desktopIssues = [
    ...(metrics.artboard?.[0] === 1280 && metrics.artboard?.[1] === 800
      ? []
      : [`artboard is ${metrics.artboard}`]),
    ...(metrics.chrome <= 56 ? [] : [`chrome is ${metrics.chrome}px`]),
    ...(metrics.viewport[0] === 1280 && metrics.viewport[1] === 800
      ? []
      : [`document is ${metrics.viewport.join("x")}`]),
    ...(metrics.minText >= 11 ? [] : [`minimum visible text is ${metrics.minText}px`]),
    ...(metrics.shortButtons.length === 0 ? [] : ["an action target is below 44px"]),
    ...metrics.clipped,
    ...pageErrors,
  ];

  await page.screenshot({ path: join(directory, composition.screenshot) });

  await page.setViewportSize({ width: 390, height: 844 });
  await page.reload({ waitUntil: "networkidle" });
  await page.evaluate(() => document.fonts.ready);
  const mobileIssues = await page.evaluate(() => {
    const issues = [];
    if (document.documentElement.scrollWidth > 390) {
      issues.push(`mobile horizontal overflow is ${document.documentElement.scrollWidth}px`);
    }
    const shortButtons = [...document.querySelectorAll("button")].filter(
      (button) => button.getBoundingClientRect().height < 44,
    );
    if (shortButtons.length) issues.push("a mobile action target is below 44px");
    return issues;
  });

  const issues = [...desktopIssues, ...mobileIssues];
  if (issues.length) {
    failed = true;
    console.error(`${composition.name}: FAIL\n  ${issues.join("\n  ")}`);
  } else {
    console.log(`${composition.name}: PASS · 1280x800 · mobile no-overflow · text ≥11px`);
  }

  await page.close();
}

await browser.close();

const failingPairs = contrastPairs
  .map(([name, foreground, background]) => [name, contrast(foreground, background)])
  .filter(([, ratio]) => ratio < 4.5);
if (failingPairs.length) {
  failed = true;
  console.error(
    `palette: FAIL\n  ${failingPairs.map(([name, ratio]) => `${name}: ${ratio.toFixed(2)}:1`).join("\n  ")}`,
  );
} else {
  console.log("palette: PASS · all approved text pairs ≥4.5:1");
}

if (failed) process.exitCode = 1;
