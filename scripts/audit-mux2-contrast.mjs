import { writeFile } from "node:fs/promises";

import { chromium } from "@playwright/test";

const baseUrl = process.argv.find((argument) => argument.startsWith("--base-url="))?.split("=")[1]
  ?? "http://127.0.0.1:3000";
const outputPath = process.argv.find((argument) => argument.startsWith("--output="))?.split("=")[1];

const views = [
  { name: "Workspace", path: "/" },
  { name: "Participant", path: "/deal-room" },
  { name: "Protocol", path: "/protocol" },
];
const viewports = [
  { name: "desktop", width: 1440, height: 900 },
  { name: "mobile", width: 390, height: 844 },
];

function markdown(results) {
  const rows = results.map((result) => (
    `| ${result.view} | ${result.viewport} | ${result.state} | ${result.textPairs} | ${result.minimumText.toFixed(2)}:1 | ${result.nonTextPairs} | ${result.minimumNonText.toFixed(2)}:1 | ${result.failures.length} |`
  ));
  const failures = results.flatMap((result) => result.failures.map((failure) => (
    `- ${result.view} ${result.viewport} ${result.state}: ${failure.kind} \`${failure.selector}\` measured ${failure.ratio.toFixed(2)}:1; required ${failure.required.toFixed(1)}:1.`
  )));
  return `# M-UX2 measured contrast report

Automated browser audit of rendered foreground/background pairs. Text thresholds follow WCAG: 4.5:1 for ordinary text and 3:1 for large text. Visible control boundaries, focus indicators, active indicators, and structural separators use 3:1.

Base URL: \`${baseUrl}\`

| View | Viewport | State | Text pairs | Minimum text | Non-text pairs | Minimum non-text | Failures |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: |
${rows.join("\n")}

## Result

${failures.length === 0 ? "All measured pairs pass their applicable thresholds." : failures.join("\n")}

The audit covers base, hover, keyboard focus, selected checkpoint, disabled proof control, and Proof. Transparent decorative borders are excluded; visible one-pixel separators are included.
`;
}

const browser = await chromium.launch({ headless: true });
const results = [];

async function audit(page, view, viewport, state) {
  const measurement = await page.evaluate(() => {
    const parse = (value) => {
      const match = value.match(/rgba?\(([^)]+)\)/);
      if (!match) return null;
      const parts = match[1].replaceAll(",", " ").replace("/", " ").split(/\s+/).filter(Boolean).map(Number);
      return { r: parts[0], g: parts[1], b: parts[2], a: Number.isFinite(parts[3]) ? parts[3] : 1 };
    };
    const composite = (foreground, background) => {
      const alpha = foreground.a + background.a * (1 - foreground.a);
      if (alpha === 0) return { r: 0, g: 0, b: 0, a: 0 };
      return {
        r: (foreground.r * foreground.a + background.r * background.a * (1 - foreground.a)) / alpha,
        g: (foreground.g * foreground.a + background.g * background.a * (1 - foreground.a)) / alpha,
        b: (foreground.b * foreground.a + background.b * background.a * (1 - foreground.a)) / alpha,
        a: alpha,
      };
    };
    const luminance = (color) => [color.r, color.g, color.b]
      .map((channel) => {
        const normalized = channel / 255;
        return normalized <= 0.04045 ? normalized / 12.92 : ((normalized + 0.055) / 1.055) ** 2.4;
      })
      .reduce((sum, channel, index) => sum + channel * [0.2126, 0.7152, 0.0722][index], 0);
    const contrast = (first, second) => {
      const a = luminance(first);
      const b = luminance(second);
      return (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05);
    };
    const visible = (element) => {
      const style = getComputedStyle(element);
      const rect = element.getBoundingClientRect();
      return style.display !== "none" && style.visibility !== "hidden" && Number(style.opacity) > 0
        && rect.width > 1 && rect.height > 1 && rect.bottom > 0 && rect.right > 0
        && rect.top < innerHeight && rect.left < innerWidth;
    };
    const background = (element) => {
      const chain = [];
      for (let current = element; current instanceof Element; current = current.parentElement) chain.push(current);
      let result = { r: 255, g: 255, b: 255, a: 1 };
      for (const current of chain.reverse()) {
        const color = parse(getComputedStyle(current).backgroundColor);
        if (color !== null && color.a > 0) result = composite(color, result);
      }
      return result;
    };
    const selector = (element) => {
      if (element.id) return `#${element.id}`;
      const testId = element.getAttribute("data-testid");
      if (testId) return `[data-testid=${testId}]`;
      const checkpoint = element.getAttribute("data-checkpoint-id");
      if (checkpoint) return `[data-checkpoint-id=${checkpoint}]`;
      return element.tagName.toLowerCase();
    };

    const textRecords = [];
    const textElements = new Set();
    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
    for (let node = walker.nextNode(); node !== null; node = walker.nextNode()) {
      if (node.textContent?.trim() && node.parentElement !== null) textElements.add(node.parentElement);
    }
    for (const element of textElements) {
      if (!visible(element) || element.closest(".visually-hidden")) continue;
      const style = getComputedStyle(element);
      const foreground = parse(style.color);
      if (foreground === null) continue;
      const backdrop = background(element);
      const rendered = composite(foreground, backdrop);
      const fontSize = Number.parseFloat(style.fontSize);
      const fontWeight = Number.parseInt(style.fontWeight, 10) || 400;
      const large = fontSize >= 24 || (fontSize >= 18.66 && fontWeight >= 700);
      textRecords.push({
        kind: "text",
        selector: selector(element),
        ratio: contrast(rendered, backdrop),
        required: large ? 3 : 4.5,
      });
    }

    const nonTextRecords = [];
    for (const element of document.querySelectorAll("*")) {
      if (!visible(element)) continue;
      const style = getComputedStyle(element);
      const backdrop = background(element.parentElement ?? element);
      for (const side of ["Top", "Right", "Bottom", "Left"]) {
        if (Number.parseFloat(style[`border${side}Width`]) < 1 || style[`border${side}Style`] === "none") continue;
        const border = parse(style[`border${side}Color`]);
        if (border === null || border.a === 0) continue;
        nonTextRecords.push({
          kind: `border-${side.toLowerCase()}`,
          selector: selector(element),
          ratio: contrast(composite(border, backdrop), backdrop),
          required: 3,
        });
      }
      if (element === document.activeElement && Number.parseFloat(style.outlineWidth) >= 2) {
        const outline = parse(style.outlineColor);
        if (outline !== null && outline.a > 0) {
          nonTextRecords.push({
            kind: "focus-outline",
            selector: selector(element),
            ratio: contrast(composite(outline, backdrop), backdrop),
            required: 3,
          });
        }
      }
      if (element.hasAttribute("aria-current")) {
        const pseudo = getComputedStyle(element, "::after");
        const indicator = parse(pseudo.backgroundColor);
        if (indicator !== null && indicator.a > 0 && Number.parseFloat(pseudo.height) >= 2) {
          nonTextRecords.push({
            kind: "active-indicator",
            selector: selector(element),
            ratio: contrast(composite(indicator, backdrop), backdrop),
            required: 3,
          });
        }
      }
    }
    const records = [...textRecords, ...nonTextRecords];
    return {
      textPairs: textRecords.length,
      nonTextPairs: nonTextRecords.length,
      minimumText: Math.min(...textRecords.map((record) => record.ratio)),
      minimumNonText: Math.min(...nonTextRecords.map((record) => record.ratio)),
      failures: records.filter((record) => record.ratio + 0.005 < record.required),
    };
  });
  results.push({ view, viewport, state, ...measurement });
}

for (const viewport of viewports) {
  for (const view of views) {
    const page = await browser.newPage({ viewport: { width: viewport.width, height: viewport.height } });
    await page.goto(`${baseUrl}${view.path}`, { waitUntil: "networkidle" });
    await page.waitForSelector("[data-testid=living-conclusion]");
    await page.evaluate(() => document.fonts.ready);
    await audit(page, view.name, viewport.name, "base + selected");

    const inactiveCheckpoint = page.locator("[data-checkpoint-id=funding]");
    await inactiveCheckpoint.hover();
    await audit(page, view.name, viewport.name, "hover");
    await inactiveCheckpoint.focus();
    await audit(page, view.name, viewport.name, "keyboard focus");

    const proofButton = page.getByRole("button", { name: "Open receipt proof" });
    await proofButton.evaluate((element) => { element.disabled = true; });
    await audit(page, view.name, viewport.name, "disabled");
    await proofButton.evaluate((element) => { element.disabled = false; });
    await proofButton.click();
    await page.waitForSelector("[data-testid=living-proof]");
    await audit(page, "Proof", viewport.name, view.name);
    await page.close();
  }
}

await browser.close();

const report = markdown(results);
if (outputPath) await writeFile(outputPath, report, "utf8");
process.stdout.write(report);

if (results.some((result) => result.failures.length > 0)) process.exitCode = 1;
