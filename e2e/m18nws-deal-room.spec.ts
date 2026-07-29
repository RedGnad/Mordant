import { expect, test, type Locator, type Page } from "@playwright/test";

import { getSyntheticDeal, proRateAmount } from "../src/lib/mordant/product-model";
import { deriveReadinessVerdict } from "../src/lib/mordant/readiness";

const benchmarkPath = "/design-lab/m18nws-deal-room";
const desktopViewport = { width: 1280, height: 800 } as const;
const mobileViewport = { width: 390, height: 844 } as const;
type ApprovalViewport = { readonly width: number; readonly height: number };

const sourceDeal = getSyntheticDeal("wrong-role");
const sourceAction = sourceDeal.actions[0];
const sourcePosition = sourceDeal.viewer.position;
const sourceDueAt = sourceDeal.nextResponsibility.dueAt;

if (!sourceAction || !sourcePosition || !sourceDueAt) {
  throw new Error("The M-18NWS benchmark requires the complete wrong-role source fixture.");
}

const sourceVerdict = deriveReadinessVerdict(sourceDeal, sourceAction);
const sourceReceivable = proRateAmount(sourceDeal.economics.receivable.outstanding, sourcePosition);
const sourceProtection = proRateAmount(sourceDeal.economics.protection.lockedReserve, sourcePosition);
const sourceActor = sourceDeal.nextResponsibility.actorLabel.replace(/\s+\(synthetic\)$/iu, "");
const sourceDeadline = new Intl.DateTimeFormat("en-GB", {
  hour: "2-digit",
  minute: "2-digit",
  hourCycle: "h23",
  timeZone: "UTC",
}).format(new Date(sourceDueAt));

const forbiddenDecisionVocabulary =
  /\b(?:wrong role|conflict registered|cure period|protection state|hash|root|rootline|folio|block|transaction|confirmation|schema|gate|contract|calldata|wallet|signature|rpc|abi)\b|0x[a-f0-9]{8,}/iu;

function formatParticipantAmount(amount: {
  readonly minorUnits: string;
  readonly asset: { readonly decimals: number; readonly symbol: string };
}): string {
  const scale = 10n ** BigInt(amount.asset.decimals);
  const raw = BigInt(amount.minorUnits);
  const whole = raw / scale;
  const fraction = (raw % scale).toString().padStart(amount.asset.decimals, "0").replace(/0+$/u, "");
  return `${whole.toLocaleString("en-US")}${fraction ? `.${fraction}` : ""} ${amount.asset.symbol}`;
}

function businessWordCount(value: string): number {
  return value
    .replace(/(?<=\d)[,\u00a0\u202f](?=\d{3}(?:\D|$))/gu, "")
    .trim()
    .split(/\s+/u)
    .filter((token) => /[\p{L}\p{N}]/u.test(token)).length;
}

async function openBenchmark(page: Page, viewport: ApprovalViewport = desktopViewport) {
  await page.setViewportSize(viewport);
  await page.goto(benchmarkPath);
  await expect(page.getByTestId("m18nws-benchmark")).toBeVisible();
}

async function expectInsideViewport(page: Page, locator: Locator, label: string) {
  await expect(locator, `${label} must be rendered`).toBeVisible();
  const box = await locator.boundingBox();
  const viewport = page.viewportSize();
  expect(box, `${label} needs a layout box`).not.toBeNull();
  expect(viewport, `${label} needs a fixed viewport`).not.toBeNull();
  if (!box || !viewport) return;

  expect(box.x, `${label} left edge`).toBeGreaterThanOrEqual(-0.5);
  expect(box.y, `${label} top edge`).toBeGreaterThanOrEqual(-0.5);
  expect(box.x + box.width, `${label} right edge`).toBeLessThanOrEqual(viewport.width + 0.5);
  expect(box.y + box.height, `${label} bottom edge`).toBeLessThanOrEqual(viewport.height + 0.5);
}

async function minimumTargetViolations(page: Page) {
  return page.getByTestId("m18nws-benchmark").evaluate((root) => {
    const selectors = 'a[href], button, input:not([type="hidden"]), select, textarea, summary, [role="button"]';
    return [...root.querySelectorAll<HTMLElement>(selectors)].flatMap((element) => {
      const style = getComputedStyle(element);
      const bounds = element.getBoundingClientRect();
      const rendered =
        style.display !== "none" &&
        style.visibility !== "hidden" &&
        Number.parseFloat(style.opacity) > 0 &&
        bounds.width > 0 &&
        bounds.height > 0;
      if (!rendered || (bounds.width >= 44 && bounds.height >= 44)) return [];
      return [
        {
          target: element.getAttribute("data-testid") ?? element.getAttribute("aria-label") ?? element.textContent?.trim(),
          width: bounds.width,
          height: bounds.height,
        },
      ];
    });
  });
}

async function contrastViolations(page: Page) {
  return page.getByTestId("m18nws-benchmark").evaluate((root) => {
    type Colour = { r: number; g: number; b: number; a: number };

    const parseColour = (value: string): Colour | null => {
      const channels = value.match(/[\d.]+/gu)?.map(Number);
      if (!channels || channels.length < 3) return null;
      return { r: channels[0], g: channels[1], b: channels[2], a: channels[3] ?? 1 };
    };
    const composite = (foreground: Colour, background: Colour): Colour => {
      const alpha = foreground.a + background.a * (1 - foreground.a);
      if (alpha === 0) return { r: 255, g: 255, b: 255, a: 0 };
      return {
        r: (foreground.r * foreground.a + background.r * background.a * (1 - foreground.a)) / alpha,
        g: (foreground.g * foreground.a + background.g * background.a * (1 - foreground.a)) / alpha,
        b: (foreground.b * foreground.a + background.b * background.a * (1 - foreground.a)) / alpha,
        a: alpha,
      };
    };
    const backgroundFor = (element: Element): Colour => {
      const layers: Colour[] = [];
      for (let current: Element | null = element; current; current = current.parentElement) {
        const colour = parseColour(getComputedStyle(current).backgroundColor);
        if (colour && colour.a > 0) layers.push(colour);
      }
      return layers
        .reverse()
        .reduce((background, foreground) => composite(foreground, background), { r: 255, g: 255, b: 255, a: 1 });
    };
    const luminance = (colour: Colour) => {
      const channels = [colour.r, colour.g, colour.b].map((channel) => {
        const normalized = channel / 255;
        return normalized <= 0.04045 ? normalized / 12.92 : ((normalized + 0.055) / 1.055) ** 2.4;
      });
      return channels[0] * 0.2126 + channels[1] * 0.7152 + channels[2] * 0.0722;
    };
    const ratio = (foreground: Colour, background: Colour) => {
      const values = [luminance(foreground), luminance(background)].sort((a, b) => b - a);
      return (values[0] + 0.05) / (values[1] + 0.05);
    };
    const intersectsViewport = (rect: DOMRect) =>
      rect.width > 0 && rect.height > 0 && rect.right > 0 && rect.bottom > 0 && rect.left < innerWidth && rect.top < innerHeight;

    return [...root.querySelectorAll<HTMLElement>("*")].flatMap((element) => {
      const style = getComputedStyle(element);
      if (style.display === "none" || style.visibility === "hidden" || Number.parseFloat(style.opacity) === 0) return [];
      const closedDisclosure = element.closest("details:not([open])");
      if (closedDisclosure && !element.closest("summary")) return [];

      const directText = [...element.childNodes]
        .filter((node) => node.nodeType === Node.TEXT_NODE && node.textContent?.trim())
        .map((node) => node.textContent?.trim() ?? "")
        .join(" ");
      if (!directText) return [];

      const visibleText = [...element.childNodes]
        .filter((node) => node.nodeType === Node.TEXT_NODE && node.textContent?.trim())
        .some((node) => {
          const range = document.createRange();
          range.selectNodeContents(node);
          return [...range.getClientRects()].some(intersectsViewport);
        });
      if (!visibleText) return [];

      const background = backgroundFor(element);
      const parsedText = parseColour(style.color);
      if (!parsedText || parsedText.a === 0) return [];
      const foreground = composite(parsedText, background);
      const fontSize = Number.parseFloat(style.fontSize);
      const fontWeight = Number.parseFloat(style.fontWeight) || 400;
      const largeText = fontSize >= 24 || (fontSize >= 18.66 && fontWeight >= 700);
      const required = largeText ? 3 : 4.5;
      const actual = ratio(foreground, background);
      if (actual + 0.005 >= required) return [];

      return [
        {
          text: directText.slice(0, 80),
          actual: Number(actual.toFixed(2)),
          required,
          fontSize,
          fontWeight,
          foreground: style.color,
          background,
        },
      ];
    });
  });
}

async function visualGrammar(page: Page) {
  return page.getByTestId("m18nws-benchmark").evaluate((root) => {
    type Colour = { r: number; g: number; b: number; a: number };

    const parseColour = (value: string): Colour | null => {
      const channels = value.match(/[\d.]+/gu)?.map(Number);
      if (!channels || channels.length < 3) return null;
      return { r: channels[0], g: channels[1], b: channels[2], a: channels[3] ?? 1 };
    };
    const colourKey = (colour: Colour) => `${Math.round(colour.r)},${Math.round(colour.g)},${Math.round(colour.b)}`;
    const isSaturated = (colour: Colour) => {
      if (colour.a < 0.05) return false;
      const channels = [colour.r, colour.g, colour.b].map((channel) => channel / 255);
      const maximum = Math.max(...channels);
      const minimum = Math.min(...channels);
      const chroma = maximum - minimum;
      const lightness = (maximum + minimum) / 2;
      const saturation = chroma === 0 ? 0 : chroma / (1 - Math.abs(2 * lightness - 1));
      return saturation >= 0.45 && chroma * 255 >= 70;
    };
    const intersectsViewport = (element: Element) => {
      const rect = element.getBoundingClientRect();
      return rect.width > 0 && rect.height > 0 && rect.right > 0 && rect.bottom > 0 && rect.left < innerWidth && rect.top < innerHeight;
    };
    const maximumTime = (value: string) =>
      Math.max(
        0,
        ...value.split(",").map((entry) => {
          const numeric = Number.parseFloat(entry);
          if (!Number.isFinite(numeric)) return 0;
          return entry.trim().endsWith("ms") ? numeric : numeric * 1_000;
        }),
      );

    const saturated = new Set<string>();
    const shadows: Array<Record<string, unknown>> = [];
    const borders: Array<Record<string, unknown>> = [];
    const gradients: Array<Record<string, unknown>> = [];
    const permanentMotion: Array<Record<string, unknown>> = [];
    const pseudos: Array<string | null> = [null, "::before", "::after"];

    for (const element of [root, ...root.querySelectorAll<HTMLElement>("*")]) {
      if (!intersectsViewport(element)) continue;

      for (const pseudo of pseudos) {
        const style = getComputedStyle(element, pseudo);
        const borderWidths = [style.borderTopWidth, style.borderRightWidth, style.borderBottomWidth, style.borderLeftWidth]
          .map(Number.parseFloat);
        const pseudoPainted =
          pseudo === null ||
          style.content !== "none" ||
          (parseColour(style.backgroundColor)?.a ?? 0) > 0 ||
          borderWidths.some((width) => width > 0);
        if (!pseudoPainted) continue;

        const paintColours = [style.color, style.backgroundColor];
        const borderColours = [style.borderTopColor, style.borderRightColor, style.borderBottomColor, style.borderLeftColor];
        borderColours.forEach((colour, index) => {
          if (borderWidths[index] > 0) paintColours.push(colour);
        });
        for (const value of paintColours) {
          const colour = parseColour(value);
          if (colour && isSaturated(colour)) saturated.add(colourKey(colour));
        }

        if (style.boxShadow !== "none" || style.textShadow !== "none" || style.filter.includes("drop-shadow")) {
          shadows.push({ tag: element.tagName.toLowerCase(), testId: element.getAttribute("data-testid"), pseudo });
        }
        borderWidths.forEach((width, side) => {
          const borderStyle = [style.borderTopStyle, style.borderRightStyle, style.borderBottomStyle, style.borderLeftStyle][side];
          if (width > 1.01 && borderStyle !== "none" && borderStyle !== "hidden") {
            borders.push({ tag: element.tagName.toLowerCase(), testId: element.getAttribute("data-testid"), pseudo, side, width });
          }
        });
        if (/gradient\(/iu.test(style.backgroundImage) || /blur\(/iu.test(style.filter) || /blur\(/iu.test(style.backdropFilter)) {
          gradients.push({ tag: element.tagName.toLowerCase(), testId: element.getAttribute("data-testid"), pseudo });
        }

        const namedAnimation = style.animationName.split(",").some((name) => name.trim() !== "none");
        const infinite = style.animationIterationCount.split(",").some((count) => count.trim() === "infinite");
        if (namedAnimation && (infinite || maximumTime(style.animationDuration) > 10_000)) {
          permanentMotion.push({ tag: element.tagName.toLowerCase(), testId: element.getAttribute("data-testid"), pseudo });
        }
      }
    }

    return {
      saturatedColours: [...saturated].sort(),
      shadows,
      borders,
      gradients,
      permanentMotion,
    };
  });
}

async function reducedMotionViolations(page: Page) {
  return page.getByTestId("m18nws-benchmark").evaluate((root) => {
    const milliseconds = (value: string) => {
      const numeric = Number.parseFloat(value);
      if (!Number.isFinite(numeric)) return 0;
      return value.trim().endsWith("ms") ? numeric : numeric * 1_000;
    };
    const maximum = (value: string) => Math.max(0, ...value.split(",").map(milliseconds));
    const violations: Array<Record<string, unknown>> = [];

    for (const element of [root, ...root.querySelectorAll<HTMLElement>("*")]) {
      for (const pseudo of [null, "::before", "::after"] as const) {
        const style = getComputedStyle(element, pseudo);
        const namedAnimation = style.animationName.split(",").some((name) => name.trim() !== "none");
        const infinite = style.animationIterationCount.split(",").some((count) => count.trim() === "infinite");
        const animationTime = maximum(style.animationDuration) + maximum(style.animationDelay);
        const transitionTime = maximum(style.transitionDuration) + maximum(style.transitionDelay);
        if ((namedAnimation && (infinite || animationTime > 20)) || transitionTime > 20) {
          violations.push({
            tag: element.tagName.toLowerCase(),
            testId: element.getAttribute("data-testid"),
            pseudo,
            animationName: style.animationName,
            animationTime,
            transitionTime,
          });
        }
      }
    }

    const runtimeAnimations = document.getAnimations().flatMap((animation) => {
      const effect = animation.effect as KeyframeEffect | null;
      if (!(effect?.target instanceof Element) || !root.contains(effect.target)) return [];
      const timing = effect.getComputedTiming();
      const duration = typeof timing.duration === "number" ? timing.duration : 0;
      const iterations = timing.iterations ?? 1;
      return duration > 20 || iterations === Number.POSITIVE_INFINITY
        ? [{ duration, iterations, playState: animation.playState }]
        : [];
    });

    return {
      preferenceMatches: matchMedia("(prefers-reduced-motion: reduce)").matches,
      scrollBehavior: getComputedStyle(document.documentElement).scrollBehavior,
      runtimeAnimations,
      violations,
    };
  });
}

test.describe("M-18NWS isolated New Wave Swiss benchmark", () => {
  test("renders the wrong-role fixture as one exact participant decision", async ({ page }) => {
    await openBenchmark(page);

    const benchmark = page.getByTestId("m18nws-benchmark");
    const firstView = page.getByTestId("m18nws-first-view");
    const decision = page.getByTestId("m18nws-decision");
    const levelOne = page.getByTestId("m18nws-level-one");

    await expect(benchmark).toHaveAttribute("lang", "en");
    await expect(page.locator('meta[name="robots"]')).toHaveAttribute("content", /noindex/u);
    await expect(levelOne).toHaveAttribute("data-readiness-verdict", sourceVerdict.code);
    expect(sourceVerdict.code).toBe("WRONG_ROLE");

    await expect(
      decision.getByRole("heading", { name: "Your receivable has not moved.", exact: true }),
    ).toBeVisible();
    await expect(decision.getByText("You have no action.", { exact: true })).toBeVisible();
    await expect(page.getByTestId("m18nws-responsible")).toHaveText(sourceActor);
    const deadline = page.getByTestId("m18nws-deadline");
    const sourceTime = deadline.locator("time");
    await expect(deadline.getByText("must cure before", { exact: true })).toBeVisible();
    await expect(sourceTime).toHaveAttribute("datetime", sourceDueAt);
    await expect(sourceTime).toHaveAttribute("aria-label", new RegExp(`${sourceDeadline} UTC on`, "u"));
    await expect(sourceTime.getByText(sourceDeadline, { exact: true })).toBeVisible();
    await expect(sourceTime.getByText("UTC.", { exact: true })).toBeVisible();

    const receivable = page.getByTestId("m18nws-domain-receivable");
    const protection = page.getByTestId("m18nws-domain-protection");
    await expect(receivable).toContainText(formatParticipantAmount(sourceReceivable));
    await expect(receivable).toContainText("Still held");
    await expect(protection).toContainText(formatParticipantAmount(sourceProtection));
    await expect(protection).toContainText("Not paid");
    await expect(page.getByTestId("m18nws-deadline-consequence")).toHaveAttribute(
      "data-consequence-source",
      "next-responsibility",
    );
    await expect(page.getByTestId("m18nws-deadline-consequence")).toContainText("Protection may become claimable.");
    await expect(page.getByTestId("m18nws-deadline-consequence")).toContainText(
      "Your receivable remains separate.",
    );

    const decisionText = await decision.innerText();
    const firstViewText = await firstView.innerText();
    expect(businessWordCount(decisionText), decisionText).toBeLessThanOrEqual(50);
    expect(businessWordCount(firstViewText), firstViewText).toBeLessThanOrEqual(120);
    expect(firstViewText).not.toMatch(forbiddenDecisionVocabulary);
    expect((await benchmark.innerText())).not.toMatch(/\b(?:rootline|folio)\b/iu);

    const primaryAction = page.getByTestId("m18nws-primary-action");
    await expect(primaryAction).toHaveCount(1);
    await expect(primaryAction).toHaveAttribute("href", "/");
    await expect(primaryAction).toHaveText(/Back to portfolio/u);
  });

  test("keeps Why and Evidence closed by default and mutually exclusive", async ({ page }) => {
    await openBenchmark(page);

    const why = page.getByTestId("m18nws-why");
    const evidence = page.getByTestId("m18nws-evidence");
    const whySummary = why.locator("summary");
    const evidenceSummary = evidence.locator("summary");

    await expect(why).not.toHaveAttribute("open", "");
    await expect(evidence).not.toHaveAttribute("open", "");
    await expect(whySummary).toHaveText(/Why this state\?/u);
    await expect(evidenceSummary).toHaveText(/View evidence/u);

    await whySummary.click();
    await expect(why).toHaveAttribute("open", "");
    await expect(evidence).not.toHaveAttribute("open", "");
    await expect(why).toContainText(sourceActor);
    await expect(why).toContainText(/does not burn or transfer your receivable units/iu);

    await evidenceSummary.click();
    await expect(evidence).toHaveAttribute("open", "");
    await expect(why).not.toHaveAttribute("open", "");
    await expect(evidence).toContainText(/source/iu);
    await expect(evidence).toContainText(/before/iu);
    await expect(evidence).toContainText(/action/iu);
    await expect(evidence).toContainText(/after/iu);
    await expect(evidence).toContainText(/limit/iu);
    await expect(evidence).toContainText(/identifier/iu);
  });

  test("recomposes the complete action path for 390 by 844 without overflow", async ({ page }) => {
    await openBenchmark(page, mobileViewport);

    const primaryAction = page.getByTestId("m18nws-primary-action");
    await expectInsideViewport(page, primaryAction, "mobile portfolio exit");

    const dimensions = await page.evaluate(() => ({
      viewportWidth: document.documentElement.clientWidth,
      documentWidth: document.documentElement.scrollWidth,
      bodyWidth: document.body.scrollWidth,
    }));
    expect(dimensions.viewportWidth).toBe(390);
    expect(dimensions.documentWidth).toBeLessThanOrEqual(390);
    expect(dimensions.bodyWidth).toBeLessThanOrEqual(390);

    const ordered = [
      page.getByRole("heading", { name: "Your receivable has not moved.", exact: true }),
      page.getByText("You have no action.", { exact: true }),
      page.getByTestId("m18nws-deadline"),
      page.getByTestId("m18nws-domain-receivable"),
      page.getByTestId("m18nws-domain-protection"),
      page.getByTestId("m18nws-deadline-consequence"),
      primaryAction,
      page.getByTestId("m18nws-why"),
      page.getByTestId("m18nws-evidence"),
    ];
    const tops = await Promise.all(ordered.map((locator) => locator.evaluate((element) => element.getBoundingClientRect().top)));
    for (let index = 1; index < tops.length; index += 1) {
      expect(tops[index], `mobile item ${index} must follow item ${index - 1}`).toBeGreaterThanOrEqual(tops[index - 1] - 0.5);
    }

    expect(await minimumTargetViolations(page)).toEqual([]);
  });

  test("keeps all visible benchmark text at WCAG 2.2 AA contrast", async ({ page }) => {
    for (const viewport of [desktopViewport, mobileViewport]) {
      await openBenchmark(page, viewport);
      expect(await contrastViolations(page), `${viewport.width}x${viewport.height} contrast violations`).toEqual([]);
    }
  });

  test("uses at most three saturated inks and rejects outlined poster mechanics", async ({ page }) => {
    for (const viewport of [desktopViewport, mobileViewport]) {
      await openBenchmark(page, viewport);
      const grammar = await visualGrammar(page);
      expect(
        grammar.saturatedColours.length,
        `${viewport.width}x${viewport.height} saturated inks: ${grammar.saturatedColours.join(" · ")}`,
      ).toBeLessThanOrEqual(3);
      expect(grammar.shadows, `${viewport.width}x${viewport.height} shadows`).toEqual([]);
      expect(grammar.borders, `${viewport.width}x${viewport.height} borders thicker than 1px`).toEqual([]);
      expect(grammar.gradients, `${viewport.width}x${viewport.height} gradients or blur`).toEqual([]);
      expect(grammar.permanentMotion, `${viewport.width}x${viewport.height} permanent motion`).toEqual([]);
    }
  });

  test("renders the final state immediately when reduced motion is requested", async ({ page }) => {
    await page.emulateMedia({ reducedMotion: "reduce" });

    for (const viewport of [desktopViewport, mobileViewport]) {
      await openBenchmark(page, viewport);
      const motion = await reducedMotionViolations(page);
      expect(motion.preferenceMatches).toBe(true);
      expect(motion.scrollBehavior).toBe("auto");
      expect(motion.violations, `${viewport.width}x${viewport.height} reduced-motion CSS`).toEqual([]);
      expect(motion.runtimeAnimations, `${viewport.width}x${viewport.height} reduced-motion runtime`).toEqual([]);
    }
  });
});
