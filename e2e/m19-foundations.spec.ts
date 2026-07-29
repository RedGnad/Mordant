import { expect, test, type Locator, type Page } from "@playwright/test";

type Bounds = {
  top: number;
  right: number;
  bottom: number;
  left: number;
  width: number;
  height: number;
};

const surfaces = [
  { path: "/", heading: "Intervention queue" },
  { path: "/deal-room", heading: /Your receivable has not moved/i },
  { path: "/protocol", heading: "Event and recovery rail" },
] as const;

async function expectInsideViewport(page: Page, locator: Locator, label: string) {
  await expect(locator, `${label} must be rendered`).toBeVisible();
  const bounds: Bounds = await locator.evaluate((element) => {
    const box = element.getBoundingClientRect();
    return {
      top: box.top,
      right: box.right,
      bottom: box.bottom,
      left: box.left,
      width: box.width,
      height: box.height,
    };
  });
  const viewport = page.viewportSize();
  expect(viewport, `${label} needs a fixed viewport`).not.toBeNull();
  if (!viewport) return;

  expect(bounds.left, `${label} left edge`).toBeGreaterThanOrEqual(-0.5);
  expect(bounds.top, `${label} top edge`).toBeGreaterThanOrEqual(-0.5);
  expect(bounds.right, `${label} right edge`).toBeLessThanOrEqual(viewport.width + 0.5);
  expect(bounds.bottom, `${label} bottom edge`).toBeLessThanOrEqual(viewport.height + 0.5);
}

async function expectMinimumTarget(locator: Locator, label: string) {
  await expect(locator).toBeVisible();
  const bounds = await locator.boundingBox();
  expect(bounds, `${label} needs a layout box`).not.toBeNull();
  if (!bounds) return;
  expect(bounds.width, `${label} width`).toBeGreaterThanOrEqual(44);
  expect(bounds.height, `${label} height`).toBeGreaterThanOrEqual(44);
}

async function visibleViewportText(page: Page) {
  return page.locator(".product-shell").evaluate((root) => {
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
    const fragments: string[] = [];

    while (walker.nextNode()) {
      const node = walker.currentNode as Text;
      const value = node.textContent?.replace(/\s+/g, " ").trim();
      const parent = node.parentElement;
      if (!value || !parent || parent.closest('[aria-hidden="true"]')) continue;
      if (parent.closest("details:not([open])") && !parent.closest("summary")) continue;

      const range = document.createRange();
      range.selectNodeContents(node);
      if (Array.from(range.getClientRects()).some((rect) => rect.bottom > 0 && rect.top < window.innerHeight)) {
        fragments.push(value);
      }
    }

    return fragments.join(" ").replace(/\s+/g, " ").trim();
  });
}

function parseHex(color: string): readonly [number, number, number] {
  const normalized = color.trim().toLowerCase();
  const match = /^#([0-9a-f]{6})$/.exec(normalized);
  if (!match) throw new Error(`Expected a six-digit hex token, received ${color}`);
  const value = match[1];
  return [
    Number.parseInt(value.slice(0, 2), 16),
    Number.parseInt(value.slice(2, 4), 16),
    Number.parseInt(value.slice(4, 6), 16),
  ] as const;
}

function relativeLuminance(color: string) {
  const channels = parseHex(color).map((channel) => {
    const normalized = channel / 255;
    return normalized <= 0.04045 ? normalized / 12.92 : ((normalized + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * channels[0] + 0.7152 * channels[1] + 0.0722 * channels[2];
}

function contrastRatio(foreground: string, background: string) {
  const values = [relativeLuminance(foreground), relativeLuminance(background)].sort((a, b) => b - a);
  return (values[0] + 0.05) / (values[1] + 0.05);
}

test.describe("1280 by 800 decision viewport", () => {
  test.use({ viewport: { width: 1280, height: 800 } });

  test("all surfaces keep persistent product chrome at or below 56px", async ({ page }) => {
    for (const surface of surfaces) {
      await page.goto(surface.path);
      await expect(page.getByRole("heading", { name: surface.heading }).first()).toBeVisible();
      const chrome = page.getByTestId("product-chrome");
      await expectInsideViewport(page, chrome, `${surface.path} chrome`);
      const bounds = await chrome.boundingBox();
      expect(bounds?.height, `${surface.path} chrome height`).toBeLessThanOrEqual(56);
      expect(bounds?.y, `${surface.path} chrome origin`).toBe(0);
    }
  });

  test("workspace shows its complete critical decision path without initial scrolling", async ({ page }) => {
    await page.goto("/");
    expect(await page.evaluate(() => window.scrollY)).toBe(0);

    const required: readonly [Locator, string][] = [
      [page.getByTestId("workspace-interventions"), "intervention queue"],
      [page.locator('.queue-item[aria-pressed="true"]'), "selected queue record"],
      [page.getByTestId("selected-folio"), "selected folio"],
      [page.locator('.workspace-domain-pair [data-domain="receivable"]'), "receivable domain"],
      [page.locator('.workspace-domain-pair [data-domain="protection"]'), "protection domain"],
      [page.locator(".workspace-decision [data-readiness-verdict]"), "unique readiness verdict"],
      [page.getByTestId("decision-deadline"), "decision deadline"],
      [page.getByTestId("primary-action"), "primary action"],
    ];

    for (const [locator, label] of required) {
      await expectInsideViewport(page, locator, label);
    }

    const scrollOffsets = await page.locator(".queue-items, .workspace-record, .workspace-decision").evaluateAll(
      (elements) => elements.map((element) => element.scrollTop),
    );
    expect(scrollOffsets).toEqual([0, 0, 0]);
  });

  test("participant and protocol keep their critical records fully above fold", async ({ page }) => {
    await page.goto("/deal-room");
    const participantRequired: readonly [Locator, string][] = [
      [page.getByRole("heading", { name: "Your receivable has not moved.", exact: true }), "participant conclusion"],
      [page.getByText("You have no action.", { exact: true }), "participant no-action decision"],
      [page.getByTestId("participant-deadline"), "participant responsibility and deadline"],
      [page.locator('.participant-domain-pair [data-domain="receivable"]'), "participant receivable"],
      [page.locator('.participant-domain-pair [data-domain="protection"]'), "participant protection"],
      [page.getByTestId("participant-deadline-consequence"), "participant consequence"],
      [page.getByTestId("participant-primary-action"), "participant exit"],
      [page.getByTestId("participant-review-action"), "participant why disclosure"],
      [page.getByTestId("participant-evidence").locator("summary"), "participant evidence disclosure"],
    ];
    for (const [locator, label] of participantRequired) await expectInsideViewport(page, locator, label);

    const participantText = await visibleViewportText(page);
    const participantWords = participantText.match(/[A-Za-zÀ-ÿ0-9]+(?:[’'.,:/-][A-Za-zÀ-ÿ0-9]+)*/g) ?? [];
    expect(participantWords.length).toBeLessThanOrEqual(80);
    expect(participantText.match(/Facility B/g)).toHaveLength(1);
    expect(participantText.match(/12:00/g)).toHaveLength(1);
    expect(participantText).not.toMatch(/invoice root|\bfolio\b|blocking gate|unlock|gate vector|0x[a-f0-9]+|MRD-|P[–-]CP/i);

    await page.goto("/protocol");
    const protocolRequired: readonly [Locator, string][] = [
      [page.locator('.protocol-record-row[data-selected="true"]'), "selected protocol record"],
      [page.locator(".protocol-proof-stage"), "protocol proof stage"],
      [page.locator('[data-readiness-verdict="RECOVERY_REQUIRED"]'), "protocol recovery verdict"],
      [page.locator(".selected-record-diagnostic"), "selected diagnostic"],
      [page.locator(".protocol-runbook"), "recovery runbook"],
    ];
    for (const [locator, label] of protocolRequired) await expectInsideViewport(page, locator, label);
  });
});

test.describe("1024px expert flow", () => {
  test.use({ viewport: { width: 1024, height: 900 } });

  test("protocol keeps impact and runbook ahead of technical proof", async ({ page }) => {
    await page.goto("/protocol");

    const impact = await page.getByTestId("protocol-impact").boundingBox();
    const runbook = await page.getByTestId("protocol-runbook").boundingBox();
    const metadata = await page.locator(".protocol-service-plate").boundingBox();
    const proof = await page.getByTestId("protocol-proof-stage").boundingBox();

    expect(impact).not.toBeNull();
    expect(runbook).not.toBeNull();
    expect(metadata).not.toBeNull();
    expect(proof).not.toBeNull();
    expect((impact?.y ?? 0) + (impact?.height ?? 0)).toBeLessThanOrEqual(runbook?.y ?? 0);
    expect((runbook?.y ?? 0) + (runbook?.height ?? 0)).toBeLessThanOrEqual(metadata?.y ?? 0);
    expect((metadata?.y ?? 0) + (metadata?.height ?? 0)).toBeLessThanOrEqual(proof?.y ?? 0);
  });
});

test.describe("390px product viewport", () => {
  test.use({ viewport: { width: 390, height: 844 } });

  test("all product surfaces avoid horizontal document overflow", async ({ page }) => {
    for (const surface of surfaces) {
      await page.goto(surface.path);
      await expect(page.getByRole("heading", { name: surface.heading }).first()).toBeVisible();

      const dimensions = await page.evaluate(() => ({
        viewportWidth: document.documentElement.clientWidth,
        documentWidth: document.documentElement.scrollWidth,
        bodyWidth: document.body.scrollWidth,
      }));

      expect(dimensions.viewportWidth).toBe(390);
      expect(dimensions.documentWidth, `${surface.path} document width`).toBeLessThanOrEqual(390);
      expect(dimensions.bodyWidth, `${surface.path} body width`).toBeLessThanOrEqual(390);

      const chrome = await page.getByTestId("product-chrome").boundingBox();
      expect(chrome?.height, `${surface.path} mobile chrome`).toBeLessThanOrEqual(56);
    }
  });

  test("critical mobile actions preserve the 44px target contract", async ({ page }) => {
    await page.goto("/");
    await expectMinimumTarget(page.getByTestId("primary-action"), "workspace action");
    await expectMinimumTarget(
      page.getByRole("navigation", { name: "Originator navigation" }).getByRole("link", {
        name: "Portfolio",
        exact: true,
      }),
      "workspace navigation",
    );

    await page.goto("/deal-room");
    await expectMinimumTarget(page.getByTestId("participant-primary-action"), "participant exit");
    await expectMinimumTarget(page.getByTestId("participant-review-action"), "participant why disclosure");

    await page.goto("/protocol");
    await expectMinimumTarget(
      page.locator(".protocol-runbook").getByRole("button", { name: "Copy selected checklist", exact: true }),
      "protocol runbook action",
    );
  });

  test("protocol mobile order is incident, impact, runbook, then proof", async ({ page }) => {
    await page.goto("/protocol");

    const incident = await page.getByTestId("protocol-incident-stage").boundingBox();
    const impact = await page.getByTestId("protocol-impact").boundingBox();
    const runbook = await page.getByTestId("protocol-runbook").boundingBox();
    const proof = await page.getByTestId("protocol-proof-stage").boundingBox();

    expect(incident).not.toBeNull();
    expect(impact).not.toBeNull();
    expect(runbook).not.toBeNull();
    expect(proof).not.toBeNull();
    expect((impact?.y ?? 0) + (impact?.height ?? 0)).toBeLessThanOrEqual(runbook?.y ?? 0);
    expect((runbook?.y ?? 0) + (runbook?.height ?? 0)).toBeLessThanOrEqual(proof?.y ?? 0);
  });
});

test.describe("motion and semantic foundations", () => {
  test("reduced motion removes element, pseudo-element, and runtime motion", async ({ page }) => {
    await page.emulateMedia({ reducedMotion: "reduce" });

    for (const surface of surfaces) {
      await page.goto(surface.path);
      await expect(page.getByRole("heading", { name: surface.heading }).first()).toBeVisible();

      const motion = await page.evaluate(() => {
        const milliseconds = (value: string) => {
          const numeric = Number.parseFloat(value);
          if (!Number.isFinite(numeric)) return 0;
          return value.trim().endsWith("ms") ? numeric : numeric * 1_000;
        };
        const maximum = (value: string) => Math.max(0, ...value.split(",").map((entry) => milliseconds(entry)));
        const pseudos: Array<string | null> = [null, "::before", "::after"];
        const violations: Array<Record<string, unknown>> = [];

        for (const element of document.querySelectorAll<HTMLElement>("body *")) {
          for (const pseudo of pseudos) {
            const style = getComputedStyle(element, pseudo);
            const namedAnimation = style.animationName.split(",").some((name) => name.trim() !== "none");
            const infiniteAnimation = style.animationIterationCount
              .split(",")
              .some((count) => count.trim() === "infinite");
            const animationTime = maximum(style.animationDuration) + maximum(style.animationDelay);
            const transitionTime = maximum(style.transitionDuration) + maximum(style.transitionDelay);

            if ((namedAnimation && (infiniteAnimation || animationTime > 20)) || transitionTime > 20) {
              violations.push({
                tag: element.tagName.toLowerCase(),
                className: element.getAttribute("class") ?? "",
                pseudo,
                animationName: style.animationName,
                animationTime,
                transitionTime,
              });
            }
          }
          if (violations.length >= 12) break;
        }

        const runtimeAnimations = document.getAnimations().flatMap((animation) => {
          const timing = animation.effect?.getComputedTiming();
          const duration = typeof timing?.duration === "number" ? timing.duration : 0;
          const iterations = timing?.iterations ?? 1;
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

      expect(motion.preferenceMatches).toBe(true);
      expect(motion.scrollBehavior).toBe("auto");
      expect(motion.violations, `${surface.path} CSS motion`).toEqual([]);
      expect(motion.runtimeAnimations, `${surface.path} runtime motion`).toEqual([]);
    }
  });

  test("semantic colors retain AA text contrast and legacy palette aliases stay absent", async ({ page }) => {
    await page.goto("/");

    const tokenNames = [
      "--background-primary",
      "--surface-raised",
      "--surface-proof",
      "--text-primary",
      "--text-secondary",
      "--text-on-proof",
      "--text-on-critical",
      "--action-primary",
      "--domain-receivable",
      "--domain-protection",
      "--state-critical",
      "--state-attention",
      "--state-positive",
      "--evidence-observed",
      "--evidence-attested",
      "--evidence-derived",
      "--evidence-external",
    ] as const;
    const legacyNames = ["--cobalt", "--sulfur", "--vermilion", "--graphite"] as const;
    const values = await page.evaluate(
      ({ required, legacy }) => {
        const style = getComputedStyle(document.documentElement);
        return Object.fromEntries([...required, ...legacy].map((name) => [name, style.getPropertyValue(name).trim()]));
      },
      { required: tokenNames, legacy: legacyNames },
    );

    for (const name of tokenNames) expect(values[name], `${name} must resolve`).not.toBe("");
    for (const name of legacyNames) expect(values[name], `${name} must stay retired`).toBe("");

    const exclusiveRoles = [
      "--action-primary",
      "--domain-receivable",
      "--domain-protection",
      "--state-critical",
      "--state-attention",
      "--state-positive",
      "--evidence-observed",
      "--evidence-attested",
      "--evidence-derived",
      "--evidence-external",
    ] as const;
    expect(new Set(exclusiveRoles.map((name) => values[name].toLowerCase())).size).toBe(exclusiveRoles.length);

    const pairs = [
      ["--text-primary", "--background-primary"],
      ["--text-secondary", "--background-primary"],
      ["--text-primary", "--surface-raised"],
      ["--text-secondary", "--surface-raised"],
      ["--action-primary", "--surface-raised"],
      ["--domain-receivable", "--surface-raised"],
      ["--domain-protection", "--surface-raised"],
      ["--state-critical", "--surface-raised"],
      ["--state-attention", "--surface-raised"],
      ["--state-positive", "--surface-raised"],
      ["--evidence-observed", "--surface-raised"],
      ["--evidence-attested", "--surface-raised"],
      ["--evidence-derived", "--surface-raised"],
      ["--evidence-external", "--background-primary"],
      ["--evidence-external", "--surface-raised"],
      ["--text-on-proof", "--surface-proof"],
      ["--text-on-critical", "--state-critical"],
    ] as const;

    for (const [foreground, background] of pairs) {
      const ratio = contrastRatio(values[foreground], values[background]);
      expect(ratio, `${foreground} on ${background}: ${ratio.toFixed(2)}:1`).toBeGreaterThanOrEqual(4.5);
    }
  });
});
