import { expect, test, type Page } from "@playwright/test";

const PERSPECTIVES = ["workspace", "participant", "protocol"] as const;

async function expectNoHorizontalOverflow(page: Page) {
  const dimensions = await page.evaluate(() => ({
    clientWidth: document.documentElement.clientWidth,
    documentWidth: document.documentElement.scrollWidth,
    bodyWidth: document.body.scrollWidth,
  }));

  expect(dimensions.documentWidth).toBeLessThanOrEqual(dimensions.clientWidth);
  expect(dimensions.bodyWidth).toBeLessThanOrEqual(dimensions.clientWidth);
}

test("the compressed landing keeps the frozen hero and one truthful journey", async ({ page }, testInfo) => {
  await page.goto("/");

  await expect(page.getByRole("heading", { name: "Conflict became recourse." })).toBeVisible();
  await expect(page.getByText(
    "When private claims collide, keep tokenized credit moving.",
    { exact: true },
  )).toBeVisible();
  if ((page.viewportSize()?.width ?? 0) > 760) {
    const promiseGeometry = await page.getByText(
      "When private claims collide, keep tokenized credit moving.",
      { exact: true },
    ).evaluate((node) => ({
      height: node.getBoundingClientRect().height,
      lineHeight: Number.parseFloat(getComputedStyle(node).lineHeight),
    }));
    expect(promiseGeometry.height).toBeLessThanOrEqual(promiseGeometry.lineHeight * 1.1);
  }
  await expect(page.getByText(
    "Mordant privately checks whether financing claims conflict, then applies a precommitted policy to the next bounded action.",
    { exact: true },
  )).toBeVisible();
  await expect(page.getByText(
    "Cleanverse verifies the receivable’s provenance and participant eligibility.",
    { exact: true },
  )).toHaveCount(0);
  await expect(page.getByText(
    "A real encrypted check on a receivable identity with verified Cleanverse provenance. About 30 seconds.",
    { exact: true },
  )).toHaveCount(0);

  const symbolField = page.locator("[class*='heroSymbolField']");
  await expect.poll(() => symbolField.locator("svg").evaluate((node) => getComputedStyle(node).fill))
    .toBe("rgb(253, 240, 255)");
  await page.waitForTimeout(900);
  if (["1280x800", "390x844"].includes(testInfo.project.name)) {
    await page.screenshot({ path: testInfo.outputPath("hero-overlap-violet-white.png") });
  }
  await page.evaluate(() => window.scrollTo({ top: 240, behavior: "instant" }));
  await expect.poll(() => symbolField.evaluate((node) => (
    Number.parseFloat(getComputedStyle(node).getPropertyValue("--symbol-scroll-rotation"))
  ))).toBeGreaterThanOrEqual(0.5);
  await expect.poll(() => symbolField.evaluate((node) => {
    const matrix = new DOMMatrix(getComputedStyle(node).transform);
    return Math.atan2(matrix.b, matrix.a) * (180 / Math.PI);
  })).toBeGreaterThanOrEqual(0.5);
  const heroGeometry = await page.getByRole("heading", { name: "Conflict became recourse." })
    .locator("xpath=ancestor::section")
    .evaluate((node) => {
      const bounds = node.getBoundingClientRect();
      return { height: bounds.height, top: bounds.top + window.scrollY };
    });
  await page.evaluate(({ height, top }) => window.scrollTo({ top: top + height, behavior: "instant" }), heroGeometry);
  await expect.poll(() => symbolField.evaluate((node) => (
    Number.parseFloat(getComputedStyle(node).getPropertyValue("--symbol-scroll-rotation"))
  ))).toBeGreaterThanOrEqual(11.5);
  await expect.poll(() => symbolField.evaluate((node) => (
    Number.parseFloat(getComputedStyle(node).getPropertyValue("--symbol-scroll-y"))
  ))).toBeLessThanOrEqual(-111);
  await page.evaluate(() => window.scrollTo({ top: 0, behavior: "instant" }));
  if ((page.viewportSize()?.width ?? 0) <= 760) {
    const mobileComposition = await page.locator("[class*='heroPhrase']").evaluate((phrase) => {
      const words = Array.from(phrase.children).map((word) => word.getBoundingClientRect());
      const phraseBounds = phrase.getBoundingClientRect();
      const symbolBounds = document.querySelector<HTMLElement>("[class*='heroSymbolField']")?.getBoundingClientRect();
      return {
        oneLine: words.length === 2 && Math.abs(words[0].top - words[1].top) <= 1,
        insideViewport: phraseBounds.left >= 0 && phraseBounds.right <= window.innerWidth,
        intersectionWidth: symbolBounds === undefined ? 0 : Math.min(phraseBounds.right, symbolBounds.right)
          - Math.max(phraseBounds.left, symbolBounds.left),
        intersectionHeight: symbolBounds === undefined ? 0 : Math.min(phraseBounds.bottom, symbolBounds.bottom)
          - Math.max(phraseBounds.top, symbolBounds.top),
      };
    });
    expect(mobileComposition.oneLine).toBe(true);
    expect(mobileComposition.insideViewport).toBe(true);
    expect(mobileComposition.intersectionWidth).toBeGreaterThan(12);
    expect(mobileComposition.intersectionHeight).toBeGreaterThan(8);
  }
  // The primary call to action lives in the shell header and opens the live
  // product directly, from every surface including the landing. There is no
  // second copy of it in the page body: this file asserts elsewhere that the
  // live product "is never duplicated as a second navigation destination", and a
  // hero link repeating it would be exactly that duplicate.
  await expect(page.getByTestId("shell-live-cta")).toHaveAttribute("href", "/protection/live");
  await expect(page.getByRole("main").getByRole("link", { name: "Run live proof" })).toHaveCount(0);
  await expect(page.getByRole("navigation", { name: "Product navigation" })
    .getByRole("link", { name: "Evidence" })).toHaveAttribute("href", "/protection/verified-run");
  await expect(page.getByRole("main").getByRole("link", { name: "Inspect verified evidence" }).first())
    .toHaveAttribute("href", "/protection/verified-run");

  await expect(page.getByTestId("mini-live-check")).toBeVisible();
  await expect(page.getByTestId("mini-live-check"))
    .toContainText("First implemented workflow · Conflicting Pledge Protection");
  const miniTitle = page.getByRole("heading", {
    name: "One receivable. Two private claims. One encrypted answer.",
  });
  await expect(miniTitle.locator(":scope > span")).toHaveText([
    "One receivable.",
    "Two private claims.",
    "One encrypted answer.",
  ]);
  await expect(page.getByTestId("mini-live-check")).toContainText("synthetic financing-claim windows");
  await expect(page.getByTestId("mini-live-check")).toContainText("real encrypted evaluation");
  await expect(page.getByTestId("mini-claim-timeline")).toContainText("Shared demo timeline · 0–600");
  await expect(page.getByTestId("mini-claim-timeline")).toContainText(
    "Each bar shows when a financing claim starts and ends.",
  );
  await expect(page.getByTestId("mini-claim-timeline")).not.toContainText("Placement only.");
  await expect(page.getByTestId("mini-live-check")).toContainText(
    "The managed demo encrypts these values before the real BGV evaluation.",
  );
  await expect(page.getByTestId("mini-claim-timeline").locator("[class*='timelineTicks'] span")).toHaveCount(7);
  await expect(page.getByTestId("mini-live-check").getByText("Example 1", { exact: true })).toBeVisible();
  await expect(page.getByTestId("mini-live-check").getByText("Example 2", { exact: true })).toBeVisible();
  await expect(page.getByTestId("mini-live-check").getByText("Arrangement 01", { exact: true })).toHaveCount(0);
  const miniPanel = page.getByTestId("mini-panel");
  await miniPanel.scrollIntoViewIfNeeded();
  const panelOptics = await miniPanel.evaluate((node) => {
    const style = getComputedStyle(node);
    const standardBackdrop = style.backdropFilter;
    const prefixedBackdrop = style.getPropertyValue("-webkit-backdrop-filter");
    const background = style.backgroundColor;
    const modernAlpha = background.match(/\/\s*([0-9.]+)\s*\)$/u);
    const legacyAlpha = background.match(/rgba\([^)]*,\s*([0-9.]+)\s*\)$/u);
    return {
      backdrop: standardBackdrop !== "none" ? standardBackdrop : prefixedBackdrop,
      background,
      backgroundAlpha: Number(modernAlpha?.[1] ?? legacyAlpha?.[1] ?? "1"),
      supportsBackdrop: CSS.supports("backdrop-filter", "blur(1px)")
        || CSS.supports("-webkit-backdrop-filter", "blur(1px)"),
      reducesTransparency: window.matchMedia("(prefers-reduced-transparency: reduce)").matches,
    };
  });
  if (panelOptics.supportsBackdrop && !panelOptics.reducesTransparency) {
    const viewportWidth = page.viewportSize()?.width ?? 1280;
    const expectedBlur = viewportWidth <= 640 ? 10 : viewportWidth <= 900 ? 16 : 24;
    expect(panelOptics.backdrop).toContain(`blur(${expectedBlur}px)`);
    const maximumAlpha = viewportWidth <= 640 ? 0.59 : viewportWidth <= 900 ? 0.51 : 0.37;
    expect(panelOptics.backgroundAlpha).toBeLessThanOrEqual(maximumAlpha);
  }
  expect(panelOptics.background).not.toBe("rgba(0, 0, 0, 0)");

  const viewport = page.viewportSize();
  await page.mouse.move((viewport?.width ?? 1280) * 0.2, (viewport?.height ?? 800) * 0.45);
  await expect.poll(() => symbolField.evaluate((node) => (
    Number.parseFloat(getComputedStyle(node).getPropertyValue("--symbol-x"))
  ))).toBeLessThanOrEqual(-6);
  if (testInfo.project.name === "1280x800" || testInfo.project.name === "390x844") {
    await page.screenshot({
      path: testInfo.outputPath(testInfo.project.name === "1280x800"
        ? "mini-run-liquid-glass.png"
        : "mini-run-liquid-glass-mobile.png"),
    });
  }
  await expect(page.getByRole("region", { name: "One path. Four bounded responsibilities." })).toBeVisible();
  await expect(page.locator("#invitation-title > span")).toHaveText([
    "One path.",
    "Four bounded responsibilities.",
  ]);
  await expect(page.locator("#how").getByText("Responsibility", { exact: true })).toHaveCount(0);
  await expect(page.locator('[data-proof="historical-onchain"]')).toBeVisible();
  await expect(page.locator('[data-proof="historical-onchain"]'))
    .toContainText("See a completed recourse, on chain.");
  await expect(page.locator('[data-proof="historical-onchain"]'))
    .toContainText("historical evidence is independent from the managed check above");
  await expect(page.getByTestId("landing-to-verified-run"))
    .toHaveAttribute("href", "/protection/verified-run");
  await expect(page.locator("[class*='flowMotionPath']"))
    .toHaveAttribute("d", "M150 120H425L505 40H695L775 120H1050");
  await expect(page.locator("[class*='flowRoutePaint']"))
    .toHaveAttribute("d", "M150 120H425L505 40H695L775 120H1050");
  await expect(page.locator("[data-integration-route-segment]")).toHaveCount(0);
  await expect(page.locator("[class*='flowNodes']")).toHaveCount(0);
  for (const section of [
    page.getByTestId("mini-live-check"),
    page.locator("#how"),
    page.getByRole("region", { name: "Complementary proofs" }),
  ]) {
    expect(await section.evaluate((node) => getComputedStyle(node).borderTopWidth)).toBe("0px");
  }

  const integration = page.locator('[aria-label="Integration stages"]');
  const responsibility = page.locator("#how");
  await page.mouse.move(1, 1);
  await responsibility.scrollIntoViewIfNeeded();
  await expect(responsibility).toHaveAttribute("data-visible", "true");
  const stageBoxes = await integration.getByRole("button").evaluateAll((buttons) => buttons.map((button) => {
    const bounds = button.getBoundingClientRect();
    return { height: bounds.height, width: bounds.width, x: bounds.x, y: bounds.y };
  }));
  expect(stageBoxes).toHaveLength(4);
  if ((viewport?.width ?? 0) > 900) {
    expect(Math.max(...stageBoxes.map(({ y }) => y)) - Math.min(...stageBoxes.map(({ y }) => y)))
      .toBeLessThanOrEqual(1);
    const flowWidth = await page.locator('[aria-label="Interactive integration path"]')
      .evaluate((node) => node.getBoundingClientRect().width);
    expect(flowWidth).toBeGreaterThanOrEqual((viewport?.width ?? 1280) * 0.8);

    const flowTop = await page.locator('[aria-label="Interactive integration path"]').evaluate((node) => {
      const bounds = node.getBoundingClientRect();
      return bounds.top + window.scrollY;
    });
    await page.evaluate(({ top, viewportHeight }) => {
      window.scrollTo({ top: top - (viewportHeight * 0.27), behavior: "instant" });
    }, { top: flowTop, viewportHeight: viewport?.height ?? 800 });
  }
  const policyActionStage = integration.getByRole("button", { name: /Policy-authorized action/ });
  if ((viewport?.width ?? 0) <= 900) await policyActionStage.click();
  await expect(policyActionStage).toHaveAttribute("aria-pressed", "true");
  if ((viewport?.width ?? 0) > 900) {
    const hardenedProofTop = await page.locator('[data-proof="historical-onchain"]')
      .evaluate((node) => node.getBoundingClientRect().top);
    expect(hardenedProofTop).toBeGreaterThan((viewport?.height ?? 800) * 0.82);
  }
  await expect(page.getByText(
    "The private result selects only a precommitted action branch, with the exact execution boundary recorded in evidence.",
    { exact: true },
  )).toBeVisible();
  if (testInfo.project.name === "1280x800" || testInfo.project.name === "390x844") {
    await page.waitForTimeout(700);
    await page.screenshot({
      path: testInfo.outputPath(testInfo.project.name === "1280x800"
        ? "responsibility-path-desktop.png"
        : "responsibility-path-mobile.png"),
    });
  }

  // The standalone caveat section is gone. The main narrative now ends at the
  // separate completed proof without replacing it with another disclaimer.
  await expect(page.locator("#boundaries")).toHaveCount(0);
  await expect(page.getByRole("heading", { name: "What this is, and what it is not." })).toHaveCount(0);
  await expect(page.getByRole("link", { name: "What this is and is not" })).toHaveCount(0);
  await expect(page.locator("main > section").last())
    .toContainText("Verified on-chain execution · separate completed run");
  await expect(page.locator("main > section").last())
    .toContainText("historical evidence is independent from the managed check above");
  const institutionalPrivacy = page.locator('[data-proof="institutional-privacy"]');
  await expect(institutionalPrivacy).toBeVisible();
  await expect(institutionalPrivacy).toContainText("Qualified institutional privacy");
  await expect(institutionalPrivacy).toContainText("before Mordant receives it");
  await expect(institutionalPrivacy).toContainText("separate institutional workflow—not the managed check above");
  await expect(institutionalPrivacy.getByRole("link", { name: "Read the technical qualification" }))
    .toHaveAttribute("href", /participant-originated-encryption\.md$/u);
  await expect(page.locator('[data-proof]').nth(0)).toHaveAttribute("data-proof", "historical-onchain");
  await expect(page.locator('[data-proof]').nth(1)).toHaveAttribute("data-proof", "institutional-privacy");
  if ((viewport?.width ?? 0) > 760) {
    const proofActionBounds = await page.locator('[data-proof] a').evaluateAll((actions) => actions.map((action) => {
      const bounds = action.getBoundingClientRect();
      return { bottom: bounds.bottom, height: bounds.height };
    }));
    expect(proofActionBounds).toHaveLength(2);
    expect(Math.abs(proofActionBounds[0].bottom - proofActionBounds[1].bottom)).toBeLessThanOrEqual(1);
    expect(Math.abs(proofActionBounds[0].height - proofActionBounds[1].height)).toBeLessThanOrEqual(1);
  }
  if (testInfo.project.name === "1280x800") {
    const complementaryProofs = page.getByRole("region", { name: "Complementary proofs" });
    await complementaryProofs.evaluate((section) => { section.dataset.visible = "true"; });
    await complementaryProofs.screenshot({
      path: testInfo.outputPath("complementary-proofs-desktop.png"),
    });
  }
  for (const technicalCaveat of [
    "native Monad FHE",
    "threshold release",
    "single-host",
    "one slot",
    "production authorized",
    "participant device",
  ]) {
    await expect(page.getByRole("main")).not.toContainText(technicalCaveat);
  }

  // The accepted scrollytelling is preserved in source but intentionally absent
  // from this first compressed render.
  await expect(page.getByRole("navigation", { name: "Transformation states" })).toHaveCount(0);
  for (const removedHeading of [
    "Conflicting Pledge Protection",
    "The answer is not the product. The consequence is.",
    "One receipt. One verifiable transition.",
    "Test accountable recourse beside the process you already trust.",
  ]) {
    await expect(page.getByRole("heading", { name: removedHeading, exact: true })).toHaveCount(0);
  }
  const renderedText = await page.locator("body").innerText();
  expect(renderedText).not.toMatch(/\b30 Jul\b/u);
  expect(renderedText).not.toMatch(/\b0[1-5]\s*[·/]\s*/u);
  expect(renderedText).not.toContain("Continue");

  await expectNoHorizontalOverflow(page);
});

test("the responsibility route advances only through the central reading band", async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== "1280x800", "One deterministic desktop scroll qualification is sufficient.");
  await page.goto("/");

  const flow = page.locator('[aria-label="Interactive integration path"]');
  const stages = page.locator('[aria-label="Integration stages"]').getByRole("button");
  const flowTop = await flow.evaluate((node) => {
    const bounds = node.getBoundingClientRect();
    return bounds.top + window.scrollY;
  });
  const placeFlowAt = async (viewportRatio: number, expectedStage: number) => {
    await page.evaluate(({ top, ratio }) => {
      window.scrollTo({ top: top - (window.innerHeight * ratio), behavior: "instant" });
    }, { top: flowTop, ratio: viewportRatio });
    await expect(stages.nth(expectedStage)).toHaveAttribute("aria-pressed", "true");
  };

  // Entering the lower viewport does not prematurely advance the story.
  await placeFlowAt(0.58, 0);
  await placeFlowAt(0.50, 1);
  await placeFlowAt(0.39, 2);
  await placeFlowAt(0.27, 3);
  // The exact same reading band governs reverse playback.
  await placeFlowAt(0.39, 2);
  await placeFlowAt(0.50, 1);
  await placeFlowAt(0.58, 0);
});

test("the responsibility route stays attached to its signal in both directions", async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== "1280x800", "One deterministic desktop motion qualification is sufficient.");
  await page.setViewportSize({ width: 2048, height: 1152 });
  await page.goto("/");
  await page.locator("#how").evaluate((section) => { section.dataset.visible = "true"; });

  const integration = page.locator('[aria-label="Integration stages"]');
  const reveal = page.locator("[class*='flowRoutePaint']");
  const clip = page.locator("[class*='flowRouteClip']");
  const signal = page.locator("[class*='integrationSignal']");
  const expectedClipEdges = [415, 505, 785, 1050];
  const expectedColours = [
    "var(--receivable)",
    "var(--protection)",
    "var(--protection)",
    "var(--action)",
  ];

  for (let index = 0; index < expectedClipEdges.length; index += 1) {
    const stage = integration.getByRole("button").nth(index);
    await stage.evaluate((button) => (button as HTMLButtonElement).focus({ preventScroll: true }));
    await expect(stage).toHaveAttribute("aria-pressed", "true");
    await expect(signal).toHaveAttribute("data-arrived", "true");
    await expect.poll(async () => Number(await clip.getAttribute("width")))
      .toBeCloseTo(expectedClipEdges[index], 2);
    await expect.poll(() => signal.evaluate((node) => (
      (node as SVGElement).style.getPropertyValue("--integration-signal-colour")
    ))).toBe(expectedColours[index]);

    const connection = await signal.evaluate((node) => {
      const clip = document.querySelector<SVGRectElement>("[class*='flowRouteClip']");
      const transform = (node as SVGGElement).transform.baseVal.consolidate()?.matrix;
      if (clip === null || transform === undefined) return null;
      return {
        clipToSignal: Math.abs(Number(clip.getAttribute("width")) - transform.e),
      };
    });
    expect(connection).not.toBeNull();
    expect(connection?.clipToSignal).toBeLessThanOrEqual(0.01);

    if (index === 2 || index === 3) {
      await page.locator('[aria-label="Interactive integration path"]').screenshot({
        path: testInfo.outputPath(index === 2
          ? "responsibility-continuity-governed.png"
          : "responsibility-continuity-action.png"),
      });
    }
  }

  // Sample every animation frame, not just the authored stops. The clip edge
  // and the marker centre must remain the same coordinate throughout motion.
  const firstStage = integration.getByRole("button").nth(0);
  await firstStage.evaluate((button) => (button as HTMLButtonElement).focus({ preventScroll: true }));
  await expect.poll(async () => Number(await clip.getAttribute("width"))).toBeCloseTo(415, 2);
  await expect(signal).toHaveAttribute("data-arrived", "true");
  const connectionSamples = signal.evaluate((node) => new Promise<number>((resolve, reject) => {
    let frames = 0;
    let maxGap = 0;
    let sawMotion = false;
    const sample = () => {
      frames += 1;
      const clip = document.querySelector<SVGRectElement>("[class*='flowRouteClip']");
      const transform = (node as SVGGElement).transform.baseVal.consolidate()?.matrix;
      if (clip === null || transform === undefined) {
        reject(new Error("Integration route geometry is unavailable"));
        return;
      }
      maxGap = Math.max(maxGap, Math.abs(Number(clip.getAttribute("width")) - transform.e));
      if ((node as SVGGElement).dataset.arrived === "false") sawMotion = true;
      if (sawMotion && (node as SVGGElement).dataset.arrived === "true") {
        resolve(maxGap);
        return;
      }
      if (frames > 120) {
        reject(new Error("Integration route motion did not settle"));
        return;
      }
      window.requestAnimationFrame(sample);
    };
    window.requestAnimationFrame(sample);
  }));
  await integration.getByRole("button").nth(3)
    .evaluate((button) => (button as HTMLButtonElement).focus({ preventScroll: true }));
  expect(await connectionSamples).toBeLessThanOrEqual(0.01);

  // One painted path owns every colour and corner. Separate painted segments
  // would be able to expose a seam even while their summed lengths look right.
  await expect(reveal).toHaveCount(1);
  await expect(reveal).not.toHaveAttribute("stroke-dasharray");
  await expect(reveal).not.toHaveAttribute("stroke-dashoffset");
  await expect(page.locator("[class*='integrationTether']")).toHaveCount(0);

  const centering = await page.locator("[class*='flowGraphic']").evaluate((svg) => {
    const path = svg.querySelector<SVGPathElement>("[class*='flowMotionPath']");
    const matrix = path?.getScreenCTM();
    if (path === null || matrix === null) return null;
    const start = new DOMPoint(150, 120).matrixTransform(matrix);
    const end = new DOMPoint(1050, 120).matrixTransform(matrix);
    const plateauStart = new DOMPoint(505, 40).matrixTransform(matrix);
    const plateauEnd = new DOMPoint(695, 40).matrixTransform(matrix);
    const bounds = svg.getBoundingClientRect();
    const stages = document.querySelector<HTMLElement>('[aria-label="Integration stages"]')
      ?.getBoundingClientRect();
    return {
      routeCenter: (start.x + end.x) / 2,
      canvasCenter: bounds.left + (bounds.width / 2),
      plateauCenter: (plateauStart.x + plateauEnd.x) / 2,
      stagesCenter: stages === undefined ? null : stages.left + (stages.width / 2),
    };
  });
  expect(centering).not.toBeNull();
  expect(Math.abs((centering?.routeCenter ?? 0) - (centering?.canvasCenter ?? 0))).toBeLessThanOrEqual(1);
  expect(centering?.stagesCenter).not.toBeNull();
  expect(Math.abs((centering?.plateauCenter ?? 0) - (centering?.stagesCenter ?? 0)))
    .toBeLessThanOrEqual(1);

  const earlierStage = integration.getByRole("button").nth(1);
  await earlierStage.evaluate((button) => (button as HTMLButtonElement).focus({ preventScroll: true }));
  await expect(earlierStage).toHaveAttribute("aria-pressed", "true");
  await expect(signal).toHaveAttribute("data-arrived", "true");
  // Reverse playback retracts in exact lockstep: the line may never reveal a
  // responsibility ahead of the travelling marker.
  await expect.poll(async () => Number(await clip.getAttribute("width")))
    .toBeCloseTo(expectedClipEdges[1], 2);
  await expect.poll(() => signal.evaluate((node) => (
    (node as SVGElement).style.getPropertyValue("--integration-signal-colour")
  ))).toBe("var(--protection)");
  const reverseRouteToSignal = await signal.evaluate((node) => {
    const clip = document.querySelector<SVGRectElement>("[class*='flowRouteClip']");
    const transform = (node as SVGGElement).transform.baseVal.consolidate()?.matrix;
    if (clip === null || transform === undefined) return null;
    return Math.abs(Number(clip.getAttribute("width")) - transform.e);
  });
  expect(reverseRouteToSignal).not.toBeNull();
  expect(reverseRouteToSignal).toBeLessThanOrEqual(1);
  await page.locator("#how").evaluate((section) => { section.dataset.visible = "true"; });
  await page.locator('[aria-label="Interactive integration path"]')
    .screenshot({ path: testInfo.outputPath("responsibility-reverse-stable.png") });
});

test("one recorded checkpoint keeps its facts across three distinct perspectives and Proof", async ({ page }) => {
  await page.goto("/demo?perspective=workspace&checkpoint=reveal");

  const workspace = page.getByTestId("living-experience");
  await expect(workspace).toHaveAttribute("data-surface", "workspace");
  await expect(workspace).toHaveAttribute("data-checkpoint", "reveal");
  await expect(page.getByText("Review queue", { exact: true })).toBeVisible();
  await expect(page.getByTestId("recorded-checkpoint-rail")).toHaveAttribute("data-density", "full");

  const identity = {
    deal: await workspace.getAttribute("data-deal-id"),
    vault: await workspace.getAttribute("data-vault"),
    root: await workspace.getAttribute("data-invoice-root"),
  };

  await page.getByRole("link", { name: "Participant", exact: true }).click();
  await expect(page).toHaveURL(/\/demo\?perspective=participant&checkpoint=reveal$/u);
  const participant = page.getByTestId("living-experience");
  await expect(participant).toHaveAttribute("data-surface", "participant");
  await expect(page.getByText("Your current status · Wait", { exact: true })).toBeVisible();
  await expect(page.getByTestId("recorded-checkpoint-rail")).toHaveAttribute("data-density", "compact");
  await expect(participant).toHaveAttribute("data-deal-id", identity.deal ?? "");
  await expect(participant).toHaveAttribute("data-vault", identity.vault ?? "");
  await expect(participant).toHaveAttribute("data-invoice-root", identity.root ?? "");

  await page.getByRole("link", { name: "Protocol", exact: true }).click();
  await expect(page).toHaveURL(/\/demo\?perspective=protocol&checkpoint=reveal$/u);
  const protocol = page.getByTestId("living-experience");
  await expect(protocol).toHaveAttribute("data-surface", "protocol");
  await expect(page.getByText("Last confirmed transition", { exact: true })).toBeVisible();
  await expect(page.getByTestId("recorded-checkpoint-rail")).toHaveAttribute("data-density", "full");
  await expect(protocol).toHaveAttribute("data-deal-id", identity.deal ?? "");
  await expect(page.getByRole("link", { name: "Apply for a shadow pilot" })).toHaveAttribute("href", "/pilot");

  await page.getByRole("button", { name: "Open receipt proof" }).click();
  await expect(page.getByTestId("living-proof")).toBeVisible();
  await expect(page.getByTestId("living-experience")).toHaveCount(0);
  await expect(page.getByRole("link", { name: "Apply for a shadow pilot" })).toHaveAttribute("href", "/pilot");
  await page.getByRole("button", { name: "Back to selected checkpoint" }).click();
  await expect(page).toHaveURL(/\/demo\?perspective=protocol&checkpoint=reveal$/u);
  await expect(page.getByTestId("living-experience")).toHaveAttribute("data-checkpoint", "reveal");
});

test("the legacy participant URL redirects to the canonical route", async ({ page }) => {
  await page.goto("/deal-room?checkpoint=reveal");
  await expect(page).toHaveURL(/\/participant\?checkpoint=reveal$/u);
  await expect(page.getByTestId("living-experience")).toHaveAttribute("data-surface", "participant");
});

test("public and recorded product routes fit the viewport", async ({ page }) => {
  await page.goto("/");
  await expectNoHorizontalOverflow(page);

  for (const perspective of PERSPECTIVES) {
    await page.goto(`/demo?perspective=${perspective}&checkpoint=reveal`);
    await expect(page.getByTestId("living-experience")).toHaveAttribute("data-surface", perspective);
    await expectNoHorizontalOverflow(page);
  }
});

test("the shadow pilot route asks only for pilot-fit information and never fakes delivery", async ({ page }, testInfo) => {
  await page.goto("/pilot");

  await expect(page.getByRole("heading", { name: "Test accountable recourse against your current process." })).toBeVisible();
  await expect(page.getByText(
    "Run Mordant alongside your current process, without moving funds or automating production actions.",
    { exact: true },
  )).toBeVisible();

  const form = page.getByTestId("pilot-application-form");
  for (const label of [
    "Organization",
    "Your role",
    "Portfolio type",
    "Approximate receivables volume",
    "How do you manage conflicting claims today?",
    "System or data source used",
    "Professional email",
  ]) {
    await expect(form.getByLabel(label, { exact: true })).toBeVisible();
  }
  await expect(form.getByRole("button", { name: "Apply for a shadow pilot" })).toBeDisabled();
  await expect(form).toContainText("no data can be sent yet");
  const pilotIntroHeight = await page.locator("main > section").first()
    .evaluate((node) => node.getBoundingClientRect().height);
  if ((page.viewportSize()?.width ?? 0) > 760) expect(pilotIntroHeight).toBeLessThanOrEqual(720);
  await expectNoHorizontalOverflow(page);
  if (["1280x800", "390x844"].includes(testInfo.project.name)) {
    await page.screenshot({ path: testInfo.outputPath("pilot-compact.png"), fullPage: true });
  }

  const invalid = await page.request.post("/api/pilot-applications", {
    data: {
      organization: "Example Factor",
      role: "Credit or operations",
      portfolioType: "Factoring",
      approximateVolume: "10,000 receivables annually",
      conflictProcess: "Email and spreadsheet escalation.",
      dataSource: "Internal servicing platform",
      workEmail: "operator@gmail.com",
      website: "",
    },
  });
  expect(invalid.status()).toBe(400);
  await expect(invalid.json()).resolves.toMatchObject({
    fields: { workEmail: ["Use your professional email address."] },
  });

  const unavailable = await page.request.post("/api/pilot-applications", {
    data: {
      organization: "Example Factor",
      role: "Credit or operations",
      portfolioType: "Factoring",
      approximateVolume: "10,000 receivables annually",
      conflictProcess: "Email and spreadsheet escalation.",
      dataSource: "Internal servicing platform",
      workEmail: "operator@example-factor.com",
      website: "",
    },
  });
  expect(unavailable.status()).toBe(503);
  await expect(unavailable.json()).resolves.toEqual({
    error: "Application intake is not connected yet. No data was sent.",
  });
});

test("the public shell exposes one hierarchy and one primary action", async ({ page }, testInfo) => {
  await page.goto("/");

  const navigation = page.getByRole("navigation", { name: "Product navigation" });
  // Destinations and their order are the contract. The visible wording is
  // deliberately shorter on a phone, so it is not what this test pins.
  const hrefs = await navigation.getByRole("link").evaluateAll(
    (links) => links.map((link) => link.getAttribute("href")),
  );
  expect(hrefs).toEqual(["/#how", "/protection/verified-run", "/pilot"]);

  // Every destination must still announce a name at this viewport, so a short
  // label can never become an empty one.
  for (const name of await navigation.getByRole("link").allInnerTexts()) {
    expect(name.trim().length).toBeGreaterThan(0);
  }

  if (!testInfo.project.use.hasTouch) {
    const header = page.getByRole("banner");
    const how = navigation.getByRole("link", { name: "How it works" });
    const label = how.locator("[class*='tabLabel']");
    const beforeBox = await how.boundingBox();
    const headerHeight = await header.evaluate((node) => node.getBoundingClientRect().height);
    const headerRule = await header.evaluate((node) => getComputedStyle(node).borderBottomColor);
    const restingTongue = await how.evaluate((node) => {
      const style = getComputedStyle(node, "::before");
      return {
        bottom: Number.parseFloat(style.bottom),
        height: Number.parseFloat(style.height)
          + Number.parseFloat(style.borderTopWidth)
          + Number.parseFloat(style.borderBottomWidth),
        opacity: Number(style.opacity),
        top: Number.parseFloat(style.top),
      };
    });
    expect(restingTongue.opacity).toBeGreaterThanOrEqual(0.99);
    const restingReferenceHeight = (page.viewportSize()?.width ?? 0) > 1023
      ? headerHeight
      : (beforeBox?.height ?? headerHeight);
    expect(restingTongue.height).toBeGreaterThanOrEqual(restingReferenceHeight);
    expect(restingTongue.top).toBeLessThanOrEqual(0.1);
    expect(restingTongue.bottom).toBeLessThanOrEqual(-0.9);
    const navigationRules = await navigation.getByRole("link").evaluateAll((links) => links.map((link) => {
      const style = getComputedStyle(link, "::before");
      return {
        color: style.borderLeftColor,
        transition: style.transitionProperty,
        width: style.borderLeftWidth,
      };
    }));
    for (const rule of navigationRules) {
      expect(rule.color).toBe(headerRule);
      expect(rule.width).toBe("1px");
      expect(rule.transition).not.toContain("background");
    }
    const navigationBoxes = await navigation.getByRole("link").evaluateAll((links) => links.map((link) => {
      const bounds = link.getBoundingClientRect();
      return { left: bounds.left, right: bounds.right };
    }));
    for (let index = 1; index < navigationBoxes.length; index += 1) {
      expect(navigationBoxes[index].left - navigationBoxes[index - 1].right).toBeLessThanOrEqual(0.1);
    }

    await how.hover();
    await expect.poll(() => label.evaluate((node) => new DOMMatrix(getComputedStyle(node).transform).m42))
      .toBeGreaterThanOrEqual(11.5);
    await expect.poll(() => how.evaluate((node) => {
      const style = getComputedStyle(node, "::before");
      return Number.parseFloat(style.height)
        + Number.parseFloat(style.borderTopWidth)
        + Number.parseFloat(style.borderBottomWidth);
    }))
      .toBeGreaterThanOrEqual(restingTongue.height + 11.5);
    expect(await how.evaluate((node) => Number.parseFloat(getComputedStyle(node, "::before").top)))
      .toBeCloseTo(restingTongue.top, 1);
    expect(await how.boundingBox()).toEqual(beforeBox);
    if (testInfo.project.name === "1280x800") {
      await page.screenshot({ path: testInfo.outputPath("header-tongue-hover.png") });
    }

    await page.getByRole("link", { name: "Mordant home" }).hover();
    await expect.poll(() => label.evaluate((node) => new DOMMatrix(getComputedStyle(node).transform).m42))
      .toBeLessThanOrEqual(0.1);
    await expect.poll(() => how.evaluate((node) => {
      const style = getComputedStyle(node, "::before");
      return Number.parseFloat(style.height)
        + Number.parseFloat(style.borderTopWidth)
        + Number.parseFloat(style.borderBottomWidth);
    }))
      .toBeLessThanOrEqual(restingTongue.height + 0.1);

    const liveTab = page.getByTestId("shell-live-cta");
    const liveLabel = liveTab.locator("[class*='ctaLabel']");
    const restingLiveTab = await liveTab.evaluate((node) => {
      const style = getComputedStyle(node, "::before");
      return {
        background: style.backgroundColor,
        borderColor: style.borderLeftColor,
        borderWidth: style.borderLeftWidth,
        height: Number.parseFloat(style.height)
          + Number.parseFloat(style.borderTopWidth)
          + Number.parseFloat(style.borderBottomWidth),
        top: Number.parseFloat(style.top),
        transition: style.transitionProperty,
      };
    });
    expect(restingLiveTab.borderColor).toBe(headerRule);
    expect(restingLiveTab.borderWidth).toBe("1px");
    expect(restingLiveTab.height).toBeGreaterThanOrEqual(restingReferenceHeight);
    expect(restingLiveTab.transition).not.toContain("background");
    await liveTab.hover();
    await expect.poll(() => liveLabel.evaluate((node) => new DOMMatrix(getComputedStyle(node).transform).m42))
      .toBeGreaterThanOrEqual(11.5);
    await expect.poll(() => liveTab.evaluate((node) => {
      const style = getComputedStyle(node, "::before");
      return Number.parseFloat(style.height)
        + Number.parseFloat(style.borderTopWidth)
        + Number.parseFloat(style.borderBottomWidth);
    }))
      .toBeGreaterThanOrEqual(restingLiveTab.height + 11.5);
    expect(await liveTab.evaluate((node) => Number.parseFloat(getComputedStyle(node, "::before").top)))
      .toBeCloseTo(restingLiveTab.top, 1);
    expect(await liveTab.evaluate((node) => getComputedStyle(node, "::before").backgroundColor))
      .not.toBe(restingLiveTab.background);
    if (testInfo.project.name === "1280x800") {
      await page.screenshot({ path: testInfo.outputPath("header-live-tongue-hover.png") });
    }

    if ((page.viewportSize()?.width ?? 0) > 1023) expect(headerHeight).toBeLessThanOrEqual(57);
    else expect(headerHeight).toBeLessThanOrEqual(110);
  }

  if (testInfo.project.name === "390x844") {
    await page.screenshot({ path: testInfo.outputPath("public-header-hero-mobile.png") });
  }

  // The live product is the only primary action, and it is never duplicated as a
  // second navigation destination.
  await expect(navigation.getByRole("link", { name: /live check|Run the live check/u })).toHaveCount(0);
  await expect(page.getByTestId("shell-live-cta")).toHaveAttribute("href", "/protection/live");

  // Old destinations must not reappear anywhere in the public chrome.
  for (const retired of ["/workspace", "/participant", "/protocol", "/design-system"]) {
    await expect(page.locator(`header a[href="${retired}"], footer a[href="${retired}"]`)).toHaveCount(0);
  }

  // The live product wears the same shell and marks itself as the current surface.
  await page.goto("/protection/live");
  await expect(page.getByRole("navigation", { name: "Product navigation" })).toBeVisible();
  await expect(page.getByTestId("shell-live-cta")).toHaveCount(0);
  await expect(page.getByRole("contentinfo").getByRole("link", { name: "Run the full managed proof" }))
    .toHaveAttribute("href", "/protection/live");
});
