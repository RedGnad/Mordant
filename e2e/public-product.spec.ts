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
    "Mordant privately checks whether financing claims conflict, then turns a confirmed conflict into governed recourse.",
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
  if (testInfo.project.name === "1280x800") {
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
  ))).toBeLessThanOrEqual(-87);
  await page.evaluate(() => window.scrollTo({ top: 0, behavior: "instant" }));
  // On the landing, both primary entry points move to its one real experiment.
  await expect(page.getByTestId("shell-live-cta")).toHaveAttribute("href", "/#product");
  await expect(page.getByRole("main").getByRole("link", { name: "Run the live check" }).first())
    .toHaveAttribute("href", "#product");
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
    "Only encrypted values enter the private check.",
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
  await expect(page.getByRole("region", { name: "Verify the consequence, not a claim about it." })).toBeVisible();
  await expect(page.getByTestId("landing-to-verified-run"))
    .toHaveAttribute("href", "/protection/verified-run");
  await expect(page.locator("[class*='flowMotionPath']"))
    .toHaveAttribute("d", "M150 120H390L470 40H660L740 120H1050");
  await expect(page.locator("[class*='flowRouteDecision']"))
    .toHaveAttribute("d", "M380 120H390L470 40H660L740 120H750");
  await expect(page.locator("[class*='flowRouteAction']"))
    .toHaveAttribute("d", "M750 120H1050");
  await expect(page.locator("[class*='flowNodes']")).toHaveCount(0);
  for (const section of [
    page.getByTestId("mini-live-check"),
    page.locator("#how"),
    page.getByRole("region", { name: "Verify the consequence, not a claim about it." }),
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
      window.scrollTo({ top: top - (viewportHeight * 0.42), behavior: "instant" });
    }, { top: flowTop, viewportHeight: viewport?.height ?? 800 });
  }
  const onchainStage = integration.getByRole("button", { name: /Onchain recourse/ });
  if ((viewport?.width ?? 0) <= 900) await onchainStage.click();
  await expect(onchainStage).toHaveAttribute("aria-pressed", "true");
  if ((viewport?.width ?? 0) > 900) {
    const hardenedProofTop = await page.getByRole("region", { name: "Verify the consequence, not a claim about it." })
      .evaluate((node) => node.getBoundingClientRect().top);
    expect(hardenedProofTop).toBeGreaterThan((viewport?.height ?? 800) * 0.82);
  }
  await expect(page.getByText(
    "In the separate hardened run, preconfigured demo policy opened the cure path and deployment configuration determined holders and payouts before settlement.",
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
  await expect(page.locator("main > section").last()).toContainText("Completed hardened proof");
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

test("the responsibility route stays attached to its signal in both directions", async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== "1280x800", "One deterministic desktop motion qualification is sufficient.");
  await page.goto("/");

  const integration = page.locator('[aria-label="Integration stages"]');
  const reveal = page.locator("[class*='flowRouteReveal']");
  const signal = page.locator("[class*='integrationSignal']");
  const expectedOffsets = [0.773, 0.648, 0.325, 0.012];
  const expectedColours = [
    "var(--receivable)",
    "var(--protection)",
    "var(--protection)",
    "var(--action)",
  ];

  for (let index = 0; index < expectedOffsets.length; index += 1) {
    const stage = integration.getByRole("button").nth(index);
    await stage.evaluate((button) => (button as HTMLButtonElement).focus({ preventScroll: true }));
    await expect(stage).toHaveAttribute("aria-pressed", "true");
    await expect(signal).toHaveAttribute("data-arrived", "true");
    await expect.poll(async () => Number(await reveal.getAttribute("stroke-dashoffset")))
      .toBeCloseTo(expectedOffsets[index], 2);
    await expect.poll(() => signal.evaluate((node) => (
      (node as SVGElement).style.getPropertyValue("--integration-signal-colour")
    ))).toBe(expectedColours[index]);

    const connection = await signal.evaluate((node) => {
      const path = document.querySelector<SVGPathElement>("[class*='flowMotionPath']");
      const reveal = document.querySelector<SVGPathElement>("[class*='flowRouteReveal']");
      const tether = node.querySelector<SVGLineElement>("[class*='integrationTether']");
      const signalMatrix = (node as SVGGElement).getScreenCTM();
      const pathMatrix = path?.getScreenCTM();
      const tetherMatrix = tether?.getScreenCTM();
      if (path === null || reveal === null || tether === null
        || signalMatrix === null || pathMatrix === null || tetherMatrix === null) return null;
      const progress = 1 - Number(reveal.getAttribute("stroke-dashoffset"));
      const routePoint = path.getPointAtLength(path.getTotalLength() * progress);
      const routeScreenPoint = new DOMPoint(routePoint.x, routePoint.y).matrixTransform(pathMatrix);
      const signalScreenPoint = new DOMPoint(0, 0).matrixTransform(signalMatrix);
      const tetherEnd = new DOMPoint(Number(tether.getAttribute("x2")), 0).matrixTransform(tetherMatrix);
      return {
        routeToSignal: Math.hypot(
          routeScreenPoint.x - signalScreenPoint.x,
          routeScreenPoint.y - signalScreenPoint.y,
        ),
        tetherToSignal: Math.hypot(
          tetherEnd.x - signalScreenPoint.x,
          tetherEnd.y - signalScreenPoint.y,
        ),
      };
    });
    expect(connection).not.toBeNull();
    expect(connection?.routeToSignal).toBeGreaterThanOrEqual(9);
    expect(connection?.routeToSignal).toBeLessThanOrEqual(13);
    expect(connection?.tetherToSignal).toBeLessThanOrEqual(3);
  }

  const earlierStage = integration.getByRole("button").nth(1);
  await earlierStage.evaluate((button) => (button as HTMLButtonElement).focus({ preventScroll: true }));
  await expect(earlierStage).toHaveAttribute("aria-pressed", "true");
  await expect(signal).toHaveAttribute("data-arrived", "true");
  // Reverse playback retracts in exact lockstep: the line may never reveal a
  // responsibility ahead of the travelling marker.
  await expect.poll(async () => Number(await reveal.getAttribute("stroke-dashoffset")))
    .toBeCloseTo(expectedOffsets[1], 2);
  await expect.poll(() => signal.evaluate((node) => (
    (node as SVGElement).style.getPropertyValue("--integration-signal-colour")
  ))).toBe("var(--protection)");
  const reverseRouteToSignal = await signal.evaluate((node) => {
    const path = document.querySelector<SVGPathElement>("[class*='flowMotionPath']");
    const reveal = document.querySelector<SVGPathElement>("[class*='flowRouteReveal']");
    const signalMatrix = (node as SVGGElement).getScreenCTM();
    const pathMatrix = path?.getScreenCTM();
    if (path === null || reveal === null || signalMatrix === null || pathMatrix === null) return null;
    const progress = 1 - Number(reveal.getAttribute("stroke-dashoffset"));
    const routePoint = path.getPointAtLength(path.getTotalLength() * progress);
    const routeScreenPoint = new DOMPoint(routePoint.x, routePoint.y).matrixTransform(pathMatrix);
    const signalScreenPoint = new DOMPoint(0, 0).matrixTransform(signalMatrix);
    return Math.hypot(
      routeScreenPoint.x - signalScreenPoint.x,
      routeScreenPoint.y - signalScreenPoint.y,
    );
  });
  expect(reverseRouteToSignal).not.toBeNull();
  expect(reverseRouteToSignal).toBeGreaterThanOrEqual(9);
  expect(reverseRouteToSignal).toBeLessThanOrEqual(13);
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

test("the shadow pilot route asks only for pilot-fit information and never fakes delivery", async ({ page }) => {
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
  await expectNoHorizontalOverflow(page);

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
  await expect(page.getByTestId("shell-live-cta")).toHaveAttribute("href", "/#product");

  // Old destinations must not reappear anywhere in the public chrome.
  for (const retired of ["/workspace", "/participant", "/protocol", "/design-system"]) {
    await expect(page.locator(`header a[href="${retired}"], footer a[href="${retired}"]`)).toHaveCount(0);
  }

  // The live product wears the same shell and marks itself as the current surface.
  await page.goto("/protection/live");
  await expect(page.getByRole("navigation", { name: "Product navigation" })).toBeVisible();
  await expect(page.getByTestId("shell-live-cta")).toHaveCount(0);
  await expect(page.getByRole("contentinfo").getByRole("link", { name: "Advanced live product" }))
    .toHaveAttribute("href", "/protection/live");
});
