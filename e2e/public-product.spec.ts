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
  await page.evaluate(() => window.scrollTo({ top: 0, behavior: "instant" }));
  // On the landing, both primary entry points move to its one real experiment.
  await expect(page.getByTestId("shell-live-cta")).toHaveAttribute("href", "/#product");
  await expect(page.getByRole("main").getByRole("link", { name: "Run the live check" }).first())
    .toHaveAttribute("href", "#product");
  await expect(page.getByRole("navigation", { name: "Product navigation" })
    .getByRole("link", { name: "Evidence" })).toHaveAttribute("href", "/protection?scenario=conflict");
  await expect(page.getByRole("main").getByRole("link", { name: "Inspect verified evidence" }).first())
    .toHaveAttribute("href", "/protection?scenario=conflict");

  await expect(page.getByTestId("mini-live-check")).toBeVisible();
  await expect(page.getByTestId("mini-live-check")).toContainText("synthetic financing-claim windows");
  await expect(page.getByTestId("mini-live-check")).toContainText("real encrypted evaluation");
  const miniPanel = page.getByTestId("mini-live-check").locator("[class*='panel']");
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
    const maximumAlpha = viewportWidth <= 640 ? 0.65 : viewportWidth <= 900 ? 0.57 : 0.43;
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
  await expect(page.getByRole("region", { name: "Verify the consequence, not a claim about it." })).toBeVisible();
  await expect(page.getByTestId("landing-to-verified-run"))
    .toHaveAttribute("href", "/protection/verified-run");

  const integration = page.locator('[aria-label="Integration stages"]');
  await page.locator("#how").scrollIntoViewIfNeeded();
  await expect(page.locator("#how")).toHaveAttribute("data-visible", "true");
  const monadStage = integration.getByRole("button", { name: /Monad recourse/ });
  await monadStage.click();
  await expect(monadStage).toHaveAttribute("aria-pressed", "true");
  await expect(page.getByText(
    "In the separate hardened run, preconfigured demo policy opened the cure path and deployment configuration determined holders and payouts before settlement.",
    { exact: true },
  )).toBeVisible();

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
  expect(hrefs).toEqual(["/#how", "/protection?scenario=conflict", "/pilot"]);

  // Every destination must still announce a name at this viewport, so a short
  // label can never become an empty one.
  for (const name of await navigation.getByRole("link").allInnerTexts()) {
    expect(name.trim().length).toBeGreaterThan(0);
  }

  if (!testInfo.project.use.hasTouch) {
    const how = navigation.getByRole("link", { name: "How it works" });
    const label = how.locator("[class*='tabLabel']");
    const beforeBox = await how.boundingBox();
    const headerHeight = await page.getByRole("banner").evaluate((node) => node.getBoundingClientRect().height);
    const restingTongue = await how.evaluate((node) => {
      const style = getComputedStyle(node, "::before");
      return {
        bottom: Number.parseFloat(style.bottom),
        height: Number.parseFloat(style.height),
        opacity: Number(style.opacity),
        top: Number.parseFloat(style.top),
      };
    });
    expect(restingTongue.opacity).toBeGreaterThanOrEqual(0.99);
    const restingReferenceHeight = (page.viewportSize()?.width ?? 0) > 1023
      ? headerHeight
      : (beforeBox?.height ?? headerHeight);
    expect(restingTongue.height).toBeGreaterThanOrEqual(restingReferenceHeight);
    expect(restingTongue.top).toBeLessThanOrEqual(-0.9);
    expect(restingTongue.bottom).toBeLessThanOrEqual(-0.9);

    await how.hover();
    await expect.poll(() => label.evaluate((node) => new DOMMatrix(getComputedStyle(node).transform).m42))
      .toBeGreaterThanOrEqual(11.5);
    await expect.poll(() => how.evaluate((node) => Number.parseFloat(getComputedStyle(node, "::before").height)))
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
    await expect.poll(() => how.evaluate((node) => Number.parseFloat(getComputedStyle(node, "::before").height)))
      .toBeLessThanOrEqual(restingTongue.height + 0.1);

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
