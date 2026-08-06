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

test("the public story stays specific and its causal control does not move", async ({ page }) => {
  await page.goto("/");

  await expect(page.getByRole("heading", {
    name: "Conflict became recourse.",
  })).toBeVisible();
  await expect(page.getByText(
    "When private claims collide, Mordant keeps tokenized credit moving.",
    { exact: true },
  )).toBeVisible();

  // The canonical primary action is the live product, in the shell and in the hero.
  await expect(page.getByTestId("shell-live-cta")).toHaveAttribute("href", "/protection/live");
  await expect(page.getByRole("main").getByRole("link", { name: "Run the live check" }).first())
    .toHaveAttribute("href", "/protection/live");
  // Evidence is the secondary proof path and resolves to the protection surface.
  await expect(page.getByRole("navigation", { name: "Product navigation" })
    .getByRole("link", { name: "Evidence" })).toHaveAttribute("href", "/protection?scenario=conflict");
  await expect(page.getByRole("main").getByRole("link", { name: "Inspect verified evidence" }).first())
    .toHaveAttribute("href", "/protection?scenario=conflict");

  // Every material limitation stays on the page, below the value explanation.
  const boundaries = page.locator("#boundaries");
  await expect(boundaries).toContainText("managed execution service prepares and encrypts the inputs");
  await expect(boundaries).toContainText("ciphertexts and holds no decryption key");
  await expect(boundaries).toContainText("not native Monad FHE, threshold release or trustless decryption");
  await expect(boundaries).toContainText("no funds move");

  // The recorded receipt names the chain that produced it, so it can never be
  // mistaken for the live encrypted check.
  await expect(page.getByRole("region", { name: /verifiable transition/iu })).toContainText("Anvil");

  // A landing must not carry a fixed historical deadline.
  expect(await page.locator("body").innerText()).not.toMatch(/\b30 Jul\b/u);

  const renderedText = await page.locator("body").innerText();
  expect(renderedText).not.toMatch(/\b0[1-5]\s*[·/]\s*/u);
  expect(renderedText).not.toContain("Continue");

  const states = [
    "Stable",
    "Conflict",
    "Recourse",
    "Proof",
  ] as const;
  let anchor: { x: number; y: number; width: number; height: number } | null = null;
  const transformation = page.getByRole("navigation", { name: "Transformation states" });
  await transformation.scrollIntoViewIfNeeded();

  for (const label of states) {
    const control = transformation.getByRole("button", { name: label });
    await expect(control).toBeVisible();
    const bounds = await control.evaluate((element) => {
      const bounds = element.getBoundingClientRect();
      return { x: bounds.x, y: bounds.y, width: bounds.width, height: bounds.height };
    });

    if (anchor === null) {
      anchor = bounds;
    } else {
      expect(Math.abs(bounds.y - anchor.y)).toBeLessThanOrEqual(1);
      expect(Math.abs(bounds.width - anchor.width)).toBeLessThanOrEqual(1);
      expect(Math.abs(bounds.height - anchor.height)).toBeLessThanOrEqual(1);
    }
  }

  await transformation.getByRole("button", { name: "Conflict" }).click();
  await expect(transformation.getByRole("button", { name: "Conflict" })).toHaveAttribute("aria-pressed", "true");
  await transformation.getByRole("button", { name: "Proof" }).click();
  await expect(transformation.getByRole("button", { name: "Proof" })).toHaveAttribute("aria-pressed", "true");

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

test("the public shell exposes one hierarchy and one primary action", async ({ page }) => {
  await page.goto("/");

  const navigation = page.getByRole("navigation", { name: "Product navigation" });
  // Destinations and their order are the contract. The visible wording is
  // deliberately shorter on a phone, so it is not what this test pins.
  const hrefs = await navigation.getByRole("link").evaluateAll(
    (links) => links.map((link) => link.getAttribute("href")),
  );
  expect(hrefs).toEqual(["/#product", "/#how", "/protection?scenario=conflict", "/pilot"]);

  // Every destination must still announce a name at this viewport, so a short
  // label can never become an empty one.
  for (const name of await navigation.getByRole("link").allInnerTexts()) {
    expect(name.trim().length).toBeGreaterThan(0);
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
  await expect(page.getByRole("contentinfo").getByRole("link", { name: "Run the live check" }))
    .toHaveAttribute("href", "/protection/live");
});
