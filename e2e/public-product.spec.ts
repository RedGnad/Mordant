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
    name: "Conflict becomes recourse.",
  })).toBeVisible();
  await expect(page.getByText("Mordant establishes responsibility, deadline, consequence, and proof.", { exact: true })).toBeVisible();
  await expect(page.getByRole("link", { name: "See the transformation" })).toHaveAttribute("href", "#product");
  await expect(page.getByRole("link", { name: "Evaluate the integration" })).toHaveAttribute("href", "#integrate");

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
  await expect(participant).toHaveAttribute("data-deal-id", identity.deal ?? "");
  await expect(participant).toHaveAttribute("data-vault", identity.vault ?? "");
  await expect(participant).toHaveAttribute("data-invoice-root", identity.root ?? "");

  await page.getByRole("link", { name: "Protocol", exact: true }).click();
  await expect(page).toHaveURL(/\/demo\?perspective=protocol&checkpoint=reveal$/u);
  const protocol = page.getByTestId("living-experience");
  await expect(protocol).toHaveAttribute("data-surface", "protocol");
  await expect(page.getByText("Last confirmed transition", { exact: true })).toBeVisible();
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
