import { expect, test, type Locator, type Page } from "@playwright/test";

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

async function relativeBounds(control: Locator) {
  return control.evaluate((element) => {
    const container = element.parentElement;
    if (container === null) throw new Error("The transformation control lost its stable container.");
    const bounds = element.getBoundingClientRect();
    const containerBounds = container.getBoundingClientRect();
    return {
      x: bounds.x - containerBounds.x,
      y: bounds.y - containerBounds.y,
      width: bounds.width,
      height: bounds.height,
    };
  });
}

test("the public story stays specific and its causal control does not move", async ({ page }) => {
  await page.goto("/");

  await expect(page.getByRole("heading", {
    name: "Tokenized assets automate ownership. Mordant automates recourse.",
  })).toBeVisible();
  await expect(page.getByText("Turn confirmed conflicts into clear responsibility", { exact: false })).toBeVisible();
  await expect(page.getByRole("link", { name: "See Mordant resolve a conflict" })).toHaveAttribute("href", "/demo");

  const renderedText = await page.locator("body").innerText();
  expect(renderedText).not.toMatch(/\b0[1-5]\s*[·/]\s*/u);
  expect(renderedText).not.toContain("Continue");

  const actions = [
    "Introduce a conflicting claim",
    "Assign responsibility",
    "Establish the deadline",
    "Retain the proof",
    "Start again",
  ] as const;
  let anchor: { x: number; y: number; width: number; height: number } | null = null;
  const transformation = page.locator('[aria-live="polite"]');
  await transformation.scrollIntoViewIfNeeded();

  for (const [index, label] of actions.entries()) {
    const control = transformation.getByRole("button", { name: label });
    await expect(control).toBeVisible();
    const bounds = await relativeBounds(control);

    if (anchor === null) {
      anchor = bounds;
    } else {
      expect(Math.abs(bounds.x - anchor.x)).toBeLessThanOrEqual(1);
      expect(Math.abs(bounds.y - anchor.y)).toBeLessThanOrEqual(1);
      expect(Math.abs(bounds.width - anchor.width)).toBeLessThanOrEqual(1);
      expect(Math.abs(bounds.height - anchor.height)).toBeLessThanOrEqual(1);
    }

    const nextAction = actions[index + 1];
    if (nextAction !== undefined) {
      await control.click();
      await expect(transformation.getByRole("button", { name: nextAction })).toBeVisible();
    }
  }

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

  await page.getByRole("button", { name: "Open receipt proof" }).click();
  await expect(page.getByTestId("living-proof")).toBeVisible();
  await expect(page.getByTestId("living-experience")).toHaveCount(0);
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
