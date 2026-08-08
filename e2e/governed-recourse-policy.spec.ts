import { expect, test } from "@playwright/test";

test.beforeEach(async ({ request }) => {
  const response = await request.post("/api/design-lab/governed-recourse-policy", { data: { action: "reset" } });
  expect(response.ok()).toBe(true);
});

test("one conflict fact follows each pre-bound policy into verifiable evidence", async ({ page }) => {
  await page.goto("/design-lab/governed-recourse-policy");
  await expect(page.getByText("EXPERIMENTAL · OFF-CHAIN · NO SETTLEMENT")).toBeVisible();
  await expect(page.getByTestId("case-state")).toHaveText("CASE AUTHORIZED");
  await expect(page.getByRole("button", { name: "Approve this exact action" })).toHaveCount(0);

  await page.getByRole("button", { name: "Bind policy before result" }).click();
  await expect(page.getByTestId("case-state")).toHaveText("POLICY BOUND");
  await page.getByRole("button", { name: "Expose verified governed result" }).click();
  await expect(page.getByTestId("selection-before-result")).toHaveText("YES");
  await expect(page.getByTestId("governed-outcome")).toHaveText("CONFLICT");
  await page.getByRole("button", { name: "Evaluate bound policy" }).click();
  await expect(page.getByTestId("case-state")).toHaveText("REVIEW REQUIRED");
  await expect(page.getByTestId("proposed-action")).toHaveText("OPEN CURE PATH");
  await page.getByRole("button", { name: "Approve this exact action" }).click();
  await expect(page.getByTestId("case-state")).toHaveText("REVIEW APPROVED");
  await page.getByRole("button", { name: "Authorize governed action" }).click();
  await page.getByRole("button", { name: "Record evidence-only action" }).click();
  await expect(page.getByTestId("case-state")).toHaveText("ACTION RECORDED");
  await expect(page.getByTestId("receipt-status")).toHaveText("INDEPENDENTLY VERIFIABLE");

  await page.getByRole("button", { name: "Start a new isolated run" }).click();
  await page.getByLabel("Choose one of exactly two immutable policy fixtures").selectOption("mordant.experimental.manual-escalation");
  await page.getByRole("button", { name: "Bind policy before result" }).click();
  await page.getByRole("button", { name: "Expose verified governed result" }).click();
  await page.getByRole("button", { name: "Evaluate bound policy" }).click();
  await expect(page.getByTestId("selection-before-result")).toHaveText("YES");
  await expect(page.getByTestId("governed-outcome")).toHaveText("CONFLICT");
  await expect(page.getByTestId("proposed-action")).toHaveText("MANUAL ESCALATION");
});

test("experimental surface remains readable at a narrow viewport", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/design-lab/governed-recourse-policy");
  await expect(page.getByRole("heading", { name: "A governed fact can authorize an operational path." })).toBeVisible();
  await expect(page.getByRole("button", { name: "Bind policy before result" })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
});
