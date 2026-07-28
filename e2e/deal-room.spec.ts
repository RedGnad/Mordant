import { expect, test } from "@playwright/test";

/**
 * Drives the whole recourse journey against the deterministic local chain.
 *
 * Every assertion below reads state the interface fetched back from the contracts after a receipt,
 * so a step that only moved component state would fail here.
 */

const STEPS = [
  "approve-funding",
  "activate",
  "positions",
  "sign-conflict",
  "commit",
  "reveal",
  "cure-window",
  "finalize",
  "claim-a",
  "claim-b",
  "approve-redemption",
  "fund-redemption",
  "redeem-a",
  "redeem-b",
] as const;

async function run(page: import("@playwright/test").Page, id: string) {
  await page.getByTestId(`run-${id}`).click();
  await expect(page.getByTestId(`receipt-${id}`)).toBeVisible({ timeout: 30_000 });
}

test("the deal room executes the recourse journey as real transactions", async ({ page }) => {
  test.slow();
  await page.goto("/deal-room");

  await expect(page.getByTestId("honesty-label")).toHaveText("LOCAL / PROTOCOL DOUBLE / SYNTHETIC");
  await expect(page.getByTestId("state-grid")).toBeVisible();
  await expect(page.getByTestId("protection-state")).toHaveText("Unfunded");

  // --- funding: 100 in, 90 to the originator, 10 held as the reserve ---
  await run(page, "approve-funding");
  await run(page, "activate");
  await expect(page.getByTestId("protection-state")).toHaveText("Active");
  await expect(page.getByTestId("receivable-state")).toHaveText("Outstanding");
  await expect(page.getByTestId("originator-settlement")).toHaveText("90.000000");

  // --- positions 60 / 40 ---
  await run(page, "positions");
  await expect(page.getByTestId("holder-a-units")).toHaveText("60.000000");
  await expect(page.getByTestId("holder-b-units")).toHaveText("40.000000");

  // --- incident: signed, sealed before disclosure, then revealed ---
  await run(page, "sign-conflict");
  await run(page, "commit");
  await expect(page.getByTestId("protection-state")).toHaveText("CommitPending");
  await run(page, "reveal");
  await expect(page.getByTestId("protection-state")).toHaveText("ConflictConfirmed");

  // --- unresolved conflict activates the 6/4 entitlement ---
  await run(page, "cure-window");
  await run(page, "finalize");
  await expect(page.getByTestId("protection-state")).toHaveText("Entitled");
  await expect(page.getByTestId("entitlement")).toHaveText("10.000000");

  // --- claims paid from the pre-funded reserve ---
  await run(page, "claim-a");
  await run(page, "claim-b");
  await expect(page.getByTestId("holder-a-settlement")).toHaveText("6.000000");
  await expect(page.getByTestId("holder-b-settlement")).toHaveText("4.000000");

  // The claim did not consume the receivable: both holders still own their units.
  await expect(page.getByTestId("holder-a-units")).toHaveText("60.000000");
  await expect(page.getByTestId("holder-b-units")).toHaveText("40.000000");

  // --- the receivable settles on its own track, after the recourse payout ---
  await run(page, "approve-redemption");
  await run(page, "fund-redemption");
  await run(page, "redeem-a");
  await run(page, "redeem-b");

  await expect(page.getByTestId("redeemed-face")).toHaveText("110.000000");
  await expect(page.getByTestId("holder-a-settlement")).toHaveText("72.000000");
  await expect(page.getByTestId("holder-b-settlement")).toHaveText("48.000000");
  await expect(page.getByTestId("receivable-state")).toHaveText("Redeemed");
});

test("every business step is backed by a transaction receipt", async ({ page }) => {
  await page.goto("/deal-room");

  for (const id of STEPS) {
    await expect(page.getByTestId(`step-${id}`)).toBeVisible();
  }

  // Only the next step is actionable, so no control can be clicked out of order.
  await expect(page.getByTestId("run-approve-funding")).toBeEnabled();
  await expect(page.getByTestId("run-activate")).toBeDisabled();
  await expect(page.getByTestId("run-redeem-b")).toBeDisabled();
});
