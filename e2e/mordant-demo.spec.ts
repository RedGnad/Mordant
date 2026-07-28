import { expect, test } from "@playwright/test";

test("the demo proves bond payout and invoice redemption are independent", async ({ page }) => {
  await page.goto("/");

  await expect(page.getByRole("heading", { name: "The programmable recourse layer for tokenized receivables." })).toBeVisible();
  await expect(page.getByText("Prebuild · no address claimed")).toBeVisible();

  await page.getByRole("button", { name: "Show funding" }).click();
  await expect(page.getByRole("heading", { name: "$90 moves. $10 stays ready." })).toBeVisible();

  await page.getByRole("button", { name: "Show the second pledge" }).click();
  await expect(page.getByRole("heading", { name: "The same invoice is pledged again." })).toBeVisible();

  await page.getByRole("button", { name: "Show recourse activation" }).click();
  await expect(page.getByRole("heading", { name: "The holders inherit the reserve." })).toBeVisible();
  await expect(page.getByText("+$6 bond")).toBeVisible();
  await expect(page.getByText("+$4 bond")).toBeVisible();
  await expect(page.getByText("The holders still own all 100 invoice units and the full $110 claim.")).toBeVisible();

  await page.getByRole("button", { name: "Show settlement" }).click();
  await expect(page.getByRole("heading", { name: "$110 settles separately. The bond was extra." })).toBeVisible();
  await expect(page.getByText("+$6 + $66")).toBeVisible();
  await expect(page.getByText("+$4 + $44")).toBeVisible();
  await expect(page.getByText("Invoice repaid independently: $66 / $44 after the $6 / $4 protection payout.")).toBeVisible();

  await page.getByRole("button", { name: "Replay" }).click();
  await expect(page.getByRole("button", { name: "Show funding" })).toBeVisible();
});
