import { expect, test, type Page } from "@playwright/test";

/**
 * M-EX2 drives one retained execution through the actual product routes. Every
 * business transition below is accepted only after the API has retained its
 * receipt and block-pinned after-state.
 */

const SOURCE = "Executed on controlled demo chain";

async function reset(page: Page) {
  const response = await page.request.post("/api/dealroom/living-demo", {
    data: { intent: "reset" },
  });
  expect(response.ok()).toBe(true);
  return response.json() as Promise<{
    deal: { id: string; invoiceRoot: string; vault: string };
  }>;
}

async function execute(page: Page, current: string, next?: string) {
  const control = page.getByTestId("living-run-next");
  await expect(control).toHaveAttribute("data-action-id", current);
  await control.click();
  if (next === undefined) {
    await expect(control).toBeDisabled({ timeout: 15_000 });
    await expect(control).not.toHaveAttribute("data-action-id", /.+/);
  } else {
    await expect(control).toHaveAttribute("data-action-id", next, { timeout: 15_000 });
  }
}

async function identity(page: Page) {
  const experience = page.getByTestId("living-experience");
  await expect(experience).toBeVisible();
  return {
    deal: await experience.getAttribute("data-deal-id"),
    root: await experience.getAttribute("data-invoice-root"),
    vault: await experience.getAttribute("data-vault"),
    source: await experience.getAttribute("data-source"),
  };
}

test("one canonical receipt-driven deal stays truthful across all three product perspectives", async ({ page }) => {
  test.slow();
  const clean = await reset(page);
  await page.goto("/?demo=transactions");

  await expect(page.getByTestId("living-source")).toHaveText(SOURCE);
  await expect(page.getByTestId("living-conclusion")).toHaveText("This receivable is ready for funding.");
  const canonicalIdentity = await identity(page);
  expect(canonicalIdentity).toEqual({
    deal: clean.deal.id,
    root: clean.deal.invoiceRoot,
    vault: clean.deal.vault,
    source: "controlled-demo-chain",
  });

  const firstControl = page.getByTestId("living-run-next");
  await expect(firstControl).toHaveAttribute("data-action-id", "approve-funding");
  await firstControl.click();
  await expect(page.getByTestId("living-pending")).toContainText("Pending", { timeout: 4_000 });
  await expect(page.getByTestId("living-pending")).toContainText("0x");
  await expect(firstControl).toHaveAttribute("data-action-id", "activate", { timeout: 15_000 });

  await execute(page, "activate", "positions");
  await expect(page.getByTestId("living-conclusion")).toHaveText("No exception is open.");
  await execute(page, "positions", "sign-conflict");
  await execute(page, "sign-conflict", "commit");
  await execute(page, "commit", "reveal");
  await execute(page, "reveal", "cure-window");

  await expect(page.getByTestId("living-conclusion")).toHaveText(
    "Facility B revealed a conflicting pledge.",
  );
  await expect(page.getByTestId("living-receivable-anchor")).toContainText("Outstanding");

  await page.getByRole("button", { name: "Open receipt proof" }).click();
  await expect(page.getByTestId("living-proof")).toBeVisible();
  await expect(page.getByTestId("living-experience")).toHaveCount(0);
  await expect(page.getByTestId("living-technical-proof")).not.toHaveAttribute("open", "");
  await expect(page.getByTestId("living-proof")).toContainText("Before · block");
  await expect(page.getByTestId("living-proof")).toContainText("After · block");
  await expect(page.getByTestId("living-proof")).toContainText("Observed events");
  await page.keyboard.press("Escape");
  await expect(page.getByRole("button", { name: "Open receipt proof" })).toBeFocused();

  await page.getByRole("link", { name: "Participant" }).click();
  await expect(page).toHaveURL(/\/deal-room\?demo=transactions$/);
  await expect(page.getByTestId("living-conclusion")).toHaveText("Nothing you need to do.");
  await expect(identity(page)).resolves.toEqual(canonicalIdentity);

  await page.getByRole("link", { name: "Protocol" }).click();
  await expect(page).toHaveURL(/\/protocol\?demo=transactions$/);
  await expect(page.getByTestId("living-conclusion")).toContainText(
    "Facility B revealed a conflicting pledge.",
  );
  await expect(page.getByTestId("living-experience")).toContainText("Last safe block");
  await expect(identity(page)).resolves.toEqual(canonicalIdentity);

  await page.getByRole("link", { name: "Participant" }).click();
  await execute(page, "cure-window", "finalize");
  await execute(page, "finalize", "claim-a");
  await expect(page.getByTestId("living-conclusion")).toHaveText(
    "6.00 dSETTLE is ready for you to claim.",
  );
  await expect(page.getByTestId("living-receivable-anchor")).toContainText("60.00 units remain yours");

  await execute(page, "claim-a", "claim-b");
  await expect(page.getByTestId("living-conclusion")).toHaveText("Your protection was paid.");
  await expect(page.getByTestId("living-receivable-anchor")).toContainText("60.00 units remain yours");

  await execute(page, "claim-b", "approve-redemption");
  await execute(page, "approve-redemption", "fund-redemption");
  await execute(page, "fund-redemption", "redeem-a");
  await execute(page, "redeem-a", "redeem-b");
  await execute(page, "redeem-b");

  await expect(page.getByTestId("living-conclusion")).toHaveText("Your invoice position has been paid.");
  await expect(page.getByTestId("living-experience")).toContainText("72.00 dSETTLE received across both domains.");

  page.once("dialog", (dialog) => dialog.accept());
  await page.getByRole("button", { name: "Reset canonical run" }).click();
  await expect(page.getByTestId("living-run-next")).toHaveAttribute("data-action-id", "approve-funding");
  await expect(page.getByTestId("living-conclusion")).toHaveText("Your position is unchanged.");
  await expect(identity(page)).resolves.toEqual(canonicalIdentity);
});

test("the execution API refuses discontinuous actions without changing contract-derived state", async ({ page }) => {
  const clean = await reset(page);
  const refused = await page.request.post("/api/dealroom/living-demo", {
    data: { intent: "execute", actionId: "activate" },
  });
  expect(refused.status()).toBe(409);
  await expect(refused.json()).resolves.toMatchObject({ error: "Expected approve-funding; received activate." });

  const read = await page.request.get("/api/dealroom/living-demo");
  const run = await read.json() as {
    deal: { id: string; invoiceRoot: string; vault: string };
    actions: unknown[];
    current: { blockNumber: string; protectionState: number; receivableState: number };
    nextAction: { id: string };
  };
  expect(run.deal).toEqual(clean.deal);
  expect(run.actions).toHaveLength(0);
  expect(run.nextAction.id).toBe("approve-funding");
  expect(run.current).toMatchObject({ protectionState: 0, receivableState: 0 });
});
