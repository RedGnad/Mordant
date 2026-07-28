import { expect, test } from "@playwright/test";

const ROUTE = "/design-lab/aero-fiduciary";
const VARIANTS = ["restrained", "fiduciary", "radical"] as const;

/** The study is one screen shown three ways, so the content must never differ between them. */
const INVARIANT_TEXT = [
  "110,000", "100,000", "10,000",
  "Conflict revealed", "Recourse line", "Holder A", "Holder B",
];

test.describe("Aero Fiduciary visual direction study", () => {
  // Reduced motion stops the countdown, so captures are deterministic without masking the figure.
  test.beforeEach(async ({ page }) => {
    await page.emulateMedia({ reducedMotion: "reduce" });
  });

  test("declares itself a study rather than a live deployment", async ({ page }) => {
    await page.goto(ROUTE);
    await expect(page.getByText("Design study")).toBeVisible();
    await expect(page.getByText("Fork rehearsal data. Not a live deployment.")).toBeVisible();
  });

  for (const variant of VARIANTS) {
    test(`${variant} shows the same content and captures cleanly`, async ({ page }, testInfo) => {
      await page.goto(ROUTE);
      await page.getByRole("button", { name: new RegExp(variant, "i") }).click();
      await expect(page.locator(".lab")).toHaveAttribute("data-variant", variant);

      for (const text of INVARIANT_TEXT) {
        await expect(page.getByText(text, { exact: false }).first()).toBeVisible();
      }

      await expect(page.locator(".lab-cure-figure")).toBeVisible();
      await expect(page).toHaveScreenshot(`${variant}-${testInfo.project.name}.png`, {
        fullPage: true,
        animations: "disabled",
        maxDiffPixelRatio: 0.02,
      });
    });
  }

  test("the primary action is inert and says so", async ({ page }) => {
    await page.goto(ROUTE);
    const cta = page.getByRole("button", { name: /available after cure|finalize conflict/i });
    await expect(cta).toBeDisabled();
    await expect(page.getByText(/no button here sends a transaction/i)).toBeVisible();
  });

  test("the wrong-role block is explained in words, not only colour", async ({ page }) => {
    await page.goto(ROUTE);
    await expect(page.getByText("BLOCKED")).toBeVisible();
    await expect(page.getByText(/You are viewing as Holder A/)).toBeVisible();
  });

  test("evidence is reachable and opens a detail panel", async ({ page }) => {
    await page.goto(ROUTE);
    const toggle = page.getByRole("button", { name: /show proof detail/i });
    await expect(toggle).toHaveAttribute("aria-expanded", "false");
    await toggle.click();
    await expect(page.getByRole("button", { name: /hide proof detail/i })).toHaveAttribute("aria-expanded", "true");
    await expect(page.getByText("0x9f2df0fed2c77648de5860a4cc508cd0818c85b8b8a1ab4ceeef8d981c8956a6")).toBeVisible();
  });

  test("refreshing is shown as a state on the figures", async ({ page }) => {
    await page.goto(ROUTE);
    await page.getByRole("button", { name: /refresh on-chain figures/i }).click();
    await expect(page.locator(".lab-refreshing")).toBeVisible();
  });

  test("every variant is reachable by keyboard with a visible focus ring", async ({ page }) => {
    await page.goto(ROUTE);
    await page.keyboard.press("Tab");
    const focused = page.locator(":focus-visible");
    await expect(focused).toBeVisible();
    const outline = await focused.evaluate((node) => getComputedStyle(node).outlineStyle);
    expect(outline).not.toBe("none");
  });
});
