import { expect, test, type Page } from "@playwright/test";

/**
 * The live product, driven from deterministic fixtures.
 *
 * No BGV execution is started: the harness renders the presentation model, so
 * every terminal state, the disabled on-chain surface and the receipt can be
 * asserted at every viewport without spending the single execution slot.
 */

const HARNESS = "/design-lab/live?scenario=";

async function open(page: Page, scenario: string) {
  await page.goto(`${HARNESS}${scenario}`);
  await expect(page.getByTestId("harness-banner")).toBeVisible();
}

async function expectNoOverflow(page: Page) {
  const metrics = await page.evaluate(() => ({
    client: document.documentElement.clientWidth,
    scroll: document.documentElement.scrollWidth,
  }));
  expect(metrics.scroll).toBeLessThanOrEqual(metrics.client);
}

test.describe("the judge acceptance path", () => {
  test("the asset, the network and the division of responsibility are stated first", async ({ page }) => {
    await open(page, "conflict");
    await expect(page.getByRole("heading", { level: 1 })).toContainText("MINV01");
    await expect(page.locator("header").filter({ hasText: "Verified receivable" })).toContainText("Monad testnet");

    // The one line that names all three Cleanverse boundaries.
    const body = page.locator("body");
    await expect(body).toContainText("Cleanverse verifies the asset and who may participate");
    await expect(body).toContainText("Mordant privately decides whether the claims conflict");
    await expect(body).toContainText("opens or refuses recourse in aUSDC");
  });

  test("the journey is five chapters, not thirty runtime states", async ({ page }) => {
    await open(page, "conflict");
    const rail = page.getByRole("list", { name: "Live product chapters" });
    await expect(rail.locator("li")).toHaveCount(5);
    await expect(rail.locator('li[aria-current="step"]')).toHaveCount(1);
  });

  test("both participants and the privacy reason are visible while authoring", async ({ page }) => {
    await open(page, "authorize");
    const body = page.locator("body");
    await expect(body).toContainText("Participant A");
    await expect(body).toContainText("Participant B");
    await expect(body).toContainText("Neither will publish its book");
    await expect(body).toContainText("does not transfer funds");
  });

  test("A-Pass eligibility is named as the Cleanverse boundary it is", async ({ page }) => {
    await open(page, "eligibility");
    await expect(page.locator("body")).toContainText("Cleanverse holds the A-Pass policy on Monad testnet");
    await expect(page.locator("body")).toContainText("it does not claim you own it");
  });
});

test.describe("private decision", () => {
  test("no percentage is ever shown and no outcome leaks", async ({ page }) => {
    await open(page, "running");
    const text = await page.locator("body").innerText();
    expect(text).not.toMatch(/\d+\s?%/u);
    expect(text).not.toMatch(/conflict confirmed|no conflict/iu);
    await expect(page.locator("body")).toContainText("No result exists until the governed decryptor releases");
    await expect(page.getByTestId("reveal")).toHaveCount(0);
    await expect(page.getByTestId("decision-rail")).toHaveCount(0);
  });

  test("the detailed trace is disclosed, not displayed by default", async ({ page }) => {
    await open(page, "running");
    await expect(page.getByTestId("execution-trace")).toHaveCount(0);
    await page.getByRole("button", { name: /Show the execution trace/u }).click();
    await expect(page.getByTestId("execution-trace")).toBeVisible();
    await expect(page.getByTestId("execution-trace").locator('li[data-progress="active"]')).toHaveCount(1);
  });
});

test.describe("conflict reveal", () => {
  test("names the consequence, keeps the receivable intact and dates the deadline", async ({ page }) => {
    await open(page, "conflict");
    const reveal = page.getByTestId("reveal");
    await expect(reveal).toHaveAttribute("data-outcome", "conflict");
    await expect(reveal).toContainText("Conflict confirmed");
    await expect(reveal).toContainText("remains outstanding and intact");

    const rail = page.getByTestId("decision-rail").first();
    await expect(rail).toContainText("Cure the conflict before the deadline");
    await expect(rail).toContainText("Responsible now");
    await expect(rail).toContainText("becomes claimable");

    // The deadline is computed, never a retained historical date.
    const deadline = await page.getByTestId("deadline").first().innerText();
    expect(deadline).toMatch(/UTC/u);
    expect(deadline).not.toMatch(/30 Jul/u);
    expect(deadline).toMatch(/in about|in \d+ minutes/u);
  });
});

test.describe("no-conflict reveal", () => {
  test("is structurally distinct and never claims approval", async ({ page }) => {
    await open(page, "no-conflict");
    const reveal = page.getByTestId("reveal");
    await expect(reveal).toHaveAttribute("data-outcome", "cleared");
    await expect(reveal).toContainText("No conflict");
    await expect(reveal).toContainText("No reserve was assigned to this case");
    await expect(reveal).toContainText("This is not a credit approval");

    const rail = page.getByTestId("decision-rail").first();
    await expect(rail).toContainText("No recourse action is available");
    await expect(rail).toContainText("No cure window opens");
  });

  test("the two outcomes differ by more than a word", async ({ page }) => {
    await open(page, "conflict");
    const conflictRule = await page.getByTestId("reveal").evaluate((node) => getComputedStyle(node).borderTopColor);
    await open(page, "no-conflict");
    const clearedRule = await page.getByTestId("reveal").evaluate((node) => getComputedStyle(node).borderTopColor);
    expect(conflictRule).not.toBe(clearedRule);
  });
});

test.describe("settlement", () => {
  test("stays honestly disconnected under the production capability", async ({ page }) => {
    await open(page, "conflict");
    const panel = page.getByTestId("onchain-panel").first();
    await expect(panel).toHaveAttribute("data-connected", "false");
    await expect(panel).toContainText("not connected on this deployment");
    await expect(panel).toContainText("prepared and not yet wired");
  });

  test("the prepared entitlement surface renders real decimals when a capability supplies it", async ({ page }) => {
    await open(page, "onchain-entitlement-opened");
    const panel = page.getByTestId("onchain-panel").first();
    await expect(panel).toHaveAttribute("data-connected", "true");
    await expect(page.getByTestId("onchain-phase").first()).toContainText("Entitlement opened");
    // 6000000 atomic units is 6.00 aUSDC, never "6,000,000".
    await expect(panel).toContainText("6.00");
    await expect(panel).toContainText("4.00");
    await expect(panel).not.toContainText("6000000");
  });
});

test.describe("notices", () => {
  test("busy explains the single slot instead of discarding the page", async ({ page }) => {
    await open(page, "busy");
    await expect(page.locator("body")).toContainText("One execution slot is available");
    // The case context survives a notice.
    await expect(page.getByRole("heading", { level: 1 })).toContainText("MINV01");
  });

  test("unavailable keeps the run and offers a way forward", async ({ page }) => {
    await open(page, "unavailable");
    await expect(page.locator("body")).toContainText("did not answer");
    await expect(page.locator("body")).toContainText("still recorded");
  });
});

test.describe("receipt drawer", () => {
  test("is layered, opaque, focus-trapped and escapable", async ({ page }) => {
    await open(page, "conflict");
    const opener = page.getByRole("button", { name: /Open the full receipt|Open receipt/u }).first();
    await opener.click();

    const drawer = page.getByTestId("receipt-drawer");
    await expect(drawer).toBeVisible();
    await expect(drawer).toContainText("Layer 1 · Decision");
    await expect(drawer).toContainText("Layer 2 · Verification");
    await expect(drawer).toContainText("Layer 3 · Raw evidence");

    // Opaque: the previous drawer resolved to a transparent background and the
    // page showed through it on a phone.
    const background = await drawer.evaluate((node) => getComputedStyle(node).backgroundColor);
    expect(background).not.toBe("rgba(0, 0, 0, 0)");
    expect(background).not.toBe("transparent");

    expect(await page.evaluate(() => getComputedStyle(document.body).overflow)).toBe("hidden");
    expect(await page.evaluate(() => document.activeElement?.closest('[data-testid="receipt-drawer"]') !== null)).toBe(true);

    for (let index = 0; index < 10; index += 1) {
      await page.keyboard.press("Tab");
      expect(await page.evaluate(() => document.activeElement?.closest('[data-testid="receipt-drawer"]') !== null)).toBe(true);
    }

    await page.keyboard.press("Escape");
    await expect(drawer).toHaveCount(0);
    await expect(opener).toBeFocused();
  });

  test("raw evidence is the third layer, disclosed on request", async ({ page }) => {
    await open(page, "conflict");
    await page.getByRole("button", { name: /Open the full receipt|Open receipt/u }).first().click();
    const disclose = page.getByRole("button", { name: /Show the verified projection/u });
    await expect(disclose).toHaveAttribute("aria-expanded", "false");
    await disclose.click();
    await expect(page.getByRole("button", { name: /Hide the verified projection/u })).toHaveAttribute("aria-expanded", "true");
  });
});

test.describe("layout and motion", () => {
  for (const scenario of ["eligibility", "authorize", "running", "conflict", "no-conflict"]) {
    test(`${scenario} fits the viewport`, async ({ page }) => {
      await open(page, scenario);
      await expectNoOverflow(page);
    });
  }

  test("the receipt drawer fits the viewport too", async ({ page }) => {
    await open(page, "conflict");
    await page.getByRole("button", { name: /Open the full receipt|Open receipt/u }).first().click();
    await expect(page.getByTestId("receipt-drawer")).toBeVisible();
    await expectNoOverflow(page);
  });

  test("reduced motion removes transitions from the product", async ({ page }) => {
    await page.emulateMedia({ reducedMotion: "reduce" });
    await open(page, "conflict");
    const moving = await page.evaluate(() => Array.from(document.querySelectorAll("main *"))
      .map((node) => ({
        cls: String(node.className).slice(0, 40),
        transition: getComputedStyle(node).transitionDuration,
        animation: getComputedStyle(node).animationDuration,
      }))
      .filter((entry) => {
        const seconds = (value: string) => value.split(",").some((part) => {
          const trimmed = part.trim();
          return trimmed.endsWith("s") && Number.parseFloat(trimmed) > 0.01;
        });
        return seconds(entry.transition) || seconds(entry.animation);
      }));
    expect(moving).toEqual([]);
  });

  test("every control meets the touch target", async ({ page }) => {
    await open(page, "conflict");
    const small = await page.evaluate(() => Array.from(document.querySelectorAll("main button, main a"))
      .map((node) => ({ text: (node.textContent ?? "").trim().slice(0, 24), height: node.getBoundingClientRect().height }))
      .filter((entry) => entry.height > 0 && entry.height < 44));
    expect(small).toEqual([]);
  });
});
