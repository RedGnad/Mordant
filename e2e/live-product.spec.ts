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
    await expect(page.locator("header").filter({ hasText: "First workflow · Conflicting Pledge Protection" }))
      .toContainText("Monad testnet");

    // The one line that names all three Cleanverse boundaries.
    const body = page.locator("body");
    await expect(body).toContainText("Cleanverse verifies asset provenance and identity plus participant eligibility");
    await expect(body).toContainText("not legal validity or enforceability");
    await expect(body).toContainText("governed result establishes only that conflict status");
    await expect(body).toContainText("precommitted policy selects a bounded branch");
    const scope = page.locator("details").filter({ hasText: "What the live workflow establishes" });
    await expect(scope.locator("summary")).toBeVisible();
    await expect(scope).not.toHaveAttribute("open", "");
  });

  test("the journey is five chapters, not thirty runtime states", async ({ page }) => {
    await open(page, "conflict");
    const rail = page.getByRole("list", { name: "Live product chapters" });
    await expect(rail.locator("li")).toHaveCount(5);
    await expect(rail.locator('li[aria-current="step"]')).toHaveCount(1);
    await expect(page.getByTestId("live-status")).toContainText("Step 5 of 5");
  });

  test("both participants and the privacy reason are visible while authoring", async ({ page }) => {
    await open(page, "authorize");
    const body = page.locator("body");
    await expect(body).toContainText("Participant A");
    await expect(body).toContainText("Participant B");
    await expect(body).toContainText("does not require either lender to disclose its pledge window to the counterparty");
    await expect(body).toContainText("moves neither funds nor the receivable");
    await expect(page.getByTestId("claim-timeline")).toBeVisible();
    const scope = page.locator("details").filter({ hasText: "Privacy and execution scope" });
    await expect(scope).not.toHaveAttribute("open", "");
    await scope.locator("summary").click();
    await expect(page.getByTestId("intake-disclosure")).toBeVisible();
  });

  test("starting a managed check produces immediate, unmistakable feedback", async ({ page }) => {
    await open(page, "starting");
    const status = page.getByTestId("live-status");
    await expect(status).toHaveAttribute("data-status", "active");
    await expect(status).toContainText("Request received. Rechecking A-Pass before the secure execution opens.");
    const action = page.getByRole("button", { name: "Starting confidential check" });
    await expect(action).toHaveAttribute("aria-disabled", "true");
    await expect(action).toHaveAttribute("aria-busy", "true");
    await expect(action).toHaveAttribute("data-loading", "true");
    await expect(action.locator("[class*='buttonLoader']")).toBeVisible();
    await expect(page.getByTestId("managed-launch-feedback"))
      .toContainText("Request received. Rechecking A-Pass, then opening the secure execution.");
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
    await expect(page.getByTestId("claim-timeline")).toBeVisible();
    await expect(page.getByTestId("claim-timeline")).toHaveAttribute("data-reveal", "none");
    await expect(page.getByTestId("managed-private-inputs-unavailable")).toHaveCount(0);
    await expect(page.locator("body")).toContainText("Encrypted evaluation is complete");
    await expect(page.locator("body")).not.toContainText("Encrypted evaluation running");
    await expect(page.getByTestId("live-status")).toHaveAttribute("data-status", "active");
    await expect(page.getByTestId("execution-progress")).toContainText("secure stages observed");
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
    await expect(reveal).toContainText("establishes only that the private claim windows conflict");
    await expect(reveal).toContainText("remains outstanding and intact");
    await expect(reveal.getByTestId("claim-timeline")).toBeVisible();
    await expect(reveal.getByTestId("claim-timeline")).toHaveAttribute("data-reveal", "none");
    await expect(page.getByTestId("managed-private-inputs-unavailable")).toHaveCount(0);
    await expect(page.getByText("Governed result", { exact: true })).toHaveCount(0);
    await expect(page.getByText("Receipt sealed", { exact: true })).toHaveCount(0);

    const rail = page.getByTestId("decision-rail").first();
    await expect(rail).toContainText("Apply approved cure policy after conflict review");
    await expect(rail).toContainText("Action owner");
    await expect(rail).toContainText("Policy / human review required");
    await expect(rail).toContainText("configured consequence applies");
    await expect(rail).not.toContainText("The conflicting pledge holder");

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
    await expect(reveal).toContainText("precommitted policy selects record and close");
    await expect(reveal).toContainText("This is not a credit approval");
    await expect(reveal.getByTestId("claim-timeline")).toBeVisible();
    await expect(reveal.getByTestId("claim-timeline")).toHaveAttribute("data-reveal", "none");

    const rail = page.getByTestId("decision-rail").first();
    await expect(rail).toContainText("No recourse action is available");
    await expect(rail).toContainText("Configured policy opens no cure window");
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
  test("states the managed boundary and points to the separate completed recourse", async ({ page }) => {
    await open(page, "conflict");
    const panel = page.getByTestId("onchain-panel").first();
    await expect(panel).toHaveAttribute("data-connected", "false");
    await expect(panel).toContainText("ends after its policy-authorized local operation and sealed evidence");
    await expect(panel).toContainText("It did not execute a new aUSDC settlement");
    await expect(panel.getByRole("link", { name: "Verify the separate completed on-chain recourse" }))
      .toHaveAttribute("href", "/protection/verified-run");
    await expect(panel).not.toContainText("synthetic prototype readback");
    await expect(panel).not.toContainText("prepared and not yet wired");
    await expect(page.getByTestId("adapter-compatibility")).toHaveCount(0);
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
    const verification = drawer.locator("details").filter({ hasText: "Technical verification values" });
    await expect(verification).not.toHaveAttribute("open", "");
    const verificationHelp = verification.getByText(/You do not need to enter them anywhere\./u);
    await expect(verificationHelp).toBeHidden();
    await verification.locator("summary").click();
    await expect(verification).toHaveAttribute("open", "");
    await expect(verificationHelp).toBeVisible();
    await expect(verification).toContainText("Governed result digest");
    await expect(drawer).toContainText("Layer 3 · Raw evidence");
    await expect(drawer).toContainText("conflict/no-conflict between the submitted windows only");
    await expect(drawer).toContainText("precommitted policy selects the bounded branch");
    await expect(drawer.getByTestId("raw-receipt-context"))
      .toContainText("not an authorization for recourse or settlement by itself");
    await expect(drawer).not.toContainText("sole authority for the terminal outcome");

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

test.describe("participant admission, behind a disabled capability", () => {
  test("production never renders the two-wallet surface", async ({ page }) => {
    await open(page, "authorize");
    await expect(page.getByTestId("participant-admission")).toHaveCount(0);
    await expect(page.getByTestId("handoff")).toHaveCount(0);
    // The production disclosure is the managed one, and only that one.
    await expect(page.getByTestId("intake-disclosure"))
      .toContainText("submits both synthetic claim windows to Mordant's managed service");
    await expect(page.locator("body")).not.toContainText("independently authorize role-bound");
  });

  test("participant A sees only its own claim and one authorization", async ({ page }) => {
    await open(page, "admission-a");
    const surface = page.getByTestId("participant-admission");
    await expect(surface).toBeVisible();
    await expect(surface).toContainText("Authorize claim A");
    // The interval is this participant's own editable input, not a rendered
    // caption, so it is read as a field value. Asserting on the visible text
    // would silently pass against an empty form, since an input's value is not
    // part of innerText.
    await expect(surface.locator("#admission-A-from")).toHaveValue("120");
    await expect(surface.locator("#admission-A-until")).toHaveValue("420");
    // Participant B's interval is on this screen in neither form.
    await expect(surface).not.toContainText("520");
    for (const field of ["#admission-A-from", "#admission-A-until"]) {
      expect(await surface.locator(field).inputValue()).not.toBe("520");
    }
    await expect(page.getByRole("button", { name: /Authorize claim B/u })).toHaveCount(0);
  });

  test("the handoff is deliberate and never disconnects for you", async ({ page }) => {
    await open(page, "admission-handoff");
    const handoff = page.getByTestId("handoff");
    await expect(handoff).toBeVisible();
    await expect(handoff).toContainText("must use a different address");
    await expect(handoff).toContainText("Nothing is disconnected for you");
    await expect(handoff.getByRole("button", { name: "Continue as Participant B" })).toBeVisible();
  });

  test("the same address is visibly refused for the second role", async ({ page }) => {
    await open(page, "admission-same");
    const refusal = page.getByTestId("same-address-B");
    await expect(refusal).toBeVisible();
    // The refusal names the reason, not just the rule: a reader has to learn
    // that this wallet already holds the other role in this same case.
    await expect(refusal).toContainText("already holds the other role in this case");
    await expect(refusal).toContainText("must use a different address");
    await expect(page.getByRole("button", { name: /Authorize claim B/u })).toBeDisabled();
  });

  test("a distinct second wallet may authorize its own claim", async ({ page }) => {
    await open(page, "admission-b");
    await expect(page.getByTestId("same-address-B")).toHaveCount(0);
    await expect(page.getByRole("button", { name: /Authorize claim B/u })).toBeEnabled();
    await expect(page.getByTestId("admitted-A")).toBeVisible();
  });

  test("no claim about independent institutions is made", async ({ page }) => {
    for (const scenario of ["admission-a", "admission-handoff", "admission-b"]) {
      await open(page, scenario);
      const text = (await page.locator("body").innerText()).toLowerCase();
      for (const forbidden of [
        "independent institution",
        "two institutions",
        "device-side",
        "no server sees",
        "threshold release",
        "trustless",
      ]) {
        expect(text).not.toContain(forbidden);
      }
    }
  });
});
