import { expect, test, type Page } from "@playwright/test";

const surfaces = [
  { path: "/", heading: "Intervention queue" },
  { path: "/deal-room", heading: /Your receivable has not moved/i },
  { path: "/protocol", heading: "Event and recovery rail" },
] as const;

const thirdPartyKycDetail =
  /issuingCountryISO2|identityDataList|(?:passport (?:number|no\.?|id)|date of birth|birth date|nationality|issuing country|credential id)\s*(?::|#|–|—)\s*[a-z0-9]/i;

async function expectNoThirdPartyKycDetail(page: Page) {
  const renderedText = await page.locator("body").innerText();
  expect(renderedText).not.toMatch(thirdPartyKycDetail);
}

test.describe("Mordant role-aware product surfaces", () => {
  test("each role receives its own compact navigation and current location", async ({ page }) => {
    const cases = [
      {
        path: "/",
        navigation: "Originator navigation",
        links: ["Workspace", "Portfolio", "Evidence"],
        current: "Workspace",
      },
      {
        path: "/deal-room",
        navigation: "Holder navigation",
        links: ["← Portfolio", "Deal room", "Evidence"],
        current: "Deal room",
      },
      {
        path: "/protocol",
        navigation: "Protocol operator navigation",
        links: ["← Workspace", "Events", "Diagnostics", "Recovery"],
        current: "Diagnostics",
      },
    ] as const;

    for (const item of cases) {
      await page.goto(item.path);

      const navigation = page.getByRole("navigation", { name: item.navigation });
      await expect(navigation).toBeVisible();
      // Protocol intentionally hides secondary anchors on narrow viewports, but
      // the role contract and link order remain present in the navigation DOM.
      await expect(navigation.locator("a")).toHaveText([...item.links]);
      await expect(navigation.getByRole("link", { name: item.current, exact: true })).toHaveAttribute(
        "aria-current",
        "page",
      );

      const session = page.getByLabel("Session context");
      await expect(session).toContainText(/Monad testnet · 10143/i);
      if (item.path === "/protocol") {
        await expect(session).toContainText("Public synthetic diagnostics");
        await expect(session).not.toContainText(/restricted/i);
      }
      await expect(page.getByText("Synthetic design fixture · no real funds", { exact: true })).toBeVisible();
    }
  });

  test("the workspace presents one verdict, a triage queue, and separate money domains", async ({ page }) => {
    await page.goto("/");

    const queue = page.getByTestId("workspace-interventions");
    await expect(queue).toBeVisible();
    await expect(queue.getByRole("button")).toHaveCount(12);
    await expect(queue).toContainText("12 shown · 14 monitored");

    const selected = queue.locator('.queue-item[aria-pressed="true"]');
    await expect(selected).toHaveCount(1);
    await expect(selected).toContainText("Cure period expiring");

    const verdicts = page.locator("[data-readiness-verdict]");
    await expect(verdicts).toHaveCount(1);
    await expect(verdicts).toHaveAttribute("data-readiness-verdict", "AVAILABLE_NOW");
    await expect(verdicts.getByRole("heading", { name: "Available now", exact: true })).toBeVisible();

    const receivable = page.locator('.workspace-domain-pair [data-domain="receivable"]');
    const protection = page.locator('.workspace-domain-pair [data-domain="protection"]');
    await expect(receivable).toHaveCount(1);
    await expect(protection).toHaveCount(1);
    await expect(receivable).toHaveAttribute("data-edge", "continuous-double");
    await expect(protection).toHaveAttribute("data-edge", "interrupted-notch");
    await expect(receivable).toContainText("Receivable · outstanding");
    await expect(protection).toContainText("Funded protection · Cure Period");

    await expect(page.locator(".workspace-decision .gate-item")).toHaveCount(5);
    await expect(page.getByTestId("decision-deadline")).toBeVisible();
    await expect(page.getByTestId("primary-action")).toBeVisible();
    await expect(page.locator("body")).not.toContainText(/\b[0-5]\s*\/\s*5\s+clear\b/i);
  });

  test("workspace anchors, reserve labels, and exceptional machine states stay truthful", async ({ page }) => {
    await page.goto("/");

    const navigation = page.getByRole("navigation", { name: "Originator navigation" });
    const portfolioLink = navigation.getByRole("link", { name: "Portfolio", exact: true });
    const evidenceLink = navigation.getByRole("link", { name: "Evidence", exact: true });
    await expect(portfolioLink).toHaveAttribute("href", "/#portfolio");
    await expect(evidenceLink).toHaveAttribute("href", "/#evidence");

    await portfolioLink.click();
    await expect(page).toHaveURL(/\/#portfolio$/);
    await expect(page.locator("#portfolio")).toBeVisible();
    await evidenceLink.click();
    await expect(page).toHaveURL(/\/#evidence$/);
    await expect(page.locator("#evidence")).toBeVisible();

    const queue = page.getByTestId("workspace-interventions");
    const protection = page.locator('.workspace-domain-pair [data-domain="protection"]');
    await queue.getByRole("button", { name: /Protection funding blocked by synthetic balance/i }).click();
    await expect(protection).toContainText("Protection reserve · Unfunded");
    await expect(protection).toContainText("0.00 aUSDC");
    await expect(protection).not.toContainText("Funded protection");

    await queue.getByRole("button", { name: /Protection transition requires recovery/i }).click();
    const protectionRail = page.locator('.workspace-machines .machine-rail[data-domain="protection"]');
    await expect(protectionRail).toHaveAttribute("data-state-mapped", "false");
    await expect(protectionRail.locator(".machine-states > li")).toHaveCount(1);
    await expect(protectionRail.locator('[aria-current="step"]')).toContainText("Recovery");
    await expect(protectionRail.locator('[aria-current="step"]')).toContainText(
      "Current observed state; lifecycle position is not mapped",
    );

    await page.getByLabel("Filter intervention queue").selectOption("all");
    await queue.getByRole("button", { name: /Protection settled while receivable remains outstanding/i }).click();
    await expect(protection).toContainText("Protection reserve · Settled");
    await expect(protection).not.toContainText("Funded protection");

    await queue.getByRole("button", { name: /Receivable and protection lifecycle completed/i }).click();
    await expect(protection).toContainText("Protection reserve · Released");
    await expect(protection).not.toContainText("Funded protection");
    await expect(protectionRail).toHaveAttribute("data-state-mapped", "false");
    await expect(protectionRail.locator('[aria-current="step"]')).toContainText("Released");
  });

  test("workspace selection survives a reload and restores its unique verdict", async ({ page }) => {
    await page.goto("/");

    const queue = page.getByTestId("workspace-interventions");
    const target = queue.getByRole("button", { name: /Viewer-specific synthetic credential required/i });
    await target.click();

    await expect(target).toHaveAttribute("aria-pressed", "true");
    await expect(page.locator('[data-readiness-verdict="CREDENTIAL_REQUIRED"]')).toHaveCount(1);
    const selectedFolio = await page.getByTestId("selected-folio").innerText();

    await page.reload();

    await expect(page.getByTestId("selected-folio")).toHaveText(selectedFolio);
    await expect(
      page.getByTestId("workspace-interventions").getByRole("button", {
        name: /Viewer-specific synthetic credential required/i,
      }),
    ).toHaveAttribute("aria-pressed", "true");
    await expect(page.locator('[data-readiness-verdict="CREDENTIAL_REQUIRED"]')).toHaveCount(1);
  });

  test("the workspace review dialog rehearses early stages without a wallet and restores focus", async ({ page }) => {
    await page.goto("/");

    const trigger = page.getByTestId("primary-action");
    await trigger.click();

    const dialog = page.getByRole("dialog", { name: "Cure registered conflict", exact: true });
    await expect(dialog).toBeVisible();
    await expect(dialog).toBeFocused();
    await expect(dialog).toContainText(
      "No wallet, network request, signature, funds, or transaction is used.",
    );
    await expect(dialog.getByText("Fixture only", { exact: true })).toBeVisible();
    await expect(dialog).toContainText("Step 1 of 11");

    const discovered = dialog.locator('[data-stage="discovered"]');
    const readiness = dialog.locator('[data-stage="readiness"]');
    const simulation = dialog.locator('[data-stage="simulation"]');
    await expect(discovered).toHaveAttribute("aria-current", "step");

    await dialog.getByRole("button", { name: "Begin synthetic review", exact: true }).click();
    await expect(discovered).toHaveAttribute("data-status", "complete");
    await expect(readiness).toHaveAttribute("aria-current", "step");
    await expect(dialog).toContainText("Step 2 of 11");

    await dialog.getByRole("button", { name: "Record readiness", exact: true }).click();
    await expect(readiness).toHaveAttribute("data-status", "complete");
    await expect(simulation).toHaveAttribute("aria-current", "step");
    await expect(simulation).toContainText("Deterministic local rehearsal; no RPC request");
    await expect(dialog).toContainText("Step 3 of 11");

    await page.keyboard.press("Escape");
    await expect(dialog).toHaveCount(0);
    await expect(trigger).toBeFocused();
  });

  test("the participant view is fixture-position-derived, exact, and offers no manual role switch", async ({ page }) => {
    await page.goto("/deal-room");

    await expect(page.getByTestId("participant-position")).toContainText("Your position · 60 / 100 units");
    await expect(page.getByText("Your synthetic role view", { exact: true })).toBeVisible();

    const receivable = page.locator('.participant-domain-pair [data-domain="receivable"]');
    const protection = page.locator('.participant-domain-pair [data-domain="protection"]');
    await expect(receivable.locator(".domain-ledger-amount")).toHaveText("1,488,000.00 aUSDC");
    await expect(protection.locator(".domain-ledger-amount")).toHaveText("148,800.00 aUSDC");
    await expect(receivable).toHaveAttribute("data-edge", "continuous-double");
    await expect(protection).toHaveAttribute("data-edge", "interrupted-notch");

    const verdicts = page.locator("[data-readiness-verdict]");
    await expect(verdicts).toHaveCount(1);
    await expect(verdicts).toHaveAttribute("data-readiness-verdict", "WRONG_ROLE");
    await expect(verdicts.getByRole("heading", { name: "Wrong role", exact: true })).toBeVisible();
    await expect(verdicts).toContainText("Facility B (synthetic)");

    await expect(page.locator(".participant-surface fieldset, .participant-surface select")).toHaveCount(0);
    await expect(page.getByRole("button", { name: /^(?:Holder A|Facility B)$/i })).toHaveCount(0);

    const participantEvidence = page.locator(".participant-proof .evidence-facts");
    await expect(participantEvidence.locator('[data-evidence-class="observed"]')).toHaveCount(0);
    await expect(participantEvidence.locator('[data-evidence-class="attested"]')).toHaveCount(0);
    await expect(participantEvidence.locator('[data-evidence-class="derived"]')).toHaveCount(2);
    await expect(participantEvidence.locator('[data-evidence-class="external"]')).toHaveCount(3);
    await expect(participantEvidence).toContainText("No corresponding event is attached to this scenario");
    await expect(participantEvidence).toContainText("No signed participant attestation is attached to this scenario");
    const liveReadBoundary = page
      .locator(".participant-evidence-area .observation-stamp > div")
      .filter({ hasText: "Live read" });
    await expect(liveReadBoundary).toContainText("Not performed");
    await page.getByTestId("participant-review-action").click();
    const review = page.getByRole("status");
    await expect(review).toContainText("No cure action is offered to this synthetic holder.");
    await expect(review).toContainText("not a live wallet read or manual selector");

    await expectNoThirdPartyKycDetail(page);
  });

  test("protocol opens on the correlated recovery record and keeps evidence registered", async ({ page }) => {
    await page.goto("/protocol");

    const selectedRecord = page.locator('.protocol-record-row[data-selected="true"]');
    await expect(selectedRecord).toHaveCount(1);
    await expect(selectedRecord).toHaveAttribute("data-record-kind", "diagnostic");
    await expect(selectedRecord).toContainText("after_state_unavailable");
    await expect(selectedRecord).toContainText("Recovery required");

    await expect(page.getByRole("heading", { name: "After-state unavailable", exact: true })).toBeVisible();
    await expect(page.locator('[data-readiness-verdict="RECOVERY_REQUIRED"]')).toHaveCount(1);
    await expect(page.locator(".diagnostic-entry")).toContainText("after_state_unavailable");
    await expect(page.locator(".diagnostic-entry")).toContainText("Protocol Operations");
    await expect(page.locator(".diagnostic-entry")).toContainText("resumeSyntheticTransition()");

    const transition = page.locator(".protocol-proof-stage .transition-flow");
    await expect(transition).toContainText("Before");
    await expect(transition).toContainText("Active");
    await expect(transition).toContainText("Action");
    await expect(transition.locator(".transition-action-node strong")).toHaveText("resumeSyntheticTransition()");
    await expect(transition).toContainText("After");
    await expect(transition).toContainText("Not reconstructed");

    const diagnosticEvidence = page.locator(".protocol-proof-stage .evidence-facts");
    await expect(diagnosticEvidence.locator('[data-evidence-class="observed"]')).toHaveCount(1);
    await expect(diagnosticEvidence.locator('[data-evidence-class="derived"]')).toHaveCount(1);
    await expect(diagnosticEvidence.locator('[data-evidence-class="attested"]')).toHaveCount(0);
    await expect(diagnosticEvidence.locator('[data-evidence-class="external"]')).toHaveCount(2);
    const missingAttestation = diagnosticEvidence.locator('[data-evidence-class="external"]', {
      hasText: "Participant attestation",
    });
    await expect(missingAttestation).toContainText("Not attached");
    await expect(missingAttestation).toContainText("Not established by the selected diagnostic record");
    await expect(page.locator(".protocol-runbook")).toContainText("Recovery runbook · no automatic retry");

    const transitionRecord = page.getByRole("button", { name: /settleSyntheticProtection\(\)/i }).first();
    await transitionRecord.click();
    await expect(transitionRecord).toHaveAttribute("aria-pressed", "true");
    await expect(page.getByRole("heading", { name: "settleSyntheticProtection()", exact: true })).toBeVisible();
    await expect(page.getByText("No diagnostic attached", { exact: true })).toBeVisible();

    const servicePlate = page.locator(".protocol-service-plate");
    await expect(servicePlate).toContainText("Obs / block 1396");
    await expect(servicePlate).toContainText("Finality / Finalized");

    const rawFields = page.locator(".protocol-raw-fields");
    await expect(rawFields.locator("div", { hasText: "After observed" })).toContainText("29 Jul 2026, 07:42 UTC");
    await expect(rawFields.locator("div", { hasText: "Synthetic block" })).toContainText("1396");
    await expect(rawFields.locator("div", { hasText: "Confirmations" })).toContainText("38");
  });

  test("skip navigation, focus treatment, and a queue choice work from the keyboard", async ({ page }) => {
    await page.goto("/");

    const skipLink = page.getByRole("link", { name: "Skip to product surface", exact: true });
    await page.keyboard.press("Tab");
    await expect(skipLink).toBeFocused();

    const focusStyle = await skipLink.evaluate((element) => {
      const style = getComputedStyle(element);
      return {
        outlineStyle: style.outlineStyle,
        outlineWidth: Number.parseFloat(style.outlineWidth),
        boxShadow: style.boxShadow,
      };
    });
    expect(focusStyle.outlineStyle).not.toBe("none");
    expect(focusStyle.outlineWidth).toBeGreaterThanOrEqual(2);
    expect(focusStyle.boxShadow).not.toBe("none");

    await page.keyboard.press("Enter");
    await expect(page.locator("main")).toBeFocused();

    await page.reload();
    await page.keyboard.press("Tab");
    await expect(skipLink).toBeFocused();
    await page.keyboard.press("Tab");
    await expect(page.getByRole("link", { name: "Mordant workspace", exact: true })).toBeFocused();
    await page.keyboard.press("Tab");
    await expect(page.getByRole("link", { name: "Workspace", exact: true })).toBeFocused();

    const target = page.getByTestId("workspace-interventions").getByRole("button", {
      name: /Protection funding blocked by synthetic balance/i,
    });
    await target.focus();
    await page.keyboard.press("Enter");
    await expect(target).toHaveAttribute("aria-pressed", "true");
    await expect(page.locator('[data-readiness-verdict="FUNDS_REQUIRED"]')).toHaveCount(1);
  });

  test("no product surface renders third-party KYC details or a legacy readiness score", async ({ page }) => {
    for (const surface of surfaces) {
      await page.goto(surface.path);
      await expect(page.getByRole("heading", { name: surface.heading }).first()).toBeVisible();
      await expectNoThirdPartyKycDetail(page);

      const renderedText = await page.locator("body").innerText();
      expect(renderedText).not.toMatch(/\b[0-5]\s*\/\s*5\s+clear\b/i);

      const navigationText = await page.locator(".role-navigation").innerText();
      expect(navigationText).not.toMatch(/Deal workspace|Participant deal room|Protocol operations/i);
    }
  });
});
