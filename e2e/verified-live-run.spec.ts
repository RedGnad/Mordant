import { expect, test } from "@playwright/test";

/**
 * The completed real Monad journey, as a judge sees it.
 *
 * These assertions are deliberately about truthfulness rather than styling: the
 * page must badge itself as a separate verified on-chain execution, must never call itself a demo,
 * must link real transactions to the real explorer, and must show the exact
 * six-decimal settlement rather than a rounded one.
 */

const PATH = "/protection/verified-run";
const RELEASE_TX = "0x09b9bbfbab53f1782506850654fe0c7be1e81bf8a1eff692c5b43e0e3936d651";
const FINALIZE_TX = "0xc74051d892a0e2f971e744ac45b159dd19f23b8ff7f649192ab77f2345e4fc34";
const CLAIM_A_TX = "0x4831b0a7aa5bb6c030a6651e3112ee806f0c0d7c61ecbdf376d096b6ecbea819";
const CLAIM_B_TX = "0x36296bf9db21123fcd155ec95c8f7a4db31cbb5158dd42139b79bb81430bfc50";
const ADAPTER = "0x9cD93089E02d301BDdfC86EaAbB39242272cAfa1";
const EXPLORER = "https://testnet.monadexplorer.com";

test.describe("verified historical on-chain execution", () => {
  test("attributes conflict, policy, cure and payouts to their real sources", async ({ page }) => {
    await page.goto("/protection/verified-run");
    const run = page.getByTestId("verified-live-run");
    await expect(run).toContainText("governed result established that their windows conflicted");
    await expect(run).toContainText("preconfigured demo recourse policy");
    await expect(run).toContainText("deployment configuration—not the Boolean—determined holders and payout amounts");
    await expect(run).toContainText("established no legal responsibility, priority, ownership, deadline or payout amount");
    await expect(run).not.toContainText("amounts the signed result carried");
    await expect(run).not.toContainText("governed result opened recourse");
  });

  test("the transition back to live names the managed public profile", async ({ page }) => {
    await page.goto("/protection/verified-run");
    const transition = page.getByText(/The current live proof starts a new managed case/iu);
    await expect(transition).toContainText("published eligible test context");
    await expect(transition).not.toContainText("two eligible wallets");
  });

  test("badges itself as a separate verified on-chain execution and never as a fixture", async ({ page }) => {
    await page.goto(PATH);
    const run = page.getByTestId("verified-live-run");
    await expect(run).toBeVisible();
    await expect(run).toHaveAttribute("data-provenance", "VERIFIED_LIVE_RUN");
    await expect(page.getByTestId("verified-live-run-badge"))
      .toHaveText(/verified on-chain execution · separate hardened run/iu);
    await expect(run).toContainText("Separate hardened execution · historical Adapter V2 configuration");

    // No part of this surface may describe the completed run as sample data.
    const body = (await page.locator("body").innerText()).toLowerCase();
    for (const forbidden of ["demo fixture", "fixture", "simulated transaction", "sample transaction"]) {
      expect(body, `verified run used the word "${forbidden}"`).not.toContain(forbidden);
    }
  });

  test("answers the five chapters in order", async ({ page }) => {
    await page.goto(PATH);
    const summary = page.getByTestId("verification-summary");
    await expect(summary).toContainText("Five verified stages. One reconciled run.");
    await expect(summary.locator("li")).toHaveCount(5);
    await expect(summary.locator("li > span")).toHaveText(["✓", "✓", "✓", "✓", "✓"]);
    for (const [index, heading] of ["Verify", "Authorize", "Decide privately", "Act", "Prove"].entries()) {
      const chapter = page.getByRole("heading", { level: 2, name: heading, exact: true });
      await expect(chapter, `chapter ${index + 1} ${heading}`).toBeVisible();
    }
  });

  test("links every real transaction to the real Monad explorer", async ({ page }) => {
    await page.goto(PATH);
    for (const hash of [RELEASE_TX, FINALIZE_TX, CLAIM_A_TX, CLAIM_B_TX]) {
      const link = page.locator(`a[href="${EXPLORER}/tx/${hash}"]`).first();
      await expect(link, `missing explorer link for ${hash}`).toHaveCount(1);
      await expect(link).toHaveAttribute("rel", /noreferrer/u);
    }
    await expect(page.locator(`a[href="${EXPLORER}/address/${ADAPTER}"]`).first()).toHaveCount(1);
    // Every external link must be https and point at the canonical explorer.
    for (const href of await page.locator("a[target=_blank]").evaluateAll(
      (nodes) => nodes.map((node) => (node as HTMLAnchorElement).href),
    )) {
      expect(href.startsWith(`${EXPLORER}/`), `unexpected external link ${href}`).toBe(true);
    }
  });

  test("shows the exact six-decimal settlement and an untouched MINV01", async ({ page }) => {
    await page.goto(PATH);
    const body = await page.locator("body").innerText();
    // 2400 and 1600 atomic units are 0.002400 and 0.001600 aUSDC, never "0.00".
    expect(body).toContain("0.002400");
    expect(body).toContain("0.001600");
    expect(body).toContain("0.004000");
    expect(body).toMatch(/MINV01/u);
    expect(body).toMatch(/Unchanged/u);
  });

  test("keeps deep cryptographic detail behind disclosures", async ({ page }) => {
    await page.goto(PATH);
    const details = page.locator("details");
    await expect(details).toHaveCount(6);
    // Closed by default: the narrative leads, the hashes do not.
    for (const open of await details.evaluateAll((nodes) => nodes.map((node) => (node as HTMLDetailsElement).open))) {
      expect(open).toBe(false);
    }
    const governedDigest = "sha256:bf2c4e77f44ed7fcbb650d1a71682bb39802dc1a34f9477968c74c69bdca5368";
    expect(await page.locator("body").innerText()).not.toContain(governedDigest);
    await details.nth(2).locator("summary").click();
    await expect(page.getByText(governedDigest)).toBeVisible();
  });

  test("survives a refresh with the same real values", async ({ page }) => {
    await page.goto(PATH);
    const before = await page.locator("body").innerText();
    await page.reload();
    const after = await page.locator("body").innerText();
    expect(after).toContain(RELEASE_TX.slice(0, 12));
    expect(after.includes("0.002400")).toBe(true);
    expect(before.includes("0.002400")).toBe(true);
    await expect(page.getByTestId("verified-live-run")).toHaveAttribute("data-provenance", "VERIFIED_LIVE_RUN");
  });

  test("offers the completed run to live check transition", async ({ page }) => {
    await page.goto(PATH);
    const cta = page.getByTestId("verified-run-to-live");
    await expect(cta).toBeVisible();
    await expect(cta).toHaveAttribute("href", "/protection/live");
  });

  test("exposes no secret or private execution input in the delivered page", async ({ page }) => {
    const response = await page.goto(PATH);
    const html = (await response?.text()) ?? "";
    for (const forbidden of [
      "activeFrom", "activeUntil", "privateKey", "PRIVATE_KEY", "signingKey",
      "MORDANT_BRIDGE_ATTESTOR_PRIVATE_KEY", "CLEANVERSE_API_KEY", "MORDANT_LIVE_SETTLEMENT_ACK",
    ]) {
      expect(html, `page exposed ${forbidden}`).not.toContain(forbidden);
    }
  });

  test("never scrolls horizontally at this viewport", async ({ page }) => {
    await page.goto(PATH);
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
    expect(overflow).toBeLessThanOrEqual(1);
  });
});
