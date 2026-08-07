import { expect, test } from "@playwright/test";

/**
 * The completed real Monad journey, as a judge sees it.
 *
 * These assertions are deliberately about truthfulness rather than styling: the
 * page must badge itself as a verified live run, must never call itself a demo,
 * must link real transactions to the real explorer, and must show the exact
 * six-decimal settlement rather than a rounded one.
 */

const PATH = "/protection/verified-run";
const RELEASE_TX = "0xa46797440a14549fd8fb4cea7d7dcff40d78b84babf48746daa58e8d314d14f6";
const FINALIZE_TX = "0x4fc798bd0608f57543e0004ddcc21e36f9dd881055144c160585da2ea87aff64";
const CLAIM_A_TX = "0x46b2cb6bd0978a3003d05c3fef6a07f89d2e598ad205d3e1f68463061f4115f4";
const CLAIM_B_TX = "0x8670482a2cbaba08a66f693150bdb34a5d46d1453f5feea9d56939d5e7e64147";
const ADAPTER = "0x00efE6AAcaC6Aa94A3c66d8F09D310197600D935";
const EXPLORER = "https://testnet.monadexplorer.com";

test.describe("verified live run", () => {
  test("badges itself as a verified live run and never as a demo or fixture", async ({ page }) => {
    await page.goto(PATH);
    const run = page.getByTestId("verified-live-run");
    await expect(run).toBeVisible();
    await expect(run).toHaveAttribute("data-provenance", "VERIFIED_LIVE_RUN");
    await expect(page.getByTestId("verified-live-run-badge")).toHaveText(/verified live run/iu);

    // No part of this surface may describe the completed run as sample data.
    const body = (await page.locator("body").innerText()).toLowerCase();
    for (const forbidden of ["demo fixture", "fixture", "simulated transaction", "sample transaction"]) {
      expect(body, `verified run used the word "${forbidden}"`).not.toContain(forbidden);
    }
  });

  test("answers the five chapters in order", async ({ page }) => {
    await page.goto(PATH);
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
    await expect(details).toHaveCount(5);
    // Closed by default: the narrative leads, the hashes do not.
    for (const open of await details.evaluateAll((nodes) => nodes.map((node) => (node as HTMLDetailsElement).open))) {
      expect(open).toBe(false);
    }
    const governedDigest = "sha256:fa60c0a35a509a48d54ad1cc4a09d376a70bffd297e30eea1775e6b69662f43c";
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
