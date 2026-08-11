import { expect, test } from "@playwright/test";

/**
 * The visual freeze: the live product surfaces as they look today.
 *
 * The coalition migration changes which runtime the web product calls, not how
 * it looks. This suite is the mechanism that holds that promise. Without it the
 * freeze is an intention, and this repository has just paid twice for rules that
 * were written down and never fired on their own.
 *
 * It captures the LiveProduct root, not the page. The root is the substrate the
 * production route and this harness genuinely share: `/protection/live` renders
 * PublicShell -> LiveExecution -> LiveProduct (and, on the admission path,
 * LiveExecution -> DirectParticipantExecution -> LiveProduct), while the harness
 * renders PublicShell -> LiveProduct from fixtures. Scoping to the root also
 * excludes the harness-only banner, which does not exist in production and has no
 * business in a reference.
 *
 * `[data-chapter]` appears exactly once in the repository, on that root, so the
 * locator needs no change to the product.
 *
 * The clock is frozen because the surface renders a computed deadline: the
 * conflict fixture derives it from `new Date()` and the product prints both the
 * absolute time, to the minute, and a relative phrase. Left alone, a reference
 * would be stale within the minute and the gate would redden for the calendar
 * rather than for a regression, which is how a visual suite ends up disabled.
 *
 * Note that running the suite twice in a row would NOT have exposed this: both
 * passes share the same minute. It was found by looking at the reference image.
 */
const FROZEN_CLOCK = "2026-08-11T00:00:00.000Z";

/**
 * The states the coalition migration will touch, and only those.
 *
 * The two terminal branches are where the V5 bits and the release wording land,
 * so a copy change there is the likeliest thing to move the layout. The two
 * admission states are the surface that moves to ParticipantAdmissionV2.
 */
const SCENARIOS = ["conflict", "no-conflict", "admitted", "admission-a"] as const;

for (const scenario of SCENARIOS) {
  test(`the live product surface is unchanged: ${scenario}`, async ({ page }) => {
    await page.goto(`/design-lab/live?scenario=${scenario}&now=${encodeURIComponent(FROZEN_CLOCK)}`);
    await expect(page.getByTestId("harness-banner")).toBeVisible();
    const surface = page.locator("[data-chapter]");
    await expect(surface).toBeVisible();
    await expect(surface).toHaveScreenshot(`${scenario}.png`, {
      // The one genuinely clock-dependent cell. `now` on the URL pins the
      // deadline the fixture derives, but the product also prints how far away
      // it is, computed at render from the real clock. Freezing the browser
      // clock instead would only fix the client and leave the server rendering
      // a different phrase, which is a hydration mismatch, not determinism.
      // Masking this cell keeps every other pixel under the freeze.
      mask: [page.getByTestId("deadline")],
    });
  });
}
