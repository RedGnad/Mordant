import { expect, test, type Page } from "@playwright/test";

const surfaces = [
  { path: "/", name: "Deal workspace" },
  { path: "/deal-room", name: "Participant deal room" },
  { path: "/protocol", name: "Protocol operations" },
] as const;

const gateLabels = ["Identity", "Role", "Time", "Economic", "Protocol"] as const;

const thirdPartyKycDetail =
  /issuingCountryISO2|identityDataList|(?:passport (?:number|no\.?|id)|date of birth|birth date|nationality|issuing country|credential id)\s*(?::|#|–|—)\s*[a-z0-9]/i;

async function expectNoThirdPartyKycDetail(page: Page) {
  const renderedText = await page.locator("body").innerText();
  expect(renderedText).not.toMatch(thirdPartyKycDetail);
}

test.describe("Mordant product surfaces", () => {
  test("the shared navigation reaches every surface and exposes the current page", async ({ page }) => {
    await page.goto("/");

    const workspaceLink = page.getByRole("link", { name: /^Deal workspace\b/i });
    const dealRoomLink = page.getByRole("link", { name: /^Participant deal room\b/i });
    const protocolLink = page.getByRole("link", { name: /^Protocol operations\b/i });

    await expect(workspaceLink).toHaveAttribute("aria-current", "page");
    await expect(page.getByRole("heading", { name: "Deal workspace", exact: true })).toBeVisible();

    await dealRoomLink.click();
    await expect(page).toHaveURL(/\/deal-room$/);
    await expect(dealRoomLink).toHaveAttribute("aria-current", "page");
    await expect(page.getByRole("heading", { name: "Participant deal room", exact: true })).toBeVisible();

    await protocolLink.click();
    await expect(page).toHaveURL(/\/protocol$/);
    await expect(protocolLink).toHaveAttribute("aria-current", "page");
    await expect(page.getByRole("heading", { name: "Protocol operations", exact: true })).toBeVisible();

    await workspaceLink.click();
    await expect(page).toHaveURL(/\/$/);
    await expect(workspaceLink).toHaveAttribute("aria-current", "page");
  });

  test("the deal workspace exposes one complete five-gate action assessment", async ({ page }) => {
    await page.goto("/");

    await expect(page.getByRole("heading", { name: "Deal workspace", exact: true })).toBeVisible();
    await expect(page.getByRole("heading", { name: /^Action readiness\b/ })).toBeVisible();

    for (const gate of gateLabels) {
      await expect(page.getByText(gate, { exact: true }).first()).toBeVisible();
    }

    await expect(page.getByText("Cure period expiring", { exact: true }).first()).toBeVisible();
    await expect(page.getByText("Originator or Facility B", { exact: true }).first()).toBeVisible();
  });

  test("the participant deal room explains the critical state without merging the money domains", async ({
    page,
  }) => {
    await page.goto("/deal-room");

    await expect(page.getByRole("heading", { name: "Participant deal room", exact: true })).toBeVisible();
    await expect(page.getByText("Conflict registered", { exact: true }).first()).toBeVisible();
    await expect(page.getByText("Receivable remains owned", { exact: true })).toBeVisible();
    await expect(page.getByText("Protection at risk", { exact: true })).toBeVisible();

    await expect(page.getByText(/\b110(?:\.00)?\s+(?:synthetic\s+)?aUSDC\b/i).first()).toBeVisible();
    await expect(page.getByText(/\b10(?:\.00)?\s+(?:synthetic\s+)?aUSDC\b/i).first()).toBeVisible();
    await expect(page.getByText(/receivable units remain untouched/i)).toBeVisible();

    await page.getByRole("button", { name: "Facility B", exact: true }).click();
    await expect(page.getByRole("heading", { name: "Prepare the Facility B cure", exact: true })).toBeVisible();
    await expect(page.getByRole("heading", { name: /^Action readiness 5 \/ 5 clear$/i })).toBeVisible();
    await page.getByRole("button", { name: "Review cure package", exact: true }).click();
    await expect(page.getByText("Package ready for synthetic review", { exact: true })).toBeVisible();
    await expect(page.getByText("No financial transaction is submitted from this prototype.", { exact: true })).toBeVisible();

    await expectNoThirdPartyKycDetail(page);
  });

  test("protocol operations preserves the Before, Action, After evidence chain", async ({ page }) => {
    await page.goto("/protocol");

    await expect(page.getByRole("heading", { name: "Protocol operations", exact: true })).toBeVisible();
    await expect(page.getByText("Before", { exact: true })).toBeVisible();
    await expect(page.getByText("Action", { exact: true })).toBeVisible();
    await expect(page.getByText("After", { exact: true })).toBeVisible();
    await expect(page.getByText("ProtectionSettled", { exact: true }).first()).toBeVisible();
    await expect(page.getByText("Receivable-unit effect", { exact: true })).toBeVisible();
    await expect(page.getByText("None", { exact: true })).toBeVisible();
  });

  test("no surface renders third-party KYC details", async ({ page }) => {
    for (const surface of surfaces) {
      await page.goto(surface.path);
      await expect(page.getByRole("heading", { name: surface.name, exact: true })).toBeVisible();
      await expectNoThirdPartyKycDetail(page);
    }
  });

  test("skip navigation and product navigation work from the keyboard", async ({ page }) => {
    await page.goto("/");

    const skipLink = page.getByRole("link", { name: "Skip to product surface", exact: true });
    await page.keyboard.press("Tab");
    await expect(skipLink).toBeFocused();
    await page.keyboard.press("Enter");
    await expect(page.locator("main")).toBeFocused();

    await page.reload();
    await page.keyboard.press("Tab");
    await expect(skipLink).toBeFocused();
    await page.keyboard.press("Tab");
    await expect(page.getByRole("link", { name: /^Mordant deal workspace$/i })).toBeFocused();
    await page.keyboard.press("Tab");
    await expect(page.getByRole("link", { name: /^Deal workspace\b/i })).toBeFocused();
    await page.keyboard.press("Tab");
    await expect(page.getByRole("link", { name: /^Participant deal room\b/i })).toBeFocused();
    await page.keyboard.press("Enter");
    await expect(page).toHaveURL(/\/deal-room$/);
  });
});

test.describe("390px viewport", () => {
  test.use({ viewport: { width: 390, height: 844 } });

  test("all three surfaces avoid horizontal document overflow", async ({ page }) => {
    for (const surface of surfaces) {
      await page.goto(surface.path);
      await expect(page.getByRole("heading", { name: surface.name, exact: true })).toBeVisible();

      const dimensions = await page.evaluate(() => ({
        viewportWidth: document.documentElement.clientWidth,
        documentWidth: document.documentElement.scrollWidth,
        bodyWidth: document.body.scrollWidth,
      }));

      expect(
        dimensions.documentWidth,
        `${surface.path} document width: ${JSON.stringify(dimensions)}`,
      ).toBeLessThanOrEqual(dimensions.viewportWidth);
      expect(dimensions.bodyWidth, `${surface.path} body width: ${JSON.stringify(dimensions)}`).toBeLessThanOrEqual(
        dimensions.viewportWidth,
      );
    }
  });
});

test.describe("reduced motion", () => {
  test("all three surfaces suppress non-essential motion", async ({ page }) => {
    await page.emulateMedia({ reducedMotion: "reduce" });

    for (const surface of surfaces) {
      await page.goto(surface.path);
      await expect(page.getByRole("heading", { name: surface.name, exact: true })).toBeVisible();

      const motion = await page.evaluate(() => {
        const toMilliseconds = (value: string) => {
          const numeric = Number.parseFloat(value);
          if (!Number.isFinite(numeric)) return 0;
          return value.trim().endsWith("ms") ? numeric : numeric * 1_000;
        };

        const maximumTime = (value: string) =>
          Math.max(...value.split(",").map((entry) => toMilliseconds(entry.trim())));

        const violations = Array.from(document.querySelectorAll<HTMLElement>("body *"))
          .flatMap((element) => {
            const style = getComputedStyle(element);
            const hasNamedAnimation = style.animationName
              .split(",")
              .some((animationName) => animationName.trim() !== "none");
            const hasInfiniteAnimation = style.animationIterationCount
              .split(",")
              .some((iterationCount) => iterationCount.trim() === "infinite");
            const animationDuration = maximumTime(style.animationDuration);
            const transitionDuration = maximumTime(style.transitionDuration);

            if (
              (hasNamedAnimation && (animationDuration > 20 || hasInfiniteAnimation)) ||
              transitionDuration > 20
            ) {
              return [
                {
                  tag: element.tagName.toLowerCase(),
                  className: element.getAttribute("class") ?? "",
                  animationName: style.animationName,
                  animationDuration,
                  transitionDuration,
                },
              ];
            }

            return [];
          })
          .slice(0, 10);

        return {
          preferenceMatches: matchMedia("(prefers-reduced-motion: reduce)").matches,
          scrollBehavior: getComputedStyle(document.documentElement).scrollBehavior,
          violations,
        };
      });

      expect(motion.preferenceMatches).toBe(true);
      expect(motion.scrollBehavior).not.toBe("smooth");
      expect(motion.violations, `${surface.path} retains motion: ${JSON.stringify(motion.violations)}`).toEqual([]);
    }
  });
});
