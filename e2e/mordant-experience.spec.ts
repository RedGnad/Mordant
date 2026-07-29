import { expect, test, type Locator, type Page } from "@playwright/test";

import { getSyntheticDeal, proRateAmount } from "../src/lib/mordant/product-model";

const experiencePath = "/design-lab/mordant-experience";
const frameIds = ["calm", "exception", "isolated", "participant", "deadline", "resolved"] as const;
const nextActions = [
  "Let the exception appear",
  "Isolate this deal",
  "See the holder view",
  "Advance to the deadline",
  "Show the modeled resolution",
] as const;
const abnormalFrames = new Set(["exception", "isolated", "participant", "deadline"]);
const sourceDeal = getSyntheticDeal("wrong-role");
const sourcePosition = sourceDeal.viewer.position;

if (!sourcePosition) {
  throw new Error("The M-EX1 tests require the wrong-role holder position.");
}

const sourceReceivable = proRateAmount(sourceDeal.economics.receivable.outstanding, sourcePosition);
const sourceProtection = proRateAmount(sourceDeal.economics.protection.lockedReserve, sourcePosition);
const sourceResponsible = sourceDeal.nextResponsibility.actorLabel.replace(/\s+\(synthetic\)$/u, "");

function wholeAmount(minorUnits: string, decimals: number) {
  return (BigInt(minorUnits) / 10n ** BigInt(decimals)).toLocaleString("en-US");
}

const receivableAmount = wholeAmount(sourceReceivable.minorUnits, sourceReceivable.asset.decimals);
const protectionAmount = wholeAmount(sourceProtection.minorUnits, sourceProtection.asset.decimals);

async function openExperience(page: Page) {
  await page.goto(experiencePath);
  await expect(page.getByTestId("mordant-experience")).toBeVisible();
}

async function advance(page: Page, action: string) {
  await page.getByRole("button", { name: action, exact: true }).click();
  await expect(page.locator("#experience-title")).toBeFocused();
}

async function visibleOccurrenceCount(page: Page, value: string) {
  const text = await page.getByTestId("experience-stage").innerText();
  return text.split(value).length - 1;
}

async function anchorPosition(anchor: Locator) {
  const box = await anchor.boundingBox();
  expect(box).not.toBeNull();
  if (!box) return { x: 0, y: 0 };
  return { x: Math.round(box.x), y: Math.round(box.y) };
}

test.describe("M-EX1 continuous Mordant experience", () => {
  test("walks one source deal through six compositional states without changing route", async ({ page }) => {
    await openExperience(page);

    const root = page.getByTestId("mordant-experience");
    await expect(root).toHaveAttribute("data-source-scenario", "wrong-role");
    await expect(page.locator('meta[name="robots"]')).toHaveAttribute("content", /noindex/iu);

    for (let index = 0; index < frameIds.length; index += 1) {
      const frameId = frameIds[index];
      await expect(root).toHaveAttribute("data-frame", frameId);
      await expect(root).toHaveAttribute("data-frame-index", String(index + 1));
      await expect(page.locator('[data-dominant="true"]:visible')).toHaveCount(1);

      const visibleRegions = await page.locator("[data-region]:visible").count();
      expect(visibleRegions).toBeLessThanOrEqual(3);
      await expect(page.locator("[data-rupture]:visible")).toHaveCount(abnormalFrames.has(frameId) ? 1 : 0);
      expect(page.url()).toMatch(/\/design-lab\/mordant-experience$/u);

      if (index < nextActions.length) await advance(page, nextActions[index]);
    }
  });

  test("keeps the receivable anchor fixed and each business truth unique", async ({ page }) => {
    await openExperience(page);

    const anchor = page.locator("[data-receivable-anchor]");
    const initialPosition = await anchorPosition(anchor);
    let participantResponsibilityX: number | null = null;
    await anchor.evaluate((element) => element.setAttribute("data-continuity-probe", "same-node"));

    for (let index = 0; index < frameIds.length; index += 1) {
      await expect(anchor).toHaveAttribute("data-continuity-probe", "same-node");

      if (index <= 4) {
        expect(await anchorPosition(anchor)).toEqual(initialPosition);
        const supportBox = await page.getByTestId("experience-support").boundingBox();
        const anchorBox = await anchor.boundingBox();
        expect(supportBox).not.toBeNull();
        expect(anchorBox).not.toBeNull();
        if (supportBox && anchorBox) {
          expect(supportBox.y + supportBox.height).toBeLessThanOrEqual(anchorBox.y);
        }
      }

      expect(await visibleOccurrenceCount(page, receivableAmount)).toBe(1);
      expect(await visibleOccurrenceCount(page, protectionAmount)).toBe(1);

      if (index === 0) expect(await visibleOccurrenceCount(page, "Funded")).toBe(1);
      if (index === 1) expect(await visibleOccurrenceCount(page, "conflict")).toBe(1);
      if (index === 3) expect(await visibleOccurrenceCount(page, "unresolved")).toBe(1);
      if (index === 4) expect(await visibleOccurrenceCount(page, "claimable")).toBe(1);

      if (index >= 2 && index <= 4) {
        expect(await visibleOccurrenceCount(page, sourceResponsible)).toBe(1);
      }

      if (index === 3) {
        participantResponsibilityX = (await page.locator("[data-region='responsibility']").boundingBox())?.x ?? null;
      }

      if (index === 4 && (await page.viewportSize())?.width === 1280) {
        const deadlineResponsibilityX = (await page.locator("[data-region='responsibility']").boundingBox())?.x ?? null;
        expect(participantResponsibilityX).not.toBeNull();
        expect(deadlineResponsibilityX).not.toBeNull();
        if (participantResponsibilityX !== null && deadlineResponsibilityX !== null) {
          expect(participantResponsibilityX - deadlineResponsibilityX).toBeGreaterThanOrEqual(30);
        }
      }

      const decisionText = await page.getByTestId("experience-stage").innerText();
      expect(decisionText).not.toMatch(
        /wrong-role|synthetic:|synroot|cureSyntheticConflict|invoice root|action record|after_state|wallet|calldata/iu,
      );

      if (index < nextActions.length) await advance(page, nextActions[index]);
    }
  });

  test("replaces the resolution with an honest retained record", async ({ page }) => {
    await openExperience(page);
    for (const action of nextActions) await advance(page, action);

    await page.getByRole("button", { name: "Open retained record", exact: true }).click();
    const proof = page.getByTestId("experience-proof-mode");
    await expect(proof).toBeVisible();
    await expect(page.getByTestId("experience-canvas")).toHaveCount(0);
    await expect(page.locator("#experience-proof-title")).toBeFocused();
    await expect(proof).toContainText("Configured");
    await expect(proof).toContainText("Derived");
    await expect(proof).toContainText("Not observed");
    await expect(proof).toContainText("Not established");
    await expect(page.locator("#experience-proof-title")).toHaveText("What this walkthrough can establish.");
    await expect(proof.getByText("Not observed", { exact: true })).toHaveCount(1);
    await expect(proof).not.toContainText("submitted or finalized");

    const technicalRecord = page.getByTestId("experience-technical-record");
    await expect(technicalRecord).not.toHaveAttribute("open", "");
    await technicalRecord.locator("summary").click();
    await expect(technicalRecord).toContainText(sourceDeal.id);
    await expect(technicalRecord).toContainText(sourceDeal.machines.receivable.immutableInvoiceRoot);
    await expect(technicalRecord).not.toContainText("proof-protection-settlement");

    await page.keyboard.press("Escape");
    await expect(proof).toHaveCount(0);
    await expect(page.getByTestId("experience-canvas")).toBeVisible();
    await expect(page.getByTestId("mordant-experience")).toHaveAttribute("data-frame", "resolved");
    await expect(page.getByRole("button", { name: "Open retained record", exact: true })).toBeFocused();
    await expect(page.locator("#experience-title")).toHaveText("A cure would restore protection.");
    await expect(page.getByTestId("experience-stage")).toContainText("Modeled outcome");
  });

  test("stays operable at approval widths and respects reduced motion", async ({ page }) => {
    for (const viewport of [
      { width: 1280, height: 800 },
      { width: 390, height: 844 },
      { width: 320, height: 720 },
    ]) {
      await page.setViewportSize(viewport);
      await openExperience(page);

      expect(
        await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth),
        `${viewport.width}px must not overflow horizontally`,
      ).toBe(true);

      const undersizedTargets = await page.getByTestId("mordant-experience").evaluate((root) =>
        [...root.querySelectorAll<HTMLElement>("a[href], button, summary")].flatMap((element) => {
          const style = getComputedStyle(element);
          const bounds = element.getBoundingClientRect();
          const rendered = style.display !== "none" && style.visibility !== "hidden" && bounds.width > 0 && bounds.height > 0;
          return rendered && (bounds.width < 44 || bounds.height < 44)
            ? [{ label: element.textContent?.trim(), width: bounds.width, height: bounds.height }]
            : [];
        }),
      );
      expect(undersizedTargets).toEqual([]);
    }

    await page.emulateMedia({ reducedMotion: "reduce" });
    await page.setViewportSize({ width: 390, height: 844 });
    await openExperience(page);
    await advance(page, nextActions[0]);

    const transitionDurations = await page.getByTestId("mordant-experience").evaluate((root) =>
      [...root.querySelectorAll<HTMLElement>("*")].flatMap((element) =>
        getComputedStyle(element)
          .transitionDuration.split(",")
          .map((value) => (value.trim().endsWith("ms") ? Number.parseFloat(value) : Number.parseFloat(value) * 1_000)),
      ),
    );
    expect(Math.max(...transitionDurations)).toBeLessThanOrEqual(20);
  });
});
