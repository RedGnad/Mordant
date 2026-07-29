import { expect, test, type Locator, type Page, type TestInfo } from "@playwright/test";

const benchmarkPath = "/design-lab/m18r-deal-room";
const forbiddenDecisionVocabulary =
  /\b(?:hash|root|rootline|folio|bloc|block|transaction|confirmation|schema|gate|porte)\b|0x[a-f0-9]{8,}/i;

function businessWordCount(value: string): number {
  return value
    .replace(/(?<=\d)[\u00a0\u202f](?=\d{3}(?:\D|$))/gu, "")
    .trim()
    .split(/\s+/u)
    .filter((token) => /[\p{L}\p{N}]/u.test(token)).length;
}

async function useApprovalViewport(page: Page, testInfo: TestInfo) {
  const mobile = testInfo.project.name === "mobile-chromium";
  await page.setViewportSize(mobile ? { width: 390, height: 844 } : { width: 1280, height: 800 });
}

async function expectTargetAtLeast44(locator: Locator) {
  const box = await locator.boundingBox();
  expect(box).not.toBeNull();
  if (!box) return;
  expect(box.width).toBeGreaterThanOrEqual(44);
  expect(box.height).toBeGreaterThanOrEqual(44);
}

async function expectInsideViewport(page: Page, locator: Locator) {
  const box = await locator.boundingBox();
  const viewport = page.viewportSize();
  expect(box).not.toBeNull();
  expect(viewport).not.toBeNull();
  if (!box || !viewport) return;
  expect(box.x).toBeGreaterThanOrEqual(0);
  expect(box.y).toBeGreaterThanOrEqual(0);
  expect(box.x + box.width).toBeLessThanOrEqual(viewport.width + 0.5);
  expect(box.y + box.height).toBeLessThanOrEqual(viewport.height + 0.5);
}

function rgbChannels(value: string): readonly [number, number, number] {
  const channels = value.match(/[\d.]+/g)?.slice(0, 3).map(Number);
  if (!channels || channels.length !== 3) throw new Error(`Unsupported colour: ${value}`);
  return channels as unknown as readonly [number, number, number];
}

function relativeLuminance(value: string): number {
  const channels = rgbChannels(value).map((channel) => {
    const normalized = channel / 255;
    return normalized <= 0.04045 ? normalized / 12.92 : ((normalized + 0.055) / 1.055) ** 2.4;
  });
  return channels[0] * 0.2126 + channels[1] * 0.7152 + channels[2] * 0.0722;
}

function contrastRatio(foreground: string, background: string): number {
  const lighter = Math.max(relativeLuminance(foreground), relativeLuminance(background));
  const darker = Math.min(relativeLuminance(foreground), relativeLuminance(background));
  return (lighter + 0.05) / (darker + 0.05);
}

test.describe("M-18R isolated participant benchmark", () => {
  test.beforeEach(async ({ page }, testInfo) => {
    await useApprovalViewport(page, testInfo);
    await page.goto(benchmarkPath);
    await expect(page.getByTestId("m18r-benchmark")).toBeVisible();
  });

  test("compresses the wrong-role decision into one truthful first view", async ({ page }) => {
    const firstView = page.getByTestId("m18r-first-view");
    const levelOne = page.getByTestId("m18r-level-one");

    await expect(page.getByTestId("m18r-benchmark")).toHaveAttribute("lang", "fr");
    await expect(levelOne).toHaveAttribute("data-readiness-verdict", "WRONG_ROLE");
    await expect(levelOne.getByRole("heading", { name: "Vous n’avez rien à faire.", exact: true })).toBeVisible();
    await expect(levelOne).toContainText("Facility B doit régulariser avant 12:00");
    await expect(levelOne).toContainText("Votre créance n’a pas bougé");
    await expect(levelOne.getByText("Facility B", { exact: true })).toBeVisible();
    await expect(levelOne.getByText(/29 juillet · 12:00 UTC/i)).toBeVisible();

    const receivable = page.getByTestId("m18r-domain-receivable");
    const protection = page.getByTestId("m18r-domain-protection");
    await expect(receivable).toContainText("1 488 000 aUSDC");
    await expect(receivable).toContainText("Toujours détenue");
    await expect(protection).toContainText("148 800 aUSDC");
    await expect(protection).toContainText("Non versée");
    await expect(levelOne).toContainText("La créance reste séparée");
    await expect(page.getByTestId("m18r-deadline-consequence")).toHaveAttribute(
      "data-consequence-source",
      "next-responsibility",
    );

    const levelOneText = await levelOne.innerText();
    const firstViewText = await firstView.innerText();
    expect(businessWordCount(levelOneText), levelOneText).toBeLessThanOrEqual(50);
    expect(businessWordCount(firstViewText), firstViewText).toBeLessThanOrEqual(120);
    expect(levelOneText).not.toMatch(forbiddenDecisionVocabulary);

    const primaryAction = page.getByTestId("m18r-primary-action");
    await expect(primaryAction).toHaveCount(1);
    await expect(primaryAction).toHaveAttribute("href", "/");
    await expect(primaryAction).toHaveText(/Portefeuille/);
    await expectTargetAtLeast44(primaryAction);
    await expectInsideViewport(page, primaryAction);

    const whySummary = page.getByTestId("m18r-why").locator("summary");
    const evidenceSummary = page.getByTestId("m18r-evidence").locator("summary");
    await expectInsideViewport(page, whySummary);
    await expectInsideViewport(page, evidenceSummary);

    const fixtureLabel = page.getByText("Scénario synthétique", { exact: true });
    await expect(fixtureLabel).toBeVisible();
    expect(
      Number.parseFloat(await fixtureLabel.evaluate((element) => getComputedStyle(element).fontSize)),
    ).toBeGreaterThanOrEqual(10);

    await primaryAction.focus();
    const focusStyle = await primaryAction.evaluate((element) => {
      const style = getComputedStyle(element);
      return { background: style.backgroundColor, outline: style.outlineColor, outlineWidth: style.outlineWidth };
    });
    expect(focusStyle.outlineWidth).toBe("3px");
    expect(contrastRatio(focusStyle.outline, focusStyle.background)).toBeGreaterThanOrEqual(3);

    const layout = await page.evaluate(() => ({
      viewportWidth: window.innerWidth,
      documentWidth: document.documentElement.scrollWidth,
    }));
    expect(layout.documentWidth).toBeLessThanOrEqual(layout.viewportWidth);

    await expect(page.getByTestId("m18r-why")).not.toHaveAttribute("open", "");
    await expect(page.getByTestId("m18r-evidence")).not.toHaveAttribute("open", "");
  });

  test("keeps explanation and evidence behind deliberate disclosure", async ({ page }) => {
    const why = page.getByTestId("m18r-why");
    const evidence = page.getByTestId("m18r-evidence");
    const whySummary = why.locator("summary");
    const evidenceSummary = evidence.locator("summary");

    await expectTargetAtLeast44(whySummary);
    await expectTargetAtLeast44(evidenceSummary);
    await whySummary.click();
    await expect(why).toHaveAttribute("open", "");
    await expect(why).toContainText("La régularisation appartient à Facility B, pas à votre rôle");
    await expect(why).toContainText("ne brûle ni ne transfère vos unités de créance");
    await expect(evidence).not.toHaveAttribute("open", "");

    await evidenceSummary.click();
    await expect(evidence).toHaveAttribute("open", "");
    await expect(evidence).toContainText("État configuré, pas observation d’une transaction réelle");
    await expect(evidence).toContainText("Cette vue montre uniquement");
    await expect(evidence).toContainText("Non fournie dans ce scénario");
    await expect(evidence).toContainText("Aucune lecture live ni attestation participant");
    await expect(evidence).toContainText(
      "Ce prototype n’établit ni financement externe, ni fraude, ni priorité juridique, ni assurance.",
    );
  });

  test("separates the two money domains by colour, form, icon, position, and language", async ({ page }) => {
    const receivable = page.getByTestId("m18r-domain-receivable");
    const protection = page.getByTestId("m18r-domain-protection");

    await expect(receivable.locator('svg[aria-hidden="true"]')).toHaveCount(1);
    await expect(protection.locator('svg[aria-hidden="true"]')).toHaveCount(1);
    await expect(receivable.getByText("Votre créance", { exact: true })).toBeVisible();
    await expect(protection.getByText("Protection concernée", { exact: true })).toBeVisible();

    const semantics = await page.evaluate(() => {
      const receivableElement = document.querySelector<HTMLElement>('[data-testid="m18r-domain-receivable"]');
      const protectionElement = document.querySelector<HTMLElement>('[data-testid="m18r-domain-protection"]');
      if (!receivableElement || !protectionElement) throw new Error("Domain elements missing");
      const receivableStyle = getComputedStyle(receivableElement);
      const protectionStyle = getComputedStyle(protectionElement);
      const containmentStyle = getComputedStyle(protectionElement, "::after");
      return {
        receivableBackground: receivableStyle.backgroundColor,
        receivableText: receivableStyle.color,
        protectionBackground: protectionStyle.backgroundColor,
        protectionText: protectionStyle.color,
        protectionContainment: containmentStyle.borderRightWidth,
        receivableTop: receivableElement.getBoundingClientRect().top,
        protectionTop: protectionElement.getBoundingClientRect().top,
        receivableLeft: receivableElement.getBoundingClientRect().left,
        protectionLeft: protectionElement.getBoundingClientRect().left,
      };
    });

    expect(semantics.receivableBackground).not.toBe(semantics.protectionBackground);
    expect(semantics.protectionContainment).toBe("2px");
    expect(contrastRatio(semantics.receivableText, semantics.receivableBackground)).toBeGreaterThanOrEqual(4.5);
    expect(contrastRatio(semantics.protectionText, semantics.protectionBackground)).toBeGreaterThanOrEqual(4.5);
    expect(
      semantics.receivableTop !== semantics.protectionTop || semantics.receivableLeft !== semantics.protectionLeft,
    ).toBe(true);
  });
});
