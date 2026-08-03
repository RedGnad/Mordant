import {
  expect,
  test,
  type APIRequestContext,
  type Locator,
  type Page,
  type Route,
  type TestInfo,
} from "@playwright/test";

type ProductScenario = "conflict" | "no-conflict";
type ImportedPayload = Readonly<{
  schemaVersion: string;
  presentation: string;
  evidence: Readonly<Record<string, unknown>>;
}>;

const IMPORTED_API = "/api/protection/conflicting-pledge";
const REAL_LOCAL = process.env.MORDANT_RUN_REAL_PROTECTION_E2E === "1";
const LOCAL_OPERATION_LABELS = [
  "Prepare private match",
  "Submit participant A",
  "Submit participant B",
  "Evaluate private conflict",
  "Verify and release Boolean",
  "Apply governed result",
  "Simulate cure-window completion",
  "Seal public evidence",
] as const;

async function importedPayload(request: APIRequestContext, scenario: ProductScenario): Promise<ImportedPayload> {
  const response = await request.get(`${IMPORTED_API}?scenario=${scenario}`);
  expect(response.ok(), `verified ${scenario} fixture should be available`).toBeTruthy();
  return await response.json() as ImportedPayload;
}

async function expectNoHorizontalOverflow(page: Page): Promise<void> {
  const dimensions = await page.evaluate(() => ({
    body: document.body.scrollWidth,
    client: document.documentElement.clientWidth,
    document: document.documentElement.scrollWidth,
  }));
  expect(dimensions.body).toBeLessThanOrEqual(dimensions.client + 1);
  expect(dimensions.document).toBeLessThanOrEqual(dimensions.client + 1);
}

async function expectAboveFold(page: Page, locator: Locator): Promise<void> {
  await expect(locator).toBeVisible();
  const bounds = await locator.boundingBox();
  const viewport = page.viewportSize();
  expect(bounds, "truth boundary must have layout bounds").not.toBeNull();
  expect(viewport, "page must have a viewport").not.toBeNull();
  expect(bounds!.y).toBeLessThan(viewport!.height);
}

async function expectMinimumTarget(locator: Locator): Promise<void> {
  await expect(locator).toBeVisible();
  const bounds = await locator.boundingBox();
  expect(bounds, "interactive control must have layout bounds").not.toBeNull();
  expect(bounds!.height).toBeGreaterThanOrEqual(44);
  expect(bounds!.width).toBeGreaterThanOrEqual(44);
}

async function fulfillJson(route: Route, value: unknown, status = 200): Promise<void> {
  await route.fulfill({ status, contentType: "application/json", body: JSON.stringify(value) });
}

function evidenceRecord(payload: ImportedPayload): Record<string, unknown> {
  return payload.evidence as Record<string, unknown>;
}

function evidenceRow(dialog: Locator, label: string): Locator {
  return dialog.locator("dl > div").filter({ hasText: label });
}

function productAlert(page: Page): Locator {
  return page.getByTestId("protection-product").getByRole("alert");
}

function recursivelyCollectedKeys(value: unknown, keys = new Set<string>()): Set<string> {
  if (Array.isArray(value)) {
    for (const item of value) recursivelyCollectedKeys(item, keys);
  } else if (value !== null && typeof value === "object") {
    for (const [key, nested] of Object.entries(value)) {
      keys.add(key);
      recursivelyCollectedKeys(nested, keys);
    }
  }
  return keys;
}

test.describe("public discovery and fixed product viewport", () => {
  for (const viewport of [
    { name: "desktop", width: 1280, height: 900 },
    { name: "mobile", width: 390, height: 844 },
  ] as const) {
    test(`landing exposes Conflicting Pledge Protection on ${viewport.name}`, async ({ page }, testInfo) => {
      await page.setViewportSize(viewport);
      await page.goto("/");

      const truthBoundary = page.getByRole("region", { name: "MVP evidence and execution boundaries" });
      await expectAboveFold(page, truthBoundary);
      await expect(truthBoundary).toContainText("Cleanverse / Monad testnet asset identity is retained real evidence");
      await expect(truthBoundary).toContainText("BGV runs locally off-chain on synthetic lender pledge fixtures");
      await expect(truthBoundary).toContainText("recourse is a local protocol double, not live settlement");
      await expect(truthBoundary).toContainText("designated decryptor is trusted");

      const publicNavigation = page.getByRole("navigation", { name: "Public navigation" });
      const protectionLink = publicNavigation.getByRole("link", { name: /Protection/u });
      await expectMinimumTarget(protectionLink);
      await expect(page.getByRole("link", { name: "Open Conflicting Pledge Protection" })).toHaveAttribute(
        "href",
        "/protection?scenario=conflict",
      );
      await expectNoHorizontalOverflow(page);
      await page.screenshot({ path: testInfo.outputPath(`landing-${viewport.name}.png`), fullPage: true });

      await protectionLink.click();
      await expect(page).toHaveURL(/\/protection\?scenario=conflict$/u);
      await expect(page.getByRole("heading", { name: /Protect MINV01 from conflicting pledges/u })).toBeVisible();
    });
  }

  for (const viewport of [
    { name: "desktop", width: 1280, height: 900 },
    { name: "tablet", width: 768, height: 1024 },
    { name: "mobile", width: 390, height: 844 },
    { name: "narrow-mobile", width: 320, height: 740 },
  ] as const) {
    test(`protection page reflows at ${viewport.width}px`, async ({ page }, testInfo) => {
      await page.setViewportSize(viewport);
      await page.goto("/protection?scenario=conflict");
      await expect(page.getByText("Conflict confirmed", { exact: true })).toBeVisible();
      await expectAboveFold(page, page.getByRole("region", { name: "MVP evidence and execution boundaries" }));
      await expectNoHorizontalOverflow(page);

      await expectMinimumTarget(page.getByRole("button", { name: "Conflict", exact: true }));
      await expectMinimumTarget(page.getByRole("button", { name: "No conflict", exact: true }));
      await expectMinimumTarget(page.getByRole("button", { name: "Open complete evidence" }));
      await page.screenshot({ path: testInfo.outputPath(`protection-${viewport.name}.png`), fullPage: true });
    });
  }

  test("200 percent desktop zoom equivalent reflows without horizontal overflow", async ({ page }, testInfo) => {
    // At 200% browser zoom a 1280px physical viewport exposes 640 CSS pixels.
    // Driving that effective CSS viewport tests reflow without relying on a
    // headless-browser pinch scale, which would magnify without relayout.
    await page.setViewportSize({ width: 640, height: 900 });
    await page.goto("/protection?scenario=no-conflict");
    await expect(page.getByText("No conflict found", { exact: true })).toBeVisible();
    await expectNoHorizontalOverflow(page);
    await page.screenshot({ path: testInfo.outputPath("protection-200-percent-zoom.png"), fullPage: true });
  });
});

test.describe("imported evidence URL authority", () => {
  test("direct URLs, refresh, back and forward preserve the selected verified scenario", async ({ page }) => {
    await page.goto("/protection?scenario=conflict");
    await expect(page.getByText("Conflict confirmed", { exact: true })).toBeVisible();
    await expect(page.getByRole("button", { name: "Conflict", exact: true })).toHaveAttribute("aria-pressed", "true");

    await page.reload();
    await expect(page).toHaveURL(/scenario=conflict$/u);
    await expect(page.getByText("Conflict confirmed", { exact: true })).toBeVisible();

    await page.getByRole("button", { name: "No conflict", exact: true }).click();
    await expect(page).toHaveURL(/scenario=no-conflict$/u);
    await expect(page.getByText("No conflict found", { exact: true })).toBeVisible();
    await expect(page.getByText("Recourse refused — signed Boolean is false", { exact: true })).toBeVisible();

    await page.goBack();
    await expect(page).toHaveURL(/scenario=conflict$/u);
    await expect(page.getByText("Conflict confirmed", { exact: true })).toBeVisible();

    await page.goForward();
    await expect(page).toHaveURL(/scenario=no-conflict$/u);
    await expect(page.getByText("No conflict found", { exact: true })).toBeVisible();

    await page.reload();
    await expect(page.getByRole("button", { name: "No conflict", exact: true })).toHaveAttribute("aria-pressed", "true");
    await expect(page.getByText("No conflict found", { exact: true })).toBeVisible();
  });

  test("a rapid superseding selection cannot restore an aborted stale response", async ({ page, request }) => {
    const conflict = await importedPayload(request, "conflict");
    const noConflict = await importedPayload(request, "no-conflict");
    await page.goto("/protection?scenario=conflict");

    let slowResponseStarted = 0;
    await page.route(`**${IMPORTED_API}?scenario=*`, async (route) => {
      const scenario = new URL(route.request().url()).searchParams.get("scenario");
      if (scenario === "no-conflict") {
        slowResponseStarted += 1;
        await new Promise((resolve) => setTimeout(resolve, 300));
        await fulfillJson(route, noConflict).catch(() => undefined);
      } else {
        await fulfillJson(route, conflict);
      }
    });

    await page.getByRole("button", { name: "No conflict", exact: true }).click();
    await expect(page.getByTestId("protection-product")).toHaveAttribute("aria-busy", "true");
    await expect(page.getByTestId("case-loading-status")).toBeVisible();
    await expect(page.getByText("Conflict confirmed", { exact: true })).toHaveCount(0);
    await expect(page.getByRole("button", { name: "Evidence", exact: true })).toBeDisabled();

    await page.getByRole("button", { name: "Conflict", exact: true }).click();
    await expect(page).toHaveURL(/scenario=conflict$/u);
    await expect(page.getByText("Conflict confirmed", { exact: true })).toBeVisible();
    await expect(page.getByTestId("protection-product")).toHaveAttribute("aria-busy", "false");
    await page.waitForTimeout(450);
    await expect(page.getByText("Conflict confirmed", { exact: true })).toBeVisible();
    await expect(page.getByText("No conflict found", { exact: true })).toHaveCount(0);
    expect(slowResponseStarted).toBe(1);
  });

  test("failed loading clears old authority and a later valid selection succeeds without fallback", async ({ page }) => {
    await page.goto("/protection?scenario=conflict");
    await page.route(`**${IMPORTED_API}?scenario=no-conflict`, async (route) => {
      await fulfillJson(route, { error: "Verified evidence store unavailable" }, 503);
    });

    await page.getByRole("button", { name: "No conflict", exact: true }).click();
    await expect(productAlert(page)).toHaveText("Verified evidence store unavailable");
    await expect(page.getByText("Conflict confirmed", { exact: true })).toHaveCount(0);
    await expect(page.getByTestId("case-loading-status")).toContainText("Verified case unavailable");
    await expect(page.getByRole("button", { name: "Evidence", exact: true })).toBeDisabled();

    await page.unroute(`**${IMPORTED_API}?scenario=no-conflict`);
    await page.getByRole("button", { name: "No conflict", exact: true }).click();
    await expect(page.getByText("No conflict found", { exact: true })).toBeVisible();
    await expect(productAlert(page)).toHaveCount(0);
  });

  test("malformed and scenario-mismatched responses never become case authority", async ({ page, request }) => {
    const conflict = await importedPayload(request, "conflict");
    await page.goto("/protection?scenario=conflict");

    await page.route(`**${IMPORTED_API}?scenario=no-conflict`, async (route) => {
      await fulfillJson(route, {
        schemaVersion: "mordant.protection-imported-view/1",
        presentation: "IMPORTED_COMPLETED_EVIDENCE",
        evidence: { scenario: "no-conflict" },
      });
    }, { times: 1 });
    await page.getByRole("button", { name: "No conflict", exact: true }).click();
    await expect(productAlert(page)).toHaveText("Verified evidence did not match the requested scenario.");
    await expect(page.getByText("Conflict confirmed", { exact: true })).toHaveCount(0);

    await page.route(`**${IMPORTED_API}?scenario=no-conflict`, async (route) => {
      await fulfillJson(route, conflict);
    }, { times: 1 });
    await page.getByRole("button", { name: "No conflict", exact: true }).click();
    await expect(productAlert(page)).toHaveText("Verified evidence did not match the requested scenario.");
    await expect(page.getByText("No conflict found", { exact: true })).toHaveCount(0);
    await expect(page.getByTestId("case-loading-status")).toBeVisible();
  });

  test("malformed URL state fails closed instead of falling back to conflict evidence", async ({ page }) => {
    await page.goto("/protection?scenario=unknown");
    await expect(productAlert(page)).toHaveText(
      "The protection scenario URL is invalid. Choose Conflict or No conflict.",
    );
    await expect(page.getByText("Conflict confirmed", { exact: true })).toHaveCount(0);
    await expect(page.getByTestId("case-loading-status")).toContainText("Verified case unavailable");

    await page.goto("/protection?runId=30ef645f-8047-45ee-8b7c-19952a54555f");
    await expect(productAlert(page)).toHaveText(
      "The durable local run URL is invalid. A run requires its validated scenario and run identifier.",
    );
    await expect(page.getByText("Conflict confirmed", { exact: true })).toHaveCount(0);

    await page.goto("/protection?scenario=conflict&scenario=no-conflict");
    await expect(productAlert(page)).toHaveText(
      "The protection scenario URL is invalid. Choose Conflict or No conflict.",
    );
    await expect(page.getByText("Conflict confirmed", { exact: true })).toHaveCount(0);

    await page.goto("/protection?scenario=conflict&unexpected=1");
    await expect(productAlert(page)).toHaveText(
      "The protection scenario URL is invalid. Choose Conflict or No conflict.",
    );
    await expect(page.getByText("Conflict confirmed", { exact: true })).toHaveCount(0);

    await page.goto("/protection?scenario=conflict&runId=NOT-A-CANONICAL-UUID");
    await expect(productAlert(page)).toHaveText(
      "The durable local run URL is invalid. A run requires its validated scenario and run identifier.",
    );
    await expect(page.getByText("Conflict confirmed", { exact: true })).toHaveCount(0);
  });
});

test.describe("verified public projection and evidence dialog", () => {
  test("API, HTML, RSC and mounted React omit raw execution records", async ({ page, request }) => {
    const apiResponse = await request.get(`${IMPORTED_API}?scenario=conflict`);
    const htmlResponse = await request.get("/protection?scenario=conflict");
    const rscResponse = await request.get("/protection?scenario=conflict", {
      headers: { RSC: "1", "Next-Url": "/protection?scenario=conflict" },
    });
    expect(apiResponse.ok()).toBeTruthy();
    expect(htmlResponse.ok()).toBeTruthy();
    expect(rscResponse.ok()).toBeTruthy();

    const api = await apiResponse.json() as unknown;
    const forbiddenKeys = [
      "caseAuthorization",
      "governedFheEvidence",
      "participantPublicIdentities",
      "evidenceReferences",
      "resultCiphertext",
      "evaluatorProvenance",
      "decryptorProvenance",
      "privateArtifactBytes",
      "ciphertextBytes",
      "artifactBytes",
      "evidencePath",
      "workingDirectory",
      "command",
    ];
    const apiKeys = recursivelyCollectedKeys(api);
    for (const key of forbiddenKeys) expect(apiKeys, `API leaked ${key}`).not.toContain(key);

    const serializedSurfaces = [await htmlResponse.text(), await rscResponse.text()];
    for (const surface of serializedSurfaces) {
      expect(surface).not.toContain("result-conflict.bin");
      for (const key of forbiddenKeys) expect(surface).not.toContain(`\"${key}\"`);
    }

    await page.goto("/protection?scenario=conflict");
    expect(await page.locator("body").innerHTML()).not.toContain("result-conflict.bin");
    await expect(page.getByText("Conflict confirmed", { exact: true })).toBeVisible();
  });

  test("conflict evidence is a named modal dialog with trapped focus, exact copy, dismissal and focus return", async ({ page, request, context }) => {
    const payload = await importedPayload(request, "conflict");
    const evidence = evidenceRecord(payload);
    const sourceCommit = evidence.sourceCommit as string;
    const manifestDigest = evidence.manifestDigest as string;
    const governedResult = evidence.governedResult as Record<string, unknown>;
    const recourse = evidence.recourse as Record<string, unknown>;

    await page.goto("/protection?scenario=conflict");
    await context.grantPermissions(["clipboard-read", "clipboard-write"], { origin: new URL(page.url()).origin });
    const trigger = page.getByRole("button", { name: "Open complete evidence" });
    await trigger.click();

    const dialog = page.getByRole("dialog", { name: "Case evidence" });
    await expect(dialog).toBeVisible();
    await expect(dialog).toHaveAccessibleDescription(/Only the verified public projection is shown/u);
    await expect(page.locator("[inert]")).toHaveCount(1);
    const close = dialog.getByRole("button", { name: "Close evidence drawer" });
    await expect(close).toBeFocused();

    await page.keyboard.press("Shift+Tab");
    await expect(dialog.locator("button").last()).toBeFocused();
    await page.keyboard.press("Tab");
    await expect(close).toBeFocused();

    await expect(evidenceRow(dialog, "Source commit").locator("code")).toHaveText(sourceCommit);
    await expect(evidenceRow(dialog, "Governed-result digest").locator("code")).toHaveText(governedResult.digest as string);
    await expect(evidenceRow(dialog, "Recourse-record digest").locator("code")).toHaveText(recourse.recordDigest as string);
    await expect(evidenceRow(dialog, "Protection evidence manifest").locator("code")).toHaveText(manifestDigest);

    const copyManifest = dialog.getByRole("button", { name: "Copy Protection evidence manifest" });
    await copyManifest.click();
    await expect(copyManifest).toHaveText("Copied");
    await expect.poll(() => page.evaluate(() => navigator.clipboard.readText())).toBe(manifestDigest);

    await page.keyboard.press("Escape");
    await expect(dialog).toHaveCount(0);
    await expect(trigger).toBeFocused();

    await trigger.click();
    await page.getByTestId("evidence-backdrop").dispatchEvent("mousedown", { button: 0 });
    await expect(page.getByRole("dialog", { name: "Case evidence" })).toHaveCount(0);
    await expect(trigger).toBeFocused();

    const navigationTrigger = page.getByRole("button", { name: "Evidence", exact: true });
    await navigationTrigger.click();
    await expect(page.getByRole("dialog", { name: "Case evidence" })).toBeVisible();
    await expect(page.getByRole("button", { name: "Close evidence drawer" })).toBeFocused();
    await page.getByRole("button", { name: "Close evidence drawer" }).click();
    await expect(navigationTrigger).toBeFocused();
  });

  test("signed false evidence explicitly refuses recourse and exposes no invented record digest", async ({ page }) => {
    await page.goto("/protection?scenario=no-conflict");
    await expect(page.getByText("Recourse refused — signed Boolean is false", { exact: true })).toBeVisible();
    await page.getByRole("button", { name: "Open complete evidence" }).click();

    const dialog = page.getByRole("dialog", { name: "Case evidence" });
    const row = evidenceRow(dialog, "Recourse-record digest");
    await expect(row).toContainText("ABSENT — signed false Boolean refused recourse; no recourse record was created.");
    await expect(row.getByRole("button", { name: "Copy Recourse-record digest" })).toHaveCount(0);
    await expect(evidenceRow(dialog, "Governed-result reference in recourse")).toContainText(
      "ABSENT — no recourse record references a governed result.",
    );
  });
});

async function currentLocalOperation(page: Page): Promise<{ label: typeof LOCAL_OPERATION_LABELS[number]; button: Locator } | null> {
  for (const label of LOCAL_OPERATION_LABELS) {
    const button = page.getByRole("button", { name: label, exact: true });
    if (await button.count() > 0 && await button.first().isVisible()) return { label, button: button.first() };
  }
  return null;
}

async function completeEvidenceReady(page: Page): Promise<boolean> {
  const button = page.getByRole("button", { name: "Open complete evidence" });
  return await button.count() > 0 && await button.first().isEnabled();
}

async function pollGetOnlyUntilLiveOperationSettles(page: Page, durableURL: string): Promise<void> {
  await expect.poll(async () => {
    await page.reload({ waitUntil: "domcontentloaded" });
    await expect(page).toHaveURL(durableURL);
    await expect(page.getByTestId("protection-product")).toHaveAttribute("aria-busy", "false", { timeout: 20_000 });
    if (await completeEvidenceReady(page)) return "ready";
    if (await currentLocalOperation(page) !== null) return "ready";
    const alert = productAlert(page);
    if (await alert.count() > 0) {
      const text = await alert.textContent();
      if (text?.includes("operation is still running")) return "waiting";
      throw new Error(`Unexpected durable readback error: ${text ?? "unknown"}`);
    }
    if (await page.getByText("ABORTED", { exact: true }).count() > 0) {
      throw new Error("Live evaluation refresh produced an ABORTED durable run");
    }
    return "waiting";
  }, { timeout: 360_000, intervals: [500, 1_000, 2_000, 5_000] }).toBe("ready");
}

async function runCurrentOperation(page: Page, label: string): Promise<void> {
  const root = page.getByTestId("protection-product");
  const button = page.getByRole("button", { name: label, exact: true });
  await expect(button).toBeEnabled({ timeout: 30_000 });
  const issued = page.waitForRequest((request) => (
    request.method() === "POST" && request.url().endsWith("/protection")
  ), { timeout: 30_000 });
  const completed = page.waitForResponse((response) => (
    response.request().method() === "POST" && response.url().endsWith("/protection")
  ), { timeout: 360_000 });
  await button.click({ timeout: 30_000 });
  await issued;
  const response = await completed;
  expect(response.ok(), `${label} adapter response must succeed`).toBeTruthy();
  await expect(root).toHaveAttribute("aria-busy", "false", { timeout: 360_000 });
  await expect(productAlert(page)).toHaveCount(0);
}

async function completeRealJourney(
  page: Page,
  scenario: ProductScenario,
  interrupt: boolean,
  testInfo: TestInfo,
): Promise<void> {
  const expectedOutcome = scenario === "conflict" ? "Conflict confirmed" : "No conflict found";
  const observedOperations: string[] = [];
  page.on("request", (request) => {
    if (request.method() !== "POST" || !request.url().endsWith("/protection")) return;
    try {
      const body = request.postDataJSON() as { operation?: unknown };
      if (typeof body.operation === "string") observedOperations.push(body.operation);
    } catch {
      // The assertion below covers only exact JSON operation requests.
    }
  });

  await page.goto(`/protection?scenario=${scenario}`);
  const localStart = page.getByRole("button", { name: "Run this case locally" });
  await expect(localStart, "real-local opt-in must expose the loopback adapter control").toBeVisible();
  const created = page.waitForResponse((response) => (
    response.request().method() === "POST" && response.url().endsWith("/protection")
  ), { timeout: 60_000 });
  await localStart.click();
  expect((await created).ok(), "local case creation adapter response must succeed").toBeTruthy();
  await expect(page.getByTestId("protection-product")).toHaveAttribute("aria-busy", "false", { timeout: 60_000 });
  await expect(page).toHaveURL(/scenario=(conflict|no-conflict)&runId=[0-9a-f-]{36}$/u);
  const durableURL = page.url();
  const durableRunId = new URL(durableURL).searchParams.get("runId");
  expect(durableRunId).toMatch(/^[0-9a-f-]{36}$/u);

  let interruptedLabel: string | null = null;
  for (let guard = 0; guard < 12; guard += 1) {
    if (await completeEvidenceReady(page)) break;
    const operation = await currentLocalOperation(page);
    expect(operation, "a durable non-terminal run must expose exactly its next fixed operation").not.toBeNull();

    if (interrupt && interruptedLabel === null && operation!.label === "Evaluate private conflict") {
      interruptedLabel = operation!.label;
      const issued = page.waitForRequest((request) => {
        if (request.method() !== "POST" || !request.url().endsWith("/protection")) return false;
        try {
          return (request.postDataJSON() as { operation?: string }).operation === "evaluatePrivateConflict";
        } catch {
          return false;
        }
      });
      await operation!.button.click();
      await issued;
      await page.reload({ waitUntil: "domcontentloaded" });
      await expect(page).toHaveURL(durableURL);
      await pollGetOnlyUntilLiveOperationSettles(page, durableURL);
      await expect(page).toHaveURL(durableURL);

      const afterResume = await currentLocalOperation(page);
      if (afterResume?.label === interruptedLabel) {
        // Durable readback says the interrupted operation did not commit. Retry
        // that exact operation once; never guess or skip to another stage.
        await runCurrentOperation(page, afterResume.label);
      }
      continue;
    }

    await runCurrentOperation(page, operation!.label);
    if (operation!.label === "Verify and release Boolean" || operation!.label === "Apply governed result") {
      await expect(page.getByTestId("provisional-product-state")).toBeVisible();
      const suffix = operation!.label === "Verify and release Boolean" ? "released" : "recourse";
      await page.screenshot({
        path: testInfo.outputPath(`${scenario}-${suffix}-provisional.png`),
        fullPage: true,
      });
    }
  }

  await expect(page.getByRole("button", { name: "Open complete evidence" })).toBeEnabled({ timeout: 360_000 });
  await expect(page.getByText(expectedOutcome, { exact: true })).toBeVisible();
  await expect(page).toHaveURL(durableURL);
  await expect(page.getByTestId("provisional-product-state")).toHaveCount(0);

  await page.reload();
  await expect(page).toHaveURL(durableURL);
  await expect(page.getByText(expectedOutcome, { exact: true })).toBeVisible({ timeout: 120_000 });
  await expect(page.getByRole("button", { name: "Open complete evidence" })).toBeEnabled();
  expect(new URL(page.url()).searchParams.get("runId")).toBe(durableRunId);

  const counts = new Map<string, number>();
  for (const operation of observedOperations) counts.set(operation, (counts.get(operation) ?? 0) + 1);
  for (const [operation, count] of counts) {
    expect(count, `${operation} must not be retried more than once`).toBeLessThanOrEqual(2);
  }
  if (interrupt) expect(interruptedLabel).toBe("Evaluate private conflict");
}

test.describe.serial("supervised loopback real-BGV browser journeys", () => {
  test.skip(!REAL_LOCAL, "Set MORDANT_RUN_REAL_PROTECTION_E2E=1 to start the loopback adapter and run real BGV journeys.");

  test("conflict reaches retained COMPLETE after interruption, refresh and durable exact retry", async ({ page }, testInfo) => {
    test.setTimeout(20 * 60_000);
    await completeRealJourney(page, "conflict", true, testInfo);
    await expect(page.getByText(
      "Simulated protocol clock · recourse would be available after cure",
      { exact: true },
    )).toBeVisible();
  });

  test("no-conflict reaches retained COMPLETE through the real governed release boundary", async ({ page }, testInfo) => {
    test.setTimeout(20 * 60_000);
    await completeRealJourney(page, "no-conflict", false, testInfo);
    await expect(page.getByText("Recourse refused — signed Boolean is false", { exact: true })).toBeVisible();
  });
});
