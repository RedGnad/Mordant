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
const LOCAL_ADAPTER = `http://127.0.0.1:${process.env.MORDANT_LOCAL_ADAPTER_PORT ?? "43125"}/protection`;
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

async function fulfillAdapterJson(route: Route, value: unknown, status = 200): Promise<void> {
  const origin = route.request().headers().origin ?? "http://127.0.0.1:3112";
  await route.fulfill({
    status,
    body: JSON.stringify(value),
    headers: {
      "access-control-allow-origin": origin,
      "access-control-allow-methods": "GET, POST, OPTIONS",
      "access-control-allow-headers": "content-type",
      "cache-control": "no-store",
      "content-type": "application/json; charset=utf-8",
      vary: "Origin",
    },
  });
}

async function fulfillAdapterPreflight(route: Route): Promise<void> {
  const origin = route.request().headers().origin ?? "http://127.0.0.1:3112";
  await route.fulfill({
    status: 204,
    headers: {
      "access-control-allow-origin": origin,
      "access-control-allow-methods": "GET, POST, OPTIONS",
      "access-control-allow-headers": "content-type",
      "access-control-max-age": "600",
      vary: "Origin",
    },
  });
}

function evidenceRecord(payload: ImportedPayload): Record<string, unknown> {
  return payload.evidence as Record<string, unknown>;
}

function localCase(
  evidence: Record<string, unknown>,
  incidentState: "PRIVATE_MATCH_OPEN" | "EVALUATED" | "CONFLICT_CONFIRMED",
  recourseState: "NOT_OPEN" | "SIMULATED_AVAILABLE",
): Record<string, unknown> {
  return {
    ...(evidence.protectionCase as Record<string, unknown>),
    incidentState,
    cureDeadline: recourseState === "SIMULATED_AVAILABLE" ? "2026-08-04T00:00:00.000Z" : null,
    recourseState,
  };
}

function localView(
  runId: string,
  stage: string,
  nextOperation: string | null,
  protectionCase: Record<string, unknown>,
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    schemaVersion: "mordant.protection-product-view/1",
    runId,
    stage,
    nextOperation,
    protectionCase,
    participantArtifactDigests: { participantA: null, participantB: null },
    evaluatedArtifactDigest: null,
    governedResult: null,
    recourse: null,
    evidence: null,
    execution: {
      fhe: "REAL_BGV_FHE",
      deployment: "LOCAL_SINGLE_HOST",
      webPresentation: "PUBLIC_EVIDENCE_READBACK",
      recourse: "LOCAL_PROTOCOL_DOUBLE",
    },
    ...overrides,
  };
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

      // The compressed boundary section closes the landing and distinguishes
      // the fresh managed experiment from the separately retained settlement.
      const truthBoundary = page.getByRole("region", { name: "What this is, and what it is not." });
      await expect(truthBoundary).toBeVisible();
      await expect(truthBoundary).toContainText("MINV01 Cleanverse provenance and identity plus A-Pass eligibility");
      await expect(truthBoundary).toContainText("does not establish invoice authenticity, legal validity or enforceability");
      await expect(truthBoundary).toContainText("financing-claim windows are synthetic");
      await expect(truthBoundary).toContainText("separate hardened two-wallet run");
      await expect(truthBoundary).toContainText("does not settle aUSDC");
      await expect(truthBoundary).toContainText("not production authorized");
      await expect(truthBoundary).toContainText("designated decryptor governs release");

      // A judge must be able to reach the settled run from the landing itself.
      await expect(page.getByTestId("landing-to-verified-run")).toHaveAttribute("href", "/protection/verified-run");

      const publicNavigation = page.getByRole("navigation", { name: "Product navigation" });
      const protectionLink = publicNavigation.getByRole("link", { name: "Evidence" });
      await expectMinimumTarget(protectionLink);
      // The landing offers this route more than once by design. Every one of
      // them must reach the same evidence, so none is asserted in isolation.
      const evidenceLinks = page.getByRole("link", { name: "Inspect verified evidence" });
      await expect(evidenceLinks.first()).toBeVisible();
      const hrefs = await evidenceLinks.evaluateAll((nodes) => nodes.map((node) => node.getAttribute("href")));
      expect(hrefs.length).toBeGreaterThan(0);
      expect(new Set(hrefs)).toEqual(new Set(["/protection?scenario=conflict"]));
      await expectNoHorizontalOverflow(page);
      await page.screenshot({ path: testInfo.outputPath(`landing-${viewport.name}.png`), fullPage: true });

      await protectionLink.click();
      await expect(page).toHaveURL(/\/protection\?scenario=conflict$/u);
      await expect(page.getByRole("heading", { name: /Protect MINV01 from conflicting pledges/u })).toBeVisible();
    });
  }

  for (const viewport of [
    { width: 768, height: 600 },
    { width: 1024, height: 600 },
    { width: 1366, height: 600 },
  ] as const) {
    test(`primary protection CTAs remain at least 44px at ${viewport.width}x${viewport.height}`, async ({ page }) => {
      await page.setViewportSize(viewport);
      await page.goto("/protection?scenario=conflict");
      await expectMinimumTarget(page.getByRole("button", { name: "Conflict", exact: true }));
      await expectMinimumTarget(page.getByRole("button", { name: "No conflict", exact: true }));
      await expectMinimumTarget(page.getByRole("button", { name: "Run this case locally" }));
      await expectMinimumTarget(page.getByRole("button", { name: "Open complete evidence" }));
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
    await expect(page.getByText("No verified conclusion", { exact: true })).toBeVisible();
    await expect(page.getByText("Private check in progress", { exact: true })).toHaveCount(0);
    await expect(page.getByText("Verified retained public evidence is ready.", { exact: true })).toHaveCount(0);
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
    await expect(evidenceRow(dialog, "Evidence verification").locator("code")).toHaveText("VERIFIED");
    await expect(evidenceRow(dialog, "Final incident state").locator("code")).toHaveText("CONFLICT_CONFIRMED");
    await expect(evidenceRow(dialog, "Final recourse state").locator("code")).toHaveText("SIMULATED_AVAILABLE");
    await expect(evidenceRow(dialog, "Clock class").locator("code")).toHaveText("SIMULATED_PROTOCOL_CLOCK");
    await expect(evidenceRow(dialog, "Signature verification status").locator("code")).toHaveText(
      "VERIFIED — participant, governed-result and recourse-attestation signatures",
    );

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
    await expect(evidenceRow(dialog, "Evidence verification").locator("code")).toHaveText("VERIFIED");
    await expect(evidenceRow(dialog, "Final incident state").locator("code")).toHaveText("CLEARED");
    await expect(evidenceRow(dialog, "Final recourse state").locator("code")).toHaveText("REFUSED");
    await expect(evidenceRow(dialog, "Clock class").locator("code")).toHaveText("REAL_OBSERVED_CLOCK");
  });
});

test.describe("persisted browser recovery authority", () => {
  test("lost creation response re-enters through lookup and GET without a second create", async ({ page, request }) => {
    const evidence = evidenceRecord(await importedPayload(request, "conflict"));
    const runId = "77777777-7777-4777-8777-777777777777";
    const createdCase = localCase(evidence, "PRIVATE_MATCH_OPEN", "NOT_OPEN");
    const calls: string[] = [];
    let creationRequestId: string | null = null;

    await page.route(`${LOCAL_ADAPTER}**`, async (route) => {
      const adapterRequest = route.request();
      if (adapterRequest.method() === "OPTIONS") return fulfillAdapterPreflight(route);
      const url = new URL(adapterRequest.url());
      if (adapterRequest.method() === "POST") {
        const body = adapterRequest.postDataJSON() as { intent: string; creationRequestId?: string };
        expect(body.intent).toBe("create");
        expect(body.creationRequestId).toMatch(/^[0-9a-f-]{36}$/u);
        creationRequestId = body.creationRequestId ?? null;
        calls.push("POST:create");
        await route.abort("connectionreset");
        return;
      }
      if (url.searchParams.has("creationRequestId")) {
        expect(url.searchParams.get("creationRequestId")).toBe(creationRequestId);
        calls.push("GET:creation");
      } else {
        expect(url.searchParams.get("runId")).toBe(runId);
        calls.push("GET:run");
      }
      await fulfillAdapterJson(route, localView(runId, "CASE_CREATED", "preparePrivateMatch", createdCase));
    });

    await page.goto("/protection?scenario=conflict");
    await page.getByRole("button", { name: "Run this case locally" }).click();
    await expect(page.getByTestId("case-loading-status")).toContainText("Creation recovery required");
    const stored = await page.evaluate(() => JSON.parse(sessionStorage.getItem(
      "mordant.protection.browser-recovery.v1",
    ) ?? "null") as Record<string, unknown> | null);
    expect(stored).toMatchObject({
      schemaVersion: "mordant.protection-browser-recovery/1",
      kind: "CREATION_PENDING",
      scenario: "conflict",
      creationRequestId,
    });
    expect(Object.keys(stored ?? {}).sort()).toEqual([
      "createdAtUnix", "creationRequestId", "expiresAtUnix", "kind", "scenario", "schemaVersion",
    ]);

    await page.goto("/");
    await page.goto("/protection?scenario=no-conflict");
    await expect(page).toHaveURL(new RegExp(`scenario=conflict&runId=${runId}$`, "u"));
    await expect(page.getByRole("button", { name: "Prepare private match" })).toBeVisible();
    expect(calls).toEqual(["POST:create", "GET:creation", "GET:run"]);
    expect(await page.evaluate(() => sessionStorage.getItem("mordant.protection.browser-recovery.v1"))).toBeNull();
  });

  test("lost mutation response survives reload and resumes with one GET and no mutation replay", async ({ page, request }) => {
    const evidence = evidenceRecord(await importedPayload(request, "conflict"));
    const runId = "88888888-8888-4888-8888-888888888888";
    const beforeEvaluation = localCase(evidence, "PRIVATE_MATCH_OPEN", "NOT_OPEN");
    const afterEvaluation = localCase(evidence, "EVALUATED", "NOT_OPEN");
    const calls: string[] = [];

    await page.route(`${LOCAL_ADAPTER}**`, async (route) => {
      const adapterRequest = route.request();
      if (adapterRequest.method() === "OPTIONS") return fulfillAdapterPreflight(route);
      if (adapterRequest.method() === "GET") {
        calls.push("GET");
        return fulfillAdapterJson(route, localView(runId, "EVALUATED", "releaseGovernedResult", afterEvaluation, {
          evaluatedArtifactDigest: (evidence.fhe as Record<string, unknown>).evaluatedArtifactDigest,
        }));
      }
      const body = adapterRequest.postDataJSON() as { intent: string; operation?: string };
      if (body.intent === "create") {
        calls.push("POST:create");
        return fulfillAdapterJson(route, localView(
          runId, "PARTICIPANT_B_SUBMITTED", "evaluatePrivateConflict", beforeEvaluation,
        ));
      }
      expect(body.operation).toBe("evaluatePrivateConflict");
      calls.push("POST:evaluatePrivateConflict");
      await route.abort("connectionreset");
    });

    await page.goto("/protection?scenario=conflict");
    await page.getByRole("button", { name: "Run this case locally" }).click();
    await page.getByRole("button", { name: "Evaluate private conflict" }).click();
    await expect(page.getByTestId("durable-readback-required")).toContainText("evaluatePrivateConflict");
    await page.reload();
    await expect(page.getByRole("button", { name: "Verify and release Boolean" })).toBeVisible();
    expect(calls).toEqual(["POST:create", "POST:evaluatePrivateConflict", "GET"]);
    expect(await page.evaluate(() => sessionStorage.getItem("mordant.protection.browser-recovery.v1"))).toBeNull();
  });

  test("export interruption exposes only fixed retention recovery and then GETs COMPLETE", async ({ page, request }) => {
    const imported = evidenceRecord(await importedPayload(request, "conflict"));
    const runId = "99999999-9999-4999-8999-999999999999";
    const completeCase = localCase(imported, "CONFLICT_CONFIRMED", "SIMULATED_AVAILABLE");
    const localEvidence = { ...imported, runId };
    const calls: string[] = [];
    let getCount = 0;

    await page.route(`${LOCAL_ADAPTER}**`, async (route) => {
      const adapterRequest = route.request();
      if (adapterRequest.method() === "OPTIONS") return fulfillAdapterPreflight(route);
      if (adapterRequest.method() === "GET") {
        getCount += 1;
        calls.push(`GET:${getCount}`);
        if (getCount === 1) return fulfillAdapterJson(route, {
          schemaVersion: "mordant.protection-retention-required/1",
          status: "RETENTION_REQUIRED",
          runId,
          scenario: "conflict",
          recoveryOperation: "retainProtectionEvidence",
        });
        return fulfillAdapterJson(route, localView(runId, "COMPLETE", null, completeCase, {
          governedResult: {
            conflict: true,
            digest: (imported.governedResult as Record<string, unknown>).digest,
            releaseMode: "governed-decryptor-v1",
          },
          recourse: { opened: true, reason: null },
          evidence: localEvidence,
        }));
      }
      const body = adapterRequest.postDataJSON() as { intent: string; operation?: string };
      if (body.intent === "create") {
        calls.push("POST:create");
        return fulfillAdapterJson(route, localView(
          runId, "CHRONOLOGY_COMPLETE", "exportProtectionEvidence", completeCase,
        ));
      }
      if (body.operation === "exportProtectionEvidence") {
        calls.push("POST:exportProtectionEvidence");
        await route.abort("connectionreset");
        return;
      }
      expect(body.operation).toBe("retainProtectionEvidence");
      calls.push("POST:retainProtectionEvidence");
      return fulfillAdapterJson(route, {
        schemaVersion: "mordant.retained-protection-view/1",
        runId,
        scenario: "conflict",
        caseId: (imported.fhe as Record<string, unknown>).caseId,
        manifestDigest: imported.manifestDigest,
        evidence: localEvidence,
      });
    });

    await page.goto("/protection?scenario=conflict");
    await page.getByRole("button", { name: "Run this case locally" }).click();
    await page.getByRole("button", { name: "Seal public evidence" }).click();
    await expect(page.getByTestId("durable-readback-required")).toContainText("exportProtectionEvidence");
    await page.getByRole("button", { name: "Resume durable run" }).click();
    await expect(page.getByTestId("case-loading-status")).toContainText("Evidence retention required");
    await expect(page.getByRole("button", { name: "Finish evidence retention" })).toBeEnabled();
    await expect(page.getByRole("button", { name: "Seal public evidence" })).toHaveCount(0);
    expect(await page.evaluate(() => JSON.parse(sessionStorage.getItem(
      "mordant.protection.browser-recovery.v1",
    ) ?? "null") as Record<string, unknown> | null)).toMatchObject({
      kind: "RETENTION_REQUIRED",
      scenario: "conflict",
      runId,
      operation: "retainProtectionEvidence",
    });

    await page.getByRole("button", { name: "Finish evidence retention" }).click();
    await expect(page.getByRole("button", { name: "Open complete evidence" })).toBeEnabled();
    await expect(page.getByText("Conflict confirmed", { exact: true })).toBeVisible();
    expect(calls).toEqual([
      "POST:create",
      "POST:exportProtectionEvidence",
      "GET:1",
      "POST:retainProtectionEvidence",
      "GET:2",
    ]);
    expect(calls.filter((call) => call === "POST:exportProtectionEvidence")).toHaveLength(1);
    expect(calls.filter((call) => call === "POST:retainProtectionEvidence")).toHaveLength(1);
    await expect(page.locator("body")).not.toContainText("ABORTED");
  });
});

test.describe("uncertain mutation durable readback barrier", () => {
  test("an aborted evaluation response blocks mutations and Back until GET-only durable replacement", async ({ page, request }) => {
    const evidence = evidenceRecord(await importedPayload(request, "conflict"));
    const runId = "44444444-4444-4444-8444-444444444444";
    const beforeEvaluation = localCase(evidence, "PRIVATE_MATCH_OPEN", "NOT_OPEN");
    const afterEvaluation = localCase(evidence, "EVALUATED", "NOT_OPEN");
    const calls: { method: string; operation: string | null }[] = [];
    let readbacks = 0;

    await page.route(`${LOCAL_ADAPTER}**`, async (route) => {
      const request = route.request();
      if (request.method() === "OPTIONS") return fulfillAdapterPreflight(route);
      if (request.method() === "GET") {
        calls.push({ method: "GET", operation: null });
        readbacks += 1;
        if (readbacks === 1) {
          return fulfillAdapterJson(route, { error: "OPERATION_STILL_RUNNING_AFTER_DISPATCH" }, 423);
        }
        return fulfillAdapterJson(route, localView(runId, "EVALUATED", "releaseGovernedResult", afterEvaluation, {
          evaluatedArtifactDigest: (evidence.fhe as Record<string, unknown>).evaluatedArtifactDigest,
        }));
      }
      const body = request.postDataJSON() as { intent: string; operation?: string };
      calls.push({ method: "POST", operation: body.operation ?? "create" });
      if (body.intent === "create") {
        return fulfillAdapterJson(route, localView(
          runId,
          "PARTICIPANT_B_SUBMITTED",
          "evaluatePrivateConflict",
          beforeEvaluation,
        ));
      }
      expect(body.operation).toBe("evaluatePrivateConflict");
      await route.abort("connectionreset");
    });

    await page.goto("/protection?scenario=conflict");
    await page.getByRole("button", { name: "Run this case locally" }).click();
    await expect(page.getByRole("button", { name: "Evaluate private conflict" })).toBeVisible();
    const durableURL = page.url();
    await page.getByRole("button", { name: "Evaluate private conflict" }).click();

    await expect(page.getByTestId("protection-product")).toHaveAttribute("data-readback-required", "true");
    await expect(page.getByTestId("durable-readback-required")).toContainText("evaluatePrivateConflict");
    await expect(page.getByRole("button", { name: "Evaluate private conflict" })).toHaveCount(0);
    await expect(page.getByRole("button", { name: "Start a fresh local case" })).toBeDisabled();
    await expect(page.getByRole("button", { name: "Conflict", exact: true })).toBeDisabled();
    await expect(page.getByRole("button", { name: "No conflict", exact: true })).toBeDisabled();

    await page.evaluate(() => window.history.back());
    await expect(page).toHaveURL(durableURL);
    await expect(productAlert(page)).toHaveText("OPERATION_STILL_RUNNING_AFTER_DISPATCH");
    await expect(page.getByTestId("durable-readback-required")).toBeVisible();
    await expect(page.getByRole("button", { name: "Resume durable run" })).toBeEnabled();
    expect(calls.filter((call) => call.method === "POST" && call.operation === "evaluatePrivateConflict")).toHaveLength(1);

    await page.getByRole("button", { name: "Resume durable run" }).click();
    await expect(page.getByTestId("protection-product")).toHaveAttribute("data-readback-required", "false");
    await expect(page.getByTestId("durable-readback-required")).toHaveCount(0);
    await expect(page.getByRole("button", { name: "Verify and release Boolean" })).toBeVisible();
    await expect(page.getByRole("button", { name: "Evaluate private conflict" })).toHaveCount(0);
    expect(calls.map((call) => call.method)).toEqual(["POST", "POST", "GET", "GET"]);
  });

  test("an admitted governed-result release exposes only Resume until durable GET replacement", async ({ page, request }) => {
    const evidence = evidenceRecord(await importedPayload(request, "conflict"));
    const runId = "55555555-5555-4555-8555-555555555555";
    const evaluatedCase = localCase(evidence, "EVALUATED", "NOT_OPEN");
    const governedResult = evidence.governedResult as Record<string, unknown>;
    const result = {
      conflict: true,
      digest: governedResult.digest,
      releaseMode: "governed-decryptor-v1",
    };
    const calls: { method: string; operation: string | null }[] = [];
    let releaseDurablyAdmitted = false;

    await page.route(`${LOCAL_ADAPTER}**`, async (route) => {
      const request = route.request();
      if (request.method() === "OPTIONS") return fulfillAdapterPreflight(route);
      if (request.method() === "GET") {
        calls.push({ method: "GET", operation: null });
        expect(releaseDurablyAdmitted, "release must be durably admitted before response loss").toBeTruthy();
        return fulfillAdapterJson(route, localView(runId, "RELEASED", "openRecourseCase", evaluatedCase, {
          evaluatedArtifactDigest: (evidence.fhe as Record<string, unknown>).evaluatedArtifactDigest,
          governedResult: result,
        }));
      }
      const body = request.postDataJSON() as { intent: string; operation?: string };
      calls.push({ method: "POST", operation: body.operation ?? "create" });
      if (body.intent === "create") {
        return fulfillAdapterJson(route, localView(runId, "EVALUATED", "releaseGovernedResult", evaluatedCase, {
          evaluatedArtifactDigest: (evidence.fhe as Record<string, unknown>).evaluatedArtifactDigest,
        }));
      }
      expect(body.operation).toBe("releaseGovernedResult");
      releaseDurablyAdmitted = true;
      await route.abort("connectionreset");
    });

    await page.goto("/protection?scenario=conflict");
    await page.getByRole("button", { name: "Run this case locally" }).click();
    await expect(page.getByRole("button", { name: "Verify and release Boolean" })).toBeVisible();
    await page.getByRole("button", { name: "Verify and release Boolean" }).click();

    await expect(page.getByTestId("durable-readback-required")).toContainText("releaseGovernedResult");
    await expect(page.getByRole("button", { name: "Verify and release Boolean" })).toHaveCount(0);
    await expect(page.getByRole("button", { name: "Start a fresh local case" })).toBeDisabled();
    await expect(page.getByRole("button", { name: "Evidence", exact: true })).toBeDisabled();
    await page.getByRole("button", { name: "Resume durable run" }).click();

    await expect(page.getByTestId("durable-readback-required")).toHaveCount(0);
    await expect(page.getByRole("button", { name: "Verify and release Boolean" })).toHaveCount(0);
    await expect(page.getByRole("button", { name: "Apply governed result" })).toBeVisible();
    await expect(page.getByRole("button", { name: "Evidence", exact: true })).toBeDisabled();
    expect(calls.map((call) => call.method)).toEqual(["POST", "POST", "GET"]);
    expect(calls.filter((call) => call.operation === "releaseGovernedResult")).toHaveLength(1);
  });

  test("a durable URL remount keeps the barrier after 423 and unlocks only after a valid second GET", async ({ page, request }) => {
    const evidence = evidenceRecord(await importedPayload(request, "conflict"));
    const runId = "66666666-6666-4666-8666-666666666666";
    const durableCase = localCase(evidence, "EVALUATED", "NOT_OPEN");
    const calls: string[] = [];

    await page.route(`${LOCAL_ADAPTER}**`, async (route) => {
      const request = route.request();
      if (request.method() === "OPTIONS") return fulfillAdapterPreflight(route);
      expect(request.method()).toBe("GET");
      calls.push("GET");
      if (calls.length === 1) return fulfillAdapterJson(route, { error: "DURABLE_READBACK_STILL_RUNNING" }, 423);
      return fulfillAdapterJson(route, localView(runId, "EVALUATED", "releaseGovernedResult", durableCase, {
        evaluatedArtifactDigest: (evidence.fhe as Record<string, unknown>).evaluatedArtifactDigest,
      }));
    });

    await page.goto(`/protection?scenario=conflict&runId=${runId}`);
    await expect(productAlert(page)).toHaveText("DURABLE_READBACK_STILL_RUNNING");
    await expect(page.getByTestId("protection-product")).toHaveAttribute("data-readback-required", "true");
    await expect(page.getByTestId("durable-readback-required")).toContainText("UNKNOWN_AFTER_RELOAD");
    await expect(page.getByRole("button", { name: "Conflict", exact: true })).toBeDisabled();
    await expect(page.getByRole("button", { name: "No conflict", exact: true })).toBeDisabled();
    await expect(page.getByRole("button", { name: "Start a fresh local case" })).toBeDisabled();
    await expect(page.getByRole("button", { name: "Resume durable run" })).toBeEnabled();

    await page.getByRole("button", { name: "Resume durable run" }).click();
    await expect(page.getByTestId("protection-product")).toHaveAttribute("data-readback-required", "false");
    await expect(page.getByRole("button", { name: "Verify and release Boolean" })).toBeVisible();
    expect(calls).toEqual(["GET", "GET"]);
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
  let evaluationResponseLostAfterCompletion = false;
  if (interrupt) {
    await page.route(`${LOCAL_ADAPTER}**`, async (route) => {
      const request = route.request();
      if (request.method() !== "POST") return route.continue();
      try {
        const body = request.postDataJSON() as { operation?: string };
        if (body.operation !== "evaluatePrivateConflict") return route.continue();
      } catch {
        return route.continue();
      }
      const completed = await route.fetch({ timeout: 360_000 });
      expect(completed.ok(), "real evaluation must durably finish before its browser response is lost").toBeTruthy();
      evaluationResponseLostAfterCompletion = true;
      await route.abort("connectionreset");
    });
  }
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
      await operation!.button.click();
      await expect(page.getByTestId("durable-readback-required")).toContainText(
        "evaluatePrivateConflict",
        { timeout: 360_000 },
      );
      expect(evaluationResponseLostAfterCompletion).toBeTruthy();
      await expect(page).toHaveURL(durableURL);
      await page.getByRole("button", { name: "Resume durable run" }).click();
      await expect(page.getByTestId("durable-readback-required")).toHaveCount(0, { timeout: 120_000 });
      await expect(page.getByRole("button", { name: "Verify and release Boolean" })).toBeVisible();
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
  if (interrupt) {
    expect(interruptedLabel).toBe("Evaluate private conflict");
    expect(counts.get("evaluatePrivateConflict")).toBe(1);
    expect(evaluationResponseLostAfterCompletion).toBeTruthy();
  }
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
