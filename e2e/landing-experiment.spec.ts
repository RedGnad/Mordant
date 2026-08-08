import { readFile } from "node:fs/promises";

import { expect, test, type Page, type Route } from "@playwright/test";

const WORKER_ORIGIN = "https://mordant-worker.test";
const HOLDER = "0x911F99f424D47F08a15fcC771e94dcc2f7252B02";
const RUN_ID = "a1b2c3d4-1234-4abc-8def-1234567890ab";
const OBSERVED_BLOCK = 51_500_321;
const DIGESTS = Object.freeze({
  asset: `sha256:${"1".repeat(64)}`,
  case: `sha256:${"2".repeat(64)}`,
  participantA: `sha256:${"3".repeat(64)}`,
  participantB: `sha256:${"4".repeat(64)}`,
  evaluated: `sha256:${"5".repeat(64)}`,
  governed: `sha256:${"6".repeat(64)}`,
});

type ClaimWindows = Readonly<{
  participantA: Readonly<{ activeFrom: number; activeUntil: number }>;
  participantB: Readonly<{ activeFrom: number; activeUntil: number }>;
}>;

function workerView(conflict: boolean | null): Record<string, unknown> {
  return {
    schemaVersion: "mordant.custom-supervised-protection-view/1",
    runId: RUN_ID,
    executionVariant: "CUSTOM_SUPERVISED",
    stage: conflict === null ? "EVALUATED" : "RELEASED",
    nextOperation: conflict === null ? "releaseGovernedResult" : null,
    terminalScenario: conflict === null ? null : conflict ? "conflict" : "no-conflict",
    protectionCase: {
      cleanverseAssetDigest: DIGESTS.asset,
      fheCaseId: DIGESTS.case,
      incidentState: conflict === null ? "EVALUATED" : conflict ? "CONFLICT_CONFIRMED" : "CLEARED",
      recourseState: conflict === null ? "NOT_OPEN" : conflict ? "CURE_WINDOW" : "REFUSED",
      cureDeadline: conflict ? "2026-08-08T12:00:00.000Z" : null,
    },
    participantArtifactDigests: {
      participantA: DIGESTS.participantA,
      participantB: DIGESTS.participantB,
    },
    evaluatedArtifactDigest: DIGESTS.evaluated,
    governedResult: conflict === null ? null : {
      conflict,
      digest: DIGESTS.governed,
      releaseMode: "governed-decryptor-v1",
    },
    recourse: conflict === null ? null : conflict
      ? { opened: true, reason: null }
      : { opened: false, reason: "SIGNED_RESULT_FALSE" },
    receipt: null,
  };
}

function envelope(conflict: boolean | null): Record<string, unknown> {
  return {
    schemaVersion: "mordant.live-worker/1",
    view: workerView(conflict),
    progress: conflict === null ? "Evaluation completed" : "Governed result released",
  };
}

async function fulfillWorker(route: Route, body: unknown, status = 200): Promise<void> {
  const origin = route.request().headers().origin ?? "http://127.0.0.1:3210";
  await route.fulfill({
    status,
    body: status === 204 ? "" : JSON.stringify(body),
    headers: {
      "access-control-allow-origin": origin,
      "access-control-allow-methods": "GET, POST, OPTIONS",
      "access-control-allow-headers": "authorization, content-type",
      "cache-control": "no-store",
      "content-type": "application/json; charset=utf-8",
      vary: "Origin",
    },
  });
}

type HarnessOptions = Readonly<{
  create?: (windows: ClaimWindows, ordinal: number) => Readonly<{ status?: number; body?: unknown }>;
  read?: () => unknown;
  tokenStatus?: number;
  tokenBody?: unknown;
}>;

async function installManagedHarness(page: Page, options: HarnessOptions = {}) {
  const submissions: ClaimWindows[] = [];
  const tokenHolders: string[] = [];

  await page.route("**/api/live-protection/token", async (route) => {
    const tokenRequest = route.request().postDataJSON() as { holderAddress?: string };
    if (typeof tokenRequest.holderAddress === "string") tokenHolders.push(tokenRequest.holderAddress);
    if (options.tokenStatus !== undefined && options.tokenStatus !== 200) {
      await route.fulfill({
        status: options.tokenStatus,
        contentType: "application/json",
        body: JSON.stringify(options.tokenBody ?? { error: "ineligible" }),
      });
      return;
    }
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(options.tokenBody ?? {
        schemaVersion: "mordant.live-launch-token/1",
        token: "deterministic-browser-only-token",
        expiresAt: Date.now() + 60_000,
        workerOrigin: WORKER_ORIGIN,
        eligibility: {
          schemaVersion: "mordant.ccp-eligibility/1",
          chainId: 10_143,
          validatorAddress: "0xaC7e5179C2C7f03f209136886c172eb34F161792",
          gateAddress: "0x3ffb28a13fd6dc372ae952f15b55263285d5a280",
          holderAddress: HOLDER,
          eligible: true,
          observedBlock: OBSERVED_BLOCK,
        },
      }),
    });
  });

  await page.route(`${WORKER_ORIGIN}/**`, async (route) => {
    if (route.request().method() === "OPTIONS") {
      await fulfillWorker(route, null, 204);
      return;
    }
    const url = new URL(route.request().url());
    if (route.request().method() === "POST" && url.pathname === "/v1/custom-cases") {
      const windows = route.request().postDataJSON() as ClaimWindows;
      submissions.push(windows);
      const response = options.create?.(windows, submissions.length) ?? { body: envelope(null) };
      await fulfillWorker(route, response.body ?? { error: "busy" }, response.status ?? 200);
      return;
    }
    if (route.request().method() === "GET" && url.pathname === `/v1/custom-cases/${RUN_ID}`) {
      await fulfillWorker(route, options.read?.() ?? envelope(true));
      return;
    }
    await fulfillWorker(route, { error: "unexpected deterministic route" }, 404);
  });

  return { submissions, tokenHolders };
}

async function expectNoHorizontalOverflow(page: Page): Promise<void> {
  const dimensions = await page.evaluate(() => ({
    client: document.documentElement.clientWidth,
    document: document.documentElement.scrollWidth,
    body: document.body.scrollWidth,
  }));
  expect(dimensions.document).toBeLessThanOrEqual(dimensions.client + 1);
  expect(dimensions.body).toBeLessThanOrEqual(dimensions.client + 1);
}

async function setWindows(page: Page, values: readonly [string, string, string, string]): Promise<void> {
  const ids = ["claim-a-from", "claim-a-until", "claim-b-from", "claim-b-until"] as const;
  for (const [index, id] of ids.entries()) await page.getByTestId(id).fill(values[index]);
}

test("editable claims accept both geometries without a browser-side judgement", async ({ page }, testInfo) => {
  const { submissions } = await installManagedHarness(page, {
    create: () => ({ status: 409, body: { error: "busy" } }),
  });
  await page.goto("/");

  const mini = page.getByTestId("mini-live-check");
  await expect(mini).toBeVisible();
  await setWindows(page, ["120", "420", "220", "520"]);
  await page.getByTestId("mini-run").click();
  await expect(page.getByTestId("mini-busy")).toBeVisible();
  expect(submissions[0]).toEqual({
    participantA: { activeFrom: 120, activeUntil: 420 },
    participantB: { activeFrom: 220, activeUntil: 520 },
  });

  await setWindows(page, ["120", "220", "320", "520"]);
  await page.getByTestId("mini-run").click();
  await expect.poll(() => submissions.length).toBe(2);
  expect(submissions[1]).toEqual({
    participantA: { activeFrom: 120, activeUntil: 220 },
    participantB: { activeFrom: 320, activeUntil: 520 },
  });

  await expect(mini.getByTestId("mini-verdict")).toHaveCount(0);
  await expect(mini).not.toContainText("Conflict confirmed");
  await expect(mini).not.toContainText("No conflict");
  await expect(mini).not.toContainText("overlap");
  if (["1280x800", "390x844"].includes(testInfo.project.name)) {
    await page.screenshot({ path: testInfo.outputPath("landing-editable.png"), fullPage: true });
  }
});

test("each claim is validated independently with the managed-product semantics", async ({ page }) => {
  await installManagedHarness(page);
  await page.goto("/");

  await setWindows(page, ["-1", "420", "220", "520"]);
  await page.getByTestId("mini-run").click();
  await expect(page.getByTestId("mini-live-check").getByRole("alert"))
    .toHaveText("Each bound must be a decimal whole number, zero or greater.");
  await expect(page.getByTestId("claim-a-from")).toHaveAttribute("aria-invalid", "true");
  await expect(page.getByTestId("claim-b-from")).toHaveAttribute("aria-invalid", "false");

  await setWindows(page, ["420", "420", "220", "520"]);
  await page.getByTestId("mini-run").click();
  await expect(page.getByTestId("mini-live-check").getByRole("alert"))
    .toHaveText("Financing claim A must start strictly before it ends.");
  await expect(page.getByTestId("claim-a-from")).toHaveAttribute("aria-invalid", "true");
  await expect(page.getByTestId("claim-a-until")).toHaveAttribute("aria-invalid", "true");
  await expect(page.getByTestId("claim-b-from")).toHaveAttribute("aria-invalid", "false");

  await setWindows(page, ["120", "420", "520", "520"]);
  await page.getByTestId("mini-run").click();
  await expect(page.getByTestId("mini-live-check").getByRole("alert"))
    .toHaveText("Financing claim B must start strictly before it ends.");
  await expect(page.getByTestId("claim-a-from")).toHaveAttribute("aria-invalid", "false");
  await expect(page.getByTestId("claim-b-from")).toHaveAttribute("aria-invalid", "true");
  await expect(page.getByTestId("claim-b-until")).toHaveAttribute("aria-invalid", "true");
});

test("real worker evidence appears, and no verdict exists before governed release", async ({ page }, testInfo) => {
  const { tokenHolders } = await installManagedHarness(page, {
    create: () => ({ body: envelope(null) }),
    read: () => envelope(true),
  });
  await page.goto("/");
  await page.getByTestId("mini-run").click();

  expect(tokenHolders).toEqual([HOLDER]);
  await expect(page.getByTestId("mini-run-identity")).toContainText(`observed at block ${OBSERVED_BLOCK}`);
  await expect(page.getByTestId("mini-run-identity")).toContainText("Fresh run · a1b2c3d4");
  await expect(page.getByRole("list", { name: "Execution phases" }))
    .toContainText("BGV evaluation completed");
  await expect(page.getByTestId("mini-verdict")).toHaveCount(0);
  await expect(page.getByTestId("mini-proof-strip")).toHaveCount(0);
  await expect(page.getByTestId("claim-a-from")).toBeDisabled();
  await expect(page.getByTestId("claim-a-from")).toHaveValue("120");
  await expect(page.getByTestId("claim-a-until")).toHaveValue("420");
  await expect(page.getByTestId("claim-b-from")).toHaveValue("220");
  await expect(page.getByTestId("claim-b-until")).toHaveValue("520");

  await expect(page.getByTestId("mini-verdict")).toHaveAttribute("data-verdict", "conflict", { timeout: 5_000 });
  await expect(page.getByTestId("mini-verdict")).toHaveText("Conflict confirmed");
  const proof = page.getByTestId("mini-proof-strip");
  await expect(proof).toContainText("A-Pass checked");
  await expect(proof).toContainText(`Block ${OBSERVED_BLOCK}`);
  await expect(proof).toContainText("BGV evaluation");
  await expect(proof).toContainText("Completed");
  await expect(proof).toContainText("Governed release");
  await expect(proof).toContainText("Elapsed");
  await expect(proof).toContainText("sha256:66666666");

  await expect(page.getByTestId("mini-status")).toContainText("establishes only that the submitted windows conflict");
  await expect(page.getByTestId("mini-status")).toContainText("policy and human review determine action owner, deadline");
  await expect(page.getByTestId("mini-status")).not.toContainText("names who is responsible");
  await expect(page.getByTestId("mini-to-verified-run")).toHaveAttribute("href", "/protection/verified-run");
  await expect(page.getByTestId("mini-to-verified-run")).toHaveText("Verify the completed on-chain recourse");
  await expect(page.getByTestId("mini-live-check")).toContainText("did not execute Monad or aUSDC settlement");
  await expect(page.getByTestId("mini-live-check")).toContainText("separate hardened two-wallet run");
  if (["1280x800", "390x844"].includes(testInfo.project.name)) {
    for (const section of [
      page.locator("#how"),
      page.getByRole("region", { name: "Verify the consequence, not a claim about it." }),
      page.locator("#boundaries"),
    ]) {
      await section.scrollIntoViewIfNeeded();
      await expect(section).toHaveAttribute("data-visible", "true");
    }
    await page.evaluate(() => window.scrollTo({ top: 0, behavior: "instant" }));
    await page.screenshot({ path: testInfo.outputPath("landing-governed-result.png"), fullPage: true });
  }
});

test("the cleared wording also comes only from governedResult.conflict", async ({ page }) => {
  await installManagedHarness(page, { create: () => ({ body: envelope(false) }) });
  await page.goto("/");
  await page.getByTestId("mini-run").click();
  await expect(page.getByTestId("mini-verdict")).toHaveAttribute("data-verdict", "no-conflict");
  await expect(page.getByTestId("mini-verdict")).toHaveText("No conflict");
  await expect(page.getByTestId("mini-status")).toContainText("establishes only that the submitted windows do not conflict");
  await expect(page.getByTestId("mini-status")).not.toContainText("assigns");
});

test("a restored managed run never reconstructs private geometry from defaults", async ({ page }) => {
  const { tokenHolders } = await installManagedHarness(page, { read: () => envelope(true) });
  await page.goto(`/protection/live?runId=${RUN_ID}`);

  const reveal = page.getByTestId("reveal");
  await expect(reveal).toContainText("Conflict confirmed");
  await expect(reveal.getByTestId("claim-timeline")).toHaveCount(0);
  await expect(reveal.getByTestId("managed-private-inputs-unavailable"))
    .toContainText("Private claim windows are not retained in this public projection.");
  await expect(page.locator("#live-aFrom, #live-aUntil, #live-bFrom, #live-bUntil")).toHaveCount(0);
  expect(tokenHolders).toEqual([]);
});

test("busy, eligibility refusal and malformed projections fail closed", async ({ page }) => {
  await installManagedHarness(page, { create: () => ({ status: 409 }) });
  await page.goto("/");
  await page.getByTestId("mini-run").click();
  await expect(page.getByTestId("mini-busy")).toBeVisible();
  await expect(page.getByTestId("mini-verdict")).toHaveCount(0);

  await page.unrouteAll({ behavior: "wait" });
  await installManagedHarness(page, { tokenStatus: 403 });
  await page.reload();
  await page.getByTestId("mini-run").click();
  await expect(page.getByTestId("mini-status")).toContainText("not eligible right now");
  await expect(page.getByTestId("mini-verdict")).toHaveCount(0);

  await page.unrouteAll({ behavior: "wait" });
  await installManagedHarness(page, { create: () => ({ body: { schemaVersion: "wrong" } }) });
  await page.reload();
  await page.getByTestId("mini-run").click();
  await expect(page.getByTestId("mini-status")).toContainText("execution response was rejected");
  await expect(page.getByTestId("mini-verdict")).toHaveCount(0);
});

test("the accepted scrollytelling is preserved, compiled and not mounted", async ({ page }) => {
  await installManagedHarness(page);
  await page.goto("/");
  await expect(page.getByRole("navigation", { name: "Transformation states" })).toHaveCount(0);

  const preserved = await readFile("src/components/preserved-scrollytelling.tsx", "utf8");
  for (const state of ["Stable", "Conflict", "Recourse", "Proof"]) expect(preserved).toContain(`label: "${state}"`);
  for (const mark of ["claimMarkPrimary", "claimMarkSatelliteOne", "claimMarkSatelliteTwo"]) {
    expect(preserved).toContain(`styles.${mark}`);
  }
  expect(preserved).toContain("TRANSFORMATION_SCROLL_THRESHOLDS");
  expect(preserved).toContain("window.addEventListener(\"scroll\"");
  expect(preserved).toContain("onClick={() => selectStep(index)}");
  expect(preserved).toContain("public-experience.module.css");
  expect(preserved).toContain("Policy-defined recourse becomes explicit.");
  expect(preserved).not.toContain("Responsibility becomes explicit.");

  const landing = await readFile("src/components/public-experience.tsx", "utf8");
  expect(landing).not.toContain("PreservedScrollytelling");
});

test("mobile, desktop, reduced motion and keyboard semantics remain usable", async ({ page }) => {
  await page.emulateMedia({ reducedMotion: "reduce" });
  await installManagedHarness(page, { create: () => ({ body: envelope(null) }) });
  await page.goto("/");

  for (const legend of ["Financing claim A", "Financing claim B"]) {
    await expect(page.getByRole("group", { name: legend })).toBeVisible();
  }
  for (const id of ["claim-a-from", "claim-a-until", "claim-b-from", "claim-b-until"] as const) {
    const bounds = await page.getByTestId(id).boundingBox();
    expect(bounds?.height).toBeGreaterThanOrEqual(44);
  }

  const integration = page.locator('[aria-label="Integration stages"]');
  const governed = integration.getByRole("button", { name: /Governed result/ });
  await governed.focus();
  await expect(governed).toHaveAttribute("aria-pressed", "true");

  await page.getByTestId("mini-run").click();
  await expect(page.locator("[class*='spinner']")).toBeVisible();
  expect(await page.locator("[class*='spinner']").evaluate((node) => getComputedStyle(node).animationName)).toBe("none");
  await expectNoHorizontalOverflow(page);
});
