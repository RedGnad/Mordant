import { readFile } from "node:fs/promises";

import { expect, test, type Page, type Route } from "@playwright/test";

const WORKER_ORIGIN = "https://mordant-worker.test";
const HOLDER = "0x911F99f424D47F08a15fcC771e94dcc2f7252B02";
const RUN_ID = "a1b2c3d4-1234-4abc-8def-1234567890ab";
const SECOND_RUN_ID = "e5f6a7b8-5678-4def-8abc-0987654321fe";
const OBSERVED_BLOCK = 51_500_321;
const DIGESTS = Object.freeze({
  asset: `sha256:${"1".repeat(64)}`,
  case: `sha256:${"2".repeat(64)}`,
  participantA: `sha256:${"3".repeat(64)}`,
  participantB: `sha256:${"4".repeat(64)}`,
  evaluated: `sha256:${"5".repeat(64)}`,
  governed: `sha256:${"6".repeat(64)}`,
  resultPolicy: "sha256:a9e039b95a56043532bcc1d7a8c1bb0086fc64d50adcb35ff54f54ee59fb6e65",
  policy: "sha256:a79e86e58de597a81d646c72434882ad60592d79fda0d6337dac4426932a225e",
  selection: `sha256:${"9".repeat(64)}`,
  plan: `sha256:${"a".repeat(64)}`,
});

type ClaimWindows = Readonly<{
  participantA: Readonly<{ activeFrom: number; activeUntil: number }>;
  participantB: Readonly<{ activeFrom: number; activeUntil: number }>;
}>;

function workerView(conflict: boolean | null, runId = RUN_ID): Record<string, unknown> {
  return {
    schemaVersion: "mordant.custom-supervised-protection-view/2",
    runId,
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
    governedPolicy: {
      selection: {
        schemaVersion: "mordant.governed-recourse-policy-selection/1",
        policyId: "mordant.managed-demo.facility-protection",
        policyVersion: 1,
        policyHash: DIGESTS.policy,
        caseId: DIGESTS.case,
        resultPolicyId: DIGESTS.resultPolicy,
        resultPolicyVersion: 1,
        selectedAtUnix: 1_700_000_000,
        selectionHash: DIGESTS.selection,
      },
      actionPlan: conflict === null ? null : {
        schemaVersion: "mordant.governed-action-plan/1",
        policyId: "mordant.managed-demo.facility-protection",
        policyVersion: 1,
        policyHash: DIGESTS.policy,
        policySelectionHash: DIGESTS.selection,
        resultDigest: DIGESTS.governed,
        resultOutcome: conflict ? "CONFLICT" : "NO_CONFLICT",
        resultSemantic: "CONFLICT_STATUS_ONLY",
        selectedGovernedAction: conflict ? "OPEN_LOCAL_CURE_PATH" : "RECORD_AND_CLOSE",
        actionOwner: "MORDANT_MANAGED_EXECUTION",
        cureWindowSeconds: conflict ? 86_400 : null,
        deadlineRule: conflict ? "STARTS_WHEN_LOCAL_CURE_PATH_OPENS" : "NOT_APPLICABLE",
        escalation: conflict ? "MANUAL_REVIEW_OUTSIDE_MANAGED_RUN" : "NONE",
        requiredApproval: "NONE_FOR_LOCAL_PROTOCOL_DOUBLE",
        actionClass: conflict ? "LOCAL_PROTOCOL_DOUBLE" : "EVIDENCE_ONLY",
        settlementAuthorization: "NOT_AUTHORIZED",
        planHash: DIGESTS.plan,
      },
      actionEvidence: null,
    },
  };
}

function envelope(conflict: boolean | null, runId = RUN_ID): Record<string, unknown> {
  return {
    schemaVersion: "mordant.live-worker/1",
    view: workerView(conflict, runId),
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
  read?: (runId: string) => unknown;
  tokenStatus?: number;
  tokenBody?: unknown;
  subsequentTokenGate?: Promise<void>;
}>;

async function installManagedHarness(page: Page, options: HarnessOptions = {}) {
  const submissions: ClaimWindows[] = [];
  const tokenHolders: string[] = [];

  await page.route("**/api/live-protection/token", async (route) => {
    const tokenRequest = route.request().postDataJSON() as { holderAddress?: string };
    if (typeof tokenRequest.holderAddress === "string") tokenHolders.push(tokenRequest.holderAddress);
    if (tokenHolders.length > 1 && options.subsequentTokenGate !== undefined) {
      await options.subsequentTokenGate;
    }
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
    if (route.request().method() === "GET" && url.pathname.startsWith("/v1/custom-cases/")) {
      const requestedRunId = url.pathname.slice("/v1/custom-cases/".length);
      await fulfillWorker(route, options.read?.(requestedRunId) ?? envelope(true, requestedRunId));
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
  await expect(mini.locator("[data-overlap], [data-conflict], [data-result]")).toHaveCount(0);
  if (["1280x800", "390x844"].includes(testInfo.project.name)) {
    await page.screenshot({ path: testInfo.outputPath("landing-editable.png"), fullPage: true });
  }
});

test("the neutral timeline and exact fields stay synchronized without interpreting geometry", async ({ page }, testInfo) => {
  const { submissions } = await installManagedHarness(page, {
    create: () => ({ status: 409, body: { error: "busy" } }),
  });
  await page.goto("/");

  const timeline = page.getByTestId("mini-claim-timeline");
  await expect(timeline).toContainText("Shared demo timeline · 0–600");
  await expect(timeline).toContainText("Each bar shows when a financing claim starts and ends.");
  await expect(timeline).not.toContainText("Placement only.");
  await expect(timeline).not.toContainText("browser never interprets the relationship");
  await expect(page.getByRole("slider")).toHaveCount(4);

  const aFrom = page.getByRole("slider", { name: "Financing claim A active from" });
  await expect(aFrom).toHaveAttribute("aria-valuenow", "120");
  await aFrom.press("ArrowRight");
  await expect(page.getByTestId("claim-a-from")).toHaveValue("140");
  await expect(aFrom).toHaveAttribute("aria-valuenow", "140");
  await aFrom.press("PageUp");
  await expect(page.getByTestId("claim-a-from")).toHaveValue("240");

  await aFrom.scrollIntoViewIfNeeded();
  const handleBounds = await aFrom.boundingBox();
  expect(handleBounds).not.toBeNull();
  if (handleBounds !== null) {
    const center = {
      x: handleBounds.x + handleBounds.width / 2,
      y: handleBounds.y + handleBounds.height / 2,
    };
    if (testInfo.project.use.hasTouch) {
      await aFrom.evaluate((handle, point) => {
        handle.dispatchEvent(new PointerEvent("pointerdown", {
          bubbles: true,
          buttons: 1,
          clientX: point.x,
          clientY: point.y,
          pointerId: 7,
          pointerType: "touch",
        }));
        window.dispatchEvent(new PointerEvent("pointermove", {
          bubbles: true,
          buttons: 1,
          clientX: point.x + 55,
          clientY: point.y,
          pointerId: 7,
          pointerType: "touch",
        }));
        window.dispatchEvent(new PointerEvent("pointerup", {
          bubbles: true,
          clientX: point.x + 55,
          clientY: point.y,
          pointerId: 7,
          pointerType: "touch",
        }));
      }, center);
    } else {
      await page.mouse.move(center.x, center.y);
      await page.mouse.down();
      await page.mouse.move(center.x + 55, center.y);
      await page.mouse.up();
    }
  }
  await expect(page.getByTestId("claim-a-from")).not.toHaveValue("240");
  await aFrom.press("Home");
  await expect(page.getByTestId("claim-a-from")).toHaveValue("0");

  await page.getByTestId("claim-b-until").fill("580");
  await expect(page.getByRole("slider", { name: "Financing claim B active until" }))
    .toHaveAttribute("aria-valuenow", "580");

  const bandStyles = await page.locator("[class*='timelineBand']").evaluateAll((bands) => bands.map((band) => ({
    background: getComputedStyle(band).backgroundColor,
    height: getComputedStyle(band).height,
  })));
  expect(bandStyles).toHaveLength(2);
  expect(bandStyles[0]).toEqual(bandStyles[1]);

  await page.getByTestId("mini-preset-two").click();
  await expect(page.getByTestId("claim-a-from")).toHaveValue("120");
  await expect(page.getByTestId("claim-a-until")).toHaveValue("220");
  await expect(page.getByTestId("claim-b-from")).toHaveValue("320");
  await expect(page.getByTestId("claim-b-until")).toHaveValue("520");
  expect(submissions).toHaveLength(0);
  await expect(page.getByTestId("mini-live-check")).not.toContainText("Conflict confirmed");
  await expect(page.getByTestId("mini-live-check")).not.toContainText("No conflict");
});

test("each claim is validated independently with the managed-product semantics", async ({ page }) => {
  await installManagedHarness(page);
  await page.goto("/");

  await setWindows(page, ["-1", "420", "220", "520"]);
  await page.getByTestId("mini-run").click();
  await expect(page.getByTestId("mini-live-check").getByRole("alert"))
    .toHaveText("Each bound must be a decimal whole number from 0 to 600.");
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

  await setWindows(page, ["120", "601", "220", "520"]);
  await page.getByTestId("mini-run").click();
  await expect(page.getByTestId("mini-live-check").getByRole("alert"))
    .toHaveText("Each bound must be a decimal whole number from 0 to 600.");
  await expect(page.getByTestId("claim-a-until")).toHaveAttribute("aria-invalid", "true");
});

test("real worker evidence appears, and no verdict exists before governed release", async ({ page }, testInfo) => {
  const { tokenHolders } = await installManagedHarness(page, {
    create: () => ({ body: envelope(null) }),
    read: () => envelope(true),
  });
  await page.goto("/");
  const miniPanel = page.getByTestId("mini-panel");
  const idlePanelHeight = await miniPanel.evaluate((node) => node.getBoundingClientRect().height);
  if (["1280x800", "390x844"].includes(testInfo.project.name)) {
    await miniPanel.screenshot({ path: testInfo.outputPath("mini-panel-idle.png") });
  }
  await page.getByTestId("mini-run").click();

  expect(tokenHolders).toEqual([HOLDER]);
  await expect(page.getByTestId("mini-run-identity")).toContainText(`observed at block ${OBSERVED_BLOCK}`);
  await expect(page.getByTestId("mini-run-identity")).toContainText("Fresh run · a1b2c3d4");
  await expect(page.getByRole("list", { name: "Execution phases" }))
    .toContainText("BGV evaluation completed");
  await expect(page.getByTestId("mini-verdict")).toHaveCount(0);
  await expect(page.getByTestId("mini-proof-details")).toHaveCount(0);
  await expect(miniPanel).toHaveAttribute("data-size-locked", "true");
  const runningPanelHeight = await miniPanel.evaluate((node) => node.getBoundingClientRect().height);
  expect(await miniPanel.evaluate((node) => node.scrollHeight - node.clientHeight)).toBeLessThanOrEqual(1);
  if (["1280x800", "390x844"].includes(testInfo.project.name)) {
    await miniPanel.screenshot({ path: testInfo.outputPath("mini-panel-running.png") });
  }
  const runningTimeline = page.getByTestId("mini-claim-timeline");
  await expect(runningTimeline).toBeVisible();
  await expect(runningTimeline).toHaveAttribute("data-private-check", "true");
  await expect(page.getByTestId("mini-timeline-privacy")).toContainText("Encrypted check in progress");
  await expect.poll(() => runningTimeline.locator("[class*='timelineContent']").evaluate((node) => (
    getComputedStyle(node).filter
  ))).toContain("blur(1.6px)");
  const privacyOptics = await runningTimeline.evaluate((timeline) => {
    const overlay = timeline.querySelector<HTMLElement>("[data-testid='mini-timeline-privacy']");
    const icon = overlay?.querySelector<SVGElement>("svg");
    const label = overlay?.querySelector<HTMLElement>("span");
    if (overlay === null || icon === undefined || icon === null || label === undefined || label === null) return null;
    const timelineStyle = getComputedStyle(timeline);
    const overlayBounds = overlay.getBoundingClientRect();
    const iconBounds = icon.getBoundingClientRect();
    const labelBounds = label.getBoundingClientRect();
    return {
      border: Number.parseFloat(timelineStyle.borderTopWidth),
      timelineFilter: timelineStyle.filter,
      overlayInset: overlayBounds.top - timeline.getBoundingClientRect().top,
      iconWidth: iconBounds.width,
      iconStroke: Number.parseFloat(getComputedStyle(icon).strokeWidth),
      labelBelowIcon: labelBounds.top >= iconBounds.bottom,
      centerDelta: Math.abs(
        (iconBounds.left + (iconBounds.width / 2)) - (overlayBounds.left + (overlayBounds.width / 2)),
      ),
    };
  });
  expect(privacyOptics).not.toBeNull();
  expect(privacyOptics?.border).toBeGreaterThanOrEqual(1);
  expect(privacyOptics?.timelineFilter).toBe("none");
  expect(privacyOptics?.overlayInset).toBeGreaterThanOrEqual(privacyOptics?.border ?? 1);
  expect(privacyOptics?.iconWidth).toBeGreaterThanOrEqual(44);
  expect(privacyOptics?.iconStroke).toBeGreaterThanOrEqual(2.3);
  expect(privacyOptics?.labelBelowIcon).toBe(true);
  expect(privacyOptics?.centerDelta).toBeLessThanOrEqual(1);
  await expect(runningTimeline).toContainText("Claim A");
  await expect(runningTimeline).toContainText("120–420");
  await expect(runningTimeline).toContainText("Claim B");
  await expect(runningTimeline).toContainText("220–520");
  await expect(runningTimeline.getByRole("slider")).toHaveCount(4);
  await expect(runningTimeline.getByRole("slider").first()).toHaveAttribute("aria-disabled", "true");
  await expect(page.getByTestId("claim-a-from")).toHaveCount(0);

  await expect(page.getByTestId("mini-verdict")).toHaveAttribute("data-verdict", "conflict", { timeout: 5_000 });
  await expect(page.getByTestId("mini-verdict")).toHaveText("Conflict confirmed");
  await expect(page.getByTestId("mini-claim-timeline")).toBeVisible();
  await expect(page.getByTestId("mini-claim-timeline")).toHaveAttribute("data-private-check", "false");
  await expect(page.getByTestId("mini-timeline-privacy")).toHaveCount(0);
  await expect(page.getByTestId("mini-claim-timeline").getByRole("slider").first())
    .toHaveAttribute("aria-disabled", "true");
  await expect(page.getByTestId("claim-a-from")).toHaveCount(0);
  await expect(page.getByRole("list", { name: "Execution phases" })).toHaveCount(0);
  await expect(page.getByTestId("mini-run-identity")).toHaveCount(0);
  const terminalPanelHeight = await miniPanel.evaluate((node) => node.getBoundingClientRect().height);
  expect(await miniPanel.evaluate((node) => node.scrollHeight - node.clientHeight)).toBeLessThanOrEqual(1);
  expect(Math.max(idlePanelHeight, runningPanelHeight, terminalPanelHeight)
    - Math.min(idlePanelHeight, runningPanelHeight, terminalPanelHeight)).toBeLessThanOrEqual(1);
  if (["1280x800", "390x844"].includes(testInfo.project.name)) {
    await miniPanel.screenshot({ path: testInfo.outputPath("mini-panel-result.png") });
  }

  const proof = page.getByTestId("mini-proof-details");
  await expect(proof.getByText("Execution proof")).toBeVisible();
  await expect(proof.getByText(/a1b2c3d4 · \d+s/u)).toBeVisible();
  await expect(proof).not.toHaveAttribute("open", "");
  await proof.locator("summary").click();
  await expect(proof).toHaveAttribute("open", "");
  expect(await miniPanel.evaluate((node) => node.scrollHeight - node.clientHeight)).toBeLessThanOrEqual(1);
  await expect(proof).toContainText("A-Pass");
  await expect(proof).toContainText(`Block ${OBSERVED_BLOCK}`);
  await expect(proof).toContainText("BGV evaluation");
  await expect(proof).toContainText("Completed");
  await expect(proof).toContainText("sha256:66666666");

  await expect(page.getByTestId("mini-status")).toContainText("entered the precommitted policy");
  await expect(page.getByTestId("mini-status")).toContainText("authorizes no legal judgment or settlement");
  await expect(page.getByTestId("mini-status")).not.toContainText("names who is responsible");
  await expect(page.getByTestId("mini-to-verified-run")).toHaveAttribute("href", "/protection/verified-run");
  await expect(page.getByTestId("mini-to-verified-run")).toHaveText("Verify the completed on-chain recourse");
  await expect(page.getByTestId("mini-try-another")).toHaveText("Try another case");
  await expect(page.getByRole("link", { name: "Inspect this managed run" }))
    .toHaveAttribute("href", `/protection/live?runId=${RUN_ID}`);
  await expect(page.getByTestId("mini-live-check"))
    .toContainText("ends after its policy-authorized local operation and evidence");
  await expect(page.getByTestId("mini-live-check")).toContainText("separate completed historical on-chain run");
  if (["1280x800", "390x844"].includes(testInfo.project.name)) {
    for (const section of [
      page.locator("#how"),
      page.getByRole("region", { name: "Complementary proofs" }),
    ]) {
      await section.scrollIntoViewIfNeeded();
      await expect(section).toHaveAttribute("data-visible", "true");
    }
    await page.evaluate(() => window.scrollTo({ top: 0, behavior: "instant" }));
    await page.screenshot({ path: testInfo.outputPath("landing-governed-result.png"), fullPage: true });
  }
});

test("Try another case starts a fresh draft while retaining exactly one completed run in memory", async ({ page }) => {
  const { submissions } = await installManagedHarness(page, {
    create: (_windows, ordinal) => ordinal === 1
      ? { body: envelope(true, RUN_ID) }
      : { body: envelope(false, SECOND_RUN_ID) },
  });
  await page.goto("/");

  await page.getByTestId("mini-run").click();
  await expect(page.getByTestId("mini-verdict")).toHaveText("Conflict confirmed");
  const terminalPanelHeight = await page.getByTestId("mini-panel")
    .evaluate((node) => node.getBoundingClientRect().height);
  await page.getByTestId("mini-try-another").click();

  await expect(page.getByTestId("mini-run")).toHaveText("Run encrypted check");
  await expect(page.getByTestId("claim-a-from")).toBeEnabled();
  const nextDraftPanelHeight = await page.getByTestId("mini-panel")
    .evaluate((node) => node.getBoundingClientRect().height);
  expect(nextDraftPanelHeight).toBeCloseTo(terminalPanelHeight, 0);
  const previous = page.getByTestId("mini-previous-run");
  await expect(previous).toHaveCount(1);
  await expect(previous).toContainText("Previous");
  await expect(previous).toContainText("Conflict");
  await expect(previous).toContainText("a1b2c3d4");
  await expect(previous).toContainText("120–420");
  await expect(previous).toContainText("220–520");

  await page.getByTestId("mini-preset-two").click();
  await expect(previous).toContainText("120–420");
  await expect(previous).toContainText("220–520");
  await page.getByTestId("mini-run").click();
  await expect(page.getByTestId("mini-verdict")).toHaveText("No conflict");
  expect(submissions).toHaveLength(2);
  expect(submissions[1]).toEqual({
    participantA: { activeFrom: 120, activeUntil: 220 },
    participantB: { activeFrom: 320, activeUntil: 520 },
  });
  await expect(previous).toHaveCount(1);
  await expect(previous).toContainText("Conflict");
  await expect(previous).not.toContainText("No conflict");

  await page.getByTestId("mini-try-another").click();
  await expect(page.getByTestId("mini-previous-run")).toHaveCount(1);
  await expect(page.getByTestId("mini-previous-run")).toContainText("No conflict");
  await expect(page.getByTestId("mini-previous-run")).toContainText("e5f6a7b8");
  await expect(page.getByTestId("mini-previous-run")).not.toContainText("a1b2c3d4");

  await page.reload();
  await expect(page.getByTestId("mini-previous-run")).toHaveCount(0);
  await expect(page.getByTestId("claim-a-from")).toHaveValue("120");
});

test("the cleared wording also comes only from governedResult.conflict", async ({ page }) => {
  await installManagedHarness(page, { create: () => ({ body: envelope(false) }) });
  await page.goto("/");
  await page.getByTestId("mini-run").click();
  await expect(page.getByTestId("mini-verdict")).toHaveAttribute("data-verdict", "no-conflict");
  await expect(page.getByTestId("mini-verdict")).toHaveText("No conflict");
  await expect(page.getByTestId("mini-status")).toContainText("establishes only that these windows do not conflict");
  await expect(page.getByTestId("mini-status")).toContainText("does not authorize legal judgment or settlement");
  await expect(page.getByTestId("mini-status")).not.toContainText("assigns");
});

test("a restored managed run never reconstructs private geometry from defaults", async ({ page }) => {
  const { tokenHolders } = await installManagedHarness(page, { read: () => envelope(true) });
  await page.goto(`/protection/live?runId=${RUN_ID}`);

  const reveal = page.getByTestId("reveal");
  await expect(reveal).toContainText("Conflict confirmed");
  await expect(reveal.getByTestId("claim-timeline")).toHaveCount(0);
  await expect(page.getByTestId("managed-private-inputs-unavailable")).toHaveCount(0);
  await expect(page.locator("body")).not.toContainText("Private claim windows are not retained in this public projection.");
  await expect(page.locator("#live-aFrom, #live-aUntil, #live-bFrom, #live-bUntil")).toHaveCount(0);
  const policy = page.getByTestId("governed-policy");
  await expect(policy).toContainText("Managed facility protection · v1");
  await expect(policy).toContainText("Selected before result exposure");
  await expect(policy).toContainText("Open a 24-hour local cure path");
  await expect(policy).toContainText("Pending");
  await expect(reveal).toContainText("neither establishes legal truth or authorizes settlement");
  await expect(page.getByTestId("decision-rail").last()).toContainText("local protocol double");
  await expect(page.getByTestId("decision-rail").last()).toContainText("Settlement is not authorized");
  await expect(reveal).toContainText("ends after its policy-authorized local operation and sealed evidence");
  expect(tokenHolders).toEqual([]);
});

test("the full managed run gives immediate start feedback and preserves its local geometry", async ({ page }, testInfo) => {
  const tokenGate: { release?: () => void } = {};
  const subsequentTokenGate = new Promise<void>((resolve) => { tokenGate.release = resolve; });
  await installManagedHarness(page, {
    create: () => ({ body: envelope(null) }),
    read: () => envelope(true),
    subsequentTokenGate,
  });
  await page.goto("/protection/live");

  await page.getByRole("button", { name: "Use the public test holder" }).click();
  await expect(page.getByRole("heading", { name: "Two private claims on the same receivable." })).toBeVisible();
  const runButton = page.getByRole("button", { name: "Run the confidential check" });
  await runButton.scrollIntoViewIfNeeded();
  const scrollBeforeStart = await page.evaluate(() => window.scrollY);
  await runButton.click();

  await expect(page.getByTestId("live-status")).toHaveAttribute("data-status", "active");
  await expect(page.getByTestId("live-status"))
    .toContainText("Request received. Rechecking A-Pass before the secure execution opens");
  await expect(page.locator("[class*='chapterFrame']")).toHaveAttribute("aria-busy", "true");
  const startingButton = page.getByRole("button", { name: "Starting confidential check" });
  await expect(startingButton).toBeDisabled();
  await expect(startingButton.locator("[class*='buttonLoader']")).toBeVisible();
  await expect(page.getByTestId("managed-launch-feedback"))
    .toContainText("Request received. Rechecking A-Pass, then opening the secure execution.");
  await page.waitForTimeout(250);
  const scrollAfterStart = await page.evaluate(() => window.scrollY);
  expect(Math.abs(scrollAfterStart - scrollBeforeStart)).toBeLessThanOrEqual(2);
  await expect(page.getByTestId("claim-timeline")).toBeVisible();
  if (["1280x800", "390x844"].includes(testInfo.project.name)) {
    await page.screenshot({ path: testInfo.outputPath("full-live-starting.png") });
  }

  tokenGate.release?.();
  await expect(page.getByRole("heading", { name: "Deciding privately." })).toBeVisible();
  await expect(page.getByTestId("claim-timeline")).toBeVisible();
  await expect(page.getByTestId("claim-timeline")).toHaveAttribute("data-reveal", "none");
  await expect(page.locator("body")).not.toContainText("Private claim windows are not retained");
  if (["1280x800", "390x844"].includes(testInfo.project.name)) {
    await page.screenshot({ path: testInfo.outputPath("full-live-deciding.png") });
  }
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

  const tamperedPolicy = envelope(true);
  const tamperedView = tamperedPolicy.view as Record<string, unknown>;
  const governedPolicy = tamperedView.governedPolicy as Record<string, unknown>;
  const selection = governedPolicy.selection as Record<string, unknown>;
  selection.policyHash = `sha256:${"f".repeat(64)}`;
  await page.unrouteAll({ behavior: "wait" });
  await installManagedHarness(page, { create: () => ({ body: tamperedPolicy }) });
  await page.reload();
  await page.getByTestId("mini-run").click();
  await expect(page.getByTestId("mini-status")).toContainText("execution response was rejected");
  await expect(page.getByTestId("mini-verdict")).toHaveCount(0);
});

test("worker capacity limits explain the retry window instead of looking broken", async ({ page }) => {
  await installManagedHarness(page, {
    create: () => ({ status: 429, body: { code: "DAILY_LIMIT" } }),
  });
  await page.goto("/");
  await page.getByTestId("mini-run").click();
  await expect(page.getByTestId("mini-status"))
    .toContainText("reached its rolling 24-hour run allowance");
  await expect(page.getByTestId("mini-status"))
    .toContainText("No execution started");
  await expect(page.getByTestId("mini-verdict")).toHaveCount(0);

  await page.unrouteAll({ behavior: "wait" });
  await installManagedHarness(page, {
    create: () => ({ status: 429, body: { code: "COOLDOWN" } }),
  });
  await page.reload();
  await page.getByTestId("mini-run").click();
  await expect(page.getByTestId("mini-status"))
    .toContainText("slot is reopening after the previous run");
  await expect(page.getByTestId("mini-status"))
    .toContainText("wait a few seconds and try again");
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
  await installManagedHarness(page, {
    create: () => ({ body: envelope(null) }),
    read: () => envelope(null),
  });
  await page.goto("/");

  const reducedMotionSymbol = page.locator("[class*='heroSymbolField']");
  await page.evaluate(() => window.scrollTo({ top: 240, behavior: "instant" }));
  expect(await reducedMotionSymbol.evaluate((node) => (
    getComputedStyle(node).getPropertyValue("--symbol-scroll-rotation").trim()
  ))).toBe("0deg");
  await page.evaluate(() => window.scrollTo({ top: 0, behavior: "instant" }));

  for (const legend of ["Financing claim A", "Financing claim B"]) {
    await expect(page.getByRole("group", { name: legend })).toBeVisible();
  }
  for (const id of ["claim-a-from", "claim-a-until", "claim-b-from", "claim-b-until"] as const) {
    const bounds = await page.getByTestId(id).boundingBox();
    expect(bounds?.height).toBeGreaterThanOrEqual(44);
  }
  for (const slider of await page.getByRole("slider").all()) {
    const bounds = await slider.boundingBox();
    expect(bounds?.width).toBeGreaterThanOrEqual(44);
    expect(bounds?.height).toBeGreaterThanOrEqual(44);
  }
  await expect(page.getByRole("slider", { name: "Financing claim A active from" }))
    .toHaveAttribute("aria-valuetext", "120 synthetic units");
  for (const slider of await page.getByRole("slider").all()) {
    const motion = await slider.evaluate((node) => {
      const style = getComputedStyle(node);
      return { animation: style.animationName, transitionSeconds: Number.parseFloat(style.transitionDuration) };
    });
    expect(motion.animation).toBe("none");
    expect(motion.transitionSeconds).toBeLessThanOrEqual(0.001);
  }

  const headerLink = page.getByRole("navigation", { name: "Product navigation" }).getByRole("link").first();
  await headerLink.focus();
  const headerTab = headerLink.locator("[class*='tabLabel']");
  expect(await headerTab.evaluate((node) => getComputedStyle(node).transform)).toBe("none");
  const tabTransitionSeconds = await headerLink.evaluate((node) => (
    Number.parseFloat(getComputedStyle(node, "::before").transitionDuration)
  ));
  expect(tabTransitionSeconds).toBeLessThanOrEqual(0.001);

  const integration = page.locator('[aria-label="Integration stages"]');
  const governedPolicy = integration.getByRole("button", { name: /Governed policy/ });
  await governedPolicy.focus();
  await expect(governedPolicy).toHaveAttribute("aria-pressed", "true");

  await page.getByTestId("mini-run").click();
  const spinner = page.locator("[class*='spinner']");
  await expect(spinner).toBeVisible();
  const spinnerMotion = await spinner.evaluate((node) => {
    const style = getComputedStyle(node);
    return {
      name: style.animationName,
      duration: Number.parseFloat(style.animationDuration) || 0,
    };
  });
  expect(["", "none"]).toContain(spinnerMotion.name);
  expect(spinnerMotion.duration).toBeLessThanOrEqual(0.001);
  await expectNoHorizontalOverflow(page);
});
