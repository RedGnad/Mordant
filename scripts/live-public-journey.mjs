#!/usr/bin/env node
/**
 * Real public journey against the deployed Vercel branch alias.
 *
 * Drives a genuine browser through the deployed product: Cleanverse eligibility, the
 * pledge form, a real BGV execution on Railway, a refresh mid-flight, and the terminal
 * receipt. Nothing is stubbed, and the page is reached anonymously.
 *
 * The load-bearing assertion is the one a screenshot cannot make: every request is
 * recorded, so it can be proven that the pledge windows reach Railway and never Vercel.
 */

import { writeFileSync } from "node:fs";

import { chromium, devices } from "@playwright/test";

const ALIAS = process.env.PUBLIC_ALIAS ?? "https://mordant-git-feature-custom-supervised-pledges-redgnads-projects.vercel.app";
const WORKER = process.env.WORKER_ORIGIN ?? "https://mordant-production.up.railway.app";
const HOLDER = "0x911F99f424D47F08a15fcC771e94dcc2f7252B02";
const WINDOWS = { aFrom: "120", aUntil: "420", bFrom: "220", bUntil: "520" };
const BOUNDS = ["120", "420", "220", "520"];
const PRIVATE_FIELDS = /activeFrom|activeUntil|supervisedPledgeWindows/u;

/** Digests are hex and routinely contain these digits by chance; they are not inputs. */
function withoutDigests(text) {
  return text.replace(/sha256:[0-9a-f]{64}/gu, "").replace(/\b[0-9a-f]{32,}\b/gu, "");
}

function carriesSubmittedBound(text) {
  const stripped = withoutDigests(text);
  return BOUNDS.some((bound) => new RegExp(`(?<![0-9a-fA-F])${bound}(?![0-9a-fA-F])`, "u").test(stripped)) || PRIVATE_FIELDS.test(stripped);
}
const OUTCOME_WORDS = /conflict confirmed|no conflict found|recourse opened/iu;

const failures = [];
const evidence = { schemaVersion: "mordant.live-public-journey/1", alias: ALIAS, worker: WORKER, checks: [], timeline: [] };

function check(condition, label, detail = {}) {
  if (!condition) failures.push(label);
  evidence.checks.push({ label, status: condition ? "PASS" : "FAIL", ...detail });
  process.stdout.write(`  ${condition ? "ok  " : "FAIL"} ${label}\n`);
  return condition;
}

/** Records every request so the pledge-window routing can be proven, not assumed. */
function instrument(page, log) {
  page.on("request", (request) => {
    let body = "";
    try {
      body = request.postData() ?? "";
    } catch {
      body = "";
    }
    log.push({ url: request.url(), method: request.method(), carriesBounds: BOUNDS.every((b) => body.includes(b)) && body.includes("activeFrom") });
  });
}

async function runJourney(page, log, label) {
  process.stdout.write(`${label}: eligibility\n`);
  await page.goto(`${ALIAS}/protection/live`, { waitUntil: "domcontentloaded" });
  check(await page.getByText(/Cleanverse eligibility/iu).first().isVisible(), `${label}: the eligibility step is shown first`);
  check(!(await page.getByLabel(/Participant A pledge start/iu).isVisible().catch(() => false)), `${label}: the pledge form is withheld before eligibility`);

  await page.getByRole("button", { name: /Use the public test holder/iu }).click();
  await page.getByText(/Cleanverse eligibility verified/iu).waitFor({ timeout: 45_000 });
  check(true, `${label}: the public UAT holder is verified against the active policy`);

  process.stdout.write(`${label}: pledge submission\n`);
  for (const [key, value] of Object.entries(WINDOWS)) await page.fill(`#live-${key}`, value);
  const startedAt = Date.now();
  await page.getByRole("button", { name: /Start encrypted check/iu }).click();

  // The page writes the run into the URL with pushState, which is not a navigation, so
  // the URL is polled rather than waited on.
  await page.waitForFunction(() => new URL(location.href).searchParams.get("runId") !== null, undefined, { timeout: 90_000 });
  const runId = new URL(page.url()).searchParams.get("runId");
  evidence.runId = runId;
  check(typeof runId === "string" && runId.length === 36, `${label}: a runId is written into the URL`, { runId });

  const bodyText = await page.locator("body").innerText();
  check(!carriesSubmittedBound(bodyText), `${label}: the submitted bounds leave the rendered page after admission`);
  check(!OUTCOME_WORDS.test(bodyText), `${label}: no outcome wording at admission`);

  process.stdout.write(`${label}: execution\n`);
  let refreshed = false;
  let releasedAt = null;
  let sawPrematureOutcome = false;
  for (let attempt = 0; attempt < 120; attempt += 1) {
    await page.waitForTimeout(2_000);
    const text = await page.locator("body").innerText();
    const stage = await page.locator('li[data-state="active"]').first().innerText().catch(() => null);
    const seconds = Math.round((Date.now() - startedAt) / 1_000);
    if (evidence.timeline.at(-1)?.stage !== stage && stage !== null) {
      evidence.timeline.push({ atSeconds: seconds, stage });
      process.stdout.write(`  [${String(seconds).padStart(3)}s] ${stage}\n`);
    }
    const released = OUTCOME_WORDS.test(text);
    // An outcome may only be named once the evaluation has actually run: seeing one
    // before the encrypted evaluation stage would mean the page anticipated a result.
    if (released && releasedAt === null) {
      releasedAt = seconds;
      const stagesSeen = evidence.timeline.map((entry) => entry.stage);
      if (!stagesSeen.includes("Encrypted evaluation running")) sawPrematureOutcome = true;
    }

    // One refresh mid-execution proves recovery is GET-only.
    if (!refreshed && seconds > 8 && releasedAt === null) {
      await page.reload({ waitUntil: "domcontentloaded" });
      refreshed = true;
      const afterReload = await page.locator("body").innerText();
      check(afterReload.includes(runId), `${label}: the run survives a browser refresh`);
      check(!carriesSubmittedBound(afterReload), `${label}: no raw bounds reappear after refresh`);
    }

    if (/View execution receipt/iu.test(text)) break;
  }
  evidence.releasedAtSeconds = releasedAt;
  check(!sawPrematureOutcome, `${label}: no premature outcome during execution`);

  const terminal = await page.locator("body").innerText();
  check(/Conflict confirmed/iu.test(terminal), `${label}: the terminal state is conflict confirmed`);
  check(/Recourse opened/iu.test(terminal), `${label}: recourse is opened`);

  process.stdout.write(`${label}: receipt\n`);
  await page.getByRole("button", { name: /View execution receipt/iu }).click();
  const drawer = page.getByRole("dialog", { name: /Execution receipt/iu });
  check(await drawer.isVisible(), `${label}: the receipt drawer opens`);
  const drawerText = await drawer.innerText();
  const digest = (drawerText.match(/sha256:[0-9a-f]{64}/gu) ?? []).at(-1) ?? null;
  evidence.receiptDigest = digest;
  check(digest !== null, `${label}: the receipt carries a digest`, { digest });
  check(/OUTSTANDING_INTACT/u.test(drawerText), `${label}: the original receivable is intact`);
  check(!carriesSubmittedBound(drawerText), `${label}: the receipt carries no submitted bound`);

  // Long digests must wrap rather than push the page sideways.
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  check(overflow <= 1, `${label}: no horizontal overflow`, { overflowPx: overflow });

  process.stdout.write(`${label}: request routing\n`);
  const toVercel = log.filter((r) => r.url.startsWith(ALIAS) && r.carriesBounds);
  const toWorker = log.filter((r) => r.url.startsWith(WORKER) && r.carriesBounds);
  check(toVercel.length === 0, `${label}: no pledge window is ever sent to Vercel`, { count: toVercel.length });
  check(toWorker.length === 1, `${label}: the pledge windows go straight to Railway exactly once`, { count: toWorker.length });
  return runId;
}

async function main() {
  const browser = await chromium.launch();
  try {
    const desktop = await browser.newContext({ viewport: { width: 1440, height: 900 } });
    const desktopLog = [];
    const desktopPage = await desktop.newPage();
    instrument(desktopPage, desktopLog);
    await runJourney(desktopPage, desktopLog, "desktop");

    // Mobile only re-checks presentation and the refused-holder path: a second real BGV
    // run would be refused as BUSY and would waste the worker's bounded daily budget.
    process.stdout.write("mobile: presentation and refusal\n");
    const mobile = await browser.newContext({ ...devices["iPhone 13"] });
    const mobilePage = await mobile.newPage();
    await mobilePage.goto(`${ALIAS}/protection/live`, { waitUntil: "domcontentloaded" });
    check(await mobilePage.getByText(/Cleanverse eligibility/iu).first().isVisible(), "mobile: the eligibility step renders");
    const mobileOverflow = await mobilePage.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
    check(mobileOverflow <= 1, "mobile: no horizontal overflow", { overflowPx: mobileOverflow });
    const button = mobilePage.getByRole("button", { name: /Use the public test holder/iu });
    const box = await button.boundingBox();
    check(box !== null && box.width > 0 && box.x >= 0, "mobile: the primary control is not clipped", { box });

    await mobilePage.fill("#ccp-holder", "0x981F6E0Ea94f45fDB8ee7680DC862212E3C720e0");
    await mobilePage.getByRole("button", { name: /Check Cleanverse eligibility/iu }).click();
    await mobilePage.getByText(/not eligible under the active policy/iu).waitFor({ timeout: 45_000 });
    check(true, "mobile: a refused holder gets an ordinary product state, not a crash");
    check(await mobilePage.getByRole("link", { name: /View verified protection evidence/iu }).isVisible(), "mobile: the fallback link to /protection remains");

    const busy = await mobilePage.evaluate(async (worker) => {
      const response = await fetch(`${worker}/v1/custom-cases/00000000-0000-4000-8000-000000000000`);
      return response.status;
    }, WORKER);
    check(busy === 404 || busy === 400, "mobile: an unknown run is refused by the worker", { status: busy });
  } finally {
    await browser.close();
  }

  evidence.result = failures.length === 0 ? "PASS" : "FAIL";
  evidence.failures = failures;
  writeFileSync(new URL(`../docs/evidence/live-public-journey-${new Date().toISOString().slice(0, 10)}.json`, import.meta.url), JSON.stringify(evidence, null, 2));
  process.stdout.write(`\n${evidence.result}: ${failures.length} failing check(s)\n`);
  for (const failure of failures) process.stdout.write(`  - ${failure}\n`);
  if (failures.length > 0) process.exitCode = 1;
}

await main();
