#!/usr/bin/env node

/**
 * The institutional two-context proof, on the real stack.
 *
 * Two independent browser contexts represent Institution A and Institution B.
 * Each carries its own EIP-6963 wallet whose typed-data signatures are made in
 * this runner with the canonical participant key for its side; no private key
 * ever enters a page. The site is the real Next app on /protection/live, the
 * worker is the real live worker with the coalition release and direct
 * participant admission both enabled, the engine runs the real Go binaries,
 * and A-Pass eligibility is read on-chain.
 *
 * Scenario "conflict":    same receivable, overlapping windows.
 * Scenario "no-conflict": same receivable, disjoint windows.
 *
 * Alongside each journey, every response body seen by each context is
 * collected, and at the end the run asserts that Institution A's context never
 * received Institution B's private window values, nor the reverse.
 *
 * Usage: node scripts/institutional-e2e.mjs conflict|no-conflict|both
 *
 * Trust modes (MORDANT_INSTITUTIONAL_E2E_TRUST):
 *   - "full" (default): the runner signs real EIP-712 admissions with the
 *     canonical participant keys (MORDANT_CASE_KEY_HOLDER_A/B must be set).
 *   - "stub-signatures": for a machine that does not hold the canonical keys.
 *     Exactly one seam is doubled, the worker's typed-data verifier, through
 *     the injection point the admission service defines for tests. Everything
 *     else stays real: on-chain A-Pass eligibility of the canonical wallets,
 *     the launch-token mint, the whole admission ledger discipline, the real
 *     BGV run and the real 2-of-3 coalition release. Signature cryptography
 *     itself keeps its own real coverage in the verifier suite.
 */

import { spawn } from "node:child_process";
import { existsSync, mkdtempSync, realpathSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { chromium } from "@playwright/test";
import { privateKeyToAccount } from "viem/accounts";

const ROOT = join(fileURLToPath(import.meta.url), "..", "..");
const SITE_PORT = 3600;
const SITE = `http://127.0.0.1:${SITE_PORT}`;
const SECRET = "institutional-e2e-secret-0123456789abcdef";
const AUDIENCE = "MORDANT_RAILWAY_WORKER";
const CHAIN_HEX = "0x279f";

// Distinctive ten-digit instants so a leaked window value cannot be mistaken
// for an incidental number in an unrelated response.
const WINDOWS = Object.freeze({
  conflict: {
    A: { from: "1900000137", until: "1900000463" },
    B: { from: "1900000271", until: "1900000809" },
  },
  "no-conflict": {
    A: { from: "1900000137", until: "1900000463" },
    B: { from: "1900001111", until: "1900002222" },
  },
});

function assert(condition, message) {
  if (!condition) throw new Error(`ASSERTION FAILED: ${message}`);
}
const log = (message) => process.stdout.write(`${message}\n`);
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function required(name) {
  const value = process.env[name];
  if (typeof value !== "string" || value.trim() === "") throw new Error(`${name} is required in the environment`);
  return value.trim();
}

const scenarios = process.argv[2] === "both"
  ? ["conflict", "no-conflict"]
  : [process.argv[2]];
if (!scenarios.every((scenario) => scenario === "conflict" || scenario === "no-conflict")) {
  console.error("usage: node scripts/institutional-e2e.mjs conflict|no-conflict|both");
  process.exit(2);
}

const TRUST = process.env.MORDANT_INSTITUTIONAL_E2E_TRUST === "stub-signatures" ? "stub-signatures" : "full";
const PUBLIC_MONAD_RPC = "https://testnet-rpc.monad.xyz";

async function bootWorker(dataRoot) {
  const workerModule = await import("./mordant-live-worker.mjs");
  const engine = await import("../.product-test-dist/src/lib/protection/governed-fhe-product-server.js");
  const service = await import("../.product-test-dist/src/lib/protection/participant-admission-service.js");
  const store = await import("../.product-test-dist/src/lib/protection/participant-admission-store.js");
  const eligibility = await import("../.product-test-dist/src/lib/protection/ccp-eligibility.js");
  const verifier = await import("../.product-test-dist/src/lib/protection/participant-typed-data-verifier.js");

  const configuration = workerModule.readWorkerConfiguration({
    ...process.env,
    MORDANT_WORKER_TOKEN_SECRET: SECRET,
    MORDANT_WORKER_TOKEN_AUDIENCE: AUDIENCE,
    MORDANT_WORKER_ALLOWED_ORIGIN: SITE,
    MORDANT_WORKER_DATA_ROOT: dataRoot,
    MORDANT_WORKER_COALITION_RELEASE: "enabled",
    MORDANT_WORKER_ENABLE_DIRECT_PARTICIPANT_ADMISSION: "enabled",
    MORDANT_WORKER_DIRECT_PARTICIPANT_ADMISSION_ACK: "MORDANT_PARTICIPANT_ADMISSION_V1",
    MORDANT_WORKER_COOLDOWN_MS: "1000",
  });
  assert(configuration.coalitionRelease && configuration.directParticipantAdmission,
    "the combined two-institution coalition profile is configured");
  const paths = workerModule.ensureWorkerLayout(configuration);
  // The engine gate mirrors the worker profile, exactly as the worker main() does.
  process.env.MORDANT_PROTECTION_DIRECT_PARTICIPANT_ADMISSION = "enabled";

  const reader = eligibility.createCcpReader();
  const admission = {
    ...service,
    resolveCaseCode: store.resolveCaseCode,
    verifyApass: (wallet) => eligibility.verifyCcpEligibility(wallet, reader),
    // The one seam this harness is allowed to double, and only in the mode
    // that says so out loud: a machine without the canonical keys cannot
    // produce verifiable canonical signatures.
    verifyTypedData: TRUST === "stub-signatures"
      ? async () => true
      : verifier.createMonadTypedDataVerifier(),
  };
  if (TRUST === "stub-signatures") {
    log("TRUST BOUNDARY: typed-data verification is stubbed in this run; every other check is real.");
  }
  const worker = workerModule.createLiveWorker({
    configuration,
    admission,
    createOrchestrator: () => engine.createProtectionOrchestrator({
      runRoot: paths.runRoot,
      retentionRoot: join(dataRoot, "receipts"),
      binRoot: join(ROOT, ".mordant", "governed-fhe-bin-fresh-check"),
    }),
    onComplete: (result) => log(`  worker case-complete pruned=[${result.pruned.join(", ")}]`),
    onError: (result) => log(`  worker case-failed ${result.runId}: ${result.error?.message ?? result.error}`),
  });
  const port = await new Promise((resolve) => {
    worker.server.listen(0, "127.0.0.1", () => resolve(worker.server.address().port));
  });
  return { worker, paths, origin: `http://127.0.0.1:${port}` };
}

async function bootSite(workerOrigin) {
  const site = spawn("npx", ["next", "dev", "--hostname", "127.0.0.1", "--port", String(SITE_PORT)], {
    cwd: ROOT,
    env: {
      ...process.env,
      NEXT_PUBLIC_MORDANT_WORKER_ORIGIN: workerOrigin,
      MORDANT_WORKER_TOKEN_SECRET: SECRET,
      MORDANT_WORKER_ENABLE_DIRECT_PARTICIPANT_ADMISSION: "enabled",
      MORDANT_WORKER_DIRECT_PARTICIPANT_ADMISSION_ACK: "MORDANT_PARTICIPANT_ADMISSION_V1",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  site.stdout.on("data", () => undefined);
  site.stderr.on("data", () => undefined);
  const deadline = Date.now() + 120_000;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(`${SITE}/protection/live`);
      if (response.ok) return site;
    } catch {
      // Still starting.
    }
    await sleep(1_000);
  }
  throw new Error("the site never became ready");
}

/**
 * One institution: its own browser context, its own wallet, its own signature
 * capability, and a collector of every response body its context ever saw.
 */
async function institution(browser, definition) {
  const context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  await context.exposeBinding("__mordantSign", async (_source, payload) => {
    const typed = JSON.parse(payload);
    const types = { ...typed.types };
    delete types.EIP712Domain;
    return definition.account.signTypedData({
      domain: typed.domain,
      types,
      primaryType: typed.primaryType,
      message: typed.message,
    });
  });
  await context.addInitScript(({ name, rdns, uuid, address, chainHex }) => {
    const listeners = new Map();
    let connected = false;
    let chainId = chainHex;
    const emit = (event, ...args) => { for (const listener of listeners.get(event) ?? []) listener(...args); };
    const provider = {
      request: async ({ method, params }) => {
        if (method === "eth_chainId") return chainId;
        if (method === "eth_accounts") return connected ? [address] : [];
        if (method === "eth_requestAccounts") { connected = true; return [address]; }
        if (method === "wallet_switchEthereumChain") {
          chainId = params?.[0]?.chainId ?? chainHex;
          queueMicrotask(() => emit("chainChanged", chainId));
          return null;
        }
        if (method === "eth_signTypedData_v4") {
          if (!connected) throw new Error("wallet is not connected");
          return window.__mordantSign(params[1]);
        }
        return null;
      },
      on: (event, listener) => {
        const existing = listeners.get(event) ?? new Set();
        existing.add(listener);
        listeners.set(event, existing);
      },
      removeListener: (event, listener) => { listeners.get(event)?.delete(listener); },
    };
    const detail = Object.freeze({
      info: Object.freeze({ uuid, name, rdns, icon: "data:image/png;base64,iVBORw0KGgo=" }),
      provider,
    });
    const announce = () => window.dispatchEvent(new CustomEvent("eip6963:announceProvider", { detail }));
    window.addEventListener("eip6963:requestProvider", announce);
    announce();
  }, { name: definition.name, rdns: definition.rdns, uuid: definition.uuid, address: definition.account.address, chainHex: CHAIN_HEX });

  const page = await context.newPage();
  const responses = [];
  page.on("response", (response) => {
    const type = response.headers()["content-type"] ?? "";
    if (!type.includes("application/json")) return;
    response.text()
      .then((body) => responses.push(`${response.status()} ${response.url()} ${body}`))
      .catch(() => undefined);
  });
  const consoleLines = [];
  page.on("console", (message) => consoleLines.push(`${message.type()}: ${message.text()}`));
  page.on("pageerror", (error) => consoleLines.push(`pageerror: ${error.message}`));
  return { context, page, responses, consoleLines, name: definition.name };
}

/** On failure, leave enough behind to diagnose without rerunning blind. */
async function dumpDiagnostics(sides, label) {
  for (const side of sides) {
    const slug = `${label}-${side.name.replaceAll(/\s+/g, "-").toLowerCase()}`;
    await side.page.screenshot({ path: `${process.env.TMPDIR ?? "/tmp"}/${slug}.png`, fullPage: true }).catch(() => undefined);
    log(`--- ${side.name}: last responses ---`);
    for (const line of side.responses.slice(-4)) log(`  ${line.slice(0, 300)}`);
    log(`--- ${side.name}: console tail ---`);
    for (const line of side.consoleLines.slice(-6)) log(`  ${line.slice(0, 200)}`);
  }
}

async function connectAndVerify(institutionSide) {
  const { page, name } = institutionSide;
  const panel = page.getByTestId("participant-admission");
  await panel.getByRole("button", { name: "Connect a wallet" }).click();
  const dialog = page.getByRole("dialog");
  await dialog.getByRole("button", { name: new RegExp(name, "u") }).click();
  await dialog.getByRole("button", { name: "Close" }).click();
  const switchButton = panel.getByRole("button", { name: "Switch to Monad testnet" });
  if (await switchButton.isVisible().catch(() => false)) await switchButton.click();
  await panel.getByRole("button", { name: "Check A-Pass eligibility" }).click();
  // The eligibility read is a real on-chain check; filling the interval before
  // it settles races the component's own state transitions.
  await panel.getByText(/Verified · block/u).waitFor({ state: "visible", timeout: 180_000 });
}

async function runScenario(browser, scenario, holderAccountA, holderAccountB, runRoot) {
  log(`\n=== ${scenario} ===`);
  const windows = WINDOWS[scenario];
  const alpha = await institution(browser, {
    name: "Institution A", rdns: "e2e.mordant.institution-a",
    uuid: "00000000-0000-4000-8000-0000000000aa", account: holderAccountA,
  });
  const beta = await institution(browser, {
    name: "Institution B", rdns: "e2e.mordant.institution-b",
    uuid: "00000000-0000-4000-8000-0000000000bb", account: holderAccountB,
  });

  // Institution A creates the private check and authorizes its own claim.
  await alpha.page.goto(`${SITE}/protection/live`, { waitUntil: "domcontentloaded" });
  await connectAndVerify(alpha);
  const panelA = alpha.page.getByTestId("participant-admission");
  await panelA.getByLabel("Active from").fill(windows.A.from);
  await panelA.getByLabel("Active until").fill(windows.A.until);
  await panelA.getByRole("button", { name: "Authorize claim A" }).click();
  await alpha.page.getByTestId("handoff").waitFor({ state: "visible", timeout: 600_000 })
    .catch(async (error) => { await dumpDiagnostics([alpha, beta], "handoff-timeout"); throw error; });
  const caseCode = new URL(alpha.page.url()).searchParams.get("caseCode");
  assert(caseCode !== null && /^[0-9A-HJKMNP-TV-Z]{16}$/u.test(caseCode), "the invitation carries a well-formed case code");
  log(`  A admitted, invitation code ${caseCode}`);

  // Institution B joins through the invitation, in its own context, and
  // authorizes only its own claim.
  await beta.page.goto(`${SITE}/protection/live?caseCode=${caseCode}`, { waitUntil: "domcontentloaded" });
  await beta.page.getByTestId("handoff").waitFor({ state: "visible", timeout: 60_000 });
  await beta.page.getByTestId("handoff").getByRole("button", { name: "Continue as Participant B" }).click();
  await connectAndVerify(beta);
  const panelB = beta.page.getByTestId("participant-admission");
  await panelB.getByLabel("Active from").fill(windows.B.from);
  await panelB.getByLabel("Active until").fill(windows.B.until);
  await panelB.getByRole("button", { name: "Authorize claim B" }).click();
  log("  B admitted, the private comparison continues on its own");

  // The runtime advances without either institution doing anything further.
  const reveal = beta.page.getByTestId("reveal");
  await reveal.waitFor({ state: "visible", timeout: 45 * 60 * 1_000 })
    .catch(async (error) => { await dumpDiagnostics([alpha, beta], "reveal-timeout"); throw error; });
  const expectConflict = scenario === "conflict";
  const heading = (await reveal.locator("h2").first().textContent() ?? "").trim();
  assert(heading === (expectConflict ? "Conflict confirmed." : "No conflict."), `B heading (got ${JSON.stringify(heading)})`);
  const factsB = (await beta.page.getByTestId("coalition-facts").textContent() ?? "").replace(/\s+/g, " ");
  assert(factsB.includes("Same economic asset") && factsB.includes("Yes"), "B sees the asset match");
  assert(factsB.includes("Policy conflict") && factsB.includes(expectConflict ? "Confirmed" : "None"), "B sees the policy bit");
  assert(factsB.includes("2 of 3 operators"), "B sees the quorum");
  const railB = (await beta.page.getByTestId("decision-rail").textContent() ?? "").replace(/\s+/g, " ");
  assert(expectConflict ? railB.includes("Bounded action authorized") && railB.includes("Execution-ready")
    : railB.includes("No settlement can derive"), "B sees the bounded outcome");

  // Institution A sees the same shared facts from its own context.
  await alpha.page.goto(`${SITE}/protection/live?caseCode=${caseCode}`, { waitUntil: "domcontentloaded" });
  await alpha.page.getByTestId("reveal").waitFor({ state: "visible", timeout: 120_000 });
  const factsA = (await alpha.page.getByTestId("coalition-facts").textContent() ?? "").replace(/\s+/g, " ");
  assert(factsA.includes(expectConflict ? "Confirmed" : "None") && factsA.includes("2 of 3 operators"),
    "A sees the same shared result");

  // Neither institution's context ever received the other's private window.
  const alphaSaw = alpha.responses.join("\n");
  const betaSaw = beta.responses.join("\n");
  for (const value of [windows.B.from, windows.B.until]) {
    assert(!alphaSaw.includes(value), `Institution A's context never receives B's window (${value})`);
  }
  for (const value of [windows.A.from, windows.A.until]) {
    assert(!betaSaw.includes(value), `Institution B's context never receives A's window (${value})`);
  }
  const alphaBody = (await alpha.page.locator("body").textContent() ?? "");
  const betaBody = (await beta.page.locator("body").textContent() ?? "");
  for (const value of [windows.B.from, windows.B.until]) assert(!alphaBody.includes(value), "A's page shows no B value");
  for (const value of [windows.A.from, windows.A.until]) assert(!betaBody.includes(value), "B's page shows no A value");

  // The release capability is pruned at terminal, on the participant rail too.
  const runLine = beta.responses.find((line) => line.includes("\"runId\""));
  const runId = runLine === undefined
    ? null
    : (JSON.parse(runLine.slice(runLine.indexOf("{")))?.view?.runId
      ?? JSON.parse(runLine.slice(runLine.indexOf("{")))?.admission?.runId
      ?? null);
  if (runId !== null) {
    for (const directory of ["coalition-operator-1", "coalition-operator-2", "coalition-operator-3", "coalition-ledger", "public"]) {
      assert(!existsSync(join(runRoot, runId, directory)), `${directory} pruned at terminal`);
    }
  }

  await alpha.context.close();
  await beta.context.close();
  log(`  ${scenario} GREEN (case ${caseCode})`);
}

async function main() {
  if (process.env.MORDANT_MONAD_RPC_URL === undefined && process.env.MONAD_RPC_URL === undefined) {
    process.env.MONAD_RPC_URL = PUBLIC_MONAD_RPC;
    log(`no RPC configured, using the public endpoint ${PUBLIC_MONAD_RPC}`);
  }
  let holderAccountA;
  let holderAccountB;
  if (TRUST === "full") {
    holderAccountA = privateKeyToAccount(required("MORDANT_CASE_KEY_HOLDER_A"));
    holderAccountB = privateKeyToAccount(required("MORDANT_CASE_KEY_HOLDER_B"));
  } else {
    // The canonical addresses come from the pinned reviewed configuration, so
    // the admission ledger, the A-Pass reads and the wallet discipline all run
    // against the real institutions even when their keys are absent here.
    const compatibility = await import("../.product-test-dist/src/lib/protection/adapter-compatibility.js");
    const canonical = compatibility.loadCanonicalRecourseConfiguration();
    holderAccountA = {
      address: canonical.participants.holderA,
      signTypedData: async () => `0x${"aa".repeat(65)}`,
    };
    holderAccountB = {
      address: canonical.participants.holderB,
      signTypedData: async () => `0x${"bb".repeat(65)}`,
    };
  }

  const dataRoot = mkdtempSync(join(realpathSync(tmpdir()), "mordant-institutional-e2e-"));
  const { worker, paths, origin } = await bootWorker(dataRoot);
  log(`worker (coalition + direct admission) on ${origin}`);
  const site = await bootSite(origin);
  log(`site on ${SITE}`);

  const browser = await chromium.launch();
  try {
    for (const scenario of scenarios) {
      await runScenario(browser, scenario, holderAccountA, holderAccountB, paths.runRoot);
      await sleep(2_000);
    }
    log("\nINSTITUTIONAL TWO-CONTEXT E2E GREEN");
  } finally {
    await browser.close();
    site.kill("SIGTERM");
    worker.server.close();
  }
  process.exit(0);
}

main().catch((error) => {
  process.stderr.write(`${error instanceof Error ? error.stack ?? error.message : String(error)}\n`);
  process.exit(1);
});
