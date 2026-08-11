#!/usr/bin/env node

/**
 * Two real coalition journeys through the live worker's own HTTP entrypoints.
 *
 * This is the product path, not a harness: the worker admits each case with a
 * launch token on POST /v1/custom-cases exactly as /protection/live does, the
 * engine runs the real Go binaries (keygen ceremony, both encryptions, the BGV
 * evaluation, the 2-of-3 coalition release), and the readback below is the same
 * GET the browser polls.
 *
 * Case 1: same receivable, overlapping windows  -> sameEconomicAsset=true, policyConflict=true,  EXECUTION_READY.
 * Case 2: same receivable, disjoint windows     -> sameEconomicAsset=true, policyConflict=false, NO_CONFLICT_NO_SETTLEMENT.
 *
 * After each terminal case the worker's prune is asserted: the operator
 * bundles, their session ledgers and every reproducible cryptographic root are
 * gone, while the durable execution record and the settlement-profile
 * commitment remain.
 */

import { randomUUID } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, realpathSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const HEX32 = /^0x[0-9a-f]{64}$/u;

function assert(condition, message) {
  if (!condition) throw new Error(`ASSERTION FAILED: ${message}`);
}

function log(message) {
  process.stdout.write(`${message}\n`);
}

async function call(url, options = {}) {
  const response = await fetch(url, options);
  const body = await response.json().catch(() => null);
  if (!response.ok) {
    throw new Error(`${options.method ?? "GET"} ${url} -> ${response.status}: ${JSON.stringify(body)}`);
  }
  return body;
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function main() {
  // The object store refuses any root whose path traverses a symlink, and
  // macOS's tmpdir (/var/folders) is one; resolve it first.
  const dataRoot = mkdtempSync(join(realpathSync(tmpdir()), "mordant-coalition-smoke-"));
  const origin = "http://localhost:3000";
  const secret = "coalition-live-smoke-secret-0123456789abcdef";
  const audience = "coalition-live-smoke";
  const environment = {
    MORDANT_WORKER_TOKEN_SECRET: secret,
    MORDANT_WORKER_TOKEN_AUDIENCE: audience,
    MORDANT_WORKER_ALLOWED_ORIGIN: origin,
    MORDANT_WORKER_DATA_ROOT: dataRoot,
    MORDANT_WORKER_COALITION_RELEASE: "enabled",
    MORDANT_WORKER_COOLDOWN_MS: "1000",
  };

  const workerModule = await import("./mordant-live-worker.mjs");
  const engine = await import("../.product-test-dist/src/lib/protection/governed-fhe-product-server.js");
  const viewModule = await import("../.product-test-dist/src/lib/protection/custom-supervised-view.js");

  const configuration = workerModule.readWorkerConfiguration(environment);
  assert(configuration.coalitionRelease === true, "worker configuration enables the coalition release");
  const paths = workerModule.ensureWorkerLayout(configuration);

  const worker = workerModule.createLiveWorker({
    configuration,
    createOrchestrator: () => engine.createProtectionOrchestrator({
      runRoot: paths.runRoot,
      retentionRoot: join(dataRoot, "receipts"),
      // A fresh binary root: the smoke must never trust binaries compiled from
      // an older working tree.
      binRoot: join(dataRoot, "governed-fhe-bin"),
    }),
    onComplete: (result) => log(`  worker case-complete pruned=[${result.pruned.join(", ")}]`),
    onError: (result) => log(`  worker case-failed ${result.runId}: ${result.error?.message ?? result.error}`),
  });

  const port = await new Promise((resolve) => {
    worker.server.listen(0, "127.0.0.1", () => resolve(worker.server.address().port));
  });
  const base = `http://127.0.0.1:${port}`;
  log(`worker listening on ${base}, data root ${dataRoot}`);

  const launchToken = () => {
    const issuedAt = Date.now();
    return workerModule.signLaunchToken({
      tokenId: randomUUID(),
      issuedAt,
      expiresAt: issuedAt + 4 * 60 * 1_000,
      audience,
      action: "CREATE_CUSTOM_CASE",
    }, secret);
  };

  async function runCase(name, windows, expectations) {
    // Wait for the worker to accept (cooldown after the previous case).
    for (let attempt = 0; attempt < 120; attempt += 1) {
      const health = await call(`${base}/health`);
      if (health.acceptingCases === true) break;
      await sleep(1_000);
    }
    log(`\n=== ${name} ===`);
    const created = await call(`${base}/v1/custom-cases`, {
      method: "POST",
      headers: {
        origin,
        "content-type": "application/json",
        authorization: `Bearer ${launchToken()}`,
      },
      body: JSON.stringify(windows),
    });
    const runId = created.view.runId;
    log(`  admitted runId=${runId} stage=${created.view.stage}`);
    assert(created.view.schemaVersion === "mordant.custom-supervised-protection-view/3",
      "the admitted case already speaks the coalition view schema");
    assert(created.view.governedResult === null && created.view.settlement === null,
      "no released fact and no settlement before the release");

    let body = null;
    const deadline = Date.now() + 45 * 60 * 1_000;
    let lastStage = null;
    while (Date.now() < deadline) {
      await sleep(5_000);
      try {
        body = await call(`${base}/v1/custom-cases/${runId}`);
      } catch {
        continue;
      }
      if (body.view.stage !== lastStage) {
        lastStage = body.view.stage;
        log(`  stage=${lastStage} progress=${JSON.stringify(body.progress)}`);
      }
      if (body.view.stage === "RELEASED" && body.view.governedResult !== null) break;
      if (body.view.stage === "ABORTED") throw new Error(`run aborted: ${JSON.stringify(body.view)}`);
    }
    assert(body !== null && body.view.stage === "RELEASED", `${name}: the journey reached the verified release`);
    const view = body.view;

    // The exact strict parser the server exposes must accept the served view.
    const parsed = viewModule.parseCustomSupervisedProtectionView(view);
    assert(parsed !== null, "the served view passes the strict coalition parser");

    const release = view.governedResult;
    assert(release.releaseMode === "coalition-v5", "release mode is the coalition");
    assert(release.sameEconomicAsset === expectations.sameEconomicAsset,
      `sameEconomicAsset=${expectations.sameEconomicAsset} (got ${release.sameEconomicAsset})`);
    assert(release.policyConflict === expectations.policyConflict,
      `policyConflict=${expectations.policyConflict} (got ${release.policyConflict})`);
    assert(release.threshold === 2 && Array.isArray(release.coalition) && release.coalition.length === 2,
      "a 2-operator quorum served the release");
    assert(typeof release.operatorTopology === "string" && release.operatorTopology.length > 0,
      "the operator topology is disclosed");
    assert(view.terminalScenario === (expectations.policyConflict ? "conflict" : "no-conflict"),
      "the terminal scenario derives from the policy bit");
    assert(view.nextOperation === null, "the lifecycle ends at the verified release");
    assert(view.recourse === null && view.receipt === null, "no recourse and no receipt in this milestone");

    const settlement = view.settlement;
    assert(settlement !== null, "the pre-committed profile yielded a settlement projection");
    assert(HEX32.test(settlement.settlementProfileDigest), "the settlement profile digest is retained");
    if (expectations.policyConflict) {
      assert(settlement.status === "EXECUTION_READY", "a released conflict is execution-ready");
      assert(HEX32.test(settlement.planHash) && HEX32.test(settlement.authorizationHash),
        "the settlement plan and its authorization are derived");
    } else {
      assert(settlement.status === "NO_CONFLICT_NO_SETTLEMENT", "a cleared run derives no settlement");
      assert(settlement.planHash === null && settlement.authorizationHash === null,
        "no plan exists for a cleared run");
    }

    // Give the worker's completion block time to prune, then assert the cleanup.
    let pruneObserved = false;
    for (let attempt = 0; attempt < 60; attempt += 1) {
      pruneObserved = !existsSync(join(paths.runRoot, runId, "coalition-ledger"));
      if (pruneObserved) break;
      await sleep(1_000);
    }
    for (const directory of [
      "public", "decryptor-private", "participant-private",
      "coalition-operator-1", "coalition-operator-2", "coalition-operator-3", "coalition-ledger",
    ]) {
      assert(!existsSync(join(paths.runRoot, runId, directory)), `${directory} was pruned at terminal`);
    }
    assert(existsSync(join(paths.runRoot, runId, "execution.json")), "the durable execution record remains");
    assert(existsSync(join(paths.runRoot, runId, "settlement-profile.json")), "the settlement commitment remains");
    const durable = JSON.parse(readFileSync(join(paths.runRoot, runId, "execution.json"), "utf8"));
    assert(durable.coalitionRelease?.policyConflict === expectations.policyConflict
      && durable.coalitionRelease?.sameEconomicAsset === expectations.sameEconomicAsset,
      "the durable state carries both released bits separately");

    const readback = await call(`${base}/v1/custom-cases/${runId}`);
    assert(readback.view.stage === "RELEASED", "the pruned run still reads back durably");
    assert(readback.progress === "Bounded action authorized",
      `the terminal coalition progress is the authorized bounded action (got ${JSON.stringify(readback.progress)})`);
    log(`  ${name} OK: sameEconomicAsset=${release.sameEconomicAsset} policyConflict=${release.policyConflict}`
      + ` settlement=${settlement.status} progress=${JSON.stringify(readback.progress)}`);
    return { runId, view: readback.view, progress: readback.progress };
  }

  const start = Math.floor(Date.now() / 1_000);
  const day = 24 * 3_600;

  const conflict = await runCase("conflict (overlapping windows)", {
    participantA: { activeFrom: start, activeUntil: start + 30 * day },
    participantB: { activeFrom: start + 10 * day, activeUntil: start + 40 * day },
  }, { sameEconomicAsset: true, policyConflict: true });

  const cleared = await runCase("no-conflict (disjoint windows)", {
    participantA: { activeFrom: start, activeUntil: start + 10 * day },
    participantB: { activeFrom: start + 20 * day, activeUntil: start + 30 * day },
  }, { sameEconomicAsset: true, policyConflict: false });

  worker.server.close();
  log(`\nBOTH JOURNEYS GREEN`);
  log(JSON.stringify({
    schemaVersion: "mordant.coalition-live-smoke/1",
    conflictRunId: conflict.runId,
    clearedRunId: cleared.runId,
    conflictProgress: conflict.progress,
    clearedProgress: cleared.progress,
  }, null, 2));
  process.exit(0);
}

main().catch((error) => {
  process.stderr.write(`${error instanceof Error ? error.stack ?? error.message : String(error)}\n`);
  process.exit(1);
});
