import assert from "node:assert/strict";
import test from "node:test";
import {
  ALLOWED_CHAIN_IDS,
  MONAD_TESTNET_CHAIN_ID,
  NetworkNotAllowedError,
  PRIVATE_MATCHING_COPY,
  PROHIBITED_CLAIMS,
  assertNetworkAllowed,
  canStartLiveSession,
  readPrivateMatchingFlags,
} from "./config";

test("every flag is off when the environment says nothing", () => {
  const flags = readPrivateMatchingFlags({});
  assert.deepEqual(flags, {
    enabled: false,
    evidenceExplorerEnabled: false,
    demoEnabled: false,
    liveSessionsEnabled: false,
  });
});

test("only an explicit true or 1 enables a flag", () => {
  assert.equal(readPrivateMatchingFlags({ NEXT_PUBLIC_PRIVATE_MATCHING_ENABLED: "true" }).enabled, true);
  assert.equal(readPrivateMatchingFlags({ NEXT_PUBLIC_PRIVATE_MATCHING_ENABLED: "1" }).enabled, true);
  for (const value of ["", "yes", "TRUE", "on", "false", "0"]) {
    assert.equal(
      readPrivateMatchingFlags({ NEXT_PUBLIC_PRIVATE_MATCHING_ENABLED: value }).enabled,
      false,
      `"${value}" must not enable the feature`,
    );
  }
});

test("the network allow-list contains Monad testnet and nothing else", () => {
  assert.deepEqual([...ALLOWED_CHAIN_IDS], [MONAD_TESTNET_CHAIN_ID]);
  assert.doesNotThrow(() => assertNetworkAllowed(MONAD_TESTNET_CHAIN_ID));
  // Ethereum, Base, Optimism, Arbitrum and Monad mainnet must all be refused.
  for (const chainId of [1, 8453, 10, 42_161, 143]) {
    assert.throws(() => assertNetworkAllowed(chainId), NetworkNotAllowedError);
  }
});

test("a live session needs both flags and an allowed chain", () => {
  const all = {
    enabled: true, evidenceExplorerEnabled: true, demoEnabled: true, liveSessionsEnabled: true,
  };
  assert.equal(canStartLiveSession(all, MONAD_TESTNET_CHAIN_ID), true);
  // Mainnet stays refused even with every flag on: the allow-list is not a flag.
  assert.equal(canStartLiveSession(all, 1), false);
  assert.equal(canStartLiveSession({ ...all, enabled: false }, MONAD_TESTNET_CHAIN_ID), false);
  assert.equal(canStartLiveSession({ ...all, liveSessionsEnabled: false }, MONAD_TESTNET_CHAIN_ID), false);
});

test("the approved copy carries no prohibited claim", () => {
  const surface = [
    PRIVATE_MATCHING_COPY.title,
    PRIVATE_MATCHING_COPY.summary,
    ...PRIVATE_MATCHING_COPY.bullets,
    ...PRIVATE_MATCHING_COPY.disclaimers,
  ].join(" ").toLowerCase();
  for (const claim of PROHIBITED_CLAIMS) {
    // "publicly proven" is prohibited as a claim, so the disclaimer states the
    // negative. Assert the affirmative form is absent.
    if (claim === "publicly proven") {
      assert.ok(
        !surface.includes("is publicly proven"),
        "copy must not assert that FHE execution is publicly proven",
      );
      continue;
    }
    assert.ok(!surface.includes(claim), `copy must not contain "${claim}"`);
  }
});

test("the copy states the bounds the evidence actually carries", () => {
  const disclaimers = PRIVATE_MATCHING_COPY.disclaimers.join(" ");
  assert.match(disclaimers, /Monad testnet/);
  assert.match(disclaimers, /quorum-attested/);
  assert.match(disclaimers, /not publicly proven/);
  assert.match(disclaimers, /Organizational independence/);
  assert.match(disclaimers, /No traffic-analysis privacy/);
});

/* ------------------------------------------------------- evidence explorer */

test("the evidence explorer reads the published bundle", async () => {
  const { loadEvidenceSummary } = await import("./evidence.js");
  const summary = await loadEvidenceSummary(process.cwd());

  assert.equal(summary.network.chainId, MONAD_TESTNET_CHAIN_ID);
  assert.match(summary.sessionCommitment, /^0x[0-9a-f]{64}$/);
  assert.match(summary.commitmentTransaction, /^0x[0-9a-f]{64}$/);
  assert.match(summary.bindingTransaction, /^0x[0-9a-f]{64}$/);

  // The claims the product surface is allowed to make, read from the evidence
  // rather than restated: they must actually hold.
  assert.equal(summary.identityMode, "full_fhe_256");
  assert.equal(summary.quorumSize, 2);
  assert.equal(summary.contractsMismatched, 0);
  assert.equal(summary.leakScan.neverLeaks, 0);
  assert.equal(summary.leakScan.preBindingLeaks, 0);
  assert.equal(summary.bindingValue, "0");
  assert.equal(summary.assetsMoved, false);
  assert.equal(summary.provenance.frozenContracts, "af5baad");
  assert.equal(summary.provenance.runnerSource, "3ca83ed");
  assert.equal(summary.provenance.evidenceSource, "dfa8fbe");

  const [rejected, total] = summary.replaysRejected.split("/").map(Number);
  assert.ok(total > 0 && rejected === total, "every replay must be rejected");
});
