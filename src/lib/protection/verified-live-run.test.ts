import assert from "node:assert/strict";
import { cpSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import {
  MINV01_ADDRESS,
  MONAD_TESTNET,
  RUN_PROVENANCES,
  RUN_PROVENANCE_BADGE,
  VERIFIED_LIVE_RUN_SOURCES,
  VerifiedLiveRunError,
  isLiveProvenance,
  loadVerifiedLiveRunReceipt,
  monadExplorerHref,
} from "./verified-live-run";
import { ausdcFromAtomic } from "../../components/live-product/live-product-view-model";

const RUN_ID = "e618abc2-0ac7-4d79-b201-44959a54b68c";
const ADAPTER = "0x9cD93089E02d301BDdfC86EaAbB39242272cAfa1";
const RELEASE_TX = "0x09b9bbfbab53f1782506850654fe0c7be1e81bf8a1eff692c5b43e0e3936d651";

/** Copies the committed evidence into a scratch root so a tamper is never written back. */
function scratchRoot(mutate?: (name: string, value: Record<string, unknown>) => void): string {
  const root = mkdtempSync(join(tmpdir(), "mordant-verified-live-"));
  mkdirSync(join(root, "docs", "evidence"), { recursive: true });
  for (const name of Object.values(VERIFIED_LIVE_RUN_SOURCES)) {
    const source = join(process.cwd(), "docs", "evidence", name);
    const target = join(root, "docs", "evidence", name);
    if (mutate === undefined) {
      cpSync(source, target);
      continue;
    }
    const value = JSON.parse(readFileSync(source, "utf8")) as Record<string, unknown>;
    mutate(name, value);
    writeFileSync(target, JSON.stringify(value, null, 2));
  }
  return root;
}

function refuses(code: string, mutate: (name: string, value: Record<string, unknown>) => void): void {
  const root = scratchRoot(mutate);
  assert.throws(
    () => loadVerifiedLiveRunReceipt(root),
    (error: unknown) => error instanceof VerifiedLiveRunError && error.code === code,
    `expected refusal ${code}`,
  );
}

test("the committed evidence parses into a verified live run receipt", () => {
  const receipt = loadVerifiedLiveRunReceipt(process.cwd());
  assert.equal(receipt.provenance, "VERIFIED_LIVE_RUN");
  assert.equal(receipt.runId, RUN_ID);
  assert.equal(receipt.network.chainId, 10_143);
  assert.equal(receipt.act.adapter, ADAPTER);
  assert.equal(receipt.act.releaseConsumedTx, RELEASE_TX);
  assert.equal(receipt.act.cureState, "CURE_OPEN");
  assert.equal(receipt.act.cureWindowSeconds, 600);
  assert.equal(receipt.decidePrivately.conflict, true);
  assert.equal(receipt.prove.terminalState, "Claimed");
});

test("the five chapters carry the exact economic facts", () => {
  const r = loadVerifiedLiveRunReceipt(process.cwd());
  // VERIFY
  assert.equal(r.verify.minv01, MINV01_ADDRESS);
  assert.equal(r.verify.minv01Untouched, true);
  assert.equal(r.verify.minv01AdapterBalanceBefore, "0");
  assert.equal(r.verify.minv01AdapterBalanceAfter, "0");
  // AUTHORIZE
  assert.equal(r.authorize.participants[0].wallet, "0x3883CbE36BE79bd8d1b73ff160B8E7c3CB983685");
  assert.equal(r.authorize.participants[1].wallet, "0x3DcF732b35406Cf5C115Bc0f5D40918DFD2aCdc9");
  assert.notEqual(r.authorize.participants[0].wallet, r.authorize.participants[1].wallet);
  for (const participant of r.authorize.participants) assert.equal(participant.apassVerified, true);
  // ACT
  assert.equal(r.act.entitlementOpenedAtomic, "4000");
  assert.equal(r.act.finalizeWasPermissionless, true);
  // PROVE
  assert.equal(r.prove.claimA.atomic, "2400");
  assert.equal(r.prove.claimB.atomic, "1600");
  assert.equal(r.prove.adapterBalanceBefore, "4000");
  assert.equal(r.prove.adapterBalanceAfter, "0");
  assert.equal(r.prove.holderABalanceBefore, "0");
  assert.equal(r.prove.holderABalanceAfter, "2400");
  assert.equal(r.prove.holderBBalanceBefore, "0");
  assert.equal(r.prove.holderBBalanceAfter, "1600");
  assert.equal(r.prove.openReserved, "0");
  assert.equal(r.prove.entitledUnpaid, "0");
  assert.equal(r.prove.solvent, true);
});

test("aUSDC renders with exact six-decimal atomic units behind it", () => {
  const r = loadVerifiedLiveRunReceipt(process.cwd());
  assert.equal(ausdcFromAtomic(r.prove.claimA.atomic).atomic, "2400");
  assert.equal(ausdcFromAtomic(r.prove.claimB.atomic).atomic, "1600");
  assert.equal(ausdcFromAtomic("2400").decimals, 6);
  // 2400 atomic aUSDC is 0.002400, which rounds to 0.00 at two displayed places:
  // the atomic string is therefore the authoritative amount, never the label.
  assert.equal(ausdcFromAtomic("2400").formatted, "0.00");
  assert.equal(ausdcFromAtomic("1000000").formatted, "1.00");
});

test("explorer links are built only from canonical network configuration", () => {
  assert.equal(monadExplorerHref("tx", RELEASE_TX), `${MONAD_TESTNET.explorerBase}/tx/${RELEASE_TX}`);
  assert.equal(monadExplorerHref("address", ADAPTER), `${MONAD_TESTNET.explorerBase}/address/${ADAPTER}`);
  assert.equal(monadExplorerHref("block", "51573394"), `${MONAD_TESTNET.explorerBase}/block/51573394`);
  // Anything malformed yields no link rather than a broken or misleading one.
  assert.equal(monadExplorerHref("tx", "not-a-hash"), null);
  assert.equal(monadExplorerHref("tx", null), null);
  assert.equal(monadExplorerHref("address", RELEASE_TX), null);
  assert.equal(monadExplorerHref("tx", `${RELEASE_TX}extra`), null);
  for (const kind of ["tx", "address", "block"] as const) {
    const href = monadExplorerHref(kind, kind === "block" ? "1" : kind === "tx" ? RELEASE_TX : ADAPTER);
    assert.ok(href !== null && href.startsWith("https://"), "explorer links must be https");
  }
});

test("every real transaction in the receipt yields a usable explorer link", () => {
  const r = loadVerifiedLiveRunReceipt(process.cwd());
  for (const hash of [
    r.act.adapterDeploymentTx, r.act.releaseConsumedTx, r.act.finalizeTx,
    r.prove.claimA.transactionHash, r.prove.claimB.transactionHash,
  ]) {
    assert.ok(monadExplorerHref("tx", hash) !== null, `no explorer link for ${hash}`);
  }
  assert.ok(monadExplorerHref("address", r.act.adapter) !== null);
  assert.ok(monadExplorerHref("address", r.verify.minv01) !== null);
});

test("provenance labelling keeps a fixture out of every live badge", () => {
  assert.deepEqual([...RUN_PROVENANCES], ["VERIFIED_LIVE_RUN", "LIVE_SESSION", "DEMO_FIXTURE"]);
  assert.equal(isLiveProvenance("VERIFIED_LIVE_RUN"), true);
  assert.equal(isLiveProvenance("LIVE_SESSION"), true);
  assert.equal(isLiveProvenance("DEMO_FIXTURE"), false);
  assert.equal(RUN_PROVENANCE_BADGE.DEMO_FIXTURE, "Demo fixture");
  assert.match(RUN_PROVENANCE_BADGE.DEMO_FIXTURE, /fixture/iu);
  assert.doesNotMatch(RUN_PROVENANCE_BADGE.DEMO_FIXTURE, /\blive\b/iu);
  // A completed real run is never called a demo.
  for (const badge of [RUN_PROVENANCE_BADGE.VERIFIED_LIVE_RUN, RUN_PROVENANCE_BADGE.LIVE_SESSION]) {
    assert.doesNotMatch(badge, /demo|fixture|simulat/iu);
  }
  assert.equal(loadVerifiedLiveRunReceipt(process.cwd()).provenance, "VERIFIED_LIVE_RUN");
});

test("the receipt exposes no secret and no private execution input", () => {
  const encoded = JSON.stringify(loadVerifiedLiveRunReceipt(process.cwd()));
  for (const forbidden of [
    "activeFrom", "activeUntil", "privateKey", "PRIVATE_KEY", "signingKey", "secretKey",
    "CLEANVERSE_API_KEY", "MORDANT_BRIDGE_ATTESTOR_PRIVATE_KEY", "publicRoot", "decryptorPrivate",
  ]) {
    assert.equal(encoded.includes(forbidden), false, `receipt exposed ${forbidden}`);
  }
  // Only commitments describe a participant's claim.
  assert.match(encoded, /"claimCommitment":"0x[0-9a-f]{64}"/u);
});

test("a disagreeing evidence set is refused rather than rendered", () => {
  refuses("RUN_MISMATCH", (name, value) => {
    if (name === VERIFIED_LIVE_RUN_SOURCES.terminal) value.runId = "00000000-0000-4000-8000-000000000000";
  });
  refuses("ADDRESS_MISMATCH", (name, value) => {
    if (name === VERIFIED_LIVE_RUN_SOURCES.release) value.adapter = "0x1111111111111111111111111111111111111111";
  });
  refuses("CONFLICT", (name, value) => {
    if (name === VERIFIED_LIVE_RUN_SOURCES.bridgeVerification) value.signedConflict = false;
  });
  refuses("EVIDENCE_DIGEST", (name, value) => {
    if (name === VERIFIED_LIVE_RUN_SOURCES.bridgeVerification) value.evidenceDigest = `sha256:${"0".repeat(64)}`;
  });
  refuses("SIGNATURE", (name, value) => {
    if (name === VERIFIED_LIVE_RUN_SOURCES.bridgeVerification) value.ed25519SignatureVerified = false;
  });
});

test("the settlement arithmetic must reconcile or the receipt refuses", () => {
  refuses("SETTLEMENT", (name, value) => {
    if (name !== VERIFIED_LIVE_RUN_SOURCES.terminal) return;
    const claims = value.claims as Record<string, Record<string, unknown>>;
    claims.holderA.amount = "9999";
  });
  refuses("RECONCILIATION", (name, value) => {
    if (name !== VERIFIED_LIVE_RUN_SOURCES.terminal) return;
    (value.reconciliation as Record<string, unknown>).exact = false;
  });
  refuses("MINV01", (name, value) => {
    if (name !== VERIFIED_LIVE_RUN_SOURCES.terminal) return;
    (value.minv01 as Record<string, unknown>).touched = true;
  });
  refuses("SOLVENT", (name, value) => {
    if (name !== VERIFIED_LIVE_RUN_SOURCES.terminal) return;
    (value.terminal as Record<string, unknown>).solvent = false;
  });
});

test("the real cure window cannot be shortened or bypassed in the receipt", () => {
  const r = loadVerifiedLiveRunReceipt(process.cwd());
  assert.equal(r.act.cureWindowSeconds, 600);
  // Finalization must be strictly after the real deadline.
  refuses("CURE", (name, value) => {
    if (name === VERIFIED_LIVE_RUN_SOURCES.terminal) value.finalizedAtChainTime = 1;
  });
  refuses("CASE_STATE", (name, value) => {
    if (name !== VERIFIED_LIVE_RUN_SOURCES.release) return;
    (value.caseState as Record<string, unknown>).stateName = "Claimed";
  });
  // A cured case is a different story and must not be told by this receipt.
  refuses("CURED", (name, value) => {
    if (name === VERIFIED_LIVE_RUN_SOURCES.terminal) value.cured = true;
  });
});

test("a claim paid to a wallet that did not participate is refused", () => {
  refuses("ADDRESS_MISMATCH", (name, value) => {
    if (name !== VERIFIED_LIVE_RUN_SOURCES.terminal) return;
    const claims = value.claims as Record<string, Record<string, unknown>>;
    claims.holderB.address = "0x981F6E0Ea94f45fDB8ee7680DC862212E3C720e0";
  });
});

test("an unreviewed adapter or an invalid adapter A-Pass is refused", () => {
  refuses("BYTECODE", (name, value) => {
    if (name === VERIFIED_LIVE_RUN_SOURCES.deployment) value.maskedMatchesReviewedArtifact = false;
  });
  refuses("APASS", (name, value) => {
    if (name === VERIFIED_LIVE_RUN_SOURCES.apass) value.isValidAPassOnChain = false;
  });
});

test("a missing committed artifact fails closed", () => {
  const root = mkdtempSync(join(tmpdir(), "mordant-verified-live-empty-"));
  mkdirSync(join(root, "docs", "evidence"), { recursive: true });
  assert.throws(
    () => loadVerifiedLiveRunReceipt(root),
    (error: unknown) => error instanceof VerifiedLiveRunError && error.code === "EVIDENCE_MISSING",
  );
});
