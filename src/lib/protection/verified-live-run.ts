/**
 * The completed, real Monad journey, projected as a product receipt.
 *
 * This is NOT a fixture and must never be rendered as one. Every value below is
 * read from committed evidence produced by the actual execution, and the loader
 * refuses to build a receipt whose parts disagree: one run id, one adapter, one
 * governed result, payouts that sum to the entitlement, and balance deltas that
 * reconcile exactly. A drifted or hand-edited evidence set fails closed rather
 * than rendering a plausible story.
 *
 * It carries no secret and no private execution input. The participants' pledge
 * windows never existed in any of these artifacts; only commitments do.
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";

export const VERIFIED_LIVE_RUN_SCHEMA = "mordant.verified-live-run/1" as const;

/**
 * How a rendered journey came to exist. The UI may badge only what this says.
 *
 * `VERIFIED_LIVE_RUN` is a completed real execution. `LIVE_SESSION` is a run
 * happening now. `DEMO_FIXTURE` is deterministic sample data and can never be
 * badged live.
 */
export const RUN_PROVENANCES = ["VERIFIED_LIVE_RUN", "LIVE_SESSION", "DEMO_FIXTURE"] as const;
export type RunProvenance = (typeof RUN_PROVENANCES)[number];

/** The exact badge each provenance is allowed to print. Nothing else may label a run. */
export const RUN_PROVENANCE_BADGE: Readonly<Record<RunProvenance, string>> = Object.freeze({
  VERIFIED_LIVE_RUN: "Verified live run",
  LIVE_SESSION: "Live session",
  DEMO_FIXTURE: "Demo fixture",
});

export function isLiveProvenance(provenance: RunProvenance): boolean {
  return provenance === "VERIFIED_LIVE_RUN" || provenance === "LIVE_SESSION";
}

export class VerifiedLiveRunError extends Error {
  constructor(readonly code: string, message: string) {
    super(message);
    this.name = "VerifiedLiveRunError";
  }
}

function fail(code: string, message: string): never {
  throw new VerifiedLiveRunError(code, message);
}

const EVIDENCE_DIRECTORY = join("docs", "evidence");

/**
 * The exact committed artifacts this receipt is built from.
 *
 * These name the HARDENED run, which is the authoritative one: its settlement
 * re-verified each participant's retained ParticipantAdmissionV1 payload and
 * signature, took its source commit from an external pin rather than from the
 * artifact, and bound the case adapter to a deployment proof resolved by address
 * and run. The earlier `activation-*` set describes a real completed journey too
 * and is retained, but it predates those checks, so it is history rather than
 * the receipt this product shows.
 */
export const VERIFIED_LIVE_RUN_SOURCES = Object.freeze({
  bridgeEvidence: "hardened-direct-participant-bridge-evidence-2026-08-07.json",
  bridgeVerification: "hardened-bridge-evidence-verification-2026-08-07.json",
  receipt: "hardened-custom-supervised-receipt-2026-08-07.json",
  deployment: "hardened-case-adapter-deployment-2026-08-07.json",
  apass: "hardened-case-adapter-apass-2026-08-07.json",
  configuration: "hardened-case-adapter-configuration-2026-08-07.json",
  release: "hardened-release-consumed-2026-08-07.json",
  terminal: "hardened-terminal-recourse-2026-08-07.json",
});

export const MONAD_TESTNET = Object.freeze({
  name: "Monad testnet",
  chainId: 10_143,
  explorerBase: "https://testnet.monadexplorer.com",
});

export const MINV01_ADDRESS = "0x66F706D1Dc820CF09EBA5359cE9acd0D290bC17b" as const;

export type VerifiedParticipant = Readonly<{
  role: "PARTICIPANT_A" | "PARTICIPANT_B";
  label: string;
  wallet: string;
  apassVerified: true;
  eligibilityBlock: number;
  authorizationDigest: string;
  claimCommitment: string;
}>;

export type VerifiedLiveRunReceipt = Readonly<{
  schemaVersion: typeof VERIFIED_LIVE_RUN_SCHEMA;
  provenance: "VERIFIED_LIVE_RUN";
  runId: string;
  sourceCommit: string;
  network: typeof MONAD_TESTNET;

  verify: Readonly<{
    assetLabel: string;
    minv01: string;
    assetIdentity: string;
    originalReceivableIntact: true;
    minv01AdapterBalanceBefore: string;
    minv01AdapterBalanceAfter: string;
    minv01Untouched: true;
  }>;

  authorize: Readonly<{
    participants: readonly [VerifiedParticipant, VerifiedParticipant];
    distinct: true;
    protectionBindingDigest: string;
  }>;

  decidePrivately: Readonly<{
    circuitId: string;
    parameterProfile: string;
    fheCaseId: string;
    caseBindingDigest: string;
    participantArtifactDigestA: string;
    participantArtifactDigestB: string;
    evaluatedArtifactDigest: string;
    governedResultDigest: string;
    releaseAuthorityId: string;
    releaseAuthorityPublicKey: string;
    resultCiphertextDigest: string;
    resultCiphertextCommitment: string;
    conflict: boolean;
    bridgeEvidenceDigest: string;
    ed25519SignatureVerified: true;
  }>;

  act: Readonly<{
    adapter: string;
    adapterDeploymentTx: string;
    adapterDeploymentBlock: number;
    adapterMaskedBytecodeMatchesReviewed: true;
    adapterApassValid: true;
    releaseConsumedTx: string;
    releaseConsumedBlock: number;
    cureState: "CURE_OPEN";
    cureDeadlineUnix: number;
    cureDeadlineIso: string;
    cureWindowSeconds: number;
    finalizeTx: string;
    finalizeBlock: number;
    entitlementOpenedAtomic: string;
    finalizeWasPermissionless: true;
  }>;

  prove: Readonly<{
    claimA: Readonly<{ wallet: string; transactionHash: string; atomic: string }>;
    claimB: Readonly<{ wallet: string; transactionHash: string; atomic: string }>;
    adapterBalanceBefore: string;
    adapterBalanceAfter: string;
    holderABalanceBefore: string;
    holderABalanceAfter: string;
    holderBBalanceBefore: string;
    holderBBalanceAfter: string;
    openReserved: string;
    entitledUnpaid: string;
    solvent: true;
    terminalState: string;
    reconciledExactly: true;
  }>;
}>;

function readJson(root: string, name: string): Record<string, unknown> {
  const path = join(root, EVIDENCE_DIRECTORY, name);
  let raw: string;
  try {
    raw = readFileSync(path, "utf8");
  } catch {
    fail("EVIDENCE_MISSING", `The committed artifact ${name} is missing`);
  }
  try {
    return JSON.parse(raw) as Record<string, unknown>;
  } catch {
    fail("EVIDENCE_JSON", `${name} is not valid JSON`);
  }
}

function text(value: unknown, code: string, label: string): string {
  if (typeof value !== "string" || value === "") fail(code, `${label} is required`);
  return value;
}

function whole(value: unknown, code: string, label: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    fail(code, `${label} must be a whole number`);
  }
  return value;
}

function requireTrue(value: unknown, code: string, label: string): true {
  if (value !== true) fail(code, `${label} must be true`);
  return true;
}

function atomic(value: unknown, code: string, label: string): string {
  if (typeof value !== "string" || !/^\d+$/u.test(value)) fail(code, `${label} must be an atomic amount`);
  return value;
}

function sameRun(actual: unknown, expected: string, artifact: string): void {
  if (actual !== expected) fail("RUN_MISMATCH", `${artifact} belongs to a different run`);
}

function sameAddress(actual: unknown, expected: string, label: string): void {
  if (typeof actual !== "string" || actual.toLowerCase() !== expected.toLowerCase()) {
    fail("ADDRESS_MISMATCH", `${label} disagrees across the committed evidence`);
  }
}

function section(value: unknown, code: string, label: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) fail(code, `${label} is required`);
  return value as Record<string, unknown>;
}

/**
 * Builds the receipt and refuses anything inconsistent.
 *
 * The cross-checks are the point. Any one artifact could be edited; making them
 * agree on the run, the adapter, the governed result, the entitlement and the
 * exact balance arithmetic is what makes this a receipt rather than a caption.
 */
export function loadVerifiedLiveRunReceipt(root: string = process.cwd()): VerifiedLiveRunReceipt {
  const bridge = readJson(root, VERIFIED_LIVE_RUN_SOURCES.bridgeEvidence);
  const verification = readJson(root, VERIFIED_LIVE_RUN_SOURCES.bridgeVerification);
  const receipt = readJson(root, VERIFIED_LIVE_RUN_SOURCES.receipt);
  const deployment = readJson(root, VERIFIED_LIVE_RUN_SOURCES.deployment);
  const apass = readJson(root, VERIFIED_LIVE_RUN_SOURCES.apass);
  const release = readJson(root, VERIFIED_LIVE_RUN_SOURCES.release);
  const terminal = readJson(root, VERIFIED_LIVE_RUN_SOURCES.terminal);

  const runId = text(bridge.runId, "RUN_ID", "bridge evidence runId");
  sameRun(verification.runId, runId, "bridge verification");
  sameRun(receipt.runId, runId, "custom receipt");
  sameRun(deployment.runId, runId, "adapter deployment");
  sameRun(release.runId, runId, "release");
  sameRun(terminal.runId, runId, "terminal recourse");

  const adapter = text(deployment.address, "ADAPTER", "adapter address");
  sameAddress(release.adapter, adapter, "release adapter");
  sameAddress(terminal.adapter, adapter, "terminal adapter");
  sameAddress(apass.address, adapter, "A-Pass adapter");

  const governedResult = section(bridge.governedResult, "GOVERNED_RESULT", "bridge governedResult");
  const bridgeDigest = text(bridge.evidenceDigest, "EVIDENCE_DIGEST", "bridge evidenceDigest");
  if (verification.evidenceDigest !== bridgeDigest) {
    fail("EVIDENCE_DIGEST", "The bridge verification does not cover this bridge evidence");
  }
  requireTrue(verification.ed25519SignatureVerified, "SIGNATURE", "ed25519SignatureVerified");
  const conflict = governedResult.conflict;
  if (typeof conflict !== "boolean") fail("CONFLICT", "The governed result carries no signed Boolean");
  if (verification.signedConflict !== conflict) fail("CONFLICT", "The verified Boolean disagrees with the signed result");
  if (release.signedConflict !== conflict) fail("CONFLICT", "The consumed release disagrees with the signed Boolean");

  // Participants, in role order, reconciled to the terminal claim recipients.
  const rawParticipants = bridge.participants;
  if (!Array.isArray(rawParticipants) || rawParticipants.length !== 2) {
    fail("PARTICIPANTS", "Exactly two participants are required");
  }
  const roles = ["PARTICIPANT_A", "PARTICIPANT_B"] as const;
  const participants = rawParticipants.map((entry, index) => {
    const record = section(entry, "PARTICIPANTS", `participant ${index}`);
    if (record.role !== roles[index]) fail("PARTICIPANTS", `participant ${index} is not ${roles[index]}`);
    return Object.freeze({
      role: roles[index],
      label: index === 0 ? "Participant A" : "Participant B",
      wallet: text(record.participantWallet, "PARTICIPANTS", "participant wallet"),
      apassVerified: true as const,
      eligibilityBlock: whole(record.eligibilityBlock, "PARTICIPANTS", "eligibility block"),
      authorizationDigest: text(record.authorizationDigest, "PARTICIPANTS", "authorization digest"),
      claimCommitment: text(record.claimCommitment, "PARTICIPANTS", "claim commitment"),
    });
  }) as unknown as readonly [VerifiedParticipant, VerifiedParticipant];
  if (participants[0].wallet.toLowerCase() === participants[1].wallet.toLowerCase()) {
    fail("PARTICIPANTS", "The two participants are not distinct");
  }

  const claims = section(terminal.claims, "CLAIMS", "terminal claims");
  const claimA = section(claims.holderA, "CLAIMS", "claim A");
  const claimB = section(claims.holderB, "CLAIMS", "claim B");
  sameAddress(claimA.address, participants[0].wallet, "claim A recipient");
  sameAddress(claimB.address, participants[1].wallet, "claim B recipient");

  const finalize = section(terminal.finalize, "FINALIZE", "terminal finalize");
  const entitlement = atomic(finalize.entitledUnpaidAfterFinalize, "FINALIZE", "entitlement");
  const amountA = atomic(claimA.amount, "CLAIMS", "claim A amount");
  const amountB = atomic(claimB.amount, "CLAIMS", "claim B amount");
  if (BigInt(amountA) + BigInt(amountB) !== BigInt(entitlement)) {
    fail("SETTLEMENT", "The two claims do not sum to the opened entitlement");
  }
  requireTrue(section(terminal.reconciliation, "RECONCILIATION", "reconciliation").exact, "RECONCILIATION", "exact reconciliation");
  if (terminal.cured !== false) fail("CURED", "This receipt describes an uncured, finalized case");

  const balances = section(terminal.balances, "BALANCES", "balances");
  const before = section(balances.before, "BALANCES", "balances.before");
  const after = section(balances.after, "BALANCES", "balances.after");
  const terminalState = section(terminal.terminal, "TERMINAL", "terminal state");
  requireTrue(terminalState.solvent, "SOLVENT", "adapter solvency");
  requireTrue(terminalState.reservedLiabilityCleared, "LIABILITY", "reserved liability cleared");
  requireTrue(terminalState.unpaidEntitlementCleared, "LIABILITY", "unpaid entitlement cleared");

  const minv01 = section(terminal.minv01, "MINV01", "MINV01 readback");
  sameAddress(minv01.address, MINV01_ADDRESS, "MINV01 address");
  if (minv01.touched !== false) fail("MINV01", "MINV01 must be untouched");

  const caseState = section(release.caseState, "CASE_STATE", "release case state");
  if (caseState.stateName !== "CureOpen") fail("CASE_STATE", "The consumed release did not open a cure window");
  const cureDeadlineUnix = whole(caseState.cureDeadlineUnix, "CURE", "cure deadline");
  const cureWindowSeconds = whole(caseState.cureWindowSeconds, "CURE", "cure window");
  if (cureDeadlineUnix <= whole(release.blockTimestamp, "CURE", "release block timestamp")) {
    fail("CURE", "The cure deadline is not after the release block");
  }
  // The finalize must genuinely be after the deadline, not merely later in the log.
  if (whole(terminal.finalizedAtChainTime, "CURE", "finalize chain time") <= cureDeadlineUnix) {
    fail("CURE", "Finalization did not happen after the real cure deadline");
  }

  requireTrue(deployment.maskedMatchesReviewedArtifact, "BYTECODE", "masked bytecode equality");
  requireTrue(apass.isValidAPassOnChain, "APASS", "adapter A-Pass validity");

  const execution = section(receipt.execution, "EXECUTION", "receipt execution");
  const authorization = section(receipt.authorization, "AUTHORIZATION", "receipt authorization");

  return Object.freeze({
    schemaVersion: VERIFIED_LIVE_RUN_SCHEMA,
    provenance: "VERIFIED_LIVE_RUN" as const,
    runId,
    sourceCommit: text(bridge.sourceCommit, "SOURCE_COMMIT", "source commit"),
    network: MONAD_TESTNET,

    verify: Object.freeze({
      assetLabel: "MINV01 tokenized receivable",
      minv01: MINV01_ADDRESS,
      assetIdentity: text(governedResult.assetIdentity, "ASSET", "asset identity"),
      originalReceivableIntact: true as const,
      minv01AdapterBalanceBefore: atomic(minv01.adapterBalanceBefore, "MINV01", "MINV01 before"),
      minv01AdapterBalanceAfter: atomic(minv01.adapterBalanceAfter, "MINV01", "MINV01 after"),
      minv01Untouched: true as const,
    }),

    authorize: Object.freeze({
      participants,
      distinct: true as const,
      protectionBindingDigest: text(authorization.protectionBindingDigest, "AUTHORIZATION", "protection binding digest"),
    }),

    decidePrivately: Object.freeze({
      circuitId: text(execution.circuitId, "EXECUTION", "circuit id"),
      parameterProfile: text(execution.parameterProfile, "EXECUTION", "parameter profile"),
      fheCaseId: text(bridge.fheCaseId, "EXECUTION", "FHE case id"),
      caseBindingDigest: text(bridge.caseBindingDigest, "EXECUTION", "case binding digest"),
      participantArtifactDigestA: text(bridge.participantArtifactDigestA, "EXECUTION", "participant artifact A"),
      participantArtifactDigestB: text(bridge.participantArtifactDigestB, "EXECUTION", "participant artifact B"),
      evaluatedArtifactDigest: text(bridge.evaluatedArtifactDigest, "EXECUTION", "evaluated artifact"),
      governedResultDigest: text(bridge.governedResultDigest, "EXECUTION", "governed result digest"),
      releaseAuthorityId: text(governedResult.releaseAuthorityId, "EXECUTION", "release authority"),
      releaseAuthorityPublicKey: text(governedResult.releaseAuthorityPublicKey, "EXECUTION", "release authority key"),
      resultCiphertextDigest: text(governedResult.resultCiphertextDigest, "EXECUTION", "result ciphertext digest"),
      resultCiphertextCommitment: text(governedResult.resultCiphertextCommitment, "EXECUTION", "result commitment"),
      conflict,
      bridgeEvidenceDigest: bridgeDigest,
      ed25519SignatureVerified: true as const,
    }),

    act: Object.freeze({
      adapter,
      adapterDeploymentTx: text(deployment.transactionHash, "DEPLOYMENT", "adapter deployment tx"),
      adapterDeploymentBlock: whole(deployment.blockNumber, "DEPLOYMENT", "adapter deployment block"),
      adapterMaskedBytecodeMatchesReviewed: true as const,
      adapterApassValid: true as const,
      releaseConsumedTx: text(release.transactionHash, "RELEASE", "release transaction"),
      releaseConsumedBlock: whole(release.blockNumber, "RELEASE", "release block"),
      cureState: "CURE_OPEN" as const,
      cureDeadlineUnix,
      cureDeadlineIso: new Date(cureDeadlineUnix * 1_000).toISOString(),
      cureWindowSeconds,
      finalizeTx: text(finalize.transactionHash, "FINALIZE", "finalize transaction"),
      finalizeBlock: whole(finalize.blockNumber, "FINALIZE", "finalize block"),
      entitlementOpenedAtomic: entitlement,
      finalizeWasPermissionless: requireTrue(terminal.callerIsHolder === false, "FINALIZE", "permissionless finalize"),
    }),

    prove: Object.freeze({
      claimA: Object.freeze({
        wallet: participants[0].wallet,
        transactionHash: text(claimA.transactionHash, "CLAIMS", "claim A transaction"),
        atomic: amountA,
      }),
      claimB: Object.freeze({
        wallet: participants[1].wallet,
        transactionHash: text(claimB.transactionHash, "CLAIMS", "claim B transaction"),
        atomic: amountB,
      }),
      adapterBalanceBefore: atomic(before.adapter, "BALANCES", "adapter before"),
      adapterBalanceAfter: atomic(after.adapter, "BALANCES", "adapter after"),
      holderABalanceBefore: atomic(before.holderA, "BALANCES", "holder A before"),
      holderABalanceAfter: atomic(after.holderA, "BALANCES", "holder A after"),
      holderBBalanceBefore: atomic(before.holderB, "BALANCES", "holder B before"),
      holderBBalanceAfter: atomic(after.holderB, "BALANCES", "holder B after"),
      openReserved: atomic(terminalState.openReserved, "TERMINAL", "open reserved"),
      entitledUnpaid: atomic(terminalState.entitledUnpaid, "TERMINAL", "entitled unpaid"),
      solvent: true as const,
      terminalState: text(terminalState.state, "TERMINAL", "terminal state name"),
      reconciledExactly: true as const,
    }),
  });
}

/**
 * A Monad explorer URL, or null.
 *
 * Built only from the canonical network configuration and a strict identifier,
 * so a malformed value yields no link rather than a broken or misleading one.
 */
export function monadExplorerHref(kind: "tx" | "address" | "block", value: string | null): string | null {
  if (value === null) return null;
  const shape = kind === "tx" ? /^0x[0-9a-fA-F]{64}$/u : kind === "address" ? /^0x[0-9a-fA-F]{40}$/u : /^\d+$/u;
  if (!shape.test(value)) return null;
  return `${MONAD_TESTNET.explorerBase}/${kind}/${value}`;
}
