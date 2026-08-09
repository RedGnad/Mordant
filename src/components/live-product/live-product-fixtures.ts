/**
 * Deterministic presentation fixtures.
 *
 * The two terminal fixtures mirror the shape of the retained public runs
 * 693a1cfc (conflict) and 5fac6616 (no conflict) so every result surface can be
 * built and tested without starting an execution. Digests are shortened but
 * well-formed; they are presentation fixtures, never evidence, and no component
 * may present them as a real run.
 */

import type { ManagedWorkerView } from "./managed-intake-adapter";
import {
  ausdcFromAtomic,
  type OnchainView,
  type WalletView,
} from "./live-product-view-model";

export const FIXTURE_NOTICE = "Design fixture. Not a real execution." as const;

function digest(seed: string): string {
  return `sha256:${seed.repeat(64).slice(0, 64)}`;
}

const CASE = Object.freeze({
  cleanverseAssetDigest: digest("7613136ebe7efb777c78cdf8bd73a5a3e5604b005875e05e1427cce9dbc4c95c"),
  fheCaseId: digest("2abc308b1a7e29f5436df95070d068cf8dd1113b74e9a2f72eb4204e24694441"),
});

/** BGV evaluation is complete; governed verification is pending and no result exists. */
export const RUNNING_VIEW: ManagedWorkerView = Object.freeze({
  schemaVersion: "mordant.custom-supervised-protection-view/1",
  runId: "00000000-0000-4000-8000-000000000001",
  executionVariant: "CUSTOM_SUPERVISED",
  stage: "EVALUATED",
  nextOperation: "verifyGovernedRelease",
  terminalScenario: null,
  protectionCase: Object.freeze({ ...CASE, incidentState: "EVALUATED", recourseState: "NOT_OPEN", cureDeadline: null }),
  participantArtifactDigests: Object.freeze({ participantA: digest("a"), participantB: digest("b") }),
  evaluatedArtifactDigest: digest("e"),
  governedResult: null,
  recourse: null,
  receipt: null,
  governedPolicy: null,
});

function receipt(conflict: boolean, runId: string): Readonly<Record<string, unknown>> {
  const events = conflict
    ? [
      { ordinal: 1, kind: "PROTECTED_HOLDER_SNAPSHOT_FIXED", atUnix: 1_700_000_001 },
      { ordinal: 2, kind: "FHE_CASE_CREATED", atUnix: 1_700_000_002 },
      { ordinal: 3, kind: "PARTICIPANT_A_ARTIFACT_BOUND", atUnix: null },
      { ordinal: 4, kind: "PARTICIPANT_B_ARTIFACT_BOUND", atUnix: null },
      { ordinal: 5, kind: "FHE_EVALUATION_BOUND", atUnix: null },
      { ordinal: 6, kind: "GOVERNED_RESULT_RELEASED", atUnix: 1_700_000_003 },
      { ordinal: 7, kind: "RECOURSE_BOUND", atUnix: 1_700_000_004 },
      { ordinal: 8, kind: "SIMULATED_CURE_WINDOW_COMPLETED", atUnix: 1_700_000_005 },
    ]
    : [
      { ordinal: 1, kind: "PROTECTED_HOLDER_SNAPSHOT_FIXED", atUnix: 1_700_000_001 },
      { ordinal: 2, kind: "FHE_CASE_CREATED", atUnix: 1_700_000_002 },
      { ordinal: 3, kind: "PARTICIPANT_A_ARTIFACT_BOUND", atUnix: null },
      { ordinal: 4, kind: "PARTICIPANT_B_ARTIFACT_BOUND", atUnix: null },
      { ordinal: 5, kind: "FHE_EVALUATION_BOUND", atUnix: null },
      { ordinal: 6, kind: "GOVERNED_RESULT_RELEASED", atUnix: 1_700_000_003 },
      { ordinal: 7, kind: "RECOURSE_REFUSED_BY_SIGNED_FALSE", atUnix: 1_700_000_003 },
    ];
  return Object.freeze({
    schemaVersion: "mordant.custom-supervised-protection-receipt/1",
    receiptDigest: digest("z"),
    runId,
    sourceCommit: "1".repeat(40),
    governedFheCommit: "2".repeat(40),
    executionVariant: "CUSTOM_SUPERVISED",
    authorization: {
      protectionBindingSchema: "mordant.protection-binding/2",
      fheCaseId: CASE.fheCaseId,
      protectionBindingDigest: digest("p"),
      caseBindingDigest: digest("c"),
    },
    execution: {
      participantArtifactDigests: [digest("a"), digest("b")],
      evaluatedArtifactDigest: digest("e"),
      evaluatorProvenance: digest("v"),
      decryptorProvenance: digest("d"),
      circuitId: "mordant.identity-full-fhe-256",
      parameterProfile: "mordant.bgv.identity-full-fhe-256.n15/v1",
    },
    governedResult: {
      conflict,
      digest: digest("g"),
      releaseMode: "governed-decryptor-v1",
      releaseOrdinal: 1,
      resultCiphertextDigest: digest("r"),
      independentlyRecomputedResultDigest: digest("r"),
    },
    terminal: {
      recourseOpened: conflict,
      recourseRefusal: conflict ? null : "SIGNED_RESULT_FALSE",
      recourseRecordDigest: conflict ? digest("x") : null,
      incidentState: conflict ? "CONFLICT_CONFIRMED" : "CLEARED",
      recourseState: conflict ? "CURE_WINDOW" : "REFUSED",
      originalReceivableState: "OUTSTANDING_INTACT",
    },
    chronology: {
      clockClass: conflict ? "SIMULATED_PROTOCOL_CLOCK" : "REAL_OBSERVED_CLOCK",
      signedAtUnix: 1_700_000_006,
      events,
    },
    disclosures: [
      "Supervised local single-host execution; not production authorized.",
      "Operator-entered pledge windows; synthetic lender fixtures and no real funds.",
      "Designated trusted decryptor; no threshold release and no native Monad FHE.",
      "The governed signed Boolean is the sole authority for the conflict/no-conflict result.",
      "Configured demo policy determines the recourse path; the Boolean does not assign legal responsibility, action ownership, deadline or payout amount.",
    ],
  });
}

/**
 * The cure deadline is always computed from the moment the fixture is read, so a
 * fixture can never bake in a historical date the way the landing once did.
 */
export function conflictView(now: Date = new Date()): ManagedWorkerView {
  const deadline = new Date(now.getTime() + 24 * 60 * 60 * 1_000).toISOString();
  const runId = "00000000-0000-4000-8000-000000000002";
  return Object.freeze({
    ...RUNNING_VIEW,
    runId,
    stage: "COMPLETE",
    terminalScenario: "conflict" as const,
    protectionCase: Object.freeze({ ...CASE, incidentState: "CONFLICT_CONFIRMED", recourseState: "CURE_WINDOW", cureDeadline: deadline }),
    governedResult: Object.freeze({ conflict: true, digest: digest("g"), releaseMode: "governed-decryptor-v1" }),
    recourse: Object.freeze({ opened: true, reason: null }),
    receipt: receipt(true, runId),
  });
}

export function noConflictView(): ManagedWorkerView {
  const runId = "00000000-0000-4000-8000-000000000003";
  return Object.freeze({
    ...RUNNING_VIEW,
    runId,
    stage: "COMPLETE",
    terminalScenario: "no-conflict" as const,
    protectionCase: Object.freeze({ ...CASE, incidentState: "CLEARED", recourseState: "REFUSED", cureDeadline: null }),
    governedResult: Object.freeze({ conflict: false, digest: digest("g"), releaseMode: "governed-decryptor-v1" }),
    recourse: Object.freeze({ opened: false, reason: "SIGNED_RESULT_FALSE" }),
    receipt: receipt(false, runId),
  });
}

// ---------------------------------------------------------------- wallet fixtures

export const WALLET_DISCONNECTED: WalletView = Object.freeze({
  state: "DISCONNECTED", address: null, connectorName: null, connectorUid: null,
  chainId: null, expectedChainId: 10_143, problem: null,
});

export const WALLET_WRONG_NETWORK: WalletView = Object.freeze({
  state: "WRONG_NETWORK",
  address: "0x911F99f424D47F08a15fcC771e94dcc2f7252B02",
  connectorName: "Injected wallet", connectorUid: "fixture-uid",
  chainId: 1, expectedChainId: 10_143,
  problem: "This wallet is on a different network. Switch it to Monad testnet to continue.",
});

export const WALLET_CONNECTED: WalletView = Object.freeze({
  ...WALLET_WRONG_NETWORK, state: "CONNECTED", chainId: 10_143, problem: null,
});

// ---------------------------------------------------------------- on-chain fixtures

/**
 * Every value here arrives from the contract branch later. Nothing is a real
 * address, amount or event, and the capability that would render it is off.
 */
export function onchainFixture(phase: OnchainView["phase"]): OnchainView {
  return Object.freeze({
    phase,
    evidence: Object.freeze({
      transactionHash: phase === "NOT_CONNECTED" ? null : `0x${"1".repeat(64)}`,
      blockNumber: phase === "NOT_CONNECTED" ? null : 51_248_337,
      contractAddress: phase === "NOT_CONNECTED" ? null : `0x${"2".repeat(40)}`,
      explorerBase: phase === "NOT_CONNECTED" ? null : "https://testnet.monadexplorer.com",
    }),
    entitlement: phase === "ENTITLEMENT_OPENED" || phase === "CLAIM_PENDING" || phase === "CLAIM_CONFIRMED"
      ? Object.freeze({
        holderA: ausdcFromAtomic("6000000"),
        holderB: ausdcFromAtomic("4000000"),
        claimedByA: phase === "CLAIM_CONFIRMED",
        claimedByB: false,
      })
      : null,
    cureDeadlineIso: null,
    disabledReason: null,
  });
}
