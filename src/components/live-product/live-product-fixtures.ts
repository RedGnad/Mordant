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

/** Mid-flight: the evaluator is running and no result exists. */
export const RUNNING_VIEW: ManagedWorkerView = Object.freeze({
  schemaVersion: "mordant.custom-supervised-protection-view/1",
  runId: "00000000-0000-4000-8000-000000000001",
  executionVariant: "CUSTOM_SUPERVISED",
  stage: "EVALUATED",
  terminalScenario: null,
  protectionCase: Object.freeze({ ...CASE, incidentState: "EVALUATED", recourseState: "NOT_OPEN", cureDeadline: null }),
  participantArtifactDigests: Object.freeze({ participantA: digest("a"), participantB: digest("b") }),
  evaluatedArtifactDigest: digest("e"),
  governedResult: null,
  recourse: null,
  receipt: null,
});

function receipt(conflict: boolean): Readonly<Record<string, unknown>> {
  return Object.freeze({
    executionVariant: "CUSTOM_SUPERVISED",
    authorization: { fheCaseId: CASE.fheCaseId, protectionBindingDigest: digest("p"), caseBindingDigest: digest("c") },
    execution: {
      participantArtifactDigests: [digest("a"), digest("b")],
      evaluatedArtifactDigest: digest("e"),
      evaluatorProvenance: digest("v"),
      decryptorProvenance: digest("d"),
    },
    governedResult: { digest: digest("g"), resultCiphertextDigest: digest("r") },
    terminal: {
      recourseRecordDigest: conflict ? digest("x") : null,
      incidentState: conflict ? "CONFLICT_CONFIRMED" : "CLEARED",
      recourseState: conflict ? "CURE_WINDOW" : "REFUSED",
      originalReceivableState: "OUTSTANDING",
    },
    receiptDigest: digest("z"),
  });
}

/**
 * The cure deadline is always computed from the moment the fixture is read, so a
 * fixture can never bake in a historical date the way the landing once did.
 */
export function conflictView(now: Date = new Date()): ManagedWorkerView {
  const deadline = new Date(now.getTime() + 24 * 60 * 60 * 1_000).toISOString();
  return Object.freeze({
    ...RUNNING_VIEW,
    runId: "00000000-0000-4000-8000-000000000002",
    stage: "COMPLETE",
    terminalScenario: "conflict" as const,
    protectionCase: Object.freeze({ ...CASE, incidentState: "CONFLICT_CONFIRMED", recourseState: "CURE_WINDOW", cureDeadline: deadline }),
    governedResult: Object.freeze({ conflict: true, digest: digest("g"), releaseMode: "governed-decryptor-v1" }),
    recourse: Object.freeze({ opened: true, reason: null }),
    receipt: receipt(true),
  });
}

export function noConflictView(): ManagedWorkerView {
  return Object.freeze({
    ...RUNNING_VIEW,
    runId: "00000000-0000-4000-8000-000000000003",
    stage: "COMPLETE",
    terminalScenario: "no-conflict" as const,
    protectionCase: Object.freeze({ ...CASE, incidentState: "CLEARED", recourseState: "REFUSED", cureDeadline: null }),
    governedResult: Object.freeze({ conflict: false, digest: digest("g"), releaseMode: "governed-decryptor-v1" }),
    recourse: Object.freeze({ opened: false, reason: "SIGNED_RESULT_FALSE" }),
    receipt: receipt(false),
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
    disabledReason: null,
  });
}
