/**
 * The one client for the managed execution path.
 *
 * Both surfaces that can start a managed run, the full live product and the
 * landing's mini check, call these functions. There is deliberately no second
 * implementation: a second one would be a second thing to get wrong about
 * eligibility, about the single execution slot, or about which responses are
 * allowed to become a result on screen.
 *
 * Nothing here orchestrates FHE. It mints a token, hands the windows to the
 * worker, and reads the worker's own durable projection back. Every decision
 * about what actually runs stays server-side, exactly as before.
 */

import { parseManagedCaseEnvelope, type ManagedWorkerView } from "./managed-intake-adapter";

/** The pledge windows the worker accepts. Values never touch Vercel. */
export type ManagedWindows = Readonly<{
  participantA: Readonly<{ activeFrom: number; activeUntil: number }>;
  participantB: Readonly<{ activeFrom: number; activeUntil: number }>;
}>;

/** Safe subset of the eligibility result already returned by token issuance. */
export type ManagedEligibilityObservation = Readonly<{
  eligible: true;
  chainId: number;
  observedBlock: number;
}>;

/**
 * Why a start did not produce a run.
 *
 * `BUSY` is a first-class outcome rather than an error: one execution slot
 * exists by design, so a second visitor waits. `REJECTED` means the worker
 * answered with something this client refused to trust, which must never
 * degrade into a rendered result.
 */
export type ManagedStartOutcome =
  | Readonly<{
      kind: "STARTED";
      view: ManagedWorkerView;
      workerOrigin: string;
      eligibility: ManagedEligibilityObservation;
    }>
  | Readonly<{ kind: "BUSY" }>
  | Readonly<{ kind: "REJECTED" }>
  | Readonly<{ kind: "INELIGIBLE" }>
  | Readonly<{ kind: "FAILED"; message: string }>;

export class ManagedResponseRejected extends Error {}

const MANAGED_CHAIN_ID = 10_143;
const ADDRESS = /^0x[0-9a-fA-F]{40}$/u;

function record(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function eligibilityObservation(value: unknown, expectedHolder: string): ManagedEligibilityObservation | null {
  if (!record(value)) return null;
  if (value.schemaVersion !== "mordant.ccp-eligibility/1"
    || value.eligible !== true
    || value.chainId !== MANAGED_CHAIN_ID
    || typeof value.holderAddress !== "string"
    || !ADDRESS.test(value.holderAddress)
    || value.holderAddress.toLowerCase() !== expectedHolder.toLowerCase()
    || typeof value.observedBlock !== "number"
    || !Number.isSafeInteger(value.observedBlock)
    || value.observedBlock < 0) return null;
  return Object.freeze({ eligible: true, chainId: MANAGED_CHAIN_ID, observedBlock: value.observedBlock });
}

/**
 * Mints a launch token for this holder.
 *
 * Minted at submit time on purpose: the server re-checks A-Pass eligibility
 * against the chain rather than trusting an answer the page obtained earlier.
 */
async function issueLaunchToken(holderAddress: string): Promise<Readonly<{
  token: string;
  workerOrigin: string;
  eligibility: ManagedEligibilityObservation;
}> | null> {
  const response = await fetch("/api/live-protection/token", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ holderAddress }),
    cache: "no-store",
  });
  if (!response.ok) return null;
  const issued = await response.json() as unknown;
  if (!record(issued)
    || issued.schemaVersion !== "mordant.live-launch-token/1"
    || typeof issued.token !== "string"
    || issued.token === ""
    || typeof issued.workerOrigin !== "string") return null;
  const eligibility = eligibilityObservation(issued.eligibility, holderAddress);
  if (eligibility === null) return null;
  return Object.freeze({ token: issued.token, workerOrigin: issued.workerOrigin, eligibility });
}

/** Starts one managed run. The windows go straight to the worker; Vercel never sees them. */
export async function startManagedRun(
  holderAddress: string,
  windows: ManagedWindows,
): Promise<ManagedStartOutcome> {
  let issued: Readonly<{
    token: string;
    workerOrigin: string;
    eligibility: ManagedEligibilityObservation;
  }> | null;
  try {
    issued = await issueLaunchToken(holderAddress);
  } catch {
    return Object.freeze({ kind: "FAILED" as const, message: "The confidential check could not be started." });
  }
  if (issued === null) return Object.freeze({ kind: "INELIGIBLE" as const });

  try {
    const created = await fetch(`${issued.workerOrigin}/v1/custom-cases`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${issued.token}` },
      body: JSON.stringify(windows),
      cache: "no-store",
    });
    if (created.status === 409) return Object.freeze({ kind: "BUSY" as const });
    if (!created.ok) {
      return Object.freeze({ kind: "FAILED" as const, message: "The execution service refused the request." });
    }
    let raw: unknown;
    try {
      raw = await created.json();
    } catch {
      return Object.freeze({ kind: "REJECTED" as const });
    }
    const view = parseManagedCaseEnvelope(raw);
    if (view === null) return Object.freeze({ kind: "REJECTED" as const });
    return Object.freeze({
      kind: "STARTED" as const,
      view,
      workerOrigin: issued.workerOrigin,
      eligibility: issued.eligibility,
    });
  } catch {
    return Object.freeze({ kind: "FAILED" as const, message: "The confidential check could not be started." });
  }
}

/**
 * Reads the worker's durable projection for one run.
 *
 * Throws `ManagedResponseRejected` when the answer is unparseable or names a
 * different run, so a caller can never mistake a bad projection for progress.
 */
export async function readManagedRun(workerOrigin: string, runId: string): Promise<ManagedWorkerView> {
  const response = await fetch(`${workerOrigin}/v1/custom-cases/${runId}`, { cache: "no-store" });
  if (!response.ok) throw new Error("unreadable");
  let raw: unknown;
  try {
    raw = await response.json();
  } catch {
    throw new ManagedResponseRejected();
  }
  const view = parseManagedCaseEnvelope(raw);
  if (view === null || view.runId !== runId) throw new ManagedResponseRejected();
  return view;
}
