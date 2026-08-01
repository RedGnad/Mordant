// The four-handler stage framework.
//
//   prepare    produces canonical immutable inputs, once
//   execute    acts, using ONLY what preparation stored in the journal
//   reconcile  derives truth from the chain and durable artifacts
//   verify     independently checks the resulting state before CONFIRMED
//
// The separation is not stylistic. `execute` is handed the journal's frozen
// record and nothing else, so it is structurally incapable of regenerating a
// nonce, a nullifier, a salt or a calldata blob that preparation already fixed.
// A runner that passed the live context into execute would look identical and
// would silently broadcast values nobody reviewed.
import { STATES } from "./v5-journal.mjs";
import { TARGETS, guardedBroadcast } from "./v5-live-guard.mjs";

export class StageError extends Error {
  constructor(code, stage, detail) {
    super(`${code} [${stage}]${detail ? `: ${detail}` : ""}`);
    this.code = code;
    this.stage = stage;
    this.name = "StageError";
  }
}

/// Values a stage must never regenerate once prepared. Naming them here means
/// a drifting value is reported as "you regenerated the session nullifier"
/// rather than as an opaque digest mismatch.
export const IMMUTABLE_FIELDS = Object.freeze([
  "calldata",
  "sessionNonce",
  "sessionNullifier",
  "sessionCommitment",
  "ceremonyId",
  "keyId",
  "enrollmentNonceA",
  "enrollmentNonceB",
  "releaseId",
  "consentNonceA",
  "consentNonceB",
  "resultCommitment",
  "sourceSalt",
  "sessionSalt",
]);

/// Defines one stage. Every handler is optional except `verify`: a stage that
/// cannot be independently checked has no business marking itself CONFIRMED.
export function defineStage({ name, target = TARGETS.LOCAL, prepare, execute, reconcile, verify }) {
  if (!name) throw new StageError("STAGE_UNNAMED", "?", "a stage needs a name");
  if (typeof verify !== "function") {
    throw new StageError("STAGE_UNVERIFIABLE", name, "verify is required");
  }
  return { name, target, prepare, execute, reconcile, verify };
}

/// Freezes a prepared record so an execute handler cannot mutate it in place
/// and then broadcast the mutation.
function deepFreeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const key of Object.keys(value)) deepFreeze(value[key]);
  }
  return value;
}

/// Runs one stage to CONFIRMED, or returns early if it already is.
///
/// `context` carries the live world: clients, addresses, accounts, the chain.
/// It reaches `prepare`, `reconcile` and `verify`. It deliberately does NOT
/// reach `execute`.
export async function runStage(stage, context) {
  const { journal } = context;
  const state = journal.state(stage.name);

  if (state === STATES.AMBIGUOUS) {
    throw new StageError("STAGE_AMBIGUOUS", stage.name, journal.stage(stage.name).reason);
  }
  if (state === STATES.CONFIRMED) {
    // A crash may happen after the receipt transition but before the independent
    // readback is fsynced. Confirmation without this flag is therefore not a
    // licence to skip verification on restart.
    if (!journal.stage(stage.name).verified) await verifyAndSeal(stage, context);
    return { stage: stage.name, skipped: true };
  }
  if (state === STATES.FAILED) {
    throw new StageError("STAGE_FAILED", stage.name, journal.stage(stage.name).reason);
  }

  // 1. Reconcile before anything else. The chain, not the journal, decides
  //    whether work already happened.
  if (stage.reconcile) {
    const finding = await stage.reconcile(context);
    if (finding?.alreadyDone) {
      await journal.recordOffChain(stage.name, finding.outputs ?? {});
      await verifyAndSeal(stage, context);
      return { stage: stage.name, reconciled: true };
    }
    if (finding?.ambiguous) {
      await journal.markAmbiguous(stage.name, finding.reason ?? "reconciliation was inconclusive");
      throw new StageError("STAGE_AMBIGUOUS", stage.name, finding.reason);
    }
    if (finding?.awaitingExternal) {
      await journal.markAwaitingExternal(stage.name, finding.request ?? {});
      return { stage: stage.name, awaitingExternal: true };
    }
  }

  // 2. Prepare. The handler runs even when the stage is already PREPARED, so a
  //    preparation that is not deterministic is DETECTED rather than papered
  //    over: the journal refuses a differing record with PREPARED_INPUT_DRIFT.
  //
  //    A handler that must generate randomness (a salt, a nonce) receives the
  //    frozen record as `existing` and is required to reuse it. That is the
  //    only way to both freeze the value and keep the check meaningful.
  if (stage.prepare && journal.state(stage.name) !== STATES.AWAITING_EXTERNAL) {
    const existing = journal.state(stage.name) === STATES.PREPARED
      ? deepFreeze({ ...journal.stage(stage.name) })
      : null;
    const record = await stage.prepare({ ...context, existing });
    await journal.prepare(stage.name, record);
  }

  const prepared = deepFreeze({ ...journal.stage(stage.name) });

  // 3. Execute. It sees the frozen prepared record and the guard, and nothing
  //    else. No client, no accounts, no chance to re-derive.
  if (stage.execute) {
    const broadcast = (description, send) =>
      guardedBroadcast({ target: stage.target, description, send, env: context.env ?? process.env });

    // An execution capability is a deliberately tiny closure supplied by the
    // environment. It can submit only this stage's already-frozen calldata;
    // it is not the live context and exposes neither a signer nor a client.
    const execution = context.executionForStage?.(stage.name);
    const args = { prepared, broadcast, journal, stage: stage.name };
    if (execution) args.execution = execution;
    const outcome = await stage.execute(args);

    if (outcome?.awaitingExternal) {
      await journal.markAwaitingExternal(stage.name, outcome.request ?? {});
      return { stage: stage.name, awaitingExternal: true };
    }

    if (outcome?.transactionHash) {
      await journal.markBroadcast(stage.name, outcome.transactionHash);
      const receipt = await context.client.waitForTransactionReceipt({ hash: outcome.transactionHash });
      if (receipt.status !== "success") {
        await journal.markFailed(stage.name, `reverted in block ${receipt.blockNumber}`);
        throw new StageError("STAGE_REVERTED", stage.name, outcome.transactionHash);
      }
      await journal.markConfirmed(stage.name, {
        blockNumber: Number(receipt.blockNumber),
        blockHash: receipt.blockHash,
        gasUsed: String(receipt.gasUsed),
      });
    } else {
      await journal.recordOffChain(stage.name, outcome?.outputs ?? {});
    }
  } else {
    await journal.recordOffChain(stage.name, {});
  }

  // 4. Verify independently, from the world rather than from what execute
  //    returned. A stage that verified its own return value would confirm a
  //    lie as readily as a truth.
  await verifyAndSeal(stage, context);
  return { stage: stage.name, confirmed: true };
}

async function verifyAndSeal(stage, context) {
  const result = await stage.verify(context);
  if (result === false || result?.ok === false) {
    await context.journal.markFailed(stage.name, result?.reason ?? "verification failed");
    throw new StageError("STAGE_VERIFICATION_FAILED", stage.name, result?.reason);
  }
  const entry = context.journal.stage(stage.name);
  if (!entry.verified) {
    entry.verified = true;
    entry.verifiedAt = new Date().toISOString();
    entry.verification = result?.evidence ?? null;
    await context.journal.recordVerification?.(stage.name);
  }
}

/// Runs an ordered pipeline from wherever the journal left off.
export async function runPipeline(stages, context) {
  const results = [];
  for (const stage of stages) {
    const outcome = await runStage(stage, context);
    results.push(outcome);
    if (outcome.awaitingExternal) break;
    if (context.stopAfter && context.stopAfter === stage.name) break;
  }
  return results;
}
