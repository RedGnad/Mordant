// Dynamic preconditions, re-evaluated before EVERY Phase B continuation.
//
// A run may resume days later, on a different fee regime, with a different
// amount of the run already paid for. A precondition checked once at the start
// is therefore worthless: what matters is whether the balance covers the gas
// that REMAINS, at the fees that apply NOW.
//
// Monad checks a sender's balance against `gas_limit * maxFeePerGas`, not
// against gas actually used, and the runner sets `gas_limit = estimate * 1.3`.
// The requirement below is built on that ceiling rather than on settled cost,
// because the ceiling is what causes "Signer had insufficient balance".
import { statfs } from "node:fs/promises";

import { STAGES, STATES } from "./v5-journal.mjs";

/// Measured on the provisional deployment. These are real gas used, not
/// estimates, so the projection starts from observed cost rather than a guess.
export const MEASURED_GAS = Object.freeze({
  "fund-role": 27_514n,
  "deploy-eligibility": 472_049n,
  "deploy-settlement": 920_644n,
  "deploy-cvaToken": 920_723n,
  "deploy-adapter": 862_412n,
  "deploy-issuerRegistry": 1_000_855n,
  "deploy-factory": 13_068_846n,
  "deploy-governance": 3_834_348n,
  "deploy-sources": 2_181_578n,
  "deploy-verifier": 3_246_963n,
  "deploy-binder": 4_388_183n,
  "config-call": 78_917n,
});

/// Gas each remaining stage still has to pay for. Deployment and configuration
/// are measured; the later stages are bounded estimates, deliberately generous,
/// because underestimating here strands a run mid-way.
export const STAGE_GAS = Object.freeze({
  INITIALIZED: 0n,
  FINAL_STACK_PLANNED: 0n,
  FINAL_STACK_DEPLOYED:
    MEASURED_GAS["fund-role"] * 4n +
    MEASURED_GAS["deploy-eligibility"] +
    MEASURED_GAS["deploy-settlement"] +
    MEASURED_GAS["deploy-cvaToken"] +
    MEASURED_GAS["deploy-adapter"] +
    MEASURED_GAS["deploy-issuerRegistry"] +
    MEASURED_GAS["deploy-factory"] +
    MEASURED_GAS["deploy-governance"] +
    MEASURED_GAS["deploy-sources"] +
    MEASURED_GAS["deploy-verifier"] +
    MEASURED_GAS["deploy-binder"] +
    MEASURED_GAS["config-call"] * 10n,
  BYTECODE_VERIFIED: 0n,
  // Vault creation is a CREATE2 deployment plus admission checks.
  VAULT_CREATED: 6_000_000n,
  AWAITING_VAULT_APASS: 0n,
  // Activation includes the bounded local custody/funding prerequisites and
  // the protected receivable state transition.
  VAULT_ACTIVATED: 4_000_000n,
  SOURCE_A_COMMITTED: 200_000n,
  SOURCE_B_COMMITTED: 200_000n,
  GOVERNANCE_A_CREATED: 200_000n,
  GOVERNANCE_B_CREATED: 200_000n,
  SESSION_PREPARED: 0n,
  SESSION_NULLIFIER_RESERVED: 0n,
  SESSION_COMMITTED: 200_000n,
  CEREMONY_COMPLETED: 0n,
  ENROLLMENTS_ADMITTED: 0n,
  EVALUATION_COMPLETED: 0n,
  OPERATOR_RECOMPUTATION_COMPLETED: 0n,
  THRESHOLD_RELEASE_COMPLETED: 0n,
  VALIDATOR_ATTESTATIONS_COMPLETED: 0n,
  DISCLOSURE_CONSENTS_COMPLETED: 0n,
  BINDING_PREPARED: 0n,
  // The one atomic transaction: verifier acceptance, two source reveals, two
  // consent recoveries, quorum verification and the recourse write.
  BINDING_BROADCAST: 3_000_000n,
  BINDING_CONFIRMED: 0n,
  READBACKS_COMPLETED: 0n,
  NEGATIVES_COMPLETED: 0n, // eth_call only, costs nothing
  LEAK_AUDIT_COMPLETED: 0n,
  EVIDENCE_FINALIZED: 0n,
});

/// Disk each remaining stage still needs, in bytes. Measured where measured.
export const STAGE_DISK = Object.freeze({
  // 344 MB of ceremony material, written once and then read by each separated
  // operator process from its own directory.
  CEREMONY_COMPLETED: 344n * 1024n * 1024n,
  // Three operator directories, because no operator may share another's
  // artifacts.
  OPERATOR_RECOMPUTATION_COMPLETED: 3n * 344n * 1024n * 1024n,
  // Two FullFHE256 envelopes, measured at 37.75 MB of ciphertext transport.
  ENROLLMENTS_ADMITTED: 80n * 1024n * 1024n,
  EVALUATION_COMPLETED: 40n * 1024n * 1024n,
  // Process captures, journal, decoded events and the retained bundle.
  EVIDENCE_FINALIZED: 200n * 1024n * 1024n,
});

/// The runner's gas ceiling multiplier, mirroring `transactor` in priv8-chain.
export const GAS_LIMIT_MULTIPLIER_PERCENT = 130n;
/// Additional safety on top of the ceiling.
export const SAFETY_MULTIPLIER_PERCENT = 120n;
/// Reserve required beyond the safety-adjusted requirement.
export const RESERVE_PERCENT = 25n;
/// Never proceed below this much free disk regardless of what the projection says.
export const ABSOLUTE_MINIMUM_FREE_BYTES = 4n * 1024n * 1024n * 1024n;
/// Mandated margin over the projected remaining peak.
export const DISK_MARGIN_MULTIPLIER = 2n;

export class PreconditionError extends Error {
  constructor(code, detail, facts) {
    super(`${code}: ${detail}`);
    this.code = code;
    this.name = "PreconditionError";
    this.facts = facts;
  }
}

/// Gas still unpaid, given what the journal has already CONFIRMED.
export function remainingGas(journal) {
  let total = 0n;
  for (const name of STAGES) {
    if (journal.state(name) === STATES.CONFIRMED) continue;
    total += STAGE_GAS[name] ?? 0n;
  }
  return total;
}

/// Peak disk still required. Stages already CONFIRMED have either released
/// their working set or already written their evidence.
export function remainingDiskPeak(journal) {
  let total = 0n;
  for (const name of STAGES) {
    if (journal.state(name) === STATES.CONFIRMED) continue;
    total += STAGE_DISK[name] ?? 0n;
  }
  return total;
}

/// The balance the deployer must hold right now.
///
///   remaining gas
///     x gas-limit multiplier   (Monad charges against the limit, not the use)
///     x max fee per gas        (read from the current block, not assumed)
///     x safety multiplier
///     + 25% reserve
export function requiredBalance(remainingGasUnits, maxFeePerGas) {
  const ceiling = (remainingGasUnits * GAS_LIMIT_MULTIPLIER_PERCENT) / 100n;
  const atCurrentFees = ceiling * maxFeePerGas;
  const withSafety = (atCurrentFees * SAFETY_MULTIPLIER_PERCENT) / 100n;
  return withSafety + (withSafety * RESERVE_PERCENT) / 100n;
}

export function requiredFreeDisk(projectedPeak) {
  const withMargin = projectedPeak * DISK_MARGIN_MULTIPLIER;
  return withMargin > ABSOLUTE_MINIMUM_FREE_BYTES ? withMargin : ABSOLUTE_MINIMUM_FREE_BYTES;
}

const mon = (wei) => (Number(wei) / 1e18).toFixed(4);
const gib = (bytes) => (Number(bytes) / 1024 ** 3).toFixed(2);

/// Runs every dynamic precondition. Throws before any broadcast if one fails.
///
/// `path` is any path on the volume the run writes to; free space is read from
/// that volume rather than assumed to be the repository's.
export async function assertPreconditions({ journal, client, deployer, path }) {
  const block = await client.getBlock();
  const base = block.baseFeePerGas ?? (await client.getGasPrice());
  const maxFeePerGas = base * 2n + 2_000_000_000n;

  const gasUnits = remainingGas(journal);
  const required = requiredBalance(gasUnits, maxFeePerGas);
  const balance = await client.getBalance({ address: deployer });

  const projectedPeak = remainingDiskPeak(journal);
  const requiredDisk = requiredFreeDisk(projectedPeak);
  const stats = await statfs(path);
  const freeBytes = BigInt(stats.bavail) * BigInt(stats.bsize);

  const facts = {
    nextStage: journal.nextStage(),
    baseFeeGwei: Number(base) / 1e9,
    maxFeePerGasGwei: Number(maxFeePerGas) / 1e9,
    remainingGas: gasUnits.toString(),
    requiredBalanceMon: mon(required),
    actualBalanceMon: mon(balance),
    projectedDiskPeakGiB: gib(projectedPeak),
    requiredFreeGiB: gib(requiredDisk),
    actualFreeGiB: gib(freeBytes),
  };

  if (balance < required) {
    throw new PreconditionError(
      "INSUFFICIENT_BALANCE",
      `have ${mon(balance)} MON, need ${mon(required)} MON for ${gasUnits} remaining gas at ${facts.maxFeePerGasGwei} gwei`,
      facts,
    );
  }
  if (freeBytes < requiredDisk) {
    throw new PreconditionError(
      "INSUFFICIENT_DISK",
      `have ${gib(freeBytes)} GiB, need ${gib(requiredDisk)} GiB`,
      facts,
    );
  }
  return { ...facts, maxFeePerGas, passed: true };
}
