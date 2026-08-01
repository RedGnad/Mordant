// Reads the published private-matching evidence bundle for the explorer.
//
// The bundle under `docs/evidence/private-matching-v4/` is the only source. It
// was curated field by field from the M-PRIV8 run, so this module does no
// filtering of its own: everything it can read is already public.

import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

export const BUNDLE_DIRECTORY = "docs/evidence/private-matching-v4";

export type EvidenceSummary = Readonly<{
  network: Readonly<{ name: string; chainId: number }>;
  sessionCommitment: string;
  commitmentTransaction: string;
  commitmentBlock: string;
  bindingTransaction: string;
  bindingBlock: string;
  bindingGasUsed: string;
  bindingValue: string;
  anchor: string;
  relayer: string;
  identityMode: string;
  coalition: readonly number[];
  quorumSize: number;
  contractsVerified: number;
  contractsMismatched: number;
  leakScan: Readonly<{ neverLeaks: number; preBindingLeaks: number; positiveControls: string }>;
  replaysRejected: string;
  assetsMoved: boolean;
  provenance: Readonly<{ frozenContracts: string; runnerSource: string; evidenceSource: string }>;
}>;

async function readBundle<T>(root: string, name: string): Promise<T> {
  return JSON.parse(await readFile(resolve(root, BUNDLE_DIRECTORY, name), "utf8")) as T;
}

/**
 * Builds the explorer summary.
 *
 * Every number is read from the bundle rather than restated here, so the
 * explorer cannot drift from the evidence it claims to show.
 */
export async function loadEvidenceSummary(root = process.cwd()): Promise<EvidenceSummary> {
  const transactions = await readBundle<Record<string, never>>(root, "transactions.json");
  const readbacks = await readBundle<Record<string, never>>(root, "readbacks.json");
  const codeHashes = await readBundle<Record<string, never>>(root, "code-hashes.json");
  const leak = await readBundle<Record<string, never>>(root, "leak-scan.json");
  const performance = await readBundle<Record<string, never>>(root, "performance.json");
  const provenance = await readBundle<Record<string, never>>(root, "provenance.json");

  const asRecord = (value: unknown): Record<string, unknown> => value as Record<string, unknown>;
  const t = asRecord(transactions);
  const commitment = asRecord(t.commitment);
  const binding = asRecord(t.binding);
  const anchor = asRecord(t.anchor);
  const summary = asRecord(asRecord(codeHashes).summary);
  const leakSummary = asRecord(asRecord(leak).summary);
  const controls = asRecord(asRecord(leak).positiveControls);
  const ceremony = asRecord(asRecord(performance).ceremony);
  const quorum = asRecord(asRecord(performance).quorum);
  const replays = asRecord(readbacks).replays as ReadonlyArray<{ rejected: boolean }>;
  const assets = asRecord(asRecord(readbacks).assetMovement);
  const p = asRecord(provenance);

  return {
    network: t.network as { name: string; chainId: number },
    sessionCommitment: String(t.sessionCommitment),
    commitmentTransaction: String(commitment.transactionHash),
    commitmentBlock: String(commitment.block),
    bindingTransaction: String(binding.transactionHash),
    bindingBlock: String(binding.block),
    bindingGasUsed: String(binding.gasUsed),
    bindingValue: String(binding.value),
    anchor: String(anchor.vault),
    relayer: String(commitment.relayer),
    identityMode: String(asRecord(performance).identityMode),
    coalition: ceremony.coalition as readonly number[],
    quorumSize: Number(quorum.quorumSize),
    contractsVerified: Number(summary.contracts),
    contractsMismatched: (summary.mismatched as unknown[]).length,
    leakScan: {
      neverLeaks: Number(leakSummary.neverLeaks),
      preBindingLeaks: Number(leakSummary.preBindingLeaks),
      positiveControls:
        `${(controls.detectedRepresentations as unknown[]).length}/${(controls.detectedRepresentations as unknown[]).length}`,
    },
    replaysRejected: `${replays.filter((entry) => entry.rejected).length}/${replays.length}`,
    assetsMoved: Boolean(assets.moved),
    provenance: {
      frozenContracts: String(p.frozenContracts),
      runnerSource: String(p.runnerSource),
      evidenceSource: String(p.evidenceSource),
    },
  };
}
