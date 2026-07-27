import {
  buildCleanverseMonadComparisons,
  buildCleanverseMonadConclusions,
  buildCleanverseMonadMissingEvidence,
  buildDocumentationRecords,
  collectCleanverseMonadObservations,
  DEFAULT_CLEANVERSE_MONAD_TARGETS,
  MONAD_TESTNET_CHAIN_ID,
  MONAD_TESTNET_NAME,
  PROTECTED_DOCUMENTATION_UNAVAILABLE,
  type CleanverseMonadTargets,
  type DocumentationAvailability,
} from "./cleanverse-monad";
import {
  CLEANVERSE_DOCUMENTATION_LIVE_FETCHED_BY_GATE,
  CLEANVERSE_DOCUMENTATION_SOURCE_KIND,
  CLEANVERSE_DOCUMENTATION_VERSION,
  CLEANVERSE_DOCUMENTATION_VERSION_SOURCE,
} from "./documentation-v56";
import { assertExpectedChain, pinBlock } from "./observe";
import { parseEvidenceReport, type EvidenceReport } from "./report";
import { createReadOnlyRpcClient, type RpcTransport } from "./rpc";

export type EvidenceRunMode = "live-read-only" | "fixture";

export type EvidenceRunOptions = Readonly<{
  transport: RpcTransport;
  mode: EvidenceRunMode;
  generatedAt: string;
  repositoryCommit: string;
  documentation: DocumentationAvailability;
  targets?: CleanverseMonadTargets;
  /** Distance from the head, so a reorg cannot invalidate the pinned readings. */
  confirmations?: bigint;
}>;

/**
 * Executes the whole gate: network check, block pinning, read-only observations, comparison
 * against what documentation could actually be read, then a schema-validated report.
 */
export async function runCleanverseMonadEvidence(
  options: EvidenceRunOptions,
): Promise<EvidenceReport> {
  // Every read goes through the allowlisted wrapper, so no write method can be issued.
  const client = createReadOnlyRpcClient(options.transport);
  const targets = options.targets ?? DEFAULT_CLEANVERSE_MONAD_TARGETS;

  // Kill gate: refuse to read anything else on the wrong chain.
  const chainId = await assertExpectedChain(client, MONAD_TESTNET_CHAIN_ID);
  const block = await pinBlock(
    client,
    MONAD_TESTNET_NAME,
    chainId,
    options.confirmations ?? 20n,
  );

  // Recorded before the reads, so the artifact separates "when observed" from "when rendered".
  const onchainObservedAt = new Date().toISOString();
  const { observations, facts } = await collectCleanverseMonadObservations(client, targets, block);
  const documentationConsultedAt = options.documentation.protectedDocsConsultedAt ?? null;
  const docsRead = documentationConsultedAt !== null;
  const comparisons = buildCleanverseMonadComparisons(facts, targets, block, docsRead);

  return parseEvidenceReport({
    schemaVersion: 1,
    generatedAt: options.generatedAt,
    repositoryCommit: options.repositoryCommit,
    mode: options.mode,
    documentationSource: {
      sourceKind: docsRead ? CLEANVERSE_DOCUMENTATION_SOURCE_KIND : "unavailable",
      documentationVersion: docsRead
        ? CLEANVERSE_DOCUMENTATION_VERSION
        : PROTECTED_DOCUMENTATION_UNAVAILABLE,
      documentationVersionSource: docsRead
        ? CLEANVERSE_DOCUMENTATION_VERSION_SOURCE
        : "The access-gated page was not read by this run",
      documentationConsultedAt,
      liveFetchedByEvidenceGate: CLEANVERSE_DOCUMENTATION_LIVE_FETCHED_BY_GATE,
    },
    network: {
      name: block.network,
      chainId: block.chainId,
      blockNumber: block.blockNumber.toString(),
      blockHash: block.blockHash,
      onchainObservedAt,
    },
    documentation: buildDocumentationRecords(options.documentation, targets),
    onchainObservations: observations,
    comparisons,
    conclusions: buildCleanverseMonadConclusions(facts, comparisons, block),
    missingEvidence: buildCleanverseMonadMissingEvidence(facts),
  });
}
