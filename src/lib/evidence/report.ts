import { z } from "zod";

import { EVIDENCE_CLASSIFICATIONS } from "./observe";
import { assertNoSecretLeak, redactSecrets } from "./redaction";

/**
 * Status vocabulary for a documentation-versus-deployment comparison. These literals are a
 * protocol between the evidence gate and its reviewers, so they are matched exactly.
 */
export const COMPARISON_STATUSES = [
  "MATCH",
  "NOT PROVEN",
  "BLOCKED",
  "BLOCKED — DOC/DEPLOYMENT VERSION SKEW",
  "NOT APPLICABLE",
] as const;

export type ComparisonStatus = (typeof COMPARISON_STATUSES)[number];

export const DOC_DEPLOYMENT_SKEW: ComparisonStatus = "BLOCKED — DOC/DEPLOYMENT VERSION SKEW";

/** Used whenever a documentation page states no version. Never inferred. */
export const UNSTATED_VERSION = "UNSTATED" as const;

export const documentationRecordSchema = z.object({
  pageTitle: z.string().min(1),
  pagePath: z.string().min(1),
  documentationVersion: z.string().min(1),
  documentationVersionSource: z.string().min(1),
  consultedAt: z.string().min(1),
  network: z.string().min(1),
  topic: z.string().min(1),
  documentedAbiOrEndpoint: z.string(),
  documentedBehavior: z.string(),
  limitations: z.string(),
}).strict();

export const onchainObservationSchema = z.object({
  network: z.string().min(1),
  chainId: z.number().int(),
  blockNumber: z.string().min(1),
  blockHash: z.string().min(1),
  address: z.string().min(1),
  implementation: z.string().nullable(),
  codeHash: z.string().nullable(),
  callOrSelector: z.string().min(1),
  result: z.string(),
  classification: z.enum(EVIDENCE_CLASSIFICATIONS),
}).strict();

export const comparisonSchema = z.object({
  topic: z.string().min(1),
  documentedNetwork: z.string().min(1),
  documentedVersion: z.string().min(1),
  documentedSignatureOrBehavior: z.string(),
  observedNetwork: z.string().min(1),
  observedBlock: z.string(),
  observedAddress: z.string(),
  observedImplementation: z.string().nullable(),
  observedSignatureOrBehavior: z.string(),
  comparisonStatus: z.enum(COMPARISON_STATUSES),
  impactOnMordant: z.string(),
  smallestSponsorQuestion: z.string(),
}).strict();

export const conclusionSchema = z.object({
  statement: z.string().min(1),
  classification: z.enum(EVIDENCE_CLASSIFICATIONS),
  basis: z.string().min(1),
}).strict();

export const missingEvidenceSchema = z.object({
  topic: z.string().min(1),
  reason: z.string().min(1),
  whatWouldProveIt: z.string().min(1),
}).strict();

/**
 * Provenance of the documented side. `manual-versioned-transcription` means a human or agent read
 * the access-gated page and transcribed the minimum technical facts into the repository. The gate
 * never fetches that page itself, so `liveFetchedByEvidenceGate` is structurally false.
 */
export const documentationSourceSchema = z.object({
  sourceKind: z.enum(["manual-versioned-transcription", "unavailable"]),
  documentationVersion: z.string().min(1),
  documentationVersionSource: z.string().min(1),
  documentationConsultedAt: z.string().nullable(),
  liveFetchedByEvidenceGate: z.literal(false),
}).strict();

export const evidenceReportSchema = z.object({
  schemaVersion: z.literal(1),
  /** When this artifact was rendered. Distinct from when anything was observed or read. */
  generatedAt: z.string().min(1),
  repositoryCommit: z.string().min(1),
  mode: z.enum(["live-read-only", "fixture"]),
  documentationSource: documentationSourceSchema,
  network: z.object({
    name: z.string().min(1),
    chainId: z.number().int(),
    blockNumber: z.string(),
    blockHash: z.string(),
    /** When the pinned block was read. Distinct from `generatedAt`. */
    onchainObservedAt: z.string().min(1),
  }).strict(),
  documentation: z.array(documentationRecordSchema),
  onchainObservations: z.array(onchainObservationSchema),
  comparisons: z.array(comparisonSchema),
  conclusions: z.array(conclusionSchema),
  missingEvidence: z.array(missingEvidenceSchema),
}).strict();

export type DocumentationRecord = z.output<typeof documentationRecordSchema>;
export type Comparison = z.output<typeof comparisonSchema>;
export type Conclusion = z.output<typeof conclusionSchema>;
export type MissingEvidence = z.output<typeof missingEvidenceSchema>;
export type EvidenceReport = z.output<typeof evidenceReportSchema>;

export class EvidenceReportError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "EvidenceReportError";
  }
}

export function parseEvidenceReport(candidate: unknown): EvidenceReport {
  const result = evidenceReportSchema.safeParse(candidate);
  if (!result.success) {
    throw new EvidenceReportError(
      `Evidence report failed validation: ${result.error.issues
        .map((issue) => `${issue.path.join(".")}: ${issue.message}`)
        .join("; ")}`,
    );
  }
  return result.data;
}

function table(headers: readonly string[], rows: readonly (readonly string[])[]): string {
  if (rows.length === 0) {
    return "_No entry._\n";
  }
  const escape = (cell: string): string => cell.replace(/\|/g, "\\|").replace(/\n/g, " ");
  return [
    `| ${headers.join(" | ")} |`,
    `| ${headers.map(() => "---").join(" | ")} |`,
    ...rows.map((row) => `| ${row.map(escape).join(" | ")} |`),
  ].join("\n") + "\n";
}

export function renderEvidenceMarkdown(report: EvidenceReport): string {
  const skewed = report.comparisons.filter(
    (comparison) => comparison.comparisonStatus === DOC_DEPLOYMENT_SKEW,
  );

  return [
    `# Cleanverse / Monad evidence report`,
    "",
    `Generated at ${report.generatedAt} in \`${report.mode}\` mode from repository state`,
    `\`${report.repositoryCommit}\`.`,
    "",
    `| Field | Value |`,
    `| --- | --- |`,
    `| mode | \`${report.mode}\` |`,
    `| generatedAt | ${report.generatedAt} |`,
    `| onchainObservedAt | ${report.network.onchainObservedAt} |`,
    `| blockNumber | ${report.network.blockNumber} |`,
    `| blockHash | \`${report.network.blockHash}\` |`,
    `| documentationVersion | ${report.documentationSource.documentationVersion} |`,
    `| documentationConsultedAt | ${report.documentationSource.documentationConsultedAt ?? "not consulted"} |`,
    `| sourceKind | \`${report.documentationSource.sourceKind}\` |`,
    `| liveFetchedByEvidenceGate | ${report.documentationSource.liveFetchedByEvidenceGate} |`,
    "",
    `Network: **${report.network.name}** (chain ${report.network.chainId}).`,
    `All on-chain readings below are pinned to block ${report.network.blockNumber}`,
    `(\`${report.network.blockHash}\`).`,
    "",
    `The documented side is a **${report.documentationSource.sourceKind}**: the evidence gate never`,
    `fetches the access-gated documentation itself, and \`--docs-consulted\` is an operator`,
    `attestation that the page was read on the stated date, nothing more.`,
    "",
    `Every reading was produced with \`eth_call\`, \`eth_getCode\`, \`eth_getStorageAt\` or an`,
    `equivalent read. No transaction was signed or broadcast, and no Cleanverse state-changing`,
    `endpoint was called.`,
    "",
    `## 1. Documentation consulted`,
    "",
    table(
      ["Topic", "Page", "Path", "Version", "Version source", "Network", "Consulted", "ABI / endpoint", "Documented behavior", "Limitations"],
      report.documentation.map((record) => [
        record.topic,
        record.pageTitle,
        record.pagePath,
        record.documentationVersion,
        record.documentationVersionSource,
        record.network,
        record.consultedAt,
        record.documentedAbiOrEndpoint,
        record.documentedBehavior,
        record.limitations,
      ]),
    ),
    `## 2. On-chain observations`,
    "",
    table(
      ["Network", "Chain", "Block", "Address", "Implementation", "Code hash", "Call / selector", "Result", "Class"],
      report.onchainObservations.map((observation) => [
        observation.network,
        String(observation.chainId),
        observation.blockNumber,
        observation.address,
        observation.implementation ?? "n/a",
        observation.codeHash === null ? "n/a" : `${observation.codeHash.slice(0, 18)}...`,
        observation.callOrSelector,
        observation.result,
        observation.classification,
      ]),
    ),
    `## 3. Documentation versus deployment`,
    "",
    table(
      ["Topic", "Doc network", "Doc version", "Documented", "Observed network", "Observed block", "Observed address", "Observed implementation", "Observed", "Status", "Impact on Mordant", "Smallest sponsor question"],
      report.comparisons.map((comparison) => [
        comparison.topic,
        comparison.documentedNetwork,
        comparison.documentedVersion,
        comparison.documentedSignatureOrBehavior,
        comparison.observedNetwork,
        comparison.observedBlock,
        comparison.observedAddress,
        comparison.observedImplementation ?? "n/a",
        comparison.observedSignatureOrBehavior,
        comparison.comparisonStatus,
        comparison.impactOnMordant,
        comparison.smallestSponsorQuestion,
      ]),
    ),
    skewed.length === 0
      ? `No surface is currently classified \`${DOC_DEPLOYMENT_SKEW}\`.`
      : `**${skewed.length} surface(s) classified \`${DOC_DEPLOYMENT_SKEW}\`.** No composite ABI was`
        + ` built to work around them.`,
    "",
    `## 4. Conclusions`,
    "",
    table(
      ["Statement", "Classification", "Basis"],
      report.conclusions.map((conclusion) => [
        conclusion.statement,
        conclusion.classification,
        conclusion.basis,
      ]),
    ),
    `## 5. Missing evidence`,
    "",
    table(
      ["Topic", "Why it is missing", "What would prove it"],
      report.missingEvidence.map((missing) => [
        missing.topic,
        missing.reason,
        missing.whatWouldProveIt,
      ]),
    ),
  ].join("\n");
}

export type RenderedEvidence = Readonly<{ json: string; markdown: string }>;

/**
 * Serializes the report and refuses to return anything that still matches a secret pattern
 * after redaction.
 */
export function renderEvidenceArtifacts(
  report: EvidenceReport,
  knownSecretValues: readonly string[] = [],
): RenderedEvidence {
  const validated = parseEvidenceReport(report);
  const json = redactSecrets(`${JSON.stringify(validated, null, 2)}\n`, knownSecretValues);
  const markdown = redactSecrets(renderEvidenceMarkdown(validated), knownSecretValues);

  assertNoSecretLeak(json, knownSecretValues);
  assertNoSecretLeak(markdown, knownSecretValues);

  return Object.freeze({ json, markdown });
}
