import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

import {
  buildDirectParticipantBridgeEvidence,
  type DirectParticipantBridgeEvidence,
} from "./direct-participant-bridge-evidence";
import { verifyGovernedResultSignature } from "./protection-evidence";

/**
 * Materializes the direct-participant bridge evidence from a run's own durable
 * artifacts.
 *
 * The worker publishes every fact this artifact carries, but it does not
 * assemble them into the shape the BridgeExecutor verifies. That assembly is
 * what this module does, and the constraint that makes it trustworthy is
 * negative: it chooses nothing. Every participant field is copied from the
 * durable admission ledger, every digest from the run's own published objects,
 * and the governed result is copied whole. There is no parameter through which
 * a caller could introduce a holder, an amount, a digest or an authority.
 *
 * Assembly is therefore deterministic: the same run root yields the same
 * evidence digest on every call, and a tampered artifact yields a different one
 * that the executor's own validation refuses.
 */

export const DIRECT_PARTICIPANT_EVIDENCE_SOURCES = Object.freeze({
  execution: "execution.json",
  caseBinding: join("public", "case-binding.json"),
  governedResult: join("public", "governed-conflict-result.json"),
  admissionA: join("admissions", "participant_a.json"),
  admissionB: join("admissions", "participant_b.json"),
  receipt: join("public", "product-recourse-attestation.json"),
  receiptFallback: "recourse-outcome.json",
});

export class DirectParticipantEvidenceAssemblyError extends Error {
  constructor(readonly code: string, message: string) {
    super(message);
    this.name = "DirectParticipantEvidenceAssemblyError";
  }
}

function fail(code: string, message: string): never {
  throw new DirectParticipantEvidenceAssemblyError(code, message);
}

function readJson(runDirectory: string, relative: string): Record<string, unknown> {
  const path = join(runDirectory, relative);
  if (!existsSync(path)) fail("MISSING_ARTIFACT", `The run has no durable ${relative}`);
  try {
    return JSON.parse(readFileSync(path, "utf8")) as Record<string, unknown>;
  } catch {
    return fail("UNREADABLE_ARTIFACT", `${relative} is not valid JSON`);
  }
}

function digestOfFile(runDirectory: string, relative: string): string {
  return `sha256:${createHash("sha256").update(readFileSync(join(runDirectory, relative))).digest("hex")}`;
}

/** The admission facts, copied verbatim from the durable ledger. */
function admissionFact(record: Record<string, unknown>, expectedRole: string) {
  if (record.role !== expectedRole) {
    fail("ADMISSION_ROLE", `The durable admission ledger holds ${String(record.role)} where ${expectedRole} was expected`);
  }
  return Object.freeze({
    role: record.role as "PARTICIPANT_A" | "PARTICIPANT_B",
    participantWallet: record.participantWallet as `0x${string}`,
    authorizationDigest: record.authorizationDigest as `sha256:${string}`,
    claimCommitment: record.claimCommitment as `sha256:${string}`,
    authorizationNonce: record.authorizationNonce as string,
    chainId: record.chainId as number,
    eligibilityBlock: record.eligibilityBlock as number,
  });
}

export function assembleDirectParticipantBridgeEvidence(
  runRoot: string,
  runId: string,
  sourceCommit: string,
): DirectParticipantBridgeEvidence {
  if (!/^[0-9a-f]{40}$/u.test(sourceCommit)) {
    fail("SOURCE_COMMIT", "The execution source commit must be a full lowercase commit id");
  }
  const directory = join(runRoot, runId);
  const execution = readJson(directory, DIRECT_PARTICIPANT_EVIDENCE_SOURCES.execution);
  const binding = readJson(directory, DIRECT_PARTICIPANT_EVIDENCE_SOURCES.caseBinding);
  const governedResult = readJson(directory, DIRECT_PARTICIPANT_EVIDENCE_SOURCES.governedResult);
  const admissionA = readJson(directory, DIRECT_PARTICIPANT_EVIDENCE_SOURCES.admissionA);
  const admissionB = readJson(directory, DIRECT_PARTICIPANT_EVIDENCE_SOURCES.admissionB);

  const keygen = execution.keygen as Record<string, string> | undefined;
  const submissions = execution.submissions as Record<string, { artifactDigest: string }> | undefined;
  const evaluation = execution.evaluation as { artifactDigest: string } | undefined;
  const protectionCase = execution.protectionCase as { fheCaseId: string } | undefined;
  if (keygen === undefined || submissions === undefined || evaluation === undefined || protectionCase === undefined) {
    fail("INCOMPLETE_EXECUTION", "The run's execution record does not yet carry the digests this artifact binds");
  }

  // Authenticate before materializing. The governed result is signed by the
  // case's own release authority, so a tampered result, a tampered authority or
  // a swapped public key fails here rather than becoming a well-formed artifact
  // that merely disagrees with the run it claims to describe.
  try {
    verifyGovernedResultSignature(governedResult as never);
  } catch (error) {
    fail("GOVERNED_RESULT_SIGNATURE", `The published governed result is not authentic: ${(error as Error).message}`);
  }
  if (governedResult.releaseAuthorityPublicKey !== binding.releaseAuthorityPublicKey) {
    fail("AUTHORITY_KEY_MISMATCH", "The governed result was signed by a key the case binding does not name");
  }

  // Cross-check every fact against the artifact that independently states it.
  // Assembly refuses a run whose own outputs disagree; it never picks a winner.
  const bound: readonly (readonly [string, unknown, unknown])[] = [
    ["caseId", binding.caseId, governedResult.caseId],
    ["caseBindingDigest", keygen.bindingDigest, governedResult.caseBindingDigest],
    ["assetIdentity", binding.assetIdentity, governedResult.assetIdentity],
    ["policyId", binding.policyId, governedResult.policyId],
    ["circuitDigest", binding.circuitDigest, governedResult.circuitDigest],
    ["parameterFingerprint", binding.parameterFingerprint, governedResult.parameterFingerprint],
    ["releaseMode", binding.releaseMode, governedResult.releaseMode],
    ["releaseAuthorityId", binding.releaseAuthorityId, governedResult.releaseAuthorityId],
    ["evaluatedArtifactDigest", evaluation.artifactDigest, governedResult.evaluatedArtifactDigest],
    ["fheCaseId", protectionCase.fheCaseId, governedResult.caseId],
  ];
  for (const [name, left, right] of bound) {
    if (left !== right) fail("ARTIFACT_DISAGREEMENT", `The run's own artifacts disagree about ${name}`);
  }
  const submittedDigests = [submissions.PARTICIPANT_A.artifactDigest, submissions.PARTICIPANT_B.artifactDigest];
  const releasedDigests = governedResult.participantArtifactDigests as readonly string[];
  if (releasedDigests.length !== 2
    || releasedDigests[0] !== submittedDigests[0] || releasedDigests[1] !== submittedDigests[1]) {
    fail("ARTIFACT_DISAGREEMENT", "The governed result does not carry the participant artifacts this run submitted");
  }

  const receiptRelative = existsSync(join(directory, DIRECT_PARTICIPANT_EVIDENCE_SOURCES.receipt))
    ? DIRECT_PARTICIPANT_EVIDENCE_SOURCES.receipt
    : DIRECT_PARTICIPANT_EVIDENCE_SOURCES.receiptFallback;
  if (!existsSync(join(directory, receiptRelative))) fail("MISSING_ARTIFACT", "The run has no durable settlement receipt");

  return buildDirectParticipantBridgeEvidence({
    sourceCommit,
    runId,
    fheCaseId: protectionCase.fheCaseId as `sha256:${string}`,
    protectionBindingDigest: keygen.protectionBindingDigest as `sha256:${string}`,
    caseBindingDigest: keygen.bindingDigest as `sha256:${string}`,
    caseBinding: {
      caseId: binding.caseId as `sha256:${string}`,
      assetIdentity: binding.assetIdentity as `sha256:${string}`,
      policyId: binding.policyId as `sha256:${string}`,
      circuitDigest: binding.circuitDigest as `sha256:${string}`,
      parameterFingerprint: binding.parameterFingerprint as `sha256:${string}`,
      releaseMode: binding.releaseMode as "governed-decryptor-v1",
      releaseAuthorityId: binding.releaseAuthorityId as `sha256:${string}`,
      releaseAuthorityPublicKey: binding.releaseAuthorityPublicKey as string,
    },
    participants: [admissionFact(admissionA, "PARTICIPANT_A"), admissionFact(admissionB, "PARTICIPANT_B")],
    participantArtifactDigestA: submissions.PARTICIPANT_A.artifactDigest as `sha256:${string}`,
    participantArtifactDigestB: submissions.PARTICIPANT_B.artifactDigest as `sha256:${string}`,
    evaluatedArtifactDigest: evaluation.artifactDigest as `sha256:${string}`,
    // Copied whole, never rebuilt field by field, so nothing can be dropped.
    governedResult: governedResult as never,
    customReceiptDigest: digestOfFile(directory, receiptRelative) as `sha256:${string}`,
  });
}
