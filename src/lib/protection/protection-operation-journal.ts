import {
  closeSync,
  existsSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  writeFileSync,
} from "node:fs";
import { dirname, join } from "node:path";
import { randomUUID } from "node:crypto";

import { sha256Digest, type Sha256Digest } from "./cleanverse-asset";

export type ProductOperationPhase =
  | "PREPARING"
  | "SUBMITTING_A"
  | "SUBMITTING_B"
  | "FINALIZING"
  | "EVALUATING"
  | "RELEASING"
  | "OPENING_RECOURSE"
  | "ADVANCING_CURE"
  | "EXPORTING"
  | "RETAINING"
  | "ABORTED";

export type ProductOperationName =
  | "preparePrivateMatch"
  | "submitParticipantA"
  | "submitParticipantB"
  | "finalizeParticipantSubmissions"
  | "evaluatePrivateConflict"
  | "releaseGovernedResult"
  | "openRecourseCase"
  | "completeCureChronology"
  | "exportProtectionEvidence"
  | "retainProtectionEvidence";

export type JournalOutcome = "PENDING" | "COMPLETED" | "RECONCILED" | "ABORTED";

export type ProductOperationRecord = Readonly<{
  schemaVersion: "mordant.protection-operation/1";
  operationId: string;
  runId: string;
  sequence: number;
  operation: ProductOperationName;
  phase: ProductOperationPhase;
  immutableParameters: Readonly<Record<string, unknown>>;
  immutableParametersDigest: Sha256Digest;
  expectedCurrentStage: string;
  expectedTargetStage: string;
  fixed: Readonly<{ nowUnix: number | null }>;
  expectedArtifacts: readonly string[];
  createdAt: string;
  outcome: JournalOutcome;
  outcomeReason: string | null;
  terminalAt: string | null;
}>;

export type ProductOperationJournal = Readonly<{
  schemaVersion: "mordant.protection-operation-journal/1";
  runId: string;
  records: readonly ProductOperationRecord[];
}>;

export type BeginOperation = Readonly<{
  operation: ProductOperationName;
  phase: Exclude<ProductOperationPhase, "ABORTED">;
  immutableParameters: Readonly<Record<string, unknown>>;
  expectedCurrentStage: string;
  expectedTargetStage: string;
  fixedNowUnix?: number;
  expectedArtifacts: readonly string[];
  createdAt: string;
}>;

export class ProductJournalError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ProductJournalError";
  }
}

export function writeDurableJsonAtomic(path: string, value: unknown, mode = 0o600, beforeRename?: () => void): void {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const temporary = `${path}.${process.pid}.${randomUUID()}.tmp`;
  let file = -1;
  try {
    file = openSync(temporary, "wx", mode);
    writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`, "utf8");
    fsyncSync(file);
  } finally {
    if (file >= 0) closeSync(file);
  }
  beforeRename?.();
  renameSync(temporary, path);
  let directory = -1;
  try {
    directory = openSync(dirname(path), "r");
    fsyncSync(directory);
  } finally {
    if (directory >= 0) closeSync(directory);
  }
}

export function journalPath(runRoot: string, runId: string): string {
  return join(runRoot, runId, "operation-journal.json");
}

function validateRecord(record: ProductOperationRecord, runId: string, sequence: number): void {
  if (
    record.schemaVersion !== "mordant.protection-operation/1" || record.runId !== runId || record.sequence !== sequence
    || record.immutableParametersDigest !== sha256Digest("MordantProtectionOperationParameters/v1", record.immutableParameters)
    || !Number.isSafeInteger(record.fixed.nowUnix ?? 0)
  ) throw new ProductJournalError("Durable operation journal integrity failure");
}

export function readOperationJournal(runRoot: string, runId: string): ProductOperationJournal {
  const path = journalPath(runRoot, runId);
  if (!existsSync(path)) return { schemaVersion: "mordant.protection-operation-journal/1", runId, records: [] };
  const journal = JSON.parse(readFileSync(path, "utf8")) as ProductOperationJournal;
  if (journal.schemaVersion !== "mordant.protection-operation-journal/1" || journal.runId !== runId || !Array.isArray(journal.records)) {
    throw new ProductJournalError("Durable operation journal rejected");
  }
  journal.records.forEach((record, index) => validateRecord(record, runId, index + 1));
  if (journal.records.slice(0, -1).some((record) => record.outcome === "PENDING")) {
    throw new ProductJournalError("Non-terminal operation is not the journal tail");
  }
  return journal;
}

function writeJournal(runRoot: string, journal: ProductOperationJournal): ProductOperationJournal {
  writeDurableJsonAtomic(journalPath(runRoot, journal.runId), journal);
  return journal;
}

export function beginOperation(runRoot: string, runId: string, input: BeginOperation): ProductOperationRecord {
  const journal = readOperationJournal(runRoot, runId);
  const pending = journal.records.at(-1);
  if (pending?.outcome === "PENDING") {
    if (
      pending.operation !== input.operation || pending.phase !== input.phase
      || pending.immutableParametersDigest !== sha256Digest("MordantProtectionOperationParameters/v1", input.immutableParameters)
    ) throw new ProductJournalError("Another durable operation requires reconciliation");
    return pending;
  }
  const record: ProductOperationRecord = {
    schemaVersion: "mordant.protection-operation/1",
    operationId: randomUUID(),
    runId,
    sequence: journal.records.length + 1,
    operation: input.operation,
    phase: input.phase,
    immutableParameters: input.immutableParameters,
    immutableParametersDigest: sha256Digest("MordantProtectionOperationParameters/v1", input.immutableParameters),
    expectedCurrentStage: input.expectedCurrentStage,
    expectedTargetStage: input.expectedTargetStage,
    fixed: { nowUnix: input.fixedNowUnix ?? null },
    expectedArtifacts: [...input.expectedArtifacts],
    createdAt: input.createdAt,
    outcome: "PENDING",
    outcomeReason: null,
    terminalAt: null,
  };
  writeJournal(runRoot, { ...journal, records: [...journal.records, record] });
  return record;
}

export function finishOperation(
  runRoot: string,
  runId: string,
  operationId: string,
  outcome: Exclude<JournalOutcome, "PENDING">,
  terminalAt: string,
  reason: string | null = null,
): ProductOperationRecord {
  const journal = readOperationJournal(runRoot, runId);
  const pending = journal.records.at(-1);
  if (pending?.operationId !== operationId || pending.outcome !== "PENDING") {
    throw new ProductJournalError("Pending operation record was replaced or already terminal");
  }
  const terminal: ProductOperationRecord = {
    ...pending,
    phase: outcome === "ABORTED" ? "ABORTED" : pending.phase,
    outcome,
    outcomeReason: reason,
    terminalAt,
  };
  writeJournal(runRoot, { ...journal, records: [...journal.records.slice(0, -1), terminal] });
  return terminal;
}

export function pendingOperation(runRoot: string, runId: string): ProductOperationRecord | null {
  const record = readOperationJournal(runRoot, runId).records.at(-1);
  return record?.outcome === "PENDING" ? record : null;
}
