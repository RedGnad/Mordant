/**
 * Create-only persistence for the bounded receivable-conflict graph experiment.
 *
 * The store deliberately knows nothing about graph-domain types. Its only job is
 * to give the graph layer explicit restricted-evidence/private-opening
 * locations and durable, immutable JSON publication. `publicRoot` is retained
 * as an API name for compatibility with the cryptographic artifact vocabulary;
 * it is operator/auditor evidence storage protected by mode 0700, not the
 * PUBLIC-audience projection and not a web-public directory. Callers remain
 * responsible for validating records before they reach this boundary.
 */

import { randomUUID } from "node:crypto";
import {
  closeSync,
  constants as fsConstants,
  fchmodSync,
  fstatSync,
  fsyncSync,
  linkSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  realpathSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import {
  basename,
  dirname,
  isAbsolute,
  join,
  relative,
  resolve,
  sep,
} from "node:path";

export const RECEIVABLE_CONFLICT_SESSION_FILES = Object.freeze({
  publicClaimAuthorization: "claim-authorization.json",
  privateClaimRecord: "private-claim-record.json",
  pairIntent: "pair-intent.json",
  pairBinding: "pair-binding.json",
  evidenceLeaf: "pair-evidence-leaf.json",
  aggregate: "aggregate-manifest.json",
  chronology: "execution-chronology.json",
  retentionDeclaration: "retention-declaration.json",
  projectionSuffix: ".projection.json",
});

export const RECEIVABLE_CONFLICT_RETENTION_SCHEMA = "mordant.receivable-conflict-retention/1" as const;

export type ReceivableConflictRetentionDeclaration = Readonly<{
  schemaVersion: typeof RECEIVABLE_CONFLICT_RETENTION_SCHEMA;
  sessionId: string;
  privateExactClaimOpenings: Readonly<{
    record: typeof RECEIVABLE_CONFLICT_SESSION_FILES.privateClaimRecord;
    retainedFields: readonly ["activeFrom", "activeUntil", "salt"];
    authorizationPrivateKey: "NOT_PERSISTED";
    authorizationPrivateKeyLifetime: "CALLER_MANAGED_PROCESS_MEMORY_UNTIL_REFERENCES_RELEASED";
    authorizationPrivateKeyZeroizationClaimed: false;
    authorizationPrivateKeyGarbageCollectionTimingClaimed: false;
    location: "PRIVATE_ROOT_ONLY";
    disposition: "PERSIST_UNTIL_EXPLICIT_OPERATOR_CLEANUP";
    automaticCleanup: false;
    operatorCleanupRequired: true;
    secureErasureClaim: false;
  }>;
}>;

export type ReceivableConflictSessionStoreOptions = Readonly<{
  /** Restricted operator/auditor evidence root; never an HTTP or PUBLIC-audience root. */
  publicRoot: string;
  /** Private exact claim openings, including interval and salt. */
  privateRoot: string;
}>;

export type CreateOnlyJsonResult = Readonly<{
  path: string;
  /** False only when an exact byte-for-byte record was already present. */
  created: boolean;
}>;

export class ReceivableConflictSessionStoreError extends Error {
  constructor(readonly code: string, message: string) {
    super(message);
    this.name = "ReceivableConflictSessionStoreError";
  }
}

function fail(code: string, message: string): never {
  throw new ReceivableConflictSessionStoreError(code, message);
}

function hasErrnoCode(error: unknown, code: string): boolean {
  return error !== null
    && typeof error === "object"
    && "code" in error
    && (error as Readonly<{ code?: unknown }>).code === code;
}

function safeIdentifier(value: string, label: string): string {
  if (
    typeof value !== "string"
    || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,191}$/u.test(value)
    || value === "."
    || value === ".."
  ) {
    fail("PATH_TRAVERSAL", `${label} must be one safe path segment`);
  }
  return value;
}

function lstatOrNull(path: string) {
  try {
    return lstatSync(path);
  } catch (error) {
    if (hasErrnoCode(error, "ENOENT")) return null;
    throw error;
  }
}

function openDirectoryNoFollow(path: string): number {
  try {
    return openSync(
      path,
      fsConstants.O_RDONLY | fsConstants.O_DIRECTORY | fsConstants.O_NOFOLLOW,
    );
  } catch (error) {
    if (hasErrnoCode(error, "ELOOP")) fail("SYMLINK_REFUSED", `Symbolic-link directory refused: ${path}`);
    throw error;
  }
}

function hardenDirectory(path: string): void {
  const entry = lstatOrNull(path);
  if (entry?.isSymbolicLink()) fail("SYMLINK_REFUSED", `Symbolic-link directory refused: ${path}`);
  if (entry !== null && !entry.isDirectory()) fail("STORE_INTEGRITY", `Expected a directory: ${path}`);

  let descriptor = -1;
  try {
    descriptor = openDirectoryNoFollow(path);
    const stat = fstatSync(descriptor);
    if (!stat.isDirectory()) fail("STORE_INTEGRITY", `Expected a directory: ${path}`);
    fchmodSync(descriptor, 0o700);
    fsyncSync(descriptor);
  } finally {
    if (descriptor >= 0) closeSync(descriptor);
  }
}

function ensureRoot(path: string): void {
  const entry = lstatOrNull(path);
  if (entry?.isSymbolicLink()) fail("SYMLINK_REFUSED", `Symbolic-link root refused: ${path}`);
  if (entry !== null && !entry.isDirectory()) fail("STORE_INTEGRITY", `Configured root is not a directory: ${path}`);
  mkdirSync(path, { recursive: true, mode: 0o700 });
  hardenDirectory(path);
}

function fsyncDirectory(path: string): void {
  let descriptor = -1;
  try {
    descriptor = openDirectoryNoFollow(path);
    fsyncSync(descriptor);
  } finally {
    if (descriptor >= 0) closeSync(descriptor);
  }
}

function ensureDirectoryPath(root: string, segments: readonly string[]): string {
  hardenDirectory(root);
  let current = root;
  for (const segment of segments) {
    const safe = safeIdentifier(segment, "path identifier");
    const parent = current;
    current = join(current, safe);
    const entry = lstatOrNull(current);
    if (entry?.isSymbolicLink()) fail("SYMLINK_REFUSED", `Symbolic-link directory refused: ${current}`);
    if (entry !== null && !entry.isDirectory()) fail("STORE_INTEGRITY", `Expected a directory: ${current}`);
    if (entry === null) {
      try {
        mkdirSync(current, { mode: 0o700 });
      } catch (error) {
        if (!hasErrnoCode(error, "EEXIST")) throw error;
      }
      fsyncDirectory(parent);
    }
    hardenDirectory(current);
  }
  return current;
}

/** False means the requested record has no directory yet; every other shape is rejected. */
function directoryPathExists(root: string, segments: readonly string[]): boolean {
  let current = root;
  for (const segment of ["", ...segments]) {
    if (segment !== "") current = join(current, safeIdentifier(segment, "path identifier"));
    const entry = lstatOrNull(current);
    if (entry === null) return false;
    if (entry.isSymbolicLink()) fail("SYMLINK_REFUSED", `Symbolic-link directory refused: ${current}`);
    if (!entry.isDirectory()) fail("STORE_INTEGRITY", `Expected a directory: ${current}`);
    let descriptor = -1;
    try {
      descriptor = openDirectoryNoFollow(current);
      if (!fstatSync(descriptor).isDirectory()) fail("STORE_INTEGRITY", `Expected a directory: ${current}`);
    } finally {
      if (descriptor >= 0) closeSync(descriptor);
    }
  }
  return true;
}

function unlinkIfPresent(path: string): void {
  try {
    unlinkSync(path);
  } catch (error) {
    if (!hasErrnoCode(error, "ENOENT")) throw error;
  }
}

function jsonBytes(value: unknown): Buffer {
  let encoded: string | undefined;
  try {
    encoded = JSON.stringify(value, null, 2);
  } catch {
    fail("JSON_VALUE", "Record is not JSON serializable");
  }
  if (encoded === undefined) fail("JSON_VALUE", "Record is not a JSON value");
  return Buffer.from(`${encoded}\n`, "utf8");
}

function readRecordBytes(path: string): Buffer | null {
  const entry = lstatOrNull(path);
  if (entry === null) return null;
  if (entry.isSymbolicLink()) fail("SYMLINK_REFUSED", `Symbolic-link record refused: ${path}`);
  if (!entry.isFile()) fail("STORE_INTEGRITY", `Expected a regular record: ${path}`);

  let descriptor = -1;
  try {
    try {
      descriptor = openSync(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
    } catch (error) {
      if (hasErrnoCode(error, "ELOOP")) fail("SYMLINK_REFUSED", `Symbolic-link record refused: ${path}`);
      throw error;
    }
    const stat = fstatSync(descriptor);
    if (!stat.isFile() || stat.nlink !== 1) fail("STORE_INTEGRITY", `Record is not an isolated regular file: ${path}`);
    if ((stat.mode & 0o777) !== 0o600) fail("FILE_MODE", `Record mode must remain 0600: ${path}`);
    return readFileSync(descriptor);
  } finally {
    if (descriptor >= 0) closeSync(descriptor);
  }
}

function readJson<T>(path: string): T | null {
  const encoded = readRecordBytes(path);
  if (encoded === null) return null;
  try {
    return JSON.parse(encoded.toString("utf8")) as T;
  } catch {
    fail("STORE_INTEGRITY", `Stored record is not valid JSON: ${path}`);
  }
}

/**
 * A synced hard-link is the create-only commit point. `rename(2)` is not used
 * because it could replace a record published by another process. The final
 * no-follow readback makes a lost-response retry distinguishable from a
 * conflicting write without mutating either record.
 */
function writeCreateOnlyJson(path: string, value: unknown): CreateOnlyJsonResult {
  const encoded = jsonBytes(value);
  const directory = dirname(path);
  const temporary = join(directory, `.${basename(path)}.${process.pid}.${randomUUID()}.tmp`);
  let descriptor = -1;
  let published = false;
  try {
    descriptor = openSync(
      temporary,
      fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_NOFOLLOW,
      0o600,
    );
    fchmodSync(descriptor, 0o600);
    writeFileSync(descriptor, encoded);
    fsyncSync(descriptor);
    closeSync(descriptor);
    descriptor = -1;

    try {
      linkSync(temporary, path);
      published = true;
    } catch (error) {
      if (!hasErrnoCode(error, "EEXIST")) throw error;
      const existing = readRecordBytes(path);
      if (existing?.equals(encoded)) return Object.freeze({ path, created: false });
      fail("RECORD_EXISTS", `A different create-only record already exists: ${path}`);
    }

    fsyncDirectory(directory);
  } finally {
    if (descriptor >= 0) closeSync(descriptor);
    unlinkIfPresent(temporary);
    fsyncDirectory(directory);
  }

  if (!published) fail("STORE_INTEGRITY", `Record publication was not confirmed: ${path}`);
  const readback = readRecordBytes(path);
  if (readback === null || !readback.equals(encoded)) {
    fail("STORE_INTEGRITY", `Create-only record failed durable readback: ${path}`);
  }
  return Object.freeze({ path, created: true });
}

function nestedRoot(parent: string, child: string): boolean {
  const relation = relative(parent, child);
  return relation === "" || (
    relation !== ".."
    && !relation.startsWith(`..${sep}`)
    && !isAbsolute(relation)
  );
}

function configuredRoot(value: string, label: string): string {
  if (!isAbsolute(value)) fail("ROOT_NOT_ABSOLUTE", `${label} must be an absolute path`);
  return resolve(value);
}

type RootIdentity = Readonly<{
  physicalPath: string;
  device: number;
  inode: number;
}>;

/**
 * Resolve an opened directory, then prove the canonical path still names that
 * same directory. Comparing both representations defeats aliases introduced by
 * a symbolic-link ancestor without trusting either representation by itself.
 */
function rootIdentity(path: string): RootIdentity {
  let configuredDescriptor = -1;
  let physicalDescriptor = -1;
  try {
    configuredDescriptor = openDirectoryNoFollow(path);
    const configured = fstatSync(configuredDescriptor);
    const physicalPath = realpathSync(path);
    physicalDescriptor = openDirectoryNoFollow(physicalPath);
    const physical = fstatSync(physicalDescriptor);
    if (
      !configured.isDirectory()
      || !physical.isDirectory()
      || configured.dev !== physical.dev
      || configured.ino !== physical.ino
    ) {
      fail("STORE_INTEGRITY", `Configured root changed during physical resolution: ${path}`);
    }
    return Object.freeze({
      physicalPath,
      device: configured.dev,
      inode: configured.ino,
    });
  } finally {
    if (physicalDescriptor >= 0) closeSync(physicalDescriptor);
    if (configuredDescriptor >= 0) closeSync(configuredDescriptor);
  }
}

function rootIdentitiesOverlap(left: RootIdentity, right: RootIdentity): boolean {
  return (
    (left.device === right.device && left.inode === right.inode)
    || nestedRoot(left.physicalPath, right.physicalPath)
    || nestedRoot(right.physicalPath, left.physicalPath)
  );
}

export function receivableConflictRetentionDeclaration(sessionId: string): ReceivableConflictRetentionDeclaration {
  return Object.freeze({
    schemaVersion: RECEIVABLE_CONFLICT_RETENTION_SCHEMA,
    sessionId: safeIdentifier(sessionId, "sessionId"),
    privateExactClaimOpenings: Object.freeze({
      record: RECEIVABLE_CONFLICT_SESSION_FILES.privateClaimRecord,
      retainedFields: Object.freeze(["activeFrom", "activeUntil", "salt"] as const),
      authorizationPrivateKey: "NOT_PERSISTED",
      authorizationPrivateKeyLifetime: "CALLER_MANAGED_PROCESS_MEMORY_UNTIL_REFERENCES_RELEASED",
      authorizationPrivateKeyZeroizationClaimed: false,
      authorizationPrivateKeyGarbageCollectionTimingClaimed: false,
      location: "PRIVATE_ROOT_ONLY",
      disposition: "PERSIST_UNTIL_EXPLICIT_OPERATOR_CLEANUP",
      automaticCleanup: false,
      operatorCleanupRequired: true,
      secureErasureClaim: false,
    }),
  });
}

export function createReceivableConflictSessionStore(options: ReceivableConflictSessionStoreOptions) {
  const operatorEvidenceRoot = configuredRoot(options.publicRoot, "publicRoot");
  const privateRoot = configuredRoot(options.privateRoot, "privateRoot");
  if (nestedRoot(resolve(process.cwd()), privateRoot)) {
    fail("PRIVATE_ROOT_IN_WORKSPACE", "Private claim openings must be stored outside the repository workspace");
  }
  if (nestedRoot(operatorEvidenceRoot, privateRoot) || nestedRoot(privateRoot, operatorEvidenceRoot)) {
    fail("ROOT_OVERLAP", "Restricted evidence and private roots must be disjoint");
  }
  ensureRoot(operatorEvidenceRoot);
  ensureRoot(privateRoot);
  const operatorEvidenceIdentity = rootIdentity(operatorEvidenceRoot);
  const privateIdentity = rootIdentity(privateRoot);
  if (rootIdentitiesOverlap(operatorEvidenceIdentity, privateIdentity)) {
    fail("ROOT_OVERLAP", "Restricted evidence and private roots resolve to overlapping physical storage");
  }
  const workspacePhysicalPath = realpathSync(process.cwd());
  if (nestedRoot(workspacePhysicalPath, privateIdentity.physicalPath)) {
    fail("PRIVATE_ROOT_IN_WORKSPACE", "Private claim openings must be stored outside the repository workspace");
  }

  const publicSessionDirectory = (sessionId: string) => join(
    operatorEvidenceRoot,
    safeIdentifier(sessionId, "sessionId"),
  );
  const privateSessionDirectory = (sessionId: string) => join(privateRoot, safeIdentifier(sessionId, "sessionId"));
  const publicClaimAuthorizationPath = (sessionId: string, claimId: string) => join(
    publicSessionDirectory(sessionId),
    "claims",
    safeIdentifier(claimId, "claimId"),
    RECEIVABLE_CONFLICT_SESSION_FILES.publicClaimAuthorization,
  );
  const privateClaimRecordPath = (sessionId: string, claimId: string) => join(
    privateSessionDirectory(sessionId),
    "claims",
    safeIdentifier(claimId, "claimId"),
    RECEIVABLE_CONFLICT_SESSION_FILES.privateClaimRecord,
  );
  const pairRecordPath = (sessionId: string, pairId: string, fileName: string) => join(
    publicSessionDirectory(sessionId),
    "pairs",
    safeIdentifier(pairId, "pairId"),
    fileName,
  );
  const aggregatePath = (sessionId: string) => join(
    publicSessionDirectory(sessionId),
    RECEIVABLE_CONFLICT_SESSION_FILES.aggregate,
  );
  const projectionPath = (sessionId: string, projectionId: string) => join(
    publicSessionDirectory(sessionId),
    "projections",
    `${safeIdentifier(projectionId, "projectionId")}${RECEIVABLE_CONFLICT_SESSION_FILES.projectionSuffix}`,
  );
  const chronologyPath = (sessionId: string) => join(
    publicSessionDirectory(sessionId),
    RECEIVABLE_CONFLICT_SESSION_FILES.chronology,
  );
  const retentionDeclarationPath = (sessionId: string) => join(
    publicSessionDirectory(sessionId),
    RECEIVABLE_CONFLICT_SESSION_FILES.retentionDeclaration,
  );

  const writePublic = (
    sessionId: string,
    directories: readonly string[],
    path: string,
    value: unknown,
  ) => {
    ensureDirectoryPath(operatorEvidenceRoot, [safeIdentifier(sessionId, "sessionId"), ...directories]);
    return writeCreateOnlyJson(path, value);
  };
  const writePrivate = (
    sessionId: string,
    directories: readonly string[],
    path: string,
    value: unknown,
  ) => {
    ensureDirectoryPath(privateRoot, [safeIdentifier(sessionId, "sessionId"), ...directories]);
    return writeCreateOnlyJson(path, value);
  };
  const readPublic = <T>(sessionId: string, directories: readonly string[], path: string): T | null => (
    directoryPathExists(operatorEvidenceRoot, [safeIdentifier(sessionId, "sessionId"), ...directories])
      ? readJson<T>(path)
      : null
  );
  const readPrivate = <T>(sessionId: string, directories: readonly string[], path: string): T | null => (
    directoryPathExists(privateRoot, [safeIdentifier(sessionId, "sessionId"), ...directories])
      ? readJson<T>(path)
      : null
  );

  const paths = Object.freeze({
    publicSession: publicSessionDirectory,
    privateSession: privateSessionDirectory,
    publicClaimAuthorization: publicClaimAuthorizationPath,
    privateClaimRecord: privateClaimRecordPath,
    pairIntent: (sessionId: string, pairId: string) => pairRecordPath(
      sessionId,
      pairId,
      RECEIVABLE_CONFLICT_SESSION_FILES.pairIntent,
    ),
    pairBinding: (sessionId: string, pairId: string) => pairRecordPath(
      sessionId,
      pairId,
      RECEIVABLE_CONFLICT_SESSION_FILES.pairBinding,
    ),
    evidenceLeaf: (sessionId: string, pairId: string) => pairRecordPath(
      sessionId,
      pairId,
      RECEIVABLE_CONFLICT_SESSION_FILES.evidenceLeaf,
    ),
    aggregate: aggregatePath,
    projection: projectionPath,
    chronology: chronologyPath,
    retentionDeclaration: retentionDeclarationPath,
  });

  return Object.freeze({
    // Compatibility name: this is restricted operator/auditor evidence, not a
    // PUBLIC-audience or web-public directory.
    publicRoot: operatorEvidenceRoot,
    privateRoot,
    paths,
    writePublicClaimAuthorization: (sessionId: string, claimId: string, value: unknown) => writePublic(
      sessionId,
      ["claims", safeIdentifier(claimId, "claimId")],
      paths.publicClaimAuthorization(sessionId, claimId),
      value,
    ),
    readPublicClaimAuthorization: <T = unknown>(sessionId: string, claimId: string): T | null => readPublic<T>(
      sessionId,
      ["claims", safeIdentifier(claimId, "claimId")],
      paths.publicClaimAuthorization(sessionId, claimId),
    ),
    writePrivateClaimRecord: (sessionId: string, claimId: string, value: unknown) => writePrivate(
      sessionId,
      ["claims", safeIdentifier(claimId, "claimId")],
      paths.privateClaimRecord(sessionId, claimId),
      value,
    ),
    readPrivateClaimRecord: <T = unknown>(sessionId: string, claimId: string): T | null => readPrivate<T>(
      sessionId,
      ["claims", safeIdentifier(claimId, "claimId")],
      paths.privateClaimRecord(sessionId, claimId),
    ),
    writePairIntent: (sessionId: string, pairId: string, value: unknown) => writePublic(
      sessionId,
      ["pairs", safeIdentifier(pairId, "pairId")],
      paths.pairIntent(sessionId, pairId),
      value,
    ),
    readPairIntent: <T = unknown>(sessionId: string, pairId: string): T | null => readPublic<T>(
      sessionId,
      ["pairs", safeIdentifier(pairId, "pairId")],
      paths.pairIntent(sessionId, pairId),
    ),
    writePairBinding: (sessionId: string, pairId: string, value: unknown) => writePublic(
      sessionId,
      ["pairs", safeIdentifier(pairId, "pairId")],
      paths.pairBinding(sessionId, pairId),
      value,
    ),
    readPairBinding: <T = unknown>(sessionId: string, pairId: string): T | null => readPublic<T>(
      sessionId,
      ["pairs", safeIdentifier(pairId, "pairId")],
      paths.pairBinding(sessionId, pairId),
    ),
    writeEvidenceLeaf: (sessionId: string, pairId: string, value: unknown) => writePublic(
      sessionId,
      ["pairs", safeIdentifier(pairId, "pairId")],
      paths.evidenceLeaf(sessionId, pairId),
      value,
    ),
    readEvidenceLeaf: <T = unknown>(sessionId: string, pairId: string): T | null => readPublic<T>(
      sessionId,
      ["pairs", safeIdentifier(pairId, "pairId")],
      paths.evidenceLeaf(sessionId, pairId),
    ),
    writeAggregate: (sessionId: string, value: unknown) => writePublic(
      sessionId,
      [],
      paths.aggregate(sessionId),
      value,
    ),
    readAggregate: <T = unknown>(sessionId: string): T | null => readPublic<T>(
      sessionId,
      [],
      paths.aggregate(sessionId),
    ),
    writeProjection: (sessionId: string, projectionId: string, value: unknown) => writePublic(
      sessionId,
      ["projections"],
      paths.projection(sessionId, projectionId),
      value,
    ),
    readProjection: <T = unknown>(sessionId: string, projectionId: string): T | null => readPublic<T>(
      sessionId,
      ["projections"],
      paths.projection(sessionId, projectionId),
    ),
    writeChronology: (sessionId: string, value: unknown) => writePublic(
      sessionId,
      [],
      paths.chronology(sessionId),
      value,
    ),
    readChronology: <T = unknown>(sessionId: string): T | null => readPublic<T>(
      sessionId,
      [],
      paths.chronology(sessionId),
    ),
    writeRetentionDeclaration: (sessionId: string) => writePublic(
      sessionId,
      [],
      paths.retentionDeclaration(sessionId),
      receivableConflictRetentionDeclaration(sessionId),
    ),
    readRetentionDeclaration: (sessionId: string): ReceivableConflictRetentionDeclaration | null => (
      readPublic<ReceivableConflictRetentionDeclaration>(sessionId, [], paths.retentionDeclaration(sessionId))
    ),
  });
}

export type ReceivableConflictSessionStore = ReturnType<typeof createReceivableConflictSessionStore>;
