import assert from "node:assert/strict";
import {
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";

import {
  RECEIVABLE_CONFLICT_SESSION_FILES,
  createReceivableConflictSessionStore,
  type ReceivableConflictSessionStoreError,
} from "./receivable-conflict-session-store";

const SESSION_ID = "session-n3-001";
const CLAIM_A = "claim-a-v1";
const PAIR_AB = "claim-a-v1--claim-b-v1";

function temporaryStore() {
  const root = mkdtempSync(join(tmpdir(), "mordant-conflict-session-store-"));
  const store = createReceivableConflictSessionStore({
    publicRoot: join(root, "public"),
    privateRoot: join(root, "private"),
  });
  return { root, store };
}

function mode(path: string): number {
  return statSync(path).mode & 0o777;
}

function throwsCode(operation: () => unknown, code: string): void {
  assert.throws(operation, (error: unknown) => {
    assert.equal((error as ReceivableConflictSessionStoreError).code, code);
    return true;
  });
}

test("all graph records use explicit create-only locations and exact retries are idempotent", () => {
  const { root, store } = temporaryStore();
  try {
    const authorization = { schemaVersion: "authorization/1", claimId: CLAIM_A, commitment: "opaque-a" };
    const privateClaim = { activeFrom: 100, activeUntil: 400, salt: "high-entropy-test-salt" };
    const pairIntent = { pairId: PAIR_AB, state: "PENDING" };
    const pairBinding = { pairId: PAIR_AB, localA: CLAIM_A, localB: "claim-b-v1" };
    const leaf = { pairId: PAIR_AB, resultDigest: "sha256:leaf" };
    const aggregate = { completeness: "COMPLETE", root: "sha256:aggregate" };
    const projection = { audience: "CLAIMANT_A", pairIds: [PAIR_AB] };
    const chronology = { jobs: [{ pairId: PAIR_AB, sequence: 1 }] };

    const writes = [
      store.writePublicClaimAuthorization(SESSION_ID, CLAIM_A, authorization),
      store.writePrivateClaimRecord(SESSION_ID, CLAIM_A, privateClaim),
      store.writePairIntent(SESSION_ID, PAIR_AB, pairIntent),
      store.writePairBinding(SESSION_ID, PAIR_AB, pairBinding),
      store.writeEvidenceLeaf(SESSION_ID, PAIR_AB, leaf),
      store.writeAggregate(SESSION_ID, aggregate),
      store.writeProjection(SESSION_ID, "claimant-a", projection),
      store.writeChronology(SESSION_ID, chronology),
      store.writeRetentionDeclaration(SESSION_ID),
    ];
    assert.equal(writes.every((write) => write.created), true);
    assert.equal(store.writePairBinding(SESSION_ID, PAIR_AB, pairBinding).created, false);

    assert.deepEqual(store.readPublicClaimAuthorization(SESSION_ID, CLAIM_A), authorization);
    assert.deepEqual(store.readPrivateClaimRecord(SESSION_ID, CLAIM_A), privateClaim);
    assert.deepEqual(store.readPairIntent(SESSION_ID, PAIR_AB), pairIntent);
    assert.deepEqual(store.readPairBinding(SESSION_ID, PAIR_AB), pairBinding);
    assert.deepEqual(store.readEvidenceLeaf(SESSION_ID, PAIR_AB), leaf);
    assert.deepEqual(store.readAggregate(SESSION_ID), aggregate);
    assert.deepEqual(store.readProjection(SESSION_ID, "claimant-a"), projection);
    assert.deepEqual(store.readChronology(SESSION_ID), chronology);

    assert.equal(store.paths.publicClaimAuthorization(SESSION_ID, CLAIM_A).endsWith(
      `/claims/${CLAIM_A}/${RECEIVABLE_CONFLICT_SESSION_FILES.publicClaimAuthorization}`,
    ), true);
    assert.equal(store.paths.privateClaimRecord(SESSION_ID, CLAIM_A).endsWith(
      `/claims/${CLAIM_A}/${RECEIVABLE_CONFLICT_SESSION_FILES.privateClaimRecord}`,
    ), true);
    assert.equal(store.paths.pairIntent(SESSION_ID, PAIR_AB).endsWith(
      `/pairs/${PAIR_AB}/${RECEIVABLE_CONFLICT_SESSION_FILES.pairIntent}`,
    ), true);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("roots and every public or private record have restrictive modes", () => {
  const { root, store } = temporaryStore();
  try {
    const publicRecord = store.writeAggregate(SESSION_ID, { root: "sha256:aggregate" }).path;
    const privateRecord = store.writePrivateClaimRecord(SESSION_ID, CLAIM_A, {
      activeFrom: 100,
      activeUntil: 400,
      salt: "secret-salt",
    }).path;
    assert.equal(mode(store.publicRoot), 0o700);
    assert.equal(mode(store.privateRoot), 0o700);
    assert.equal(mode(dirname(publicRecord)), 0o700);
    assert.equal(mode(dirname(privateRecord)), 0o700);
    assert.equal(mode(publicRecord), 0o600);
    assert.equal(mode(privateRecord), 0o600);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("an existing different record cannot be overwritten", () => {
  const { root, store } = temporaryStore();
  try {
    const path = store.writeAggregate(SESSION_ID, { root: "sha256:first" }).path;
    const original = readFileSync(path, "utf8");
    throwsCode(() => store.writeAggregate(SESSION_ID, { root: "sha256:second" }), "RECORD_EXISTS");
    assert.equal(readFileSync(path, "utf8"), original);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("symbolic-link roots, directories and records are refused", () => {
  const root = mkdtempSync(join(tmpdir(), "mordant-conflict-session-symlink-"));
  try {
    const actualPublic = join(root, "actual-public");
    const publicLink = join(root, "public-link");
    mkdirSync(actualPublic, { mode: 0o700 });
    symlinkSync(actualPublic, publicLink);
    throwsCode(() => createReceivableConflictSessionStore({
      publicRoot: publicLink,
      privateRoot: join(root, "private-for-root-test"),
    }), "SYMLINK_REFUSED");

    const store = createReceivableConflictSessionStore({
      publicRoot: join(root, "public"),
      privateRoot: join(root, "private"),
    });
    const outside = join(root, "outside");
    mkdirSync(outside, { mode: 0o700 });
    symlinkSync(outside, store.paths.publicSession(SESSION_ID));
    throwsCode(() => store.writeAggregate(SESSION_ID, { root: "sha256:outside" }), "SYMLINK_REFUSED");
    throwsCode(() => store.readAggregate(SESSION_ID), "SYMLINK_REFUSED");
    assert.equal(lstatSync(store.paths.publicSession(SESSION_ID)).isSymbolicLink(), true);

    const secondSession = "session-n3-002";
    const recordPath = store.paths.publicClaimAuthorization(secondSession, CLAIM_A);
    mkdirSync(dirname(recordPath), { recursive: true, mode: 0o700 });
    const outsideRecord = join(root, "outside-record.json");
    writeFileSync(outsideRecord, "unchanged", { mode: 0o600 });
    symlinkSync(outsideRecord, recordPath);
    throwsCode(
      () => store.writePublicClaimAuthorization(secondSession, CLAIM_A, { commitment: "opaque" }),
      "SYMLINK_REFUSED",
    );
    throwsCode(() => store.readPublicClaimAuthorization(secondSession, CLAIM_A), "SYMLINK_REFUSED");
    assert.equal(readFileSync(outsideRecord, "utf8"), "unchanged");

    const thirdSession = "session-n3-003";
    const nonRegular = store.paths.aggregate(thirdSession);
    mkdirSync(dirname(nonRegular), { recursive: true, mode: 0o700 });
    mkdirSync(nonRegular, { mode: 0o700 });
    throwsCode(() => store.readAggregate(thirdSession), "STORE_INTEGRITY");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("symlinked ancestors cannot alias restricted evidence and private roots", () => {
  const root = mkdtempSync(join(tmpdir(), "mordant-conflict-session-root-alias-"));
  try {
    const physicalParent = join(root, "physical-parent");
    const aliasParent = join(root, "alias-parent");
    mkdirSync(physicalParent, { mode: 0o700 });
    symlinkSync(physicalParent, aliasParent);

    // These paths are lexically disjoint but resolve to the same directory and
    // therefore have the same device/inode identity.
    throwsCode(() => createReceivableConflictSessionStore({
      publicRoot: join(physicalParent, "same-root"),
      privateRoot: join(aliasParent, "same-root"),
    }), "ROOT_OVERLAP");

    // These paths are also lexically disjoint, but physical resolution reveals
    // that the private root is nested inside the restricted evidence root.
    throwsCode(() => createReceivableConflictSessionStore({
      publicRoot: join(aliasParent, "nested-root"),
      privateRoot: join(physicalParent, "nested-root", "private"),
    }), "ROOT_OVERLAP");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("relative roots and traversal-shaped identifiers are refused", () => {
  throwsCode(() => createReceivableConflictSessionStore({
    publicRoot: "relative-public",
    privateRoot: "/absolute-private",
  }), "ROOT_NOT_ABSOLUTE");
  throwsCode(() => createReceivableConflictSessionStore({
    publicRoot: join(tmpdir(), "mordant-unused-operator-root"),
    privateRoot: join(process.cwd(), ".mordant", "forbidden-graph-private-root"),
  }), "PRIVATE_ROOT_IN_WORKSPACE");

  const { root, store } = temporaryStore();
  try {
    throwsCode(() => createReceivableConflictSessionStore({
      publicRoot: join(root, "overlap"),
      privateRoot: join(root, "overlap", "private"),
    }), "ROOT_OVERLAP");
    throwsCode(() => store.writeAggregate("../escape", {}), "PATH_TRAVERSAL");
    throwsCode(
      () => store.writePublicClaimAuthorization(SESSION_ID, "claim/a", {}),
      "PATH_TRAVERSAL",
    );
    throwsCode(() => store.writePairIntent(SESSION_ID, "..", {}), "PATH_TRAVERSAL");
    throwsCode(() => store.writeProjection(SESSION_ID, "../../operator", {}), "PATH_TRAVERSAL");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("retention explicitly keeps exact intervals and salts private until operator cleanup", () => {
  const { root, store } = temporaryStore();
  try {
    const exactOpening = {
      schemaVersion: "private-claim/1",
      activeFrom: 100,
      activeUntil: 400,
      salt: "test-only-high-entropy-salt",
    };
    const privatePath = store.writePrivateClaimRecord(SESSION_ID, CLAIM_A, exactOpening).path;
    store.writeRetentionDeclaration(SESSION_ID);

    // Reopening the store performs no automatic cleanup; the exact opening is
    // still present until an operator performs an explicit out-of-band cleanup.
    const reopened = createReceivableConflictSessionStore({
      publicRoot: store.publicRoot,
      privateRoot: store.privateRoot,
    });
    assert.deepEqual(reopened.readPrivateClaimRecord(SESSION_ID, CLAIM_A), exactOpening);
    assert.equal(readFileSync(privatePath, "utf8").includes("test-only-high-entropy-salt"), true);

    const declaration = reopened.readRetentionDeclaration(SESSION_ID);
    assert.deepEqual(declaration?.privateExactClaimOpenings.retainedFields, ["activeFrom", "activeUntil", "salt"]);
    assert.equal(declaration?.privateExactClaimOpenings.authorizationPrivateKey, "NOT_PERSISTED");
    assert.equal(
      declaration?.privateExactClaimOpenings.authorizationPrivateKeyLifetime,
      "CALLER_MANAGED_PROCESS_MEMORY_UNTIL_REFERENCES_RELEASED",
    );
    assert.equal(declaration?.privateExactClaimOpenings.authorizationPrivateKeyZeroizationClaimed, false);
    assert.equal(
      declaration?.privateExactClaimOpenings.authorizationPrivateKeyGarbageCollectionTimingClaimed,
      false,
    );
    assert.equal(declaration?.privateExactClaimOpenings.location, "PRIVATE_ROOT_ONLY");
    assert.equal(
      declaration?.privateExactClaimOpenings.disposition,
      "PERSIST_UNTIL_EXPLICIT_OPERATOR_CLEANUP",
    );
    assert.equal(declaration?.privateExactClaimOpenings.automaticCleanup, false);
    assert.equal(declaration?.privateExactClaimOpenings.operatorCleanupRequired, true);
    assert.equal(declaration?.privateExactClaimOpenings.secureErasureClaim, false);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
