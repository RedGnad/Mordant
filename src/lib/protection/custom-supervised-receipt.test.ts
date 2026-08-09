import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";

import {
  CUSTOM_RECEIPT_BOOLEAN_AUTHORITY_DISCLOSURE,
  CUSTOM_RECEIPT_RECOURSE_BOUNDARY_DISCLOSURE,
  LEGACY_CUSTOM_RECEIPT_BOOLEAN_AUTHORITY_DISCLOSURE,
  PRE_POLICY_CUSTOM_RECEIPT_BOOLEAN_AUTHORITY_DISCLOSURE,
  PRE_POLICY_CUSTOM_RECEIPT_RECOURSE_BOUNDARY_DISCLOSURE,
  classifyCustomReceiptDisclosures,
  currentCustomReceiptDisclosures,
} from "../custom-supervised-receipt-disclosures";
import type { Sha256Digest } from "./cleanverse-asset";
import {
  CUSTOM_SUPERVISED_RECEIPT_SCHEMA,
  CustomSupervisedReceiptError,
  assertCustomSupervisedReceipt,
  customSupervisedReceiptDigest,
  type CustomSupervisedProtectionReceipt,
} from "./custom-supervised-receipt";

function digest(character: string): Sha256Digest {
  return `sha256:${character.repeat(64)}` as Sha256Digest;
}

function receiptBody(
  conflict: boolean,
  disclosures: readonly string[] = currentCustomReceiptDisclosures("OPERATOR"),
): Omit<CustomSupervisedProtectionReceipt, "receiptDigest"> {
  return {
    schemaVersion: CUSTOM_SUPERVISED_RECEIPT_SCHEMA,
    runId: conflict
      ? "11111111-1111-4111-8111-111111111111"
      : "22222222-2222-4222-8222-222222222222",
    sourceCommit: "1".repeat(40),
    governedFheCommit: "1".repeat(40),
    executionVariant: "CUSTOM_SUPERVISED",
    authorization: {
      protectionBindingSchema: "mordant.protection-binding/2",
      protectionBindingDigest: digest("a"),
      fheCaseId: digest("b"),
      caseBindingDigest: digest("c"),
    },
    execution: {
      participantArtifactDigests: [digest("d"), digest("e")],
      evaluatedArtifactDigest: digest("f"),
      evaluatorProvenance: digest("1"),
      decryptorProvenance: digest("2"),
      circuitId: "mordant.identity-full-fhe-256",
      parameterProfile: "mordant.bgv.identity-full-fhe-256.n15/v1",
    },
    governedResult: {
      conflict,
      digest: digest("3"),
      releaseMode: "governed-decryptor-v1",
      releaseOrdinal: 1,
      resultCiphertextDigest: digest("4"),
      independentlyRecomputedResultDigest: digest("4"),
    },
    terminal: {
      incidentState: conflict ? "CONFLICT_CONFIRMED" : "CLEARED",
      recourseState: conflict ? "CURE_WINDOW" : "REFUSED",
      recourseOpened: conflict,
      recourseRefusal: conflict ? null : "SIGNED_RESULT_FALSE",
      recourseRecordDigest: conflict ? digest("5") : null,
      originalReceivableState: "OUTSTANDING_INTACT",
    },
    chronology: {
      clockClass: "REAL_OBSERVED_CLOCK",
      signedAtUnix: 1_700_000_010,
      events: [],
    },
    disclosures,
  };
}

function receipt(
  conflict: boolean,
  disclosures?: readonly string[],
): CustomSupervisedProtectionReceipt {
  const body = receiptBody(conflict, disclosures);
  return { ...body, receiptDigest: customSupervisedReceiptDigest(body) };
}

function legacyDisclosures(): readonly string[] {
  return Object.freeze([
    ...currentCustomReceiptDisclosures("PARTICIPANT").slice(0, 3),
    LEGACY_CUSTOM_RECEIPT_BOOLEAN_AUTHORITY_DISCLOSURE,
  ]);
}

function prePolicyDisclosures(): readonly string[] {
  return Object.freeze([
    ...currentCustomReceiptDisclosures("PARTICIPANT").slice(0, 3),
    PRE_POLICY_CUSTOM_RECEIPT_BOOLEAN_AUTHORITY_DISCLOSURE,
    PRE_POLICY_CUSTOM_RECEIPT_RECOURSE_BOUNDARY_DISCLOSURE,
  ]);
}

function rejectsWithCode(value: CustomSupervisedProtectionReceipt, code: string): void {
  assert.throws(() => assertCustomSupervisedReceipt(value), (error: unknown) => (
    error instanceof CustomSupervisedReceiptError && error.code === code
  ));
}

test("fresh managed receipt disclosures state the Boolean and recourse authorities separately", () => {
  const disclosures = currentCustomReceiptDisclosures("OPERATOR");
  assert.equal(classifyCustomReceiptDisclosures(disclosures), "CURRENT");
  assert.equal(disclosures[3], CUSTOM_RECEIPT_BOOLEAN_AUTHORITY_DISCLOSURE);
  assert.equal(disclosures[4], CUSTOM_RECEIPT_RECOURSE_BOUNDARY_DISCLOSURE);
  assert.match(disclosures[3], /authenticated input to the precommitted policy/u);
  assert.match(disclosures[4], /does not authorize settlement/u);
  assert.doesNotMatch(disclosures[3], /terminal outcome/u);
});

for (const conflict of [true, false]) {
  test(`a fresh ${conflict ? "conflict" : "no-conflict"} receipt validates without private input`, () => {
    const value = receipt(conflict);
    assert.doesNotThrow(() => assertCustomSupervisedReceipt(value));
    const encoded = JSON.stringify(value);
    for (const forbidden of ["activeFrom", "activeUntil", "supervisedPledgeWindows", "privateKey", "root"]) {
      assert.equal(encoded.includes(`"${forbidden}"`), false, forbidden);
    }
    assert.equal(value.governedResult.conflict, conflict);
    assert.equal(value.terminal.recourseOpened, conflict);
  });
}

test("only the exact current and exact immutable historical disclosure layouts are accepted", () => {
  const current = currentCustomReceiptDisclosures("OPERATOR");
  const prePolicy = prePolicyDisclosures();
  const legacy = legacyDisclosures();
  assert.equal(classifyCustomReceiptDisclosures(current), "CURRENT");
  assert.equal(classifyCustomReceiptDisclosures(prePolicy), "PRE_POLICY");
  assert.equal(classifyCustomReceiptDisclosures(legacy), "LEGACY");

  const malformed = [
    [...current.slice(0, 3), "The governed Boolean controls everything."],
    current.slice(0, 4),
    [...legacy, CUSTOM_RECEIPT_RECOURSE_BOUNDARY_DISCLOSURE],
    [...current.slice(0, 3), LEGACY_CUSTOM_RECEIPT_BOOLEAN_AUTHORITY_DISCLOSURE, CUSTOM_RECEIPT_RECOURSE_BOUNDARY_DISCLOSURE],
    [...current, "extra"],
  ];
  for (const disclosures of malformed) {
    assert.equal(classifyCustomReceiptDisclosures(disclosures), null);
    rejectsWithCode(receipt(true, disclosures), "DISCLOSURES");
  }
});

test("correcting disclosure text changes new receipt digests without invalidating immutable historical bytes", () => {
  const current = receipt(true, currentCustomReceiptDisclosures("PARTICIPANT"));
  const prePolicy = receipt(true, prePolicyDisclosures());
  const legacy = receipt(true, legacyDisclosures());
  assert.notEqual(current.receiptDigest, prePolicy.receiptDigest);
  assert.notEqual(current.receiptDigest, legacy.receiptDigest);
  assert.doesNotThrow(() => assertCustomSupervisedReceipt(current));
  assert.doesNotThrow(() => assertCustomSupervisedReceipt(prePolicy));
  assert.doesNotThrow(() => assertCustomSupervisedReceipt(legacy));

  // Both disclosure contracts are recognized, so retaining a digest after
  // changing between them is rejected specifically as a digest mismatch.
  rejectsWithCode({ ...legacy, disclosures: current.disclosures }, "RECEIPT_DIGEST");
});

test("the two retained legacy managed receipts remain readable and byte-stable", () => {
  const fixtures = [
    ["hardened-custom-supervised-receipt-2026-08-07.json", "755ab5235e1c8960233569f72570d88c49b0f3949a28a1cfe46ed405a89033bf"],
    ["activation-custom-supervised-receipt-2026-08-07.json", "06c536bfc9714b775f79f86cb26f9a3a3cf1c7ab02c0ed81a4102049eb17be61"],
  ] as const;

  for (const [name, expectedFileDigest] of fixtures) {
    const bytes = readFileSync(join(process.cwd(), "docs", "evidence", name));
    assert.equal(createHash("sha256").update(bytes).digest("hex"), expectedFileDigest);
    const value = JSON.parse(bytes.toString("utf8")) as CustomSupervisedProtectionReceipt;
    assert.equal(classifyCustomReceiptDisclosures(value.disclosures), "LEGACY");
    assert.doesNotThrow(() => assertCustomSupervisedReceipt(value));
  }
});
