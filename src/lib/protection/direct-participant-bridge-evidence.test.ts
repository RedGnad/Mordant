import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";

import {
  DIRECT_PARTICIPANT_BRIDGE_EVIDENCE_SCHEMA,
  assertDirectParticipantBridgeEvidence,
  buildDirectParticipantBridgeEvidence,
  directParticipantBridgeEvidenceDigest,
  DirectParticipantBridgeEvidenceError,
  type DirectParticipantAdmissionFact,
  type DirectParticipantBridgeEvidence,
  type DirectParticipantBridgeExpectations,
} from "./direct-participant-bridge-evidence";
import type { GovernedSignedResult } from "./protection-evidence";

/**
 * The signed governed result is taken from the retained evidence rather than
 * synthesized, so every test here exercises the real Ed25519 verification path
 * over a real decryptor-published object. The retained file is only read.
 */
const RETAINED = JSON.parse(readFileSync(
  join(process.cwd(), "docs", "evidence", "conflicting-pledge-protection", "conflict.json"),
  "utf8",
)) as Readonly<{ governedResult: GovernedSignedResult & Readonly<{ digest?: string }> }>;

const HOLDER_A = "0x3883CbE36BE79bd8d1b73ff160B8E7c3CB983685";
const HOLDER_B = "0x3DcF732b35406Cf5C115Bc0f5D40918DFD2aCdc9";
const NEGATIVE_CONTROL = "0x981F6E0Ea94f45fDB8ee7680DC862212E3C720e0";
const UNCONTROLLED_APASS = "0x911F99f424D47F08a15fcC771e94dcc2f7252B02";
const SOURCE_COMMIT = "68ab53bf3edb20297251609c48985b9204dc7924";
const RUN_ID = "d91d389c-1d86-439a-8444-d2e42b5a3bf6";
const PROTECTION_BINDING = "sha256:c7a2b4863b5d209a1701e0ccfb26e4cf93ca8de9f6ab0af2790ec0f1e7d231f4" as const;
const RECEIPT_DIGEST = "sha256:5620c364c1e269b13eb16f99750b5b37bd14ba82b6709d7ace7147adf04bba32" as const;

function governedResult(): GovernedSignedResult {
  return JSON.parse(JSON.stringify(RETAINED.governedResult)) as GovernedSignedResult;
}

function admission(role: "PARTICIPANT_A" | "PARTICIPANT_B"): DirectParticipantAdmissionFact {
  const a = role === "PARTICIPANT_A";
  return {
    role,
    participantWallet: a ? HOLDER_A : HOLDER_B,
    authorizationDigest: a
      ? "0x67441f4ccd7a9017e513e1a9c010949fc875ed51ff1445575d336609b4ada22d"
      : "0x86fff7f2055ca4db0595d4a1d8a2f3c8ba2fbb6dbb8b64f2a1d0a8de6c8f5b31",
    claimCommitment: a
      ? "0xfe23408d72fd91f420250ad8a7914cb574e2dbc5e89f5182a8f9a29749503896"
      : "0xb17175d85d83800b0173a3ba1a1a0dcbdc5f1d5d8b2b3f2e1f0e9d8c7b6a5940",
    authorizationNonce: a
      ? "0xb90b8ad5a7aae9e49405f2e796f83e98201555d03746bf8979d3cdcb453b26d5"
      : "0x2f1e0d9c8b7a6958473625140312fedcba9876543210fedcba98765432100112",
    chainId: 10_143,
    eligibilityBlock: a ? 51_507_855 : 51_507_874,
  };
}

function validEvidence(): DirectParticipantBridgeEvidence {
  const result = governedResult();
  return buildDirectParticipantBridgeEvidence({
    sourceCommit: SOURCE_COMMIT,
    runId: RUN_ID,
    fheCaseId: result.caseId,
    protectionBindingDigest: PROTECTION_BINDING,
    caseBindingDigest: result.caseBindingDigest,
    caseBinding: {
      caseId: result.caseId,
      assetIdentity: result.assetIdentity,
      policyId: result.policyId,
      circuitDigest: result.circuitDigest,
      parameterFingerprint: result.parameterFingerprint,
      releaseMode: result.releaseMode,
      releaseAuthorityId: result.releaseAuthorityId,
      releaseAuthorityPublicKey: result.releaseAuthorityPublicKey,
    },
    participants: [admission("PARTICIPANT_A"), admission("PARTICIPANT_B")],
    participantArtifactDigestA: result.participantArtifactDigests[0],
    participantArtifactDigestB: result.participantArtifactDigests[1],
    evaluatedArtifactDigest: result.evaluatedArtifactDigest,
    governedResult: result,
    customReceiptDigest: RECEIPT_DIGEST,
  });
}

function expectations(overrides: Partial<DirectParticipantBridgeExpectations> = {}): DirectParticipantBridgeExpectations {
  return {
    sourceCommit: SOURCE_COMMIT,
    assetIdentity: RETAINED.governedResult.assetIdentity,
    holderA: HOLDER_A,
    holderB: HOLDER_B,
    excludedWallets: [NEGATIVE_CONTROL, UNCONTROLLED_APASS],
    ...overrides,
  };
}

/** Mutates a deep copy and reseals the digest, so only the intended defect is under test. */
function tamper(mutate: (draft: Record<string, unknown>) => void): unknown {
  const draft = JSON.parse(JSON.stringify(validEvidence())) as Record<string, unknown>;
  mutate(draft);
  const { evidenceDigest: _ignored, ...body } = draft;
  draft.evidenceDigest = directParticipantBridgeEvidenceDigest(
    body as unknown as Omit<DirectParticipantBridgeEvidence, "evidenceDigest">,
  );
  return draft;
}

function refuses(code: string, value: unknown, overrides: Partial<DirectParticipantBridgeExpectations> = {}): void {
  assert.throws(
    () => assertDirectParticipantBridgeEvidence(value, expectations(overrides)),
    (error: unknown) => error instanceof DirectParticipantBridgeEvidenceError && error.code === code,
    `expected refusal ${code}`,
  );
}

test("exact valid fresh evidence verifies and returns the signed Boolean", () => {
  const verified = assertDirectParticipantBridgeEvidence(validEvidence(), expectations());
  assert.equal(verified.evidence.schemaVersion, DIRECT_PARTICIPANT_BRIDGE_EVIDENCE_SCHEMA);
  assert.equal(verified.evidence.executionVariant, "CUSTOM_SUPERVISED");
  assert.equal(verified.conflict, RETAINED.governedResult.conflict);
  assert.equal(verified.holderA, HOLDER_A);
  assert.equal(verified.holderB, HOLDER_B);
  // The Boolean is the signed one, never a field of the artifact envelope.
  assert.equal(verified.conflict, verified.governedResult.conflict);
});

test("the evidence digest is exact", () => {
  const evidence = validEvidence();
  const { evidenceDigest, ...body } = evidence;
  assert.equal(evidenceDigest, directParticipantBridgeEvidenceDigest(body));
  // A changed field with the original digest is refused.
  refuses("EVIDENCE_DIGEST", { ...evidence, runId: "00000000-0000-4000-8000-000000000000" });
});

test("malformed schema is refused", () => {
  refuses("EVIDENCE_FIELDS", { schemaVersion: DIRECT_PARTICIPANT_BRIDGE_EVIDENCE_SCHEMA });
  refuses("EVIDENCE_FIELDS", tamper((draft) => { draft.unexpected = 1; }));
  refuses("SCHEMA", tamper((draft) => { draft.schemaVersion = "mordant.protection-evidence/4"; }));
  refuses("EXECUTION_VARIANT", tamper((draft) => { draft.executionVariant = "FIXED_FIXTURE"; }));
  refuses("EVIDENCE_FIELDS", null);
  refuses("EVIDENCE_FIELDS", []);
});

test("source commit must be exact and must match the execution", () => {
  refuses("SOURCE_COMMIT", validEvidence(), { sourceCommit: "a".repeat(40) });
  refuses("SOURCE_COMMIT", tamper((draft) => { draft.sourceCommit = "not-a-commit"; }));
  refuses("SOURCE_COMMIT", tamper((draft) => { draft.sourceCommit = SOURCE_COMMIT.toUpperCase(); }));
});

test("a tampered Ed25519 result signature is refused", () => {
  refuses("GOVERNED_RESULT_SIGNATURE", tamper((draft) => {
    const result = draft.governedResult as Record<string, unknown>;
    const signature = String(result.signature);
    result.signature = `${signature.slice(0, -2)}${signature.slice(-2) === "aa" ? "bb" : "aa"}`;
  }));
});

test("a changed release authority public key is refused", () => {
  refuses("GOVERNED_RESULT_SIGNATURE", tamper((draft) => {
    const result = draft.governedResult as Record<string, unknown>;
    const key = String(result.releaseAuthorityPublicKey);
    const swapped = `${key.slice(0, -2)}${key.slice(-2) === "AA" ? "BB" : "AA"}`;
    result.releaseAuthorityPublicKey = swapped;
    (draft.caseBinding as Record<string, unknown>).releaseAuthorityPublicKey = swapped;
  }));
});

test("a changed release authority id is refused", () => {
  refuses("GOVERNED_RESULT_SIGNATURE", tamper((draft) => {
    (draft.governedResult as Record<string, unknown>).releaseAuthorityId = `sha256:${"1".repeat(64)}`;
  }));
  // Even with a consistent envelope, the case binding must name the signed authority.
  refuses("RELEASE_AUTHORITY", tamper((draft) => {
    (draft.caseBinding as Record<string, unknown>).releaseAuthorityId = `sha256:${"2".repeat(64)}`;
  }));
});

test("a wrong asset identity is refused", () => {
  refuses("ASSET_IDENTITY", validEvidence(), { assetIdentity: `sha256:${"3".repeat(64)}` });
  refuses("ASSET_IDENTITY", tamper((draft) => {
    (draft.caseBinding as Record<string, unknown>).assetIdentity = `sha256:${"4".repeat(64)}`;
  }));
});

test("a wrong circuit digest or parameter fingerprint is refused", () => {
  refuses("CIRCUIT", tamper((draft) => {
    (draft.caseBinding as Record<string, unknown>).circuitDigest = `sha256:${"5".repeat(64)}`;
  }));
  refuses("PARAMETERS", tamper((draft) => {
    (draft.caseBinding as Record<string, unknown>).parameterFingerprint = `sha256:${"6".repeat(64)}`;
  }));
});

test("a wrong case binding is refused", () => {
  refuses("CASE_BINDING", tamper((draft) => { draft.caseBindingDigest = `sha256:${"7".repeat(64)}`; }));
  refuses("CASE_ID", tamper((draft) => { draft.fheCaseId = `sha256:${"8".repeat(64)}`; }));
  refuses("CASE_ID", tamper((draft) => {
    (draft.caseBinding as Record<string, unknown>).caseId = `sha256:${"9".repeat(64)}`;
  }));
  refuses("BINDING_DISTINCT", tamper((draft) => {
    draft.protectionBindingDigest = draft.caseBindingDigest;
  }));
});

test("a wrong participant artifact is refused on either side", () => {
  refuses("PARTICIPANT_ARTIFACTS", tamper((draft) => {
    draft.participantArtifactDigestA = `sha256:${"a".repeat(64)}`;
  }));
  refuses("PARTICIPANT_ARTIFACTS", tamper((draft) => {
    draft.participantArtifactDigestB = `sha256:${"b".repeat(64)}`;
  }));
  refuses("ARTIFACTS_DISTINCT", tamper((draft) => {
    draft.participantArtifactDigestB = draft.participantArtifactDigestA;
  }));
});

test("a wrong evaluated artifact is refused", () => {
  refuses("EVALUATED_ARTIFACT", tamper((draft) => {
    draft.evaluatedArtifactDigest = `sha256:${"c".repeat(64)}`;
  }));
});

test("a wrong result ciphertext digest or commitment is refused", () => {
  refuses("GOVERNED_RESULT_SIGNATURE", tamper((draft) => {
    (draft.governedResult as Record<string, unknown>).resultCiphertextDigest = `sha256:${"d".repeat(64)}`;
  }));
  refuses("GOVERNED_RESULT_SIGNATURE", tamper((draft) => {
    (draft.governedResult as Record<string, unknown>).resultCiphertextCommitment = `sha256:${"e".repeat(64)}`;
  }));
  // A missing field never reaches the shape check below: the signed object's own
  // exact-keys gate rejects it first, which is the stronger refusal.
  refuses("GOVERNED_RESULT_SIGNATURE", tamper((draft) => {
    delete (draft.governedResult as Record<string, unknown>).resultCiphertextCommitment;
  }));
});

test("a changed Boolean is refused because it is signed", () => {
  refuses("GOVERNED_RESULT_SIGNATURE", tamper((draft) => {
    const result = draft.governedResult as Record<string, unknown>;
    result.conflict = !(result.conflict as boolean);
  }));
});

test("the governed result digest must be the digest of the signed object", () => {
  refuses("RESULT_DIGEST", tamper((draft) => {
    draft.governedResultDigest = `sha256:${"f".repeat(64)}`;
  }));
});

test("a changed wallet on either side is refused", () => {
  refuses("CANONICAL_PARTICIPANT", tamper((draft) => {
    (draft.participants as Record<string, unknown>[])[0].participantWallet = "0x1111111111111111111111111111111111111111";
  }));
  refuses("CANONICAL_PARTICIPANT", tamper((draft) => {
    (draft.participants as Record<string, unknown>[])[1].participantWallet = "0x2222222222222222222222222222222222222222";
  }));
});

test("an A/B role swap is refused", () => {
  refuses("ADMISSION_ROLE", tamper((draft) => {
    const participants = draft.participants as Record<string, unknown>[];
    participants[0].role = "PARTICIPANT_B";
    participants[1].role = "PARTICIPANT_A";
  }));
  // Wallets swapped while roles stay in order is equally refused.
  refuses("CANONICAL_PARTICIPANT", tamper((draft) => {
    const participants = draft.participants as Record<string, unknown>[];
    participants[0].participantWallet = HOLDER_B;
    participants[1].participantWallet = HOLDER_A;
  }));
});

test("the same wallet in both roles is refused", () => {
  refuses("CANONICAL_PARTICIPANT", tamper((draft) => {
    (draft.participants as Record<string, unknown>[])[1].participantWallet = HOLDER_A;
  }));
  // And it is refused on the admitted wallets even if the pins collapsed too.
  refuses("PARTICIPANTS_DISTINCT", tamper((draft) => {
    (draft.participants as Record<string, unknown>[])[1].participantWallet = HOLDER_A;
  }), { holderB: HOLDER_A });
});

test("the uncontrolled UAT wallet and the negative control can never participate", () => {
  for (const wallet of [UNCONTROLLED_APASS, NEGATIVE_CONTROL]) {
    refuses("EXCLUDED_PARTICIPANT", tamper((draft) => {
      (draft.participants as Record<string, unknown>[])[0].participantWallet = wallet;
    }), { holderA: wallet });
  }
});

test("an admission from another run or another binding is refused", () => {
  refuses("RUN_ID", tamper((draft) => { draft.runId = "not-a-run-id"; }));
  const other = tamper((draft) => { draft.runId = "11111111-1111-4111-8111-111111111111"; });
  assert.throws(
    () => assertDirectParticipantBridgeEvidence(other, { ...expectations(), runId: RUN_ID }),
    (error: unknown) => error instanceof DirectParticipantBridgeEvidenceError && error.code === "RUN_ID",
  );
  refuses("ADMISSION_CHAIN", tamper((draft) => {
    (draft.participants as Record<string, unknown>[])[0].chainId = 1;
  }));
  refuses("ADMISSION_FIELDS", tamper((draft) => {
    delete (draft.participants as Record<string, unknown>[])[0].claimCommitment;
  }));
  refuses("PARTICIPANTS", tamper((draft) => { draft.participants = [admission("PARTICIPANT_A")]; }));
});

test("no raw pledge window or private material can ride along", () => {
  const encoded = JSON.stringify(validEvidence());
  for (const forbidden of ["activeFrom", "activeUntil", "privateKey", "signingKey", "publicRoot"]) {
    assert.equal(encoded.includes(`"${forbidden}"`), false, `${forbidden} must not appear`);
  }
  // The claim itself is a commitment, never the interval.
  assert.match(encoded, /"claimCommitment":"0x[0-9a-f]{64}"/u);
});

test("retained protection evidence v4 is refused by this verifier", () => {
  // The two contracts stay disjoint in both directions: V4 evidence cannot enter
  // here, and this artifact cannot enter assertPublicProtectionEvidence.
  const v4 = JSON.parse(readFileSync(
    join(process.cwd(), "docs", "evidence", "conflicting-pledge-protection", "conflict.json"),
    "utf8",
  )) as unknown;
  refuses("EVIDENCE_FIELDS", v4);
});

test("the artifact is not and cannot be read as protection evidence v4", () => {
  const evidence = validEvidence();
  assert.notEqual(evidence.schemaVersion as string, "mordant.protection-evidence/4");
  // It carries no V4 members at all, so it can never be mistaken for one.
  for (const v4Member of ["manifestDigest", "cleanverseAsset", "protectionCase", "chronology", "governedFheCommit"]) {
    assert.equal(Object.hasOwn(evidence, v4Member), false, `${v4Member} must not appear`);
  }
});
