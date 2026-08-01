// Off-chain mirrors of the frozen V4 digest constructions.
//
// These are NOT standard EIP-712 struct hashes. The frozen contracts hash in
// nested chunks to stay inside the stack limit, so a generic EIP-712 encoder
// would produce different digests. Every function here reproduces the exact
// Solidity byte layout, and `v4-digests.test.mjs` pins each one against vectors
// emitted by the contracts themselves.
//
// This module is the CLIENT-side implementation. The runner recomputes the same
// values by an independent path and both are checked against `eth_call` on the
// deployed contracts before anything is published or evaluated.

import { keccak256, encodeAbiParameters, encodePacked, stringToBytes, getAddress } from "viem";

const b32 = { type: "bytes32" };
const u256 = { type: "uint256" };
const u64 = { type: "uint64" };
const u32 = { type: "uint32" };
const u16 = { type: "uint16" };
const u8 = { type: "uint8" };
const addr = { type: "address" };
const bool = { type: "bool" };

export const EIP712_DOMAIN_TYPEHASH = keccak256(
  stringToBytes("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
);

export const GOVERNANCE_DOMAIN = { name: "Mordant Bilateral Session Intent", version: "1" };
export const BINDER_DOMAIN = { name: "Mordant Private Match Binder", version: "1" };
export const VERIFIER_DOMAIN = { name: "Mordant Confidential Match", version: "4" };
export const SOURCE_DOMAIN = { name: "Mordant Source Attestation", version: "1" };

export const INTENT_TYPEHASH = keccak256(
  stringToBytes(
    "BilateralSessionIntent(uint256 chainId,address governanceRegistry,bytes32 policyId,uint32 policyVersion,bytes32 governanceRecordA,bytes32 governanceRecordB,bytes32 controllerKeyIdA,bytes32 controllerKeyIdB,uint32 controllerEpochA,uint32 controllerEpochB,uint32 scopeAuthorizationVersionA,uint32 scopeAuthorizationVersionB,bytes32 sourceRecordA,bytes32 sourceRecordB,bytes32 issuerKeyId,uint32 identityEpoch,bytes32 strictAssetCommitmentA,bytes32 supersedesCandidateSession,bool candidateAuthorized,uint32 exactBudget,uint32 candidateBudget,uint256 sessionNonce,uint64 expiry,uint32 disclosureVersion)",
  ),
);

export const SIGNATURE_DOMAIN = keccak256(stringToBytes("mordant.session-initiation-signatures/1"));
export const COMMITMENT_DOMAIN = keccak256(stringToBytes("mordant.bilateral-session-commitment/2"));

export const DISCLOSURE_CONSENT_TYPEHASH = keccak256(
  stringToBytes(
    "DisclosureConsent(uint256 chainId,address binder,bytes32 policyId,uint32 policyVersion,bytes32 sessionCommitment,bytes32 resultCommitment,bytes32 matchCommitment,bytes32 scopeCommitment,bytes32 governanceRecord,bytes32 controllerKeyId,uint32 controllerEpoch,uint32 scopeAuthorizationVersion,address anchor,uint32 disclosureVersion,uint64 validUntil,uint256 nonce)",
  ),
);

export const RESULT_CORE_TYPEHASH = keccak256(
  stringToBytes(
    "ConfidentialMatchResultV4Core(uint256 chainId,address binder,bytes32 policyId,uint32 policyVersion,bytes32 sessionCommitment,bytes32 sessionId,bytes32 scopeCommitmentA,bytes32 scopeCommitmentB,bytes32 inputCommitmentA,bytes32 inputCommitmentB,uint8 outcome,bool conflictConfirmed,bytes32 matchCommitment,uint8 anchorCount,uint256 nonce,uint64 validUntil,bytes32 providerProofCommitment)",
  ),
);

export const ATTESTATION_TYPEHASH = keccak256(
  stringToBytes("ConfidentialMatchAttestation(bytes32 validatorSetId,bytes32 resultDigest)"),
);

export const SOURCE_ATTESTATION_TYPEHASH = keccak256(
  stringToBytes(
    "SourceAssetAttestation(uint256 chainId,address factory,bytes32 creationDigest,bytes32 assetCommitment,bytes32 initialTermsCommitment,uint16 identitySchemeVersion,uint16 termsSchemeVersion,uint32 identityEpoch,bytes32 issuerKeyId,bytes32 invoiceRoot,address controller,uint64 validUntil,uint256 nonce)",
  ),
);

export function domainSeparator({ name, version }, chainId, verifyingContract) {
  return keccak256(
    encodeAbiParameters(
      [b32, b32, b32, u256, addr],
      [
        EIP712_DOMAIN_TYPEHASH,
        keccak256(stringToBytes(name)),
        keccak256(stringToBytes(version)),
        BigInt(chainId),
        getAddress(verifyingContract),
      ],
    ),
  );
}

const signed = (separator, structHash) =>
  keccak256(encodePacked(["bytes2", "bytes32", "bytes32"], ["0x1901", separator, structHash]));

/* ------------------------------------------------------- bilateral intent */

/** Mirrors MordantScopeGovernanceRegistry.intentHash, chunk for chunk. */
export function intentHash(intent) {
  const authority = keccak256(
    encodeAbiParameters(
      [b32, b32, b32, b32, u32, u32, u32, u32],
      [
        intent.governanceRecordA,
        intent.governanceRecordB,
        intent.controllerKeyIdA,
        intent.controllerKeyIdB,
        Number(intent.controllerEpochA),
        Number(intent.controllerEpochB),
        Number(intent.scopeAuthorizationVersionA),
        Number(intent.scopeAuthorizationVersionB),
      ],
    ),
  );
  const anchors = keccak256(
    encodeAbiParameters(
      [b32, b32, b32, u32, b32, b32],
      [
        intent.sourceRecordA,
        intent.sourceRecordB,
        intent.issuerKeyId,
        Number(intent.identityEpoch),
        intent.strictAssetCommitmentA,
        intent.supersedesCandidateSession,
      ],
    ),
  );
  const permissions = keccak256(
    encodeAbiParameters(
      [bool, u32, u32, u256, u64, u32],
      [
        Boolean(intent.candidateAuthorized),
        Number(intent.exactBudget),
        Number(intent.candidateBudget),
        BigInt(intent.sessionNonce),
        BigInt(intent.expiry),
        Number(intent.disclosureVersion),
      ],
    ),
  );
  return keccak256(
    encodeAbiParameters(
      [b32, u256, addr, b32, u32, b32, b32, b32],
      [
        INTENT_TYPEHASH,
        BigInt(intent.chainId),
        getAddress(intent.governanceRegistry),
        intent.policyId,
        Number(intent.policyVersion),
        authority,
        anchors,
        permissions,
      ],
    ),
  );
}

export function intentDigest(intent, chainId, governance) {
  return signed(domainSeparator(GOVERNANCE_DOMAIN, chainId, governance), intentHash(intent));
}

/**
 * The three initiation signatures, canonically ordered.
 *
 * Order is fixed, so swapping two signatures is a different session rather than
 * the same one differently presented.
 */
export function signatureBundleDigest({ controllerA, controllerB, issuer }) {
  return keccak256(
    encodeAbiParameters(
      [b32, b32, b32, b32],
      [SIGNATURE_DOMAIN, keccak256(controllerA), keccak256(controllerB), keccak256(issuer)],
    ),
  );
}

/**
 * The opaque value the relayer publishes.
 *
 * It binds the intent AND the three authorizations, so a published commitment
 * proves that bilateral initiation and issuer authorization already existed when
 * it was posted, not merely that the intent fields did.
 */
export function sessionCommitment({ intent, signatures, salt, chainId, governance }) {
  return keccak256(
    encodeAbiParameters(
      [b32, u256, addr, b32, b32, b32],
      [
        COMMITMENT_DOMAIN,
        BigInt(chainId),
        getAddress(governance),
        intentHash(intent),
        signatureBundleDigest(signatures),
        salt,
      ],
    ),
  );
}

/* ------------------------------------------------------- disclosure consent */

/** Mirrors PrivateMatchBinder.consentDigest, including its three-part packing. */
export function consentDigest({
  chainId, binder, policyId, policyVersion, sessionCommitment: session, resultCommitment,
  matchCommitment, anchor, consent, authorization,
}) {
  const structHash = keccak256(
    encodePacked(
      ["bytes", "bytes", "bytes"],
      [
        encodeAbiParameters(
          [b32, u256, addr, b32, u32, b32, b32],
          [
            DISCLOSURE_CONSENT_TYPEHASH,
            BigInt(chainId),
            getAddress(binder),
            policyId,
            Number(policyVersion),
            session,
            resultCommitment,
          ],
        ),
        encodeAbiParameters(
          [b32, b32, b32, b32, u32, u32],
          [
            matchCommitment,
            consent.scopeCommitment,
            consent.governanceRecord,
            authorization.controllerKeyId,
            Number(authorization.controllerEpoch),
            Number(authorization.authorizationVersion),
          ],
        ),
        encodeAbiParameters(
          [addr, u32, u64, u256],
          [
            getAddress(anchor),
            Number(consent.disclosureVersion),
            BigInt(consent.validUntil),
            BigInt(consent.nonce),
          ],
        ),
      ],
    ),
  );
  return signed(domainSeparator(BINDER_DOMAIN, chainId, binder), structHash);
}

/* ------------------------------------------------------------- V4 result */

/** Mirrors ECDSAQuorumMatchVerifierV4.resultCoreCommitment. */
export function resultCoreCommitment(envelope) {
  const r = envelope.result;
  const scope = keccak256(
    encodeAbiParameters(
      [b32, b32, b32, b32, b32],
      [r.sessionId, r.scopeCommitmentA, r.scopeCommitmentB, r.inputCommitmentA, r.inputCommitmentB],
    ),
  );
  const verdict = keccak256(
    encodeAbiParameters(
      [u8, bool, b32, u8, b32],
      [
        Number(r.outcome),
        Boolean(r.conflictConfirmed),
        r.matchCommitment,
        Number(r.anchorCount),
        r.providerProofCommitment,
      ],
    ),
  );
  return keccak256(
    encodePacked(
      ["bytes", "bytes"],
      [
        encodeAbiParameters(
          [b32, u256, addr, b32, u32, b32],
          [
            RESULT_CORE_TYPEHASH,
            BigInt(envelope.chainId),
            getAddress(envelope.binder),
            envelope.policyId,
            Number(envelope.policyVersion),
            envelope.sessionCommitment,
          ],
        ),
        encodeAbiParameters(
          [u256, u64, b32, b32],
          [BigInt(envelope.nonce), BigInt(envelope.validUntil), scope, verdict],
        ),
      ],
    ),
  );
}

export function resultDigest(envelope, chainId, verifier) {
  return signed(domainSeparator(VERIFIER_DOMAIN, chainId, verifier), resultCoreCommitment(envelope));
}

export function attestationDigest({ validatorSetId, resultHash, chainId, verifier }) {
  return signed(
    domainSeparator(VERIFIER_DOMAIN, chainId, verifier),
    keccak256(encodeAbiParameters([b32, b32, b32], [ATTESTATION_TYPEHASH, validatorSetId, resultHash])),
  );
}

/* --------------------------------------------------------- source attestation */

/** Mirrors MordantSourceAttestation.digest. */
export function sourceAttestationDigest(attestation, chainId, verifyingContract) {
  const structHash = keccak256(
    encodeAbiParameters(
      [b32, u256, addr, b32, b32, b32, u16, u16, u32, b32, b32, addr, u64, u256],
      [
        SOURCE_ATTESTATION_TYPEHASH,
        BigInt(attestation.chainId),
        getAddress(attestation.factory),
        attestation.creationDigest,
        attestation.assetCommitment,
        attestation.initialTermsCommitment,
        Number(attestation.identitySchemeVersion),
        Number(attestation.termsSchemeVersion),
        Number(attestation.identityEpoch),
        attestation.issuerKeyId,
        attestation.invoiceRoot,
        getAddress(attestation.controller),
        BigInt(attestation.validUntil),
        BigInt(attestation.nonce),
      ],
    ),
  );
  return signed(domainSeparator(SOURCE_DOMAIN, chainId, verifyingContract), structHash);
}

/* ------------------------------------------------------------- signatures */

const SECP256K1_HALF_ORDER =
  0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0n;

/**
 * The canonical encoding every frozen contract requires: 65 bytes, v in {27,28},
 * s in the lower half of the group order.
 *
 * Both signature bytes AND the recovered signer feed the commitment, so a
 * non-canonical variant of a valid signature is a different, unusable session
 * rather than an equivalent one.
 */
export function assertCanonicalSignature(signature, label) {
  if (typeof signature !== "string" || !/^0x[0-9a-fA-F]{130}$/.test(signature)) {
    throw new Error(`SIGNATURE_MALFORMED:${label}`);
  }
  const s = BigInt(`0x${signature.slice(66, 130)}`);
  const v = Number.parseInt(signature.slice(130, 132), 16);
  if (s === 0n || s > SECP256K1_HALF_ORDER) throw new Error(`SIGNATURE_NOT_LOW_S:${label}`);
  if (v !== 27 && v !== 28) throw new Error(`SIGNATURE_BAD_V:${label}`);
  return true;
}
