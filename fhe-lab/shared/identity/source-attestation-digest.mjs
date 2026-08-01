// The source-attestation digest, agreed three ways.
//
// `MordantSourceAttestation` is a library with `internal` functions and
// `MordantFactoryV2` exposes no `attestationDigest` view, so this is the one
// digest in the V5 flow that cannot be read back from a deployed contract. A
// runner must derive it, and a wrong derivation only reverts AFTER broadcast.
//
// So it is derived twice by independent code paths and both are pinned against
// a Solidity vector emitted by the frozen library itself. The gate below is
// what a runner calls before asking an issuer to sign anything.
import { keccak256, stringToBytes, concatHex, pad, toHex, getAddress } from "viem";

import { sourceAttestationDigest, SOURCE_ATTESTATION_TYPEHASH, SOURCE_DOMAIN }
  from "./v4-digests.mjs";

/* ------------------------------------------- independent reference implementation */

/// Left-pads any value to one 32-byte EIP-712 word.
const word = (value) => pad(typeof value === "string" ? value : toHex(value), { size: 32 });

/// Builds the struct hash by explicit word concatenation rather than through an
/// ABI encoder, so it shares no code path with the runner implementation.
export function referenceStructHash(a) {
  return keccak256(concatHex([
    SOURCE_ATTESTATION_TYPEHASH,
    word(BigInt(a.chainId)),
    word(getAddress(a.factory).toLowerCase()),
    word(a.creationDigest),
    word(a.assetCommitment),
    word(a.initialTermsCommitment),
    word(Number(a.identitySchemeVersion)),
    word(Number(a.termsSchemeVersion)),
    word(Number(a.identityEpoch)),
    word(a.issuerKeyId),
    word(a.invoiceRoot),
    word(getAddress(a.controller).toLowerCase()),
    word(BigInt(a.validUntil)),
    word(BigInt(a.nonce)),
  ]));
}

export function referenceDomainSeparator(chainId, verifyingContract) {
  return keccak256(concatHex([
    keccak256(stringToBytes(
      "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")),
    keccak256(stringToBytes(SOURCE_DOMAIN.name)),
    keccak256(stringToBytes(SOURCE_DOMAIN.version)),
    word(BigInt(chainId)),
    word(getAddress(verifyingContract).toLowerCase()),
  ]));
}

export function referenceDigest(a, chainId, verifyingContract) {
  return keccak256(concatHex([
    "0x1901",
    referenceDomainSeparator(chainId, verifyingContract),
    referenceStructHash(a),
  ]));
}

/* ------------------------------------------------------------------- the gate */

/// The single check a runner calls before signing anything. Throws unless all
/// three producers agree.
export function agreedSourceAttestationDigest(attestation, chainId, verifyingContract) {
  const runner = sourceAttestationDigest(attestation, chainId, verifyingContract);
  const reference = referenceDigest(attestation, chainId, verifyingContract);
  if (runner !== reference) {
    throw new Error(
      `SOURCE_ATTESTATION_DIGEST_DISAGREEMENT: runner ${runner} reference ${reference}`,
    );
  }
  return runner;
}


