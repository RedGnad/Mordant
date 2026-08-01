// Group 3: opaque source admission.
//
// This is the correction to external audit finding C-01. In V4 the whole
// attestation was an ABI argument to `register`, so the controller sat in
// permanent public calldata and could be joined against the vault's public
// `originatorTreasury`. Both participants were linkable before the session was
// even committed.
//
// Here exactly one 32-byte value reaches the chain before binding. Everything
// else lives in a reveal package that never leaves the private working root.
import { randomBytes } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { encodeFunctionData, keccak256, toBytes, toHex } from "viem";

import { agreedSourceAttestationDigest }
  from "../shared/identity/source-attestation-digest.mjs";

export class SourceFlowError extends Error {
  constructor(code, detail) {
    super(`${code}: ${detail}`);
    this.code = code;
    this.name = "SourceFlowError";
  }
}

/// The fields that must never be publicly recoverable before binding.
///
/// Named as data so the metadata audit scans exactly the set the mission
/// requires, and a field added to the preimage without being added here fails
/// the coverage test rather than silently going unscanned.
export const CONFIDENTIAL_SOURCE_FIELDS = Object.freeze([
  "controller",
  "invoiceRoot",
  "assetCommitment",
  "initialTermsCommitment",
  "creationDigest",
  "issuerKeyId",
]);

/// A 32-byte salt. Generated once, frozen in the journal, never regenerated.
export function freshSourceSalt() {
  return toHex(randomBytes(32));
}

/// Builds the complete private preimage.
///
/// `salt` is passed in rather than generated here so a resumed run supplies the
/// frozen one; generating inside would make preparation non-deterministic and
/// the stage framework would reject it as drift.
export function sourcePreimage({
  chainId, sourceRegistry, controller, invoiceRoot, assetCommitment,
  initialTermsCommitment, creationDigest, issuerKeyId, identityEpoch, validUntil, nonce, salt,
}) {
  if (!/^0x[0-9a-fA-F]{64}$/.test(salt)) {
    throw new SourceFlowError("SOURCE_SALT_INVALID", "salt must be 32 bytes of hex");
  }
  return {
    attestation: {
      chainId: BigInt(chainId),
      // The verifying contract for an opaque source is the source registry,
      // NOT the factory. The same attestation signed for the factory produces a
      // different digest, which is what stops a creation signature being
      // replayed at admission.
      factory: sourceRegistry,
      creationDigest,
      assetCommitment,
      initialTermsCommitment,
      identitySchemeVersion: 3,
      termsSchemeVersion: 1,
      identityEpoch,
      issuerKeyId,
      invoiceRoot,
      controller,
      validUntil,
      nonce,
    },
    salt,
  };
}

/// Agrees the attestation digest three ways, then asks the issuer to sign it.
export async function signSourceAttestation({ preimage, chainId, sourceRegistry, signer }) {
  if (preimage.attestation.factory.toLowerCase() !== sourceRegistry.toLowerCase()) {
    throw new SourceFlowError(
      "SOURCE_REGISTRY_MISMATCH",
      `attestation names ${preimage.attestation.factory}, registry is ${sourceRegistry}`,
    );
  }
  const digest = agreedSourceAttestationDigest(preimage.attestation, chainId, sourceRegistry);
  const signature = await signer.signDigest(digest);
  if (!/^0x[0-9a-fA-F]{130}$/.test(signature)) {
    throw new SourceFlowError("SOURCE_SIGNATURE_MALFORMED", signature);
  }
  return { digest, signature };
}

/// Reads the commitment from the registry itself rather than deriving it.
///
/// `sourceCommitmentOf` is a view on the frozen contract, so there is no reason
/// for the runner to reimplement the hashing and every reason not to.
export async function sourceCommitmentFromChain({
  client, sourcesAbi, sourceRegistry, attestation, signature, salt,
}) {
  return client.readContract({
    address: sourceRegistry, abi: sourcesAbi, functionName: "sourceCommitmentOf",
    args: [attestation, signature, salt],
  });
}

export function commitSourceCalldata({ sourcesAbi, commitment }) {
  return encodeFunctionData({ abi: sourcesAbi, functionName: "commitSource", args: [commitment] });
}

/// The reveal package. Written outside the tracked tree, 0600.
///
/// It is the only place the preimage exists after preparation, and it is what
/// the binder will later consume. Losing it strands the session; committing it
/// would defeat the entire opaque-admission design.
export async function writeRevealPackage({ path, preimage, signature, digest, commitment }) {
  if (path.includes("/contracts/") || path.includes("/docs/") || path.includes("/src/")) {
    throw new SourceFlowError("REVEAL_PACKAGE_INSIDE_TRACKED_TREE", path);
  }
  await mkdir(dirname(path), { recursive: true });
  const body = JSON.stringify(
    {
      schemaVersion: "mordant.v5-source-reveal/1",
      commitment,
      attestationDigest: digest,
      attestation: Object.fromEntries(
        Object.entries(preimage.attestation).map(([key, value]) => [
          key, typeof value === "bigint" ? value.toString() : value,
        ]),
      ),
      salt: preimage.salt,
      issuerSignature: signature,
    },
    null, 2,
  );
  await writeFile(path, body + "\n", { mode: 0o600 });
  return { path, bytes: body.length };
}

/* --------------------------------------------------------- metadata audit */

/// Every representation a confidential value could plausibly wear in public
/// data. Unaligned matching matters: a 32-byte value embedded at an odd offset
/// inside calldata is just as recoverable as one on a word boundary, and a
/// scanner that only reads aligned words would miss it.
export function representationsOf(value) {
  const hex = value.toLowerCase().replace(/^0x/, "");
  const raw = Buffer.from(hex, "hex");
  const forms = new Map();
  const add = (name, buffer) => {
    if (buffer && buffer.length > 0) forms.set(name, buffer);
  };
  add("raw", raw);
  add("reversed", Buffer.from([...raw].reverse()));
  add("lower-hex", Buffer.from(hex, "utf8"));
  add("upper-hex", Buffer.from(hex.toUpperCase(), "utf8"));
  add("prefixed-hex", Buffer.from(`0x${hex}`, "utf8"));
  add("base64", Buffer.from(raw.toString("base64"), "utf8"));
  add("base64url", Buffer.from(raw.toString("base64url"), "utf8"));
  // An address is twenty bytes; scanning only the padded word would miss the
  // unpadded form that appears inside packed encodings.
  if (raw.length === 32 && raw.subarray(0, 12).every((byte) => byte === 0)) {
    add("address-unpadded", raw.subarray(12));
  }
  if (raw.length === 20) add("address-padded", Buffer.concat([Buffer.alloc(12), raw]));
  return [...forms.entries()].map(([name, bytes]) => ({ name, bytes }));
}

/// Scans one public surface for any representation of any confidential value.
///
/// `surfaces` is a map of label -> hex string or Buffer. Matching is a plain
/// byte search over the whole buffer, so an unaligned occurrence is found.
export function scanPublicSurface({ surfaces, confidential }) {
  const findings = [];
  for (const [label, surface] of Object.entries(surfaces)) {
    if (surface === null || surface === undefined) continue;
    const haystack = Buffer.isBuffer(surface)
      ? surface
      : Buffer.from(String(surface).replace(/^0x/, ""), "hex");
    if (haystack.length === 0) continue;
    for (const [field, value] of Object.entries(confidential)) {
      if (value === null || value === undefined) continue;
      for (const form of representationsOf(String(value))) {
        if (haystack.includes(form.bytes)) {
          findings.push({ surface: label, field, representation: form.name });
        }
      }
    }
  }
  return findings;
}

/// The gate. Throws with every leak named, rather than returning a boolean a
/// caller might ignore.
export function requireOpaqueAdmission({ surfaces, confidential }) {
  const findings = scanPublicSurface({ surfaces, confidential });
  if (findings.length > 0) {
    throw new SourceFlowError(
      "SOURCE_ADMISSION_LEAK",
      findings.map((f) => `${f.field} as ${f.representation} in ${f.surface}`).join("; "),
    );
  }
  return { scanned: Object.keys(surfaces).length, fields: Object.keys(confidential).length };
}
