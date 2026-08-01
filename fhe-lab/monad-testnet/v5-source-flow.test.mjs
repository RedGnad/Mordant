// Group 3 integration: opaque source admission against a real local EVM,
// including the metadata audit over the actual transaction.
import assert from "node:assert/strict";
import test from "node:test";
import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { decodeEventLog, keccak256, toBytes } from "viem";

import { deployStack, artifact, CHAIN_ID } from "./v5-rehearsal-support.mjs";
import { startLocalChain } from "./v5-local-chain.mjs";
import {
  CONFIDENTIAL_SOURCE_FIELDS, SourceFlowError, commitSourceCalldata, freshSourceSalt,
  representationsOf, requireOpaqueAdmission, scanPublicSurface, signSourceAttestation,
  sourceCommitmentFromChain, sourcePreimage, writeRevealPackage,
} from "./v5-source-flow.mjs";

/// Builds, signs and admits one opaque source. Returns everything the audit
/// and the later negatives need.
async function admitSource(chain, stack, {
  label = "counterparty", nonce = 11n, controller = null, salt = null, submitter = null,
} = {}) {
  const sourcesArt = await artifact("sources");
  const now = BigInt((await chain.client.getBlock()).timestamp);
  const preimage = sourcePreimage({
    chainId: CHAIN_ID,
    sourceRegistry: stack.at.sources,
    controller: controller ?? stack.accounts.originator.address,
    invoiceRoot: keccak256(toBytes(`mordant.v5.source-root/${label}`)),
    assetCommitment: keccak256(toBytes(`mordant.v5.source-asset/${label}`)),
    initialTermsCommitment: keccak256(toBytes(`mordant.v5.source-terms/${label}`)),
    creationDigest: keccak256(toBytes(`mordant.v5.source-creation/${label}`)),
    issuerKeyId: stack.issuerKeyId,
    identityEpoch: 1,
    validUntil: now + 30n * 24n * 3600n,
    nonce,
    salt: salt ?? freshSourceSalt(),
  });
  const { digest, signature } = await signSourceAttestation({
    preimage, chainId: CHAIN_ID, sourceRegistry: stack.at.sources, signer: stack.issuerSigner,
  });
  const commitment = await sourceCommitmentFromChain({
    client: chain.client, sourcesAbi: sourcesArt.abi, sourceRegistry: stack.at.sources,
    attestation: preimage.attestation, signature, salt: preimage.salt,
  });

  const sender = submitter ?? stack.accounts.submitter;
  const hash = await stack.tx.write(sender, {
    address: stack.at.sources, abi: sourcesArt.abi, functionName: "commitSource", args: [commitment],
  });
  const receipt = await chain.client.waitForTransactionReceipt({ hash });
  return { preimage, digest, signature, commitment, hash, receipt, sourcesArt };
}

/* --------------------------------------------------------------- the flow */

test("an opaque source is admitted and reads back correctly", async (t) => {
  const chain = await startLocalChain();
  t.after(() => chain.stop());
  const stack = await deployStack(chain);

  const admitted = await admitSource(chain, stack);
  assert.equal(admitted.receipt.status, "success");

  const record = await chain.client.readContract({
    address: stack.at.sources, abi: admitted.sourcesArt.abi, functionName: "commitment",
    args: [admitted.commitment],
  });
  // `commitment` returns a named struct, so viem decodes it as an object.
  assert.equal(record.exists, true);
  assert.equal(record.revealed, false, "a source is not revealed before binding");
  assert.equal(record.submitter.toLowerCase(), stack.accounts.submitter.address.toLowerCase());
  assert.ok(Number(record.committedInBlock) > 0);
  assert.ok(Number(record.committedAt) > 0);
});

/* ------------------------------------------------------- metadata audit */

test("the source admission transaction leaks no confidential field", async (t) => {
  const chain = await startLocalChain();
  t.after(() => chain.stop());
  const stack = await deployStack(chain);
  const admitted = await admitSource(chain, stack);

  const transaction = await chain.client.getTransaction({ hash: admitted.hash });
  const receipt = admitted.receipt;

  // Everything a bystander can read: the calldata, every topic, every log data
  // blob, and the stored record.
  const surfaces = { calldata: transaction.input };
  receipt.logs.forEach((log, index) => {
    log.topics.forEach((topic, position) => {
      surfaces[`log${index}.topic${position}`] = topic;
    });
    surfaces[`log${index}.data`] = log.data;
  });
  const record = await chain.client.readContract({
    address: stack.at.sources, abi: admitted.sourcesArt.abi, functionName: "commitment",
    args: [admitted.commitment],
  });
  surfaces["storage.commitmentRecord"] = Buffer.from(
    JSON.stringify(record, (key, value) => (typeof value === "bigint" ? value.toString() : value)),
    "utf8",
  );

  const confidential = {
    controller: admitted.preimage.attestation.controller,
    invoiceRoot: admitted.preimage.attestation.invoiceRoot,
    assetCommitment: admitted.preimage.attestation.assetCommitment,
    initialTermsCommitment: admitted.preimage.attestation.initialTermsCommitment,
    creationDigest: admitted.preimage.attestation.creationDigest,
    salt: admitted.preimage.salt,
    attestationDigest: admitted.digest,
    issuerSignature: admitted.signature,
  };

  const summary = requireOpaqueAdmission({ surfaces, confidential });
  assert.ok(summary.scanned >= 2, "expected calldata and at least one log surface");

  // The calldata must be exactly the selector plus the commitment: 4 + 32 bytes.
  const expected = commitSourceCalldata({
    sourcesAbi: admitted.sourcesArt.abi, commitment: admitted.commitment,
  });
  assert.equal(transaction.input, expected);
  assert.equal((transaction.input.length - 2) / 2, 36, "one selector and one word, nothing else");
});

// A scanner that only reads aligned words would miss a value embedded at an odd
// offset, so the unaligned case is asserted directly.
test("the scanner finds a value at an unaligned offset", () => {
  const secret = keccak256(toBytes("secret"));
  const raw = Buffer.from(secret.slice(2), "hex");
  const haystack = Buffer.concat([Buffer.alloc(7, 0xab), raw, Buffer.alloc(5, 0xcd)]);
  const findings = scanPublicSurface({
    surfaces: { odd: haystack },
    confidential: { secret },
  });
  assert.equal(findings.length >= 1, true, "an unaligned occurrence must be found");
  assert.equal(findings[0].representation, "raw");
});

test("the scanner covers every declared representation", () => {
  const value = keccak256(toBytes("value"));
  const forms = representationsOf(value);
  const names = forms.map((form) => form.name);
  for (const expected of ["raw", "reversed", "lower-hex", "upper-hex", "prefixed-hex", "base64", "base64url"]) {
    assert.ok(names.includes(expected), `missing representation ${expected}`);
  }
  // Each representation must actually be detectable.
  for (const form of forms) {
    const findings = scanPublicSurface({
      surfaces: { buried: Buffer.concat([Buffer.alloc(3), form.bytes, Buffer.alloc(3)]) },
      confidential: { value },
    });
    assert.ok(findings.length > 0, `${form.name} was not detected`);
  }
});

test("an address is scanned both padded and unpadded", () => {
  const address = "0x1234567890abcdef1234567890abcdef12345678";
  const unpadded = Buffer.from(address.slice(2), "hex");
  const findings = scanPublicSurface({
    surfaces: { packed: Buffer.concat([Buffer.alloc(5), unpadded]) },
    confidential: { controller: address },
  });
  assert.ok(findings.length > 0, "an unpadded address must be detected");
});

// A field added to the preimage without being added to the audit list would go
// unscanned. This keeps the two in step.
test("every confidential field name is covered by the audit list", () => {
  for (const field of ["controller", "invoiceRoot", "assetCommitment", "initialTermsCommitment", "creationDigest"]) {
    assert.ok(CONFIDENTIAL_SOURCE_FIELDS.includes(field), `${field} is not in the audit list`);
  }
});

test("a deliberate leak is caught rather than passed", () => {
  const controller = "0x1234567890abcdef1234567890abcdef12345678";
  assert.throws(
    () => requireOpaqueAdmission({
      surfaces: { calldata: Buffer.from(controller.slice(2), "hex") },
      confidential: { controller },
    }),
    (error) => error instanceof SourceFlowError && error.code === "SOURCE_ADMISSION_LEAK",
  );
});

/* ------------------------------------------------------------ negatives */

test("the same attestation under a different salt is a different commitment", async (t) => {
  const chain = await startLocalChain();
  t.after(() => chain.stop());
  const stack = await deployStack(chain);
  const sourcesArt = await artifact("sources");
  const first = await admitSource(chain, stack, { label: "salted", nonce: 21n });

  const other = await sourceCommitmentFromChain({
    client: chain.client, sourcesAbi: sourcesArt.abi, sourceRegistry: stack.at.sources,
    attestation: first.preimage.attestation, signature: first.signature, salt: freshSourceSalt(),
  });
  assert.notEqual(other, first.commitment);
});

test("an unauthorized submitter cannot publish a commitment", async (t) => {
  const chain = await startLocalChain();
  t.after(() => chain.stop());
  const stack = await deployStack(chain);
  await assert.rejects(
    () => admitSource(chain, stack, { label: "rogue", nonce: 31n, submitter: stack.accounts.buyer }),
  );
});

test("the same commitment cannot be published twice", async (t) => {
  const chain = await startLocalChain();
  t.after(() => chain.stop());
  const stack = await deployStack(chain);
  const sourcesArt = await artifact("sources");
  const first = await admitSource(chain, stack, { label: "once", nonce: 41n });

  await assert.rejects(() => stack.tx.write(stack.accounts.submitter, {
    address: stack.at.sources, abi: sourcesArt.abi, functionName: "commitSource",
    args: [first.commitment],
  }));
});

// The attestation names the registry it is for. A signature produced for the
// factory must not be usable at the source registry.
test("an attestation naming the factory is refused for the source registry", async (t) => {
  const chain = await startLocalChain();
  t.after(() => chain.stop());
  const stack = await deployStack(chain);
  const now = BigInt((await chain.client.getBlock()).timestamp);
  const preimage = sourcePreimage({
    chainId: CHAIN_ID, sourceRegistry: stack.at.factory, // wrong registry
    controller: stack.accounts.originator.address,
    invoiceRoot: keccak256(toBytes("r")), assetCommitment: keccak256(toBytes("a")),
    initialTermsCommitment: keccak256(toBytes("t")), creationDigest: keccak256(toBytes("c")),
    issuerKeyId: stack.issuerKeyId, identityEpoch: 1, validUntil: now + 3600n,
    nonce: 51n, salt: freshSourceSalt(),
  });
  await assert.rejects(
    () => signSourceAttestation({
      preimage, chainId: CHAIN_ID, sourceRegistry: stack.at.sources, signer: stack.issuerSigner,
    }),
    (error) => error.code === "SOURCE_REGISTRY_MISMATCH",
  );
});

test("a malformed salt is refused before anything is signed", () => {
  assert.throws(
    () => sourcePreimage({
      chainId: CHAIN_ID, sourceRegistry: "0x1", controller: "0x2",
      invoiceRoot: "0x3", assetCommitment: "0x4", initialTermsCommitment: "0x5",
      creationDigest: "0x6", issuerKeyId: "0x7", identityEpoch: 1, validUntil: 1n, nonce: 1n,
      salt: "0xshort",
    }),
    (error) => error.code === "SOURCE_SALT_INVALID",
  );
});

/* -------------------------------------------------------- reveal package */

test("the reveal package is written privately and never inside the tracked tree", async () => {
  const root = await mkdtemp(join(tmpdir(), "v5-reveal-"));
  const path = join(root, "source-a.json");
  const preimage = sourcePreimage({
    chainId: CHAIN_ID, sourceRegistry: "0x2222222222222222222222222222222222222222",
    controller: "0x3333333333333333333333333333333333333333",
    invoiceRoot: keccak256(toBytes("r")), assetCommitment: keccak256(toBytes("a")),
    initialTermsCommitment: keccak256(toBytes("t")), creationDigest: keccak256(toBytes("c")),
    issuerKeyId: keccak256(toBytes("k")), identityEpoch: 1, validUntil: 1n << 40n,
    nonce: 1n, salt: freshSourceSalt(),
  });
  const written = await writeRevealPackage({
    path, preimage, signature: `0x${"11".repeat(65)}`,
    digest: keccak256(toBytes("d")), commitment: keccak256(toBytes("c")),
  });
  assert.ok(written.bytes > 0);
  const parsed = JSON.parse(await readFile(path, "utf8"));
  assert.equal(parsed.salt, preimage.salt);
  assert.equal(parsed.attestation.controller, preimage.attestation.controller);

  await assert.rejects(
    () => writeRevealPackage({
      path: "/repo/contracts/src/leak.json", preimage,
      signature: "0x00", digest: "0x00", commitment: "0x00",
    }),
    (error) => error.code === "REVEAL_PACKAGE_INSIDE_TRACKED_TREE",
  );
});
