// Group 2: Vault V2 creation and activation.
//
// The anchor is the one on-chain object the binder later proves provenance for,
// so everything here is checked twice: the source-attestation digest is agreed
// three ways before the issuer signs it, and the vault address is agreed four
// ways before the deployment is accepted.
//
// The digest matters more than it looks. `MordantSourceAttestation` is a
// library with `internal` functions and Factory V2 exposes no
// `attestationDigest` view, so this is the one value in the whole flow that
// cannot be read back from a deployed contract. A wrong derivation reverts, but
// only after broadcast.
import { encodeFunctionData, getContractAddress, keccak256, toBytes } from "viem";

import { agreedSourceAttestationDigest }
  from "../shared/identity/source-attestation-digest.mjs";

export class VaultFlowError extends Error {
  constructor(code, detail) {
    super(`${code}: ${detail}`);
    this.code = code;
    this.name = "VaultFlowError";
  }
}

/// Roles: buyer 1, originator 2, facility 3, holder 4. Read from the frozen
/// factory, not invented here.
export const ROLE = Object.freeze({ BUYER: 1, ORIGINATOR: 2, FACILITY: 3, HOLDER: 4 });

/// Builds the InvoiceConfig in the exact ABI field order of the frozen factory.
///
/// The order is normative: `creationDigest` hashes this struct, the attestation
/// names that digest, and the issuer signs the attestation. A transposed field
/// changes all three and fails at `createIdentityAnchoredVault`.
export function invoiceConfig({ adapter, settlement, invoiceRoot, currency, roles, economics }) {
  return {
    cvaAdapter: adapter,
    settlementToken: settlement,
    invoiceRoot,
    currency,
    buyer: roles.buyer,
    originatorTreasury: roles.originator,
    initialOriginatorSigner: roles.originator,
    initialUnits: economics.units,
    advanceAmount: economics.advance,
    faceValue: economics.face,
    bondBps: economics.bondBps,
    protectionEnd: economics.protectionEnd,
    revealPeriod: economics.revealPeriod,
    curePeriod: economics.curePeriod,
  };
}

/// The attestation an accountable issuer signs BEFORE the anchor exists.
///
/// `factory` inside the struct and the verifying contract are the same address
/// by construction: the frozen library checks `attestation.factory ==
/// verifyingContract`, so a mismatch is refused rather than silently accepted.
export function sourceAttestation({
  chainId, factory, creationDigest, assetCommitment, initialTermsCommitment,
  issuerKeyId, invoiceRoot, controller, identityEpoch, validUntil, nonce,
}) {
  return {
    chainId: BigInt(chainId),
    factory,
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
  };
}

/// Agrees the digest three ways, then asks the issuer process to sign it.
///
/// The runner never holds the issuer key: `signer` is an opaque capability that
/// returns a signature for a digest and nothing else.
export async function agreeAndSignAttestation({ attestation, chainId, verifyingContract, signer }) {
  if (attestation.factory.toLowerCase() !== verifyingContract.toLowerCase()) {
    throw new VaultFlowError(
      "ATTESTATION_FACTORY_MISMATCH",
      `struct names ${attestation.factory}, verifying contract is ${verifyingContract}`,
    );
  }
  // Throws SOURCE_ATTESTATION_DIGEST_DISAGREEMENT unless the runner
  // implementation and the independent reference agree; both are pinned
  // against the frozen Solidity vector in CI.
  const digest = agreedSourceAttestationDigest(attestation, chainId, verifyingContract);
  const signature = await signer.signDigest(digest);
  if (!/^0x[0-9a-fA-F]{130}$/.test(signature)) {
    throw new VaultFlowError("ATTESTATION_SIGNATURE_MALFORMED", signature);
  }
  return { digest, signature };
}

/// Predicts the vault address the factory will produce.
///
/// The frozen factory deploys with CREATE2 salted by the attestation digest, so
/// the address is knowable before broadcast. Predicting it is what turns "the
/// deployment worked" into "the deployment produced the anchor we intended".
export function predictVaultAddress({ factory, attestationDigest, initCodeHash }) {
  return getContractAddress({
    opcode: "CREATE2",
    from: factory,
    salt: attestationDigest,
    bytecodeHash: initCodeHash,
  });
}

/// Simulates the exact creation calldata from the intended buyer.
///
/// This is the last chance to learn that eligibility, the adapter approval or
/// the issuer registration is wrong, and it costs nothing. It also returns the
/// address the factory WOULD produce, which must equal the prediction.
export async function simulateCreation({ client, factoryAbi, factory, buyer, config, attestation, signature }) {
  const { result } = await client.simulateContract({
    address: factory,
    abi: factoryAbi,
    functionName: "createIdentityAnchoredVault",
    args: [config, attestation, signature],
    account: buyer,
  });
  return result;
}

export function creationCalldata({ factoryAbi, config, attestation, signature }) {
  return encodeFunctionData({
    abi: factoryAbi,
    functionName: "createIdentityAnchoredVault",
    args: [config, attestation, signature],
  });
}

/// Requires every independent source of the vault address to agree.
///
/// Four sources: the CREATE2 prediction, the eth_call return, the factory's own
/// `vaultForRoot` readback, and the address the deployment receipt implies via
/// `vaultForAttestation`. Any disagreement means the anchor on chain is not the
/// one that was reviewed.
export function requireAddressAgreement({ predicted, simulated, byRoot, byAttestation }) {
  const values = { predicted, simulated, byRoot, byAttestation };
  const normalized = Object.fromEntries(
    Object.entries(values).map(([key, value]) => [key, value?.toLowerCase() ?? null]),
  );
  const present = Object.entries(normalized).filter(([, value]) => value);
  if (present.length < 2) {
    throw new VaultFlowError("ADDRESS_AGREEMENT_INSUFFICIENT", JSON.stringify(values));
  }
  const distinct = new Set(present.map(([, value]) => value));
  if (distinct.size !== 1) {
    throw new VaultFlowError("ADDRESS_DISAGREEMENT", JSON.stringify(values));
  }
  return present[0][1];
}

/// Reads back everything the binder will later depend on.
///
/// The binder proves anchor provenance through
/// `factory.vaultForAttestation(anchor.sourceAttestationDigest()) == anchor`,
/// so that exact round trip is verified here rather than assumed.
export async function readVaultState({ client, vaultAbi, factoryAbi, vault, factory }) {
  const read = (functionName, args = []) =>
    client.readContract({ address: vault, abi: vaultAbi, functionName, args });

  const [
    assetCommitment, identitySchemeVersion, initialTermsCommitment, termsSchemeVersion,
    identityEpoch, issuerKeyId, sourceAttestationDigest, receivableState, protectionState,
    totalSupply, invoiceRoot,
  ] = await Promise.all([
    read("assetCommitment"), read("identitySchemeVersion"), read("initialTermsCommitment"),
    read("termsSchemeVersion"), read("identityEpoch"), read("issuerKeyId"),
    read("sourceAttestationDigest"), read("receivableState"), read("protectionState"),
    read("totalSupply"), read("invoiceRoot"),
  ]);

  const admitted = await client.readContract({
    address: factory, abi: factoryAbi, functionName: "vaultForAttestation",
    args: [sourceAttestationDigest],
  });

  return {
    assetCommitment, identitySchemeVersion, initialTermsCommitment, termsSchemeVersion,
    identityEpoch, issuerKeyId, sourceAttestationDigest, receivableState, protectionState,
    totalSupply, invoiceRoot, admittedAs: admitted,
  };
}

/// The post-activation state the binder requires. Stated as one function so the
/// rehearsal and the live run cannot check different things.
export function requireActivatedAnchor(state, expected) {
  const problems = [];
  if (Number(state.receivableState) !== 1) problems.push(`receivableState ${state.receivableState}, expected Outstanding (1)`);
  if (Number(state.protectionState) !== 1) problems.push(`protectionState ${state.protectionState}, expected Active (1)`);
  if (BigInt(state.totalSupply) === 0n) problems.push("totalSupply is zero");
  if (Number(state.identitySchemeVersion) !== 3) problems.push(`identityScheme ${state.identitySchemeVersion}, expected 3`);
  if (Number(state.termsSchemeVersion) !== 1) problems.push(`termsScheme ${state.termsSchemeVersion}, expected 1`);
  if (state.assetCommitment !== expected.assetCommitment) problems.push("assetCommitment does not match the attestation");
  if (state.initialTermsCommitment !== expected.initialTermsCommitment) problems.push("initialTermsCommitment does not match the attestation");
  if (state.issuerKeyId !== expected.issuerKeyId) problems.push("issuerKeyId does not match the attestation");
  if (state.invoiceRoot !== expected.invoiceRoot) problems.push("invoiceRoot does not match the attestation");
  if (state.sourceAttestationDigest !== expected.attestationDigest) {
    problems.push("sourceAttestationDigest does not match the signed attestation");
  }
  // The provenance round trip the binder performs.
  if (state.admittedAs?.toLowerCase() !== expected.vault.toLowerCase()) {
    problems.push(
      `factory.vaultForAttestation resolves to ${state.admittedAs}, not the anchor ${expected.vault}`,
    );
  }
  if (problems.length > 0) {
    throw new VaultFlowError("ANCHOR_STATE_INVALID", problems.join("; "));
  }
  return true;
}

/// A deterministic invoice root for one rehearsal or run, derived from the
/// journal's frozen session label rather than from a clock, so a resumed run
/// reproduces it exactly.
export function deriveInvoiceRoot(label) {
  return keccak256(toBytes(`mordant.v5.invoice/${label}`));
}
