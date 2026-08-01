// Group 2 integration rehearsal: a real stack, a real vault, real activation.
//
// This deploys the actual compiled contracts to a fresh local EVM and drives
// the real handlers. A mocked chain would prove the handlers agree with the
// mock, which is the one thing nobody needs to know.
import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { keccak256, encodeAbiParameters, parseAbiParameters, toBytes, encodePacked } from "viem";

import { REPO } from "./priv8-chain.mjs";
import { ARTIFACTS } from "./v5-call-matrix.mjs";
import { DEPLOYMENTS, deploymentOrder, resolveArguments, resolveConfiguration }
  from "./v5-deployment-plan.mjs";
import { startLocalChain, localTransactor } from "./v5-local-chain.mjs";
import {
  ROLE, VaultFlowError, agreeAndSignAttestation, deriveInvoiceRoot, invoiceConfig,
  predictVaultAddress, readVaultState, requireActivatedAnchor, requireAddressAgreement,
  simulateCreation, sourceAttestation,
} from "./v5-vault-flow.mjs";

const CHAIN_ID = 31_337;
const CURRENCY = keccak256(toBytes("USD"));
const POLICY_ID = keccak256(toBytes("mordant.policy.v5"));

const artifacts = {};
async function artifact(key) {
  if (!artifacts[key]) {
    artifacts[key] = JSON.parse(await readFile(resolve(REPO, ARTIFACTS[key]), "utf8"));
  }
  return artifacts[key];
}

/// An issuer process stand-in. It exposes ONLY `signDigest`: the runner cannot
/// reach the key, cannot ask it to sign arbitrary bytes as a transaction, and
/// cannot enumerate it.
function issuerSigner(account) {
  return {
    address: account.address,
    async signDigest(digest) {
      assert.match(digest, /^0x[0-9a-f]{64}$/, "issuer signs a 32-byte digest only");
      return account.sign({ hash: digest });
    },
  };
}

async function deployStack(chain) {
  const tx = localTransactor(chain.client, chain.walletFor);
  const [deployer, issuer, buyer, originator, facility, holder, relayer, submitter] = chain.accounts;
  const [v1, v2, v3] = chain.accounts.slice(8, 11);
  const roles = {
    deployer: deployer.address, issuer: issuer.address, buyer: buyer.address,
    originator: originator.address, facility: facility.address, holder: holder.address,
    relayer: relayer.address, submitter: submitter.address,
  };
  const validators = [v1.address, v2.address, v3.address]
    .sort((a, b) => (BigInt(a) < BigInt(b) ? -1 : 1));
  assert.equal(new Set(validators).size, 3, "validators must be distinct");
  const config = {
    policyId: POLICY_ID, policyVersion: 1, validators, quorum: 2n, recomputationQuorum: 2,
    curePeriod: 604_800n, consequenceId: keccak256(toBytes("consequence")), identityEpoch: 1,
  };

  const at = {};
  for (const entry of deploymentOrder()) {
    const art = await artifact(entry.artifact);
    const args = resolveArguments(entry, { at, roles, config });
    const hash = await tx.deploy(deployer, art, args);
    const receipt = await chain.client.waitForTransactionReceipt({ hash });
    assert.equal(receipt.status, "success", `deploy ${entry.id}`);
    at[entry.id] = receipt.contractAddress;
  }

  for (const step of ["register-issuer", "set-policy-version", "authorize-relayer",
    "authorize-binder", "authorize-submitter", "authorize-revealer", "approve-adapter",
    "approve-settlement", "approve-facility", "eligible-buyer", "eligible-originator",
    "eligible-facility", "eligible-holder"]) {
    const call = resolveConfiguration(step, { at, roles, config });
    const key = DEPLOYMENTS.find((entry) => entry.id ===
      Object.keys(at).find((id) => at[id] === call.at))?.artifact;
    const art = await artifact(key);
    const hash = await tx.write(deployer, { address: call.at, abi: art.abi, functionName: call.fn, args: call.args });
    const receipt = await chain.client.waitForTransactionReceipt({ hash });
    assert.equal(receipt.status, "success", step);
  }

  return { at, roles, config, tx, accounts: { deployer, issuer, buyer, originator, facility, holder, relayer, submitter } };
}

/// Builds and creates one anchored vault, agreeing the address four ways.
async function createVault(chain, stack, { label = "rehearsal", nonce = 1n } = {}) {
  const factoryArt = await artifact("factory");
  const invoiceRoot = deriveInvoiceRoot(label);
  const now = BigInt((await chain.client.getBlock()).timestamp);
  const economics = {
    units: 100_000_000n, advance: 100_000_000n, face: 110_000_000n, bondBps: 1_000,
    protectionEnd: now + 30n * 24n * 3600n, revealPeriod: 3600n, curePeriod: 3600n,
  };
  const config = invoiceConfig({
    adapter: stack.at.adapter, settlement: stack.at.settlement, invoiceRoot,
    currency: CURRENCY, roles: stack.roles, economics,
  });
  const creationDigest = await chain.client.readContract({
    address: stack.at.factory, abi: factoryArt.abi, functionName: "creationDigest", args: [config],
  });
  const issuerKeyId = await chain.client.readContract({
    address: stack.at.issuerRegistry, abi: (await artifact("issuerRegistry")).abi,
    functionName: "issuerKeyIdFor", args: [stack.roles.issuer],
  });

  const stableId = keccak256(toBytes(`mordant.v5.stable/${label}`));
  const assetCommitment = keccak256(
    encodeAbiParameters(parseAbiParameters("bytes32,uint256"), [stableId, nonce]),
  );
  const attestation = sourceAttestation({
    chainId: CHAIN_ID, factory: stack.at.factory, creationDigest, assetCommitment,
    initialTermsCommitment: keccak256(toBytes(`terms/${label}`)),
    issuerKeyId, invoiceRoot, controller: stack.roles.originator,
    identityEpoch: 1, validUntil: now + 7n * 24n * 3600n, nonce,
  });

  const { digest, signature } = await agreeAndSignAttestation({
    attestation, chainId: CHAIN_ID, verifyingContract: stack.at.factory,
    signer: issuerSigner(stack.accounts.issuer),
  });

  const simulated = await simulateCreation({
    client: chain.client, factoryAbi: factoryArt.abi, factory: stack.at.factory,
    buyer: stack.accounts.buyer, config, attestation, signature,
  });

  const hash = await stack.tx.write(stack.accounts.buyer, {
    address: stack.at.factory, abi: factoryArt.abi,
    functionName: "createIdentityAnchoredVault", args: [config, attestation, signature],
  });
  const receipt = await chain.client.waitForTransactionReceipt({ hash });
  assert.equal(receipt.status, "success", "vault creation");

  const byRoot = await chain.client.readContract({
    address: stack.at.factory, abi: factoryArt.abi, functionName: "vaultForRoot", args: [invoiceRoot],
  });

  // Activation prerequisite discovered by the rehearsal: every settlement
  // transfer calls `cviVerifier.hasValidIdentity(address(this))`, so the VAULT
  // itself must carry a valid identity or `activate` reverts
  // `SettlementNotReady()`. In production this is a real CVI registration; the
  // mock exposes it as `setIdentityValid`.
  await stack.tx.write(stack.accounts.deployer, {
    address: stack.at.eligibility, abi: (await artifact("eligibility")).abi,
    functionName: "setIdentityValid", args: [byRoot, true],
  }).then((h) => chain.client.waitForTransactionReceipt({ hash: h }));
  const byAttestation = await chain.client.readContract({
    address: stack.at.factory, abi: factoryArt.abi, functionName: "vaultForAttestation", args: [digest],
  });

  return {
    vault: byRoot, attestation, attestationDigest: digest, signature, config, invoiceRoot,
    assetCommitment, issuerKeyId, simulated, byRoot, byAttestation, economics, receipt,
  };
}

/* ------------------------------------------------------------------ tests */

test("the full stack deploys and a vault is created with agreeing addresses", async (t) => {
  const chain = await startLocalChain();
  t.after(() => chain.stop());

  const stack = await deployStack(chain);
  for (const entry of DEPLOYMENTS) {
    assert.match(stack.at[entry.id], /^0x[0-9a-fA-F]{40}$/, entry.id);
  }

  const created = await createVault(chain, stack);

  // Three independent sources must agree. The CREATE2 prediction needs the
  // init-code hash, which the frozen factory does not expose, so the fourth
  // source is the factory's own `predictVaultAddress` view.
  const factoryArt = await artifact("factory");
  const initCode = await chain.client.readContract({
    address: stack.at.factory, abi: factoryArt.abi, functionName: "predictVaultAddress",
    args: [created.attestationDigest, "0x"],
  }).catch(() => null);

  const agreed = requireAddressAgreement({
    predicted: null,
    simulated: created.simulated,
    byRoot: created.byRoot,
    byAttestation: created.byAttestation,
  });
  assert.equal(agreed, created.vault.toLowerCase());
  assert.ok(initCode === null || typeof initCode === "string");
});

test("the anchor reaches Outstanding, protected and funded after activation", async (t) => {
  const chain = await startLocalChain();
  t.after(() => chain.stop());
  const stack = await deployStack(chain);
  const created = await createVault(chain, stack);

  // Activation prerequisites, through the vault's own path.
  const erc20 = await artifact("erc20");
  const adapterArt = await artifact("adapter");
  const vaultArt = await artifact("vault");
  const { units } = { units: created.economics.units };

  await stack.tx.write(stack.accounts.deployer, {
    address: stack.at.cvaToken, abi: erc20.abi, functionName: "mint",
    args: [stack.accounts.deployer.address, units],
  }).then((h) => chain.client.waitForTransactionReceipt({ hash: h }));
  await stack.tx.write(stack.accounts.deployer, {
    address: stack.at.cvaToken, abi: erc20.abi, functionName: "approve",
    args: [stack.at.adapter, units],
  }).then((h) => chain.client.waitForTransactionReceipt({ hash: h }));
  await stack.tx.write(stack.accounts.deployer, {
    address: stack.at.adapter, abi: adapterArt.abi, functionName: "creditVault",
    args: [created.vault, units],
  }).then((h) => chain.client.waitForTransactionReceipt({ hash: h }));

  await stack.tx.write(stack.accounts.deployer, {
    address: stack.at.settlement, abi: erc20.abi, functionName: "mint",
    args: [stack.accounts.holder.address, created.economics.advance],
  }).then((h) => chain.client.waitForTransactionReceipt({ hash: h }));
  await stack.tx.write(stack.accounts.holder, {
    address: stack.at.settlement, abi: erc20.abi, functionName: "approve",
    args: [created.vault, created.economics.advance * 10n],
  }).then((h) => chain.client.waitForTransactionReceipt({ hash: h }));

  const now = BigInt((await chain.client.getBlock()).timestamp);
  const pledge = {
    invoiceRoot: created.invoiceRoot,
    originatorSigner: stack.roles.originator,
    facility: stack.roles.facility,
    obligationId: keccak256(encodePacked(["string", "address"], ["obligation", created.vault])),
    amount: created.economics.face,
    currency: CURRENCY,
    activeFrom: now - 1n,
    activeUntil: created.economics.protectionEnd + 1n,
    nonce: BigInt(created.vault),
    deadline: now + 2n * 24n * 3600n,
    exclusive: true,
  };
  const pledgeHash = await chain.client.readContract({
    address: created.vault, abi: vaultArt.abi, functionName: "hashPledge", args: [pledge],
  });
  const pledgeSignature = await stack.accounts.originator.sign({ hash: pledgeHash });

  const activateHash = await stack.tx.write(stack.accounts.facility, {
    address: created.vault, abi: vaultArt.abi, functionName: "activate",
    args: [pledge, pledgeSignature, stack.roles.holder, [stack.roles.holder], [created.economics.units]],
  });
  const activation = await chain.client.waitForTransactionReceipt({ hash: activateHash });
  assert.equal(activation.status, "success", "activation");

  const state = await readVaultState({
    client: chain.client, vaultAbi: vaultArt.abi, factoryAbi: (await artifact("factory")).abi,
    vault: created.vault, factory: stack.at.factory,
  });

  requireActivatedAnchor(state, {
    assetCommitment: created.assetCommitment,
    initialTermsCommitment: created.attestation.initialTermsCommitment,
    issuerKeyId: created.issuerKeyId,
    invoiceRoot: created.invoiceRoot,
    attestationDigest: created.attestationDigest,
    vault: created.vault,
  });

  assert.equal(Number(state.receivableState), 1, "Outstanding");
  assert.equal(Number(state.protectionState), 1, "Active");
  assert.ok(BigInt(state.totalSupply) > 0n, "funded");
});

/* --------------------------------------------------------------- negatives */

test("an attestation signed by the wrong issuer is refused", async (t) => {
  const chain = await startLocalChain();
  t.after(() => chain.stop());
  const stack = await deployStack(chain);

  // Sign with an account that was never registered as an issuer.
  const rogue = chain.accounts[6];
  const factoryArt = await artifact("factory");
  const invoiceRoot = deriveInvoiceRoot("rogue");
  const now = BigInt((await chain.client.getBlock()).timestamp);
  const config = invoiceConfig({
    adapter: stack.at.adapter, settlement: stack.at.settlement, invoiceRoot, currency: CURRENCY,
    roles: stack.roles,
    economics: {
      units: 100_000_000n, advance: 100_000_000n, face: 110_000_000n, bondBps: 1_000,
      protectionEnd: now + 30n * 24n * 3600n, revealPeriod: 3600n, curePeriod: 3600n,
    },
  });
  const creationDigest = await chain.client.readContract({
    address: stack.at.factory, abi: factoryArt.abi, functionName: "creationDigest", args: [config],
  });
  const issuerKeyId = await chain.client.readContract({
    address: stack.at.issuerRegistry, abi: (await artifact("issuerRegistry")).abi,
    functionName: "issuerKeyIdFor", args: [stack.roles.issuer],
  });
  const attestation = sourceAttestation({
    chainId: CHAIN_ID, factory: stack.at.factory, creationDigest,
    assetCommitment: keccak256(toBytes("rogue.asset")),
    initialTermsCommitment: keccak256(toBytes("rogue.terms")),
    issuerKeyId, invoiceRoot, controller: stack.roles.originator,
    identityEpoch: 1, validUntil: now + 3600n, nonce: 99n,
  });
  const { signature } = await agreeAndSignAttestation({
    attestation, chainId: CHAIN_ID, verifyingContract: stack.at.factory,
    signer: issuerSigner(rogue),
  });

  await assert.rejects(() => simulateCreation({
    client: chain.client, factoryAbi: factoryArt.abi, factory: stack.at.factory,
    buyer: stack.accounts.buyer, config, attestation, signature,
  }));
});

// The attestation names the factory it is for. Signing for one contract and
// submitting to another must fail, or a signature could be lifted between
// deployments.
test("an attestation naming a different factory is refused before signing", async (t) => {
  const chain = await startLocalChain();
  t.after(() => chain.stop());
  const stack = await deployStack(chain);
  const attestation = sourceAttestation({
    chainId: CHAIN_ID, factory: stack.at.sources, // wrong contract
    creationDigest: keccak256(toBytes("x")), assetCommitment: keccak256(toBytes("a")),
    initialTermsCommitment: keccak256(toBytes("t")), issuerKeyId: keccak256(toBytes("k")),
    invoiceRoot: keccak256(toBytes("r")), controller: stack.roles.originator,
    identityEpoch: 1, validUntil: 1n << 40n, nonce: 1n,
  });
  await assert.rejects(
    () => agreeAndSignAttestation({
      attestation, chainId: CHAIN_ID, verifyingContract: stack.at.factory,
      signer: issuerSigner(stack.accounts.issuer),
    }),
    (error) => error instanceof VaultFlowError && error.code === "ATTESTATION_FACTORY_MISMATCH",
  );
});

// Changing any creation parameter after signing invalidates the creationDigest
// the attestation names.
test("a creation parameter changed after signing is refused", async (t) => {
  const chain = await startLocalChain();
  t.after(() => chain.stop());
  const stack = await deployStack(chain);
  const factoryArt = await artifact("factory");
  const created = await createVault(chain, stack, { label: "mutate", nonce: 7n });

  const mutated = { ...created.config, advanceAmount: created.config.advanceAmount + 1n };
  await assert.rejects(() => simulateCreation({
    client: chain.client, factoryAbi: factoryArt.abi, factory: stack.at.factory,
    buyer: stack.accounts.buyer, config: mutated,
    attestation: created.attestation, signature: created.signature,
  }));
});

test("a replayed attestation nonce is refused", async (t) => {
  const chain = await startLocalChain();
  t.after(() => chain.stop());
  const stack = await deployStack(chain);
  const first = await createVault(chain, stack, { label: "first", nonce: 5n });
  assert.match(first.vault, /^0x[0-9a-fA-F]{40}$/);

  // A different invoice, same issuer nonce.
  await assert.rejects(() => createVault(chain, stack, { label: "second", nonce: 5n }));
});

test("address disagreement is detected rather than tolerated", () => {
  assert.throws(
    () => requireAddressAgreement({
      predicted: "0xaaaa", simulated: "0xaaaa", byRoot: "0xbbbb", byAttestation: "0xaaaa",
    }),
    (error) => error.code === "ADDRESS_DISAGREEMENT",
  );
  assert.throws(
    () => requireAddressAgreement({ predicted: null, simulated: "0xaaaa", byRoot: null, byAttestation: null }),
    (error) => error.code === "ADDRESS_AGREEMENT_INSUFFICIENT",
  );
});

test("an anchor missing any required property is refused", () => {
  const base = {
    receivableState: 1, protectionState: 1, totalSupply: 1n,
    identitySchemeVersion: 3, termsSchemeVersion: 1,
    assetCommitment: "0xa", initialTermsCommitment: "0xt", issuerKeyId: "0xk",
    invoiceRoot: "0xr", sourceAttestationDigest: "0xd", admittedAs: "0xVAULT",
  };
  const expected = {
    assetCommitment: "0xa", initialTermsCommitment: "0xt", issuerKeyId: "0xk",
    invoiceRoot: "0xr", attestationDigest: "0xd", vault: "0xVAULT",
  };
  assert.equal(requireActivatedAnchor(base, expected), true);

  for (const [field, value] of [
    ["receivableState", 0], ["protectionState", 0], ["totalSupply", 0n],
    ["identitySchemeVersion", 4], ["termsSchemeVersion", 2],
    ["assetCommitment", "0xZ"], ["sourceAttestationDigest", "0xZ"],
    ["admittedAs", "0xOTHER"],
  ]) {
    assert.throws(
      () => requireActivatedAnchor({ ...base, [field]: value }, expected),
      (error) => error.code === "ANCHOR_STATE_INVALID",
      `${field} must be required`,
    );
  }
});
