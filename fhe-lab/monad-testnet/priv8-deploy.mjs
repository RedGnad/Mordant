// M-PRIV8 deployment: the frozen V4 stack, one real tokenized receivable, and
// one independently registered non-vault source.
//
// Nothing here changes frozen Solidity. It deploys the exact artifacts compiled
// from the frozen tree, configures policy, quorum, relayer and binder, and
// leaves every configuration surface readable for the report.
//
// The two sides are deliberately asymmetric in what they publish. The vault is
// a real ERC-20 receivable with public economics, because that is what a
// tokenized receivable is. The non-vault source publishes only the five opaque
// identity fields, so before binding there is nothing public that correlates it
// with the vault.

import { getAddress, keccak256, stringToHex, parseEventLogs } from "viem";
import {
  artifact, fail, step, settle, writeAtomic,
} from "./priv8-chain.mjs";
import {
  assetCommitment, deriveSalt, namespace, normalize, Profile, IdentityTier,
  strictStableAssetId, termsCommitment, Relation,
} from "../shared/identity/asset-identity.mjs";

export const UNITS = 100_000_000n;   // 100.000000 receivable units, 6 decimals
export const ADVANCE = 100_000_000n;
export const FACE = 110_000_000n;
export const BOND_BPS = 1_000;
export const REVEAL_PERIOD = 3_600n;
export const VAULT_CURE_PERIOD = 3_600n;
export const PROTECTION_DAYS = 30n;
export const FUND_WEI = 4_000_000_000_000_000_000n;
export const IDENTITY_EPOCH = 1;

export const ARTIFACTS = Object.freeze({
  eligibility: ["MockEligibility", "MockEligibility.sol"],
  erc20: ["MockERC20", "MockERC20.sol"],
  adapter: ["MockCvaAdapter", "MockCvaAdapter.sol"],
  issuerRegistry: ["MordantIssuerRegistry", "MordantIssuerRegistry.sol"],
  factory: ["MordantFactoryV2", "MordantFactoryV2.sol"],
  vault: ["MordantInvoiceVaultV2", "MordantInvoiceVaultV2.sol"],
  sources: ["MordantSourceIdentityRegistry", "MordantSourceIdentityRegistry.sol"],
  governance: ["MordantScopeGovernanceRegistry", "MordantScopeGovernanceRegistry.sol"],
  verifier: ["ECDSAQuorumMatchVerifierV4", "ECDSAQuorumMatchVerifierV4.sol"],
  binder: ["PrivateMatchBinder", "PrivateMatchBinder.sol"],
});

export async function loadArtifacts() {
  const loaded = {};
  for (const [key, [name, path]] of Object.entries(ARTIFACTS)) loaded[key] = await artifact(name, path);
  return loaded;
}

/**
 * The single economic receivable both sides describe.
 *
 * Both platforms hold the SAME canonical identity and derive INDEPENDENT salts,
 * so their public asset commitments differ while the private strict identity is
 * identical. That asymmetry is the whole point: equality is only discoverable
 * under encryption.
 */
export function receivableIdentity(invoiceNumber = "INV-2026-0042", issueDateDays = 20_500) {
  return {
    sellerNamespace: namespace("lei"),
    sellerId: normalize(Profile.ALNUM_UPPER_FIXED, "213800WAVVOPS85N2205", 20),
    sellerProfile: Profile.ALNUM_UPPER_FIXED,
    debtorNamespace: namespace("lei"),
    debtorId: normalize(Profile.ALNUM_UPPER_FIXED, "529900T8BM49AURSDO55", 20),
    debtorProfile: Profile.ALNUM_UPPER_FIXED,
    invoiceNamespace: namespace("seller"),
    invoiceId: normalize(Profile.INVOICE_CASE_SENSITIVE, invoiceNumber, 0),
    invoiceProfile: Profile.INVOICE_CASE_SENSITIVE,
    tier: IdentityTier.StrictSellerIssued,
    issueDateDays,
  };
}

export function sideCommitments(stableId, { anchorMasterSecret, sourceMasterSecret }) {
  const anchorSalt = deriveSalt({
    issuerMasterSecret: anchorMasterSecret, stableId, identityEpoch: IDENTITY_EPOCH, anchorNonce: 1,
  });
  const sourceSalt = deriveSalt({
    issuerMasterSecret: sourceMasterSecret, stableId, identityEpoch: IDENTITY_EPOCH, anchorNonce: 1,
  });
  const anchor = assetCommitment({ stableId, identityEpoch: IDENTITY_EPOCH, salt: anchorSalt });
  const source = assetCommitment({ stableId, identityEpoch: IDENTITY_EPOCH, salt: sourceSalt });
  if (anchor === source) fail("SALTS_NOT_INDEPENDENT");
  return { anchorSalt, sourceSalt, anchorAssetCommitment: anchor, sourceAssetCommitment: source };
}

export function initialTerms(stableId, { faceValueMinor, dueDateDays, currencyCode, effectiveFrom }) {
  return termsCommitment(stableId, {
    termsVersion: 1,
    relation: Relation.Original,
    currencyCode,
    faceValueMinor,
    amountExponent: 2,
    dueDateDays,
    effectiveFrom,
  });
}

/* ------------------------------------------------------------------ deploy */

export async function deployStack(context) {
  const { client, tx, journal, journalPath, settings, art, scope, parties, validators } = context;
  const record = {};

  const deploy = async (name, art_, args) => {
    const key = `deploy:${name}`;
    const { hash, replayed } = await step(journal, journalPath, key, async () => ({
      hash: await tx.deploy(settings.deployer, art_, args), meta: { contract: name },
    }));
    const settled = await settle(journal, journalPath, key, client, hash, { contract: name });
    record[name] = { address: getAddress(settled.contractAddress), hash, block: settled.block, replayed };
    return record[name].address;
  };

  const write = async (key, account, request) => {
    const { hash } = await step(journal, journalPath, key, async () => ({
      hash: await tx.write(account, request), meta: { call: key },
    }));
    return settle(journal, journalPath, key, client, hash, { call: key });
  };

  // 0. Fund the economic role accounts that must send their own transactions.
  for (const [label, account] of [["buyer", settings.buyer], ["facility", settings.facility], ["holder", settings.holder]]) {
    const balance = await client.getBalance({ address: account.address });
    if (balance >= FUND_WEI / 2n) continue;
    const key = `fund:${label}`;
    const { hash } = await step(journal, journalPath, key, async () => ({
      hash: await tx.send(settings.deployer, { to: account.address, value: FUND_WEI - balance }),
      meta: { role: label, to: account.address },
    }));
    await settle(journal, journalPath, key, client, hash, { role: label, to: account.address });
  }

  // 1. Test-asset doubles the vault's own accounting requires.
  const eligibility = await deploy("MockEligibility", art.eligibility, []);
  const settlement = await deploy("SettlementToken", art.erc20, ["Mordant settlement (test)", "tUSD", 6]);
  const cvaToken = await deploy("ReceivableUnits", art.erc20, ["Mordant receivable units (test)", "tINV", 6]);
  const adapter = await deploy("MockCvaAdapter", art.adapter, [cvaToken]);

  // 2. Identity and governance.
  const issuerRegistry = await deploy("MordantIssuerRegistry", art.issuerRegistry, [settings.deployer.address]);
  const factory = await deploy("MordantFactoryV2", art.factory, [settings.deployer.address, eligibility, issuerRegistry]);
  const sources = await deploy("MordantSourceIdentityRegistry", art.sources, [issuerRegistry]);
  const governance = await deploy("MordantScopeGovernanceRegistry", art.governance, [settings.deployer.address]);

  // 3. The frozen V4 stack. Validators are sorted because the verifier requires
  //    strictly increasing signers and derives its set id from this exact array.
  const validatorSet = [...validators].sort((a, b) => (BigInt(a) < BigInt(b) ? -1 : 1));
  const verifier = await deploy("ECDSAQuorumMatchVerifierV4", art.verifier, [
    settings.deployer.address, governance, validatorSet, 2n,
  ]);
  const binder = await deploy("PrivateMatchBinder", art.binder, [
    verifier, governance, issuerRegistry, sources,
    scope.policyId, scope.policyVersion, scope.responsibleRole, scope.curePeriod, scope.consequenceId,
  ]);

  // 4. Configuration.
  await write("config:registerIssuer", settings.deployer, {
    address: issuerRegistry, abi: art.issuerRegistry.abi, functionName: "registerIssuer",
    args: [getAddress(parties.issuer.address), IDENTITY_EPOCH],
  });
  await write("config:setFacility", settings.deployer, {
    address: factory, abi: art.factory.abi, functionName: "setFacility", args: [settings.facility.address, true],
  });
  await write("config:setCvaAdapter", settings.deployer, {
    address: factory, abi: art.factory.abi, functionName: "setCvaAdapter", args: [adapter, true],
  });
  await write("config:setSettlementToken", settings.deployer, {
    address: factory, abi: art.factory.abi, functionName: "setSettlementToken", args: [settlement, true],
  });
  for (const [label, account, role] of [
    ["buyer", settings.buyer, 1], ["originator", settings.originator, 2],
    ["facility", settings.facility, 3], ["holder", settings.holder, 4],
  ]) {
    // The factory checks buyer and originator eligibility at admission, so the
    // roles must exist before any vault is created.
    await write(`config:eligible:${label}`, settings.deployer, {
      address: eligibility, abi: art.eligibility.abi, functionName: "setEligible",
      args: [account.address, role, true],
    });
  }
  await write("config:setPolicyVersion", settings.deployer, {
    address: verifier, abi: art.verifier.abi, functionName: "setPolicyVersion",
    args: [scope.policyId, scope.policyVersion],
  });
  await write("config:setAuthorizedRelayer", settings.deployer, {
    address: governance, abi: art.governance.abi, functionName: "setAuthorizedRelayer",
    args: [getAddress(parties.relayer.address), true],
  });
  await write("config:setAuthorizedBinder", settings.deployer, {
    address: governance, abi: art.governance.abi, functionName: "setAuthorizedBinder",
    args: [binder, true],
  });

  return {
    addresses: {
      eligibility, settlement, cvaToken, adapter, issuerRegistry, factory, sources,
      governance, verifier, binder,
    },
    validatorSet,
    deployments: record,
  };
}

/* ------------------------------------------------------- governance records */

export async function authorizeScopes(context, addresses, parties, scope) {
  const { client, tx, journal, journalPath, settings, art } = context;
  const results = {};
  const sides = [
    ["A", scope.scopeA, parties.controllerA.address, scope.controllerKeyIdA, scope.organizationA],
    ["B", scope.scopeB, parties.controllerB.address, scope.controllerKeyIdB, scope.organizationB],
  ];
  for (const [label, scopeCommitment, controller, controllerKeyId, organizationId] of sides) {
    const key = `governance:authorize${label}`;
    const request = {
      address: addresses.governance, abi: art.governance.abi, functionName: "authorize",
      args: [{
        scopeCommitment, controller: getAddress(controller), controllerKeyId, organizationId,
        controllerEpoch: 1, authorizationVersion: 1, nonce: label === "A" ? 1n : 2n,
      }],
    };
    const { hash } = await step(journal, journalPath, key, async () => ({
      hash: await tx.write(settings.deployer, request), meta: { call: key },
    }));
    const settled = await settle(journal, journalPath, key, client, hash, { call: key });
    const receipt = await client.getTransactionReceipt({ hash });
    const [event] = parseEventLogs({ abi: art.governance.abi, eventName: "ScopeAuthorized", logs: receipt.logs });
    if (!event) fail("GOVERNANCE_RECORD_MISSING", label);
    results[label] = {
      recordDigest: event.args.recordDigest,
      scopeCommitment: event.args.scopeCommitment,
      controller: getAddress(event.args.controller),
      organizationId: event.args.organizationId,
      controllerEpoch: Number(event.args.controllerEpoch),
      authorizationVersion: Number(event.args.authorizationVersion),
      validFrom: Number(event.args.validFrom),
      block: settled.block,
      hash,
    };
  }
  if (results.A.recordDigest === results.B.recordDigest) fail("GOVERNANCE_RECORDS_IDENTICAL");
  if (results.A.organizationId === results.B.organizationId) fail("GOVERNANCE_SAME_ORGANIZATION");
  return results;
}

/* --------------------------------------------------------------- the anchor */

export function vaultConfig(addresses, settings, invoiceRoot, protectionEnd) {
  return {
    cvaAdapter: addresses.adapter,
    settlementToken: addresses.settlement,
    invoiceRoot,
    currency: stringToHex("USD", { size: 32 }),
    buyer: settings.buyer.address,
    originatorTreasury: settings.originator.address,
    initialOriginatorSigner: settings.originator.address,
    initialUnits: UNITS,
    advanceAmount: ADVANCE,
    faceValue: FACE,
    bondBps: BOND_BPS,
    protectionEnd,
    revealPeriod: REVEAL_PERIOD,
    curePeriod: VAULT_CURE_PERIOD,
  };
}

export async function deployAnchor(context, addresses, identity, signSource) {
  const { client, tx, journal, journalPath, settings, art } = context;
  const invoiceRoot = keccak256(stringToHex("mordant.priv8.receivable/1"));

  // On resume the anchor already exists. Read it back off the chain rather than
  // rebuilding an attestation and asking the issuer to sign something that will
  // never be sent.
  if (journal.steps["anchor:create"]?.status === "success") {
    return anchorFromChain(context, addresses, journal.steps["anchor:create"].hash, invoiceRoot);
  }
  const latest = await client.getBlock();
  const protectionEnd = BigInt(latest.timestamp) + PROTECTION_DAYS * 86_400n;
  const config = vaultConfig(addresses, settings, invoiceRoot, protectionEnd);

  const creationDigest = await client.readContract({
    address: addresses.factory, abi: art.factory.abi, functionName: "creationDigest", args: [config],
  });

  // The issuer signs the anchor's identity BEFORE the anchor exists. Its own
  // process recomputes the digest; this runner never holds the issuer key.
  const attestation = {
    chainId: BigInt(context.chainId),
    factory: addresses.factory,
    creationDigest,
    assetCommitment: identity.anchorAssetCommitment,
    initialTermsCommitment: identity.anchorTermsCommitment,
    identitySchemeVersion: 3,
    termsSchemeVersion: 1,
    identityEpoch: IDENTITY_EPOCH,
    issuerKeyId: identity.issuerKeyId,
    invoiceRoot,
    controller: settings.originator.address,
    validUntil: BigInt(latest.timestamp) + 86_400n,
    nonce: 1n,
  };
  const signature = await signSource(attestation, addresses.factory);

  const createKey = "anchor:create";
  const { hash } = await step(journal, journalPath, createKey, async () => ({
    hash: await tx.write(settings.buyer, {
      address: addresses.factory, abi: art.factory.abi, functionName: "createIdentityAnchoredVault",
      args: [config, attestation, signature],
    }),
    meta: { call: createKey },
  }));
  const created = await settle(journal, journalPath, createKey, client, hash, { call: createKey });
  const receipt = await client.getTransactionReceipt({ hash });
  const [event] = parseEventLogs({
    abi: art.factory.abi, eventName: "IdentityAnchoredVaultCreated", logs: receipt.logs,
  });
  if (!event) fail("ANCHOR_VAULT_MISSING");
  const vault = getAddress(event.args.vault);

  return {
    vault, invoiceRoot, protectionEnd, config, attestation, creationDigest,
    sourceAttestationDigest: event.args.sourceAttestationDigest,
    publishedAssetCommitment: event.args.assetCommitment,
    block: created.block, hash,
  };
}

export async function anchorFromChain(context, addresses, hash, invoiceRoot) {
  const { client, art } = context;
  const receipt = await client.getTransactionReceipt({ hash });
  const [event] = parseEventLogs({
    abi: art.factory.abi, eventName: "IdentityAnchoredVaultCreated", logs: receipt.logs,
  });
  if (!event) fail("ANCHOR_VAULT_MISSING");
  const vault = getAddress(event.args.vault);
  return {
    vault,
    invoiceRoot: event.args.invoiceRoot ?? invoiceRoot,
    protectionEnd: null,
    config: null,
    attestation: null,
    creationDigest: null,
    sourceAttestationDigest: await client.readContract({
      address: vault, abi: art.vault.abi, functionName: "sourceAttestationDigest",
    }),
    publishedAssetCommitment: await client.readContract({
      address: vault, abi: art.vault.abi, functionName: "assetCommitment",
    }),
    block: String(receipt.blockNumber),
    hash,
    resumed: true,
  };
}

export async function activateAnchor(context, addresses, anchor) {
  const { client, tx, journal, journalPath, settings, art } = context;
  const write = async (key, account, request) => {
    const { hash } = await step(journal, journalPath, key, async () => ({
      hash: await tx.write(account, request), meta: { call: key },
    }));
    return settle(journal, journalPath, key, client, hash, { call: key });
  };

  if (journal.steps["anchor:activate"]?.status === "success") {
    return { pledge: null, pledgeDigest: null, resumed: true };
  }
  await write("anchor:identityValid", settings.deployer, {
    address: addresses.eligibility, abi: art.eligibility.abi, functionName: "setIdentityValid",
    args: [anchor.vault, true],
  });

  // Credit the vault with its receivable units through the adapter, exactly as
  // the vault's own accounting requires.
  await write("anchor:mintUnits", settings.deployer, {
    address: addresses.cvaToken, abi: art.erc20.abi, functionName: "mint",
    args: [settings.deployer.address, UNITS],
  });
  await write("anchor:approveAdapter", settings.deployer, {
    address: addresses.cvaToken, abi: art.erc20.abi, functionName: "approve",
    args: [addresses.adapter, UNITS],
  });
  await write("anchor:creditVault", settings.deployer, {
    address: addresses.adapter, abi: art.adapter.abi, functionName: "creditVault",
    args: [anchor.vault, UNITS],
  });
  await write("anchor:mintSettlement", settings.deployer, {
    address: addresses.settlement, abi: art.erc20.abi, functionName: "mint",
    args: [settings.holder.address, ADVANCE],
  });
  await write("anchor:approveVault", settings.holder, {
    address: addresses.settlement, abi: art.erc20.abi, functionName: "approve",
    args: [anchor.vault, ADVANCE],
  });

  const latest = await client.getBlock();
  const pledge = {
    invoiceRoot: anchor.invoiceRoot,
    originatorSigner: settings.originator.address,
    facility: settings.facility.address,
    obligationId: keccak256(stringToHex("mordant.priv8.obligation/1")),
    amount: FACE,
    currency: stringToHex("USD", { size: 32 }),
    activeFrom: BigInt(latest.timestamp) - 60n,
    activeUntil: anchor.protectionEnd + 1n,
    nonce: 1n,
    deadline: BigInt(latest.timestamp) + 2n * 86_400n,
    exclusive: true,
  };
  const pledgeDigest = await client.readContract({
    address: anchor.vault, abi: art.vault.abi, functionName: "hashPledge", args: [pledge],
  });
  const signature = await settings.originator.sign({ hash: pledgeDigest });

  await write("anchor:activate", settings.facility, {
    address: anchor.vault, abi: art.vault.abi, functionName: "activate",
    args: [pledge, signature, settings.holder.address, [settings.holder.address], [UNITS]],
  });

  return { pledge, pledgeDigest };
}

/* ------------------------------------------------------- the non-vault source */

export async function registerSource(context, addresses, identity, signSource) {
  const { client, tx, journal, journalPath, settings, art } = context;
  if (journal.steps["source:register"]?.status === "success") {
    const hash = journal.steps["source:register"].hash;
    const receipt = await client.getTransactionReceipt({ hash });
    const [event] = parseEventLogs({
      abi: art.sources.abi, eventName: "SourceIdentityRegistered", logs: receipt.logs,
    });
    if (!event) fail("SOURCE_REGISTRATION_MISSING");
    return { anchorId: event.args.anchorId, attestation: null, hash, block: String(receipt.blockNumber), resumed: true };
  }
  const latest = await client.getBlock();
  const attestation = {
    chainId: BigInt(context.chainId),
    factory: addresses.sources,
    // A non-vault source has no creation parameters, so it commits to its own
    // facility reference instead. It publishes no economics at all.
    creationDigest: keccak256(stringToHex("mordant.priv8.non-vault-source/1")),
    assetCommitment: identity.sourceAssetCommitment,
    initialTermsCommitment: identity.sourceTermsCommitment,
    identitySchemeVersion: 3,
    termsSchemeVersion: 1,
    identityEpoch: IDENTITY_EPOCH,
    issuerKeyId: identity.issuerKeyId,
    invoiceRoot: keccak256(stringToHex("mordant.priv8.non-vault-source.reference/1")),
    controller: settings.originator.address,
    validUntil: BigInt(latest.timestamp) + 86_400n,
    nonce: 2n,
  };
  const signature = await signSource(attestation, addresses.sources);

  const key = "source:register";
  const { hash } = await step(journal, journalPath, key, async () => ({
    hash: await tx.write(settings.deployer, {
      address: addresses.sources, abi: art.sources.abi, functionName: "register",
      args: [attestation, signature],
    }),
    meta: { call: key },
  }));
  const settled = await settle(journal, journalPath, key, client, hash, { call: key });
  const receipt = await client.getTransactionReceipt({ hash });
  const [event] = parseEventLogs({ abi: art.sources.abi, eventName: "SourceIdentityRegistered", logs: receipt.logs });
  if (!event) fail("SOURCE_REGISTRATION_MISSING");
  return { anchorId: event.args.anchorId, attestation, hash, block: settled.block };
}

export { strictStableAssetId, writeAtomic };
