import {
  bytecodeContainsSelector,
  describeRevertSelector,
  observeDeployedCode,
  observeViewCall,
  type OnchainObservation,
  type PinnedBlock,
} from "./observe";
import {
  CLEANVERSE_DOCUMENTATION_PAGE_TITLE,
  CLEANVERSE_DOCUMENTATION_VERSION,
  CLEANVERSE_DOCUMENTATION_VERSION_SOURCE,
  CLEANVERSE_V56_FACTS,
} from "./documentation-v56";
import {
  DOC_DEPLOYMENT_SKEW,
  UNSTATED_VERSION,
  type Comparison,
  type Conclusion,
  type DocumentationRecord,
  type MissingEvidence,
} from "./report";
import type { RpcTransport } from "./rpc";

export const MONAD_TESTNET_CHAIN_ID = 10_143 as const;
export const MONAD_TESTNET_NAME = "monad-testnet" as const;

/**
 * Addresses are not authority: they are re-verified on chain at the pinned block on every run.
 * The defaults mirror the unauthenticated `GET /api/skills/query_chain_config` response.
 */
export type CleanverseMonadTargets = Readonly<{
  apass: string;
  aUsdc: string;
  usdc: string;
  accessCore: string;
  depositGateway: string;
  aTokenFactoryProxy: string;
  /** Optional: only set once a Mordant vault is actually deployed. */
  mordantVault: string | null;
}>;

export const DEFAULT_CLEANVERSE_MONAD_TARGETS: CleanverseMonadTargets = Object.freeze({
  apass: "0xbA82D189540CaC9DC6FF46B6837CaC1BFdEC58B9",
  aUsdc: "0xaC0893567D43C3E7e6e35a72803df05416C1f20D",
  usdc: "0x534b2f3A21130d7a60830c2Df862319e593943A3",
  accessCore: "0x8F118338a1fa41E7Fa86Be19A4e8B99Ed58A6EcC",
  depositGateway: "0x8e084646080a35347B2D053Dd72F550f12245c8B",
  aTokenFactoryProxy: "0xd1ad67ca3b7da5934813f4bd005812ebb3b43ff6",
  mordantVault: null,
});

/**
 * Launch selectors observed on the shared A-Token factory proxy. The ten-argument selector is the
 * one an official Base launch uses; the eight-argument selector is the older surface.
 */
export const ATOKEN_LAUNCH_SELECTOR_TEN_ARG = "0xeff21872" as const;
export const ATOKEN_LAUNCH_SELECTOR_EIGHT_ARG = "0xef84b94a" as const;
export const ERC20_MINT_SELECTOR = "0x40c10f19" as const;
export const ERC20_BURN_SELECTOR = "0x9dc29fac" as const;

/**
 * Addresses probed against `isValidAPass` to show the credential check discriminates.
 * Kept lowercase: a mixed-case literal is validated as an EIP-55 checksum and would be rejected
 * before it ever reaches the RPC.
 */
const APASS_PROBE_ADDRESSES: readonly string[] = Object.freeze([
  "0x0000000000000000000000000000000000000000",
  "0x000000000000000000000000000000000000dead",
  "0x00000000000000000000000000000000deadbeef",
]);

export type CleanverseMonadFacts = Readonly<{
  apassHasCode: boolean;
  apassImplementation: string | null;
  aUsdcHasCode: boolean;
  aUsdcImplementation: string | null;
  aUsdcDecimals: string | null;
  aUsdcPolicy: string | null;
  aUsdcMinterRole: string | null;
  aUsdcTotalSupply: string | null;
  aUsdcHasRoleSurface: boolean;
  aUsdcBalanceOfSurface: boolean;
  aUsdcMintSelectorPresent: boolean | null;
  aUsdcBurnSelectorPresent: boolean | null;
  policyHasCode: boolean | null;
  policyCanTransferAnswered: boolean | null;
  /** Custom-error selector the policy reverted with, when it never returned a boolean. */
  policyRevertSelector: string | null;
  factoryHasCode: boolean;
  factoryImplementation: string | null;
  factoryTenArgLaunchSelectorPresent: boolean | null;
  factoryEightArgLaunchSelectorPresent: boolean | null;
  apassDiscriminates: boolean;
  mordantVaultHasCode: boolean | null;
}>;

export type CleanverseMonadObservations = Readonly<{
  observations: readonly OnchainObservation[];
  facts: CleanverseMonadFacts;
}>;

function record(
  block: PinnedBlock,
  address: string,
  callOrSelector: string,
  result: string,
  options: Readonly<{ implementation?: string | null; codeHash?: string | null }> = {},
): OnchainObservation {
  return Object.freeze({
    network: block.network,
    chainId: block.chainId,
    blockNumber: block.blockNumber.toString(),
    blockHash: block.blockHash,
    address,
    implementation: options.implementation ?? null,
    codeHash: options.codeHash ?? null,
    callOrSelector,
    result,
    // Everything this module produces comes from eth_call / eth_getCode / eth_getStorageAt.
    classification: "READ-ONLY",
  });
}

/**
 * Runs the complete read-only observation plan at one pinned block.
 * The caller must have gated the chain id first.
 */
export async function collectCleanverseMonadObservations(
  client: RpcTransport,
  targets: CleanverseMonadTargets,
  block: PinnedBlock,
): Promise<CleanverseMonadObservations> {
  const observations: OnchainObservation[] = [];

  const codeTargets: readonly (readonly [string, string])[] = [
    ["A-Pass", targets.apass],
    ["aUSDC", targets.aUsdc],
    ["USDC", targets.usdc],
    ["AccessCore", targets.accessCore],
    ["deposit gateway", targets.depositGateway],
    ["A-Token factory proxy", targets.aTokenFactoryProxy],
  ];

  const codeByLabel = new Map<string, Awaited<ReturnType<typeof observeDeployedCode>>>();
  for (const [label, address] of codeTargets) {
    const code = await observeDeployedCode(client, address, block);
    codeByLabel.set(label, code);
    observations.push(record(
      block,
      address,
      "eth_getCode + EIP-1967 implementation slot",
      code.hasBytecode
        ? `${label}: ${code.byteLength} bytes of bytecode`
          + (code.implementation === null ? ", not an EIP-1967 proxy" : ", EIP-1967 proxy")
        : `${label}: NO BYTECODE at this address`,
      { implementation: code.implementation, codeHash: code.codeHash },
    ));
  }

  const apassCode = codeByLabel.get("A-Pass");
  const aUsdcCode = codeByLabel.get("aUSDC");
  const factoryCode = codeByLabel.get("A-Token factory proxy");

  // --- A-Pass credential surface -------------------------------------------------------------
  const apassProbes: { address: string; value: string; ok: boolean }[] = [];
  if (apassCode?.hasBytecode === true) {
    for (const probe of APASS_PROBE_ADDRESSES) {
      const outcome = await observeViewCall(
        client,
        targets.apass,
        "isValidAPass(address) view returns (bool)",
        [probe],
        block,
      );
      apassProbes.push({ address: probe, value: outcome.value, ok: outcome.ok });
      observations.push(record(
        block,
        targets.apass,
        `isValidAPass(${probe})`,
        outcome.ok ? outcome.value : outcome.value,
        { implementation: apassCode.implementation },
      ));
    }
  }
  const apassDiscriminates = apassProbes.some((probe) => probe.value === "false")
    && apassProbes.every((probe) => probe.ok);

  // --- aUSDC token surface -------------------------------------------------------------------
  let aUsdcDecimals: string | null = null;
  let aUsdcPolicy: string | null = null;
  let aUsdcMinterRole: string | null = null;
  let aUsdcTotalSupply: string | null = null;
  let aUsdcHasRoleSurface = false;
  let aUsdcBalanceOfSurface = false;

  if (aUsdcCode?.hasBytecode === true) {
    const decimals = await observeViewCall(client, targets.aUsdc, "decimals() view returns (uint8)", [], block);
    aUsdcDecimals = decimals.ok ? decimals.value : null;
    observations.push(record(block, targets.aUsdc, "decimals()", decimals.value, {
      implementation: aUsdcCode.implementation,
    }));

    const policy = await observeViewCall(client, targets.aUsdc, "policy() view returns (address)", [], block);
    aUsdcPolicy = policy.ok ? policy.value : null;
    observations.push(record(block, targets.aUsdc, "policy()", policy.value, {
      implementation: aUsdcCode.implementation,
    }));

    const minterRole = await observeViewCall(client, targets.aUsdc, "MINTER_ROLE() view returns (bytes32)", [], block);
    aUsdcMinterRole = minterRole.ok ? minterRole.value : null;
    observations.push(record(block, targets.aUsdc, "MINTER_ROLE()", minterRole.value));

    const totalSupply = await observeViewCall(client, targets.aUsdc, "totalSupply() view returns (uint256)", [], block);
    aUsdcTotalSupply = totalSupply.ok ? totalSupply.value : null;
    observations.push(record(block, targets.aUsdc, "totalSupply()", totalSupply.value));

    const balanceOf = await observeViewCall(
      client,
      targets.aUsdc,
      "balanceOf(address) view returns (uint256)",
      [targets.accessCore],
      block,
    );
    aUsdcBalanceOfSurface = balanceOf.ok;
    observations.push(record(block, targets.aUsdc, `balanceOf(${targets.accessCore})`, balanceOf.value));

    if (aUsdcMinterRole !== null) {
      const hasRole = await observeViewCall(
        client,
        targets.aUsdc,
        "hasRole(bytes32,address) view returns (bool)",
        [aUsdcMinterRole, targets.accessCore],
        block,
      );
      aUsdcHasRoleSurface = hasRole.ok;
      observations.push(record(
        block,
        targets.aUsdc,
        `hasRole(MINTER_ROLE, ${targets.accessCore})`,
        hasRole.value,
      ));
    }
  }

  const aUsdcImplementationCode = aUsdcCode?.implementationCode ?? null;
  const aUsdcMintSelectorPresent = aUsdcImplementationCode === null
    ? null
    : bytecodeContainsSelector(aUsdcImplementationCode, ERC20_MINT_SELECTOR);
  const aUsdcBurnSelectorPresent = aUsdcImplementationCode === null
    ? null
    : bytecodeContainsSelector(aUsdcImplementationCode, ERC20_BURN_SELECTOR);
  if (aUsdcImplementationCode !== null) {
    observations.push(record(
      block,
      aUsdcCode?.implementation ?? targets.aUsdc,
      `bytecode selector scan ${ERC20_MINT_SELECTOR} mint(address,uint256) / ${ERC20_BURN_SELECTOR} burn(address,uint256)`,
      `mint ${aUsdcMintSelectorPresent === true ? "PRESENT" : "ABSENT"},`
        + ` burn ${aUsdcBurnSelectorPresent === true ? "PRESENT" : "ABSENT"}`
        + ` (dispatch-table scan, not a callability proof)`,
      { codeHash: aUsdcCode?.implementationCodeHash ?? null },
    ));
  }

  // --- transfer policy surface ---------------------------------------------------------------
  let policyHasCode: boolean | null = null;
  let policyCanTransferAnswered: boolean | null = null;
  let policyRevertSelector: string | null = null;
  if (aUsdcPolicy !== null) {
    const policyCode = await observeDeployedCode(client, aUsdcPolicy, block);
    policyHasCode = policyCode.hasBytecode;
    observations.push(record(
      block,
      aUsdcPolicy,
      "eth_getCode (aUSDC policy contract)",
      policyCode.hasBytecode
        ? `${policyCode.byteLength} bytes of bytecode`
        : "NO BYTECODE at the policy address",
      { implementation: policyCode.implementation, codeHash: policyCode.codeHash },
    ));

    if (policyCode.hasBytecode) {
      // Several tuples, including two addresses that hold a valid A-Pass. One rejected tuple
      // proves nothing; a surface that never returns a boolean is a different fact entirely.
      const tuples: readonly (readonly [string, string, string])[] = [
        ["AccessCore", targets.accessCore, targets.depositGateway],
        ["A-Pass holder to A-Pass holder", APASS_PROBE_ADDRESSES[1], targets.accessCore],
        ["A-Pass holder to itself", APASS_PROBE_ADDRESSES[1], APASS_PROBE_ADDRESSES[1]],
      ];

      policyCanTransferAnswered = false;
      for (const [label, from, to] of tuples) {
        const canTransfer = await observeViewCall(
          client,
          aUsdcPolicy,
          "canTransfer(address,address,address,uint256) view returns (bool)",
          [targets.aUsdc, from, to, 1n],
          block,
        );
        if (canTransfer.ok) {
          policyCanTransferAnswered = true;
        } else if (policyRevertSelector === null) {
          policyRevertSelector = canTransfer.revertSelector;
        }
        observations.push(record(
          block,
          aUsdcPolicy,
          `canTransfer(aUSDC, ${from}, ${to}, 1) [${label}]`,
          canTransfer.ok ? `answered ${canTransfer.value}` : canTransfer.value,
        ));
      }
    }
  }

  // --- A-Token factory surface ---------------------------------------------------------------
  const factoryImplementationCode = factoryCode?.implementationCode ?? null;
  const factoryTenArg = factoryImplementationCode === null
    ? null
    : bytecodeContainsSelector(factoryImplementationCode, ATOKEN_LAUNCH_SELECTOR_TEN_ARG);
  const factoryEightArg = factoryImplementationCode === null
    ? null
    : bytecodeContainsSelector(factoryImplementationCode, ATOKEN_LAUNCH_SELECTOR_EIGHT_ARG);
  if (factoryImplementationCode !== null) {
    observations.push(record(
      block,
      factoryCode?.implementation ?? targets.aTokenFactoryProxy,
      `bytecode selector scan ${ATOKEN_LAUNCH_SELECTOR_TEN_ARG} / ${ATOKEN_LAUNCH_SELECTOR_EIGHT_ARG}`,
      `${ATOKEN_LAUNCH_SELECTOR_TEN_ARG} ${factoryTenArg === true ? "PRESENT" : "ABSENT"},`
        + ` ${ATOKEN_LAUNCH_SELECTOR_EIGHT_ARG} ${factoryEightArg === true ? "PRESENT" : "ABSENT"}`
        + ` (dispatch-table scan, not a callability proof)`,
      { codeHash: factoryCode?.implementationCodeHash ?? null },
    ));
  }

  // --- Mordant vault -------------------------------------------------------------------------
  let mordantVaultHasCode: boolean | null = null;
  if (targets.mordantVault !== null) {
    const vaultCode = await observeDeployedCode(client, targets.mordantVault, block);
    mordantVaultHasCode = vaultCode.hasBytecode;
    observations.push(record(
      block,
      targets.mordantVault,
      "eth_getCode (Mordant invoice vault)",
      vaultCode.hasBytecode
        ? `${vaultCode.byteLength} bytes of bytecode`
        : "NO BYTECODE at the configured vault address",
      { codeHash: vaultCode.codeHash },
    ));
  }

  return Object.freeze({
    observations: Object.freeze(observations),
    facts: Object.freeze({
      apassHasCode: apassCode?.hasBytecode ?? false,
      apassImplementation: apassCode?.implementation ?? null,
      aUsdcHasCode: aUsdcCode?.hasBytecode ?? false,
      aUsdcImplementation: aUsdcCode?.implementation ?? null,
      aUsdcDecimals,
      aUsdcPolicy,
      aUsdcMinterRole,
      aUsdcTotalSupply,
      aUsdcHasRoleSurface,
      aUsdcBalanceOfSurface,
      aUsdcMintSelectorPresent,
      aUsdcBurnSelectorPresent,
      policyHasCode,
      policyCanTransferAnswered,
      policyRevertSelector,
      factoryHasCode: factoryCode?.hasBytecode ?? false,
      factoryImplementation: factoryCode?.implementation ?? null,
      factoryTenArgLaunchSelectorPresent: factoryTenArg,
      factoryEightArgLaunchSelectorPresent: factoryEightArg,
      apassDiscriminates,
      mordantVaultHasCode,
    }),
  });
}

/**
 * The protected Cleanverse documentation is the only authority for these topics. Without the
 * session access code they stay unproven; a repository note is explicitly not a substitute.
 */
export const PROTECTED_DOCUMENTATION_UNAVAILABLE =
  "NOT PROVEN — OFFICIAL DOCUMENTATION UNAVAILABLE" as const;

export type DocumentationAvailability = Readonly<{
  protectedDocsReachable: boolean;
  protectedDocsHttpStatus: number | null;
  chainConfigReachable: boolean;
  consultedAt: string;
  /**
   * ISO date on which an operator actually read the access-gated documentation. Only when this
   * is set may the recorded v5.6 facts be emitted as a documented side. Never inferred from an
   * HTTP status, because an unauthenticated probe can only ever prove the gate exists.
   */
  protectedDocsConsultedAt?: string | null;
}>;

export function buildDocumentationRecords(
  availability: DocumentationAvailability,
  targets: CleanverseMonadTargets,
): readonly DocumentationRecord[] {
  const records: DocumentationRecord[] = [];

  records.push({
    pageTitle: availability.chainConfigReachable
      ? "Cleanverse public chain configuration (unauthenticated)"
      : "Cleanverse public chain configuration (unreachable)",
    pagePath: "GET /api/skills/query_chain_config",
    documentationVersion: UNSTATED_VERSION,
    documentationVersionSource: availability.chainConfigReachable
      ? "The response body carries no version field"
      : "Endpoint not reachable during this run",
    consultedAt: availability.consultedAt,
    network: MONAD_TESTNET_NAME,
    topic: "Monad chain id and contract configuration",
    documentedAbiOrEndpoint: availability.chainConfigReachable
      ? `chain_id 10143, apass_address ${targets.apass}, aUSDC ${targets.aUsdc},`
        + ` access_core ${targets.accessCore}, deposit_gateway ${targets.depositGateway}`
      : "not retrieved",
    documentedBehavior: availability.chainConfigReachable
      ? "Publishes the canonical Monad testnet addresses and six-decimal aUSDC"
      : "Unknown",
    limitations: "Unauthenticated endpoint. It states no documentation version and does not"
      + " describe ABIs, lifecycle rules or gateway acceptance.",
  });

  const consultedAt = availability.protectedDocsConsultedAt ?? null;

  if (consultedAt !== null) {
    for (const fact of CLEANVERSE_V56_FACTS) {
      records.push({
        pageTitle: CLEANVERSE_DOCUMENTATION_PAGE_TITLE,
        pagePath: fact.pagePath,
        documentationVersion: CLEANVERSE_DOCUMENTATION_VERSION,
        documentationVersionSource: CLEANVERSE_DOCUMENTATION_VERSION_SOURCE,
        consultedAt,
        network: MONAD_TESTNET_NAME,
        topic: fact.topic,
        documentedAbiOrEndpoint: fact.documentedAbiOrEndpoint,
        documentedBehavior: fact.documentedBehavior,
        limitations: fact.limitations,
      });
    }
    return Object.freeze(records);
  }

  for (const fact of CLEANVERSE_V56_FACTS) {
    records.push({
      pageTitle: "Cleanverse protected API documentation",
      pagePath: fact.pagePath,
      documentationVersion: PROTECTED_DOCUMENTATION_UNAVAILABLE,
      documentationVersionSource: availability.protectedDocsHttpStatus === null
        ? "Not requested: no session access code was available to this run"
        : `Request returned HTTP ${availability.protectedDocsHttpStatus} without a session access code`,
      consultedAt: availability.consultedAt,
      network: MONAD_TESTNET_NAME,
      topic: fact.topic,
      documentedAbiOrEndpoint: PROTECTED_DOCUMENTATION_UNAVAILABLE,
      documentedBehavior: PROTECTED_DOCUMENTATION_UNAVAILABLE,
      limitations: "The access-gated page could not be read during this run. No repository note"
        + " was substituted for it.",
    });
  }

  return Object.freeze(records);
}

/** A prior recorded in the repository. Explicitly not official documentation. */
export type RepositoryRecord = Readonly<{
  topic: string;
  source: string;
  recordedBehavior: string;
}>;

export const REPOSITORY_RECORDS: readonly RepositoryRecord[] = Object.freeze([
  {
    topic: "Monad A-Token factory implementation",
    source: "docs/cleanverse-integration.md (recorded 27 July 2026)",
    recordedBehavior: "Monad proxy points to implementation 0x31759eff15291a5e36bb5625b55c49107dc0ee71,"
      + " which lacks selector 0xeff21872 and exposes only the eight-argument 0xef84b94a",
  },
]);

const RECORDED_MONAD_FACTORY_IMPLEMENTATION = "0x31759eff15291a5e36bb5625b55c49107dc0ee71";

/**
 * Resolves the documented side of a comparison. When the access-gated page was not read, the
 * documented side stays explicitly unavailable rather than falling back to a repository note.
 */
function documentedSide(
  topic: string,
  docsRead: boolean,
): Readonly<{ version: string; behavior: string }> {
  if (!docsRead) {
    return {
      version: PROTECTED_DOCUMENTATION_UNAVAILABLE,
      behavior: PROTECTED_DOCUMENTATION_UNAVAILABLE,
    };
  }
  const fact = CLEANVERSE_V56_FACTS.find((candidate) => candidate.topic === topic);
  return fact === undefined
    ? { version: CLEANVERSE_DOCUMENTATION_VERSION, behavior: "Topic not covered by the page" }
    : {
        version: CLEANVERSE_DOCUMENTATION_VERSION,
        behavior: `${fact.documentedBehavior} LIMITS: ${fact.limitations}`,
      };
}

export function buildCleanverseMonadComparisons(
  facts: CleanverseMonadFacts,
  targets: CleanverseMonadTargets,
  block: PinnedBlock,
  docsRead = false,
): readonly Comparison[] {
  const observedBlock = block.blockNumber.toString();
  const comparisons: Comparison[] = [];
  const apassDoc = documentedSide("A-Pass support for smart-contract addresses", docsRead);
  const rolesDoc = documentedSide("Mint and burn role semantics on issued A-Tokens", docsRead);
  const policyDoc = documentedSide("Custody and transfer policy", docsRead);
  const launchDoc = documentedSide("A-Token launch and factory ABI", docsRead);
  const cviDoc = documentedSide("CVI / A-Pass issuance and expiry", docsRead);

  comparisons.push({
    topic: "Monad chain id and canonical addresses",
    documentedNetwork: MONAD_TESTNET_NAME,
    documentedVersion: UNSTATED_VERSION,
    documentedSignatureOrBehavior:
      `chain_id ${MONAD_TESTNET_CHAIN_ID}, A-Pass ${targets.apass}, aUSDC ${targets.aUsdc}`,
    observedNetwork: MONAD_TESTNET_NAME,
    observedBlock,
    observedAddress: `${targets.apass}, ${targets.aUsdc}`,
    observedImplementation: facts.aUsdcImplementation,
    observedSignatureOrBehavior: facts.apassHasCode && facts.aUsdcHasCode
      ? `chain id ${block.chainId} confirmed by the RPC; both addresses carry bytecode`
      : "at least one canonical address carries no bytecode",
    comparisonStatus: facts.apassHasCode && facts.aUsdcHasCode ? "MATCH" : "BLOCKED",
    impactOnMordant: "Settlement token and credential contract addresses can be discovered and"
      + " verified before any deployment.",
    smallestSponsorQuestion: "None for this surface.",
  });

  comparisons.push({
    topic: "aUSDC six-decimal scale",
    documentedNetwork: MONAD_TESTNET_NAME,
    documentedVersion: UNSTATED_VERSION,
    documentedSignatureOrBehavior: "chain config publishes decimals 6 for aUSDC",
    observedNetwork: MONAD_TESTNET_NAME,
    observedBlock,
    observedAddress: targets.aUsdc,
    observedImplementation: facts.aUsdcImplementation,
    observedSignatureOrBehavior: facts.aUsdcDecimals === null
      ? "decimals() did not answer"
      : `decimals() returned ${facts.aUsdcDecimals}`,
    comparisonStatus: facts.aUsdcDecimals === "6" ? "MATCH" : "NOT PROVEN",
    impactOnMordant: "Mordant receipts and face values share the settlement token's six-decimal"
      + " base unit; a different scale would invalidate every amount in the vault.",
    smallestSponsorQuestion: "None for this surface.",
  });

  comparisons.push({
    topic: "A-Pass isValidAPass(address) credential surface",
    documentedNetwork: MONAD_TESTNET_NAME,
    documentedVersion: cviDoc.version,
    documentedSignatureOrBehavior: cviDoc.behavior,
    observedNetwork: MONAD_TESTNET_NAME,
    observedBlock,
    observedAddress: targets.apass,
    observedImplementation: facts.apassImplementation,
    observedSignatureOrBehavior: facts.apassDiscriminates
      ? "isValidAPass(address) answers and returns false for addresses without a record"
      : "isValidAPass(address) did not produce a discriminating answer",
    // The deployed surface answers, but its documented contract cannot be read this run, so the
    // pair can never reach MATCH here.
    comparisonStatus: facts.apassDiscriminates ? "NOT PROVEN" : "BLOCKED",
    impactOnMordant: "CleanverseAPassVerifier depends on this exact selector and on a false answer"
      + " for absent records. The deployment behaves that way; the documented guarantee is unread.",
    smallestSponsorQuestion: "Which documentation page and version defines isValidAPass(address)"
      + " and its behavior for expired or absent records on Monad?",
  });

  comparisons.push({
    topic: "aUSDC role-gated mint and burn surface",
    documentedNetwork: MONAD_TESTNET_NAME,
    documentedVersion: rolesDoc.version,
    documentedSignatureOrBehavior: rolesDoc.behavior,
    observedNetwork: MONAD_TESTNET_NAME,
    observedBlock,
    observedAddress: targets.aUsdc,
    observedImplementation: facts.aUsdcImplementation,
    observedSignatureOrBehavior:
      `MINTER_ROLE() ${facts.aUsdcMinterRole === null ? "absent" : "present"},`
      + ` hasRole(bytes32,address) ${facts.aUsdcHasRoleSurface ? "answers" : "does not answer"},`
      + ` mint selector ${facts.aUsdcMintSelectorPresent === true ? "present" : "absent"},`
      + ` burn selector ${facts.aUsdcBurnSelectorPresent === true ? "present" : "absent"}`,
    comparisonStatus: "NOT PROVEN",
    impactOnMordant: "CleanverseCvaAdapter assumes the issued invoice A-Token exposes the same"
      + " MINTER_ROLE-gated mint/burn surface proven here for the deployed aUSDC.",
    smallestSponsorQuestion: "On a standard A-Token created by /atoken/launch, does MINTER_ROLE"
      + " authorize both mint(address,uint256) and burn(address,uint256) as it does on aUSDC?",
  });

  comparisons.push({
    topic: "Transfer policy canTransfer(address,address,address,uint256)",
    documentedNetwork: MONAD_TESTNET_NAME,
    documentedVersion: policyDoc.version,
    documentedSignatureOrBehavior: policyDoc.behavior,
    observedNetwork: MONAD_TESTNET_NAME,
    observedBlock,
    observedAddress: facts.aUsdcPolicy ?? "unresolved",
    observedImplementation: null,
    observedSignatureOrBehavior: facts.policyCanTransferAnswered === true
      ? "the policy contract answers the four-argument canTransfer probe with a boolean"
      : `the probed tuples were rejected with`
        + ` ${describeRevertSelector(facts.policyRevertSelector)}, which is consistent with a`
        + ` compliance rule that is not satisfied by those participants`,
    comparisonStatus: facts.policyCanTransferAnswered === true ? "NOT PROVEN" : "BLOCKED",
    impactOnMordant: facts.policyCanTransferAnswered === true
      ? "Every outgoing settlement transfer is prechecked against this exact tuple. The surface"
        + " answers, but its stability and policy class are undocumented here."
      : "CleanverseAPassVerifier treats a rejecting policy as a refusal, so for these exact"
        + " participants every aUSDC settlement path in Mordant (activation proceeds, bond claims,"
        + " cash redemption) fails closed with SettlementNotReady. Mordant has not identified an"
        + " A-Pass profile this token accepts. Which attribute is unsatisfied was not read back"
        + " and is not asserted.",
    smallestSponsorQuestion: facts.policyCanTransferAnswered === true
      ? "Which policy classes may a standard A-Token use, and is"
        + " canTransfer(token,from,to,amount) a stable documented interface on Monad?"
      : "Which A-Pass profile (tier, subTier, group, subGroup, country tags) satisfies the Monad"
        + " aUSDC compliance rule? The tuples we probed were rejected with ComplianceFailed.",
  });

  const factoryImplementation = facts.factoryImplementation;
  const factoryMoved = factoryImplementation !== null
    && factoryImplementation.toLowerCase() !== RECORDED_MONAD_FACTORY_IMPLEMENTATION;
  const tenArgPresent = facts.factoryTenArgLaunchSelectorPresent === true;

  comparisons.push({
    topic: "Monad A-Token factory launch ABI",
    documentedNetwork: MONAD_TESTNET_NAME,
    documentedVersion: launchDoc.version,
    documentedSignatureOrBehavior: launchDoc.behavior,
    observedNetwork: MONAD_TESTNET_NAME,
    observedBlock,
    observedAddress: targets.aTokenFactoryProxy,
    observedImplementation: factoryImplementation,
    observedSignatureOrBehavior:
      `${ATOKEN_LAUNCH_SELECTOR_TEN_ARG} ${tenArgPresent ? "PRESENT" : "ABSENT"},`
      + ` ${ATOKEN_LAUNCH_SELECTOR_EIGHT_ARG}`
      + ` ${facts.factoryEightArgLaunchSelectorPresent === true ? "PRESENT" : "ABSENT"}`
      + (factoryMoved
        ? `; implementation differs from the one recorded in the repository`
        : `; implementation matches the one recorded in the repository`),
    // The previously recorded skew is a bytecode fact that this run re-measures. It is only a
    // documentation/deployment skew while the documented ABI itself cannot be read.
    comparisonStatus: tenArgPresent ? "NOT PROVEN" : DOC_DEPLOYMENT_SKEW,
    impactOnMordant: tenArgPresent
      ? `No backend/factory selector skew was observable at block ${observedBlock}. That is a`
        + " read-only bytecode fact: whether a /atoken/launch application now succeeds stays"
        + " NOT PROVEN — WRITE ACTION REQUIRED."
      : "A dedicated invoice A-Token cannot be issued on Monad through the documented launch"
        + " surface while the deployed factory lacks that selector.",
    smallestSponsorQuestion: "Which factory implementation and launch ABI version is the Monad"
      + " backend expected to call today?",
  });

  comparisons.push({
    topic: "Gateway acceptance of an A-Pass for a smart-contract address",
    documentedNetwork: MONAD_TESTNET_NAME,
    documentedVersion: apassDoc.version,
    documentedSignatureOrBehavior: apassDoc.behavior,
    observedNetwork: MONAD_TESTNET_NAME,
    observedBlock,
    observedAddress: targets.apass,
    observedImplementation: facts.apassImplementation,
    observedSignatureOrBehavior: "not observable read-only: issuing an A-Pass is a write action",
    comparisonStatus: "NOT PROVEN",
    impactOnMordant: "The adapter and each vault need their own A-Pass. On-chain feasibility and"
      + " gateway acceptance are separate proofs and only the first is within read-only reach.",
    smallestSponsorQuestion: "Does the /generate_apass gateway accept a contract address"
      + " controlled by a verified legal entity on Monad?",
  });

  comparisons.push({
    topic: "Mordant invoice vault deployment",
    documentedNetwork: MONAD_TESTNET_NAME,
    documentedVersion: "NOT APPLICABLE",
    documentedSignatureOrBehavior: "Mordant owns this contract; Cleanverse documents nothing here",
    observedNetwork: MONAD_TESTNET_NAME,
    observedBlock,
    observedAddress: targets.mordantVault ?? "not configured",
    observedImplementation: null,
    observedSignatureOrBehavior: targets.mordantVault === null
      ? "no vault address configured for this run"
      : facts.mordantVaultHasCode === true
        ? "bytecode present at the configured vault address"
        : "NO BYTECODE at the configured vault address",
    comparisonStatus: targets.mordantVault === null ? "NOT APPLICABLE" : "MATCH",
    impactOnMordant: "The live vault proof in the interface stays unconfigured until a judged"
      + " deployment exists.",
    smallestSponsorQuestion: "None: this is a Mordant deployment step, not a sponsor dependency.",
  });

  return Object.freeze(comparisons);
}

export function buildCleanverseMonadConclusions(
  facts: CleanverseMonadFacts,
  comparisons: readonly Comparison[],
  block: PinnedBlock,
): readonly Conclusion[] {
  const blockNumber = block.blockNumber.toString();
  const conclusions: Conclusion[] = [
    {
      statement: "The canonical Cleanverse Monad testnet contracts exist and answer their"
        + " documented-by-configuration read surfaces at the pinned block.",
      classification: "READ-ONLY",
      basis: "eth_getCode and eth_call against the A-Pass, aUSDC, AccessCore and factory"
        + " addresses at one pinned block.",
    },
    {
      statement: facts.factoryTenArgLaunchSelectorPresent === true
        ? `No backend/factory selector skew was observable at block ${blockNumber}: the Monad`
          + ` A-Token factory implementation exposes both launch selectors.`
        : `A backend/factory selector skew was observable at block ${blockNumber}: the Monad`
          + ` A-Token factory implementation lacks the ten-argument launch selector.`,
      classification: "READ-ONLY",
      basis: "EIP-1967 implementation slot read, followed by a dispatch-table selector scan of the"
        + " implementation bytecode. A selector scan proves presence in the dispatch table. It does"
        + " not show that a /atoken/launch application succeeds, which stays"
        + " NOT PROVEN — WRITE ACTION REQUIRED.",
    },
    {
      statement: facts.policyCanTransferAnswered === true
        ? "The deployed aUSDC transfer policy answers the exact tuple Mordant prechecks."
        : "BLOCKED — COMPLIANT APASS PROFILE NOT IDENTIFIED: the probed tuples were rejected with"
          + " ComplianceFailed, which is consistent with a compliance rule that is not satisfied"
          + " by those participants. Mordant settlement prechecks fail closed for them.",
      classification: facts.policyCanTransferAnswered === true ? "READ-ONLY" : "BLOCKED",
      basis: facts.policyCanTransferAnswered === true
        ? "eth_call against policy().canTransfer(token, from, to, amount) at the pinned block."
        : `eth_call against policy().canTransfer(aUSDC, from, to, 1) for three tuples, including`
          + ` two addresses whose isValidAPass is true; each was rejected with`
          + ` ${describeRevertSelector(facts.policyRevertSelector)}. Bounded to those tuples: it`
          + ` does not establish which attribute is unsatisfied, that the policy rejects every`
          + ` participant, that the policy is faulty, or that holding a valid A-Pass suffices.`,
    },
    {
      statement: "The Cleanverse CVA/aUSDC rail is not live for Mordant.",
      classification: "NOT PROVEN",
      basis: "No A-Pass was issued, no A-Token was launched, no role was granted and no"
        + " transaction was broadcast. Those are write actions and are out of scope here.",
    },
    {
      statement: "Every claim that depends on the protected Cleanverse documentation is unproven"
        + " in this run.",
      classification: "BLOCKED",
      basis: "No documentation session access code was available, so the access-gated pages could"
        + " not be read. Repository notes were not substituted for them.",
    },
  ];

  const skew = comparisons.filter(
    (comparison) => comparison.comparisonStatus === DOC_DEPLOYMENT_SKEW,
  );
  if (skew.length !== 0) {
    conclusions.push({
      statement: `${skew.length} surface(s) remain classified as a documentation/deployment skew.`,
      classification: "BLOCKED",
      basis: skew.map((comparison) => comparison.topic).join("; "),
    });
  }

  return Object.freeze(conclusions);
}

export function buildCleanverseMonadMissingEvidence(
  facts: CleanverseMonadFacts,
): readonly MissingEvidence[] {
  const missing: MissingEvidence[] = [
    {
      topic: "Protected Cleanverse API documentation (all chapters)",
      reason: "No session access code was available to this run; the pages are access-gated.",
      whatWouldProveIt: "A documentation session that can read the A-Pass, A-Token launch,"
        + " roles, policy and Monad network chapters, recording page, path, version and date.",
    },
    {
      topic: "Gateway issuance of an A-Pass to the adapter and vault contract addresses",
      reason: "Issuing an A-Pass is a state-changing sponsor call and is out of scope.",
      whatWouldProveIt: "A controlled, authorized /generate_apass call for both contract"
        + " addresses, with the resulting credential read back on chain.",
    },
    {
      topic: "End-to-end issuance of a dedicated invoice A-Token on Monad",
      reason: "Launching an A-Token is a state-changing sponsor call and is out of scope.",
      whatWouldProveIt: "One authorized /atoken/launch application reaching ISSUED, followed by"
        + " read-back of the issued token implementation, decimals, policy and role surface.",
    },
    {
      topic: "Mint and burn authority on a newly issued invoice A-Token",
      reason: "Requires a token that does not exist yet, plus a role grant.",
      whatWouldProveIt: "hasRole(MINTER_ROLE, adapter) returning true on the issued token, and a"
        + " burn attempt from an unauthorized address reverting.",
    },
  ];

  if (facts.policyCanTransferAnswered !== true) {
    missing.push({
      topic: "An A-Pass profile the Monad aUSDC compliance rule accepts",
      reason: "The probed tuples were rejected with"
        + ` ${describeRevertSelector(facts.policyRevertSelector)}, consistent with an unsatisfied`
        + " compliance rule. Compliant participants cannot be enumerated from public state.",
      whatWouldProveIt: "One canTransfer(aUSDC, from, to, amount) tuple returning true, or the"
        + " rule values the token was launched with, read back from the sponsor.",
    });
  }

  if (facts.mordantVaultHasCode === null) {
    missing.push({
      topic: "Mordant invoice vault on Monad testnet",
      reason: "No vault address is configured, so the interface cannot show a live proof.",
      whatWouldProveIt: "A judged deployment address whose accounting reads back at a pinned"
        + " block through the Mordant read layer.",
    });
  }

  return Object.freeze(missing);
}
