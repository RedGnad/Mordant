/**
 * Technical facts recorded from the access-gated Cleanverse API documentation.
 *
 * These are NOT scraped at run time: the page is behind a session invitation code, and no
 * credential belongs in this repository. They are a dated, attributed transcription of the
 * minimum technical surface the evidence gate needs (endpoint, fields, lifecycle, roles), and
 * they are only emitted when the operator asserts a consultation with `--docs-consulted`.
 *
 * Anything absent from the documentation is recorded as absent, never inferred.
 */

/**
 * How the documented side was obtained. This is a transcription committed to the repository,
 * never an automated read: the evidence gate has no credential and must never imply otherwise.
 */
export const CLEANVERSE_DOCUMENTATION_SOURCE_KIND = "manual-versioned-transcription" as const;

/**
 * Structurally false. The gate probes the page only for reachability (it answers HTTP 403 without
 * a session), and never sends an access code. If this ever needs to become true, the credential
 * handling must be designed first.
 */
export const CLEANVERSE_DOCUMENTATION_LIVE_FETCHED_BY_GATE = false as const;

export const CLEANVERSE_DOCUMENTATION_VERSION = "v5.6" as const;

/** How the version was established, so a reviewer can re-derive it. */
export const CLEANVERSE_DOCUMENTATION_VERSION_SOURCE =
  "Page title \"Cleanverse API v5.6 - Integration Documentation\" and the version-history table,"
  + " whose latest entry is v5.6 dated 2026-07-21";

export const CLEANVERSE_DOCUMENTATION_PAGE_TITLE =
  "Cleanverse API v5.6 - Integration Documentation" as const;

export type RecordedDocumentationFact = Readonly<{
  topic: string;
  /** Section of the single-page documentation. No session token, ever. */
  pagePath: string;
  documentedAbiOrEndpoint: string;
  documentedBehavior: string;
  limitations: string;
}>;

export const CLEANVERSE_V56_FACTS: readonly RecordedDocumentationFact[] = Object.freeze([
  {
    topic: "CVI / A-Pass issuance and expiry",
    pagePath: "/docs/cleanverse#a-pass-management",
    documentedAbiOrEndpoint: "POST /generate_apass (AES/CBC encrypted body, api-id header)",
    documentedBehavior: "Creates an A-Pass for wallet{address, chain}. expirationTime is a"
      + " required Unix-seconds timestamp. Country tags are derived from"
      + " identityDataList[].issuingCountryISO2 since v5.5.",
    limitations: "The chapter documents the gateway request contract only. It publishes no"
      + " Solidity interface and does not state whether a contract address is accepted.",
  },
  {
    topic: "A-Pass support for smart-contract addresses",
    pagePath: "/docs/cleanverse#a-pass-management",
    documentedAbiOrEndpoint: "POST /generate_apass, field wallet.address",
    documentedBehavior: "Described generically as the \"A-Pass receiving wallet address\". No"
      + " EOA-only restriction is stated anywhere in the chapter.",
    limitations: "Absence of a restriction is not a documented guarantee of acceptance. Only the"
      + " Validator chapter explicitly contemplates contract addresses, and it does so for the"
      + " registrar role, not for A-Pass issuance.",
  },
  {
    topic: "A-Token launch and factory ABI",
    pagePath: "/docs/cleanverse#a-token-management",
    documentedAbiOrEndpoint: "POST /atoken/launch with chain, token_name, token_symbol, decimals,"
      + " admin_address, rule, icon, optional callback_url",
    documentedBehavior: "Submits an application for a standard A-Token. The rule object carries"
      + " allowed_group, allowed_sub_group, min_tier, min_sub_tier and, since v5.5 (2026-07-13),"
      + " is_black_list and countries.",
    limitations: "The documentation describes the REST contract. It publishes no on-chain factory"
      + " ABI, so no documented launch selector exists to compare against bytecode.",
  },
  {
    topic: "A-Token issuance application lifecycle",
    pagePath: "/docs/cleanverse#a-token-management",
    documentedAbiOrEndpoint: "GET /atoken/query_apply_status/{requestId}; optional apply-result"
      + " webhook via callback_url",
    documentedBehavior: "Submission returns only a requestId. An issuance is successful only when"
      + " applyStatus becomes ISSUED.",
    limitations: "Terminal failure states are observable through the same endpoint but their"
      + " remediation is not documented.",
  },
  {
    topic: "Mint and burn role semantics on issued A-Tokens",
    pagePath: "/docs/cleanverse#a-token-management",
    documentedAbiOrEndpoint: "MINTER_ROLE, granted by admin_address after ISSUED",
    documentedBehavior: "For a standard A-Token the admin wallet grants MINTER_ROLE to the chosen"
      + " minter, and only then may that minter mint. For a Wrapped A-Token, MINTER_ROLE is"
      + " granted to the access_core contract, which locks the origin token and mints 1:1.",
    limitations: "BURN authority is never documented for a standard A-Token. The documentation"
      + " states what MINTER_ROLE permits for minting only.",
  },
  {
    topic: "Custody and transfer policy",
    pagePath: "/docs/cleanverse#a-token-management",
    documentedAbiOrEndpoint: "rule object (compliance rule) evaluated against A-Pass attributes",
    documentedBehavior: "The platform uses the token's rule together with the holder's A-Pass"
      + " attributes (tier, subTier, group, subGroup and country tags) to determine whether a"
      + " wallet may receive or transfer that A-Token. min_tier admits a user whose tier is"
      + " strictly greater than the configured value.",
    limitations: "No Solidity policy interface is published. `canTransfer(address,address,address,"
      + "uint256)` appears nowhere in the documentation; Mordant's ICleanversePolicy is inferred"
      + " from deployed bytecode, not from a documented ABI.",
  },
  {
    topic: "aUSDC semantics",
    pagePath: "/docs/cleanverse#a-token-management",
    documentedAbiOrEndpoint: "Wrapped A-Token flow; access_core resolved via the supported"
      + " A-Token list endpoint",
    documentedBehavior: "A wrapped asset is minted 1:1 against a locked origin token when a"
      + " whitelisted institution address funds the deposit address.",
    limitations: "Per-network aUSDC addresses and decimals are not published as a static table;"
      + " they must be discovered through the query endpoints.",
  },
  {
    topic: "Monad configuration and addresses",
    pagePath: "/docs/cleanverse#a-pass-management",
    documentedAbiOrEndpoint: "chain slug \"monad\" in the supported-network lists",
    documentedBehavior: "monad is a documented, case-insensitive chain slug for A-Pass and"
      + " A-Token operations, alongside solana, base, avalanche, arbitrum, ethereum, polygon,"
      + " bsc, hashkey and platon.",
    limitations: "The documentation publishes no Monad chain id and no Monad contract addresses."
      + " Those come from the runtime configuration endpoint, which states no version.",
  },
  {
    topic: "Validator Compliance surface",
    pagePath: "/docs/cleanverse#validator-compliance",
    documentedAbiOrEndpoint: "POST /validator/{grant,register,set_rule,add_rule,remove_rule,"
      + "set_paused} encrypted; /validator/{is_register,rules,verify,is_paused} plain JSON",
    documentedBehavior: "Pools are on-chain addresses registered with the APass Compliance"
      + " Validator contract. grant and register require an EIP-191 owner_signature over the"
      + " lowercase chain slug concatenated with the lowercase hex address. Signed grant is"
      + " explicitly intended for smart-contract addresses exposing Ownable.owner().",
    limitations: "No Validator contract address and no Solidity ABI are published for any"
      + " network, so an on-chain ICviVerifier cannot be written from the documentation.",
  },
]);
