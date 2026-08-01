// Feature configuration for private matching V4.
//
// Everything here is off unless explicitly enabled. A production deployment can
// never become enabled as a side effect of merging this integration: the network
// allow-list contains only Monad testnet, and `assertNetworkAllowed` throws on
// anything else regardless of how the flags are set.
//
// The evidence behind this feature is controlled Monad testnet evidence. The
// copy in `PRIVATE_MATCHING_COPY` is the only wording approved for it.

export const MONAD_TESTNET_CHAIN_ID = 10_143;

/// The only chain this feature may address. Mainnet is absent by construction,
/// not by a flag someone can flip.
export const ALLOWED_CHAIN_IDS: readonly number[] = [MONAD_TESTNET_CHAIN_ID];

export type PrivateMatchingFlags = Readonly<{
  /// Shows the private-matching product flow. Off by default.
  enabled: boolean;
  /// Shows the evidence explorer over the published bundle. Off by default.
  evidenceExplorerEnabled: boolean;
  /// Shows the read-only demo. Off by default.
  demoEnabled: boolean;
  /// Permits a live session against a chain. Off by default, and still bounded
  /// by ALLOWED_CHAIN_IDS.
  liveSessionsEnabled: boolean;
}>;

const truthy = (value: string | undefined): boolean => value === "true" || value === "1";

/**
 * Reads the flags from the environment.
 *
 * Absent is false. There is no default-on path, and no flag can widen the
 * network allow-list.
 */
export function readPrivateMatchingFlags(
  env: Record<string, string | undefined> = process.env,
): PrivateMatchingFlags {
  return {
    enabled: truthy(env.NEXT_PUBLIC_PRIVATE_MATCHING_ENABLED),
    evidenceExplorerEnabled: truthy(env.NEXT_PUBLIC_PRIVATE_MATCHING_EVIDENCE_ENABLED),
    demoEnabled: truthy(env.NEXT_PUBLIC_PRIVATE_MATCHING_DEMO_ENABLED),
    liveSessionsEnabled: truthy(env.PRIVATE_MATCHING_LIVE_SESSIONS_ENABLED),
  };
}

/**
 * The protocol version the live product path speaks.
 *
 * An external audit returned NO-GO on every public claim made for the V4/RC1
 * protocol. RC1 remains in the repository as immutable historical evidence, and
 * its sixteen frozen sources are unchanged, but it must not stay reachable as a
 * product protocol. Anything below V5 fails closed here rather than depending on
 * a deployment remembering not to select it.
 */
export const PRODUCT_PROTOCOL_VERSION = 5;
export const MINIMUM_SUPPORTED_PROTOCOL_VERSION = 5;

export class ProtocolVersionRetiredError extends Error {
  readonly version: number;
  constructor(version: number) {
    super(
      `Private matching protocol v${version} is retired and cannot serve a live ` +
      `session. The live path requires v${MINIMUM_SUPPORTED_PROTOCOL_VERSION} or ` +
      "later. Protocol versions below that failed external audit on every public " +
      "claim and are retained only as historical evidence.",
    );
    this.name = "ProtocolVersionRetiredError";
    this.version = version;
  }
}

/// Throws unless the protocol version is one the live path may serve.
export function assertProtocolVersionSupported(version: number): void {
  if (!Number.isInteger(version) || version < MINIMUM_SUPPORTED_PROTOCOL_VERSION) {
    throw new ProtocolVersionRetiredError(version);
  }
}

export class NetworkNotAllowedError extends Error {
  readonly chainId: number;
  constructor(chainId: number) {
    super(
      `Private matching is limited to Monad testnet (${MONAD_TESTNET_CHAIN_ID}). ` +
      `Chain ${chainId} is not allowed. The evidence behind this feature is ` +
      "controlled Monad testnet evidence only.",
    );
    this.name = "NetworkNotAllowedError";
    this.chainId = chainId;
  }
}

/// Throws unless the chain is on the allow-list. Called before any live path.
export function assertNetworkAllowed(chainId: number): void {
  if (!ALLOWED_CHAIN_IDS.includes(chainId)) throw new NetworkNotAllowedError(chainId);
}

/**
 * A live session needs the feature, the live flag, an allowed chain AND a
 * supported protocol version.
 *
 * The protocol version defaults to the retired V4 rather than to the current
 * one, so a caller that forgets to pass it gets a refusal instead of an
 * unintended live V4 session.
 */
export function canStartLiveSession(
  flags: PrivateMatchingFlags,
  chainId: number,
  protocolVersion = 4,
): boolean {
  if (!flags.enabled || !flags.liveSessionsEnabled) return false;
  if (!Number.isInteger(protocolVersion) || protocolVersion < MINIMUM_SUPPORTED_PROTOCOL_VERSION) {
    return false;
  }
  return ALLOWED_CHAIN_IDS.includes(chainId);
}

/**
 * The only wording approved for this feature.
 *
 * Every sentence is bounded by what the M-PRIV8 evidence supports. The
 * disclaimers are not decoration: they are the difference between a supported
 * claim and one the evidence does not carry.
 */
export const PRIVATE_MATCHING_COPY = Object.freeze({
  title: "Private matching",
  summary:
    "Two mutually authorized parties can determine privately whether their " +
    "submissions describe the same receivable, and open a governed recourse " +
    "record only after both sides consent to disclose it.",
  bullets: Object.freeze([
    "Private matching between mutually authorized submissions.",
    "Governed recourse after bilateral disclosure consent.",
    "The evaluator does not receive the submitted identities or commercial terms.",
  ]),
  disclaimers: Object.freeze([
    "Controlled Monad testnet evidence. Test assets only.",
    "Computation is quorum-attested; correct FHE execution is not publicly proven.",
    "Process separation is architectural. Organizational independence is a " +
      "production deployment property and was not established.",
    "No traffic-analysis privacy is claimed.",
  ]),
});

/**
 * Wording this feature must never carry.
 *
 * Kept as data so the lexicon test can assert the product copy avoids it,
 * rather than relying on a reviewer noticing.
 */
export const PROHIBITED_CLAIMS: readonly string[] = Object.freeze([
  "fraud detection",
  "market completeness",
  "zero knowledge",
  "zero-knowledge",
  "trustless",
  "private transactions",
  "private settlement",
  "publicly proven",
  "independent organizational custody",
  "production ready",
  "production-ready",
]);
