import type {
  QueryAPassData,
  QueryApplyStatusData,
  QuerySupportedATokensData,
} from "./schemas";

export function toPublicDiscovery(result: QuerySupportedATokensData) {
  return {
    chain: result.chain,
    tokens: result.tokens.map((pair) => ({
      origin_token: {
        address: pair.origin_token.address,
        name: pair.origin_token.name,
        symbol: pair.origin_token.symbol,
        decimals: pair.origin_token.decimals,
        icon: pair.origin_token.icon,
      },
      atoken: {
        address: pair.atoken.address,
        name: pair.atoken.name,
        symbol: pair.atoken.symbol,
        decimals: pair.atoken.decimals,
        icon: pair.atoken.icon,
      },
      accesscore_address: pair.accesscore_address,
      apass_address: pair.apass_address,
    })),
  };
}

export function toPublicApplyStatus(result: QueryApplyStatusData) {
  return {
    flowType: result.flowType,
    requestId: result.requestId,
    applyStatus: result.applyStatus,
    chain: result.chain,
    atokenAddress: result.atokenAddress ?? null,
    originTokenAddress: result.originTokenAddress ?? null,
    tokenSymbol: result.tokenSymbol ?? null,
    txHash: result.txHash ?? null,
    issuedAt: result.issuedAt ?? null,
  };
}

export function toPublicAPass(result: QueryAPassData) {
  return {
    tier: result.tier,
    subTier: result.subTier,
    status: result.status,
    expirationTime: result.expirationTime,
    group: result.group,
    subGroup: result.subGroup,
  };
}
