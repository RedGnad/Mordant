import { z } from "zod";

export const CLEANVERSE_CHAINS = [
  "solana",
  "base",
  "avalanche",
  "arbitrum",
  "ethereum",
  "polygon",
  "bsc",
  "monad",
  "hashkey",
  "platon",
] as const;

const cleanverseChainEnum = z.enum(CLEANVERSE_CHAINS);

export const cleanverseChainSchema = z.preprocess(
  (value) => (typeof value === "string" ? value.trim().toLowerCase() : value),
  cleanverseChainEnum,
);

const evmAddressSchema = z.string().regex(/^0x[0-9a-fA-F]{40}$/, "Invalid EVM address");
const solanaAddressSchema = z
  .string()
  .regex(/^[1-9A-HJ-NP-Za-km-z]{32,44}$/, "Invalid Solana address");

export const chainAddressSchema = z
  .object({
    chain: cleanverseChainSchema,
    address: z.string().trim().min(1).max(128),
  })
  .strict()
  .superRefine(({ chain, address }, context) => {
    const result = chain === "solana" ? solanaAddressSchema.safeParse(address) : evmAddressSchema.safeParse(address);
    if (!result.success) {
      context.addIssue({
        code: "custom",
        path: ["address"],
        message: result.error.issues[0]?.message ?? "Invalid address",
      });
    }
  });

const httpUrlSchema = z.string().url().refine((value) => {
  const protocol = new URL(value).protocol;
  return protocol === "http:" || protocol === "https:";
}, "Expected an HTTP or HTTPS URL");

const isoAlpha2Schema = z.string().regex(/^[A-Za-z]{2}$/, "Expected an ISO 3166-1 alpha-2 code");
const isoCurrencySchema = z.string().regex(/^[A-Za-z]{3}$/, "Expected an ISO 4217 currency code");
const eip191SignatureSchema = z
  .string()
  .regex(/^0x[0-9a-fA-F]{130}$/, "Expected a 65-byte EIP-191 signature");

export const aPassIdentityDataSchema = z
  .object({
    idType: z.enum([
      "ID_CARD",
      "PASSPORT",
      "DRIVER_LICENSE",
      "HK_MACAO_TAIWAN_PASS",
      "RESIDENCE_PERMIT",
    ]),
    fullName: z.string(),
    idNumber: z.string().optional(),
    validUntil: z.string().regex(/^\d{4}-\d{2}-\d{2}$/, "Expected yyyy-MM-dd").optional(),
    issuingCountryISO2: isoAlpha2Schema,
  })
  .strict();

export const aPassBankAccountSchema = z
  .object({
    bankCountry: isoAlpha2Schema,
    bankName: z.string(),
    bankAccount: z.string().optional(),
    bankAccountType: z.enum(["C", "D", "A"]).optional(),
    balance: z.number().int().optional(),
    currency: isoCurrencySchema.optional(),
  })
  .strict();

export const generateAPassRequestSchema = z
  .object({
    customerId: z.string().regex(/^[A-Za-z0-9]{12,}$/, "Expected at least 12 alphanumeric characters"),
    kycSource: z.string().optional(),
    kycId: z.string().optional(),
    subTier: z.number().int().min(1).max(99).optional(),
    subGroup: z.string().length(2).optional(),
    override: z.boolean().optional(),
    expirationTime: z.number().int(),
    wallet: chainAddressSchema,
    identityDataList: z.array(aPassIdentityDataSchema).optional(),
    bankAccountList: z.array(aPassBankAccountSchema).optional(),
  })
  .strict();

export const generateAPassWalletDataSchema = z
  .object({
    operate: z.string(),
    address: z.string(),
    chain: z.string(),
    txHash: z.string(),
    depositUSDCWallet: z.string().nullish(),
    depositUSDCAccount: z.string().nullish(),
    depositUSDTWallet: z.string().nullish(),
    depositUSDTAccount: z.string().nullish(),
    apassAddress: z.string().nullish(),
  })
  .passthrough();

export const generateAPassDataSchema = z
  .object({
    customerId: z.string(),
    cvRecordId: z.string(),
    tier: z.string(),
    wallet: generateAPassWalletDataSchema,
  })
  .passthrough();

export const aTokenRuleSchema = z
  .object({
    allowed_group: z.union([z.literal(""), z.string().length(2)]),
    allowed_sub_group: z.union([z.literal(""), z.string().length(2)]),
    min_tier: z.number().int().min(0).max(99),
    min_sub_tier: z.number().int().min(0).max(99),
    is_black_list: z.boolean().optional(),
    countries: z.array(z.string().regex(/^[A-Za-z]{2}$/)).optional(),
  })
  .strict();

export const launchATokenRequestSchema = z
  .object({
    chain: cleanverseChainSchema,
    token_name: z.string().trim().min(1),
    token_symbol: z.string().trim().min(1),
    decimals: z.number().int().min(0),
    admin_address: z.string().trim().min(1).max(128),
    rule: aTokenRuleSchema,
    icon: httpUrlSchema,
    callback_url: httpUrlSchema.max(512).optional(),
  })
  .strict();

export const launchATokenDataSchema = z
  .object({
    requestId: z.string(),
    issueAssetId: z.number().int(),
  })
  .passthrough();

export const registerATokenRequestSchema = z
  .object({
    chain: cleanverseChainSchema,
    atoken_address: z.string().trim().min(1).max(128),
    owner_signature: eip191SignatureSchema,
    atoken_icon: httpUrlSchema,
    callback_url: httpUrlSchema.max(512).optional(),
  })
  .strict()
  .superRefine(({ chain, atoken_address }, context) => {
    const result = chainAddressSchema.safeParse({ chain, address: atoken_address });
    if (!result.success) {
      context.addIssue({
        code: "custom",
        path: ["atoken_address"],
        message: result.error.issues[0]?.message ?? "Invalid address",
      });
    }
  });

export const registerATokenDataSchema = z
  .object({
    requestId: z.string(),
    issueAssetRegisterId: z.number().int(),
  })
  .passthrough();

export const requestIdSchema = z.string().trim().min(1).max(128).regex(/^[A-Za-z0-9_-]+$/);

export const applyStatusSchema = z.enum([
  "PENDING",
  "APPROVED",
  "ISSUING",
  "ISSUED",
  "REJECTED",
  "ISSUE_FAILED",
]);
export const flowTypeSchema = z.enum(["LAUNCH", "LAUNCH_WRAPPED", "REGISTER_WRAPPED", "REGISTER_ATOKEN"]);

export const queryApplyStatusDataSchema = z
  .object({
    flowType: flowTypeSchema,
    requestId: z.string(),
    applyStatus: applyStatusSchema,
    rejectReason: z.string().nullish(),
    issueErrorMsg: z.string().nullish(),
    chain: z.string(),
    atokenAddress: z.string().nullish(),
    originTokenAddress: z.string().nullish(),
    tokenSymbol: z.string().nullish(),
    txHash: z.string().nullish(),
    issuedAt: z.string().nullish(),
    callbackUrl: z.string().nullish(),
    callbackStatus: z.enum(["PENDING", "SUCCESS", "FAILED"]).optional(),
    callbackAttempts: z.number().int().optional(),
    callbackLastError: z.string().nullish(),
  })
  .passthrough();

export const querySupportedATokensRequestSchema = z
  .object({
    chain: cleanverseChainSchema,
    symbol: z.string().trim().min(1).max(64).optional(),
    address: z.string().trim().min(1).max(128).optional(),
  })
  .strict();

export const tokenInfoSchema = z
  .object({
    address: z.string(),
    name: z.string(),
    symbol: z.string(),
    decimals: z.number().int(),
    icon: z.string(),
  })
  .passthrough();

export const supportedTokenPairSchema = z
  .object({
    origin_token: tokenInfoSchema,
    atoken: tokenInfoSchema,
    accesscore_address: z.string(),
    apass_address: z.string(),
  })
  .passthrough();

export const querySupportedATokensDataSchema = z
  .object({
    chain: z.string(),
    tokens: z.array(supportedTokenPairSchema),
  })
  .passthrough();

export const queryAPassRequestSchema = chainAddressSchema;

export const queryAPassDataSchema = z
  .object({
    cvRecordId: z.string(),
    subTier: z.number().int(),
    tier: z.string(),
    status: z.number().int(),
    expirationTime: z.number().int(),
    subGroup: z.string(),
    currentKycHash: z.string(),
    group: z.string(),
    countries: z.array(z.string()),
  })
  .passthrough();

export const verifyAPassRequestSchema = z
  .object({
    chain: cleanverseChainSchema,
    atoken: z.string().trim().min(1).max(128),
    address: z.string().trim().min(1).max(128),
  })
  .strict();

export const verifyAPassDataSchema = z
  .object({
    chain: z.string(),
    atoken: z.string(),
    address: z.string(),
    code: z.union([z.literal(1), z.literal(2), z.literal(3), z.literal(4)]),
    message: z.string(),
    magickLink: z.string(),
  })
  .passthrough();

export const validatorRuleSchema = z
  .object({
    allowed_group: z.union([z.literal(""), z.string().min(1).max(2)]),
    allowed_sub_group: z.union([z.literal(""), z.string().min(1).max(2)]),
    min_tier: z.number().int().min(0).max(99),
    min_sub_tier: z.number().int().min(0).max(99),
    is_black_list: z.boolean().optional(),
    countries: z.array(z.string().regex(/^[A-Za-z]{2}$/)).optional(),
  })
  .strict();

export const registerValidatorPoolRequestSchema = z
  .object({
    chain: cleanverseChainSchema,
    contract_address: evmAddressSchema,
    rule: validatorRuleSchema,
    owner_signature: eip191SignatureSchema,
  })
  .strict();

export const registerValidatorPoolDataSchema = z
  .object({
    chain: z.string(),
    contract_address: z.string(),
    tx_hash: z.string(),
  })
  .passthrough();

export const isValidatorPoolRegisteredRequestSchema = z
  .object({
    chain: cleanverseChainSchema,
    contract_address: evmAddressSchema,
  })
  .strict();

export const isValidatorPoolRegisteredDataSchema = z
  .object({
    chain: z.string(),
    contract_address: z.string(),
    registered: z.boolean(),
  })
  .passthrough();

export const verifyValidatorPoolRequestSchema = z
  .object({
    chain: cleanverseChainSchema,
    contract_address: evmAddressSchema,
    user_address: evmAddressSchema,
  })
  .strict();

export const verifyValidatorPoolDataSchema = z
  .object({
    chain: z.string(),
    contract_address: z.string(),
    user_address: z.string(),
    valid: z.boolean(),
  })
  .passthrough();

export const faucetRequestSchema = z
  .object({
    chain: cleanverseChainSchema,
    symbol: z.string().trim().min(1),
    depositAddress: z.string().trim().min(1).max(128),
    amount: z.string().trim().min(1),
  })
  .strict()
  .superRefine(({ chain, depositAddress }, context) => {
    const result = chainAddressSchema.safeParse({ chain, address: depositAddress });
    if (!result.success) {
      context.addIssue({
        code: "custom",
        path: ["depositAddress"],
        message: result.error.issues[0]?.message ?? "Invalid address",
      });
    }
  });

export const faucetDataSchema = z
  .object({
    chain: z.string(),
    symbol: z.string(),
    deposit_address: z.string(),
    amount: z.string(),
    tx_hash: z.string(),
  })
  .passthrough();

export const cleanverseEnvelopeSchema = z
  .object({
    code: z.string(),
    message: z.string(),
    data: z.unknown(),
  })
  .passthrough();

export type LaunchATokenRequest = z.output<typeof launchATokenRequestSchema>;
export type LaunchATokenData = z.output<typeof launchATokenDataSchema>;
export type GenerateAPassRequest = z.output<typeof generateAPassRequestSchema>;
export type GenerateAPassData = z.output<typeof generateAPassDataSchema>;
export type RegisterATokenRequest = z.output<typeof registerATokenRequestSchema>;
export type RegisterATokenData = z.output<typeof registerATokenDataSchema>;
export type QueryApplyStatusData = z.output<typeof queryApplyStatusDataSchema>;
export type QuerySupportedATokensRequest = z.output<typeof querySupportedATokensRequestSchema>;
export type QuerySupportedATokensData = z.output<typeof querySupportedATokensDataSchema>;
export type QueryAPassRequest = z.output<typeof queryAPassRequestSchema>;
export type QueryAPassData = z.output<typeof queryAPassDataSchema>;
export type VerifyAPassRequest = z.output<typeof verifyAPassRequestSchema>;
export type VerifyAPassData = z.output<typeof verifyAPassDataSchema>;
export type RegisterValidatorPoolRequest = z.output<typeof registerValidatorPoolRequestSchema>;
export type RegisterValidatorPoolData = z.output<typeof registerValidatorPoolDataSchema>;
export type IsValidatorPoolRegisteredRequest = z.output<typeof isValidatorPoolRegisteredRequestSchema>;
export type IsValidatorPoolRegisteredData = z.output<typeof isValidatorPoolRegisteredDataSchema>;
export type VerifyValidatorPoolRequest = z.output<typeof verifyValidatorPoolRequestSchema>;
export type VerifyValidatorPoolData = z.output<typeof verifyValidatorPoolDataSchema>;
export type FaucetRequest = z.output<typeof faucetRequestSchema>;
export type FaucetData = z.output<typeof faucetDataSchema>;
