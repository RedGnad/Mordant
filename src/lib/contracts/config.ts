import {
  createPublicClient,
  getAddress,
  http,
  isAddress,
  type Address,
} from "viem";
import { monadTestnet } from "viem/chains";
import { z } from "zod";

export const MORDANT_MONAD_TESTNET_CHAIN_ID = 10_143 as const;

const httpUrlSchema = z.string().trim().url().refine((value) => {
  const protocol = new URL(value).protocol;
  return protocol === "http:" || protocol === "https:";
}, "Expected an HTTP or HTTPS URL");

const addressSchema = z
  .string()
  .trim()
  .refine((value) => isAddress(value, { strict: false }), "Expected an EVM address")
  .transform((value): Address => getAddress(value));

const monadTestnetPublicConfigSchema = z
  .object({
    chainId: z.coerce.number().int().refine(
      (value) => value === MORDANT_MONAD_TESTNET_CHAIN_ID,
      `Expected Monad testnet chain ${MORDANT_MONAD_TESTNET_CHAIN_ID}`,
    ),
    rpcUrl: httpUrlSchema,
    explorerUrl: httpUrlSchema,
    vaultAddress: addressSchema,
  })
  .strict();

export type MonadTestnetPublicConfig = Readonly<
  z.output<typeof monadTestnetPublicConfigSchema>
>;

export class MonadTestnetPublicConfigError extends Error {
  readonly invalidFields: readonly string[];

  constructor(invalidFields: readonly string[]) {
    super("Public Monad testnet configuration is missing or invalid");
    this.name = "MonadTestnetPublicConfigError";
    this.invalidFields = invalidFields;
  }
}

export function getMonadTestnetPublicConfig(): MonadTestnetPublicConfig {
  const result = monadTestnetPublicConfigSchema.safeParse({
    chainId: process.env.NEXT_PUBLIC_CHAIN_ID,
    rpcUrl: process.env.NEXT_PUBLIC_MONAD_RPC_URL,
    explorerUrl: process.env.NEXT_PUBLIC_MONAD_EXPLORER_URL,
    vaultAddress: process.env.NEXT_PUBLIC_MORDANT_VAULT_ADDRESS,
  });

  if (!result.success) {
    throw new MonadTestnetPublicConfigError(
      [...new Set(result.error.issues.map((issue) => String(issue.path[0] ?? "config")))],
    );
  }

  return Object.freeze({
    ...result.data,
    rpcUrl: result.data.rpcUrl.replace(/\/+$/, ""),
    explorerUrl: result.data.explorerUrl.replace(/\/+$/, ""),
  });
}

export function createMonadTestnetReadClient(config: MonadTestnetPublicConfig) {
  const chain = {
    ...monadTestnet,
    rpcUrls: {
      default: { http: [config.rpcUrl] },
    },
    blockExplorers: {
      default: {
        name: "Monad Testnet Explorer",
        url: config.explorerUrl,
      },
    },
  } as const;

  return createPublicClient({
    chain,
    transport: http(config.rpcUrl),
  });
}

export type MonadTestnetReadClient = ReturnType<typeof createMonadTestnetReadClient>;
