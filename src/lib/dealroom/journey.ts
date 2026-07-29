import {
  createPublicClient,
  createWalletClient,
  http,
  keccak256,
  parseEventLogs,
  type Abi,
  type Address,
  type Hex,
  type PublicClient,
  type TransactionReceipt,
  type WalletClient,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { anvil } from "viem/chains";

import {
  MORDANT_EIP712_NAME,
  MORDANT_EIP712_VERSION,
  buildMordantConflictCommitment,
  mordantPledgeTypes,
  type MordantPledge,
} from "@/lib/contracts/pledge";

/**
 * The deal-room journey. Every business step here sends a real transaction to the local chain and
 * is only considered done once its receipt confirms. Nothing advances on local state alone.
 *
 * Honesty labels: the chain is LOCAL, the settlement and CVA tokens are PROTOCOL DOUBLE, and the
 * invoice is SYNTHETIC. Nothing in this module is live and no Cleanverse endpoint is called.
 */

export const ROLES = [
  "deployer", "buyer", "originator", "facilityA", "facilityB", "holderA", "holderB",
] as const;

export type Role = (typeof ROLES)[number];

export type Deployment = Readonly<{
  label: string;
  warning: string;
  generatedAt: string;
  resetSnapshotId: string;
  rpcUrl: string;
  chainId: number;
  contracts: Readonly<Record<"eligibility" | "settlement" | "cva" | "adapter" | "factory" | "vault", Address>>;
  invoice: Readonly<{
    invoiceRoot: Hex;
    currency: Hex;
    initialUnits: string;
    advanceAmount: string;
    faceValue: string;
    bondBps: number;
    protectionEnd: string;
    revealPeriod: string;
    curePeriod: string;
  }>;
  accounts: Readonly<Record<Role, { address: Address; key: Hex }>>;
  abis: Readonly<Record<"vault" | "factory" | "erc20" | "adapter" | "eligibility", Abi>>;
}>;

export type StepKind = "transaction" | "signature" | "local-chain";

export type StepOutcome = Readonly<{
  kind: StepKind;
  hash?: Hex;
  blockNumber?: string;
  blockHash?: Hex;
  status?: "success" | "reverted";
  gasUsed?: string;
  events: readonly string[];
  note?: string;
}>;

export type JourneyContext = {
  deployment: Deployment;
  publicClient: PublicClient;
  wallet: (role: Role) => WalletClient;
  onTransactionBroadcast?: (observation: Readonly<{
    hash: Hex;
    role: Role;
    address: Address;
    functionName: string;
  }>) => Promise<void> | void;
  receiptObservationDelayMs?: number;
  /** Conflicting pledge produced by the signature step and consumed by commit and reveal. */
  conflict?: { pledge: MordantPledge; signature: Hex; salt: Hex; digest: Hex };
};

export type JourneyStep = Readonly<{
  id: string;
  title: string;
  detail: string;
  role: Role;
  kind: StepKind;
  contract: "vault" | "settlement" | null;
  method: string | null;
  run: (context: JourneyContext) => Promise<StepOutcome>;
}>;

const UNIT = 1_000_000n;
const SALT = `0x${"5a".repeat(32)}` as Hex;

export function createClients(deployment: Deployment) {
  const chain = { ...anvil, id: deployment.chainId };
  const transport = http(deployment.rpcUrl);
  const publicClient = createPublicClient({ chain, transport }) as PublicClient;
  const wallets = new Map<Role, WalletClient>();

  for (const role of ROLES) {
    wallets.set(
      role,
      createWalletClient({
        account: privateKeyToAccount(deployment.accounts[role].key),
        chain,
        transport,
      }),
    );
  }

  return {
    publicClient,
    wallet: (role: Role) => {
      const client = wallets.get(role);
      if (client === undefined) {
        throw new Error(`No wallet configured for role ${role}`);
      }
      return client;
    },
  };
}

export function decodeReceiptEvents(abi: Abi, receipt: TransactionReceipt): readonly string[] {
  const parsed = parseEventLogs({ abi, logs: receipt.logs });
  return parsed.map((event) => {
    const args = event.args as Record<string, unknown> | undefined;
    const summary = args === undefined
      ? ""
      : Object.entries(args)
        .slice(0, 3)
        .map(([key, value]) => `${key}=${String(value)}`)
        .join(", ");
    return summary.length === 0 ? event.eventName : `${event.eventName}(${summary})`;
  });
}

export function transactionOutcomeFromReceipt(
  abi: Abi,
  hash: Hex,
  receipt: TransactionReceipt,
): StepOutcome {
  return {
    kind: "transaction",
    hash,
    blockNumber: receipt.blockNumber.toString(),
    blockHash: receipt.blockHash,
    status: receipt.status,
    gasUsed: receipt.gasUsed.toString(),
    events: decodeReceiptEvents(abi, receipt),
  };
}

/** Sends a transaction and resolves only once its receipt is available. */
async function sendTransaction(
  context: JourneyContext,
  role: Role,
  address: Address,
  abi: Abi,
  functionName: string,
  args: readonly unknown[],
): Promise<StepOutcome> {
  const wallet = context.wallet(role);
  const account = wallet.account;
  if (account === undefined) {
    throw new Error(`Wallet for ${role} has no account`);
  }

  // Simulate first so a revert surfaces with its decoded reason instead of a bare failure.
  const { request } = await context.publicClient.simulateContract({
    address, abi, functionName, args: args as never, account,
  });
  const hash = await wallet.writeContract(request as never);
  await context.onTransactionBroadcast?.({ hash, role, address, functionName });
  if ((context.receiptObservationDelayMs ?? 0) > 0) {
    await new Promise((resolve) => setTimeout(resolve, context.receiptObservationDelayMs));
  }
  const receipt = await context.publicClient.waitForTransactionReceipt({ hash });

  if (receipt.status !== "success") {
    throw new Error(`Transaction ${hash} reverted on chain`);
  }

  return transactionOutcomeFromReceipt(abi, hash, receipt);
}

function buildPledge(
  context: JourneyContext,
  facility: Address,
  nonce: bigint,
  activeFrom: bigint,
): MordantPledge {
  const { deployment } = context;
  return {
    invoiceRoot: deployment.invoice.invoiceRoot,
    originatorSigner: deployment.accounts.originator.address,
    facility,
    obligationId: keccak256(`0x${nonce.toString(16).padStart(64, "0")}` as Hex),
    amount: BigInt(deployment.invoice.faceValue),
    currency: deployment.invoice.currency,
    activeFrom,
    activeUntil: BigInt(deployment.invoice.protectionEnd) + 1n,
    nonce,
    deadline: activeFrom + 2n * 24n * 3_600n,
    exclusive: true,
  };
}

async function signPledge(context: JourneyContext, pledge: MordantPledge): Promise<Hex> {
  const wallet = context.wallet("originator");
  const account = wallet.account;
  if (account === undefined) {
    throw new Error("Originator wallet has no account");
  }
  return wallet.signTypedData({
    account,
    domain: {
      name: MORDANT_EIP712_NAME,
      version: MORDANT_EIP712_VERSION,
      chainId: context.deployment.chainId,
      verifyingContract: context.deployment.contracts.vault,
    },
    types: mordantPledgeTypes,
    primaryType: "Pledge",
    message: pledge,
  });
}

async function currentTimestamp(context: JourneyContext): Promise<bigint> {
  const block = await context.publicClient.getBlock();
  return block.timestamp;
}

/** Local-chain time control. Only ever used against the deterministic Anvil instance. */
async function advanceTime(context: JourneyContext, seconds: bigint): Promise<void> {
  const response = await fetch(context.deployment.rpcUrl, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify([
      { jsonrpc: "2.0", id: 1, method: "evm_increaseTime", params: [Number(seconds)] },
      { jsonrpc: "2.0", id: 2, method: "evm_mine", params: [] },
    ]),
  });
  if (!response.ok) {
    throw new Error("Local chain refused the time advance");
  }
}

export const JOURNEY: readonly JourneyStep[] = Object.freeze([
  {
    id: "approve-funding",
    title: "Approve the funding transfer",
    detail: "The funder allows the vault to pull the 100-unit advance.",
    role: "holderA",
    kind: "transaction",
    contract: "settlement",
    method: "approve",
    run: (context) => sendTransaction(
      context, "holderA", context.deployment.contracts.settlement,
      context.deployment.abis.erc20, "approve",
      [context.deployment.contracts.vault, BigInt(context.deployment.invoice.advanceAmount)],
    ),
  },
  {
    id: "activate",
    title: "Finance the invoice: 90 originator / 10 reserve",
    detail: "The facility activates the vault against an originator-signed exclusive pledge.",
    role: "facilityA",
    kind: "transaction",
    contract: "vault",
    method: "activate",
    run: async (context) => {
      const now = await currentTimestamp(context);
      const pledge = buildPledge(
        context, context.deployment.accounts.facilityA.address, 1n, now - 1n,
      );
      const signature = await signPledge(context, pledge);
      return sendTransaction(
        context, "facilityA", context.deployment.contracts.vault,
        context.deployment.abis.vault, "activate",
        [
          pledge,
          signature,
          context.deployment.accounts.holderA.address,
          [context.deployment.accounts.holderA.address],
          [BigInt(context.deployment.invoice.initialUnits)],
        ],
      );
    },
  },
  {
    id: "positions",
    title: "Split the positions 60 / 40",
    detail: "Holder A transfers 40 invoice units to holder B under the live policy checks.",
    role: "holderA",
    kind: "transaction",
    contract: "vault",
    method: "transfer",
    run: (context) => sendTransaction(
      context, "holderA", context.deployment.contracts.vault,
      context.deployment.abis.vault, "transfer",
      [context.deployment.accounts.holderB.address, 40n * UNIT],
    ),
  },
  {
    id: "sign-conflict",
    title: "Sign the conflicting pledge",
    detail: "The originator signs a second exclusive pledge to facility B. EIP-712 signature, no transaction.",
    role: "originator",
    kind: "signature",
    contract: null,
    method: "signTypedData",
    run: async (context) => {
      const now = await currentTimestamp(context);
      const pledge = buildPledge(
        context, context.deployment.accounts.facilityB.address, 2n, now - 1n,
      );
      const signature = await signPledge(context, pledge);
      const digest = await context.publicClient.readContract({
        address: context.deployment.contracts.vault,
        abi: context.deployment.abis.vault,
        functionName: "hashPledge",
        args: [pledge],
      }) as Hex;

      context.conflict = { pledge, signature, salt: SALT, digest };
      return {
        kind: "signature",
        events: [`Pledge digest ${digest.slice(0, 18)}...`],
        note: "Signature only. Nothing is on chain until the commitment is sent.",
      };
    },
  },
  {
    id: "commit",
    title: "Seal the incident commitment",
    detail: "Facility B commits the hidden conflict, fixing the record date before disclosure.",
    role: "facilityB",
    kind: "transaction",
    contract: "vault",
    method: "commitConflict",
    run: (context) => {
      if (context.conflict === undefined) {
        throw new Error("Sign the conflicting pledge first");
      }
      const commitment = buildMordantConflictCommitment({
        pledgeDigest: context.conflict.digest,
        signature: context.conflict.signature,
        facility: context.deployment.accounts.facilityB.address,
        vault: context.deployment.contracts.vault,
        salt: context.conflict.salt,
      });
      return sendTransaction(
        context, "facilityB", context.deployment.contracts.vault,
        context.deployment.abis.vault, "commitConflict", [commitment],
      );
    },
  },
  {
    id: "reveal",
    title: "Reveal the conflict",
    detail: "Facility B discloses the pledge that the commitment already bound.",
    role: "facilityB",
    kind: "transaction",
    contract: "vault",
    method: "revealConflict",
    run: (context) => {
      if (context.conflict === undefined) {
        throw new Error("Sign and commit the conflicting pledge first");
      }
      return sendTransaction(
        context, "facilityB", context.deployment.contracts.vault,
        context.deployment.abis.vault, "revealConflict",
        [context.conflict.pledge, context.conflict.signature, context.conflict.salt],
      );
    },
  },
  {
    id: "cure-window",
    title: "Let the cure window expire",
    detail: "Advances the local chain past the cure deadline. LOCAL chain control, not a business action.",
    role: "deployer",
    kind: "local-chain",
    contract: null,
    method: "evm_increaseTime",
    run: async (context) => {
      await advanceTime(context, BigInt(context.deployment.invoice.curePeriod) + 60n);
      const block = await context.publicClient.getBlock();
      return {
        kind: "local-chain",
        blockNumber: block.number.toString(),
        events: [`chain time is now ${block.timestamp}`],
        note: "Anvil time control. Available only on the local chain.",
      };
    },
  },
  {
    id: "finalize",
    title: "Activate recourse: 6 / 4 entitlement",
    detail: "The unresolved conflict converts the still-required reserve into a record-date entitlement.",
    role: "facilityB",
    kind: "transaction",
    contract: "vault",
    method: "finalizeConflict",
    run: (context) => sendTransaction(
      context, "facilityB", context.deployment.contracts.vault,
      context.deployment.abis.vault, "finalizeConflict", [],
    ),
  },
  {
    id: "claim-a",
    title: "Holder A claims 6 from the reserve",
    detail: "The claim pays from the pre-funded reserve and does not touch the invoice claim.",
    role: "holderA",
    kind: "transaction",
    contract: "vault",
    method: "claimBond",
    run: (context) => sendTransaction(
      context, "holderA", context.deployment.contracts.vault,
      context.deployment.abis.vault, "claimBond", [],
    ),
  },
  {
    id: "claim-b",
    title: "Holder B claims 4 from the reserve",
    detail: "Same record date, proportional to the 40-unit position.",
    role: "holderB",
    kind: "transaction",
    contract: "vault",
    method: "claimBond",
    run: (context) => sendTransaction(
      context, "holderB", context.deployment.contracts.vault,
      context.deployment.abis.vault, "claimBond", [],
    ),
  },
  {
    id: "approve-redemption",
    title: "Buyer approves the 110 redemption",
    detail: "The receivable settles on its own track, after the recourse payout.",
    role: "buyer",
    kind: "transaction",
    contract: "settlement",
    method: "approve",
    run: (context) => sendTransaction(
      context, "buyer", context.deployment.contracts.settlement,
      context.deployment.abis.erc20, "approve",
      [context.deployment.contracts.vault, BigInt(context.deployment.invoice.faceValue)],
    ),
  },
  {
    id: "fund-redemption",
    title: "Buyer funds the 110 face value",
    detail: "Redemption escrow is funded independently of the reserve that was already paid out.",
    role: "buyer",
    kind: "transaction",
    contract: "vault",
    method: "fundRedemption",
    run: (context) => sendTransaction(
      context, "buyer", context.deployment.contracts.vault,
      context.deployment.abis.vault, "fundRedemption",
      [BigInt(context.deployment.invoice.faceValue)],
    ),
  },
  {
    id: "redeem-a",
    title: "Holder A redeems 60 units for 66",
    detail: "The invoice claim settles at face value, unaffected by the earlier 6 payout.",
    role: "holderA",
    kind: "transaction",
    contract: "vault",
    method: "redeem",
    run: (context) => sendTransaction(
      context, "holderA", context.deployment.contracts.vault,
      context.deployment.abis.vault, "redeem", [60n * UNIT],
    ),
  },
  {
    id: "redeem-b",
    title: "Holder B redeems 40 units for 44",
    detail: "The receivable is fully settled while both holders kept their recourse payout.",
    role: "holderB",
    kind: "transaction",
    contract: "vault",
    method: "redeem",
    run: (context) => sendTransaction(
      context, "holderB", context.deployment.contracts.vault,
      context.deployment.abis.vault, "redeem", [40n * UNIT],
    ),
  },
]);

export type DealRoomState = Readonly<{
  blockNumber: string;
  blockHash: Hex;
  blockTimestamp: string;
  protectionState: number;
  receivableState: number;
  totalSupply: string;
  bondLocked: string;
  entitlementAllocated: string;
  entitlementClaimed: string;
  redeemedFace: string;
  holderAUnits: string;
  holderBUnits: string;
  holderASettlement: string;
  holderBSettlement: string;
  originatorSettlement: string;
  vaultSettlement: string;
  holderABondClaimed: boolean;
  holderBBondClaimed: boolean;
  pendingConflict: Readonly<{
    facility: Address;
    committedAt: string;
    revealDeadline: string;
    cureDeadline: string;
    conflictingPledgeDigest: Hex;
  }>;
}>;

/** Re-reads everything the deal room displays straight from the contracts. */
export async function readDealRoomState(
  context: JourneyContext,
  atBlockNumber?: bigint,
): Promise<DealRoomState> {
  const { deployment, publicClient } = context;
  const vault = { address: deployment.contracts.vault, abi: deployment.abis.vault } as const;
  const token = { address: deployment.contracts.settlement, abi: deployment.abis.erc20 } as const;
  const block = atBlockNumber === undefined
    ? await publicClient.getBlock()
    : await publicClient.getBlock({ blockNumber: atBlockNumber });
  if (block.hash === null) {
    throw new Error(`Block ${block.number} is not finalized enough to identify.`);
  }
  const blockNumber = block.number;

  const read = (functionName: string, args: readonly unknown[] = []) =>
    publicClient.readContract({ ...vault, functionName, args: args as never, blockNumber });
  const balance = (address: Address) =>
    publicClient.readContract({ ...token, functionName: "balanceOf", args: [address], blockNumber });

  const [
    protectionState, receivableState, totalSupply, bondLocked, entitlementAllocated,
    entitlementClaimed, redeemedFace, holderAUnits, holderBUnits,
    holderASettlement, holderBSettlement, originatorSettlement, vaultSettlement,
    holderABondClaimed, holderBBondClaimed, pendingConflict,
  ] = await Promise.all([
    read("protectionState"), read("receivableState"), read("totalSupply"), read("bondLocked"),
    read("entitlementAllocated"), read("entitlementClaimed"), read("redeemedFace"),
    read("balanceOf", [deployment.accounts.holderA.address]),
    read("balanceOf", [deployment.accounts.holderB.address]),
    balance(deployment.accounts.holderA.address),
    balance(deployment.accounts.holderB.address),
    balance(deployment.accounts.originator.address),
    balance(deployment.contracts.vault),
    read("bondClaimedBy", [deployment.accounts.holderA.address]),
    read("bondClaimedBy", [deployment.accounts.holderB.address]),
    read("pendingConflict"),
  ]);

  const pending = pendingConflict as readonly [
    Hex, Address, bigint, bigint, bigint, bigint, bigint, bigint, Hex, Address,
  ];

  return Object.freeze({
    blockNumber: blockNumber.toString(),
    blockHash: block.hash,
    blockTimestamp: block.timestamp.toString(),
    protectionState: Number(protectionState),
    receivableState: Number(receivableState),
    totalSupply: String(totalSupply),
    bondLocked: String(bondLocked),
    entitlementAllocated: String(entitlementAllocated),
    entitlementClaimed: String(entitlementClaimed),
    redeemedFace: String(redeemedFace),
    holderAUnits: String(holderAUnits),
    holderBUnits: String(holderBUnits),
    holderASettlement: String(holderASettlement),
    holderBSettlement: String(holderBSettlement),
    originatorSettlement: String(originatorSettlement),
    vaultSettlement: String(vaultSettlement),
    holderABondClaimed: Boolean(holderABondClaimed),
    holderBBondClaimed: Boolean(holderBBondClaimed),
    pendingConflict: Object.freeze({
      facility: pending[1],
      committedAt: pending[5].toString(),
      revealDeadline: pending[6].toString(),
      cureDeadline: pending[7].toString(),
      conflictingPledgeDigest: pending[8],
    }),
  });
}

export function formatUnits6(value: string): string {
  const raw = BigInt(value);
  return `${raw / UNIT}.${(raw % UNIT).toString().padStart(6, "0")}`;
}
