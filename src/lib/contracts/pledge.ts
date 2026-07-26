import {
  encodeAbiParameters,
  hashTypedData,
  keccak256,
  type Address,
  type Hex,
} from "viem";

export const MORDANT_EIP712_NAME = "Mordant" as const;
export const MORDANT_EIP712_VERSION = "1" as const;

export const mordantPledgeTypes = {
  Pledge: [
    { name: "invoiceRoot", type: "bytes32" },
    { name: "originatorSigner", type: "address" },
    { name: "facility", type: "address" },
    { name: "obligationId", type: "bytes32" },
    { name: "amount", type: "uint256" },
    { name: "currency", type: "bytes32" },
    { name: "activeFrom", type: "uint64" },
    { name: "activeUntil", type: "uint64" },
    { name: "nonce", type: "uint256" },
    { name: "deadline", type: "uint64" },
    { name: "exclusive", type: "bool" },
  ],
} as const;

export type MordantPledge = Readonly<{
  invoiceRoot: Hex;
  originatorSigner: Address;
  facility: Address;
  obligationId: Hex;
  amount: bigint;
  currency: Hex;
  activeFrom: bigint;
  activeUntil: bigint;
  nonce: bigint;
  deadline: bigint;
  exclusive: boolean;
}>;

export function hashMordantPledge(input: Readonly<{
  chainId: number;
  vault: Address;
  pledge: MordantPledge;
}>): Hex {
  return hashTypedData({
    domain: {
      name: MORDANT_EIP712_NAME,
      version: MORDANT_EIP712_VERSION,
      chainId: input.chainId,
      verifyingContract: input.vault,
    },
    types: mordantPledgeTypes,
    primaryType: "Pledge",
    message: input.pledge,
  });
}

/** Mirrors MordantInvoiceVault.conflictCommitment without needing an RPC round trip. */
export function buildMordantConflictCommitment(input: Readonly<{
  pledgeDigest: Hex;
  signature: Hex;
  facility: Address;
  vault: Address;
  salt: Hex;
}>): Hex {
  return keccak256(encodeAbiParameters(
    [
      { name: "pledgeDigest", type: "bytes32" },
      { name: "signatureHash", type: "bytes32" },
      { name: "facility", type: "address" },
      { name: "vault", type: "address" },
      { name: "salt", type: "bytes32" },
    ],
    [
      input.pledgeDigest,
      keccak256(input.signature),
      input.facility,
      input.vault,
      input.salt,
    ],
  ));
}
