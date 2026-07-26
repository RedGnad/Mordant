import assert from "node:assert/strict";
import { test } from "node:test";

import { buildMordantConflictCommitment, hashMordantPledge, type MordantPledge } from "./pledge";

const VAULT = "0x1111111111111111111111111111111111111111";
const FACILITY = "0x2222222222222222222222222222222222222222";
const ORIGINATOR = "0x3333333333333333333333333333333333333333";
const ROOT = `0x${"44".repeat(32)}` as const;
const SALT = `0x${"55".repeat(32)}` as const;
const SIGNATURE = `0x${"66".repeat(65)}` as const;

const PLEDGE: MordantPledge = Object.freeze({
  invoiceRoot: ROOT,
  originatorSigner: ORIGINATOR,
  facility: FACILITY,
  obligationId: `0x${"77".repeat(32)}`,
  amount: 110_000_000n,
  currency: `0x${Buffer.from("USD").toString("hex").padEnd(64, "0")}`,
  activeFrom: 1_000n,
  activeUntil: 2_000n,
  nonce: 7n,
  deadline: 1_900n,
  exclusive: true,
});

test("pledge digest is domain-separated by chain and vault", () => {
  const digest = hashMordantPledge({ chainId: 10_143, vault: VAULT, pledge: PLEDGE });
  assert.notEqual(digest, hashMordantPledge({ chainId: 1, vault: VAULT, pledge: PLEDGE }));
  assert.notEqual(digest, hashMordantPledge({
    chainId: 10_143,
    vault: "0x8888888888888888888888888888888888888888",
    pledge: PLEDGE,
  }));
});

test("hidden commitment binds the exact signature and facility", () => {
  const pledgeDigest = hashMordantPledge({ chainId: 10_143, vault: VAULT, pledge: PLEDGE });
  const commitment = buildMordantConflictCommitment({
    pledgeDigest,
    signature: SIGNATURE,
    facility: FACILITY,
    vault: VAULT,
    salt: SALT,
  });
  assert.notEqual(commitment, buildMordantConflictCommitment({
    pledgeDigest,
    signature: `0x${"99".repeat(65)}`,
    facility: FACILITY,
    vault: VAULT,
    salt: SALT,
  }));
  assert.notEqual(commitment, buildMordantConflictCommitment({
    pledgeDigest,
    signature: SIGNATURE,
    facility: "0x9999999999999999999999999999999999999999",
    vault: VAULT,
    salt: SALT,
  }));
});
