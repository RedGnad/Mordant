import assert from "node:assert/strict";
import test from "node:test";

import {
  CCP_CHAIN_ID,
  CCP_GATE_ADDRESS,
  CCP_PUBLIC_TEST_HOLDER,
  CCP_VALIDATOR_ADDRESS,
  CcpEligibilityError,
  normalizeHolderAddress,
  readCcpRpcUrl,
  verifyCcpEligibility,
  type CcpReader,
  type EnvironmentLike,
} from "./ccp-eligibility";

const ELIGIBLE = CCP_PUBLIC_TEST_HOLDER;
const CONTROL = "0x981F6E0Ea94f45fDB8ee7680DC862212E3C720e0";

/** A reader that answers exactly like the measured Monad testnet deployment. */
function reader(overrides: Partial<CcpReader> = {}): CcpReader {
  return {
    getChainId: async () => CCP_CHAIN_ID,
    getBlockNumber: async () => 51_150_000n,
    isRegistered: async () => true,
    complianceVerify: async (_gate, holder) => holder.toLowerCase() === ELIGIBLE.toLowerCase(),
    ...overrides,
  };
}

async function refusal(promise: Promise<unknown>): Promise<CcpEligibilityError> {
  try {
    await promise;
  } catch (error) {
    assert.ok(error instanceof CcpEligibilityError);
    return error;
  }
  throw new Error("expected a refusal");
}

test("a known eligible holder is admitted", async () => {
  const result = await verifyCcpEligibility(ELIGIBLE, reader());
  assert.equal(result.eligible, true);
  assert.equal(result.chainId, CCP_CHAIN_ID);
  assert.equal(result.validatorAddress, CCP_VALIDATOR_ADDRESS);
  assert.equal(result.gateAddress, CCP_GATE_ADDRESS);
  assert.equal(result.holderAddress, ELIGIBLE);
  assert.equal(result.observedBlock, 51_150_000);
});

test("the control holder is refused without an error", async () => {
  const result = await verifyCcpEligibility(CONTROL, reader());
  assert.equal(result.eligible, false);
  assert.equal(result.holderAddress, CONTROL);
});

test("a malformed holder address is rejected before any network call", async () => {
  let reached = false;
  const spy = reader({ getChainId: async () => { reached = true; return CCP_CHAIN_ID; } });
  for (const candidate of ["", "0x", "not-an-address", "0x1234", 42, null, undefined, `${ELIGIBLE}00`]) {
    const error = await refusal(verifyCcpEligibility(candidate, spy));
    assert.equal(error.code, "ADDRESS");
    assert.equal(error.status, 400);
  }
  assert.equal(reached, false, "no RPC call may happen for a malformed address");
});

test("a lowercase address is normalized to its checksummed form", () => {
  assert.equal(normalizeHolderAddress(ELIGIBLE.toLowerCase()), ELIGIBLE);
  assert.equal(normalizeHolderAddress(`  ${ELIGIBLE}  `), ELIGIBLE);
});

test("a wrong chain refuses without consulting the validator", async () => {
  let consulted = false;
  const error = await refusal(verifyCcpEligibility(ELIGIBLE, reader({
    getChainId: async () => 1,
    isRegistered: async () => { consulted = true; return true; },
  })));
  assert.equal(error.code, "CHAIN");
  assert.equal(consulted, false);
});

test("an unregistered gate refuses without asking for a verdict", async () => {
  let asked = false;
  const error = await refusal(verifyCcpEligibility(ELIGIBLE, reader({
    isRegistered: async () => false,
    complianceVerify: async () => { asked = true; return true; },
  })));
  assert.equal(error.code, "GATE");
  assert.equal(asked, false);
});

test("an RPC failure never leaks the upstream message", async () => {
  const secretish = "https://rpc.internal/KEY-should-not-appear";
  for (const override of [
    { getChainId: async () => { throw new Error(secretish); } },
    { isRegistered: async () => { throw new Error(secretish); } },
    { complianceVerify: async () => { throw new Error(secretish); } },
    { getBlockNumber: async () => { throw new Error(secretish); } },
  ] as Array<Partial<CcpReader>>) {
    const error = await refusal(verifyCcpEligibility(ELIGIBLE, reader(override)));
    assert.equal(error.code, "UPSTREAM");
    assert.equal(error.status, 503);
    assert.ok(!error.message.includes("KEY-should-not-appear"));
    assert.ok(!error.message.includes("rpc.internal"));
  }
});

test("the RPC url must be configured and https", () => {
  const configured: EnvironmentLike = { MONAD_RPC_URL: "https://testnet-rpc.monad.xyz" };
  assert.equal(readCcpRpcUrl(configured), "https://testnet-rpc.monad.xyz/");

  const overridden: EnvironmentLike = { MORDANT_MONAD_RPC_URL: "https://a.example", MONAD_RPC_URL: "https://b.example" };
  assert.equal(readCcpRpcUrl(overridden), "https://a.example/");

  const rejected: readonly EnvironmentLike[] = [
    {},
    { MONAD_RPC_URL: "" },
    { MONAD_RPC_URL: "not a url" },
    { MONAD_RPC_URL: "http://insecure.example" },
  ];
  for (const environment of rejected) {
    assert.throws(() => readCcpRpcUrl(environment), CcpEligibilityError);
  }
});

test("the projection carries no rpc detail and no extra members", async () => {
  const result = await verifyCcpEligibility(ELIGIBLE, reader());
  assert.deepEqual(Object.keys(result).sort(), [
    "chainId", "eligible", "gateAddress", "holderAddress", "observedBlock", "schemaVersion", "validatorAddress",
  ]);
  assert.ok(!JSON.stringify(result).includes("monad.xyz"));
});
