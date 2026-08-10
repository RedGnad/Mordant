import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { encodeAbiParameters, encodeEventTopics, hashTypedData, type Hex } from "viem";
import { privateKeyToAccount } from "viem/accounts";

import {
  BRIDGE_ENVIRONMENT,
  BRIDGE_EXECUTION_SCHEMA,
  BRIDGE_SIMULATION_MAX_AGE_SECONDS,
  ADAPTER_ABI,
  BridgeExecutionError,
  bridgeRecordPath,
  createBridgeExecutor,
  createBridgeExecutorForTest,
  pollBridgeReceipt,
  readBridgeConfiguration,
  readCanonicalAdapterV2Compatibility,
  readBridgeRecord,
  type AdapterReader,
  type AdapterState,
  type PrepareInput,
  type SignedBridge,
} from "./bridge-executor";
import {
  AdapterCompatibilityError,
  loadCanonicalRecourseBridgeArtifacts,
  parseCanonicalRecourseBridgeArtifacts,
  retryReadOnly,
  type CanonicalRecourseBridgeArtifacts,
} from "./adapter-compatibility";
import { bridgeRunId, type GovernedBridgePayload } from "./governed-recourse-bridge";
import { digestToBytes32 } from "./participant-authorization";
import {
  SETTLEMENT_AUTHORIZED,
  SETTLEMENT_PROFILE_SCHEMA,
  deriveSettlementAuthorization,
  deriveSettlementPlan,
  settlementProfileDigest,
  type SettlementProfile,
} from "./settlement-authority";

const CONFIG = JSON.parse(readFileSync("docs/evidence/recourse-v2-demo-config-2026-08-06.json", "utf8")) as Record<string, unknown>;
const HANDOFF = JSON.parse(readFileSync("docs/evidence/runtime-contract-handoff-2026-08-06.json", "utf8")) as Record<string, unknown>;
const CONFLICT_EVIDENCE = JSON.parse(readFileSync("docs/evidence/conflicting-pledge-protection/conflict.json", "utf8")) as unknown;

/** Test-only key; production code never carries this value or accepts one as input. */
const TEST_KEY = `0x${"11".repeat(32)}` as Hex;
const OTHER_KEY = `0x${"22".repeat(32)}` as Hex;
const TEST_ACCOUNT = privateKeyToAccount(TEST_KEY);
const OTHER_ACCOUNT = privateKeyToAccount(OTHER_KEY);
const TEST_EVIDENCE = Object.freeze({ unit: "verified-evidence" });

function clone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

/** A complete canonical fixture with only the public bridge attestor changed. */
function canonicalFixture(): CanonicalRecourseBridgeArtifacts {
  const config = clone(CONFIG);
  const handoff = clone(HANDOFF);
  ((config.bridgeAttestor as Record<string, unknown>).address) = TEST_ACCOUNT.address;
  ((config.privilegedAddressesKeptSeparate as Record<string, unknown>).bridgeAttestor) = TEST_ACCOUNT.address;
  ((handoff.canonicalConfiguration as Record<string, unknown>).bridgeAttestor) = TEST_ACCOUNT.address;
  ((handoff.adapter as Record<string, unknown>).attestor) = TEST_ACCOUNT.address;
  ((handoff.expectedBridgeSigner as Record<string, unknown>).address) = TEST_ACCOUNT.address;
  return parseCanonicalRecourseBridgeArtifacts(config, handoff);
}

const TEST_CANONICAL = canonicalFixture();
const LIVE_CANONICAL = loadCanonicalRecourseBridgeArtifacts();

function configuration(canonical: CanonicalRecourseBridgeArtifacts = TEST_CANONICAL) {
  return readBridgeConfiguration({
    [BRIDGE_ENVIRONMENT.rpcUrl]: "https://rpc.invalid",
    [BRIDGE_ENVIRONMENT.adapterAddress]: canonical.adapter.address,
  });
}

function stateFor(
  canonical: CanonicalRecourseBridgeArtifacts,
  overrides: Partial<AdapterState> = {},
): AdapterState {
  const adapter = canonical.adapter;
  return Object.freeze({
    address: adapter.address,
    chainId: adapter.chainId,
    codeHash: adapter.codeHash,
    runtimeBytes: adapter.runtimeBytes,
    settlementToken: adapter.settlementToken,
    cviVerifier: adapter.cviVerifier,
    attestor: adapter.attestor,
    facility: adapter.facility,
    assetIdentityDigest: adapter.assetIdentityDigest,
    expectedGovernedReleaseAuthorityId: adapter.releaseAuthorityId,
    releaseMode: adapter.releaseMode,
    circuitHash: adapter.circuitHash,
    parameterFingerprint: adapter.parameterFingerprint,
    availableReserve: adapter.availableReserve,
    openReserved: adapter.openReserved,
    entitledUnpaid: adapter.entitledUnpaid,
    tokenBalance: adapter.tokenBalance,
    solvent: adapter.solvent,
    domainSeparator: adapter.domainSeparator,
    roleHolder: adapter.roleHolder,
    roleFacility: adapter.roleFacility,
    ...overrides,
  });
}

const OWNER = "0x79C53151315FaD9163f75a65A8Bd4D04a10e1e45" as const;
const CURE_WINDOW_SECONDS = 600;
const RUNTIME_CODE = `0x${"60".repeat(64)}` as const;

type ReaderOptions = Readonly<{
  state?: Partial<AdapterState>;
  owner?: `0x${string}`;
  cureWindow?: number;
  runtimeCode?: `0x${string}`;
  /** Undefined means use the canonical live eligibility baseline. */
  eligibility?: (account: `0x${string}`, role: number) => boolean | undefined;
  transferAllowed?: (to: `0x${string}`, amount: bigint) => boolean;
  consumed?: boolean;
  digest?: Hex;
  failures?: Partial<Record<"state" | "eligibility" | "transfer" | "hash" | "consumed" | "simulate", number>>;
  simulateError?: Error;
}>;

function reader(
  canonical: CanonicalRecourseBridgeArtifacts = TEST_CANONICAL,
  options: ReaderOptions = {},
): AdapterReader & { calls: string[] } {
  const calls: string[] = [];
  const remaining = { ...options.failures };
  const failRead = (name: keyof NonNullable<ReaderOptions["failures"]>) => {
    calls.push(name);
    if ((remaining[name] ?? 0) > 0) {
      remaining[name] = (remaining[name] ?? 0) - 1;
      throw new Error(`${name} temporary failure`);
    }
  };
  const state = stateFor(canonical, options.state);
  return {
    calls,
    readAdapterState: async () => {
      failRead("state");
      return state;
    },
    readOwner: async () => {
      failRead("state");
      return options.owner ?? OWNER;
    },
    readCureWindow: async () => {
      failRead("state");
      return options.cureWindow ?? CURE_WINDOW_SECONDS;
    },
    readRuntimeCode: async () => {
      failRead("state");
      return options.runtimeCode ?? RUNTIME_CODE;
    },
    isEligible: async (_verifier, account, role) => {
      failRead("eligibility");
      const explicit = options.eligibility?.(account, role);
      if (explicit !== undefined) return explicit;
      return account.toLowerCase() !== canonical.configuration.participants.excluded.negativeControl.toLowerCase();
    },
    isAssetTransferAllowed: async (_verifier, _asset, _from, to, amount) => {
      failRead("transfer");
      return options.transferAllowed?.(to, amount) ?? true;
    },
    hashRelease: async (payload) => {
      failRead("hash");
      return options.digest ?? hashTypedData({
        domain: payload.domain,
        types: payload.types,
        primaryType: payload.primaryType,
        message: payload.message,
      });
    },
    resultConsumed: async () => {
      failRead("consumed");
      return options.consumed === true;
    },
    simulate: async () => {
      failRead("simulate");
      if (options.simulateError !== undefined) throw options.simulateError;
    },
  };
}

/**
 * The settlement authority the canonical fixture's paying release requires.
 *
 * Built the way a real operator must build it: a profile committing every
 * economic term, its digest taken before the result is consulted, then a plan
 * and an authorization derived from that digest and the governed Boolean. The
 * fixture's own participants and payouts are used, so the authorization matches
 * the release the executor will actually be asked to sign.
 */
function settlementFor(
  canonical: CanonicalRecourseBridgeArtifacts = TEST_CANONICAL,
  overrides: Partial<SettlementProfile> = {},
) {
  const participants = (canonical.configuration as unknown as {
    participants: { holderA: `0x${string}`; holderB: `0x${string}`; payoutA: string; payoutB: string };
  }).participants;
  const profile: SettlementProfile = Object.freeze({
    schemaVersion: SETTLEMENT_PROFILE_SCHEMA,
    profileId: "mordant.test-settlement.canonical-fixture",
    profileVersion: 1,
    caseBinding: {
      runId: canonical.release.runId,
      caseId: canonical.release.fheCaseId,
      caseBindingDigest: canonical.release.caseBindingDigest,
      protectionBindingDigest: canonical.release.caseBindingDigest,
      releaseMode: canonical.release.releaseMode,
    },
    participantConfig: { path: "docs/evidence/recourse-v2-demo-config-2026-08-06.json", sha256: "00".repeat(32) },
    committedAtUnix: 1_784_000_000,
    chainId: canonical.adapter.chainId,
    adapter: canonical.adapter.address,
    settlementToken: canonical.adapter.settlementToken,
    cviVerifier: canonical.adapter.cviVerifier,
    facility: canonical.adapter.facility,
    attestor: canonical.adapter.attestor,
    holderA: participants.holderA,
    holderB: participants.holderB,
    // The adapter state carries chain-read numerics as bigint at run time even
    // where the type says number, so every committed term is normalised here.
    payoutA: String(participants.payoutA),
    payoutB: String(participants.payoutB),
    cureWindowSeconds: Number(canonical.adapter.cureWindowSeconds),
    releaseAuthorityId: digestToBytes32(canonical.release.releaseAuthorityId),
    settlementAuthorization: SETTLEMENT_AUTHORIZED,
    ...overrides,
  });
  const committedDigest = settlementProfileDigest(profile);
  const plan = deriveSettlementPlan(profile, committedDigest, {
    governedResultDigest: digestToBytes32(canonical.release.governedResultDigest),
    runId: bridgeRunId(canonical.release.runId),
    releaseAuthorityId: profile.releaseAuthorityId,
    conflict: canonical.release.conflict,
    caseId: profile.caseBinding.caseId,
    caseBindingDigest: profile.caseBinding.caseBindingDigest,
  });
  return { plan, authorization: deriveSettlementAuthorization(plan) };
}

function input(overrides: Partial<PrepareInput> = {}): PrepareInput {
  return {
    evidence: TEST_EVIDENCE,
    nonce: 1n,
    issuedAt: 1_785_000_000,
    expiry: 1_785_003_600,
    settlement: settlementFor(),
    ...overrides,
  };
}

function temporaryRoot(): string {
  return mkdtempSync(join(tmpdir(), "mordant-bridge-"));
}

function matchingReleaseConsumedLog(signed: SignedBridge, overrides: Readonly<Record<string, unknown>> = {}) {
  const message = signed.prepared.payload.message;
  return {
    address: signed.record.adapterAddress,
    topics: encodeEventTopics({
      abi: ADAPTER_ABI,
      eventName: "ReleaseConsumed",
      args: { runId: message.runId },
    }),
    data: encodeAbiParameters(
      [{ type: "bool" }, { type: "bytes32" }],
      [message.conflict, message.governedResultDigest],
    ),
    ...overrides,
  };
}

function successfulReceipt(signed: SignedBridge, overrides: Readonly<Record<string, unknown>> = {}) {
  return {
    transactionHash: `0x${"ab".repeat(32)}`,
    status: "success",
    to: signed.record.adapterAddress,
    logs: [matchingReleaseConsumedLog(signed)],
    ...overrides,
  } as Readonly<Record<string, unknown>>;
}

async function rejectsCode(promise: Promise<unknown>, code: string): Promise<void> {
  await assert.rejects(promise, (error: unknown) => {
    assert.ok(error instanceof BridgeExecutionError, `expected BridgeExecutionError, got ${String(error)}`);
    assert.equal(error.code, code);
    return true;
  });
}

function throwsCode(action: () => unknown, code: string): void {
  assert.throws(action, (error: unknown) => {
    assert.ok(error instanceof BridgeExecutionError);
    assert.equal(error.code, code);
    return true;
  });
}

type FixtureExecutor = Readonly<{
  executor: ReturnType<typeof createBridgeExecutorForTest>;
  signatures: () => number;
}>;

function fixtureExecutor(
  runRoot: string,
  readerInput: AdapterReader = reader(),
  options: Readonly<{
    canonical?: CanonicalRecourseBridgeArtifacts;
    signerAddress?: `0x${string}`;
    sign?: (payload: GovernedBridgePayload) => Promise<Hex>;
    verifyEvidence?: (evidence: unknown, canonical: CanonicalRecourseBridgeArtifacts) => ReturnType<typeof canonicalFixture>["release"];
    now?: () => number;
  }> = {},
): FixtureExecutor {
  let calls = 0;
  const canonical = options.canonical ?? TEST_CANONICAL;
  const sign = options.sign ?? (async (payload) => {
    calls += 1;
    return TEST_ACCOUNT.signTypedData({
      domain: payload.domain,
      types: payload.types,
      primaryType: payload.primaryType,
      message: payload.message,
    });
  });
  return Object.freeze({
    executor: createBridgeExecutorForTest({
      configuration: configuration(canonical),
      reader: readerInput,
      runRoot,
      canonical,
      signerAddress: options.signerAddress ?? TEST_ACCOUNT.address,
      sign,
      verifyEvidence: options.verifyEvidence ?? ((evidence, trusted) => {
        if (evidence !== TEST_EVIDENCE) throw new Error("unit evidence rejected");
        return trusted.release;
      }),
      now: options.now,
    }),
    signatures: () => calls,
  });
}

// ------------------------------------------------------------------ configuration and canonical boundary

test("bridge configuration reads exactly the two read-only environment names", () => {
  assert.deepEqual(Object.values(BRIDGE_ENVIRONMENT).sort(), [
    "MORDANT_BRIDGE_ATTESTOR_PRIVATE_KEY",
    "MORDANT_MONAD_RPC_URL",
    "MORDANT_RECOURSE_ADAPTER_ADDRESS",
  ]);
  throwsCode(() => readBridgeConfiguration({
    MONAD_RPC_URL: "https://legacy.invalid",
    [BRIDGE_ENVIRONMENT.adapterAddress]: TEST_CANONICAL.adapter.address,
  }), "RPC_NOT_CONFIGURED");
  throwsCode(() => readBridgeConfiguration({
    [BRIDGE_ENVIRONMENT.rpcUrl]: "https://rpc.invalid",
  }), "ADAPTER_NOT_CONFIGURED");
});

test("read-only configuration never loads or serializes the attestor key", () => {
  let keyRead = false;
  const environment = {
    [BRIDGE_ENVIRONMENT.rpcUrl]: "https://rpc.invalid",
    [BRIDGE_ENVIRONMENT.adapterAddress]: TEST_CANONICAL.adapter.address,
  } as Record<string, string | undefined>;
  Object.defineProperty(environment, BRIDGE_ENVIRONMENT.attestorPrivateKey, {
    enumerable: true,
    get: () => {
      keyRead = true;
      throw new Error("key must not be read by compatibility");
    },
  });
  const config = readBridgeConfiguration(environment);
  assert.equal(keyRead, false);
  assert.equal(Object.keys(config).includes("attestorPrivateKey"), false);
  assert.equal(JSON.stringify(config).includes("PRIVATE_KEY"), false);
});

test("the production bridge verifies evidence before any compatibility read or key access", async () => {
  const root = temporaryRoot();
  let keyRead = false;
  const environment = {
    [BRIDGE_ENVIRONMENT.rpcUrl]: "https://rpc.invalid",
    [BRIDGE_ENVIRONMENT.adapterAddress]: LIVE_CANONICAL.adapter.address,
  } as Record<string, string | undefined>;
  Object.defineProperty(environment, BRIDGE_ENVIRONMENT.attestorPrivateKey, {
    get: () => {
      keyRead = true;
      throw new Error("key access is forbidden in prepare");
    },
  });
  const liveReader = reader(LIVE_CANONICAL);
  try {
    const executor = createBridgeExecutor({
      configuration: readBridgeConfiguration(environment),
      reader: liveReader,
      runRoot: root,
      environment,
    });
    await rejectsCode(executor.prepare({ ...input(), evidence: {} }), "GOVERNED_EVIDENCE");
    assert.equal(keyRead, false);
    assert.deepEqual(liveReader.calls, []);
    const prepared = await executor.prepare({
      evidence: CONFLICT_EVIDENCE,
      nonce: 1n,
      issuedAt: 1_785_000_000,
      expiry: 1_785_003_600,
    });
    assert.equal(prepared.payload.message.conflict, true);
    assert.equal(keyRead, false, "prepare must remain key-free even on valid evidence");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("the read-only report uses retained vector values and is JSON-safe without key access", async () => {
  let keyRead = false;
  const environment = {
    [BRIDGE_ENVIRONMENT.rpcUrl]: "https://rpc.invalid",
    [BRIDGE_ENVIRONMENT.adapterAddress]: LIVE_CANONICAL.adapter.address,
  } as Record<string, string | undefined>;
  Object.defineProperty(environment, BRIDGE_ENVIRONMENT.attestorPrivateKey, {
    get: () => {
      keyRead = true;
      throw new Error("key access is forbidden in a report");
    },
  });
  const report = await readCanonicalAdapterV2Compatibility(environment, reader(LIVE_CANONICAL));
  assert.equal(report.compatible, true);
  assert.equal(report.adapter.availableReserve, "4000");
  assert.equal(report.adapter.openReserved, "0");
  assert.equal(report.adapter.roleFacility, 3);
  assert.equal(report.pins.attestor, LIVE_CANONICAL.adapter.attestor);
  assert.equal(report.eligibility.facility, true);
  assert.equal(report.eligibility.negativeControl, false);
  assert.equal(report.eligibility.negativeControlCanonicalParticipant, false);
  assert.equal(report.eligibility.uncontrolledApassWallet, true);
  assert.equal(report.eligibility.uncontrolledApassWalletCanonicalParticipant, false);
  assert.equal(report.digestParity, true);
  assert.equal(report.retainedVector.nonce, "1");
  assert.equal(JSON.stringify(report).includes("signature"), false);
  assert.equal(keyRead, false);
});

// ------------------------------------------------------------------ compatibility gate

test("Adapter V2 compatibility rejects every critical drift and checks all live eligibility boundaries", async () => {
  const drifts: ReadonlyArray<readonly [string, Partial<AdapterState>, string]> = [
    ["code hash", { codeHash: `0x${"9".repeat(64)}` }, "ADAPTER_INCOMPATIBLE"],
    ["runtime length", { runtimeBytes: 1 }, "ADAPTER_INCOMPATIBLE"],
    ["authority pin", { expectedGovernedReleaseAuthorityId: `0x${"9".repeat(64)}` }, "ADAPTER_INCOMPATIBLE"],
    ["facility role", { roleFacility: 4 }, "ADAPTER_INCOMPATIBLE"],
    ["available reserve", { availableReserve: 3_999n }, "ADAPTER_INCOMPATIBLE"],
    ["open reserve", { openReserved: 1n, tokenBalance: 4_001n }, "ADAPTER_INCOMPATIBLE"],
    ["unpaid entitlement", { entitledUnpaid: 1n, tokenBalance: 4_001n }, "ADAPTER_INCOMPATIBLE"],
    ["token balance", { tokenBalance: 3_999n }, "INSOLVENT"],
    ["solvency", { solvent: false }, "INSOLVENT"],
  ];
  const root = temporaryRoot();
  try {
    for (const [_label, mutation, code] of drifts) {
      const fixture = fixtureExecutor(root, reader(TEST_CANONICAL, { state: mutation }));
      await rejectsCode(fixture.executor.prepare(input()), code);
    }
    const all = reader();
    const fixture = fixtureExecutor(root, all);
    await fixture.executor.prepare(input());
    const eligibilityCalls = all.calls.filter((call) => call === "eligibility");
    assert.equal(eligibilityCalls.length, 5, "holders, facility, negative control, and uncontrolled A-Pass wallet must all be checked");
    const ineligibleFacility = fixtureExecutor(root, reader(TEST_CANONICAL, {
      eligibility: (account, role) => (
        account.toLowerCase() === TEST_CANONICAL.adapter.facility.toLowerCase() && role === 3 ? false : undefined
      ),
    }));
    await rejectsCode(ineligibleFacility.executor.prepare(input()), "FACILITY_INELIGIBLE");
    const eligibleNegativeControl = fixtureExecutor(root, reader(TEST_CANONICAL, {
      eligibility: (account) => (
        account.toLowerCase() === TEST_CANONICAL.configuration.participants.excluded.negativeControl.toLowerCase() ? true : undefined
      ),
    }));
    await rejectsCode(eligibleNegativeControl.executor.prepare(input()), "NEGATIVE_CONTROL_ELIGIBLE");
    const ineligibleUncontrolledApass = fixtureExecutor(root, reader(TEST_CANONICAL, {
      eligibility: (account) => (
        account.toLowerCase() === TEST_CANONICAL.configuration.participants.excluded.uncontrolledApassWallet.toLowerCase() ? false : undefined
      ),
    }));
    await rejectsCode(ineligibleUncontrolledApass.executor.prepare(input()), "UNCONTROLLED_APASS_INELIGIBLE");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("caller literals cannot replace verified release, canonical participants, or payouts", async () => {
  const root = temporaryRoot();
  try {
    const fixture = fixtureExecutor(root);
    const forged = {
      ...input(),
      release: { conflict: false, payoutA: 0, payoutB: 0 },
      demo: { holderA: "0x0000000000000000000000000000000000000001", payoutA: "999999" },
      governedSignatureVerified: true,
      crossReferencesVerified: true,
    } as unknown as PrepareInput;
    const prepared = await fixture.executor.prepare(forged);
    assert.equal(prepared.payload.message.conflict, true);
    assert.equal(prepared.payload.message.holderA, TEST_CANONICAL.configuration.participants.holderA);
    assert.equal(prepared.payload.message.payoutA, 2_400n);
    await rejectsCode(fixture.executor.prepare(input({ evidence: { forged: true } })), "GOVERNED_EVIDENCE");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

// ------------------------------------------------------------------ opaque state, simulation, and persistence

test("a paying release is refused before any key access when settlement authority is absent", async () => {
  const root = temporaryRoot();
  try {
    const fixture = fixtureExecutor(root);
    const prepared = await fixture.executor.prepare(input({ settlement: undefined }));
    await rejectsCode(fixture.executor.simulate(prepared), "SETTLEMENT_NOT_AUTHORIZED");
    // The refusal precedes the signer, so no candidate signature can exist.
    assert.equal(fixture.signatures(), 0, "the attestor is never reached without settlement authority");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("a paying release is refused when the settlement authority does not match it", async () => {
  const root = temporaryRoot();
  try {
    const attacker = "0x9999999999999999999999999999999999999999" as const;
    const other = "0x1111111111111111111111111111111111111111" as const;
    for (const [overrides, code] of [
      [{ holderB: attacker }, "SETTLEMENT_HOLDER_MISMATCH"],
      [{ payoutA: "4000" }, "SETTLEMENT_PAYOUT_MISMATCH"],
      [{ adapter: other }, "SETTLEMENT_ADAPTER_MISMATCH"],
    ] as const) {
      const fixture = fixtureExecutor(root);
      const prepared = await fixture.executor.prepare(input({ settlement: settlementFor(TEST_CANONICAL, overrides) }));
      await rejectsCode(fixture.executor.simulate(prepared), code);
      assert.equal(fixture.signatures(), 0, `${code} must be refused before signing`);
    }
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("only a fresh executor-issued simulation can release an authorization", async () => {
  const root = temporaryRoot();
  try {
    const fixture = fixtureExecutor(root);
    const prepared = await fixture.executor.prepare(input());
    await rejectsCode(fixture.executor.sign(prepared as never), "SIMULATION_REQUIRED");
    await rejectsCode(fixture.executor.simulate({ ...prepared }), "PREPARED_UNTRUSTED");
    assert.equal(fixture.signatures(), 0, "no candidate signature before a valid simulation request");

    const simulated = await fixture.executor.simulate(prepared);
    assert.equal(fixture.signatures(), 1);
    assert.equal(JSON.stringify(simulated).includes("0x" + "11".repeat(32)), false, "a permit never carries the key");
    assert.equal(Object.hasOwn(simulated, "signature"), false, "a permit never carries a candidate signature");

    const signed = await fixture.executor.sign(simulated);
    assert.equal(signed.newlySigned, true);
    assert.equal(fixture.signatures(), 1, "signing never retries or recreates the candidate");
    await rejectsCode(fixture.executor.sign(simulated), "SIMULATION_REQUIRED");
    throwsCode(() => fixture.executor.reconcileReceipt({ ...signed }, {
      transactionHash: `0x${"ab".repeat(32)}`,
      status: "success",
      to: TEST_CANONICAL.adapter.address,
    }), "SIGNED_UNTRUSTED");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("simulation failure cannot leak or persist a candidate signature", async () => {
  const root = temporaryRoot();
  try {
    const fixture = fixtureExecutor(root, reader(TEST_CANONICAL, { simulateError: new Error("revert") }));
    const prepared = await fixture.executor.prepare(input());
    await rejectsCode(fixture.executor.simulate(prepared), "SIMULATION_FAILED");
    assert.equal(fixture.signatures(), 1, "one private candidate was needed for eth_call");
    assert.equal(readBridgeRecord(root, prepared.payload.message.governedResultDigest), null);
    await rejectsCode(fixture.executor.sign({
      schemaVersion: BRIDGE_EXECUTION_SCHEMA,
      intentDigest: prepared.intentDigest,
      typedDataDigest: prepared.typedDataDigest,
      signerAddress: prepared.signerAddress,
      simulatedAtUnix: 1_785_000_001,
    }), "SIMULATION_REQUIRED");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("a simulation permit expires and an attestor mismatch is refused before candidate creation", async () => {
  const root = temporaryRoot();
  try {
    let clock = 1_785_000_001;
    const fixture = fixtureExecutor(root, reader(), { now: () => clock });
    const simulated = await fixture.executor.simulate(await fixture.executor.prepare(input()));
    clock += BRIDGE_SIMULATION_MAX_AGE_SECONDS + 1;
    await rejectsCode(fixture.executor.sign(simulated), "SIMULATION_STALE");

    let invoked = 0;
    const mismatched = fixtureExecutor(root, reader(), {
      signerAddress: OTHER_ACCOUNT.address,
      sign: async () => {
        invoked += 1;
        return `0x${"00".repeat(65)}` as Hex;
      },
    });
    await rejectsCode(mismatched.executor.simulate(await mismatched.executor.prepare(input())), "SIGNER_MISMATCH");
    assert.equal(invoked, 0);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("only read-only calls retry, bounded at three attempts", async () => {
  const root = temporaryRoot();
  try {
    const retried = reader(TEST_CANONICAL, { failures: { state: 2, hash: 2, simulate: 2 } });
    const fixture = fixtureExecutor(root, retried);
    const simulated = await fixture.executor.simulate(await fixture.executor.prepare(input()));
    assert.equal(retried.calls.filter((call) => call === "state").length, 3);
    assert.equal(retried.calls.filter((call) => call === "hash").length, 3);
    assert.equal(retried.calls.filter((call) => call === "simulate").length, 3);
    assert.equal(fixture.signatures(), 1, "the signer is never retried");
    await fixture.executor.sign(simulated);
    assert.equal(fixture.signatures(), 1, "durable persistence does not trigger signing retries");

    let receiptAttempts = 0;
    const receipt = await pollBridgeReceipt(async () => {
      receiptAttempts += 1;
      if (receiptAttempts < 3) throw new Error("not indexed");
      return { ok: true };
    });
    assert.deepEqual(receipt, { ok: true });
    assert.equal(receiptAttempts, 3);
    await assert.rejects(retryReadOnly(async () => ({ never: true }), 4), (error: unknown) => {
      assert.ok(error instanceof AdapterCompatibilityError);
      assert.equal(error.code, "READ_RETRY_BOUND");
      return true;
    });
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("concurrent simulation permits publish one create-only authorization record", async () => {
  const root = temporaryRoot();
  try {
    const first = fixtureExecutor(root);
    const second = fixtureExecutor(root);
    const [firstPermit, secondPermit] = await Promise.all([
      first.executor.simulate(await first.executor.prepare(input())),
      second.executor.simulate(await second.executor.prepare(input())),
    ]);
    const [one, two] = await Promise.all([
      first.executor.sign(firstPermit),
      second.executor.sign(secondPermit),
    ]);
    assert.equal(Number(one.newlySigned) + Number(two.newlySigned), 1);
    assert.equal(one.record.intentDigest, two.record.intentDigest);
    const stored = readBridgeRecord(root, one.record.governedResultDigest);
    assert.notEqual(stored, null);
    assert.equal(stored!.intentDigest, one.record.intentDigest);
    const source = readFileSync("src/lib/protection/bridge-executor.ts", "utf8");
    assert.equal(source.includes("linkSync(temporary, path)"), true, "record publication must be create-only");
    assert.equal(source.includes("writeDurableJsonAtomic"), false, "rename-based overwrite must not return");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("durable records are exact and an EEXIST record is cross-checked before reuse", async () => {
  const root = temporaryRoot();
  try {
    const first = fixtureExecutor(root);
    const signed = await first.executor.sign(await first.executor.simulate(await first.executor.prepare(input())));
    const digest = signed.record.governedResultDigest;
    const path = bridgeRecordPath(root, digest);

    writeFileSync(path, `${JSON.stringify({ ...signed.record, unexpected: true })}\n`, "utf8");
    throwsCode(() => readBridgeRecord(root, digest), "RECORD_INVALID");

    writeFileSync(path, `${JSON.stringify({ ...signed.record, structHash: `0x${"34".repeat(32)}` })}\n`, "utf8");
    const conflict = fixtureExecutor(root);
    const permit = await conflict.executor.simulate(await conflict.executor.prepare(input()));
    await rejectsCode(conflict.executor.sign(permit), "CHANGED_PAYLOAD");

    const forgedSignature = await OTHER_ACCOUNT.signTypedData({
      domain: signed.prepared.payload.domain,
      types: signed.prepared.payload.types,
      primaryType: signed.prepared.payload.primaryType,
      message: signed.prepared.payload.message,
    });
    writeFileSync(path, `${JSON.stringify({ ...signed.record, signature: forgedSignature })}\n`, "utf8");
    const invalidSigner = fixtureExecutor(root);
    const invalidSignerPermit = await invalidSigner.executor.simulate(await invalidSigner.executor.prepare(input()));
    await rejectsCode(invalidSigner.executor.sign(invalidSignerPermit), "RECORD_SIGNATURE");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("submission fails closed and receipt reconciliation requires the exact adapter event", async () => {
  const root = temporaryRoot();
  try {
    const fixture = fixtureExecutor(root);
    const signed = await fixture.executor.sign(await fixture.executor.simulate(await fixture.executor.prepare(input())));
    await rejectsCode(fixture.executor.submit(signed), "SUBMISSION_DISABLED");
    await rejectsCode(fixture.executor.submit({} as SignedBridge), "SUBMISSION_DISABLED");
    const receipt = fixture.executor.reconcileReceipt(signed, successfulReceipt(signed));
    assert.equal(receipt.status, "success");
    assert.equal(receipt.conflict, true);
    throwsCode(() => fixture.executor.reconcileReceipt(signed, {
      transactionHash: `0x${"ab".repeat(32)}`,
      status: "success",
      to: TEST_CANONICAL.adapter.address,
    }), "RECEIPT_EVENT");
    throwsCode(() => fixture.executor.reconcileReceipt(signed, successfulReceipt(signed, {
      logs: [matchingReleaseConsumedLog(signed, { address: "0x0000000000000000000000000000000000000001" })],
    })), "RECEIPT_EVENT");
    throwsCode(() => fixture.executor.reconcileReceipt(signed, successfulReceipt(signed, {
      logs: [matchingReleaseConsumedLog(signed, {
        data: encodeAbiParameters(
          [{ type: "bool" }, { type: "bytes32" }],
          [false, signed.record.governedResultDigest],
        ),
      })],
    })), "RECEIPT_EVENT");
    const reverted = fixture.executor.reconcileReceipt(signed, {
      transactionHash: `0x${"ab".repeat(32)}`,
      status: "reverted",
      to: TEST_CANONICAL.adapter.address,
    });
    assert.deepEqual(reverted, {
      transactionHash: `0x${"ab".repeat(32)}`,
      status: "reverted",
      runId: null,
      conflict: null,
      governedResultDigest: null,
    });
    throwsCode(() => fixture.executor.reconcileReceipt(signed, successfulReceipt(signed, {
      to: "0x0000000000000000000000000000000000000001",
    })), "RECEIPT_ADAPTER");
    const source = readFileSync("src/lib/protection/bridge-executor.ts", "utf8");
    assert.equal(source.includes("sendTransaction("), false, "the bridge module must not own a broadcaster");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("canonical parser failures remain typed and contain no signing material", () => {
  const bad = clone(CONFIG);
  ((bad.participants as Record<string, Record<string, unknown>>).holderB).address =
    ((bad.participants as Record<string, Record<string, unknown>>).holderA).address;
  assert.throws(() => parseCanonicalRecourseBridgeArtifacts(bad, HANDOFF), (error: unknown) => {
    assert.ok(error instanceof AdapterCompatibilityError);
    assert.equal(error.code, "CANONICAL_PARTICIPANTS");
    return true;
  });
});
