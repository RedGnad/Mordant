import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { getAddress, hashTypedData, keccak256, toHex, type Hex } from "viem";
import { privateKeyToAccount } from "viem/accounts";

import {
  BRIDGE_ENVIRONMENT,
  BridgeExecutionError,
  createBridgeExecutor,
  defaultSigner,
  loadRecourseDemoConfiguration,
  parseRecourseDemoConfiguration,
  validateRecourseDemoConfiguration,
  readBridgeConfiguration,
  readBridgeRecord,
  type AdapterReader,
  type AdapterState,
  type PrepareInput,
  type Signer,
} from "./bridge-executor";
import { SUPERSEDED_ADAPTER_ADDRESS, type VerifiedGovernedRelease } from "./governed-recourse-bridge";

/**
 * What the executor has to be worth.
 *
 * It holds the only key that can authorize an on-chain release, so the properties
 * under test are: it fails closed without configuration, it refuses to sign for
 * anything but the adapter that pins the governed authority, it never produces two
 * different authorizations for one governed result, and the key never appears
 * anywhere it could be read.
 */

const HANDOFF = JSON.parse(
  readFileSync("docs/evidence/runtime-contract-handoff-2026-08-06.json", "utf8"),
) as {
  adapter: Record<string, string | number>;
  governedResult: Record<string, string | boolean>;
  encodingVector: { payload: Record<string, string | boolean> };
};

/** Test-only key. Never used anywhere but here, and never the real attestor. */
const TEST_KEY = `0x${"11".repeat(32)}` as Hex;
const TEST_ACCOUNT = privateKeyToAccount(TEST_KEY);
const OTHER_KEY = `0x${"22".repeat(32)}` as Hex;

const V2_ADDRESS = HANDOFF.adapter.address as `0x${string}`;
const V2_CHAIN = HANDOFF.adapter.chainId as number;
const CVI = "0xCFFA4cbF5117718EB7fC0dE2E13E07ce75B840aB" as const;
const HOLDER_A = HANDOFF.encodingVector.payload.holderA as `0x${string}`;
const HOLDER_B = HANDOFF.encodingVector.payload.holderB as `0x${string}`;
const NEGATIVE_CONTROL = "0x981F6E0Ea94f45fDB8ee7680DC862212E3C720e0" as const;
const UNCONTROLLED_APASS = "0x911F99f424D47F08a15fcC771e94dcc2f7252B02" as const;
const governed = HANDOFF.governedResult as Record<string, string>;

function release(overrides: Partial<VerifiedGovernedRelease> = {}): VerifiedGovernedRelease {
  return {
    runId: governed.runId,
    fheCaseId: governed.fheCaseId as `sha256:${string}`,
    caseBindingDigest: governed.caseBindingDigest as `sha256:${string}`,
    assetIdentity: governed.assetIdentityDigest as `sha256:${string}`,
    governedResultDigest: governed.governedResultDigest as `sha256:${string}`,
    resultCiphertextDigest: governed.resultCiphertextDigest as `sha256:${string}`,
    participantArtifactDigests: [
      governed.participantArtifactDigestA as `sha256:${string}`,
      governed.participantArtifactDigestB as `sha256:${string}`,
    ],
    circuitDigest: governed.circuitDigest as `sha256:${string}`,
    parameterFingerprint: governed.parameterFingerprint as `sha256:${string}`,
    releaseAuthorityId: governed.releaseAuthorityId as `sha256:${string}`,
    releaseMode: "governed-decryptor-v1",
    conflict: true,
    ...overrides,
  };
}

function adapterState(overrides: Partial<AdapterState> = {}): AdapterState {
  return Object.freeze({
    address: V2_ADDRESS,
    chainId: V2_CHAIN,
    settlementToken: HANDOFF.adapter.settlementToken as `0x${string}`,
    cviVerifier: CVI,
    // The stub reports what the canonical configuration names, so the drift check passes.
    // The test signer stands in for the attestor, so signing can be exercised.
    attestor: TEST_ACCOUNT.address,
    facility: HANDOFF.adapter.facility as `0x${string}`,
    assetIdentityDigest: HANDOFF.adapter.assetIdentityDigest as Hex,
    expectedGovernedReleaseAuthorityId: HANDOFF.adapter.expectedGovernedReleaseAuthorityId as Hex,
    releaseMode: HANDOFF.adapter.releaseMode as Hex,
    circuitHash: HANDOFF.adapter.circuitHash as Hex,
    parameterFingerprint: HANDOFF.adapter.parameterFingerprint as Hex,
    availableReserve: 4_000n,
    domainSeparator: HANDOFF.adapter.domainSeparator as Hex,
    roleHolder: 4,
    ...overrides,
  });
}

type ReaderOptions = {
  state?: Partial<AdapterState>;
  eligible?: (account: string) => boolean;
  consumed?: boolean;
  simulateError?: Error;
  digestOverride?: Hex;
};

function reader(options: ReaderOptions = {}): AdapterReader & { calls: string[] } {
  const calls: string[] = [];
  const state = adapterState(options.state);
  return {
    calls,
    readAdapterState: async () => { calls.push("state"); return state; },
    isEligible: async (_verifier, account) => {
      calls.push(`eligible:${account}`);
      return options.eligible === undefined ? true : options.eligible(account);
    },
    hashRelease: async (payload) => {
      calls.push("hashRelease");
      return options.digestOverride ?? hashTypedData({
        domain: payload.domain, types: payload.types,
        primaryType: payload.primaryType, message: payload.message,
      });
    },
    resultConsumed: async () => { calls.push("resultConsumed"); return options.consumed === true; },
    simulate: async () => {
      calls.push("simulate");
      if (options.simulateError !== undefined) throw options.simulateError;
    },
  };
}

function environment(overrides: Record<string, string | undefined> = {}) {
  return {
    MORDANT_MONAD_RPC_URL: "https://rpc.invalid",
    [BRIDGE_ENVIRONMENT.adapterAddress]: V2_ADDRESS,
    [BRIDGE_ENVIRONMENT.attestorPrivateKey]: TEST_KEY,
    ...overrides,
  };
}

/** The committed canonical configuration, parsed exactly as production parses it. */
const CANONICAL = JSON.parse(
  readFileSync("docs/evidence/recourse-v2-demo-config-2026-08-06.json", "utf8"),
) as Record<string, unknown>;

function canonicalWith(mutate: (draft: Record<string, unknown>) => void) {
  const draft = JSON.parse(JSON.stringify(CANONICAL)) as Record<string, unknown>;
  mutate(draft);
  return draft;
}

/**
 * The canonical configuration with the attestor pointed at the test key.
 *
 * Production requires the configured attestor to equal the adapter immutable, and
 * that check is exercised separately. Here the stub adapter reports the test
 * signer, so the configuration must name the same address or the drift check
 * would, correctly, refuse every prepare.
 */
const TEST_CANONICAL = canonicalWith((d) => {
  (d.bridgeAttestor as Record<string, unknown>).address = TEST_ACCOUNT.address;
});

function prepareInput(overrides: Partial<PrepareInput> = {}): PrepareInput {
  return {
    release: release(),
    demo: parseRecourseDemoConfiguration(TEST_CANONICAL),
    nonce: 1n,
    issuedAt: 1_785_000_000,
    expiry: 1_785_003_600,
    governedSignatureVerified: true,
    crossReferencesVerified: true,
    ...overrides,
  };
}

function temporaryRoot() {
  return mkdtempSync(join(tmpdir(), "mordant-bridge-"));
}

async function rejectsCode(promise: Promise<unknown>, code: string) {
  await assert.rejects(promise, (error: unknown) => {
    assert.ok(error instanceof BridgeExecutionError, `expected a typed refusal, got ${String(error)}`);
    assert.equal(error.code, code);
    return true;
  });
}

function throwsCode(fn: () => unknown, code: string) {
  assert.throws(fn, (error: unknown) => {
    assert.ok(error instanceof BridgeExecutionError);
    assert.equal(error.code, code);
    return true;
  });
}

// ------------------------------------------------------------------ configuration

test("no key configured fails closed", () => {
  throwsCode(
    () => readBridgeConfiguration(environment({ [BRIDGE_ENVIRONMENT.attestorPrivateKey]: undefined })),
    "ATTESTOR_KEY_NOT_CONFIGURED",
  );
});

test("no adapter configured fails closed", () => {
  throwsCode(
    () => readBridgeConfiguration(environment({ [BRIDGE_ENVIRONMENT.adapterAddress]: undefined })),
    "ADAPTER_NOT_CONFIGURED",
  );
});

test("the superseded adapter is refused at configuration time", () => {
  throwsCode(
    () => readBridgeConfiguration(environment({ [BRIDGE_ENVIRONMENT.adapterAddress]: SUPERSEDED_ADAPTER_ADDRESS })),
    "SUPERSEDED_ADAPTER",
  );
});

test("the signer address is derived from the key, and the key never serializes", () => {
  const configuration = readBridgeConfiguration(environment());
  assert.equal(configuration.signerAddress, TEST_ACCOUNT.address);
  const serialized = JSON.stringify(configuration);
  assert.equal(serialized.includes(TEST_KEY.slice(2)), false, "the private key must never serialize");
  assert.equal(serialized.includes("[redacted]"), true);
});

test("submission stays disarmed unless explicitly armed", () => {
  assert.equal(readBridgeConfiguration(environment()).submitArmed, false);
  assert.equal(readBridgeConfiguration(environment({ [BRIDGE_ENVIRONMENT.armSubmit]: "1" })).submitArmed, true);
});

// ------------------------------------------------------------------ demo configuration

test("the canonical configuration parses to the committed values", () => {
  const parsed = parseRecourseDemoConfiguration(CANONICAL);
  assert.equal(parsed.holderA, getAddress(HOLDER_A));
  assert.equal(parsed.holderB, getAddress(HOLDER_B));
  assert.equal(parsed.payoutA, 2_400n);
  assert.equal(parsed.payoutB, 1_600n);
  assert.equal(parsed.payoutA + parsed.payoutB, parsed.availableReserve);
  assert.equal(parsed.chainId, 10_143);
  assert.equal(getAddress(parsed.excluded.negativeControl), getAddress(NEGATIVE_CONTROL));
  assert.equal(getAddress(parsed.excluded.uncontrolledApassWallet), getAddress(UNCONTROLLED_APASS));
  assert.doesNotThrow(() => validateRecourseDemoConfiguration(parsed));
});

test("every required section is mandatory", () => {
  for (const [section, code] of [
    ["network", "DEMO_CONFIG_SECTION"], ["contracts", "DEMO_CONFIG_SECTION"],
    ["participants", "DEMO_CONFIG_SECTION"], ["settlement", "DEMO_CONFIG_SECTION"],
    ["facility", "DEMO_CONFIG_SECTION"], ["bridgeAttestor", "DEMO_CONFIG_SECTION"],
    ["aUsdcTransferPolicyReadbacks", "DEMO_CONFIG_SECTION"], ["walletControl", "DEMO_CONFIG_SECTION"],
  ] as const) {
    throwsCode(() => parseRecourseDemoConfiguration(canonicalWith((d) => { delete d[section]; })), code);
  }
  throwsCode(() => parseRecourseDemoConfiguration(canonicalWith((d) => { (d.network as Record<string, unknown>).chainId = "10143"; })), "DEMO_CONFIG_CHAIN");
});

test("the negative control and the uncontrolled A-Pass wallet cannot be participants", () => {
  // A valid A-Pass is not custody: the uncontrolled wallet passes every policy
  // gate on-chain and still must never hold a role.
  for (const excluded of [NEGATIVE_CONTROL, UNCONTROLLED_APASS]) {
    throwsCode(
      () => validateRecourseDemoConfiguration(parseRecourseDemoConfiguration(canonicalWith((d) => {
        ((d.participants as Record<string, Record<string, unknown>>).holderB).address = excluded;
      }))),
      "DEMO_CONFIG_EXCLUDED_PARTICIPANT",
    );
  }
});

test("the configuration gates are enforced, not merely recorded", () => {
  const cases: ReadonlyArray<readonly [string, (d: Record<string, unknown>) => void]> = [
    ["DEMO_CONFIG_DUPLICATE", (d) => { ((d.participants as Record<string, Record<string, unknown>>).holderB).address = HOLDER_A; }],
    ["DEMO_CONFIG_INELIGIBLE", (d) => { ((d.participants as Record<string, Record<string, unknown>>).holderA).roleHolderEligible = false; }],
    ["DEMO_CONFIG_TRANSFER_REFUSED", (d) => { ((d.aUsdcTransferPolicyReadbacks as Record<string, Record<string, unknown>>).adapterToHolderB).allowed = false; }],
    ["DEMO_CONFIG_INSOLVENT", (d) => { ((d.settlement as Record<string, Record<string, unknown>>).reserve).solvent = false; }],
    ["DEMO_CONFIG_RESERVE", (d) => { (d.settlement as Record<string, unknown>).payoutAAtomic = "9999"; }],
  ];
  for (const [code, mutate] of cases) {
    throwsCode(() => validateRecourseDemoConfiguration(parseRecourseDemoConfiguration(canonicalWith(mutate))), code);
  }
});

test("the committed configuration on disk loads and passes every gate", () => {
  const loaded = loadRecourseDemoConfiguration(process.cwd());
  assert.equal(loaded.holderA, getAddress(HOLDER_A));
  assert.equal(loaded.payoutA + loaded.payoutB, 4_000n);
});

test("a missing committed demo configuration fails closed", () => {
  const root = temporaryRoot();
  try {
    throwsCode(() => loadRecourseDemoConfiguration(root), "DEMO_CONFIG_MISSING");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

// ------------------------------------------------------------------ preparation refusals

test("a signer that is not the adapter attestor is refused", async () => {
  const configuration = readBridgeConfiguration(environment({ [BRIDGE_ENVIRONMENT.attestorPrivateKey]: OTHER_KEY }));
  const root = temporaryRoot();
  try {
    const executor = createBridgeExecutor({ configuration, reader: reader(), runRoot: root });
    await rejectsCode(executor.prepare(prepareInput()), "SIGNER_MISMATCH");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("a wrong adapter or chain is refused", async () => {
  const configuration = readBridgeConfiguration(environment());
  const root = temporaryRoot();
  try {
    const other = "0x0000000000000000000000000000000000000009" as const;
    let executor = createBridgeExecutor({ configuration, reader: reader(), runRoot: root });
    await rejectsCode(
      executor.prepare(prepareInput({ demo: parseRecourseDemoConfiguration(canonicalWith((d) => {
        (d.bridgeAttestor as Record<string, unknown>).address = TEST_ACCOUNT.address;
        ((d.contracts as Record<string, Record<string, unknown>>).adapter).address = other;
      })) })),
      "ADAPTER_MISMATCH",
    );
    executor = createBridgeExecutor({ configuration, reader: reader({ state: { chainId: 1 } }), runRoot: root });
    await rejectsCode(executor.prepare(prepareInput()), "CHAIN_MISMATCH");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("an ineligible participant is refused, and both are checked", async () => {
  const configuration = readBridgeConfiguration(environment());
  const root = temporaryRoot();
  try {
    const only = reader({ eligible: (account) => account.toLowerCase() === HOLDER_A.toLowerCase() });
    const executor = createBridgeExecutor({ configuration, reader: only, runRoot: root });
    await rejectsCode(executor.prepare(prepareInput()), "PARTICIPANT_INELIGIBLE");
    assert.ok(only.calls.includes(`eligible:${HOLDER_A}`), "holder A must be checked");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("holder A and holder B are both eligible on the happy path", async () => {
  const configuration = readBridgeConfiguration(environment());
  const root = temporaryRoot();
  try {
    const both = reader();
    const executor = createBridgeExecutor({ configuration, reader: both, runRoot: root });
    await executor.prepare(prepareInput());
    assert.ok(both.calls.includes(`eligible:${HOLDER_A}`));
    assert.ok(both.calls.includes(`eligible:${HOLDER_B}`));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("the same wallet in both roles is refused", async () => {
  const configuration = readBridgeConfiguration(environment());
  const root = temporaryRoot();
  try {
    const executor = createBridgeExecutor({ configuration, reader: reader(), runRoot: root });
    await rejectsCode(
      executor.prepare(prepareInput({
        demo: { ...parseRecourseDemoConfiguration(TEST_CANONICAL), holderB: getAddress(HOLDER_A) },
      })),
      // Caught by the configuration gate, which runs before any chain read.
      "DEMO_CONFIG_DUPLICATE",
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("a wrong authority, circuit or parameter pin is refused", async () => {
  const configuration = readBridgeConfiguration(environment());
  const root = temporaryRoot();
  try {
    for (const mutation of [
      { expectedGovernedReleaseAuthorityId: `0x${"9".repeat(64)}` as Hex },
      { circuitHash: keccak256(toHex("mordant.identity-full-fhe-256")) },
      { parameterFingerprint: keccak256(toHex("mordant.bgv.identity-full-fhe-256.n15/v1")) },
      { assetIdentityDigest: `0x${"9".repeat(64)}` as Hex },
    ]) {
      const executor = createBridgeExecutor({ configuration, reader: reader({ state: mutation }), runRoot: root });
      await rejectsCode(executor.prepare(prepareInput()), "ADAPTER_INCOMPATIBLE");
    }
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("payouts beyond the available reserve are refused", async () => {
  const configuration = readBridgeConfiguration(environment());
  const root = temporaryRoot();
  try {
    const executor = createBridgeExecutor({ configuration, reader: reader({ state: { availableReserve: 100n } }), runRoot: root });
    await rejectsCode(executor.prepare(prepareInput()), "INSUFFICIENT_RESERVE");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("an already consumed governed result is refused", async () => {
  const configuration = readBridgeConfiguration(environment());
  const root = temporaryRoot();
  try {
    const executor = createBridgeExecutor({ configuration, reader: reader({ consumed: true }), runRoot: root });
    await rejectsCode(executor.prepare(prepareInput()), "RESULT_CONSUMED");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("a digest the adapter does not agree with is refused", async () => {
  const configuration = readBridgeConfiguration(environment());
  const root = temporaryRoot();
  try {
    const executor = createBridgeExecutor({
      configuration, runRoot: root,
      reader: reader({ digestOverride: `0x${"9".repeat(64)}` as Hex }),
    });
    await rejectsCode(executor.prepare(prepareInput()), "DIGEST_MISMATCH");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("an unverified governed result cannot be prepared", async () => {
  const configuration = readBridgeConfiguration(environment());
  const root = temporaryRoot();
  try {
    const executor = createBridgeExecutor({ configuration, reader: reader(), runRoot: root });
    await assert.rejects(
      executor.prepare(prepareInput({ governedSignatureVerified: false as never })),
      /governed signature must be verified/u,
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

// ------------------------------------------------------------------ signing and idempotence

test("an exact retry reuses the one authorization and never signs twice", async () => {
  const configuration = readBridgeConfiguration(environment());
  const root = temporaryRoot();
  try {
    let signatures = 0;
    const signer: Signer = async (input) => { signatures += 1; return defaultSigner(input); };
    const executor = createBridgeExecutor({ configuration, reader: reader(), runRoot: root, signer });
    const first = await executor.sign(await executor.prepare(prepareInput()));
    const retry = await executor.sign(await executor.prepare(prepareInput()));
    assert.equal(first.newlySigned, true);
    assert.equal(retry.newlySigned, false);
    assert.equal(retry.signature, first.signature);
    assert.equal(retry.record.intentDigest, first.record.intentDigest);
    assert.equal(signatures, 1, "one governed result must produce one signature");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("a changed payload for the same governed result is refused", async () => {
  const configuration = readBridgeConfiguration(environment());
  const root = temporaryRoot();
  try {
    const executor = createBridgeExecutor({ configuration, reader: reader(), runRoot: root });
    await executor.sign(await executor.prepare(prepareInput()));
    // Same governed result, different payouts: a second, different authorization.
    const changed = await executor.prepare(prepareInput({
      demo: parseRecourseDemoConfiguration(canonicalWith((d) => {
        (d.bridgeAttestor as Record<string, unknown>).address = TEST_ACCOUNT.address;
        (d.settlement as Record<string, unknown>).payoutAAtomic = "2500";
        (d.settlement as Record<string, unknown>).payoutBAtomic = "1500";
      })),
    }));
    await rejectsCode(executor.sign(changed), "CHANGED_PAYLOAD");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("the durable record preserves the payload identity and never the key", async () => {
  const configuration = readBridgeConfiguration(environment());
  const root = temporaryRoot();
  try {
    const executor = createBridgeExecutor({ configuration, reader: reader(), runRoot: root });
    const signed = await executor.sign(await executor.prepare(prepareInput()));
    const stored = readBridgeRecord(root, signed.record.governedResultDigest);
    assert.notEqual(stored, null);
    assert.equal(stored?.typedDataDigest, signed.prepared.typedDataDigest);
    assert.equal(stored?.intentDigest, signed.prepared.intentDigest);
    assert.equal(stored?.submitted, false);
    assert.equal(stored?.transactionHash, null);
    const raw = readFileSync(join(root, "bridge", `${signed.record.governedResultDigest.slice(2)}.json`), "utf8");
    assert.equal(raw.includes(TEST_KEY.slice(2)), false, "the durable record must never carry the key");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("the signature verifies as the adapter attestor", async () => {
  const configuration = readBridgeConfiguration(environment());
  const root = temporaryRoot();
  try {
    const executor = createBridgeExecutor({ configuration, reader: reader(), runRoot: root });
    const prepared = await executor.prepare(prepareInput());
    const signed = await executor.sign(prepared);
    const { recoverTypedDataAddress } = await import("viem");
    const recovered = await recoverTypedDataAddress({
      domain: prepared.payload.domain, types: prepared.payload.types,
      primaryType: prepared.payload.primaryType, message: prepared.payload.message,
      signature: signed.signature,
    });
    assert.equal(getAddress(recovered), getAddress(prepared.adapter.attestor));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

// ------------------------------------------------------------------ simulation and receipt

test("simulation runs before any write and surfaces a revert", async () => {
  const configuration = readBridgeConfiguration(environment());
  const root = temporaryRoot();
  try {
    const ok = reader();
    let executor = createBridgeExecutor({ configuration, reader: ok, runRoot: root });
    const prepared = await executor.prepare(prepareInput());
    const signed = await executor.sign(prepared);
    await executor.simulate(prepared, signed.signature);
    assert.ok(ok.calls.includes("simulate"));

    executor = createBridgeExecutor({
      configuration, runRoot: root,
      reader: reader({ simulateError: new Error("InsufficientReserve") }),
    });
    await assert.rejects(executor.simulate(prepared, signed.signature), /InsufficientReserve/u);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("this package refuses to broadcast", async () => {
  const configuration = readBridgeConfiguration(environment({ [BRIDGE_ENVIRONMENT.armSubmit]: "1" }));
  const root = temporaryRoot();
  try {
    const executor = createBridgeExecutor({ configuration, reader: reader(), runRoot: root });
    const signed = await executor.sign(await executor.prepare(prepareInput()));
    await rejectsCode(executor.submit(signed), "SUBMIT_NOT_ENABLED");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("a receipt is reconciled against the authorization it belongs to", async () => {
  const configuration = readBridgeConfiguration(environment());
  const root = temporaryRoot();
  try {
    const executor = createBridgeExecutor({ configuration, reader: reader(), runRoot: root });
    const signed = await executor.sign(await executor.prepare(prepareInput()));
    const receipt = executor.reconcileReceipt(signed, {
      transactionHash: `0x${"ab".repeat(32)}`, status: "success", to: V2_ADDRESS,
    });
    assert.equal(receipt.status, "success");
    assert.equal(receipt.conflict, true);
    assert.equal(receipt.governedResultDigest, signed.record.governedResultDigest);
    // A receipt for another contract is not this authorization's receipt.
    throwsCode(
      () => executor.reconcileReceipt(signed, {
        transactionHash: `0x${"ab".repeat(32)}`, status: "success", to: SUPERSEDED_ADAPTER_ADDRESS,
      }),
      "RECEIPT_ADAPTER",
    );
    throwsCode(() => executor.reconcileReceipt(signed, { transactionHash: "0x00", status: "success", to: V2_ADDRESS }), "RECEIPT_HASH");
    throwsCode(
      () => executor.reconcileReceipt(signed, { transactionHash: `0x${"ab".repeat(32)}`, status: "unknown", to: V2_ADDRESS }),
      "RECEIPT_STATUS",
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("the facility address is read-only context and is never signed", async () => {
  const configuration = readBridgeConfiguration(environment());
  const root = temporaryRoot();
  try {
    const executor = createBridgeExecutor({ configuration, reader: reader(), runRoot: root });
    const prepared = await executor.prepare(prepareInput());
    assert.equal(prepared.adapter.facility, HANDOFF.adapter.facility);
    // It is context the executor reconciles against, not a signed field.
    assert.equal(
      JSON.stringify(prepared.payload.message, (_k, v) => (typeof v === "bigint" ? v.toString() : v))
        .toLowerCase().includes(String(HANDOFF.adapter.facility).toLowerCase()),
      false,
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("the executor source carries no private key literal", () => {
  const source = readFileSync("src/lib/protection/bridge-executor.ts", "utf8");
  assert.equal(/0x[0-9a-fA-F]{64}(?![0-9a-fA-F])/u.test(source), false, "no 32-byte literal may appear");
  assert.equal(source.includes("server-only"), true, "the executor must be server-only");
});

test("a configuration that disagrees with the deployed adapter is refused", async () => {
  const configuration = readBridgeConfiguration(environment());
  const root = temporaryRoot();
  try {
    // The real canonical configuration names the production attestor, which is
    // not the test signer the stub adapter reports.
    const executor = createBridgeExecutor({ configuration, reader: reader(), runRoot: root });
    await rejectsCode(
      executor.prepare(prepareInput({ demo: parseRecourseDemoConfiguration(CANONICAL) })),
      "CONFIGURATION_DRIFT",
    );
    for (const [section, key] of [["facility", "address"], ["contracts", "verifier"]] as const) {
      const drifted = parseRecourseDemoConfiguration(canonicalWith((d) => {
        (d.bridgeAttestor as Record<string, unknown>).address = TEST_ACCOUNT.address;
        if (section === "facility") (d.facility as Record<string, unknown>)[key] = "0x0000000000000000000000000000000000000007";
        else (d.contracts as Record<string, unknown>)[key] = "0x0000000000000000000000000000000000000007";
      }));
      await rejectsCode(executor.prepare(prepareInput({ demo: drifted })), "CONFIGURATION_DRIFT");
    }
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
