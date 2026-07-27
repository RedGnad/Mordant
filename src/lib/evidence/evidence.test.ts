import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import {
  DEFAULT_CLEANVERSE_MONAD_TARGETS,
  MONAD_TESTNET_CHAIN_ID,
  PROTECTED_DOCUMENTATION_UNAVAILABLE,
  buildDocumentationRecords,
} from "./cleanverse-monad";
import {
  REVERT_PREFIX,
  createFixtureTransport,
  createMonadFixtureChain,
  fixtureBytecodeWithSelectors,
} from "./fixtures";
import {
  WrongNetworkError,
  bytecodeContainsSelector,
  observeDeployedCode,
  pinBlock,
} from "./observe";
import {
  DOC_DEPLOYMENT_SKEW,
  UNSTATED_VERSION,
  parseEvidenceReport,
  renderEvidenceArtifacts,
} from "./report";
import {
  SecretLeakError,
  assertNoSecretLeak,
  findSecretLeaks,
  redactSecrets,
} from "./redaction";
import {
  ForbiddenRpcMethodError,
  assertReadOnlyRpcMethod,
  createReadOnlyRpcClient,
} from "./rpc";
import { runCleanverseMonadEvidence } from "./run";
import { ALLOWLIST_FILE, loadAllowlist } from "./secret-scan";

const DOCUMENTATION_UNAVAILABLE = Object.freeze({
  protectedDocsReachable: false,
  protectedDocsHttpStatus: 403,
  chainConfigReachable: true,
  consultedAt: "2026-07-27T00:00:00.000Z",
});

function baseRunOptions() {
  return {
    mode: "fixture" as const,
    generatedAt: "2026-07-27T00:00:00.000Z",
    repositoryCommit: "test-commit",
    documentation: DOCUMENTATION_UNAVAILABLE,
  };
}

// --- network gate ----------------------------------------------------------------------------

test("the gate accepts Monad testnet and pins one block for the whole run", async () => {
  const report = await runCleanverseMonadEvidence({
    ...baseRunOptions(),
    transport: createFixtureTransport(),
  });

  assert.equal(report.network.chainId, MONAD_TESTNET_CHAIN_ID);
  assert.equal(report.network.blockNumber, "48645464");
  assert.ok(report.network.blockHash.startsWith("0x"));
  assert.ok(report.onchainObservations.length > 0);
  for (const observation of report.onchainObservations) {
    assert.equal(observation.blockNumber, report.network.blockNumber);
    assert.equal(observation.blockHash, report.network.blockHash);
    assert.equal(observation.classification, "READ-ONLY");
  }
});

test("the gate refuses to read anything on the wrong network", async () => {
  const transport = createFixtureTransport({
    overrides: { chainId: 84_532 },
  });

  let businessReads = 0;
  const counting = async (method: string, params: readonly unknown[]) => {
    if (method !== "eth_chainId") {
      businessReads += 1;
    }
    return transport(method, params);
  };

  await assert.rejects(
    runCleanverseMonadEvidence({ ...baseRunOptions(), transport: counting }),
    (error: unknown) => {
      assert.ok(error instanceof WrongNetworkError);
      assert.match(error.message, /BLOCKED — WRONG NETWORK/);
      return true;
    },
  );
  assert.equal(businessReads, 0, "no business read may follow a wrong-network answer");
});

// --- read-only transport ---------------------------------------------------------------------

test("the transport refuses every state-changing JSON-RPC method", async () => {
  for (const method of [
    "eth_sendTransaction",
    "eth_sendRawTransaction",
    "eth_sign",
    "eth_signTransaction",
    "personal_sign",
    "anvil_impersonateAccount",
    "hardhat_setBalance",
    "evm_mine",
    "debug_traceCall",
    "miner_start",
  ]) {
    assert.throws(() => assertReadOnlyRpcMethod(method), ForbiddenRpcMethodError, method);
  }

  let reached = false;
  const client = createReadOnlyRpcClient(async () => {
    reached = true;
    return "0x1";
  });
  await assert.rejects(client("eth_sendRawTransaction", ["0xdead"]), ForbiddenRpcMethodError);
  assert.equal(reached, false, "a write method must never reach the underlying transport");
});

test("the transport allows only the documented read methods", () => {
  for (const method of ["eth_chainId", "eth_call", "eth_getCode", "eth_getStorageAt"]) {
    assert.doesNotThrow(() => assertReadOnlyRpcMethod(method));
  }
  assert.throws(() => assertReadOnlyRpcMethod("eth_unknownMethod"), ForbiddenRpcMethodError);
});

// --- address and proxy observations ------------------------------------------------------------

test("an address without bytecode is reported as such, not silently skipped", async () => {
  const chain = createMonadFixtureChain();
  const transport = createFixtureTransport({ chain });
  const client = createReadOnlyRpcClient(transport);
  const block = await pinBlock(client, "monad-testnet", MONAD_TESTNET_CHAIN_ID);

  const code = await observeDeployedCode(
    client,
    "0x000000000000000000000000000000000000c0de",
    block,
  );
  assert.equal(code.hasBytecode, false);
  assert.equal(code.codeHash, null);
  assert.equal(code.implementation, null);
});

test("a proxy resolves its EIP-1967 implementation and hashes both code blobs", async () => {
  const client = createReadOnlyRpcClient(createFixtureTransport());
  const block = await pinBlock(client, "monad-testnet", MONAD_TESTNET_CHAIN_ID);

  const code = await observeDeployedCode(
    client,
    DEFAULT_CLEANVERSE_MONAD_TARGETS.aTokenFactoryProxy,
    block,
  );
  assert.equal(code.hasBytecode, true);
  assert.equal(code.implementation, "0x21084e6ca8d65d3f1a3d27cac9c1abe06f1582ea");
  assert.ok(code.codeHash?.startsWith("0x"));
  assert.ok(code.implementationCodeHash?.startsWith("0x"));
  assert.notEqual(code.codeHash, code.implementationCodeHash);
});

// --- selector evidence ---------------------------------------------------------------------

test("a documented selector present in the dispatch table is detected", () => {
  const code = fixtureBytecodeWithSelectors(["0xeff21872", "0xef84b94a"]);
  assert.equal(bytecodeContainsSelector(code, "0xeff21872"), true);
  assert.equal(bytecodeContainsSelector(code, "0xef84b94a"), true);
});

test("a documented selector absent from the dispatch table is detected", () => {
  const code = fixtureBytecodeWithSelectors(["0xef84b94a"]);
  assert.equal(bytecodeContainsSelector(code, "0xeff21872"), false);
  assert.throws(() => bytecodeContainsSelector(code, "0xbad"), /4-byte selector/);
});

test("a factory missing the launch selector is classified as a version skew", async () => {
  const chain = createMonadFixtureChain();
  const staleImplementation = "0x31759eff15291a5e36bb5625b55c49107dc0ee71";
  const transport = createFixtureTransport({
    overrides: {
      accounts: {
        ...chain.accounts,
        [DEFAULT_CLEANVERSE_MONAD_TARGETS.aTokenFactoryProxy.toLowerCase()]: {
          code: fixtureBytecodeWithSelectors([]),
          implementation: staleImplementation,
        },
        [staleImplementation]: {
          // The older implementation exposes only the eight-argument launch surface.
          code: fixtureBytecodeWithSelectors(["0xef84b94a"]),
        },
      },
    },
  });

  const report = await runCleanverseMonadEvidence({ ...baseRunOptions(), transport });
  const factory = report.comparisons.find(
    (comparison) => comparison.topic === "Monad A-Token factory launch ABI",
  );
  assert.equal(factory?.comparisonStatus, DOC_DEPLOYMENT_SKEW);
  assert.equal(factory?.observedImplementation, staleImplementation);
  assert.ok(report.conclusions.some((conclusion) => conclusion.classification === "BLOCKED"));
});

test("a factory exposing the launch selector is not reported as a skew", async () => {
  const report = await runCleanverseMonadEvidence({
    ...baseRunOptions(),
    transport: createFixtureTransport(),
  });
  const factory = report.comparisons.find(
    (comparison) => comparison.topic === "Monad A-Token factory launch ABI",
  );
  assert.notEqual(factory?.comparisonStatus, DOC_DEPLOYMENT_SKEW);
  // Presence of the selector still does not prove the documented ABI.
  assert.equal(factory?.comparisonStatus, "NOT PROVEN");
});

// --- transfer policy -------------------------------------------------------------------------

test("a policy that answers by reverting is reported as a refusal, not as a broken call", async () => {
  const chain = createMonadFixtureChain();
  const policy = "0x36489be45fa84f70a0c2bdb11d824be608cb12dd";
  const transport = createFixtureTransport({
    overrides: {
      calls: {
        ...chain.calls,
        [`${policy}:0x6d62a4fe`]:
          `${REVERT_PREFIX}0x8a4e1859000000000000000000000000ac0893567d43c3e7e6e35a72803df05416c1f20d`,
      },
    },
  });

  const report = await runCleanverseMonadEvidence({ ...baseRunOptions(), transport });
  const comparison = report.comparisons.find(
    (candidate) => candidate.topic.startsWith("Transfer policy"),
  );
  assert.equal(comparison?.comparisonStatus, "BLOCKED");
  assert.match(comparison?.observedSignatureOrBehavior ?? "", /ComplianceFailed\(address\)/);
  assert.match(comparison?.impactOnMordant ?? "", /fails? closed/);
  assert.ok(report.missingEvidence.some((missing) =>
    /compliance rule accepts/.test(missing.topic)));

  const observations = report.onchainObservations.filter(
    (observation) => observation.callOrSelector.startsWith("canTransfer("),
  );
  assert.equal(observations.length, 3, "each probed tuple must be recorded");
  for (const observation of observations) {
    assert.match(observation.result, /reverted with ComplianceFailed\(address\) \[0x8a4e1859\]/);
  }
});

test("a policy that answers with a boolean is not reported as blocked", async () => {
  const report = await runCleanverseMonadEvidence({
    ...baseRunOptions(),
    transport: createFixtureTransport(),
  });
  const comparison = report.comparisons.find(
    (candidate) => candidate.topic.startsWith("Transfer policy"),
  );
  assert.equal(comparison?.comparisonStatus, "NOT PROVEN");
});

// --- documentation availability --------------------------------------------------------------

test("an unreadable protected page yields NOT PROVEN, never a repository substitute", () => {
  const records = buildDocumentationRecords(
    DOCUMENTATION_UNAVAILABLE,
    DEFAULT_CLEANVERSE_MONAD_TARGETS,
  );
  const gated = records.filter(
    (record) => record.documentationVersion === PROTECTED_DOCUMENTATION_UNAVAILABLE,
  );
  assert.ok(gated.length >= 8);
  for (const record of gated) {
    assert.equal(record.documentedBehavior, PROTECTED_DOCUMENTATION_UNAVAILABLE);
    assert.match(record.documentationVersionSource, /403|no session access code/);
    // A page path must never carry a session credential.
    assert.doesNotMatch(record.pagePath, /[?&](token|access_code|code|api[-_]?key)=/i);
  }
});

test("a source that states no version is recorded as UNSTATED, never inferred", () => {
  const records = buildDocumentationRecords(
    DOCUMENTATION_UNAVAILABLE,
    DEFAULT_CLEANVERSE_MONAD_TARGETS,
  );
  const chainConfig = records.find((record) => record.pagePath.includes("query_chain_config"));
  assert.equal(chainConfig?.documentationVersion, UNSTATED_VERSION);
  assert.match(chainConfig?.documentationVersionSource ?? "", /no version field/);
});

test("recorded v5.6 facts are emitted only when a consultation is asserted", async () => {
  const withoutDocs = buildDocumentationRecords(
    DOCUMENTATION_UNAVAILABLE,
    DEFAULT_CLEANVERSE_MONAD_TARGETS,
  );
  assert.ok(withoutDocs.every((record) =>
    record.documentationVersion === PROTECTED_DOCUMENTATION_UNAVAILABLE
    || record.documentationVersion === UNSTATED_VERSION));

  const withDocs = buildDocumentationRecords(
    { ...DOCUMENTATION_UNAVAILABLE, protectedDocsConsultedAt: "2026-07-27" },
    DEFAULT_CLEANVERSE_MONAD_TARGETS,
  );
  const gated = withDocs.filter((record) => record.documentationVersion === "v5.6");
  assert.ok(gated.length >= 8, "every recorded topic must carry the documented version");
  for (const record of gated) {
    assert.equal(record.consultedAt, "2026-07-27");
    assert.match(record.documentationVersionSource, /version-history table/);
    assert.notEqual(record.documentedBehavior, PROTECTED_DOCUMENTATION_UNAVAILABLE);
    // A recorded fact must never smuggle a credential or a session URL into an artifact.
    assert.doesNotMatch(record.pagePath, /[?&](token|access_code|code|api[-_]?key)=/i);
  }

  // The documentation must state what it does NOT cover, so gaps stay visible.
  const policy = gated.find((record) => record.topic === "Custody and transfer policy");
  assert.match(policy?.limitations ?? "", /No Solidity policy interface is published/);
  const roles = gated.find((record) => record.topic.startsWith("Mint and burn"));
  assert.match(roles?.limitations ?? "", /BURN authority is never documented/);
});

test("every documentation-dependent comparison stays unproven without the docs", async () => {
  const report = await runCleanverseMonadEvidence({
    ...baseRunOptions(),
    transport: createFixtureTransport(),
  });
  const apass = report.comparisons.find(
    (comparison) => comparison.topic.startsWith("A-Pass isValidAPass"),
  );
  assert.equal(apass?.documentedVersion, PROTECTED_DOCUMENTATION_UNAVAILABLE);
  assert.equal(apass?.comparisonStatus, "NOT PROVEN");
  assert.ok(apass?.smallestSponsorQuestion.length > 0);
});

test("a write-dependent conclusion is reported as NOT PROVEN, never as live", async () => {
  const report = await runCleanverseMonadEvidence({
    ...baseRunOptions(),
    transport: createFixtureTransport(),
  });
  assert.ok(report.conclusions.some(
    (conclusion) => conclusion.classification === "NOT PROVEN"
      && /not live/i.test(conclusion.statement),
  ));
  assert.equal(
    report.conclusions.some((conclusion) => conclusion.classification === "LIVE"),
    false,
    "a read-only run may never conclude LIVE",
  );
  assert.ok(report.missingEvidence.some((missing) => /generate_apass|A-Pass/i.test(missing.topic)));
});

// --- report schema ---------------------------------------------------------------------------

test("the report schema rejects an unknown classification", () => {
  assert.throws(() => parseEvidenceReport({
    schemaVersion: 1,
    generatedAt: "now",
    repositoryCommit: "abc",
    mode: "fixture",
    network: { name: "monad-testnet", chainId: 10_143, blockNumber: "1", blockHash: "0x1" },
    documentation: [],
    onchainObservations: [],
    comparisons: [],
    conclusions: [{ statement: "x", classification: "TOTALLY LIVE", basis: "y" }],
    missingEvidence: [],
  }), /failed validation/);
});

// --- secret handling -------------------------------------------------------------------------

test("the artifact writer refuses documentation access codes and API keys", () => {
  for (const leaky of [
    `CLEANVERSE_DOCS_ACCESS_CODE=super-secret-value`,
    `CLEANVERSE_API_KEY: "abcdef0123456789"`,
    `DEPLOYER_PRIVATE_KEY=0x${"11".repeat(32)}`,
    `Authorization: Bearer abcdef.token.value`,
    `Cookie: session=abcdef0123456789`,
    `https://docs.cleanverse.com/docs?access_code=abcdef0123456789`,
  ]) {
    const leaks = findSecretLeaks(leaky);
    assert.ok(leaks.length > 0, `expected a leak for ${leaky.slice(0, 24)}`);
    const redacted = redactSecrets(leaky);
    assert.equal(findSecretLeaks(redacted).length, 0, `redaction failed for ${leaks[0].kind}`);
  }
});

test("an injected test secret is caught by value, and never echoed", () => {
  const injected = "mordant-injected-canary-secret";
  const text = `documentedBehavior: uses ${injected} for access`;

  const leaks = findSecretLeaks(text, [injected]);
  assert.equal(leaks.length, 1);
  assert.equal(leaks[0].kind, "known-secret-value");
  assert.doesNotMatch(leaks[0].location, new RegExp(injected));

  const error = new SecretLeakError(leaks);
  assert.doesNotMatch(error.message, new RegExp(injected));
  assert.equal(findSecretLeaks(redactSecrets(text, [injected]), [injected]).length, 0);
});

test("rendering fails closed when a report still carries secret material", async () => {
  const report = await runCleanverseMonadEvidence({
    ...baseRunOptions(),
    transport: createFixtureTransport(),
  });
  const injected = "mordant-injected-canary-secret";
  const poisoned = {
    ...report,
    conclusions: [
      ...report.conclusions,
      { statement: `leaked ${injected}`, classification: "READ-ONLY" as const, basis: "test" },
    ],
  };

  // Redaction runs first, so a known value is scrubbed rather than blocking the artifact.
  const artifacts = renderEvidenceArtifacts(poisoned, [injected]);
  assert.doesNotMatch(artifacts.json, new RegExp(injected));
  assert.doesNotMatch(artifacts.markdown, new RegExp(injected));

  assert.match(artifacts.json, /\[REDACTED\]/);

  // The guard that runs after redaction is fail-closed: anything still matching a secret pattern
  // aborts the write instead of being persisted, and the error never quotes the value.
  assert.throws(
    () => assertNoSecretLeak("Authorization: Bearer abcdef0123456789"),
    (error: unknown) => {
      assert.ok(error instanceof SecretLeakError);
      assert.equal(error.leaks[0].kind, "authorization-header");
      assert.doesNotMatch(error.message, /abcdef0123456789/);
      return true;
    },
  );

  // A header-shaped secret nobody declared is still scrubbed by pattern before writing.
  const withHeader = renderEvidenceArtifacts({
    ...report,
    conclusions: [
      ...report.conclusions,
      {
        statement: "Cookie: session=abcdef0123456789",
        classification: "READ-ONLY" as const,
        basis: "test",
      },
    ],
  });
  assert.doesNotMatch(withHeader.json, /abcdef0123456789/);
  assert.equal(findSecretLeaks(withHeader.json).length, 0);
});

test("the scanner catches a documentation invite code and a provider key in an RPC URL", () => {
  const invite = findSecretLeaks("see https://docs.cleanverse.com/api/docs/invite/AbCd1234");
  assert.equal(invite.length, 1);
  assert.equal(invite[0].kind, "docs-invite-code");
  assert.equal(findSecretLeaks(redactSecrets("https://docs.cleanverse.com/api/docs/invite/AbCd1234")).length, 0);

  const rpc = findSecretLeaks('rpc_url: "https://base-sepolia.g.alchemy.com/v2/SyntheticProviderKeyAAAAAAAA"');
  assert.ok(rpc.some((leak) => leak.kind === "provider-key-in-rpc-url"));
  const redacted = redactSecrets('rpc_url: "https://base-sepolia.g.alchemy.com/v2/SyntheticProviderKeyAAAAAAAA"');
  assert.doesNotMatch(redacted, /SyntheticProviderKey/);
  assert.equal(findSecretLeaks(redacted).length, 0);

  // A public RPC without an embedded credential must not be flagged.
  assert.equal(findSecretLeaks("https://testnet-rpc.monad.xyz").length, 0);
});

test("the report separates when it was rendered, observed and consulted", async () => {
  const report = await runCleanverseMonadEvidence({
    ...baseRunOptions(),
    transport: createFixtureTransport(),
    documentation: { ...DOCUMENTATION_UNAVAILABLE, protectedDocsConsultedAt: "2026-07-27" },
  });

  assert.equal(report.documentationSource.sourceKind, "manual-versioned-transcription");
  assert.equal(report.documentationSource.documentationVersion, "v5.6");
  assert.equal(report.documentationSource.documentationConsultedAt, "2026-07-27");
  // The gate has no credential and must never imply it fetched the gated page.
  assert.equal(report.documentationSource.liveFetchedByEvidenceGate, false);
  assert.ok(report.network.onchainObservedAt.length > 0);
  assert.notEqual(report.network.onchainObservedAt, report.documentationSource.documentationConsultedAt);
});

test("without an operator attestation the documentation source is unavailable", async () => {
  const report = await runCleanverseMonadEvidence({
    ...baseRunOptions(),
    transport: createFixtureTransport(),
  });
  assert.equal(report.documentationSource.sourceKind, "unavailable");
  assert.equal(report.documentationSource.documentationConsultedAt, null);
  assert.equal(report.documentationSource.liveFetchedByEvidenceGate, false);
});

test("the launcher conclusion is bounded to the observed block and never claims a fix", async () => {
  const report = await runCleanverseMonadEvidence({
    ...baseRunOptions(),
    transport: createFixtureTransport(),
  });
  const launcher = report.conclusions.find((conclusion) =>
    /selector skew/.test(conclusion.statement));
  assert.ok(launcher, "a launcher conclusion must exist");
  assert.match(launcher.statement, /No backend\/factory selector skew was observable at block \d+/);
  assert.doesNotMatch(launcher.statement, /fixed|repaired|healthy/i);
  assert.match(launcher.basis, /NOT PROVEN — WRITE ACTION REQUIRED/);
});

test("the ComplianceFailed conclusion stays bounded to the probed tuples", async () => {
  const chain = createMonadFixtureChain();
  const policy = "0x36489be45fa84f70a0c2bdb11d824be608cb12dd";
  const report = await runCleanverseMonadEvidence({
    ...baseRunOptions(),
    transport: createFixtureTransport({
      overrides: {
        calls: {
          ...chain.calls,
          [`${policy}:0x6d62a4fe`]:
            `${REVERT_PREFIX}0x8a4e1859000000000000000000000000ac0893567d43c3e7e6e35a72803df05416c1f20d`,
        },
      },
    }),
  });

  const conclusion = report.conclusions.find((candidate) =>
    /COMPLIANT APASS PROFILE NOT IDENTIFIED/.test(candidate.statement));
  assert.ok(conclusion, "the bounded ComplianceFailed conclusion must be present");
  assert.match(conclusion.statement, /consistent with a compliance rule that is not satisfied/);

  // The statement is the claim, so it alone must be free of overclaiming. The basis is allowed to
  // name these very claims in order to disclaim them.
  const forbidden = [
    /policy is (broken|faulty|down)/i,
    /refuses everyone/i,
    /rejects every (possible )?participant/i,
    /a valid A-Pass (is )?(therefore )?suffic/i,
    /tier is too low/i,
    /issuance is fixed/i,
  ];
  for (const pattern of forbidden) {
    assert.doesNotMatch(conclusion.statement, pattern, `overclaiming: ${pattern}`);
  }

  // The basis must explicitly bound the finding.
  assert.match(conclusion.basis, /does not establish which attribute is unsatisfied/);
  assert.match(conclusion.basis, /rejects every participant/);
  assert.match(conclusion.basis, /holding a valid A-Pass suffices/);
});

test("an allowlist entry without a stated reason is ignored", () => {
  const directory = mkdtempSync(join(tmpdir(), "mordant-scan-"));
  writeFileSync(join(directory, ALLOWLIST_FILE), JSON.stringify({
    allow: [
      { path: ".env.example", kind: "cleanverse-api-key", reason: "documented placeholder" },
      { path: "src/secret.ts", kind: "cleanverse-api-key", reason: "   " },
      { path: "src/other.ts", kind: "cleanverse-api-key" },
    ],
  }));

  const entries = loadAllowlist(directory);
  assert.equal(entries.length, 1, "only the entry that states a reason may suppress a finding");
  assert.equal(entries[0].path, ".env.example");
  assert.equal(loadAllowlist(join(directory, "missing")).length, 0);
});

test("generated artifacts contain no secret pattern and no session URL", async () => {
  const report = await runCleanverseMonadEvidence({
    ...baseRunOptions(),
    transport: createFixtureTransport(),
  });
  const artifacts = renderEvidenceArtifacts(report);

  assert.equal(findSecretLeaks(artifacts.json).length, 0);
  assert.equal(findSecretLeaks(artifacts.markdown).length, 0);
  assert.doesNotMatch(artifacts.json, /authorization|cookie|api[-_]?key/i);
  assert.match(artifacts.markdown, /No transaction was signed or broadcast/);
});
