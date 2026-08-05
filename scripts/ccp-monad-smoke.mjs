#!/usr/bin/env node
/**
 * Cleanverse CCP V2 Monad testnet smoke.
 *
 * Answers one question: can Mordant register a contract address with the Cleanverse
 * APass Compliance Validator on Monad testnet today, put a RuleV2 on it, and read a
 * compliance verdict back?
 *
 * Nothing here touches the live BGV product. It deploys a throwaway gate, drives the
 * documented Cleanverse validator endpoints and reads the validator contract directly.
 *
 * Every step records what it observed, including failures, so a refusal is evidence
 * rather than a crash. Secrets are never printed.
 */

import { createCipheriv, randomUUID } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";

import {
  createPublicClient,
  createWalletClient,
  http,
  parseAbi,
  toFunctionSelector,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";

const CHAIN_SLUG = "monad";
const CHAIN_ID = 10143;
const VALIDATOR = "0xaC7e5179C2C7f03f209136886c172eb34F161792";

// The process environment wins, so a rerun can reuse an already-deployed gate without
// editing the checked-in .env.
const env = {
  ...Object.fromEntries(
    readFileSync(new URL("../.env", import.meta.url), "utf8")
      .split("\n")
      .filter((line) => /^[A-Z0-9_]+=/.test(line))
      .map((line) => [line.slice(0, line.indexOf("=")), line.slice(line.indexOf("=") + 1)]),
  ),
  ...Object.fromEntries(Object.entries(process.env).filter(([, value]) => value !== undefined && value !== "")),
};

const RPC_URL = env.MONAD_RPC_URL;
const API_BASE = env.CLEANVERSE_API_BASE_URL;
const API_ID = env.CLEANVERSE_API_ID;
const API_KEY = env.CLEANVERSE_API_KEY;
const DEPLOYER_KEY = env.FHE_MONAD_DEPLOYER_PRIVATE_KEY;

const evidence = {
  schemaVersion: "mordant.ccp-monad-smoke/1",
  chain: { slug: CHAIN_SLUG, chainId: CHAIN_ID },
  validator: VALIDATOR,
  steps: [],
};

function record(step, status, detail) {
  evidence.steps.push({ step, status, ...detail });
  const mark = status === "PASS" ? "ok  " : status === "INFO" ? "--  " : "FAIL";
  process.stdout.write(`  ${mark} ${step}${detail?.note ? ` :: ${detail.note}` : ""}\n`);
}

/** Cleanverse encrypts request bodies with AES-CBC under a zero IV, base64 encoded. */
function encryptBody(payload) {
  const key = Buffer.from(API_KEY.trim(), "base64");
  const cipher = createCipheriv(`aes-${key.byteLength * 8}-cbc`, key, Buffer.alloc(16, 0));
  cipher.setAutoPadding(true);
  return {
    data: Buffer.concat([
      cipher.update(Buffer.from(JSON.stringify(payload), "utf8")),
      cipher.final(),
    ]).toString("base64"),
  };
}

async function callCleanverse(path, body, { encrypted }) {
  const response = await fetch(`${API_BASE}${path}`, {
    method: "POST",
    headers: {
      "api-id": API_ID,
      "X-Request-ID": randomUUID(),
      "Content-Type": "application/json",
    },
    body: JSON.stringify(encrypted ? encryptBody(body) : body),
    cache: "no-store",
  });
  let parsed = null;
  const text = await response.text();
  try {
    parsed = JSON.parse(text);
  } catch {
    parsed = { unparsed: text.slice(0, 400) };
  }
  return { httpStatus: response.status, envelope: parsed };
}

const publicClient = createPublicClient({ transport: http(RPC_URL) });
const account = privateKeyToAccount(DEPLOYER_KEY);
const walletClient = createWalletClient({
  account,
  transport: http(RPC_URL),
  chain: { id: CHAIN_ID, name: "monad-testnet", nativeCurrency: { name: "MON", symbol: "MON", decimals: 18 }, rpcUrls: { default: { http: [RPC_URL] } } },
});

const validatorAbi = parseAbi([
  "function isRegistered(address) view returns (bool)",
  "function complianceVerify(address,address) view returns (bool)",
  "function isPaused(address) view returns (bool)",
]);

async function main() {
  process.stdout.write("1. chain and validator bytecode\n");
  const chainId = await publicClient.getChainId();
  const blockNumber = await publicClient.getBlockNumber();
  evidence.pinnedBlock = Number(blockNumber);
  record("chain id is 10143", chainId === CHAIN_ID ? "PASS" : "FAIL", { observed: chainId });

  const proxyCode = await publicClient.getCode({ address: VALIDATOR });
  const implSlot = await publicClient.getStorageAt({
    address: VALIDATOR,
    slot: "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc",
  });
  const implementation = `0x${implSlot.slice(-40)}`;
  const implCode = await publicClient.getCode({ address: implementation });
  evidence.validatorProxyBytes = (proxyCode.length - 2) / 2;
  evidence.validatorImplementation = implementation;
  evidence.validatorImplementationBytes = (implCode.length - 2) / 2;
  record("validator carries bytecode and is an EIP-1967 proxy", proxyCode.length > 2 ? "PASS" : "FAIL", {
    proxyBytes: evidence.validatorProxyBytes,
    implementation,
    implementationBytes: evidence.validatorImplementationBytes,
  });

  // The dispatch table is the only published description of this contract: Cleanverse
  // documents no Solidity ABI and the implementation is unverified on Sourcify.
  const selectors = new Set();
  const hex = implCode.slice(2);
  for (let i = 0; i < hex.length; i += 2) {
    const op = parseInt(hex.slice(i, i + 2), 16);
    if (op === 0x63) {
      if (/^(14|80|81|82|90|91)/.test(hex.slice(i + 10, i + 14))) selectors.add(`0x${hex.slice(i + 2, i + 10)}`);
      i += 8;
    } else if (op >= 0x60 && op <= 0x7f) {
      i += (op - 0x5f) * 2;
    }
  }
  const required = {
    "isRegistered(address)": toFunctionSelector("isRegistered(address)"),
    "getRulesV2(address)": toFunctionSelector("getRulesV2(address)"),
    "removeRuleV2FromContract(uint256)": toFunctionSelector("removeRuleV2FromContract(uint256)"),
    "complianceVerify(address,address)": toFunctionSelector("complianceVerify(address,address)"),
    "isPaused(address)": toFunctionSelector("isPaused(address)"),
  };
  evidence.validatorSelectors = [...selectors].sort();
  evidence.resolvedInterface = required;
  const missing = Object.entries(required).filter(([, sel]) => !selectors.has(sel));
  record("the derived CCP V2 interface is present in the dispatch table", missing.length === 0 ? "PASS" : "FAIL", {
    selectorCount: selectors.size,
    missing: missing.map(([name]) => name),
  });

  process.stdout.write("2. minimal Ownable gate\n");
  let gate = env.CCP_GATE_ADDRESS?.trim();
  if (gate) {
    record("reusing an existing gate", "INFO", { gate });
  } else {
    const artifact = JSON.parse(
      readFileSync(new URL("../contracts/out/MordantCcpGate.sol/MordantCcpGate.json", import.meta.url), "utf8"),
    );
    const hash = await walletClient.deployContract({
      abi: artifact.abi,
      bytecode: artifact.bytecode.object,
      args: [account.address],
    });
    const receipt = await publicClient.waitForTransactionReceipt({ hash });
    gate = receipt.contractAddress;
    record("gate deployed", receipt.status === "success" ? "PASS" : "FAIL", { gate, txHash: hash });
  }
  evidence.gate = gate;

  const onChainOwner = await publicClient.readContract({
    address: gate,
    abi: parseAbi(["function owner() view returns (address)"]),
    functionName: "owner",
  });
  record("gate exposes Ownable.owner() equal to the signer", onChainOwner.toLowerCase() === account.address.toLowerCase() ? "PASS" : "FAIL", {
    owner: onChainOwner,
  });

  process.stdout.write("3. owner signature\n");
  // Exactly the construction Cleanverse supplied: EIP-191 personal_sign over the
  // lowercase chain slug concatenated with the lowercase contract address.
  const message = CHAIN_SLUG.trim().toLowerCase() + gate.trim().toLowerCase();
  const ownerSignature = await account.signMessage({ message });
  evidence.signedMessage = message;
  record("owner signature produced over the exact supplied construction", /^0x[0-9a-f]{130}$/i.test(ownerSignature) ? "PASS" : "FAIL", {
    message,
    signatureLength: ownerSignature.length,
  });

  process.stdout.write("4. Cleanverse registration\n");
  const rule = {
    allowed_group: "",
    allowed_sub_group: "",
    min_tier: 0,
    min_sub_tier: 0,
    is_black_list: false,
    countries: [],
  };
  const registration = await callCleanverse(
    "/validator/register",
    { chain: CHAIN_SLUG, contract_address: gate, rule, owner_signature: ownerSignature },
    { encrypted: true },
  );
  evidence.registration = registration;
  const alreadyRegistered = await publicClient.readContract({
    address: VALIDATOR, abi: validatorAbi, functionName: "isRegistered", args: [gate],
  });
  // A second registration of the same gate reverts on-chain. That is idempotency, so it is
  // only a failure when the gate was not already registered.
  const registeredOk = registration.envelope?.code === "0000" || alreadyRegistered;
  record("POST /validator/register accepted", registeredOk ? "PASS" : "FAIL", {
    alreadyRegistered,
    httpStatus: registration.httpStatus,
    code: registration.envelope?.code,
    note: registeredOk ? registration.envelope?.data?.tx_hash : JSON.stringify(registration.envelope).slice(0, 300),
  });

  process.stdout.write("5. isRegistered readback\n");
  let onChainRegistered = false;
  for (let attempt = 0; attempt < 20; attempt += 1) {
    onChainRegistered = await publicClient.readContract({
      address: VALIDATOR,
      abi: validatorAbi,
      functionName: "isRegistered",
      args: [gate],
    });
    if (onChainRegistered) break;
    await new Promise((resolve) => setTimeout(resolve, 3_000));
  }
  record("validator.isRegistered(gate) is true on-chain", onChainRegistered ? "PASS" : "FAIL", { gate });

  const apiRegistered = await callCleanverse(
    "/validator/is_register",
    { chain: CHAIN_SLUG, contract_address: gate },
    { encrypted: false },
  );
  evidence.isRegistered = { onChain: onChainRegistered, api: apiRegistered };
  record("POST /validator/is_register reports registered", apiRegistered.envelope?.data?.registered === true ? "PASS" : "FAIL", {
    httpStatus: apiRegistered.httpStatus,
    code: apiRegistered.envelope?.code,
    note: JSON.stringify(apiRegistered.envelope?.data ?? apiRegistered.envelope).slice(0, 200),
  });

  process.stdout.write("6. RuleV2 transaction and readback\n");
  const ruleV2 = {
    allowed_group: "",
    allowed_sub_group: "",
    min_tier: 1,
    min_sub_tier: 0,
    is_black_list: false,
    countries: ["FR"],
  };
  const ruleAttempts = [];
  for (const path of ["/validator/set_rule", "/validator/add_rule"]) {
    // No owner_signature here: the endpoint rejects it as an unknown field, because
    // registration already bound this contract to its owner.
    const attempt = await callCleanverse(
      path,
      { chain: CHAIN_SLUG, contract_address: gate, rule: ruleV2 },
      { encrypted: true },
    );
    ruleAttempts.push({ path, httpStatus: attempt.httpStatus, envelope: attempt.envelope });
    record(`POST ${path}`, attempt.envelope?.code === "0000" ? "PASS" : "INFO", {
      httpStatus: attempt.httpStatus,
      code: attempt.envelope?.code,
      note: JSON.stringify(attempt.envelope).slice(0, 220),
    });
    if (attempt.envelope?.code === "0000") break;
  }
  evidence.ruleWrite = ruleAttempts;
  const acceptedRule = ruleAttempts.find((attempt) => attempt.envelope?.code === "0000");
  if (acceptedRule?.envelope?.data?.tx_hash) {
    const receipt = await publicClient.waitForTransactionReceipt({ hash: acceptedRule.envelope.data.tx_hash });
    evidence.ruleTx = { hash: acceptedRule.envelope.data.tx_hash, status: receipt.status, blockNumber: Number(receipt.blockNumber) };
    record("the RuleV2 transaction is mined against the validator", receipt.status === "success" && receipt.to.toLowerCase() === VALIDATOR.toLowerCase() ? "PASS" : "FAIL", {
      txHash: acceptedRule.envelope.data.tx_hash,
      blockNumber: Number(receipt.blockNumber),
    });
  }

  // Raw readback: the RuleV2 struct shape is not published, so the raw return is recorded
  // and only then decoded against candidate shapes.
  const rawRules = await publicClient
    .call({
      to: VALIDATOR,
      data: `${toFunctionSelector("getRulesV2(address)")}${gate.slice(2).toLowerCase().padStart(64, "0")}`,
    })
    .catch((error) => ({ data: null, reverted: String(error.shortMessage ?? error.message).slice(0, 200) }));
  evidence.getRulesV2Raw = rawRules.data ?? null;
  if (rawRules.reverted) record("validator.getRulesV2(gate) reverted", "INFO", { note: rawRules.reverted });
  let decoded = null;
  if (rawRules.data) {
    const words = rawRules.data.slice(2).match(/.{64}/gu) ?? [];
    const count = Number(BigInt(`0x${words[1] ?? "0"}`));
    const fieldsPerRule = count > 0 ? (words.length - 2) / count : 0;
    decoded = {
      ruleCount: count,
      fieldsPerRule,
      encoding: Number.isInteger(fieldsPerRule) ? "static tuple" : "dynamic",
      rules: Array.from({ length: count }, (_unused, index) =>
        words.slice(2 + index * fieldsPerRule, 2 + (index + 1) * fieldsPerRule).map((w) => BigInt(`0x${w}`).toString()),
      ),
    };
  }
  evidence.getRulesV2Decoded = decoded;
  record("validator.getRulesV2(gate) returns a rule set", decoded !== null && decoded.ruleCount > 0 ? "PASS" : "FAIL", {
    rawBytes: rawRules.data ? (rawRules.data.length - 2) / 2 : 0,
    ruleCount: decoded?.ruleCount ?? 0,
    fieldsPerRule: decoded?.fieldsPerRule ?? 0,
  });

  // Field order is not published. It was measured: writing min_tier=1 moves field 2, and
  // writing a country list sets one bit per country in field 5, indexed alphabetically over
  // ISO 3166-1 alpha-2 (measured AF=2, FR=74, US=232, and FR+US as the union of both bits).
  const written = decoded?.rules?.[0] ?? null;
  const franceBit = 74n;
  evidence.ruleFieldLayout = {
    measured: "0:allowed_group 1:allowed_sub_group 2:min_tier 3:min_sub_tier 4:is_black_list 5:countries-bitmask",
    countryBitsObserved: { AF: 2, FR: 74, US: 232 },
  };
  const layoutHolds =
    written !== null && written[2] === String(ruleV2.min_tier) && (BigInt(written[5]) >> franceBit) % 2n === 1n;
  record("the readback carries the written min_tier and country bit", layoutHolds ? "PASS" : "FAIL", {
    minTierField: written?.[2] ?? null,
    countriesField: written === null ? null : `0x${BigInt(written[5]).toString(16)}`,
  });

  process.stdout.write("7. complianceVerify\n");
  const probeUser = account.address;
  const onChainVerdict = await publicClient.readContract({
    address: VALIDATOR,
    abi: validatorAbi,
    functionName: "complianceVerify",
    args: [gate, probeUser],
  }).catch((error) => ({ reverted: String(error.shortMessage ?? error.message).slice(0, 200) }));
  const apiVerify = await callCleanverse(
    "/validator/verify",
    { chain: CHAIN_SLUG, contract_address: gate, user_address: probeUser },
    { encrypted: false },
  );
  evidence.complianceVerify = { probeUser, onChain: onChainVerdict, api: apiVerify.envelope };
  record("validator.complianceVerify(gate, probe) answered", typeof onChainVerdict === "boolean" ? "PASS" : "INFO", {
    verdict: typeof onChainVerdict === "boolean" ? onChainVerdict : onChainVerdict.reverted,
  });
  record("POST /validator/verify answered", apiVerify.envelope?.code === "0000" ? "PASS" : "INFO", {
    httpStatus: apiVerify.httpStatus,
    code: apiVerify.envelope?.code,
    note: JSON.stringify(apiVerify.envelope?.data ?? apiVerify.envelope).slice(0, 200),
  });

  const failures = evidence.steps.filter((s) => s.status === "FAIL");
  evidence.result = failures.length === 0 ? "PASS" : "FAIL";
  evidence.failureCount = failures.length;
  const out = new URL(`../docs/evidence/ccp-monad-smoke-${new Date().toISOString().slice(0, 10)}.json`, import.meta.url);
  writeFileSync(out, JSON.stringify(evidence, null, 2));
  process.stdout.write(`\n${evidence.result}: ${failures.length} failing step(s)\n`);
  for (const failure of failures) process.stdout.write(`  - ${failure.step}\n`);
  process.stdout.write(`evidence: ${out.pathname.split("/").slice(-1)[0]}\n`);
}

await main();
