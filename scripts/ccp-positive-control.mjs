#!/usr/bin/env node
/**
 * Cleanverse CCP V2 positive control on Monad testnet.
 *
 * The smoke proved the plumbing works but every compliance verdict was false. This
 * asks the one question that decides whether CCP can gate a product at all: under a
 * completely unrestricted RuleV2, does a known public UAT A-Pass holder pass, and does
 * a holder without an A-Pass still fail?
 *
 * A positive candidate that is false under an unrestricted rule means the verdict does
 * not depend on policy tightness, and no combination of tier, group or country would
 * rescue it. That is a stop signal, not an invitation to guess.
 *
 * Reuses the already-registered gate. It never re-registers and never deploys.
 * Secrets, signatures and encrypted payloads are never printed or written.
 */

import { createCipheriv, randomUUID } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";

import { createPublicClient, http, parseAbi, toFunctionSelector } from "viem";

const CHAIN_SLUG = "monad";
const CHAIN_ID = 10143;
const VALIDATOR = "0xaC7e5179C2C7f03f209136886c172eb34F161792";
const GATE = "0x3ffb28a13fd6dc372ae952f15b55263285d5a280";
const APASS = "0xbA82D189540CaC9DC6FF46B6837CaC1BFdEC58B9";
const POSITIVE = "0x911F99f424D47F08a15fcC771e94dcc2f7252B02";
const NEGATIVE = "0x981F6E0Ea94f45fDB8ee7680DC862212E3C720e0";

const env = Object.fromEntries(
  readFileSync(new URL("../.env", import.meta.url), "utf8")
    .split("\n")
    .filter((line) => /^[A-Z0-9_]+=/.test(line))
    .map((line) => [line.slice(0, line.indexOf("=")), line.slice(line.indexOf("=") + 1)]),
);

const evidence = {
  schemaVersion: "mordant.ccp-positive-control/1",
  chain: { slug: CHAIN_SLUG, chainId: CHAIN_ID },
  validator: VALIDATOR,
  gate: GATE,
  steps: [],
};

function record(step, status, detail = {}) {
  evidence.steps.push({ step, status, ...detail });
  process.stdout.write(`  ${status === "PASS" ? "ok  " : status === "INFO" ? "--  " : "FAIL"} ${step}${detail.note ? ` :: ${detail.note}` : ""}\n`);
  return status === "PASS";
}

function encryptBody(payload) {
  const key = Buffer.from(env.CLEANVERSE_API_KEY.trim(), "base64");
  const cipher = createCipheriv(`aes-${key.byteLength * 8}-cbc`, key, Buffer.alloc(16, 0));
  cipher.setAutoPadding(true);
  return { data: Buffer.concat([cipher.update(Buffer.from(JSON.stringify(payload), "utf8")), cipher.final()]).toString("base64") };
}

async function callCleanverse(path, body, { encrypted }) {
  const response = await fetch(`${env.CLEANVERSE_API_BASE_URL}${path}`, {
    method: "POST",
    headers: { "api-id": env.CLEANVERSE_API_ID, "X-Request-ID": randomUUID(), "Content-Type": "application/json" },
    body: JSON.stringify(encrypted ? encryptBody(body) : body),
    cache: "no-store",
  });
  const text = await response.text();
  try {
    return { httpStatus: response.status, envelope: JSON.parse(text) };
  } catch {
    return { httpStatus: response.status, envelope: { unparsed: text.slice(0, 300) } };
  }
}

const client = createPublicClient({ transport: http(env.MONAD_RPC_URL) });
const validatorAbi = parseAbi([
  "function isRegistered(address) view returns (bool)",
  "function complianceVerify(address,address) view returns (bool)",
]);

async function readRulesV2() {
  const raw = await client.call({
    to: VALIDATOR,
    data: `${toFunctionSelector("getRulesV2(address)")}${GATE.slice(2).toLowerCase().padStart(64, "0")}`,
  });
  const words = raw.data.slice(2).match(/.{64}/gu) ?? [];
  const count = Number(BigInt(`0x${words[1] ?? "0"}`));
  return {
    ruleCount: count,
    fields: count === 0 ? [] : words.slice(2, 8).map((w) => BigInt(`0x${w}`).toString()),
  };
}

async function main() {
  process.stdout.write("1. the gate is still registered\n");
  const registered = await client.readContract({ address: VALIDATOR, abi: validatorAbi, functionName: "isRegistered", args: [GATE] });
  record("validator.isRegistered(gate) is true", registered ? "PASS" : "FAIL");

  process.stdout.write("2. replace RuleV2 with an entirely unrestricted policy\n");
  const unrestricted = {
    allowed_group: "",
    allowed_sub_group: "",
    min_tier: 0,
    min_sub_tier: 0,
    is_black_list: false,
    countries: [],
  };
  const write = await callCleanverse("/validator/set_rule", { chain: CHAIN_SLUG, contract_address: GATE, rule: unrestricted }, { encrypted: true });
  record("POST /validator/set_rule returns 0000", write.envelope?.code === "0000" ? "PASS" : "FAIL", {
    httpStatus: write.httpStatus,
    code: write.envelope?.code,
    note: write.envelope?.code === "0000" ? write.envelope.data.tx_hash : JSON.stringify(write.envelope).slice(0, 200),
  });

  if (write.envelope?.data?.tx_hash) {
    const receipt = await client.waitForTransactionReceipt({ hash: write.envelope.data.tx_hash });
    evidence.ruleTx = { hash: write.envelope.data.tx_hash, status: receipt.status, blockNumber: Number(receipt.blockNumber) };
    record("the RuleV2 transaction is mined against the validator", receipt.status === "success" && receipt.to.toLowerCase() === VALIDATOR.toLowerCase() ? "PASS" : "FAIL", {
      blockNumber: Number(receipt.blockNumber),
    });
  }

  const rules = await readRulesV2();
  evidence.rulesV2 = rules;
  const [group, subGroup, minTier, minSubTier, blacklist, countryBitmap] = rules.fields;
  record("getRulesV2 readback is entirely unrestricted", rules.fields.length === 6 && rules.fields.every((f) => f === "0") ? "PASS" : "FAIL", {
    group, subGroup, minTier, minSubTier, blacklist, countryBitmap,
  });

  process.stdout.write("3. A-Pass status of both candidates\n");
  const apassAbi = parseAbi(["function isValidAPass(address) view returns (bool)"]);
  evidence.candidates = {};
  for (const [label, address] of [["positive", POSITIVE], ["negative", NEGATIVE]]) {
    const onChainAPass = await client
      .readContract({ address: APASS, abi: apassAbi, functionName: "isValidAPass", args: [address] })
      .catch((error) => ({ reverted: String(error.shortMessage ?? error.message).slice(0, 120) }));
    const query = await callCleanverse("/query_apass", { chain: CHAIN_SLUG, address }, { encrypted: false });
    // Only a bounded projection of the record is kept: no identity payload is retained.
    const data = query.envelope?.data ?? null;
    const projection = data === null || typeof data !== "object" ? null : {
      tier: data.tier ?? null,
      subTier: data.subTier ?? null,
      group: data.group ?? null,
      subGroup: data.subGroup ?? null,
      status: data.status ?? null,
      hasExpiration: typeof data.expirationTime === "number" && data.expirationTime > 0,
      expired: typeof data.expirationTime === "number" ? data.expirationTime * 1000 < Date.now() : null,
    };
    evidence.candidates[label] = { address, onChainAPass, apiCode: query.envelope?.code ?? null, apiMessage: String(query.envelope?.message ?? "").slice(0, 120), record: projection };
    record(`${label} candidate A-Pass status`, "INFO", {
      note: `onChain isValidAPass=${JSON.stringify(onChainAPass)} apiCode=${query.envelope?.code} ${projection ? `tier=${projection.tier} status=${projection.status} expired=${projection.expired}` : "no record"}`,
    });
  }

  process.stdout.write("4. complianceVerify under the unrestricted rule\n");
  for (const [label, address] of [["positive", POSITIVE], ["negative", NEGATIVE]]) {
    const onChain = await client
      .readContract({ address: VALIDATOR, abi: validatorAbi, functionName: "complianceVerify", args: [GATE, address] })
      .catch((error) => ({ reverted: String(error.shortMessage ?? error.message).slice(0, 160) }));
    const api = await callCleanverse("/validator/verify", { chain: CHAIN_SLUG, contract_address: GATE, user_address: address }, { encrypted: false });
    evidence.candidates[label].complianceVerify = { onChain, apiValid: api.envelope?.data?.valid ?? null, apiCode: api.envelope?.code ?? null };
    record(`${label} candidate complianceVerify`, "INFO", {
      note: `onChain=${JSON.stringify(onChain)} api.valid=${api.envelope?.data?.valid}`,
    });
  }

  const positiveVerdict = evidence.candidates.positive.complianceVerify.onChain;
  const negativeVerdict = evidence.candidates.negative.complianceVerify.onChain;
  const positivePassed = positiveVerdict === true;
  const negativePassed = negativeVerdict === false;
  record("positive candidate is true", positivePassed ? "PASS" : "FAIL", { verdict: positiveVerdict });
  record("negative control is false", negativePassed ? "PASS" : "FAIL", { verdict: negativeVerdict });

  evidence.pinnedBlock = Number(await client.getBlockNumber());
  evidence.result = positivePassed && negativePassed ? "CCP MONAD POSITIVE CONTROL PASS" : "CCP MONAD POSITIVE CONTROL NOT PROVEN";
  const out = new URL(`../docs/evidence/ccp-positive-control-${new Date().toISOString().slice(0, 10)}.json`, import.meta.url);
  writeFileSync(out, JSON.stringify(evidence, null, 2));
  process.stdout.write(`\n${evidence.result}\n`);
  if (!positivePassed) {
    process.stdout.write("The unrestricted rule did not admit the candidate, so no policy tightening could.\n");
    process.exitCode = 1;
  }
}

await main();
