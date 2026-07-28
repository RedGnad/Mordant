/**
 * M-15 shared internals: configuration, phase chaining and the gates every writing runner carries.
 *
 * The seven phase runners are deliberately thin. Everything worth testing lives here as a pure
 * function, so a gate can be exercised without a fork, a key or a network.
 *
 * No runner in this package broadcasts. Each supports --check, and --run is written but refused
 * until public writes are authorized.
 */
import { readFileSync } from "node:fs";

import { ControlError } from "./runner-controls.mjs";

export const PHASES = Object.freeze(["A", "B", "C1", "C2", "D", "E", "F"]);

/** Each phase consumes the previous phase's artifact, and only that one. */
export const PHASE_INPUT = Object.freeze({
  A: null, B: "A", C1: "B", C2: "C1", D: "C2", E: "D", F: "E",
});

const fail = (message) => {
  throw new ControlError(`STOP — ${message}`);
};

/**
 * The six inputs the owner must supply, with the role each fills.
 *
 * No address is chosen or invented here. An absent one is an error, never a default.
 */
export const REQUIRED_INPUTS = Object.freeze([
  { key: "buyer", env: "MORDANT_ADDRESS_BUYER", role: "ROLE_BUYER", needsAUsdc: 0n },
  { key: "funder", env: "MORDANT_ADDRESS_FUNDER", role: "ROLE_HOLDER", needsAUsdc: 100_000n },
  { key: "originator", env: "MORDANT_ADDRESS_ORIGINATOR", role: "ROLE_ORIGINATOR", needsAUsdc: 0n },
  { key: "facilityProtected", env: "MORDANT_ADDRESS_FACILITY_A", role: "ROLE_FACILITY", needsAUsdc: 0n },
  { key: "facilityChallenger", env: "MORDANT_ADDRESS_FACILITY_B", role: "ROLE_FACILITY", needsAUsdc: 0n },
  { key: "issuanceMinter", env: "MORDANT_ADDRESS_ISSUANCE_MINTER", role: "none", needsAUsdc: 0n },
]);

/** Addresses already known from earlier missions. */
export const KNOWN_INPUTS = Object.freeze([
  { key: "holderA", env: "MORDANT_ADDRESS_HOLDER_A", role: "ROLE_HOLDER", needsAUsdc: 0n },
  { key: "holderB", env: "MORDANT_ADDRESS_HOLDER_B", role: "ROLE_HOLDER", needsAUsdc: 0n },
]);

/**
 * Pairs that must not be the same address, each with the reason the contracts refuse it.
 *
 * These are not stylistic: every one cost a failed run during the M-13 rehearsal.
 */
export const INCOMPATIBLE_PAIRS = Object.freeze([
  { a: "funder", b: "buyer",
    why: "_requireHolderRole rejects a funder that is also the buyer" },
  { a: "facilityProtected", b: "facilityChallenger",
    why: "a conflict cannot be raised by the protected facility against itself" },
  { a: "issuanceMinter", b: "holderA",
    why: "the temporary minter must be disposable, not a participant that outlives the ceremony" },
  { a: "issuanceMinter", b: "holderB",
    why: "the temporary minter must be disposable, and holderB survives the ceremony as a holder" },
  { a: "originator", b: "buyer",
    why: "_validatePledge rejects a facility or counterparty that is also the originator" },
  { a: "originator", b: "facilityProtected",
    why: "_validatePledge rejects a facility caller that is also an authorized originator" },
  { a: "originator", b: "facilityChallenger",
    why: "the challenger is a facility caller too, so the same rejection applies" },
]);

const ADDRESS_PATTERN = /^0x[0-9a-fA-F]{40}$/;

/**
 * Loads and validates every configured address.
 *
 * Refuses absent, malformed, and duplicated-across-incompatible-roles. Reports rather than throws
 * for the absent case when `requireAll` is false, so a --check run can say what is still missing
 * instead of stopping at the first gap.
 */
export function loadParticipants(env, { requireAll = true } = {}) {
  const wanted = [...KNOWN_INPUTS, ...REQUIRED_INPUTS];
  const resolved = {};
  const missing = [];
  const malformed = [];
  for (const input of wanted) {
    const raw = env[input.env];
    if (raw === undefined || raw === null || String(raw).trim() === "") {
      missing.push(input.key);
      continue;
    }
    const value = String(raw).trim();
    if (!ADDRESS_PATTERN.test(value)) {
      malformed.push(`${input.key} (${input.env}) is not a 20-byte hex address`);
      continue;
    }
    resolved[input.key] = value;
  }
  if (malformed.length > 0) fail(`malformed addresses: ${malformed.join("; ")}`);
  if (requireAll && missing.length > 0) {
    fail(`addresses not supplied: ${missing.join(", ")}. They are provided by the owner and are`
      + " never chosen or defaulted here.");
  }
  assertRolesCompatible(resolved);
  return { participants: resolved, missing, complete: missing.length === 0 };
}

/** Refuses any address filling two roles the contracts treat as mutually exclusive. */
export function assertRolesCompatible(participants) {
  const clashes = [];
  for (const pair of INCOMPATIBLE_PAIRS) {
    const a = participants[pair.a];
    const b = participants[pair.b];
    if (!a || !b) continue;
    if (a.toLowerCase() === b.toLowerCase()) {
      clashes.push(`${pair.a} and ${pair.b} are the same address: ${pair.why}`);
    }
  }
  if (clashes.length > 0) fail(`incompatible roles: ${clashes.join("; ")}`);
  return true;
}

/**
 * Funding and credential readiness for one address. Reported as data so a --check run can list
 * everything wrong at once rather than surfacing one problem per attempt.
 */
export function assessReadiness({ key, address, isValidAPass, monBalance, aUsdcBalance,
  requiredMon, requiredAUsdc }) {
  const problems = [];
  if (isValidAPass !== true) problems.push("no valid A-Pass");
  if (typeof monBalance !== "bigint" || monBalance < BigInt(requiredMon)) {
    problems.push(`MON ${monBalance} below the ${requiredMon} needed`);
  }
  if (BigInt(requiredAUsdc) > 0n
    && (typeof aUsdcBalance !== "bigint" || aUsdcBalance < BigInt(requiredAUsdc))) {
    problems.push(`aUSDC ${aUsdcBalance} below the ${requiredAUsdc} needed`);
  }
  return { key, address, ready: problems.length === 0, problems };
}

/** Every participant must be ready before a phase that depends on them may run. */
export function assertAllReady(assessments) {
  const blocked = assessments.filter((entry) => !entry.ready);
  if (blocked.length > 0) {
    fail(`participants not ready: ${blocked.map((entry) => `${entry.key} (${entry.problems.join(", ")})`).join("; ")}`);
  }
  return true;
}

/**
 * Loads the preceding phase's artifact and refuses to proceed on anything else.
 *
 * A phase that ran against a stale, stopped or wrong-phase artifact would be acting on a state that
 * no longer holds, which is exactly how a half-finished deployment gets compounded.
 */
export function loadPreviousArtifact(phase, path, readFile = (p) => readFileSync(p, "utf8")) {
  const expected = PHASE_INPUT[phase];
  if (expected === null) return null;
  if (!path) {
    fail(`phase ${phase} consumes the phase ${expected} artifact; pass --from <path>.`);
  }
  let parsed;
  try {
    parsed = JSON.parse(readFile(path));
  } catch (error) {
    fail(`the phase ${expected} artifact at ${path} could not be read: ${error.message}`);
  }
  if (parsed.phase !== expected) {
    fail(`${path} is a phase ${parsed.phase} artifact, but phase ${phase} consumes phase ${expected}.`);
  }
  if (parsed.status !== "SUCCESS") {
    fail(`the phase ${expected} artifact reports ${parsed.status}, not SUCCESS.`
      + " A phase never resumes from an unfinished one; reconcile by hand first.");
  }
  return parsed;
}

/**
 * The deployed contract must be the reviewed one. An address merely having code is not enough: a
 * different contract there would behave under rules nobody reviewed.
 */
export function assertRuntimeHash(label, observedHash, expectedHash) {
  if (!observedHash || observedHash === "0x") fail(`${label} has no code at the recorded address.`);
  if (String(observedHash).toLowerCase() !== String(expectedHash).toLowerCase()) {
    fail(`${label} runtime hash ${observedHash} does not match the frozen ${expectedHash}.`
      + " This is not the reviewed contract.");
  }
  return true;
}

/** Any on-chain readback differing from the manifest stops the phase. */
export function assertReadbacksMatch(label, observed, expected) {
  const differences = [];
  for (const [key, want] of Object.entries(expected)) {
    const got = observed[key];
    const same = typeof want === "bigint" || typeof got === "bigint"
      ? BigInt(got ?? -1n) === BigInt(want)
      : String(got ?? "").toLowerCase() === String(want).toLowerCase();
    if (!same) differences.push(`${key} is ${got}, expected ${want}`);
  }
  if (differences.length > 0) {
    fail(`${label} does not match the manifest: ${differences.join("; ")}`);
  }
  return true;
}

/**
 * Before binding, the adapter must be the only address that can mint. An unexpected minter means
 * the supply invariant bindVault relies on can be broken from outside afterwards.
 */
export function assertOnlyExpectedMinter(activeMinters, adapterAddress) {
  if (!Array.isArray(activeMinters)) {
    fail("the minter history could not be reconstructed, so exclusivity is unproven. Do not bind.");
  }
  const expected = String(adapterAddress).toLowerCase();
  const unexpected = activeMinters.map((entry) => String(entry).toLowerCase())
    .filter((entry) => entry !== expected);
  if (unexpected.length > 0) {
    fail(`unexpected active minter(s) before binding: ${unexpected.join(", ")}. Revoke first.`);
  }
  if (!activeMinters.some((entry) => String(entry).toLowerCase() === expected)) {
    fail("the adapter does not hold MINTER_ROLE, so it could not burn during redemption.");
  }
  return true;
}

/**
 * The mode gate. Public writes are not authorized, so --run is recognised and refused rather than
 * silently absent: the runners are complete, and only the authorization is missing.
 */
export function resolveMode(argv, { publicWritesAuthorized = false } = {}) {
  const wantsRun = argv.includes("--run");
  if (!wantsRun) return "check";
  if (!publicWritesAuthorized) {
    fail("--run is implemented but public writes are NOT AUTHORIZED. The package is prepared;"
      + " executing it is a separate decision.");
  }
  const outIndex = argv.indexOf("--out");
  if (outIndex === -1 || !argv[outIndex + 1]) {
    fail("--out <prefix> is mandatory with --run, so a phase that spends gas always leaves an"
      + " artifact, including when it stops.");
  }
  return "run";
}

/** A phase never triggers the next; it says what comes next and stops. */
export function nextPhase(phase) {
  const index = PHASES.indexOf(phase);
  if (index === -1) fail(`${phase} is not a known phase.`);
  const next = PHASES[index + 1] ?? null;
  return { next, instruction: next === null
    ? "This is the final phase."
    : `STOP. Phase ${next} is a separate, deliberate command and is never triggered from here.` };
}

/** The four statuses this package reports, and the conditions for each. */
export function packageStatus({ runnersComplete, inputsComplete }) {
  return {
    "LIVE EXECUTION ENGINE": runnersComplete ? "READY" : "INCOMPLETE",
    "EXECUTION INPUTS": inputsComplete ? "COMPLETE" : "INCOMPLETE",
    "PUBLIC WRITES": "NOT AUTHORIZED",
    "MORDANT SETTLEMENT": "NOT PROVEN LIVE",
  };
}
