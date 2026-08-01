// Fail-closed gate for live Monad broadcasts.
//
// Every broadcast in the V5 runner goes through `guardedBroadcast`. Nothing
// else in the runner is permitted to call a wallet's send/deploy/write
// directly, and `v5-live-guard.test.mjs` enforces that statically by reading
// the runner sources: a new broadcast path added anywhere else fails the test
// rather than quietly shipping.
//
// The gate is deliberately an exact string match on "1". "true", "yes", "TRUE",
// a trailing space or a stray newline from a shell heredoc all mean disabled.
// A gate that accepts several spellings is a gate that eventually accepts one
// nobody intended.
export const LIVE_GATE = "MORDANT_LIVE_V5_EXECUTION";

/// Broadcast targets. `local` is an ephemeral chain used by the rehearsal and
/// is never gated; only `monad` is.
export const TARGETS = Object.freeze({ MONAD: "monad", LOCAL: "local" });

export class LiveExecutionBlocked extends Error {
  constructor(detail) {
    super(`LIVE_EXECUTION_BLOCKED: ${detail}`);
    this.code = "LIVE_EXECUTION_BLOCKED";
    this.name = "LiveExecutionBlocked";
  }
}

/// True only for the exact string "1".
export function isLiveExecutionEnabled(env = process.env) {
  return Object.prototype.hasOwnProperty.call(env, LIVE_GATE) && env[LIVE_GATE] === "1";
}

export function assertLiveExecutionAllowed(env = process.env) {
  if (!isLiveExecutionEnabled(env)) {
    const raw = env[LIVE_GATE];
    const shown = raw === undefined ? "absent" : JSON.stringify(raw);
    throw new LiveExecutionBlocked(
      `${LIVE_GATE} is ${shown}; live Monad broadcasts require exactly "1"`,
    );
  }
}

/// The single broadcast chokepoint.
///
/// `send` is the function that actually puts a transaction on the wire. It is
/// only invoked after the gate passes, so a caller cannot broadcast by
/// accident, and a reviewer has exactly one place to look.
///
/// A local target is allowed unconditionally: the rehearsal must be able to run
/// a complete atomic binding without anyone setting a production gate, and an
/// ephemeral chain carries no value.
export async function guardedBroadcast({ target, description, send, env = process.env }) {
  if (target !== TARGETS.MONAD && target !== TARGETS.LOCAL) {
    throw new LiveExecutionBlocked(`unknown broadcast target ${JSON.stringify(target)}`);
  }
  if (target === TARGETS.MONAD) assertLiveExecutionAllowed(env);
  if (typeof send !== "function") {
    throw new LiveExecutionBlocked(`no send function for ${description}`);
  }
  return send();
}

/// Describes the current gate state for the journal and the report, without
/// leaking any other environment value.
export function guardStatus(env = process.env) {
  const raw = env[LIVE_GATE];
  return {
    variable: LIVE_GATE,
    present: raw !== undefined,
    enabled: isLiveExecutionEnabled(env),
    // The literal value matters when diagnosing a refused run, and it is a
    // flag rather than a secret.
    value: raw === undefined ? null : raw,
  };
}
