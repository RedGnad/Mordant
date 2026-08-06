/**
 * Operator-entered private pledge windows for a supervised local run.
 *
 * These values are the only part of the pledge an operator may author. They
 * reach the existing Go participant client through the existing private pledge
 * JSON boundary; no cryptographic semantics change. Every other pledge field
 * stays derived exactly as the fixed fixture derives it.
 *
 * The values are private. They exist only in the local execution state needed
 * to write the transient participant pledge files, and must never reach a
 * public view, public evidence, the operation journal, a log line, an error
 * message, a URL or a hydration payload.
 */

export type SupervisedPledgeWindow = Readonly<{
  activeFrom: number;
  activeUntil: number;
}>;

export type SupervisedPledgeWindows = Readonly<{
  participantA: SupervisedPledgeWindow;
  participantB: SupervisedPledgeWindow;
}>;

/**
 * The circuit carries activeFrom/activeUntil as full uint64 values. JavaScript
 * can only represent integers exactly up to 2^53-1, so that is the honest
 * bound: past it we could not guarantee that the value written to the pledge
 * file is the value the operator entered.
 */
export const SUPERVISED_PLEDGE_MAX_INSTANT = Number.MAX_SAFE_INTEGER;

export class SupervisedPledgeWindowsError extends Error {
  constructor(readonly code: string, message: string) {
    super(message);
    this.name = "SupervisedPledgeWindowsError";
  }
}

function fail(code: string, message: string): never {
  throw new SupervisedPledgeWindowsError(code, message);
}

function exactKeys(value: unknown, expected: readonly string[]): value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  if (Object.getPrototypeOf(value) !== Object.prototype) return false;
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  return actual.length === wanted.length && actual.every((key, index) => key === wanted[index]);
}

/**
 * No coercion anywhere: a string, a float, a boolean, null, undefined, NaN, an
 * infinity, a negative value or a numeric-looking string is a rejection, never
 * a conversion.
 */
function exactInstant(value: unknown, code: string, label: string): number {
  if (typeof value !== "number") fail(code, `${label} must be a number`);
  if (!Number.isInteger(value)) fail(code, `${label} must be a whole number`);
  if (!Number.isSafeInteger(value)) fail(code, `${label} is outside the exactly representable range`);
  if (Object.is(value, -0)) fail(code, `${label} must not be negative zero`);
  if (value < 0) fail(code, `${label} must not be negative`);
  if (value > SUPERVISED_PLEDGE_MAX_INSTANT) fail(code, `${label} is outside the supported circuit range`);
  return value;
}

function exactWindow(value: unknown, role: "participantA" | "participantB"): SupervisedPledgeWindow {
  if (!exactKeys(value, ["activeFrom", "activeUntil"])) {
    fail("PLEDGE_WINDOW_FIELDS", `${role} must carry exactly activeFrom and activeUntil`);
  }
  const activeFrom = exactInstant(value.activeFrom, "PLEDGE_WINDOW_FROM", `${role} activeFrom`);
  const activeUntil = exactInstant(value.activeUntil, "PLEDGE_WINDOW_UNTIL", `${role} activeUntil`);
  // The Go client enforces this too. Rejecting here keeps an invalid window
  // from ever being written to a private pledge file.
  if (activeFrom >= activeUntil) {
    fail("PLEDGE_WINDOW_ORDER", `${role} activeFrom must be strictly before activeUntil`);
  }
  return Object.freeze({ activeFrom, activeUntil });
}

/**
 * One window on its own, for the participant-admission path where each wallet
 * submits only its own claim. Exactly the same validation the pair form applies
 * to each half, so a single-sided claim can never be laxer than an operator one.
 */
export function assertSupervisedPledgeWindow(
  value: unknown,
  role: "participantA" | "participantB",
): SupervisedPledgeWindow {
  return exactWindow(value, role);
}

export function assertSupervisedPledgeWindows(value: unknown): SupervisedPledgeWindows {
  if (!exactKeys(value, ["participantA", "participantB"])) {
    fail("PLEDGE_WINDOWS_FIELDS", "Pledges must carry exactly participantA and participantB");
  }
  return Object.freeze({
    participantA: exactWindow(value.participantA, "participantA"),
    participantB: exactWindow(value.participantB, "participantB"),
  });
}

export function isSupervisedPledgeWindows(value: unknown): value is SupervisedPledgeWindows {
  try {
    assertSupervisedPledgeWindows(value);
    return true;
  } catch {
    return false;
  }
}
