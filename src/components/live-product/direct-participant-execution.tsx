"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import { WalletModal } from "../wallet/wallet-modal";
import { useMordantWallet } from "../wallet/use-mordant-wallet";
import { adaptDirectParticipantIntake } from "./direct-participant-adapter";
import { LiveProduct } from "./live-product";
import {
  parseParticipantAdmissionResponse,
  parseParticipantCaseResponse,
  parseParticipantChallengeResponse,
  workerRoleFor,
  type AdmissionClaim,
  type AdmissionPost,
  type DirectParticipantRole,
  type ParticipantCaseResponse,
} from "./participant-admission-client";
import type { CapabilitySet, DirectClaimDraft, EligibilityView, LiveProductState, LiveProductViewModel } from "./live-product-view-model";

const CASE_CODE = /^[0-9A-HJKMNP-TV-Z]{16}$/u;
/** Canonical participants are EOAs, so the admission rail accepts one 65-byte signature only. */
const SIGNATURE = /^0x[0-9a-fA-F]{130}$/u;
const ADDRESS = /^0x[0-9a-fA-F]{40}$/u;
const SHA256_DIGEST = /^sha256:([0-9a-f]{64})$/u;
const CCP_CHAIN_ID = 10_143;
const CCP_VALIDATOR_ADDRESS = "0xac7e5179c2c7f03f209136886c172eb34f161792";
const CCP_GATE_ADDRESS = "0x3ffb28a13fd6dc372ae952f15b55263285d5a280";
const POLL_INTERVAL_MS = 2_000;
const FAILURES_BEFORE_UNAVAILABLE = 3;

const EMPTY_DRAFT: DirectClaimDraft = Object.freeze({ activeFrom: "", activeUntil: "" });
const IDLE_ELIGIBILITY: EligibilityView = Object.freeze({
  state: "IDLE", holderAddress: null, chainId: null, gateAddress: null, observedBlock: null, problem: null,
});

type LaunchAuthorization = Readonly<{
  token: string;
  expiresAt: number;
  holderAddress: string;
  eligibility: EligibilityView;
}>;

class WorkerResponseRejected extends Error {
  constructor() {
    super("The worker response could not be verified.");
    this.name = "WorkerResponseRejected";
  }
}

class WorkerRequestRejected extends Error {
  constructor(readonly status: number, readonly code: string | null) {
    super("The worker refused this participant admission.");
    this.name = "WorkerRequestRejected";
  }
}

function safeErrorCode(value: unknown): string | null {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return null;
  const code = (value as Record<string, unknown>).code;
  return typeof code === "string" && /^[A-Z_]{2,64}$/u.test(code) ? code : null;
}

async function bodyOrReject(response: Response): Promise<unknown> {
  let body: unknown = null;
  try {
    body = await response.json();
  } catch {
    if (response.ok) throw new WorkerResponseRejected();
  }
  if (!response.ok) throw new WorkerRequestRejected(response.status, safeErrorCode(body));
  return body;
}

function workerMessage(error: unknown, fallback: string): string {
  if (error instanceof WorkerResponseRejected) {
    return "The worker response could not be verified. No admission or result is shown.";
  }
  if (error instanceof WorkerRequestRejected) {
    if (error.status === 404) return "Participant admission is not enabled by this execution service.";
    if (error.status === 409 && error.code === "DUPLICATE_SIGNER") return "This wallet already holds the other role in this case.";
    if (error.status === 410 || error.code === "CASE_ABANDONED") return "This participant case is no longer accepting admissions.";
    if (error.status === 401 || error.status === 403) return "This wallet was not admitted by the active participant policy.";
    if (error.status === 429 || error.status === 507 || error.status === 503) return "The execution service cannot accept this admission right now. You can retry the same signed admission.";
    return "The execution service refused this admission. You can retry the same signed admission if it was already signed.";
  }
  return error instanceof Error && error.message !== "" ? error.message : fallback;
}

function parseOwnClaim(draft: DirectClaimDraft): AdmissionClaim | null {
  const activeFrom = /^\d+$/u.test(draft.activeFrom.trim()) ? Number(draft.activeFrom) : Number.NaN;
  const activeUntil = /^\d+$/u.test(draft.activeUntil.trim()) ? Number(draft.activeUntil) : Number.NaN;
  if (!Number.isSafeInteger(activeFrom) || !Number.isSafeInteger(activeUntil) || activeFrom < 0 || activeUntil <= activeFrom) return null;
  return Object.freeze({ activeFrom, activeUntil });
}

function sameAddress(left: string | null, right: string | null): boolean {
  return left !== null && right !== null && left.toLowerCase() === right.toLowerCase();
}

function exactRecord(value: unknown, keys: readonly string[]): value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function digestToBytes32(value: string): `0x${string}` | null {
  const match = SHA256_DIGEST.exec(value);
  return match === null ? null : `0x${match[1]}`;
}

function terminal(caseResponse: ParticipantCaseResponse | null): boolean {
  return caseResponse?.view.stage === "COMPLETE" || caseResponse?.view.stage === "ABORTED";
}

function eligibilityView(value: unknown, expectedHolder: string, expectedEligible: boolean): EligibilityView | null {
  if (!exactRecord(value, [
    "schemaVersion", "chainId", "validatorAddress", "gateAddress", "holderAddress", "eligible", "observedBlock",
  ])) return null;
  const eligibility = value;
  if (eligibility.schemaVersion !== "mordant.ccp-eligibility/1" || eligibility.chainId !== CCP_CHAIN_ID
    || typeof eligibility.validatorAddress !== "string" || !ADDRESS.test(eligibility.validatorAddress)
    || eligibility.validatorAddress.toLowerCase() !== CCP_VALIDATOR_ADDRESS
    || typeof eligibility.gateAddress !== "string" || !ADDRESS.test(eligibility.gateAddress)
    || eligibility.gateAddress.toLowerCase() !== CCP_GATE_ADDRESS
    || typeof eligibility.holderAddress !== "string" || !ADDRESS.test(eligibility.holderAddress)
    || !sameAddress(eligibility.holderAddress, expectedHolder)
    || eligibility.eligible !== expectedEligible
    || typeof eligibility.observedBlock !== "number" || !Number.isSafeInteger(eligibility.observedBlock) || eligibility.observedBlock < 0) return null;
  return Object.freeze({
    state: expectedEligible ? "VERIFIED" : "REFUSED",
    holderAddress: eligibility.holderAddress,
    chainId: eligibility.chainId,
    gateAddress: eligibility.gateAddress,
    observedBlock: eligibility.observedBlock,
    problem: expectedEligible ? null : "This wallet is not admitted by the active A-Pass policy.",
  });
}

function launchToken(value: unknown, workerOrigin: string, expectedHolder: string): LaunchAuthorization | null {
  if (!exactRecord(value, ["eligibility", "expiresAt", "schemaVersion", "token", "workerOrigin"])) return null;
  const body = value;
  const expiresAt = body.expiresAt;
  if (body.schemaVersion !== "mordant.live-launch-token/1" || typeof body.token !== "string" || body.token.length === 0
    || typeof expiresAt !== "number" || !Number.isSafeInteger(expiresAt) || expiresAt <= Date.now() || body.workerOrigin !== workerOrigin) return null;
  const eligibility = eligibilityView(body.eligibility, expectedHolder, true);
  if (eligibility === null) return null;
  return Object.freeze({ token: body.token, expiresAt, holderAddress: eligibility.holderAddress!, eligibility });
}

function refusedEligibility(value: unknown, expectedHolder: string): EligibilityView | null {
  if (!exactRecord(value, ["schemaVersion", "eligibility", "token"]) || value.schemaVersion !== "mordant.live-launch-token/1"
    || value.token !== null) return null;
  return eligibilityView(value.eligibility, expectedHolder, false);
}

/**
 * A dormant, real two-wallet controller. It creates a neutral worker case,
 * obtains one server-issued challenge for the active role's own interval, asks
 * Wagmi to sign it from the click handler, and then posts that exact signature.
 */
export function DirectParticipantExecution({
  workerOrigin,
  initialCaseCode,
  publicTestHolder,
  capabilitySet,
}: {
  readonly workerOrigin: string;
  readonly initialCaseCode: string | null;
  readonly publicTestHolder: string;
  readonly capabilitySet: CapabilitySet;
}) {
  const wallet = useMordantWallet();
  const [participantCase, setParticipantCase] = useState<ParticipantCaseResponse | null>(null);
  const [activeRole, setActiveRole] = useState<DirectParticipantRole | null>("A");
  const [ownDraft, setOwnDraft] = useState<DirectClaimDraft>(EMPTY_DRAFT);
  const [eligibility, setEligibility] = useState<EligibilityView>(IDLE_ELIGIBILITY);
  const [launchAuthorization, setLaunchAuthorization] = useState<LaunchAuthorization | null>(null);
  const [authorizing, setAuthorizing] = useState(false);
  const [pendingPost, setPendingPost] = useState<AdmissionPost | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const [notice, setNotice] = useState<LiveProductViewModel["notice"]>(null);
  const [noticeState, setNoticeState] = useState<LiveProductState | null>(null);
  const [walletModalOpen, setWalletModalOpen] = useState(false);
  const [restoring, setRestoring] = useState(initialCaseCode !== null && CASE_CODE.test(initialCaseCode));
  const [elapsed, setElapsed] = useState<number | null>(null);
  const failures = useRef(0);
  const startedAt = useRef<number | null>(null);

  const caseCode = participantCase?.admission.caseCode ?? initialCaseCode;

  // A token is wallet-bound presentation state. Changing accounts or networks
  // never carries a previous wallet's A-Pass verdict into the next role.
  useEffect(() => {
    if (activeRole === null) return;
    const stillBound = wallet.view.state === "CONNECTED" && wallet.view.address !== null
      && sameAddress(wallet.view.address, eligibility.holderAddress);
    if (!stillBound && (eligibility.state !== "IDLE" || launchAuthorization !== null)) {
      // Wallet changes synchronously invalidate every wallet-bound authorization view.
      // eslint-disable-next-line react-hooks/set-state-in-effect
      setEligibility(IDLE_ELIGIBILITY);
      setLaunchAuthorization(null);
    }
  }, [activeRole, eligibility.holderAddress, eligibility.state, launchAuthorization, wallet.view.address, wallet.view.state]);

  const readCase = useCallback(async (code: string): Promise<ParticipantCaseResponse> => {
    const response = await fetch(`${workerOrigin}/v1/participant-cases/${code}`, { cache: "no-store" });
    const body = await bodyOrReject(response);
    const parsed = parseParticipantCaseResponse(body);
    if (parsed === null || parsed.admission.caseCode !== code) throw new WorkerResponseRejected();
    return parsed;
  }, [workerOrigin]);

  const failClosed = useCallback((title: string, body: string) => {
    setNoticeState("SERVICE_UNAVAILABLE");
    setNotice({ title, body, retryable: true });
  }, []);

  const acceptCase = useCallback((next: ParticipantCaseResponse) => {
    setParticipantCase(next);
    if (startedAt.current === null) startedAt.current = Date.now();
    if (next.admission.bothAdmitted) {
      setActiveRole(null);
      setOwnDraft(EMPTY_DRAFT);
      setPendingPost(null);
      return;
    }
    if (next.admission.participantA.admitted) {
      setActiveRole(null);
      setOwnDraft(EMPTY_DRAFT);
      setPendingPost(null);
    } else {
      setActiveRole("A");
    }
  }, []);

  useEffect(() => {
    if (initialCaseCode === null || !CASE_CODE.test(initialCaseCode)) {
      return;
    }
    let cancelled = false;
    void (async () => {
      try {
        const restored = await readCase(initialCaseCode);
        if (!cancelled) acceptCase(restored);
      } catch (error) {
        if (!cancelled) {
          if (error instanceof WorkerResponseRejected) {
            failClosed("The participant-case response was rejected.", "No admission or result is shown because the worker projection was not valid.");
          } else {
            failClosed("This participant case could not be restored.", "No admission or result is shown until the worker can provide its public projection.");
          }
        }
      } finally {
        if (!cancelled) setRestoring(false);
      }
    })();
    return () => { cancelled = true; };
  }, [acceptCase, failClosed, initialCaseCode, readCase]);

  useEffect(() => {
    if (caseCode === null || !CASE_CODE.test(caseCode) || !participantCase?.admission.bothAdmitted || terminal(participantCase)
      || noticeState !== null) return;
    let cancelled = false;
    const timer = window.setInterval(() => {
      void (async () => {
        try {
          const next = await readCase(caseCode);
          if (cancelled) return;
          failures.current = 0;
          setParticipantCase(next);
        } catch (error) {
          if (cancelled) return;
          if (error instanceof WorkerResponseRejected) {
            failClosed("The participant-case response was rejected.", "No result is shown because the worker projection was not valid.");
            return;
          }
          failures.current += 1;
          if (failures.current >= FAILURES_BEFORE_UNAVAILABLE) {
            failClosed("The execution service did not answer.", "The participant case remains recorded. You can retry reading its public state.");
          }
        }
      })();
    }, POLL_INTERVAL_MS);
    return () => { cancelled = true; window.clearInterval(timer); };
  }, [caseCode, failClosed, noticeState, participantCase, readCase]);

  useEffect(() => {
    if (startedAt.current === null || terminal(participantCase)) return;
    const timer = window.setInterval(() => {
      setElapsed(Math.round((Date.now() - (startedAt.current ?? Date.now())) / 1_000));
    }, 1_000);
    return () => window.clearInterval(timer);
  }, [participantCase]);

  const createNeutralCase = useCallback(async (authorization: LaunchAuthorization): Promise<ParticipantCaseResponse> => {
    const response = await fetch(`${workerOrigin}/v1/participant-cases`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${authorization.token}` },
      body: "{}",
      cache: "no-store",
    });
    const body = await bodyOrReject(response);
    const created = parseParticipantCaseResponse(body);
    if (created === null || created.admission.participantA.admitted || created.admission.participantB.admitted) throw new WorkerResponseRejected();
    setParticipantCase(created);
    startedAt.current = Date.now();
    window.history.pushState(null, "", `/protection/live?caseCode=${created.admission.caseCode}`);
    return created;
  }, [workerOrigin]);

  const postAdmission = useCallback(async (post: AdmissionPost, currentCase: ParticipantCaseResponse) => {
    const response = await fetch(`${workerOrigin}/v1/participant-cases/${currentCase.admission.caseCode}/admissions`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      // The case code is bound by the URL; these four fields are the exact
      // browser request and the worker injects the URL value before validation.
      body: JSON.stringify({
        role: post.role,
        authorization: post.authorization,
        signature: post.signature,
        claim: post.claim,
      }),
      cache: "no-store",
    });
    const body = await bodyOrReject(response);
    const admitted = parseParticipantAdmissionResponse(body, {
      caseCode: currentCase.admission.caseCode,
      role: post.role,
      participantWallet: post.authorization.participantWallet,
    });
    if (admitted === null) throw new WorkerResponseRejected();
    acceptCase(admitted);
  }, [acceptCase, workerOrigin]);

  const checkEligibility = useCallback(async (role: DirectParticipantRole) => {
    if (authorizing || activeRole !== role || eligibility.state === "CHECKING") return;
    const walletAddress = wallet.view.address;
    if (wallet.view.state !== "CONNECTED" || walletAddress === null) {
      setFormError("Connect the wallet for this role on Monad testnet before checking its A-Pass.");
      return;
    }
    const reusable = launchAuthorization !== null
      && sameAddress(launchAuthorization.holderAddress, walletAddress)
      && launchAuthorization.expiresAt > Date.now();
    if (reusable) {
      setEligibility(launchAuthorization.eligibility);
      setFormError(null);
      return;
    }

    setEligibility(Object.freeze({
      state: "CHECKING", holderAddress: walletAddress, chainId: null, gateAddress: null, observedBlock: null, problem: null,
    }));
    setFormError(null);
    try {
      const response = await fetch("/api/live-protection/token", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ holderAddress: walletAddress }),
        cache: "no-store",
      });
      let body: unknown = null;
      try {
        body = await response.json();
      } catch {
        body = null;
      }
      const authorized = response.ok ? launchToken(body, workerOrigin, walletAddress) : null;
      if (authorized !== null) {
        setLaunchAuthorization(authorized);
        setEligibility(authorized.eligibility);
        return;
      }
      const refused = response.status === 403 ? refusedEligibility(body, walletAddress) : null;
      if (refused !== null) {
        setLaunchAuthorization(null);
        setEligibility(refused);
        return;
      }
      setLaunchAuthorization(null);
      setEligibility(Object.freeze({
        state: "ERROR", holderAddress: walletAddress, chainId: null, gateAddress: null, observedBlock: null,
        problem: "A-Pass eligibility could not be verified right now. No admission was requested.",
      }));
    } catch {
      setLaunchAuthorization(null);
      setEligibility(Object.freeze({
        state: "ERROR", holderAddress: walletAddress, chainId: null, gateAddress: null, observedBlock: null,
        problem: "A-Pass eligibility could not be verified right now. No admission was requested.",
      }));
    }
  }, [activeRole, authorizing, eligibility.state, launchAuthorization, wallet.view.address, wallet.view.state, workerOrigin]);

  const authorize = useCallback(async (role: DirectParticipantRole) => {
    if (authorizing || activeRole !== role) return;
    if (pendingPost !== null) {
      setAuthorizing(true);
      setFormError(null);
      try {
        if (participantCase === null) throw new WorkerResponseRejected();
        await postAdmission(pendingPost, participantCase);
      } catch (error) {
        if (error instanceof WorkerResponseRejected) {
          failClosed("The admission response was rejected.", "The signed admission was not accepted into the screen because the worker projection was invalid. You may retry the same signed admission.");
        } else {
          setFormError(workerMessage(error, "The signed admission could not be posted."));
        }
      } finally {
        setAuthorizing(false);
      }
      return;
    }

    const claim = parseOwnClaim(ownDraft);
    if (claim === null) {
      setFormError("Enter a whole-number interval where active from is strictly before active until.");
      return;
    }
    const walletAddress = wallet.view.address;
    if (wallet.view.state !== "CONNECTED" || walletAddress === null) {
      setFormError("Connect the wallet for this role on Monad testnet before authorizing its claim.");
      return;
    }
    if (eligibility.state !== "VERIFIED" || !sameAddress(eligibility.holderAddress, walletAddress)) {
      setFormError("Check this wallet's A-Pass before authorizing its claim.");
      return;
    }
    const otherWallet = role === "A" ? participantCase?.admission.participantB.wallet ?? null : participantCase?.admission.participantA.wallet ?? null;
    if (sameAddress(walletAddress, otherWallet)) {
      setFormError("This address already holds the other role in this case. Connect a different wallet.");
      return;
    }

    setAuthorizing(true);
    setFormError(null);
    try {
      const reusableLaunch = launchAuthorization !== null
        && sameAddress(launchAuthorization.holderAddress, walletAddress)
        && launchAuthorization.expiresAt > Date.now();
      if (participantCase === null && !reusableLaunch) {
        setFormError("The A-Pass launch authorization has expired. Check this wallet's A-Pass again before creating a neutral case.");
        return;
      }
      const currentCase = participantCase ?? await createNeutralCase(launchAuthorization!);
      const workerRole = workerRoleFor(role);
      const fheCaseId = digestToBytes32(currentCase.view.protectionCase.fheCaseId);
      const assetIdentityDigest = digestToBytes32(currentCase.view.protectionCase.cleanverseAssetDigest);
      if (fheCaseId === null || assetIdentityDigest === null) throw new WorkerResponseRejected();
      const challengeResponse = await fetch(`${workerOrigin}/v1/participant-cases/${currentCase.admission.caseCode}/challenge`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ role: workerRole, participantWallet: walletAddress, claim }),
        cache: "no-store",
      });
      const challengeBody = await bodyOrReject(challengeResponse);
      const challenge = parseParticipantChallengeResponse(challengeBody, {
        runId: currentCase.admission.runId,
        role: workerRole,
        participantWallet: walletAddress,
        claim,
        fheCaseId,
        assetIdentityDigest,
        expectedChainId: wallet.view.expectedChainId,
        expectedService: window.location.origin,
        nowUnixSeconds: Math.floor(Date.now() / 1_000),
      });
      if (challenge === null) throw new WorkerResponseRejected();
      // This is the only call that can open a signature request. It occurs only
      // in response to the participant pressing the authorization button.
      const signature = await wallet.signParticipantAdmission(challenge);
      if (!SIGNATURE.test(signature)) throw new WorkerResponseRejected();
      const post: AdmissionPost = Object.freeze({ role: workerRole, authorization: challenge.message, signature, claim });
      // Preserve this exact signed payload before the POST. A lost response can
      // therefore be retried without a second challenge or signature.
      setPendingPost(post);
      await postAdmission(post, currentCase);
    } catch (error) {
      if (error instanceof WorkerResponseRejected) {
        failClosed("The worker response was rejected.", "No admission or result is shown because the worker projection was not valid. A signed admission can be retried without signing again.");
      } else {
        setFormError(workerMessage(error, "The typed authorization could not be completed."));
      }
    } finally {
      setAuthorizing(false);
    }
  }, [activeRole, authorizing, createNeutralCase, eligibility.holderAddress, eligibility.state, failClosed, launchAuthorization, ownDraft, participantCase, pendingPost, postAdmission, wallet]);

  const retry = useCallback(() => {
    failures.current = 0;
    setNotice(null);
    setNoticeState(null);
  }, []);

  const model = useMemo(() => adaptDirectParticipantIntake({
    view: participantCase?.view ?? null,
    admission: participantCase?.admission ?? null,
    capabilitySet,
    activeRole,
    eligibility,
    ownDraft,
    wallet: wallet.view,
    authorizing,
    retryReady: pendingPost !== null,
    elapsedSeconds: terminal(participantCase) ? null : elapsed,
    notice: restoring && participantCase === null && notice === null
      ? { title: "Restoring this participant case.", body: "Reading the durable public admission state.", retryable: false }
      : notice,
    noticeState: restoring && participantCase === null && notice === null ? "RECOVERY_AVAILABLE" : noticeState,
  }), [activeRole, authorizing, capabilitySet, eligibility, elapsed, notice, noticeState, ownDraft, participantCase, pendingPost, restoring, wallet.view]);

  return (
    <>
      <LiveProduct
        model={model}
        draft={null}
        invalidFields={[]}
        formError={formError}
        holderDraft=""
        publicTestHolder={publicTestHolder}
        busy={authorizing || wallet.busy}
        actions={{
          onConnectWallet: (role) => { if (activeRole === role) setWalletModalOpen(true); },
          onSwitchNetwork: () => { void wallet.switchToMonad(); },
          onDisconnect: () => { void wallet.disconnect(); },
          onCheckEligibility: (role) => { if (role !== undefined) void checkEligibility(role); },
          onAuthorizeClaim: (role) => { void authorize(role); },
          onDirectDraftChange: (key, value) => {
            // A retry must use the exact signed payload. The fields are disabled
            // in the surface too; this guard keeps programmatic events honest.
            if (pendingPost !== null) return;
            setFormError(null);
            setOwnDraft((current) => Object.freeze({ ...current, [key]: value }));
          },
          onContinueAsParticipantB: () => {
            setActiveRole("B");
            setOwnDraft(EMPTY_DRAFT);
            setEligibility(IDLE_ELIGIBILITY);
            setLaunchAuthorization(null);
            setFormError(null);
          },
          onRetry: retry,
        }}
      />
      <WalletModal
        open={walletModalOpen}
        role={activeRole ?? "A"}
        receivable={model.assetLabel}
        onClose={() => setWalletModalOpen(false)}
      />
    </>
  );
}
