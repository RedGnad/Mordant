"use client";

import Link from "next/link";
import { useEffect, useRef, useState } from "react";

import {
  PRIVATE_CONFLICT_STEPS,
  PRODUCT_EXECUTION_LABELS,
  evidenceForDisplayedCase,
  recoursePresentation,
  recourseStatePresentation,
} from "@/lib/protection/protection-presentation";
import type { MordantProtectionEvidence } from "@/lib/protection/protection-evidence";
import type { ProductScenario } from "@/lib/protection/protection-case";
import type { ProtectionCaseView } from "@/lib/protection/governed-fhe-product-server";

import styles from "./protection-experience.module.css";

const ENDPOINT = "/api/protection/conflicting-pledge";

type ImportedView = Readonly<{
  schemaVersion: "mordant.protection-imported-view/1";
  presentation: "IMPORTED_COMPLETED_EVIDENCE";
  evidence: MordantProtectionEvidence;
}>;

type RequestState = "idle" | "loading" | "executing";

const STAGE_INDEX: Readonly<Record<ProtectionCaseView["stage"], number>> = {
  CASE_CREATED: 0,
  MATCH_PREPARED: 0,
  PARTICIPANT_A_SUBMITTED: 1,
  PARTICIPANT_B_PUBLISHED: 2,
  PARTICIPANT_B_SUBMITTED: 2,
  EVALUATED: 3,
  RELEASED: 5,
  RECOURSE_OPENED: 5,
  CHRONOLOGY_COMPLETE: 5,
  COMPLETE: 5,
  ABORTED: 0,
};

const OPERATION: Readonly<Record<string, Readonly<{ api: string; label: string; support: string }>>> = {
  preparePrivateMatch: {
    api: "preparePrivateMatch",
    label: "Prepare private match",
    support: "Runs the disk preflight, fixes the holder snapshot, and creates the case-specific N15 key.",
  },
  "submitParticipantPledge:PARTICIPANT_A": {
    api: "submitParticipantA",
    label: "Submit participant A",
    support: "Encrypts participant A’s synthetic pledge in its participant process.",
  },
  "submitParticipantPledge:PARTICIPANT_B": {
    api: "submitParticipantB",
    label: "Submit participant B",
    support: "Encrypts participant B’s synthetic pledge and seals the immutable case manifest.",
  },
  evaluatePrivateConflict: {
    api: "evaluatePrivateConflict",
    label: "Evaluate private conflict",
    support: "Runs the one fixed BGV circuit. This is the longest local step.",
  },
  releaseGovernedResult: {
    api: "releaseGovernedResult",
    label: "Verify and release Boolean",
    support: "The designated decryptor recomputes the circuit, releases one Boolean, and signs it.",
  },
  openRecourseCase: {
    api: "openRecourseCase",
    label: "Apply governed result",
    support: "Verifies trusted pins and either opens the cure record or refuses recourse.",
  },
  completeCureChronology: {
    api: "completeCureChronology",
    label: "Complete cure chronology",
    support: "Advances only the local protocol-double chronology beyond the recorded cure deadline.",
  },
  exportProtectionEvidence: {
    api: "exportProtectionEvidence",
    label: "Seal public evidence",
    support: "Exports the public digest-only protection manifest for independent readback.",
  },
};

function compact(value: string, leading = 11, trailing = 9): string {
  return value.length <= leading + trailing + 1 ? value : `${value.slice(0, leading)}…${value.slice(-trailing)}`;
}

function formatAmount(value: string): string {
  const raw = BigInt(value);
  return `${raw / 1_000_000n}.${((raw % 1_000_000n) / 10_000n).toString().padStart(2, "0")}`;
}

async function body<T extends object>(response: Response): Promise<T> {
  const value = await response.json() as T | { error?: string };
  if (!response.ok) throw new Error("error" in value && value.error ? value.error : "Protection backend refused the operation.");
  return value as T;
}

function EvidenceDrawer({ evidence, onClose }: {
  readonly evidence: MordantProtectionEvidence;
  readonly onClose: () => void;
}) {
  const titleRef = useRef<HTMLHeadingElement>(null);
  useEffect(() => {
    titleRef.current?.focus({ preventScroll: true });
    const escape = (event: KeyboardEvent) => { if (event.key === "Escape") onClose(); };
    window.addEventListener("keydown", escape);
    return () => window.removeEventListener("keydown", escape);
  }, [onClose]);
  const rows = [
    ["Asset record", evidence.cleanverseAssetDigest],
    ["Protection binding", evidence.protectionAuthorization.bindingDigest],
    ["Protection signature A", evidence.protectionAuthorization.participantSignatures[0].signature],
    ["Protection signature B", evidence.protectionAuthorization.participantSignatures[1].signature],
    ["FHE CaseID", evidence.fhe.caseId],
    ["Case binding", evidence.fhe.caseBindingDigest],
    ["Profile", evidence.fhe.profile],
    ["Circuit", `${evidence.fhe.circuitId} · v${evidence.fhe.circuitVersion}`],
    ["Participant A", evidence.fhe.participantArtifactDigests[0]],
    ["Participant B", evidence.fhe.participantArtifactDigests[1]],
    ["Evaluated artifact", evidence.fhe.evaluatedArtifactDigest],
    ["Result ciphertext", `${evidence.fhe.resultCiphertext.sha256} · ${evidence.fhe.resultCiphertext.length.toLocaleString()} B`],
    ["Recomputed result", evidence.fhe.independentlyRecomputedResultDigest],
    ["Signed result", evidence.governedResult.digest],
    ["Signature", evidence.governedResult.signature],
    ["Release authority", evidence.governedResult.releaseAuthorityId],
    ["Release mode", evidence.governedResult.releaseMode],
    ["Recourse record", evidence.recourse.record === null ? "Refused by signed false result" : String(evidence.recourse.record.resultDigest)],
    ["Recourse attestation", evidence.recourseAttestation.digest],
    ["Attestation signature", evidence.recourseAttestation.attestation.signature],
  ] as const;
  return (
    <div className={styles.drawerBackdrop} role="presentation" onMouseDown={(event) => {
      if (event.currentTarget === event.target) onClose();
    }}>
      <aside className={styles.drawer} role="dialog" aria-modal="true" aria-labelledby="evidence-title">
        <header className={styles.drawerHeader}>
          <div>
            <p>Public evidence · digest view</p>
            <h2 id="evidence-title" ref={titleRef} tabIndex={-1}>Case evidence</h2>
          </div>
          <button type="button" onClick={onClose} aria-label="Close evidence drawer">Close</button>
        </header>
        <div className={styles.drawerBody}>
          <p className={styles.drawerNotice}>Large ciphertexts and evaluation keys stay out of the page. Only public references, digests, sizes and signatures are shown.</p>
          <dl className={styles.evidenceList}>
            {rows.map(([label, value]) => (
              <div key={label}><dt>{label}</dt><dd title={value}>{compact(value, 18, 14)}</dd></div>
            ))}
          </dl>
          <section className={styles.classifications}>
            <h3>Source classifications</h3>
            {evidence.sourceClassifications.map((source) => (
              <article key={source.subject} data-classification={source.classification}>
                <strong>{source.classification.replaceAll("_", " ")}</strong>
                <span>{source.subject}</span>
                <p>{source.detail}</p>
              </article>
            ))}
          </section>
          <footer className={styles.drawerDigest}>
            <span>Protection evidence manifest</span>
            <code>{evidence.manifestDigest}</code>
          </footer>
        </div>
      </aside>
    </div>
  );
}

export function ProtectionExperience({
  initialEvidence,
  localExecutionAvailable,
}: {
  readonly initialEvidence: MordantProtectionEvidence;
  readonly localExecutionAvailable: boolean;
}) {
  const [scenario, setScenario] = useState<ProductScenario>(initialEvidence.scenario);
  const [evidence, setEvidence] = useState(initialEvidence);
  const [localView, setLocalView] = useState<ProtectionCaseView | null>(null);
  const [mode, setMode] = useState<"imported" | "local">("imported");
  const [requestState, setRequestState] = useState<RequestState>("idle");
  const [error, setError] = useState<string | null>(null);
  const [drawerOpen, setDrawerOpen] = useState(false);

  const localMode = mode === "local";
  const activeCase = localMode ? localView?.protectionCase ?? null : evidence.protectionCase;
  const activeEvidence = evidenceForDisplayedCase(mode, evidence, localView);
  const completedStep = localMode && localView !== null ? STAGE_INDEX[localView.stage] : localMode ? 0 : 5;
  const recourse = localMode
    ? recourseStatePresentation(localView?.protectionCase.recourseState ?? "NOT_OPEN")
    : recoursePresentation(evidence);
  const conflict = localMode ? localView?.governedResult?.conflict ?? null : evidence.governedResult.conflict;
  const currentOperation = localView?.nextOperation === null || localView?.nextOperation === undefined
    ? null : OPERATION[localView.nextOperation] ?? null;

  async function selectImportedScenario(next: ProductScenario) {
    setRequestState("loading");
    setError(null);
    setDrawerOpen(false);
    setMode("imported");
    setLocalView(null);
    try {
      const response = await fetch(`${ENDPOINT}?scenario=${next}`, { cache: "no-store" });
      const imported = await body<ImportedView>(response);
      setScenario(next);
      setEvidence(imported.evidence);
    } catch (nextError) {
      setError(nextError instanceof Error ? nextError.message : "Evidence readback failed");
    } finally {
      setRequestState("idle");
    }
  }

  async function startLocalRun() {
    setRequestState("executing");
    setError(null);
    setDrawerOpen(false);
    setMode("local");
    setLocalView(null);
    try {
      const response = await fetch(ENDPOINT, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ intent: "create", scenario }),
      });
      setLocalView(await body<ProtectionCaseView>(response));
    } catch (nextError) {
      setError(nextError instanceof Error ? nextError.message : "Local case creation failed");
    } finally {
      setRequestState("idle");
    }
  }

  async function executeNext() {
    if (localView === null || currentOperation === null) return;
    setRequestState("executing");
    setError(null);
    try {
      const response = await fetch(ENDPOINT, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ intent: "execute", runId: localView.runId, operation: currentOperation.api }),
      });
      setLocalView(await body<ProtectionCaseView>(response));
    } catch (nextError) {
      setError(nextError instanceof Error ? nextError.message : "Local protection operation failed");
    } finally {
      setRequestState("idle");
    }
  }

  return (
    <div className={styles.page} data-testid="protection-product" data-execution={localMode ? "local" : "imported"}>
      <a className={styles.skip} href="#protection-main">Skip to protection case</a>
      <header className={styles.chrome}>
        <Link href="/" className={styles.brand} aria-label="Mordant home">
          <svg viewBox="0 0 100 100" aria-hidden="true"><rect x="43" width="14" height="100" /><rect y="43" width="100" height="14" /><rect x="43" width="14" height="100" transform="rotate(45 50 50)" /><rect x="43" width="14" height="100" transform="rotate(-45 50 50)" /></svg>
          <span>Mordant</span>
          <small>Asset protection</small>
        </Link>
        <nav aria-label="Protection navigation">
          <Link href="/workspace">Workspace</Link>
          <span aria-current="page">Conflicting Pledge Protection</span>
          <button type="button" disabled={activeEvidence === null} onClick={() => setDrawerOpen(true)}>Evidence</button>
        </nav>
      </header>

      <div className={styles.boundaryBar}>
        <span>{localMode ? PRODUCT_EXECUTION_LABELS.fhe : PRODUCT_EXECUTION_LABELS.web}</span>
        <span>{PRODUCT_EXECUTION_LABELS.recourse}</span>
      </div>

      <main id="protection-main" className={styles.main} tabIndex={-1}>
        <section className={styles.assetHeader}>
          <div className={styles.assetTitle}>
            <p className={styles.eyebrow}>Cleanverse receivable · Monad testnet</p>
            <h1>Protect <span>MINV01</span> from conflicting pledges.</h1>
            <p>The asset is the case root. One classified Cleanverse record binds the private match, signed result, cure chronology and recourse evidence.</p>
          </div>
          <div className={styles.outcome} data-conflict={conflict === null ? "pending" : conflict ? "true" : "false"}>
            <span>Current conclusion</span>
            <strong>{conflict === null ? "Private check in progress" : conflict ? "Conflict confirmed" : "No conflict found"}</strong>
            <p>{recourse.label}</p>
          </div>
        </section>

        <section className={styles.controlStrip} aria-label="Evidence scenario controls">
          <div>
            <span>Completed evidence</span>
            <div className={styles.segmented}>
              {(["conflict", "no-conflict"] as const).map((option) => (
                <button key={option} type="button" aria-pressed={!localMode && scenario === option} disabled={requestState !== "idle"} onClick={() => void selectImportedScenario(option)}>
                  {option === "conflict" ? "Conflict" : "No conflict"}
                </button>
              ))}
            </div>
          </div>
          <p>{localMode ? "Local run · real BGV · single host" : "Imported retained run · not browser-side execution"}</p>
          {localExecutionAvailable ? (
            <button className={styles.localButton} type="button" disabled={requestState !== "idle"} onClick={() => void startLocalRun()}>
              {localMode ? "Start a fresh local case" : "Run this case locally"}
            </button>
          ) : null}
        </section>

        {error === null ? null : <p className={styles.error} role="alert">{error}</p>}

        {activeCase === null ? (
          <section className={styles.localStatus} data-testid="local-case-status" aria-live="polite">
            <p>{error === null ? "Creating a new local protection case…" : "Local protection case unavailable"}</p>
            <strong>{error === null ? "Imported case data is withheld while the local run is loading." : error}</strong>
          </section>
        ) : (
          <>
          <div className={styles.productGrid}>
          <section className={styles.assetCard} aria-labelledby="asset-heading">
            <header><p>Root product object</p><h2 id="asset-heading">Cleanverse asset</h2></header>
            <dl>
              <div><dt>Asset identity</dt><dd title={activeCase.cleanverseAssetDigest}>{compact(activeCase.cleanverseAssetDigest)}</dd></div>
              <div><dt>A-Token / CVA</dt><dd title={activeCase.cleanverseAsset.token.value.address}>MINV01 · {compact(activeCase.cleanverseAsset.token.value.address)}</dd></div>
              <div><dt>Source</dt><dd>Cleanverse request {activeCase.cleanverseAsset.sourceIdentity.value.cleanverseRequestId}</dd></div>
              <div><dt>Issuer identity</dt><dd>Admin address observed · legal identity unproven</dd></div>
              <div><dt>A-Pass</dt><dd>Holder profiles admitted at observation</dd></div>
              <div><dt>Settlement asset</dt><dd>aUSDC · identity observed, not settled in this slice</dd></div>
              <div><dt>Terms / policy</dt><dd>{activeCase.cleanverseAsset.documentationTerms.value.version} documented · min tier 50 observed</dd></div>
              <div><dt>Issuance</dt><dd>Deployment block {activeCase.cleanverseAsset.tokenDeployment.value.blockNumber} · {compact(activeCase.cleanverseAsset.issuance.value.transactionHash)}</dd></div>
            </dl>
            <footer><span>LIVE OBSERVED</span><p>Issuance and readback are retained evidence, not a fresh browser observation.</p></footer>
          </section>

          <section className={styles.protectionCard} aria-labelledby="protection-heading">
            <header><p>Mordant service · v{activeCase.serviceVersion}</p><h2 id="protection-heading">Protection case</h2></header>
            <div className={styles.moneyDomains}>
              <article><span>Protected amount</span><strong>{formatAmount(activeCase.protectedAmount.minorUnits)} <small>aUSDC</small></strong><p>Fixture amount</p></article>
              <article><span>Separate reserve · 10%</span><strong>{formatAmount(activeCase.reserve.minorUnits)} <small>aUSDC</small></strong><p>Protocol double</p></article>
            </div>
            <dl>
              <div><dt>Protection status</dt><dd>{activeCase.incidentState.replaceAll("_", " ")}</dd></div>
              <div><dt>Holder record date</dt><dd>{new Date(activeCase.holderRecordDate).toLocaleString("en-GB", { timeZone: "UTC" })} UTC</dd></div>
              <div><dt>Snapshot</dt><dd>Holder A 60% · Holder B 40%</dd></div>
              <div><dt>FHE CaseID</dt><dd title={activeCase.fheCaseId}>{compact(activeCase.fheCaseId)}</dd></div>
              <div><dt>Recourse</dt><dd>{activeCase.recourseState.replaceAll("_", " ")}</dd></div>
              <div><dt>Original claim</dt><dd className={styles.intact}>Outstanding · 100 units intact</dd></div>
            </dl>
          </section>

          <section className={styles.matchCard} aria-labelledby="match-heading">
            <header><p>Private conflict check</p><h2 id="match-heading">One fixed Boolean</h2></header>
            <ol>
              {PRIVATE_CONFLICT_STEPS.map((step, index) => (
                <li key={step} data-complete={index <= completedStep ? "true" : "false"}>
                  <i aria-hidden="true">{index < completedStep || !localMode ? "✓" : index === completedStep ? "•" : index + 1}</i>
                  <span>{step}</span>
                </li>
              ))}
            </ol>
            <div className={styles.matchBoundary}>
              <span>{FHE_PROFILE_LABEL}</span>
              <span>Evaluator has no decrypt key</span>
              <span>Release · {activeCase.releaseMode}</span>
            </div>
            {localMode && currentOperation !== null ? (
              <div className={styles.nextAction}>
                <p>{currentOperation.support}</p>
                <button type="button" disabled={requestState !== "idle"} onClick={() => void executeNext()}>
                  {requestState === "executing" ? "Working…" : currentOperation.label}
                </button>
              </div>
            ) : (
              <button className={styles.evidenceButton} type="button" disabled={activeEvidence === null} onClick={() => setDrawerOpen(true)}>
                {activeEvidence === null ? "Evidence available after sealing" : "Open complete evidence"}
              </button>
            )}
          </section>
          </div>

          <section className={styles.timeline} aria-labelledby="timeline-heading">
          <header><p>Case chronology</p><h2 id="timeline-heading">Asset → private result → recourse</h2></header>
          <ol>
            {activeCase.timeline.map((event) => (
              <li key={`${event.ordinal}-${event.kind}`}>
                <time>{new Date(event.at).toLocaleString("en-GB", { day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit", timeZone: "UTC" })}</time>
                <i aria-hidden="true" />
                <div><strong>{event.label}</strong><span>{event.classification.replaceAll("_", " ")}</span></div>
              </li>
            ))}
            <li className={styles.claimRetained}>
              <time>Retained</time><i aria-hidden="true" />
              <div><strong>Original receivable claim remains intact</strong><span>RECEIVABLE DOMAIN · NO PROTECTION BURN OR TRANSFER</span></div>
            </li>
          </ol>
          </section>
          </>
        )}

        <section className={styles.claimBoundary}>
          <p>{PRODUCT_CLAIM}</p>
          <strong>{PRODUCT_DISCLOSURE}</strong>
        </section>
      </main>

      {drawerOpen && activeEvidence !== null ? <EvidenceDrawer evidence={activeEvidence} onClose={() => setDrawerOpen(false)} /> : null}
    </div>
  );
}

const FHE_PROFILE_LABEL = "BGV · IdentityFullFHE256 · N15";
const PRODUCT_CLAIM = "Mordant protects a tokenized receivable with a private conflict check and governed recourse. The parties’ pledge records are evaluated under BGV fully homomorphic encryption. The evaluator cannot inspect the inputs or dictate the released result. A designated governed decryptor independently recomputes the fixed circuit, decrypts the final Boolean, and signs it into the recourse workflow.";
const PRODUCT_DISCLOSURE = "The MVP uses a designated trusted decryptor and local single-host execution. Threshold output release and production custody isolation remain post-MVP upgrades.";
