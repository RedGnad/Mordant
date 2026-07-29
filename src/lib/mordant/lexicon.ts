/**
 * Canonical product language for the synthetic Mordant prototype.
 *
 * These definitions describe software states and demo accounting only. They do
 * not create legal characterizations, priority, insurance, or production claims.
 */

export const MORDANT_TERMS = [
  "receivable",
  "protection",
  "reserve",
  "claim",
  "pledge",
  "conflict",
  "cure",
  "entitlement",
  "settlement",
  "release",
  "redemption",
  "recovery",
] as const;

export type MordantTerm = (typeof MORDANT_TERMS)[number];

export type LexiconEntry = Readonly<{
  label: string;
  participant: string;
  operator: string;
  technical: string;
  error: string;
}>;

export const MORDANT_LEXICON: Readonly<Record<MordantTerm, LexiconEntry>> = {
  receivable: {
    label: "Receivable",
    participant: "The buyer-accepted invoice amount represented by your invoice units.",
    operator: "The invoice accounting domain, independent from funded protection.",
    technical: "Receivable machine and ledger bound to one immutable synthetic invoice root.",
    error: "The receivable state could not be read; do not infer redemption or ownership changes.",
  },
  protection: {
    label: "Protection",
    participant: "A separately funded policy consequence that may become payable after configured events.",
    operator: "The recourse domain governed by its own state machine and reserve ledger.",
    technical: "Protection policy state bound to one vault and one immutable policy identifier.",
    error: "Protection availability is unknown; the receivable remains a separate accounting domain.",
  },
  reserve: {
    label: "Reserve",
    participant: "Synthetic protection money held separately from invoice repayment money.",
    operator: "The funded amount required by the configured protection policy.",
    technical: "Locked protection-domain balance, amortized against protected outstanding principal.",
    error: "The reserve balance is unavailable; do not present protection as funded.",
  },
  claim: {
    label: "Claim",
    participant: "A request to receive an available protection entitlement.",
    operator: "A protection-only action that does not burn or transfer invoice units.",
    technical: "Protection settlement call against a crystallized entitlement.",
    error: "The claim could not be prepared; invoice-unit ownership is unchanged.",
  },
  pledge: {
    label: "Pledge",
    participant: "A party’s attested financing assertion about the invoice inside this workflow.",
    operator: "A participant assertion registered for the configured conflict policy.",
    technical: "Signed synthetic pledge reference; not universal duplicate-financing evidence.",
    error: "The pledge assertion is missing or invalid; no off-network conclusion is established.",
  },
  conflict: {
    label: "Conflict",
    participant: "An overlapping pledge registered inside the configured Mordant workflow.",
    operator: "A policy event that can open a cure period in the protection machine.",
    technical: "A synthetic conflict transition; not proof of fraud or legal priority.",
    error: "The conflict record is incomplete; refresh evidence before presenting a consequence.",
  },
  cure: {
    label: "Cure",
    participant: "The configured step responsible parties can take before protection becomes claimable.",
    operator: "A protection transition that resolves a registered conflict without changing receivable units.",
    technical: "Authorized cure action from cure_period to active under the policy.",
    error: "The cure is not available; show the blocking gate, responsible role, and deadline.",
  },
  entitlement: {
    label: "Entitlement",
    participant: "Your calculated share of protection if the policy makes it claimable.",
    operator: "A record-date allocation in the protection domain.",
    technical: "Pro-rata protection allocation derived from immutable invoice-unit positions.",
    error: "The entitlement could not be derived exactly; do not display a rounded estimate.",
  },
  settlement: {
    label: "Settlement",
    participant: "Payment in the named domain: protection settlement or receivable redemption.",
    operator: "A finalized money movement whose domain must always be explicit.",
    technical: "Terminal domain-specific monetary effect linked to a receipt and state readback.",
    error: "Settlement is not established until a receipt and consistent state readback are present.",
  },
  release: {
    label: "Release",
    participant: "Protection reserve returned after its configured obligation ends.",
    operator: "A terminal protection-only transition when no entitlement remains.",
    technical: "Reserve release from the protection ledger; no receivable-unit effect.",
    error: "Release is not established; keep the reserve state unresolved until readback succeeds.",
  },
  redemption: {
    label: "Redemption",
    participant: "Buyer-funded payment of the receivable for redeemed invoice units.",
    operator: "A receivable-only settlement that burns exactly the units paid.",
    technical: "Receivable transition with to-holder payment and burn_redeemed_units effect.",
    error: "Redemption is not established; do not show invoice units as burned without consistent readback.",
  },
  recovery: {
    label: "Recovery",
    participant: "A restricted operations process used when a protocol result cannot be trusted.",
    operator: "An explicit runbook from the last safe state; never an automatic retry.",
    technical: "Protocol-operator reconciliation after missing receipt, failed simulation, or inconsistent after-state.",
    error: "Recovery required: stop execution, preserve the last safe state, and follow the selected-record runbook.",
  },
};

export const EVIDENCE_BOUNDARIES = {
  observed: {
    label: "Observed",
    meaning: "A named source returned this field at a stated time or block.",
  },
  attested: {
    label: "Attested",
    meaning: "A named participant asserted or signed this information.",
  },
  derived: {
    label: "Derived",
    meaning: "Mordant computed this interpretation from named inputs and rules.",
  },
  external: {
    label: "Not established",
    meaning: "This record cannot establish the external fact or legal conclusion.",
  },
} as const;

export function lexiconEntry(term: MordantTerm): LexiconEntry {
  return MORDANT_LEXICON[term];
}
