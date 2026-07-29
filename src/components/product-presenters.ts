import type {
  DomainAmount,
  EvidenceClassification,
  GateCheck,
  GateStatus,
  MonetaryDomain,
  Observation,
  ParticipantPosition,
  ParticipantRole,
  SyntheticDeal,
} from "@/lib/mordant/product-model";
import { proRateAmount } from "@/lib/mordant/product-model";
import { syntheticFolioForScenario } from "@/lib/mordant/identity";
import type { EvidenceFact, GateTone, GateView } from "@/components/structural-ui";

const GATE_STATUS_COPY: Readonly<Record<GateStatus, { label: string; tone: GateTone }>> = {
  satisfied: { label: "Clear", tone: "pass" },
  blocked: { label: "Blocked", tone: "blocked" },
  pending: { label: "Waiting", tone: "wait" },
  unknown: { label: "Unknown", tone: "attention" },
  not_applicable: { label: "Not required", tone: "complete" },
};

export function gateToView(gate: GateCheck): GateView {
  const status = GATE_STATUS_COPY[gate.status];
  return {
    kind: gate.kind,
    label: gate.label,
    status: status.label,
    detail: gate.detail,
    tone: status.tone,
    ...(gate.remediation ? { resolution: gate.remediation } : {}),
  };
}

export function formatDomainAmount(amount: DomainAmount<MonetaryDomain>, fractionDigits = 2): string {
  const scale = 10n ** BigInt(amount.asset.decimals);
  const raw = BigInt(amount.minorUnits);
  const whole = raw / scale;
  const fraction = (raw % scale).toString().padStart(amount.asset.decimals, "0").slice(0, fractionDigits);
  return fractionDigits > 0 ? `${whole.toLocaleString("en-US")}.${fraction}` : whole.toLocaleString("en-US");
}

/**
 * Derives the connected participant's exact monetary exposure using integer
 * minor units. The model helper rejects non-representable fractions rather
 * than permitting display-only rounding to change the economic meaning.
 */
export function proRateDomainAmount<D extends MonetaryDomain>(
  source: DomainAmount<D>,
  position: ParticipantPosition,
): DomainAmount<D> {
  return proRateAmount(source, position);
}

export function formatState(value: string): string {
  return value
    .split("_")
    .map((part) => `${part.charAt(0).toUpperCase()}${part.slice(1)}`)
    .join(" ");
}

export function formatRole(role: ParticipantRole): string {
  return role
    .split("_")
    .map((part) => `${part.charAt(0).toUpperCase()}${part.slice(1)}`)
    .join(" ");
}

export function formatUtc(timestamp?: string): string {
  if (!timestamp) return "Not observed";
  return new Intl.DateTimeFormat("en-GB", {
    day: "2-digit",
    month: "short",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    hourCycle: "h23",
    timeZone: "UTC",
    timeZoneName: "short",
  }).format(new Date(timestamp));
}

export function shortReference(reference: string, front = 14, back = 8): string {
  if (reference.length <= front + back + 1) return reference;
  return `${reference.slice(0, front)}…${reference.slice(-back)}`;
}

export function observationCopy(observation: Observation) {
  return {
    block: observation.finality.syntheticBlock ?? "Unknown",
    time: formatUtc(observation.freshness.observedAt),
    finality: formatState(observation.finality.status),
    freshness: formatState(observation.freshness.status),
  };
}

export function evidenceTone(classification: EvidenceClassification): EvidenceFact["tone"] {
  switch (classification) {
    case "observed_onchain":
      return "observed";
    case "attested":
      return "attested";
    case "derived_by_mordant":
      return "derived";
    case "external_unverified":
      return "external";
  }
}

export function dealShortId(deal: SyntheticDeal): string {
  return syntheticFolioForScenario(deal.scenario);
}

export function responsibilityDue(deal: SyntheticDeal): string {
  if (!deal.nextResponsibility.dueAt) return "No deadline";
  return formatUtc(deal.nextResponsibility.dueAt);
}
