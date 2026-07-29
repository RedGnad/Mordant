import type { Metadata } from "next";

import {
  formatDomainAmount,
  formatState,
  proRateDomainAmount,
} from "@/components/product-presenters";
import { getSyntheticDeal } from "@/lib/mordant/product-model";
import { deriveReadinessVerdict } from "@/lib/mordant/readiness";

import {
  MordantExperience,
  type ExperienceStory,
} from "./mordant-experience";

export const metadata: Metadata = {
  title: "M-EX1 experience prototype",
  description: "A continuous six-state study of the Mordant experience grammar.",
  robots: {
    index: false,
    follow: false,
    nocache: true,
  },
};

function deadlineParts(timestamp: string) {
  const value = new Date(timestamp);
  if (Number.isNaN(value.getTime())) {
    throw new Error("The M-EX1 experience requires a valid modeled deadline.");
  }

  const clock = new Intl.DateTimeFormat("en-GB", {
    hour: "2-digit",
    minute: "2-digit",
    hourCycle: "h23",
    timeZone: "UTC",
  }).format(value);

  const date = new Intl.DateTimeFormat("en-GB", {
    day: "2-digit",
    month: "short",
    year: "numeric",
    timeZone: "UTC",
  }).format(value);

  return {
    clock: `${clock} UTC`,
    full: `${date}, ${clock} UTC`,
  };
}

export default function MordantExperiencePage() {
  const deal = getSyntheticDeal("wrong-role");
  const action = deal.actions[0];
  const position = deal.viewer.position;
  const dueAt = deal.nextResponsibility.dueAt;

  if (!action || !position || !dueAt) {
    throw new Error("The M-EX1 experience requires the complete wrong-role source fixture.");
  }

  const verdict = deriveReadinessVerdict(deal, action);
  const protectionTransition = action.consequence.protectionTransition;

  if (verdict.code !== "WRONG_ROLE" || !protectionTransition) {
    throw new Error("The M-EX1 experience requires the modeled Facility B cure transition.");
  }

  const receivable = proRateDomainAmount(deal.economics.receivable.outstanding, position);
  const protection = proRateDomainAmount(deal.economics.protection.lockedReserve, position);
  const deadline = deadlineParts(dueAt);
  const responsible = deal.nextResponsibility.actorLabel.replace(/\s+\(synthetic\)$/u, "");

  const story: ExperienceStory = {
    sourceScenario: deal.scenario,
    receivable: {
      amount: formatDomainAmount(receivable, 0),
      asset: receivable.asset.symbol,
      units: `${position.invoiceUnits} of ${position.totalUnits}`,
    },
    protection: {
      amount: formatDomainAmount(protection, 0),
      asset: protection.asset.symbol,
    },
    responsible,
    deadline: {
      iso: dueAt,
      clock: deadline.clock,
      full: deadline.full,
    },
    modeledResolution: {
      before: formatState(protectionTransition.from),
      action: action.label,
      contractAction: action.contractAction,
      after: formatState(protectionTransition.to),
      receivableEffect: "No receivable units are burned or transferred.",
    },
    technicalRecord: {
      dealId: deal.id,
      actionId: action.id,
      invoiceRoot: deal.machines.receivable.immutableInvoiceRoot,
      observation: "No transition proof or live observation is attached to this walkthrough.",
    },
  };

  return <MordantExperience story={story} />;
}
