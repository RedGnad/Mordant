import type { Metadata } from "next";

import { ProductShell } from "@/components/product-shell";
import { TransactionDrivenExperience } from "@/components/transaction-driven-experience";
import { isRecordedCheckpointId, type LivingSurface, type RecordedCheckpointId } from "@/lib/dealroom/living-demo";

export const metadata: Metadata = {
  title: "Recorded workflow evidence",
  description: "Follow one retained first-workflow case through its historical policy, consequence and evidence.",
};

type Perspective = "workspace" | "participant" | "protocol";
const PUBLIC_CHECKPOINTS: ReadonlyArray<RecordedCheckpointId> = ["funding", "reveal", "deadline", "entitlement", "claims"];

export default async function DemoPage({
  searchParams,
}: {
  searchParams: Promise<{ perspective?: string | string[]; checkpoint?: string | string[] }>;
}) {
  const parameters = await searchParams;
  const requested = parameters.perspective;
  const perspective: Perspective = requested === "participant" || requested === "protocol" ? requested : "workspace";
  const surface: LivingSurface = perspective;
  const active = perspective === "participant" ? "deal-room" : perspective;
  const requestedCheckpoint = typeof parameters.checkpoint === "string" && isRecordedCheckpointId(parameters.checkpoint)
    ? parameters.checkpoint
    : "funding";
  const initialCheckpoint = PUBLIC_CHECKPOINTS.includes(requestedCheckpoint) ? requestedCheckpoint : "funding";

  return (
    <ProductShell active={active} mode="public-demo">
      <TransactionDrivenExperience key={surface} surface={surface} mode="review" timeline="public" initialCheckpoint={initialCheckpoint} />
    </ProductShell>
  );
}
