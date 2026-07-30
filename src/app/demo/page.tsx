import type { Metadata } from "next";

import { ProductShell } from "@/components/product-shell";
import { TransactionDrivenExperience } from "@/components/transaction-driven-experience";
import type { LivingSurface } from "@/lib/dealroom/living-demo";

export const metadata: Metadata = {
  title: "Recorded conflict demo",
  description: "Follow one retained Mordant run from funding through conflict, responsibility, consequence, and proof.",
};

type Perspective = "workspace" | "participant" | "protocol";

export default async function DemoPage({
  searchParams,
}: {
  searchParams: Promise<{ perspective?: string | string[] }>;
}) {
  const requested = (await searchParams).perspective;
  const perspective: Perspective = requested === "participant" || requested === "protocol" ? requested : "workspace";
  const surface: LivingSurface = perspective;
  const active = perspective === "participant" ? "deal-room" : perspective;

  return (
    <ProductShell active={active} mode="public-demo">
      <TransactionDrivenExperience surface={surface} mode="review" timeline="public" />
    </ProductShell>
  );
}
