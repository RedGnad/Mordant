import type { Metadata } from "next";
import { ProductShell } from "@/components/product-shell";
import { TransactionDrivenExperience } from "@/components/transaction-driven-experience";
import { TRANSACTION_DEMO_QUERY } from "@/lib/dealroom/living-demo";

export const metadata: Metadata = {
  title: "Protocol operations",
  description:
    "Inspect execution gates, state transitions, on-chain evidence, and recovery paths in the Mordant prototype.",
};

export default async function ProtocolPage({
  searchParams,
}: {
  searchParams: Promise<{ demo?: string | string[] }>;
}) {
  const demo = process.env.NODE_ENV !== "production"
    && (await searchParams).demo === TRANSACTION_DEMO_QUERY;
  return (
    <ProductShell active="protocol" mode={demo ? "transaction-demo" : "executed-review"}>
      <TransactionDrivenExperience surface="protocol" mode={demo ? "live" : "review"} />
    </ProductShell>
  );
}
