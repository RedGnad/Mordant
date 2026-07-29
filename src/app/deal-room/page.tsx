import type { Metadata } from "next";
import { ProductShell } from "@/components/product-shell";
import { TransactionDrivenExperience } from "@/components/transaction-driven-experience";
import { TRANSACTION_DEMO_QUERY } from "@/lib/dealroom/living-demo";

export const metadata: Metadata = {
  title: "Participant deal room",
  description:
    "Understand participant responsibility, exposure, action timing, and evidence for a Mordant synthetic receivable deal.",
};

export default async function DealRoomPage({
  searchParams,
}: {
  searchParams: Promise<{ demo?: string | string[] }>;
}) {
  const demo = process.env.NODE_ENV !== "production"
    && (await searchParams).demo === TRANSACTION_DEMO_QUERY;
  return (
    <ProductShell active="deal-room" mode={demo ? "transaction-demo" : "executed-review"}>
      <TransactionDrivenExperience surface="participant" mode={demo ? "live" : "review"} />
    </ProductShell>
  );
}
