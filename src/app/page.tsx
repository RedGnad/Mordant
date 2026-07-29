import type { Metadata } from "next";
import { DealWorkspace } from "@/components/deal-workspace";
import { ProductShell } from "@/components/product-shell";
import { TransactionDrivenExperience } from "@/components/transaction-driven-experience";
import { TRANSACTION_DEMO_QUERY } from "@/lib/dealroom/living-demo";

export const metadata: Metadata = {
  title: "Deal workspace",
  description:
    "Monitor responsibilities, action windows, and evidence across Mordant synthetic receivable deals.",
};

export default async function Home({
  searchParams,
}: {
  searchParams: Promise<{ demo?: string | string[] }>;
}) {
  const demo = (await searchParams).demo === TRANSACTION_DEMO_QUERY;
  return (
    <ProductShell active="workspace" mode={demo ? "transaction-demo" : undefined}>
      {demo ? <TransactionDrivenExperience surface="workspace" /> : <DealWorkspace />}
    </ProductShell>
  );
}
