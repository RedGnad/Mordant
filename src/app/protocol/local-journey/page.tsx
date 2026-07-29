import type { Metadata } from "next";
import { DealRoom } from "@/components/deal-room";
import "@/app/local-journey.css";

export const metadata: Metadata = {
  title: "Local transaction journey",
  description:
    "Run the synthetic Mordant recourse journey against a deterministic local protocol double.",
};

export default function LocalJourneyPage() {
  return <DealRoom />;
}
