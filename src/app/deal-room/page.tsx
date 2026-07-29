import type { Metadata } from "next";
import { ParticipantDealRoom } from "@/components/participant-deal-room";
import { ProductShell } from "@/components/product-shell";

export const metadata: Metadata = {
  title: "Participant deal room",
  description:
    "Understand participant responsibility, exposure, action timing, and evidence for a Mordant synthetic receivable deal.",
};

export default function DealRoomPage() {
  return (
    <ProductShell active="deal-room">
      <ParticipantDealRoom />
    </ProductShell>
  );
}
