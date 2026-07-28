import { DealRoom } from "@/components/deal-room";

export const metadata = {
  title: "Mordant deal room: local transactional walkthrough",
  description:
    "Executes the Mordant recourse journey against a local chain, with real transactions,"
    + " receipts and state read back from the contracts.",
};

export default function DealRoomPage() {
  return <DealRoom />;
}
