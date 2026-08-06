"use client";

import { DirectParticipantExecution } from "@/components/live-product/direct-participant-execution";
import { capabilities } from "@/components/live-product/live-product-view-model";
import { PublicShell } from "@/components/public-shell";
import { WalletProvider } from "@/components/wallet/wallet-provider";

/** Local-only wiring harness for deterministic wallet/request-discipline tests. */
export function DirectExecutionHarness({ initialCaseCode = null }: {
  readonly initialCaseCode?: string | null;
}) {
  return (
    <PublicShell surface="live">
      <p
        data-testid="direct-execution-harness"
        style={{
          margin: 0,
          padding: "10px var(--shell-gutter)",
          background: "#fff7db",
          borderBottom: "1px solid var(--rule)",
          font: "11px var(--font-proof), monospace",
          letterSpacing: "0.07em",
          textTransform: "uppercase",
        }}
      >
        Design harness · direct participant admission · no worker execution
      </p>
      <WalletProvider walletConnectProjectId={null}>
        <DirectParticipantExecution
          workerOrigin="https://mordant-worker.test"
          initialCaseCode={initialCaseCode}
          publicTestHolder="0x911F99f424D47F08a15fcC771e94dcc2f7252B02"
          capabilitySet={capabilities("DIRECT_PARTICIPANT_ADMISSION")}
        />
      </WalletProvider>
    </PublicShell>
  );
}
