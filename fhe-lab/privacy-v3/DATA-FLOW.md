# M-PRIV1 field-level data flow

This is the required target data flow for the V3 laboratory run. “Encrypted envelope” means the
canonical `CipherPledge` binary representation. A commitment is public but not a proof that a
source fact is true.

| Field | Origin | Plaintext visibility | Ciphertext visibility | Public commitment/output | Retention / deletion | Residual leakage |
|---|---|---|---|---|---|---|
| invoice identifier | Client A / Client B | respective client only | encrypted in full-FHE mode; salted link otherwise | salted receivable link / input commitment | client memory only; envelopes retained only through session | linkability when public-link mode is selected |
| amount | respective client | respective client only | encrypted | ciphertext digest / input commitment | client memory only | size/timing of envelope |
| currency | respective client | respective client only | encrypted | ciphertext digest / input commitment | client memory only | size/timing |
| active periods | respective client | respective client only | encrypted | ciphertext digest / input commitment | client memory only | size/timing |
| obligation ID | respective client | respective client only | encrypted | ciphertext digest / input commitment | client memory only | size/timing |
| exclusivity | respective client | respective client only | encrypted | ciphertext digest / input commitment | client memory only | final Boolean may imply conflict |
| identities | respective client / issuer | submitting client and issuer | only commitments cross evaluator boundary | subject/role commitments in enrollment | enrollment bounded to session | participant pseudonym/linkage |
| authorization credential | issuer/client | issuer and submitting client | signed enrollment only | authorization commitment and signature | issuer policy; public artifact excludes it | issuer/key identity and timing |
| signatures | validators | validator process only before signature | n/a | EIP-712 signatures in calldata; validator addresses | chain and receipt | validator identity and timing |
| final Boolean | threshold release | selected threshold release / evaluator result path | result ciphertext before release | `conflictConfirmed` | retained in receipt | outcome is public |
| recourse role / deadline | immutable consumer policy | n/a | n/a | event and recourse record | chain | role, policy, timestamp and deadline are public |

## Public metadata retained intentionally

Addresses, transaction timing, ciphertext/message sizes, commitments, Boolean result, policy ID and
version, responsibility, deadline, gas, transaction hash, block number and block hash. No claim is
made that these metadata are private.

## Current gate status

The required capture exists. Separately launched Client A, Client B, evaluator/coordinator and
three mTLS threshold-node processes were recorded and scanned, and the resulting result was
consumed by one atomic Monad testnet recourse transaction
(`0x038d075412a031591e53d5a8d598563e5a0882b840a665af0b460809347ea023`, block 49715282). The
recursive leak audit swept the six-process capture together with the journal, report, calldata,
decoded events and readbacks, and found no pledge plaintext and no canary leak.

This authorizes controlled laboratory language only. It does not establish correct FHE execution,
source truth, transaction-metadata privacy, private settlement, independent operator custody or
production readiness.
