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

The V3 contract and public schema exist. This document is not proof of the required final process
run. Until independently launched Client A, Client B, evaluator and threshold-node processes have
been captured and scanned, the privacy product claim remains **not ready**.
