# Participant admission V1

Status: **capability-gated and disabled by default.**

The direct path lets two canonical wallet holders contribute one private pledge
interval each without sending either interval to the other participant. It uses
the existing neutral custom-supervised runtime and does not alter the Go pledge
schema, BGV circuit, governed-result schema, or protection binding.

Separate admission proves who authorized each role-bound claim. It does **not** prove that the claim
was encrypted in a participant-controlled environment before Mordant coordination received it.
That property belongs to the separately qualified, opt-in participant-originated native-CLI
profile; it must not be inferred from this browser admission flow.

## Protocol

1. The browser creates a neutral participant case with `POST /v1/participant-cases`
   and the exact body `{}`.
2. For the active role only, it requests a server challenge from
   `POST /v1/participant-cases/{caseCode}/challenge` with that role, the connected
   wallet, and that role's claim.
3. After an explicit user gesture, the wallet signs the returned
   `ParticipantAdmissionV1` EIP-712 data. Opening the page or wallet modal never
   connects, switches network, or signs.
4. The browser submits the exact authorization, signature, and claim to
   `POST /v1/participant-cases/{caseCode}/admissions`.
5. The server verifies typed-data integrity, signature/wallet control, chain
   `10143`, case and role binding, nonce, deadline, interval bounds, canonical
   role-to-wallet mapping, distinct addresses, Cleanverse eligibility, and
   durable replay/exclusivity rules before recording admission.
6. Participant A hands off the case code. Participant B repeats the same process
   for B. The runtime starts private execution only after both durable admissions
   exist.

One signed challenge is cached for its one admission POST. A recoverable network
failure may retry the same POST without asking for a second signature. It must
never cause automatic re-signing.

## Privacy boundary

The public participant-case projection contains status and admitted wallet
addresses, not claims, interval endpoints, or internal admitted records. The UI
model is role-local: it carries the active participant's draft only. While B is
active, A's interval is neither rendered nor retained in the B-facing model (and
vice versa). The combined two-claim timeline exists only for the managed intake
path.

Verified authorization and claim commitments are bound into the existing Go
pledge commitment fields. The clear interval is written only to that
participant's private input artifact. Receipts describe wallet-admitted windows
without reproducing their endpoints.

Managed Mordant preparation handles that private input artifact before BGV evaluation. The
evaluator receives ciphertext artifacts and has no decryption key; the designated governed
decryptor is Mordant-controlled.

## Fail-closed gates

Direct admission remains unavailable unless the server has an explicit enable
flag, a valid worker origin/token configuration, the exact canonical V2 adapter
configuration, chain `10143`, and the canonical controlled A/B wallet mapping.
An invalid or unknown worker response is rejected at the UI edge and shown as
unavailable; unknown stages never become plausible progress or outcomes.

The negative-control wallet and the uncontrolled A-Pass wallet in the canonical
configuration are excluded even if supplied by a caller. The second role cannot
reuse the first role's wallet or nonce, including under concurrent requests.

This is a synthetic testnet product path. It does not promise legal priority,
custody, insurance, duplicate-financing prevention, or production safety, and it
does not perform any on-chain recourse transaction in this preflight.
