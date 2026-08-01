# Pledge confidentiality classification

The source structure is `MordantInvoiceVault.Pledge`. The current vault exposes several of these
values, so this table describes a future confidential-input path, not the behavior of the deployed
prototype.

Ordinary evaluation decrypts only the policy result. “Recovery quorum” means an explicit governed
incident procedure using threshold key shares; it is not an evaluator capability and is not part of
the normal path.

| Field | Public representation | Encrypted input | Decryptable by | Reason |
| --- | --- | --- | --- | --- |
| `invoiceRoot` / invoice identifier | Preferred MVP: high-entropy salted, vault-scoped pseudonymous link commitment. Full-FHE option: none. | Raw identifier when full-FHE equality is selected; otherwise it may remain client-only. | Client; recovery quorum only if included in ciphertext. | The evaluator needs equality, not the business identifier. A raw or unsalted hash invites dictionary and cross-deal linking. |
| `originatorSigner` | Opaque authorization commitment, role only in an accepted result. | Identity and pledge authorization material. | Client; recovery quorum under incident policy. | Public recovery of an ECDSA signature reveals the signer. The policy needs authorization, not routine identity disclosure. |
| `facility` | Opaque authorization commitment; responsible **role** may be public. | Facility identity. | Client; recovery quorum under incident policy. | The relayer need not be the commercial party. Publishing the address creates avoidable relationship metadata. |
| `obligationId` | None; covered by the input commitment. | Yes. | Client; recovery quorum under incident policy. | It is commercially identifying and not used by the minimal policy beyond binding the submitted pledge. |
| `amount` | None; covered by the input commitment. | Yes, even though policy V1 does not evaluate it. | Client; recovery quorum under incident policy. | Amount disclosure is explicitly excluded. Keeping it encrypted preserves a compatible pledge envelope without expanding policy V1. |
| `currency` | Equality result only through `conflictConfirmed`. | Yes; exact equality. | Client; normally never decrypted. | The policy needs same-currency equality, not the currency label. |
| `activeFrom` | None. | Yes; exact unsigned value. | Client; recovery quorum under incident policy. | Exact commercial dates are confidential. Comparisons must be exact, never approximate CKKS decisions. |
| `activeUntil` | None. | Yes; exact unsigned value. | Client; recovery quorum under incident policy. | Same as `activeFrom`; adjacency must remain non-overlap. |
| `nonce` (pledge) | None; covered by the input commitment. | Yes. | Client; recovery quorum under incident policy. | This nonce can link activity. The public result has a separate adapter replay nonce. |
| `deadline` (pledge) | None. The public `cureDeadline` is newly derived from the active policy, not this field. | Yes. | Client; recovery quorum under incident policy. | The signed pledge deadline is a commercial condition and is not policy V1’s public cure window. |
| `exclusive` | No standalone value; its contribution is reflected in the final result. | Yes; exact Boolean. | Client; normally never decrypted. | Exclusivity is a required confidential predicate. |
| pledge signature | Only an opaque authorization commitment within the encrypted-input commitment. | Yes, or retained solely inside an authorized client gateway. | Client; recovery quorum only when dispute procedure requires it. | Raw ECDSA material can disclose identity and must never reach Monad calldata or logs. |
| result attestation | `validatorSetId`, quorum, ordered validator addresses, signatures, and result digest. | No. | Public. | This authenticates the **result**, not the pledge or the truth of off-chain facts. |

## Submitter authorization

`submitters are authorized` is a real predicate, not an assertion supplied by the evaluator. Each
input envelope binds an `authorizationCommitment`. The spike may satisfy it with an authenticated
gateway credential or a private allow-list predicate, but the provider runner must state which one
it implements. A bare Boolean sent by the client does not pass.

The public result exposes only `responsibleRole`. Policy V1 uses the role constant selected in its
versioned configuration; it does not reveal a facility address.

## Receivable identity options

### A. Full FHE equality

- Encrypt the complete identifier and evaluate exact equality inside the circuit.
- Metadata leakage: the public observer learns only the final policy result and ordinary traffic
  metadata; no stable receivable link is required.
- Cost to measure: identifier ciphertext bytes, equality gates/operations, evaluation-key delta,
  equality latency, total latency, and memory. For a 256-bit identifier this is a materially larger
  predicate than comparing a single public commitment, but no numerical estimate is accepted until
  each provider benchmark measures it.
- Operational risk: more parameters and circuit depth may interact badly with threshold operations.

### B. Salted pseudonymous public commitment

- Compute a commitment scoped to `vault + policyVersion` using the same high-entropy shared salt for
  the two submissions; compare the commitments publicly.
- Metadata leakage: equality and repeated use within that scope are visible. Cross-vault linking is
  prevented only if the salt and scope are not reused. Timing and submitter-network metadata remain.
- Cost to measure: client commitment time and 32 public bytes per input. It removes identifier
  equality from the FHE circuit.
- Security requirement: the salt must be at least 128 bits from a CSPRNG, never derived from a
  low-entropy invoice number, never logged, and rotated per vault/policy epoch.

**Ten-day MVP recommendation:** option B, unless prospect discovery establishes that same-vault
linkability is itself unacceptable. Both providers must still report option A’s measured incremental
cost so the decision is reversible and evidence-based.
