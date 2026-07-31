package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// Commercial-term coverage.
//
// Every field a facility pledges is enumerated here with its confidentiality
// class, where its value is materialised, how it is protected, and which path
// consumes it. The client emits this table as a public artifact so the coverage
// claim can be checked field by field instead of being asserted in prose.
//
// The classification is deliberately not uniform, because the system is not
// uniform. Seven fields are encrypted and only ever cross the evaluator
// boundary as ciphertext. Two are protected as commitments whose preimages stay
// client-side: the enrollment carries the authorization claim to the evaluator
// in cleartext, so the commitment is visible even though the underlying
// identity and credential are not. Two are public policy scope by design.
//
// Only CONFIDENTIAL canaries are swept as leaks. A PUBLIC-BY-DESIGN value is
// expected to appear in public artifacts and is recorded, never scanned.

type confidentiality string

const (
	// Encrypted: the value enters the FHE ciphertext and only ciphertext
	// crosses the evaluator boundary.
	classEncrypted confidentiality = "CONFIDENTIAL-ENCRYPTED"
	// CommittedPreimage: the evaluator sees a commitment; the canary is the
	// preimage and must never appear.
	classCommittedPreimage confidentiality = "CONFIDENTIAL-COMMITTED-PREIMAGE"
	// PublicScope: the value is public policy scope and is not a secret.
	classPublicScope confidentiality = "PUBLIC-BY-DESIGN"
)

type canaryKind string

const (
	kindBytes32 canaryKind = "bytes32"
	kindUint    canaryKind = "uint"
)

// termSpec describes one commercial term.
type termSpec struct {
	Field        string          `json:"field"`
	Class        confidentiality `json:"confidentiality"`
	Kind         canaryKind      `json:"kind"`
	EntropyBits  int             `json:"canaryEntropyBits"`
	Encoded      string          `json:"encodedAs"`
	Protection   string          `json:"protection"`
	ConsumedBy   string          `json:"consumedBy"`
	Scanned      bool            `json:"scannedAfterExecution"`
	Materialized bool            `json:"materializedByClient"`
}

// commercialTerms is the frozen coverage table for one facility pledge.
var commercialTerms = []termSpec{
	{
		Field: "receivable_identifier", Class: classEncrypted, Kind: kindBytes32, EntropyBits: 256,
		Encoded:    "PlainPledge.ReceivableID (32 bytes)",
		Protection: "encrypted into the CipherPledge under the collective ceremony key",
		ConsumedBy: "ciphertext digest inside the canonical input commitment",
		Scanned:    true, Materialized: true,
	},
	{
		Field: "amount", Class: classEncrypted, Kind: kindUint, EntropyBits: 64,
		Encoded:    "PlainPledge.Amount (uint256, big-endian word)",
		Protection: "encrypted into the CipherPledge",
		ConsumedBy: "ciphertext digest inside the canonical input commitment",
		Scanned:    true, Materialized: true,
	},
	{
		Field: "currency", Class: classEncrypted, Kind: kindBytes32, EntropyBits: 256,
		Encoded:    "PlainPledge.Currency (32 bytes)",
		Protection: "encrypted into the CipherPledge",
		ConsumedBy: "homomorphic 256-bit equality between the two pledges (policy)",
		Scanned:    true, Materialized: true,
	},
	{
		Field: "active_from", Class: classEncrypted, Kind: kindUint, EntropyBits: 20,
		Encoded:    "PlainPledge.ActiveFrom (uint64)",
		Protection: "encrypted into the CipherPledge",
		ConsumedBy: "homomorphic strict interval overlap (policy)",
		Scanned:    true, Materialized: true,
	},
	{
		Field: "active_until", Class: classEncrypted, Kind: kindUint, EntropyBits: 20,
		Encoded:    "PlainPledge.ActiveUntil (uint64)",
		Protection: "encrypted into the CipherPledge",
		ConsumedBy: "homomorphic strict interval overlap (policy)",
		Scanned:    true, Materialized: true,
	},
	{
		Field: "obligation_id", Class: classEncrypted, Kind: kindBytes32, EntropyBits: 256,
		Encoded:    "PlainPledge.ObligationID (32 bytes)",
		Protection: "encrypted into the CipherPledge",
		ConsumedBy: "ciphertext digest inside the canonical input commitment",
		Scanned:    true, Materialized: true,
	},
	{
		Field: "exclusivity_metadata", Class: classEncrypted, Kind: kindBytes32, EntropyBits: 256,
		Encoded:    "PlainPledge.PrivateMetadataCommitment (32 bytes), with PlainPledge.Exclusive = true",
		Protection: "encrypted into the CipherPledge",
		ConsumedBy: "exclusivity AND term of the policy; metadata carried in the ciphertext digest",
		Scanned:    true, Materialized: true,
	},
	{
		Field: "submitter_identity", Class: classCommittedPreimage, Kind: kindBytes32, EntropyBits: 256,
		Encoded:    "sha256(canary) -> AuthorizationClaim.SubjectCommitment",
		Protection: "hiding commitment; the evaluator sees the commitment, never the preimage",
		ConsumedBy: "authorization commitment -> canonical input commitment and signed enrollment",
		Scanned:    true, Materialized: true,
	},
	{
		Field: "authorization_credential", Class: classCommittedPreimage, Kind: kindBytes32, EntropyBits: 256,
		Encoded:    "sha256(canary) -> AuthorizationClaim.Role",
		Protection: "hiding commitment; the evaluator sees the commitment, never the preimage",
		ConsumedBy: "authorization commitment -> canonical input commitment and signed enrollment",
		Scanned:    true, Materialized: true,
	},
	{
		Field: "pledge_nonce", Class: classPublicScope, Kind: kindUint, EntropyBits: 0,
		Encoded:    "AuthorizationClaim.Nonce and InputCommitmentContext.ClientNonce (uint256)",
		Protection: "none: replay scope the evaluator must read to bind the input commitment",
		ConsumedBy: "canonical input commitment and one-shot enrollment identity",
		Scanned:    false, Materialized: true,
	},
	{
		Field: "pledge_expiry", Class: classPublicScope, Kind: kindUint, EntropyBits: 0,
		Encoded:    "AuthorizationClaim.ValidUntil (uint64)",
		Protection: "none: validity window the evaluator must read to reject a stale enrollment",
		ConsumedBy: "enrollment validity check and authorization commitment",
		Scanned:    false, Materialized: true,
	},
}

// canaryValue is one materialised commercial term. `Value` is the 32-byte
// canonical encoding the scanner searches; `Numeric` is set for numeric fields
// so the scanner also covers decimal and word-sized encodings.
type canaryValue struct {
	Kind    canaryKind `json:"kind"`
	Value   string     `json:"value"`
	Numeric string     `json:"numeric,omitempty"`
}

type privateManifest struct {
	Party  string                 `json:"party"`
	Fields map[string]canaryValue `json:"fields"`
}

type coverageEntry struct {
	termSpec
	Generated            bool   `json:"generated"`
	EncryptedOrCommitted bool   `json:"encryptedOrCommitted"`
	Consumed             bool   `json:"consumedByExpectedPath"`
	CanarySha256         string `json:"canarySha256"`
}

type coverageAssertion struct {
	SchemaVersion  string          `json:"schemaVersion"`
	Party          string          `json:"party"`
	IdentityMode   string          `json:"identityMode"`
	ReceivableRoot string          `json:"receivableAnchorRoot"`
	Terms          []coverageEntry `json:"terms"`
	Summary        struct {
		Total             int `json:"total"`
		Encrypted         int `json:"confidentialEncrypted"`
		CommittedPreimage int `json:"confidentialCommittedPreimage"`
		PublicScope       int `json:"publicByDesign"`
		ScannedAsLeaks    int `json:"scannedAsLeaks"`
	} `json:"summary"`
}

// freshTerms materialises every commercial term. Confidential fields get fresh
// 32 bytes of entropy; numeric fields carry both their canonical 32-byte word
// and their decimal value so both encodings are searchable.
func freshTerms(shared sharedSession, party string) (map[string]canaryValue, error) {
	values := make(map[string]canaryValue, len(commercialTerms))
	random32 := func() ([32]byte, error) {
		var out [32]byte
		_, err := rand.Read(out[:])
		return out, err
	}
	put := func(field string, kind canaryKind, raw [32]byte, numeric string) {
		values[field] = canaryValue{Kind: kind, Value: hex.EncodeToString(raw[:]), Numeric: numeric}
	}
	word := func(value uint64) [32]byte {
		var out [32]byte
		binary.BigEndian.PutUint64(out[24:], value)
		return out
	}

	for _, term := range []string{"receivable_identifier", "obligation_id", "exclusivity_metadata", "submitter_identity", "authorization_credential"} {
		raw, err := random32()
		if err != nil {
			return nil, err
		}
		put(term, kindBytes32, raw, "")
	}

	// Currency must be identical across both facilities for the frozen policy to
	// find a conflict, so it is derived from the dispute session secret the two
	// facilities share and the anchor's public currency code. It is high-entropy
	// and unknown to the evaluator, which never receives the session secret.
	currency := sha256.Sum256(append(append([]byte{}, shared.secret[:]...), []byte("currency:"+shared.currencyCode)...))
	put("currency", kindBytes32, currency, "")

	// Amount: a realistic invoice amount with 64 bits of entropy in its low
	// bits, encoded as the uint256 word the pledge actually carries.
	var amountBytes [8]byte
	if _, err := rand.Read(amountBytes[:]); err != nil {
		return nil, err
	}
	amount := binary.BigEndian.Uint64(amountBytes[:])
	put("amount", kindUint, word(amount), fmt.Sprintf("%d", amount))

	// Active window: the two facilities must strictly overlap for the policy to
	// confirm a conflict, so the window is bounded. Entropy is therefore limited
	// by the field's domain and the coverage table records that honestly.
	spreadBytes := make([]byte, 4)
	if _, err := rand.Read(spreadBytes); err != nil {
		return nil, err
	}
	spread := uint64(binary.BigEndian.Uint32(spreadBytes)) % (1 << 20)
	var from, until uint64
	if party == "a" {
		from, until = shared.windowBase, shared.windowBase+(3<<20)+spread
	} else {
		from, until = shared.windowBase+(1<<20)+spread, shared.windowBase+(4<<20)
	}
	put("active_from", kindUint, word(from), fmt.Sprintf("%d", from))
	put("active_until", kindUint, word(until), fmt.Sprintf("%d", until))

	// Public scope values are recorded for completeness and never scanned.
	put("pledge_nonce", kindUint, word(shared.nonce), fmt.Sprintf("%d", shared.nonce))
	put("pledge_expiry", kindUint, word(shared.validUntil), fmt.Sprintf("%d", shared.validUntil))
	return values, nil
}

// sharedSession is what the two facilities agree out of band because they are
// both party to the same dispute over the same receivable. The evaluator never
// receives it.
type sharedSession struct {
	secret       [32]byte
	currencyCode string
	windowBase   uint64
	nonce        uint64
	validUntil   uint64
	anchorRoot   [32]byte
}

func buildCoverage(party string, values map[string]canaryValue, anchorRoot [32]byte) coverageAssertion {
	assertion := coverageAssertion{
		SchemaVersion:  "mordant.commercial-term-coverage/4",
		Party:          party,
		IdentityMode:   "IdentityPublicCommitment",
		ReceivableRoot: "0x" + hex.EncodeToString(anchorRoot[:]),
	}
	for _, term := range commercialTerms {
		value, present := values[term.Field]
		digest := ""
		if present {
			sum := sha256.Sum256([]byte(value.Value))
			digest = hex.EncodeToString(sum[:])
		}
		assertion.Terms = append(assertion.Terms, coverageEntry{
			termSpec:             term,
			Generated:            present,
			EncryptedOrCommitted: present && term.Class != classPublicScope,
			Consumed:             present,
			CanarySha256:         digest,
		})
		assertion.Summary.Total++
		switch term.Class {
		case classEncrypted:
			assertion.Summary.Encrypted++
		case classCommittedPreimage:
			assertion.Summary.CommittedPreimage++
		case classPublicScope:
			assertion.Summary.PublicScope++
		}
		if term.Scanned {
			assertion.Summary.ScannedAsLeaks++
		}
	}
	return assertion
}

func marshalCoverage(assertion coverageAssertion) ([]byte, error) {
	return json.MarshalIndent(assertion, "", "  ")
}

// scannableManifest strips the public-by-design values so the offline auditor
// only ever sweeps genuinely confidential canaries.
func scannableManifest(party string, values map[string]canaryValue) privateManifest {
	fields := make(map[string]canaryValue, len(values))
	for _, term := range commercialTerms {
		if !term.Scanned {
			continue
		}
		if value, present := values[term.Field]; present {
			fields[term.Field] = value
		}
	}
	return privateManifest{Party: party, Fields: fields}
}
