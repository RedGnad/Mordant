package lattigospike

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"golang.org/x/crypto/sha3"
)

const (
	PolicyVersion      uint32 = 1
	pledgeMagic               = "MLP2"
	maxCiphertextBytes        = 128 << 20
)

var (
	ErrInvalidPlaintext    = errors.New("invalid pledge input")
	ErrMalformedPledge     = errors.New("malformed encrypted pledge")
	ErrWrongKeyID          = errors.New("wrong key id")
	ErrWrongPolicy         = errors.New("wrong policy version")
	ErrExpired             = errors.New("request expired")
	ErrReplay              = errors.New("nonce already used")
	ErrInsufficientShare   = errors.New("insufficient threshold shares")
	ErrUnauthorizedIngress = errors.New("unauthorized ingress commitment")
	ErrCiphertextNotIssued = errors.New("ciphertext origin not proven")
	ErrMalformedEnrollment = errors.New("malformed ciphertext enrollment")
	ErrUnknownIssuer       = errors.New("unknown enrollment issuer")
	ErrRevokedIssuer       = errors.New("revoked enrollment issuer")
	ErrInvalidSignature    = errors.New("invalid enrollment signature")
	ErrEnrollmentReplay    = errors.New("ciphertext enrollment already used")
)

type IdentityMode string

const (
	IdentityPublicCommitment IdentityMode = "public_salted_commitment"
	IdentityFullFHE256       IdentityMode = "full_fhe_256"
)

// Uint256 stores four big-endian 64-bit limbs: limb 0 is the most significant.
type Uint256 [4]uint64

// PlainPledge exists only at the encrypting client boundary. The benchmark
// runner never prints it and the evaluator API accepts CipherPledge only.
type PlainPledge struct {
	ActiveFrom                uint64
	ActiveUntil               uint64
	Amount                    Uint256
	Currency                  [32]byte
	ObligationID              [32]byte
	ReceivableID              [32]byte
	Exclusive                 bool
	ReceivableCommitment      [32]byte
	AuthorizationCommitment   [32]byte
	PrivateMetadataCommitment [32]byte
}

// CipherPledge is the complete encrypted payload measured by the spike.
// PolicyBits contains activeFrom, activeUntil and the exclusive policy flag.
// Amount and ObligationID are encrypted even though policy v1 does not use
// them. ReceivableIDBits is present only in full-FHE identity mode. The two
// commitments are deliberately public, opaque identifiers.
type CipherPledge struct {
	KeyID                     string
	ParameterFingerprint      [32]byte
	ReceivableCommitment      [32]byte
	AuthorizationCommitment   [32]byte
	PrivateMetadataCommitment [32]byte
	PolicyBits                *rlwe.Ciphertext
	CurrencyBits              *rlwe.Ciphertext
	AmountBits                *rlwe.Ciphertext
	ObligationIDBits          *rlwe.Ciphertext
	ReceivableIDBits          *rlwe.Ciphertext
}

type EvaluationRequest struct {
	KeyID         string
	PolicyVersion uint32
	Nonce         [32]byte
	ValidUntil    time.Time
	IdentityMode  IdentityMode
	A             *CipherPledge
	B             *CipherPledge
	// EnrollmentA and EnrollmentB form the external-client boundary. They must
	// either both be present or both be absent. When present, the evaluator
	// verifies their issuer signatures and exact binding to A and B instead of
	// trusting the process-local lab issuance registry.
	EnrollmentA *SignedCiphertextEnrollment
	EnrollmentB *SignedCiphertextEnrollment
}

// InputCommitmentContext contains the public, provider-independent fields
// required by ConfidentialPolicyInput. The runtime injects its own key ID and
// the pledge supplies its ciphertext, authorization and receivable-link
// commitments, preventing callers from substituting those values at hashing
// time.
type InputCommitmentContext struct {
	ChainID       Uint256
	Vault         [20]byte
	PolicyID      [32]byte
	PolicyVersion uint32
	InputSlot     uint8
	ClientNonce   Uint256
}

type EncryptedDecision struct {
	Conflict                   *rlwe.Ciphertext
	Nonce                      [32]byte
	ResultCiphertextCommitment [32]byte
}

type SetupMetrics struct {
	ThresholdSetup               time.Duration `json:"threshold_setup"`
	CollectivePublicKey          time.Duration `json:"collective_public_key"`
	RelinearizationKey           time.Duration `json:"relinearization_key"`
	GaloisKeys                   time.Duration `json:"galois_keys"`
	Total                        time.Duration `json:"total"`
	PublicKeyBytes               int           `json:"public_key_bytes"`
	EvaluationKeyBytes           int           `json:"evaluation_key_bytes"`
	FullFHEIdentityKeyDeltaBytes int           `json:"full_fhe_identity_key_delta_bytes"`
	ThresholdShareBytes          int           `json:"threshold_share_bytes"`
	PublicKeyMarshal             time.Duration `json:"public_key_marshal"`
	EvaluationKeyMarshal         time.Duration `json:"evaluation_key_marshal"`
}

type EncryptionMetrics struct {
	PolicyBits              time.Duration `json:"policy_bits"`
	AmountBits              time.Duration `json:"amount_bits"`
	ObligationBits          time.Duration `json:"obligation_bits"`
	CurrencyBits            time.Duration `json:"currency_bits"`
	ReceivableIdentityBits  time.Duration `json:"receivable_identity_bits"`
	Total                   time.Duration `json:"total"`
	CiphertextBytes         int           `json:"ciphertext_bytes"`
	IdentityCiphertextBytes int           `json:"identity_ciphertext_bytes"`
	Marshal                 time.Duration `json:"marshal"`
	Unmarshal               time.Duration `json:"unmarshal"`
	Digest                  string        `json:"ciphertext_digest"`
}

type EvaluationMetrics struct {
	Layout                   time.Duration `json:"layout"`
	ComparisonBatch          time.Duration `json:"comparison_batch"`
	ComparisonAAmortized     time.Duration `json:"comparison_a_amortized"`
	ComparisonBAmortized     time.Duration `json:"comparison_b_amortized"`
	CurrencyEquality         time.Duration `json:"currency_equality"`
	IdentityEquality         time.Duration `json:"identity_equality"`
	Conditions               time.Duration `json:"conditions"`
	FinalAND                 time.Duration `json:"final_and"`
	Total                    time.Duration `json:"total"`
	MultiplicativeDepth      int           `json:"multiplicative_depth"`
	StrictComparisonsInBatch int           `json:"strict_comparisons_in_batch"`
}

type DecryptionMetrics struct {
	ThresholdKeySwitch time.Duration `json:"threshold_key_switch"`
	ReceiverDecrypt    time.Duration `json:"receiver_decrypt"`
	Total              time.Duration `json:"total"`
	Participants       int           `json:"participants"`
	Threshold          int           `json:"threshold"`
	ReceiverIndex      int           `json:"receiver_index"`
	HelperIndex        int           `json:"helper_index"`
}

func (p *CipherPledge) MarshalBinary() ([]byte, error) {
	if err := validateCipherPledge(p); err != nil {
		return nil, err
	}

	var out bytes.Buffer
	out.WriteString(pledgeMagic)
	if len(p.KeyID) == 0 || len(p.KeyID) > 1024 {
		return nil, fmt.Errorf("%w: invalid key id", ErrMalformedPledge)
	}
	if err := binary.Write(&out, binary.BigEndian, uint16(len(p.KeyID))); err != nil {
		return nil, err
	}
	out.WriteString(p.KeyID)
	out.Write(p.ParameterFingerprint[:])
	out.Write(p.ReceivableCommitment[:])
	out.Write(p.AuthorizationCommitment[:])
	out.Write(p.PrivateMetadataCommitment[:])
	if p.ReceivableIDBits == nil {
		out.WriteByte(0)
	} else {
		out.WriteByte(1)
	}
	cts := []*rlwe.Ciphertext{p.PolicyBits, p.CurrencyBits, p.AmountBits, p.ObligationIDBits}
	if p.ReceivableIDBits != nil {
		cts = append(cts, p.ReceivableIDBits)
	}
	for _, ct := range cts {
		blob, err := ct.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("%w: ciphertext encoding", ErrMalformedPledge)
		}
		if len(blob) > maxCiphertextBytes {
			return nil, fmt.Errorf("%w: ciphertext too large", ErrMalformedPledge)
		}
		if err := binary.Write(&out, binary.BigEndian, uint32(len(blob))); err != nil {
			return nil, err
		}
		out.Write(blob)
	}
	return out.Bytes(), nil
}

func UnmarshalCipherPledge(data []byte) (*CipherPledge, error) {
	r := bytes.NewReader(data)
	magic := make([]byte, len(pledgeMagic))
	if _, err := io.ReadFull(r, magic); err != nil || string(magic) != pledgeMagic {
		return nil, fmt.Errorf("%w: invalid header", ErrMalformedPledge)
	}

	p := new(CipherPledge)
	var keyIDLength uint16
	if err := binary.Read(r, binary.BigEndian, &keyIDLength); err != nil || keyIDLength == 0 || int(keyIDLength) > r.Len() {
		return nil, fmt.Errorf("%w: invalid key id", ErrMalformedPledge)
	}
	keyID := make([]byte, keyIDLength)
	if _, err := io.ReadFull(r, keyID); err != nil {
		return nil, fmt.Errorf("%w: truncated key id", ErrMalformedPledge)
	}
	p.KeyID = string(keyID)
	if _, err := io.ReadFull(r, p.ParameterFingerprint[:]); err != nil {
		return nil, fmt.Errorf("%w: truncated parameter fingerprint", ErrMalformedPledge)
	}
	if _, err := io.ReadFull(r, p.ReceivableCommitment[:]); err != nil {
		return nil, fmt.Errorf("%w: truncated receivable commitment", ErrMalformedPledge)
	}
	if _, err := io.ReadFull(r, p.AuthorizationCommitment[:]); err != nil {
		return nil, fmt.Errorf("%w: truncated authorization commitment", ErrMalformedPledge)
	}
	if _, err := io.ReadFull(r, p.PrivateMetadataCommitment[:]); err != nil {
		return nil, fmt.Errorf("%w: truncated private metadata commitment", ErrMalformedPledge)
	}
	hasEncryptedID, err := r.ReadByte()
	if err != nil || hasEncryptedID > 1 {
		return nil, fmt.Errorf("%w: invalid identity mode", ErrMalformedPledge)
	}

	count := 4 + int(hasEncryptedID)
	cts := make([]*rlwe.Ciphertext, count)
	for i := range cts {
		cts[i] = new(rlwe.Ciphertext)
		var size uint32
		if err := binary.Read(r, binary.BigEndian, &size); err != nil || size == 0 || size > maxCiphertextBytes || uint64(size) > uint64(r.Len()) {
			return nil, fmt.Errorf("%w: invalid ciphertext length", ErrMalformedPledge)
		}
		blob := make([]byte, size)
		if _, err := io.ReadFull(r, blob); err != nil {
			return nil, fmt.Errorf("%w: truncated ciphertext", ErrMalformedPledge)
		}
		if err := cts[i].UnmarshalBinary(blob); err != nil {
			return nil, fmt.Errorf("%w: ciphertext decoding", ErrMalformedPledge)
		}
	}
	if r.Len() != 0 {
		return nil, fmt.Errorf("%w: trailing bytes", ErrMalformedPledge)
	}

	p.PolicyBits, p.CurrencyBits, p.AmountBits, p.ObligationIDBits = cts[0], cts[1], cts[2], cts[3]
	if hasEncryptedID == 1 {
		p.ReceivableIDBits = cts[4]
	}
	if err := validateCipherPledge(p); err != nil {
		return nil, err
	}
	return p, nil
}

// CipherPledgeDigest returns only keccak256(canonical provider envelope).
// CanonicalInputCommitment wraps this digest with the full provider-neutral
// Solidity ABI context. Ethereum's Keccak-256 is used, not SHA3-256.
func CipherPledgeDigest(p *CipherPledge) (string, error) {
	digest, err := cipherPledgeDigestBytes(p)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("keccak256:%x", digest[:]), nil
}

func cipherPledgeDigestBytes(p *CipherPledge) ([32]byte, error) {
	var digest [32]byte
	b, err := p.MarshalBinary()
	if err != nil {
		return digest, err
	}
	hash := sha3.NewLegacyKeccak256()
	_, _ = hash.Write(b)
	copy(digest[:], hash.Sum(nil))
	return digest, nil
}

func validateCipherPledge(p *CipherPledge) error {
	if p == nil || p.KeyID == "" || p.ParameterFingerprint == ([32]byte{}) || p.PolicyBits == nil || p.CurrencyBits == nil || p.AmountBits == nil || p.ObligationIDBits == nil {
		return fmt.Errorf("%w: missing ciphertext", ErrMalformedPledge)
	}
	cts := []*rlwe.Ciphertext{p.PolicyBits, p.CurrencyBits, p.AmountBits, p.ObligationIDBits}
	if p.ReceivableIDBits != nil {
		cts = append(cts, p.ReceivableIDBits)
	}
	for _, ct := range cts {
		if ct.MetaData == nil || ct.Degree() != 1 || ct.Level() < 0 {
			return fmt.Errorf("%w: invalid ciphertext shape", ErrMalformedPledge)
		}
	}
	return nil
}

func boolToUint64(v bool) uint64 {
	if v {
		return 1
	}
	return 0
}
