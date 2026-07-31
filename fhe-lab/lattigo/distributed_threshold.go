package lattigospike

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sort"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/multiparty"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

const (
	thresholdOperatorMagic    = "MTO1"
	thresholdDescriptorMagic  = "MTD1"
	thresholdResponseMagic    = "MTR1"
	maxThresholdMaterialSize  = 16 << 20
	maxReleaseShareSize       = 64 << 20
	thresholdReleaseDomain    = "mordant.threshold.release-descriptor/v1"
	thresholdResponseDomain   = "mordant.threshold.release-response/v1"
	thresholdTranscriptDomain = "mordant.threshold.transcript/v1"
	thresholdKeyDomain        = "mordant.threshold.key-epoch/v1"
	policyCircuitDomain       = "mordant.policy.circuit/overlap-v1"
)

var (
	ErrInvalidThresholdOperator = errors.New("invalid threshold operator material")
	ErrInvalidReleaseDescriptor = errors.New("invalid threshold release descriptor")
	ErrInvalidReleaseShare      = errors.New("invalid threshold release share")
)

// ThresholdOperatorPublic is the non-secret identity of one threshold node.
// Signing keys are independent from FHE shares and EVM validator keys.
type ThresholdOperatorPublic struct {
	OperatorID       [32]byte
	Point            uint64
	SigningPublicKey [ed25519.PublicKeySize]byte
}

// ThresholdManifest is safe to distribute to the coordinator and clients.
// The initial controlled ceremony is still co-located; only online release is
// process-separable. A production custody claim requires a distributed DKG.
type ThresholdManifest struct {
	KeyID                [32]byte
	ParameterFingerprint [32]byte
	Threshold            uint16
	Operators            []ThresholdOperatorPublic
}

// ThresholdOperator owns one Shamir share and an accountability signing key.
// It deliberately has no evaluation keys, public-result signer or business
// state.
type ThresholdOperator struct {
	params      bgv.Parameters
	keyID       [32]byte
	fingerprint [32]byte
	threshold   int
	point       multiparty.ShamirPublicPoint
	allPoints   []multiparty.ShamirPublicPoint
	share       multiparty.ShamirSecretShare
	signingKey  ed25519.PrivateKey
	public      ThresholdOperatorPublic
}

// ReleaseDescriptor binds a one-shot threshold share to one evaluated
// ciphertext and its public policy context. ProtocolBinding is derived from
// c1 and cannot be chosen by the caller.
type ReleaseDescriptor struct {
	SessionID                  [32]byte
	KeyID                      [32]byte
	ParameterFingerprint       [32]byte
	PolicyID                   [32]byte
	PolicyVersion              uint32
	InputCommitmentA           [32]byte
	InputCommitmentB           [32]byte
	ResultNonce                Uint256
	ValidUntil                 uint64
	ResultCiphertextCommitment [32]byte
	ProtocolBinding            [32]byte
	Coalition                  [2]uint64
}

// ThresholdReleaseResponse contains only a smudged key-switch share, public
// metadata and an operator signature. It never serializes the Shamir share.
type ThresholdReleaseResponse struct {
	OperatorID      [32]byte
	Point           uint64
	SessionID       [32]byte
	ProtocolBinding [32]byte
	ShareDigest     [32]byte
	Share           []byte
	StatementDigest [32]byte
	Signature       [ed25519.SignatureSize]byte
}

// ProvisionThresholdOperators creates binary per-node configurations and a
// public manifest from the controlled runtime ceremony. Each config must be
// written to a different 0600 file and consumed by a separate process. This
// proves online process separation, not independent setup custody.
func (r *Runtime) ProvisionThresholdOperators() ([][]byte, ThresholdManifest, error) {
	if r == nil || len(r.parties) != defaultParties || r.threshold != defaultThreshold {
		return nil, ThresholdManifest{}, ErrInvalidThresholdOperator
	}
	parameterBytes, err := r.Params.MarshalBinary()
	if err != nil {
		return nil, ThresholdManifest{}, fmt.Errorf("marshal threshold parameters: %w", err)
	}
	manifest := ThresholdManifest{
		KeyID:                r.keyIDBytes,
		ParameterFingerprint: r.parameterFingerprint,
		Threshold:            uint16(r.threshold),
		Operators:            make([]ThresholdOperatorPublic, len(r.parties)),
	}
	configs := make([][]byte, len(r.parties))
	points := partyPoints(r.parties)
	for i, party := range r.parties {
		_, signingKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, ThresholdManifest{}, fmt.Errorf("operator signing key: %w", err)
		}
		shareBytes, err := party.tsk.MarshalBinary()
		if err != nil {
			return nil, ThresholdManifest{}, fmt.Errorf("marshal threshold share: %w", err)
		}
		publicKey := signingKey.Public().(ed25519.PublicKey)
		operatorID := sha256.Sum256(publicKey)
		public := ThresholdOperatorPublic{OperatorID: operatorID, Point: uint64(party.point)}
		copy(public.SigningPublicKey[:], publicKey)
		manifest.Operators[i] = public
		configs[i], err = marshalThresholdOperatorConfig(
			parameterBytes,
			r.keyIDBytes,
			r.parameterFingerprint,
			uint16(r.threshold),
			party.point,
			points,
			shareBytes,
			signingKey,
		)
		if err != nil {
			return nil, ThresholdManifest{}, err
		}
	}
	return configs, manifest, nil
}

// DetachThresholdParties removes online access to co-located share objects
// after per-process provisioning. Go does not guarantee secure memory erasure;
// this is a boundary assertion for the controlled harness, not KMS sealing.
func (r *Runtime) DetachThresholdParties() {
	if r == nil {
		return
	}
	for _, party := range r.parties {
		party.sk = nil
		party.ephemSK = nil
		party.tsk = multiparty.ShamirSecretShare{}
	}
	r.parties = nil
}

func marshalThresholdOperatorConfig(
	parameterBytes []byte,
	keyID, fingerprint [32]byte,
	threshold uint16,
	point multiparty.ShamirPublicPoint,
	allPoints []multiparty.ShamirPublicPoint,
	shareBytes []byte,
	signingKey ed25519.PrivateKey,
) ([]byte, error) {
	if len(parameterBytes) == 0 || len(parameterBytes) > maxParameterMaterialBytes ||
		len(shareBytes) == 0 || len(shareBytes) > maxThresholdMaterialSize ||
		len(signingKey) != ed25519.PrivateKeySize || threshold < 2 || len(allPoints) < int(threshold) {
		return nil, ErrInvalidThresholdOperator
	}
	var out bytes.Buffer
	out.WriteString(thresholdOperatorMagic)
	writeSized(&out, parameterBytes)
	out.Write(keyID[:])
	out.Write(fingerprint[:])
	_ = binary.Write(&out, binary.BigEndian, threshold)
	_ = binary.Write(&out, binary.BigEndian, uint64(point))
	_ = binary.Write(&out, binary.BigEndian, uint16(len(allPoints)))
	for _, candidate := range allPoints {
		_ = binary.Write(&out, binary.BigEndian, uint64(candidate))
	}
	writeSized(&out, shareBytes)
	writeSized(&out, signingKey)
	return out.Bytes(), nil
}

// NewThresholdOperator imports one sealed-at-transport operator bundle. The
// caller is responsible for loading it from a 0600 file or KMS-wrapped source.
func NewThresholdOperator(config []byte) (*ThresholdOperator, error) {
	reader := bytes.NewReader(config)
	magic := make([]byte, len(thresholdOperatorMagic))
	if _, err := io.ReadFull(reader, magic); err != nil || string(magic) != thresholdOperatorMagic {
		return nil, ErrInvalidThresholdOperator
	}
	parameterBytes, err := readSized(reader, maxParameterMaterialBytes)
	if err != nil {
		return nil, err
	}
	var params bgv.Parameters
	if err := params.UnmarshalBinary(parameterBytes); err != nil {
		return nil, ErrInvalidThresholdOperator
	}
	canonicalParameters, err := params.MarshalBinary()
	if err != nil {
		return nil, ErrInvalidThresholdOperator
	}
	var keyID, fingerprint [32]byte
	if _, err := io.ReadFull(reader, keyID[:]); err != nil {
		return nil, ErrInvalidThresholdOperator
	}
	if _, err := io.ReadFull(reader, fingerprint[:]); err != nil || sha256.Sum256(canonicalParameters) != fingerprint {
		return nil, ErrInvalidThresholdOperator
	}
	var threshold uint16
	var ownPoint uint64
	var pointCount uint16
	if binary.Read(reader, binary.BigEndian, &threshold) != nil ||
		binary.Read(reader, binary.BigEndian, &ownPoint) != nil ||
		binary.Read(reader, binary.BigEndian, &pointCount) != nil ||
		threshold < 2 || pointCount < threshold || pointCount > 255 {
		return nil, ErrInvalidThresholdOperator
	}
	points := make([]multiparty.ShamirPublicPoint, pointCount)
	foundOwn := false
	seen := make(map[uint64]struct{}, pointCount)
	for i := range points {
		var point uint64
		if binary.Read(reader, binary.BigEndian, &point) != nil || point == 0 {
			return nil, ErrInvalidThresholdOperator
		}
		if _, exists := seen[point]; exists {
			return nil, ErrInvalidThresholdOperator
		}
		seen[point] = struct{}{}
		points[i] = multiparty.ShamirPublicPoint(point)
		foundOwn = foundOwn || point == ownPoint
	}
	if !foundOwn {
		return nil, ErrInvalidThresholdOperator
	}
	shareBytes, err := readSized(reader, maxThresholdMaterialSize)
	if err != nil {
		return nil, err
	}
	share := multiparty.NewThresholdizer(params).AllocateThresholdSecretShare()
	if err := share.UnmarshalBinary(shareBytes); err != nil {
		return nil, ErrInvalidThresholdOperator
	}
	signingBytes, err := readSized(reader, ed25519.PrivateKeySize)
	if err != nil || len(signingBytes) != ed25519.PrivateKeySize || reader.Len() != 0 {
		return nil, ErrInvalidThresholdOperator
	}
	signingKey := append(ed25519.PrivateKey(nil), signingBytes...)
	publicKey := signingKey.Public().(ed25519.PublicKey)
	operatorID := sha256.Sum256(publicKey)
	public := ThresholdOperatorPublic{OperatorID: operatorID, Point: ownPoint}
	copy(public.SigningPublicKey[:], publicKey)
	return &ThresholdOperator{
		params:      params,
		keyID:       keyID,
		fingerprint: fingerprint,
		threshold:   int(threshold),
		point:       multiparty.ShamirPublicPoint(ownPoint),
		allPoints:   points,
		share:       share,
		signingKey:  signingKey,
		public:      public,
	}, nil
}

func (o *ThresholdOperator) Public() ThresholdOperatorPublic { return o.public }

// ValidateReleaseRequest validates every public binding required before a
// durable PREPARE is recorded. It performs no share generation.
func (o *ThresholdOperator) ValidateReleaseRequest(descriptor ReleaseDescriptor, ciphertext *rlwe.Ciphertext) error {
	if o == nil || len(o.signingKey) != ed25519.PrivateKeySize {
		return ErrInvalidThresholdOperator
	}
	if err := validateReleaseDescriptor(descriptor); err != nil {
		return err
	}
	if descriptor.KeyID != o.keyID || descriptor.ParameterFingerprint != o.fingerprint {
		return ErrWrongKeyID
	}
	commitment, err := ciphertextCommitment(ciphertext)
	if err != nil || commitment != descriptor.ResultCiphertextCommitment {
		return ErrMalformedPledge
	}
	binding, err := ProtocolBindingDigest(o.keyID, ProtocolCollectiveKeySwitchToZero, ciphertext)
	if err != nil || binding != descriptor.ProtocolBinding {
		return ErrInvalidProtocolBinding
	}
	if !coalitionContains(descriptor.Coalition, uint64(o.point)) {
		return ErrInsufficientShare
	}
	return nil
}

// GenerateReleaseShare creates exactly one collective key-switch share toward
// the zero key. Durable PREPARE/COMMIT/GENERATED state is enforced by the
// network service before and after this function.
func (o *ThresholdOperator) GenerateReleaseShare(descriptor ReleaseDescriptor, ciphertext *rlwe.Ciphertext) (ThresholdReleaseResponse, error) {
	if err := o.ValidateReleaseRequest(descriptor, ciphertext); err != nil {
		return ThresholdReleaseResponse{}, err
	}
	coalition := []multiparty.ShamirPublicPoint{
		multiparty.ShamirPublicPoint(descriptor.Coalition[0]),
		multiparty.ShamirPublicPoint(descriptor.Coalition[1]),
	}
	if !containsPoint(coalition, o.point) {
		return ThresholdReleaseResponse{}, ErrInsufficientShare
	}
	combiner := multiparty.NewCombiner(o.params, o.point, o.allPoints, o.threshold)
	additive := rlwe.NewSecretKey(o.params)
	if err := combiner.GenAdditiveShare(coalition, o.point, o.share, additive); err != nil {
		return ThresholdReleaseResponse{}, ErrInsufficientShare
	}
	protocol, err := multiparty.NewKeySwitchProtocol(
		o.params,
		ring.DiscreteGaussian{Sigma: 1 << 30, Bound: 6 * (1 << 30)},
	)
	if err != nil {
		return ThresholdReleaseResponse{}, fmt.Errorf("threshold key switch: %w", err)
	}
	share := protocol.AllocateShare(ciphertext.Level())
	zero := rlwe.NewSecretKey(o.params)
	protocol.GenShare(additive, zero, ciphertext, &share)
	shareBytes, err := share.MarshalBinary()
	if err != nil || len(shareBytes) == 0 || len(shareBytes) > maxReleaseShareSize {
		return ThresholdReleaseResponse{}, ErrInvalidReleaseShare
	}
	response := ThresholdReleaseResponse{
		OperatorID:      o.public.OperatorID,
		Point:           uint64(o.point),
		SessionID:       descriptor.SessionID,
		ProtocolBinding: descriptor.ProtocolBinding,
		ShareDigest:     legacyKeccak(shareBytes),
		Share:           shareBytes,
	}
	response.StatementDigest = thresholdResponseStatementDigest(descriptor, response)
	copy(response.Signature[:], ed25519.Sign(o.signingKey, response.StatementDigest[:]))
	return response, nil
}

// CombineZeroKeySwitchShares verifies two distinct signed operator responses,
// aggregates their shares and releases only the Boolean decision.
func CombineZeroKeySwitchShares(
	params bgv.Parameters,
	descriptor ReleaseDescriptor,
	manifest ThresholdManifest,
	ciphertext *rlwe.Ciphertext,
	responses []ThresholdReleaseResponse,
) (bool, [32]byte, error) {
	var zeroDigest [32]byte
	if err := validateReleaseDescriptor(descriptor); err != nil || len(responses) != int(manifest.Threshold) || manifest.Threshold != 2 {
		return false, zeroDigest, ErrInsufficientShare
	}
	if descriptor.KeyID != manifest.KeyID || descriptor.ParameterFingerprint != manifest.ParameterFingerprint {
		return false, zeroDigest, ErrWrongKeyID
	}
	commitment, err := ciphertextCommitment(ciphertext)
	if err != nil || commitment != descriptor.ResultCiphertextCommitment {
		return false, zeroDigest, ErrMalformedPledge
	}
	binding, err := ProtocolBindingDigest(manifest.KeyID, ProtocolCollectiveKeySwitchToZero, ciphertext)
	if err != nil || binding != descriptor.ProtocolBinding {
		return false, zeroDigest, ErrInvalidProtocolBinding
	}
	publicByID := make(map[[32]byte]ThresholdOperatorPublic, len(manifest.Operators))
	for _, operator := range manifest.Operators {
		publicByID[operator.OperatorID] = operator
	}
	protocol, err := multiparty.NewKeySwitchProtocol(
		params,
		ring.DiscreteGaussian{Sigma: 1 << 30, Bound: 6 * (1 << 30)},
	)
	if err != nil {
		return false, zeroDigest, err
	}
	combined := protocol.AllocateShare(ciphertext.Level())
	seenPoints := make(map[uint64]struct{}, len(responses))
	statementDigests := make([][32]byte, 0, len(responses))
	for _, response := range responses {
		operator, exists := publicByID[response.OperatorID]
		if !exists || operator.Point != response.Point || !coalitionContains(descriptor.Coalition, response.Point) {
			return false, zeroDigest, ErrInvalidReleaseShare
		}
		if _, duplicate := seenPoints[response.Point]; duplicate {
			return false, zeroDigest, ErrInvalidReleaseShare
		}
		seenPoints[response.Point] = struct{}{}
		if response.SessionID != descriptor.SessionID || response.ProtocolBinding != descriptor.ProtocolBinding ||
			response.ShareDigest != legacyKeccak(response.Share) {
			return false, zeroDigest, ErrInvalidReleaseShare
		}
		expectedStatement := thresholdResponseStatementDigest(descriptor, response)
		if subtle.ConstantTimeCompare(expectedStatement[:], response.StatementDigest[:]) != 1 ||
			!ed25519.Verify(operator.SigningPublicKey[:], expectedStatement[:], response.Signature[:]) {
			return false, zeroDigest, ErrInvalidSignature
		}
		share := protocol.AllocateShare(ciphertext.Level())
		if len(response.Share) == 0 || len(response.Share) > maxReleaseShareSize || share.UnmarshalBinary(response.Share) != nil || share.Level() != ciphertext.Level() {
			return false, zeroDigest, ErrInvalidReleaseShare
		}
		if err := protocol.AggregateShares(share, combined, &combined); err != nil {
			return false, zeroDigest, ErrInvalidReleaseShare
		}
		statementDigests = append(statementDigests, expectedStatement)
	}
	if len(seenPoints) != int(manifest.Threshold) {
		return false, zeroDigest, ErrInsufficientShare
	}
	switched := bgv.NewCiphertext(params, 1, ciphertext.Level())
	protocol.KeySwitch(ciphertext, combined, switched)
	zeroKey := rlwe.NewSecretKey(params)
	plaintext := rlwe.NewDecryptor(params, zeroKey).DecryptNew(switched)
	decoded := make([]uint64, params.MaxSlots())
	if err := bgv.NewEncoder(params).Decode(plaintext, decoded); err != nil || decoded[0] > 1 {
		return false, zeroDigest, ErrInvalidReleaseShare
	}
	confirmed := decoded[0] == 1
	transcript := ThresholdTranscriptCommitment(descriptor, statementDigests, confirmed)
	return confirmed, transcript, nil
}

func ThresholdKeyCommitment(manifest ThresholdManifest) ([32]byte, error) {
	var zero [32]byte
	if manifest.KeyID == zero || manifest.ParameterFingerprint == zero || manifest.Threshold < 2 || len(manifest.Operators) < int(manifest.Threshold) {
		return zero, ErrInvalidThresholdOperator
	}
	operators := append([]ThresholdOperatorPublic(nil), manifest.Operators...)
	sort.Slice(operators, func(i, j int) bool { return operators[i].Point < operators[j].Point })
	var encoded bytes.Buffer
	encoded.WriteString(thresholdKeyDomain)
	encoded.WriteByte(0)
	encoded.Write(manifest.KeyID[:])
	encoded.Write(manifest.ParameterFingerprint[:])
	_ = binary.Write(&encoded, binary.BigEndian, manifest.Threshold)
	for _, operator := range operators {
		if operator.OperatorID == zero || operator.Point == 0 {
			return zero, ErrInvalidThresholdOperator
		}
		encoded.Write(operator.OperatorID[:])
		_ = binary.Write(&encoded, binary.BigEndian, operator.Point)
		encoded.Write(operator.SigningPublicKey[:])
	}
	return legacyKeccak(encoded.Bytes()), nil
}

func PolicyCircuitCommitment(parameterFingerprint, policyID [32]byte, policyVersion uint32) ([32]byte, error) {
	if parameterFingerprint == ([32]byte{}) || policyID == ([32]byte{}) || policyVersion != PolicyVersion {
		return [32]byte{}, ErrWrongPolicy
	}
	var encoded bytes.Buffer
	encoded.WriteString(policyCircuitDomain)
	encoded.WriteByte(0)
	encoded.Write(parameterFingerprint[:])
	encoded.Write(policyID[:])
	_ = binary.Write(&encoded, binary.BigEndian, policyVersion)
	encoded.WriteString(ConfidentialPolicyInputType)
	return legacyKeccak(encoded.Bytes()), nil
}

func ThresholdTranscriptCommitment(descriptor ReleaseDescriptor, statementDigests [][32]byte, confirmed bool) [32]byte {
	sorted := append([][32]byte(nil), statementDigests...)
	sort.Slice(sorted, func(i, j int) bool { return bytes.Compare(sorted[i][:], sorted[j][:]) < 0 })
	var encoded bytes.Buffer
	encoded.WriteString(thresholdTranscriptDomain)
	encoded.WriteByte(0)
	descriptorDigest := ReleaseDescriptorDigest(descriptor)
	encoded.Write(descriptorDigest[:])
	for _, digest := range sorted {
		encoded.Write(digest[:])
	}
	if confirmed {
		encoded.WriteByte(1)
	} else {
		encoded.WriteByte(0)
	}
	return legacyKeccak(encoded.Bytes())
}

func validateReleaseDescriptor(descriptor ReleaseDescriptor) error {
	zero := [32]byte{}
	if descriptor.SessionID == zero || descriptor.KeyID == zero || descriptor.ParameterFingerprint == zero ||
		descriptor.PolicyID == zero || descriptor.PolicyVersion != PolicyVersion ||
		descriptor.InputCommitmentA == zero || descriptor.InputCommitmentB == zero ||
		descriptor.ResultNonce == (Uint256{}) || descriptor.ValidUntil == 0 || descriptor.ResultCiphertextCommitment == zero ||
		descriptor.ProtocolBinding == zero || descriptor.Coalition[0] == 0 ||
		descriptor.Coalition[1] == 0 || descriptor.Coalition[0] == descriptor.Coalition[1] {
		return ErrInvalidReleaseDescriptor
	}
	return nil
}

// ReleaseDescriptorDigest is the canonical signed digest used by threshold
// operators and the network coordinator.
func ReleaseDescriptorDigest(descriptor ReleaseDescriptor) [32]byte {
	var encoded bytes.Buffer
	encoded.WriteString(thresholdReleaseDomain)
	encoded.WriteByte(0)
	encoded.Write(descriptor.SessionID[:])
	encoded.Write(descriptor.KeyID[:])
	encoded.Write(descriptor.ParameterFingerprint[:])
	encoded.Write(descriptor.PolicyID[:])
	_ = binary.Write(&encoded, binary.BigEndian, descriptor.PolicyVersion)
	encoded.Write(descriptor.InputCommitmentA[:])
	encoded.Write(descriptor.InputCommitmentB[:])
	encoded.Write(uint256Word(descriptor.ResultNonce))
	_ = binary.Write(&encoded, binary.BigEndian, descriptor.ValidUntil)
	encoded.Write(descriptor.ResultCiphertextCommitment[:])
	encoded.Write(descriptor.ProtocolBinding[:])
	_ = binary.Write(&encoded, binary.BigEndian, descriptor.Coalition[0])
	_ = binary.Write(&encoded, binary.BigEndian, descriptor.Coalition[1])
	return legacyKeccak(encoded.Bytes())
}

// MarshalBinary returns the canonical fixed-width release descriptor used on
// the threshold network. It contains no secret material.
func (descriptor ReleaseDescriptor) MarshalBinary() ([]byte, error) {
	if err := validateReleaseDescriptor(descriptor); err != nil {
		return nil, err
	}
	var out bytes.Buffer
	out.WriteString(thresholdDescriptorMagic)
	out.Write(descriptor.SessionID[:])
	out.Write(descriptor.KeyID[:])
	out.Write(descriptor.ParameterFingerprint[:])
	out.Write(descriptor.PolicyID[:])
	_ = binary.Write(&out, binary.BigEndian, descriptor.PolicyVersion)
	out.Write(descriptor.InputCommitmentA[:])
	out.Write(descriptor.InputCommitmentB[:])
	out.Write(uint256Word(descriptor.ResultNonce))
	_ = binary.Write(&out, binary.BigEndian, descriptor.ValidUntil)
	out.Write(descriptor.ResultCiphertextCommitment[:])
	out.Write(descriptor.ProtocolBinding[:])
	_ = binary.Write(&out, binary.BigEndian, descriptor.Coalition[0])
	_ = binary.Write(&out, binary.BigEndian, descriptor.Coalition[1])
	return out.Bytes(), nil
}

// UnmarshalReleaseDescriptor rejects trailing bytes and non-canonical values.
func UnmarshalReleaseDescriptor(data []byte) (ReleaseDescriptor, error) {
	reader := bytes.NewReader(data)
	magic := make([]byte, len(thresholdDescriptorMagic))
	if _, err := io.ReadFull(reader, magic); err != nil || string(magic) != thresholdDescriptorMagic {
		return ReleaseDescriptor{}, ErrInvalidReleaseDescriptor
	}
	var descriptor ReleaseDescriptor
	var nonceWord [32]byte
	if readFullMany(reader,
		descriptor.SessionID[:], descriptor.KeyID[:], descriptor.ParameterFingerprint[:], descriptor.PolicyID[:],
	) != nil || binary.Read(reader, binary.BigEndian, &descriptor.PolicyVersion) != nil ||
		readFullMany(reader, descriptor.InputCommitmentA[:], descriptor.InputCommitmentB[:], nonceWord[:]) != nil ||
		binary.Read(reader, binary.BigEndian, &descriptor.ValidUntil) != nil ||
		readFullMany(reader, descriptor.ResultCiphertextCommitment[:], descriptor.ProtocolBinding[:]) != nil ||
		binary.Read(reader, binary.BigEndian, &descriptor.Coalition[0]) != nil ||
		binary.Read(reader, binary.BigEndian, &descriptor.Coalition[1]) != nil || reader.Len() != 0 {
		return ReleaseDescriptor{}, ErrInvalidReleaseDescriptor
	}
	for index := range descriptor.ResultNonce {
		descriptor.ResultNonce[index] = binary.BigEndian.Uint64(nonceWord[index*8 : (index+1)*8])
	}
	if err := validateReleaseDescriptor(descriptor); err != nil {
		return ReleaseDescriptor{}, err
	}
	return descriptor, nil
}

func thresholdResponseStatementDigest(descriptor ReleaseDescriptor, response ThresholdReleaseResponse) [32]byte {
	var encoded bytes.Buffer
	encoded.WriteString(thresholdResponseDomain)
	encoded.WriteByte(0)
	descriptorDigest := ReleaseDescriptorDigest(descriptor)
	encoded.Write(descriptorDigest[:])
	encoded.Write(response.OperatorID[:])
	_ = binary.Write(&encoded, binary.BigEndian, response.Point)
	encoded.Write(response.ShareDigest[:])
	return legacyKeccak(encoded.Bytes())
}

func (response ThresholdReleaseResponse) MarshalBinary() ([]byte, error) {
	if len(response.Share) == 0 || len(response.Share) > maxReleaseShareSize || response.ShareDigest != legacyKeccak(response.Share) {
		return nil, ErrInvalidReleaseShare
	}
	var out bytes.Buffer
	out.WriteString(thresholdResponseMagic)
	out.Write(response.OperatorID[:])
	_ = binary.Write(&out, binary.BigEndian, response.Point)
	out.Write(response.SessionID[:])
	out.Write(response.ProtocolBinding[:])
	out.Write(response.ShareDigest[:])
	out.Write(response.StatementDigest[:])
	out.Write(response.Signature[:])
	writeSized(&out, response.Share)
	return out.Bytes(), nil
}

func UnmarshalThresholdReleaseResponse(data []byte) (ThresholdReleaseResponse, error) {
	reader := bytes.NewReader(data)
	magic := make([]byte, len(thresholdResponseMagic))
	if _, err := io.ReadFull(reader, magic); err != nil || string(magic) != thresholdResponseMagic {
		return ThresholdReleaseResponse{}, ErrInvalidReleaseShare
	}
	var response ThresholdReleaseResponse
	if _, err := io.ReadFull(reader, response.OperatorID[:]); err != nil ||
		binary.Read(reader, binary.BigEndian, &response.Point) != nil ||
		readFullMany(reader, response.SessionID[:], response.ProtocolBinding[:], response.ShareDigest[:], response.StatementDigest[:], response.Signature[:]) != nil {
		return ThresholdReleaseResponse{}, ErrInvalidReleaseShare
	}
	share, err := readSized(reader, maxReleaseShareSize)
	if err != nil || reader.Len() != 0 || response.ShareDigest != legacyKeccak(share) {
		return ThresholdReleaseResponse{}, ErrInvalidReleaseShare
	}
	response.Share = share
	return response, nil
}

func writeSized(out *bytes.Buffer, value []byte) {
	_ = binary.Write(out, binary.BigEndian, uint32(len(value)))
	out.Write(value)
}

func readSized(reader *bytes.Reader, maximum uint32) ([]byte, error) {
	var size uint32
	if binary.Read(reader, binary.BigEndian, &size) != nil || size == 0 || size > maximum || uint64(size) > uint64(reader.Len()) {
		return nil, ErrInvalidThresholdOperator
	}
	value := make([]byte, size)
	if _, err := io.ReadFull(reader, value); err != nil {
		return nil, ErrInvalidThresholdOperator
	}
	return value, nil
}

func readFullMany(reader io.Reader, destinations ...[]byte) error {
	for _, destination := range destinations {
		if _, err := io.ReadFull(reader, destination); err != nil {
			return err
		}
	}
	return nil
}

func containsPoint(points []multiparty.ShamirPublicPoint, target multiparty.ShamirPublicPoint) bool {
	for _, point := range points {
		if point == target {
			return true
		}
	}
	return false
}

func coalitionContains(coalition [2]uint64, point uint64) bool {
	return coalition[0] == point || coalition[1] == point
}
