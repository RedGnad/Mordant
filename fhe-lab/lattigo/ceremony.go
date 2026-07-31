package lattigospike

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sort"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/multiparty"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
	"github.com/tuneinsight/lattigo/v6/utils/sampling"
)

// The V4 ceremony is dealerless: every operator samples its own RLWE secret and
// its own Shamir polynomial locally, and no process ever holds more than one
// operator's secret material. The coordinator aggregates public protocol shares
// only; it has no method in this file that accepts a secret key or a Shamir
// share.
//
// Lattigo's multiparty package is secure against passive adversaries only and
// documents that retrying a round with reused shares and the same public
// polynomial can leak secret material. Every round below is therefore one-shot
// per (ceremony, epoch, round, recipient); a failed ceremony is terminal.

const (
	ceremonyRosterDomain     = "mordant.ceremony.roster/v4"
	ceremonyCRSDomain        = "mordant.ceremony.crs-seed/v4"
	ceremonyShareDomain      = "mordant.ceremony.private-share/v4"
	ceremonyManifestDomain   = "mordant.ceremony.key-manifest/v4"
	ceremonyPublicKeyDomain  = "mordant.ceremony.collective-public-key/v4"
	ceremonyRelinDomain      = "mordant.ceremony.relinearization-key/v4"
	ceremonyGaloisDomain     = "mordant.ceremony.galois-key/v4"
	ceremonyPrivateShareCap  = 16 << 20
	ceremonyPublicShareCap   = 256 << 20
	maxCeremonyOperators     = 16
	ceremonyPrivateShareWire = "MCS1"
	ceremonyAttestationWire  = "MCA1"
	ceremonyStatementDomain  = "mordant.ceremony.operator-statement/v4"
)

var (
	ErrCeremonyState     = errors.New("invalid ceremony state")
	ErrCeremonyBinding   = errors.New("ceremony binding mismatch")
	ErrCeremonyReplay    = errors.New("ceremony message already consumed")
	ErrCeremonyRoster    = errors.New("invalid ceremony roster")
	ErrCeremonyMaterial  = errors.New("invalid ceremony material")
	ErrCeremonySignature = errors.New("invalid ceremony signature")
)

type ceremonyRound uint8

// Rounds are strictly ordered. The order is also the order in which every
// operator draws common random polynomials from the shared CRS stream, so an
// out-of-order round would desynchronise the CRS and is refused.
const (
	roundCRSContribution ceremonyRound = iota
	roundCRSSealed
	roundPrivateShares
	roundThresholdShareSealed
	roundPublicKey
	roundRelinOne
	roundRelinTwo
	roundGalois
	roundSealed
)

// CeremonyOperatorIdentity is the public identity of one ceremony participant.
type CeremonyOperatorIdentity struct {
	Point            uint64
	SigningPublicKey [ed25519.PublicKeySize]byte
}

// OperatorID is the stable identifier derived from the signing key.
func (identity CeremonyOperatorIdentity) OperatorID() [32]byte {
	return sha256.Sum256(identity.SigningPublicKey[:])
}

// CeremonyRoster is the public description of the operator set. Every ceremony
// message binds its digest, so an operator that was handed a different roster
// cannot be silently folded into the same ceremony.
type CeremonyRoster struct {
	ParameterFingerprint [32]byte
	Threshold            uint16
	CeremonyID           [32]byte
	KeyEpoch             uint64
	Operators            []CeremonyOperatorIdentity
}

func (roster CeremonyRoster) validate() error {
	if roster.Threshold < 2 || int(roster.Threshold) > len(roster.Operators) ||
		len(roster.Operators) < 2 || len(roster.Operators) > maxCeremonyOperators ||
		roster.CeremonyID == ([32]byte{}) || roster.ParameterFingerprint == ([32]byte{}) ||
		roster.KeyEpoch == 0 {
		return ErrCeremonyRoster
	}
	seenPoint := make(map[uint64]struct{}, len(roster.Operators))
	seenKey := make(map[[ed25519.PublicKeySize]byte]struct{}, len(roster.Operators))
	for index, operator := range roster.Operators {
		if operator.Point == 0 || operator.SigningPublicKey == ([ed25519.PublicKeySize]byte{}) {
			return ErrCeremonyRoster
		}
		if index > 0 && roster.Operators[index-1].Point >= operator.Point {
			return ErrCeremonyRoster
		}
		if _, exists := seenPoint[operator.Point]; exists {
			return ErrCeremonyRoster
		}
		if _, exists := seenKey[operator.SigningPublicKey]; exists {
			return ErrCeremonyRoster
		}
		seenPoint[operator.Point] = struct{}{}
		seenKey[operator.SigningPublicKey] = struct{}{}
	}
	return nil
}

// Digest binds parameters, threshold, ceremony identity, epoch and every
// operator identity into one value carried by all ceremony messages.
func (roster CeremonyRoster) Digest() [32]byte {
	hash := sha256.New()
	_, _ = hash.Write([]byte(ceremonyRosterDomain))
	_, _ = hash.Write(roster.ParameterFingerprint[:])
	_ = binary.Write(hash, binary.BigEndian, roster.Threshold)
	_, _ = hash.Write(roster.CeremonyID[:])
	_ = binary.Write(hash, binary.BigEndian, roster.KeyEpoch)
	_ = binary.Write(hash, binary.BigEndian, uint16(len(roster.Operators)))
	for _, operator := range roster.Operators {
		_ = binary.Write(hash, binary.BigEndian, operator.Point)
		_, _ = hash.Write(operator.SigningPublicKey[:])
	}
	var digest [32]byte
	copy(digest[:], hash.Sum(nil))
	return digest
}

func (roster CeremonyRoster) points() []multiparty.ShamirPublicPoint {
	points := make([]multiparty.ShamirPublicPoint, len(roster.Operators))
	for index, operator := range roster.Operators {
		points[index] = multiparty.ShamirPublicPoint(operator.Point)
	}
	return points
}

func (roster CeremonyRoster) contains(point uint64) bool {
	for _, operator := range roster.Operators {
		if operator.Point == point {
			return true
		}
	}
	return false
}

func (roster CeremonyRoster) signingKeyFor(point uint64) (ed25519.PublicKey, bool) {
	for _, operator := range roster.Operators {
		if operator.Point == point {
			return ed25519.PublicKey(append([]byte(nil), operator.SigningPublicKey[:]...)), true
		}
	}
	return nil, false
}

// CeremonyPrivateShare is one Shamir re-sharing message travelling from its
// author to exactly one recipient over an authenticated private channel. The
// payload is the only secret in the ceremony wire format, and it is meaningful
// to its named recipient alone.
type CeremonyPrivateShare struct {
	RosterDigest [32]byte
	CeremonyID   [32]byte
	KeyEpoch     uint64
	Sender       uint64
	Recipient    uint64
	Payload      []byte
	Signature    [ed25519.SignatureSize]byte
}

func (share CeremonyPrivateShare) signingDigest() [32]byte {
	payloadDigest := sha256.Sum256(share.Payload)
	hash := sha256.New()
	_, _ = hash.Write([]byte(ceremonyShareDomain))
	_, _ = hash.Write(share.RosterDigest[:])
	_, _ = hash.Write(share.CeremonyID[:])
	_ = binary.Write(hash, binary.BigEndian, share.KeyEpoch)
	_ = binary.Write(hash, binary.BigEndian, share.Sender)
	_ = binary.Write(hash, binary.BigEndian, share.Recipient)
	_, _ = hash.Write(payloadDigest[:])
	var digest [32]byte
	copy(digest[:], hash.Sum(nil))
	return digest
}

// MarshalBinary encodes the private share for transport on an authenticated
// private channel.
func (share CeremonyPrivateShare) MarshalBinary() ([]byte, error) {
	if len(share.Payload) == 0 || len(share.Payload) > ceremonyPrivateShareCap ||
		share.Sender == 0 || share.Recipient == 0 || share.KeyEpoch == 0 {
		return nil, ErrCeremonyMaterial
	}
	var out bytes.Buffer
	out.WriteString(ceremonyPrivateShareWire)
	out.Write(share.RosterDigest[:])
	out.Write(share.CeremonyID[:])
	_ = binary.Write(&out, binary.BigEndian, share.KeyEpoch)
	_ = binary.Write(&out, binary.BigEndian, share.Sender)
	_ = binary.Write(&out, binary.BigEndian, share.Recipient)
	writeSized(&out, share.Payload)
	out.Write(share.Signature[:])
	return out.Bytes(), nil
}

// UnmarshalCeremonyPrivateShare decodes a private share message.
func UnmarshalCeremonyPrivateShare(data []byte) (CeremonyPrivateShare, error) {
	var share CeremonyPrivateShare
	reader := bytes.NewReader(data)
	magic := make([]byte, len(ceremonyPrivateShareWire))
	if _, err := io.ReadFull(reader, magic); err != nil || string(magic) != ceremonyPrivateShareWire {
		return share, ErrCeremonyMaterial
	}
	if _, err := io.ReadFull(reader, share.RosterDigest[:]); err != nil {
		return share, ErrCeremonyMaterial
	}
	if _, err := io.ReadFull(reader, share.CeremonyID[:]); err != nil {
		return share, ErrCeremonyMaterial
	}
	if binary.Read(reader, binary.BigEndian, &share.KeyEpoch) != nil ||
		binary.Read(reader, binary.BigEndian, &share.Sender) != nil ||
		binary.Read(reader, binary.BigEndian, &share.Recipient) != nil {
		return share, ErrCeremonyMaterial
	}
	payload, err := readSized(reader, ceremonyPrivateShareCap)
	if err != nil {
		return share, ErrCeremonyMaterial
	}
	share.Payload = payload
	if _, err := io.ReadFull(reader, share.Signature[:]); err != nil || reader.Len() != 0 {
		return share, ErrCeremonyMaterial
	}
	if share.Sender == 0 || share.Recipient == 0 || share.KeyEpoch == 0 {
		return share, ErrCeremonyMaterial
	}
	return share, nil
}

// CeremonyKeyDigests are the public commitments produced by the ceremony. They
// are what every operator signs and what a client checks before encrypting.
type CeremonyKeyDigests struct {
	CRSCommitment           [32]byte
	PublicKeyCommitment     [32]byte
	RelinearizationKeyDigest [32]byte
	GaloisKeyCommitment     [32]byte
	PolicyCircuitCommitment [32]byte
}

func (digests CeremonyKeyDigests) manifestDigest(roster CeremonyRoster) [32]byte {
	rosterDigest := roster.Digest()
	hash := sha256.New()
	_, _ = hash.Write([]byte(ceremonyManifestDomain))
	_, _ = hash.Write(rosterDigest[:])
	_, _ = hash.Write(digests.CRSCommitment[:])
	_, _ = hash.Write(digests.PublicKeyCommitment[:])
	_, _ = hash.Write(digests.RelinearizationKeyDigest[:])
	_, _ = hash.Write(digests.GaloisKeyCommitment[:])
	_, _ = hash.Write(digests.PolicyCircuitCommitment[:])
	var digest [32]byte
	copy(digest[:], hash.Sum(nil))
	return digest
}

// CeremonyAttestation is one operator's signature over the final key manifest.
type CeremonyAttestation struct {
	Point     uint64
	Signature [ed25519.SignatureSize]byte
}

// CeremonyOperatorState is one operator's private ceremony state machine. It is
// created inside the operator process and never leaves it. No method returns
// the local RLWE secret, the Shamir polynomial or the ephemeral relinearization
// secret.
type CeremonyOperatorState struct {
	params     bgv.Parameters
	roster     CeremonyRoster
	rosterHash [32]byte
	point      multiparty.ShamirPublicPoint
	signingKey ed25519.PrivateKey

	secretKey  *rlwe.SecretKey
	polynomial multiparty.ShamirPolynomial
	ephemeral  *rlwe.SecretKey
	share      multiparty.ShamirSecretShare
	sealed     bool

	contribution  [32]byte
	contributions map[uint64][32]byte
	received      map[uint64]struct{}
	emitted       map[uint64]struct{}
	galoisDone    int
	crs           sampling.PRNG
	crsCommitment [32]byte
	round         ceremonyRound

	thresholdizer multiparty.Thresholdizer
	publicKeyGen  multiparty.PublicKeyGenProtocol
	relinGen      multiparty.RelinearizationKeyGenProtocol
	galoisGen     multiparty.GaloisKeyGenProtocol
	relinRoundOne multiparty.RelinearizationKeyGenShare
}

// NewCeremonyOperatorState samples this operator's own RLWE secret locally. No
// caller supplies secret material, and none is returned.
func NewCeremonyOperatorState(params bgv.Parameters, roster CeremonyRoster, point uint64, signingKey ed25519.PrivateKey) (*CeremonyOperatorState, error) {
	if err := roster.validate(); err != nil {
		return nil, err
	}
	if len(signingKey) != ed25519.PrivateKeySize || !roster.contains(point) {
		return nil, ErrCeremonyRoster
	}
	declared, ok := roster.signingKeyFor(point)
	if !ok || !bytes.Equal(declared, signingKey.Public().(ed25519.PublicKey)) {
		return nil, ErrCeremonyRoster
	}
	parameterBytes, err := params.MarshalBinary()
	if err != nil {
		return nil, ErrCeremonyMaterial
	}
	if sha256.Sum256(parameterBytes) != roster.ParameterFingerprint {
		return nil, ErrCeremonyBinding
	}
	var contribution [32]byte
	if _, err := rand.Read(contribution[:]); err != nil {
		return nil, err
	}
	state := &CeremonyOperatorState{
		params:        params,
		roster:        roster,
		rosterHash:    roster.Digest(),
		point:         multiparty.ShamirPublicPoint(point),
		signingKey:    append(ed25519.PrivateKey(nil), signingKey...),
		secretKey:     rlwe.NewKeyGenerator(params).GenSecretKeyNew(),
		contribution:  contribution,
		contributions: map[uint64][32]byte{point: contribution},
		received:      make(map[uint64]struct{}),
		emitted:       make(map[uint64]struct{}),
		thresholdizer: multiparty.NewThresholdizer(params),
		publicKeyGen:  multiparty.NewPublicKeyGenProtocol(params),
		relinGen:      multiparty.NewRelinearizationKeyGenProtocol(params),
		galoisGen:     multiparty.NewGaloisKeyGenProtocol(params),
		round:         roundCRSContribution,
	}
	return state, nil
}

// Point exposes the operator's public Shamir point.
func (state *CeremonyOperatorState) Point() uint64 { return uint64(state.point) }

// RosterDigest exposes the binding this operator will enforce on every message.
func (state *CeremonyOperatorState) RosterDigest() [32]byte { return state.rosterHash }

// RosterSigningPoint maps a presented transport identity back to a roster point.
// The private channel uses it so an operator's mTLS identity and its signed
// ceremony identity must be the same key.
func (state *CeremonyOperatorState) RosterSigningPoint(publicKey ed25519.PublicKey) (uint64, bool) {
	if len(publicKey) != ed25519.PublicKeySize {
		return 0, false
	}
	for _, operator := range state.roster.Operators {
		if bytes.Equal(operator.SigningPublicKey[:], publicKey) {
			return operator.Point, true
		}
	}
	return 0, false
}

// RosterOperatorPoints lists the roster points in canonical order.
func (state *CeremonyOperatorState) RosterOperatorPoints() []uint64 {
	points := make([]uint64, len(state.roster.Operators))
	for index, operator := range state.roster.Operators {
		points[index] = operator.Point
	}
	return points
}

// CRSContribution returns this operator's public randomness contribution to the
// collaborative common reference string.
func (state *CeremonyOperatorState) CRSContribution() [32]byte { return state.contribution }

// AcceptCRSContribution folds one peer contribution into the CRS seed input.
func (state *CeremonyOperatorState) AcceptCRSContribution(point uint64, value [32]byte) error {
	if state.round != roundCRSContribution {
		return ErrCeremonyState
	}
	if !state.roster.contains(point) || value == ([32]byte{}) {
		return ErrCeremonyBinding
	}
	if existing, seen := state.contributions[point]; seen {
		if existing != value {
			return ErrCeremonyReplay
		}
		return nil
	}
	state.contributions[point] = value
	return nil
}

// SealCRS derives the collaborative CRS once every operator has contributed.
// The seed is a pure function of public data, so any verifier can recompute it.
func (state *CeremonyOperatorState) SealCRS() error {
	if state.round != roundCRSContribution || len(state.contributions) != len(state.roster.Operators) {
		return ErrCeremonyState
	}
	seed, commitment := ceremonyCRSSeed(state.roster, state.contributions)
	prng, err := sampling.NewKeyedPRNG(seed[:])
	if err != nil {
		return err
	}
	state.crs = prng
	state.crsCommitment = commitment
	polynomial, err := state.thresholdizer.GenShamirPolynomial(int(state.roster.Threshold), state.secretKey)
	if err != nil {
		return err
	}
	state.polynomial = polynomial
	state.share = state.thresholdizer.AllocateThresholdSecretShare()
	state.round = roundPrivateShares
	return nil
}

// CRSCommitment returns the public commitment to the sealed CRS.
func (state *CeremonyOperatorState) CRSCommitment() [32]byte { return state.crsCommitment }

// ceremonyCRSSeed derives the CRS seed and its commitment from public data
// only. Every operator contributes; no single operator fixes the value.
func ceremonyCRSSeed(roster CeremonyRoster, contributions map[uint64][32]byte) (seed [32]byte, commitment [32]byte) {
	points := make([]uint64, 0, len(contributions))
	for point := range contributions {
		points = append(points, point)
	}
	sort.Slice(points, func(i, j int) bool { return points[i] < points[j] })
	rosterDigest := roster.Digest()
	hash := sha256.New()
	_, _ = hash.Write([]byte(ceremonyCRSDomain))
	_, _ = hash.Write(rosterDigest[:])
	_, _ = hash.Write(roster.ParameterFingerprint[:])
	_, _ = hash.Write(roster.CeremonyID[:])
	_ = binary.Write(hash, binary.BigEndian, roster.KeyEpoch)
	for _, point := range points {
		value := contributions[point]
		_ = binary.Write(hash, binary.BigEndian, point)
		_, _ = hash.Write(value[:])
	}
	copy(seed[:], hash.Sum(nil))
	commitment = sha256.Sum256(append([]byte(ceremonyCRSDomain+".commitment\x00"), seed[:]...))
	return seed, commitment
}

// PrivateShareFor produces the Shamir re-sharing addressed to one recipient.
// It is one-shot per recipient: a second call is refused, because Lattigo
// documents that reusing protocol material across retries can leak secrets.
func (state *CeremonyOperatorState) PrivateShareFor(recipient uint64) (CeremonyPrivateShare, error) {
	if state.round != roundPrivateShares {
		return CeremonyPrivateShare{}, ErrCeremonyState
	}
	if !state.roster.contains(recipient) {
		return CeremonyPrivateShare{}, ErrCeremonyBinding
	}
	if _, done := state.emitted[recipient]; done {
		return CeremonyPrivateShare{}, ErrCeremonyReplay
	}
	outgoing := state.thresholdizer.AllocateThresholdSecretShare()
	state.thresholdizer.GenShamirSecretShare(multiparty.ShamirPublicPoint(recipient), state.polynomial, &outgoing)
	payload, err := outgoing.MarshalBinary()
	if err != nil {
		return CeremonyPrivateShare{}, err
	}
	share := CeremonyPrivateShare{
		RosterDigest: state.rosterHash,
		CeremonyID:   state.roster.CeremonyID,
		KeyEpoch:     state.roster.KeyEpoch,
		Sender:       uint64(state.point),
		Recipient:    recipient,
		Payload:      payload,
	}
	digest := share.signingDigest()
	copy(share.Signature[:], ed25519.Sign(state.signingKey, digest[:]))
	state.emitted[recipient] = struct{}{}
	return share, nil
}

// AcceptPrivateShare authenticates and aggregates one inbound re-sharing. The
// sender's signature is verified against the roster before the payload is
// deserialised, and each sender may contribute exactly once.
func (state *CeremonyOperatorState) AcceptPrivateShare(share CeremonyPrivateShare) error {
	if state.round != roundPrivateShares {
		return ErrCeremonyState
	}
	if share.RosterDigest != state.rosterHash || share.CeremonyID != state.roster.CeremonyID ||
		share.KeyEpoch != state.roster.KeyEpoch || share.Recipient != uint64(state.point) {
		return ErrCeremonyBinding
	}
	senderKey, ok := state.roster.signingKeyFor(share.Sender)
	if !ok {
		return ErrCeremonyBinding
	}
	digest := share.signingDigest()
	if !ed25519.Verify(senderKey, digest[:], share.Signature[:]) {
		return ErrCeremonySignature
	}
	if _, seen := state.received[share.Sender]; seen {
		return ErrCeremonyReplay
	}
	incoming := state.thresholdizer.AllocateThresholdSecretShare()
	if err := incoming.UnmarshalBinary(share.Payload); err != nil {
		return ErrCeremonyMaterial
	}
	if err := state.thresholdizer.AggregateShares(incoming, state.share, &state.share); err != nil {
		return err
	}
	state.received[share.Sender] = struct{}{}
	return nil
}

// SealThresholdShare finalises S(alpha_i) once every operator has contributed,
// and erases the local Shamir polynomial. A missing contribution is terminal:
// the ceremony must be restarted with a fresh ceremony ID and fresh secrets.
func (state *CeremonyOperatorState) SealThresholdShare() error {
	if state.round != roundPrivateShares {
		return ErrCeremonyState
	}
	if len(state.received) != len(state.roster.Operators) {
		return ErrCeremonyState
	}
	state.polynomial = multiparty.ShamirPolynomial{}
	state.round = roundPublicKey
	return nil
}

// PublicKeyShare emits this operator's public collective-public-key share. It
// uses the raw local secret in the N-out-of-N regime, which targets the same
// ideal secret S(0) that any 2-of-3 coalition later reconstructs.
func (state *CeremonyOperatorState) PublicKeyShare() ([]byte, error) {
	if state.round != roundPublicKey {
		return nil, ErrCeremonyState
	}
	crp := state.publicKeyGen.SampleCRP(state.crs)
	share := state.publicKeyGen.AllocateShare()
	state.publicKeyGen.GenShare(state.secretKey, crp, &share)
	wire, err := share.MarshalBinary()
	if err != nil {
		return nil, err
	}
	state.round = roundRelinOne
	return wire, nil
}

// RelinearizationShareRoundOne emits the first relinearization round share and
// retains the ephemeral secret required by round two.
func (state *CeremonyOperatorState) RelinearizationShareRoundOne() ([]byte, error) {
	if state.round != roundRelinOne {
		return nil, ErrCeremonyState
	}
	crp := state.relinGen.SampleCRP(state.crs)
	ephemeral, roundOne, _ := state.relinGen.AllocateShare()
	state.relinGen.GenShareRoundOne(state.secretKey, crp, ephemeral, &roundOne)
	wire, err := roundOne.MarshalBinary()
	if err != nil {
		return nil, err
	}
	state.ephemeral = ephemeral
	state.round = roundRelinTwo
	return wire, nil
}

// RelinearizationShareRoundTwo consumes the aggregated first round and emits the
// second round share.
func (state *CeremonyOperatorState) RelinearizationShareRoundTwo(aggregatedRoundOne []byte) ([]byte, error) {
	if state.round != roundRelinTwo || state.ephemeral == nil {
		return nil, ErrCeremonyState
	}
	if len(aggregatedRoundOne) == 0 || len(aggregatedRoundOne) > ceremonyPublicShareCap {
		return nil, ErrCeremonyMaterial
	}
	_, combined, roundTwo := state.relinGen.AllocateShare()
	if err := combined.UnmarshalBinary(aggregatedRoundOne); err != nil {
		return nil, ErrCeremonyMaterial
	}
	state.relinGen.GenShareRoundTwo(state.ephemeral, state.secretKey, combined, &roundTwo)
	wire, err := roundTwo.MarshalBinary()
	if err != nil {
		return nil, err
	}
	state.relinRoundOne = combined
	state.round = roundGalois
	return wire, nil
}

// GaloisShare emits this operator's share for one Galois element. Elements must
// be requested in the canonical circuit order so every operator draws the same
// common random polynomial from the shared CRS stream.
func (state *CeremonyOperatorState) GaloisShare(galoisElement uint64) ([]byte, error) {
	if state.round != roundGalois || state.galoisDone >= len(rotationSteps) {
		return nil, ErrCeremonyState
	}
	if galoisElement != state.params.GaloisElement(rotationSteps[state.galoisDone]) {
		return nil, ErrCeremonyBinding
	}
	crp := state.galoisGen.SampleCRP(state.crs)
	share := state.galoisGen.AllocateShare()
	if err := state.galoisGen.GenShare(state.secretKey, galoisElement, crp, &share); err != nil {
		return nil, err
	}
	wire, err := share.MarshalBinary()
	if err != nil {
		return nil, err
	}
	state.galoisDone++
	return wire, nil
}

// Seal erases every transient secret, keeps only the retained Shamir share, and
// signs the public key manifest. After Seal the operator can release with a
// coalition but can never contribute to key generation again.
func (state *CeremonyOperatorState) Seal(digests CeremonyKeyDigests) (CeremonyAttestation, error) {
	if state.round != roundGalois || state.galoisDone != len(rotationSteps) {
		return CeremonyAttestation{}, ErrCeremonyState
	}
	if digests.CRSCommitment != state.crsCommitment {
		return CeremonyAttestation{}, ErrCeremonyBinding
	}
	if digests.PublicKeyCommitment == ([32]byte{}) || digests.RelinearizationKeyDigest == ([32]byte{}) ||
		digests.GaloisKeyCommitment == ([32]byte{}) || digests.PolicyCircuitCommitment == ([32]byte{}) {
		return CeremonyAttestation{}, ErrCeremonyBinding
	}
	// Erasing the local RLWE secret and the relinearization ephemeral is what
	// makes the retained Shamir share the operator's only decryption-relevant
	// material. It is irreversible by construction.
	state.secretKey = nil
	state.ephemeral = nil
	state.relinRoundOne = multiparty.RelinearizationKeyGenShare{}
	state.crs = nil
	state.sealed = true
	state.round = roundSealed
	manifest := digests.manifestDigest(state.roster)
	attestation := CeremonyAttestation{Point: uint64(state.point)}
	copy(attestation.Signature[:], ed25519.Sign(state.signingKey, manifest[:]))
	return attestation, nil
}

// HoldsLocalSecretKey reports whether the transient local RLWE secret is still
// resident. It exists so tests and evidence can assert erasure after Seal.
func (state *CeremonyOperatorState) HoldsLocalSecretKey() bool {
	return state.secretKey != nil || state.ephemeral != nil
}

// Sealed reports whether the ceremony completed for this operator.
func (state *CeremonyOperatorState) Sealed() bool { return state.sealed }

// SealedOperatorBundle serialises this operator's own long-lived material into
// its own storage. It contains exactly one Shamir share and one signing key.
// There is deliberately no function anywhere that serialises more than one
// operator's secret material.
func (state *CeremonyOperatorState) SealedOperatorBundle(keyID [32]byte) ([]byte, error) {
	if !state.sealed {
		return nil, ErrCeremonyState
	}
	parameterBytes, err := state.params.MarshalBinary()
	if err != nil {
		return nil, err
	}
	shareBytes, err := state.share.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return marshalThresholdOperatorConfig(
		parameterBytes,
		keyID,
		state.roster.ParameterFingerprint,
		state.roster.Threshold,
		state.point,
		state.roster.points(),
		shareBytes,
		state.signingKey,
	)
}

// VerifyCeremonyAttestations checks that every operator in the roster signed the
// same manifest digest. A manifest missing any operator signature is rejected:
// the key set is jointly authenticated or it is not authenticated at all.
func VerifyCeremonyAttestations(roster CeremonyRoster, digests CeremonyKeyDigests, attestations []CeremonyAttestation) error {
	if err := roster.validate(); err != nil {
		return err
	}
	manifest := digests.manifestDigest(roster)
	seen := make(map[uint64]struct{}, len(attestations))
	for _, attestation := range attestations {
		key, ok := roster.signingKeyFor(attestation.Point)
		if !ok {
			return ErrCeremonyBinding
		}
		if _, duplicate := seen[attestation.Point]; duplicate {
			return ErrCeremonyReplay
		}
		if !ed25519.Verify(key, manifest[:], attestation.Signature[:]) {
			return ErrCeremonySignature
		}
		seen[attestation.Point] = struct{}{}
	}
	if len(seen) != len(roster.Operators) {
		return fmt.Errorf("%w: %d of %d operator attestations", ErrCeremonySignature, len(seen), len(roster.Operators))
	}
	return nil
}

// SignOperatorStatement signs an operator-authored statement with the operator's
// own ceremony key. It exists so operator state can be verified against the
// roster by any party, instead of being trusted because the coordinator relayed
// it. The signing key survives Seal; only the FHE secrets are erased.
func (state *CeremonyOperatorState) SignOperatorStatement(payload []byte) [ed25519.SignatureSize]byte {
	var signature [ed25519.SignatureSize]byte
	digest := sha256.Sum256(append([]byte(ceremonyStatementDomain), payload...))
	copy(signature[:], ed25519.Sign(state.signingKey, digest[:]))
	return signature
}

// VerifyOperatorStatement checks an operator-authored statement against the
// roster entry for the claimed point.
func VerifyOperatorStatement(roster CeremonyRoster, point uint64, payload []byte, signature [ed25519.SignatureSize]byte) error {
	key, ok := roster.signingKeyFor(point)
	if !ok {
		return ErrCeremonyBinding
	}
	digest := sha256.Sum256(append([]byte(ceremonyStatementDomain), payload...))
	if !ed25519.Verify(key, digest[:], signature[:]) {
		return ErrCeremonySignature
	}
	return nil
}
