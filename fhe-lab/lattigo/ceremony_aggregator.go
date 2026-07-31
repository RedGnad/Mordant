package lattigospike

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/multiparty"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
	"github.com/tuneinsight/lattigo/v6/utils/sampling"
)

// CeremonyAggregator combines the public protocol shares emitted by the
// operators. Every exported method takes []byte that is deserialised into a
// public Lattigo share type; none accepts, returns or stores an rlwe.SecretKey,
// a multiparty.ShamirSecretShare or a ShamirPolynomial. That absence is the
// evaluator-side custody boundary and is asserted by
// TestAggregatorHasNoSecretMaterialAPI.
type CeremonyAggregator struct {
	params     bgv.Parameters
	roster     CeremonyRoster
	rosterHash [32]byte

	publicKeyGen multiparty.PublicKeyGenProtocol
	relinGen     multiparty.RelinearizationKeyGenProtocol
	galoisGen    multiparty.GaloisKeyGenProtocol

	crs           sampling.PRNG
	crsCommitment [32]byte
	contributions map[uint64][32]byte

	publicKeyShares  map[uint64]struct{}
	publicKeyCRP     multiparty.PublicKeyGenCRP
	publicKeyCombine multiparty.PublicKeyGenShare

	relinCRP        multiparty.RelinearizationKeyGenCRP
	relinOneSeen    map[uint64]struct{}
	relinTwoSeen    map[uint64]struct{}
	relinCombineOne multiparty.RelinearizationKeyGenShare
	relinCombineTwo multiparty.RelinearizationKeyGenShare

	galoisIndex    int
	galoisCRP      multiparty.GaloisKeyGenCRP
	galoisSeen     map[uint64]struct{}
	galoisCombine  multiparty.GaloisKeyGenShare
	galoisElements []uint64
	galoisKeys     []*rlwe.GaloisKey

	publicKey      *rlwe.PublicKey
	relinKey       *rlwe.RelinearizationKey
	stage          ceremonyRound
	relinOneWire   []byte
	galoisComplete bool
}

// NewCeremonyAggregator prepares the public-share aggregation for one roster.
func NewCeremonyAggregator(params bgv.Parameters, roster CeremonyRoster) (*CeremonyAggregator, error) {
	if err := roster.validate(); err != nil {
		return nil, err
	}
	parameterBytes, err := params.MarshalBinary()
	if err != nil {
		return nil, ErrCeremonyMaterial
	}
	if sha256.Sum256(parameterBytes) != roster.ParameterFingerprint {
		return nil, ErrCeremonyBinding
	}
	elements := make([]uint64, len(rotationSteps))
	for index, step := range rotationSteps {
		elements[index] = params.GaloisElement(step)
	}
	return &CeremonyAggregator{
		params:          params,
		roster:          roster,
		rosterHash:      roster.Digest(),
		publicKeyGen:    multiparty.NewPublicKeyGenProtocol(params),
		relinGen:        multiparty.NewRelinearizationKeyGenProtocol(params),
		galoisGen:       multiparty.NewGaloisKeyGenProtocol(params),
		contributions:   make(map[uint64][32]byte),
		publicKeyShares: make(map[uint64]struct{}),
		relinOneSeen:    make(map[uint64]struct{}),
		relinTwoSeen:    make(map[uint64]struct{}),
		galoisSeen:      make(map[uint64]struct{}),
		galoisElements:  elements,
		galoisKeys:      make([]*rlwe.GaloisKey, 0, len(elements)),
		stage:           roundCRSContribution,
	}, nil
}

// GaloisElements exposes the canonical circuit rotation order the operators
// must follow.
func (aggregator *CeremonyAggregator) GaloisElements() []uint64 {
	return append([]uint64(nil), aggregator.galoisElements...)
}

// AcceptCRSContribution records one operator's public randomness contribution.
func (aggregator *CeremonyAggregator) AcceptCRSContribution(point uint64, value [32]byte) error {
	if aggregator.stage != roundCRSContribution {
		return ErrCeremonyState
	}
	if !aggregator.roster.contains(point) || value == ([32]byte{}) {
		return ErrCeremonyBinding
	}
	if _, seen := aggregator.contributions[point]; seen {
		return ErrCeremonyReplay
	}
	aggregator.contributions[point] = value
	return nil
}

// SealCRS derives the same collaborative CRS the operators derived.
func (aggregator *CeremonyAggregator) SealCRS() error {
	if aggregator.stage != roundCRSContribution || len(aggregator.contributions) != len(aggregator.roster.Operators) {
		return ErrCeremonyState
	}
	seed, commitment := ceremonyCRSSeed(aggregator.roster, aggregator.contributions)
	prng, err := sampling.NewKeyedPRNG(seed[:])
	if err != nil {
		return err
	}
	aggregator.crs = prng
	aggregator.crsCommitment = commitment
	aggregator.publicKeyCRP = aggregator.publicKeyGen.SampleCRP(prng)
	aggregator.publicKeyCombine = aggregator.publicKeyGen.AllocateShare()
	aggregator.stage = roundPublicKey
	return nil
}

// CRSCommitment returns the public commitment to the sealed CRS.
func (aggregator *CeremonyAggregator) CRSCommitment() [32]byte { return aggregator.crsCommitment }

// AcceptPublicKeyShare folds one operator's collective public-key share.
func (aggregator *CeremonyAggregator) AcceptPublicKeyShare(point uint64, wire []byte) error {
	if aggregator.stage != roundPublicKey {
		return ErrCeremonyState
	}
	if err := aggregator.checkOrigin(point, aggregator.publicKeyShares, wire); err != nil {
		return err
	}
	share := aggregator.publicKeyGen.AllocateShare()
	if err := share.UnmarshalBinary(wire); err != nil {
		return ErrCeremonyMaterial
	}
	aggregator.publicKeyGen.AggregateShares(share, aggregator.publicKeyCombine, &aggregator.publicKeyCombine)
	aggregator.publicKeyShares[point] = struct{}{}
	if len(aggregator.publicKeyShares) == len(aggregator.roster.Operators) {
		publicKey := rlwe.NewPublicKey(aggregator.params)
		aggregator.publicKeyGen.GenPublicKey(aggregator.publicKeyCombine, aggregator.publicKeyCRP, publicKey)
		aggregator.publicKey = publicKey
		aggregator.relinCRP = aggregator.relinGen.SampleCRP(aggregator.crs)
		_, combineOne, combineTwo := aggregator.relinGen.AllocateShare()
		aggregator.relinCombineOne, aggregator.relinCombineTwo = combineOne, combineTwo
		aggregator.stage = roundRelinOne
	}
	return nil
}

// AcceptRelinearizationShareRoundOne folds one first-round relinearization share.
func (aggregator *CeremonyAggregator) AcceptRelinearizationShareRoundOne(point uint64, wire []byte) error {
	if aggregator.stage != roundRelinOne {
		return ErrCeremonyState
	}
	if err := aggregator.checkOrigin(point, aggregator.relinOneSeen, wire); err != nil {
		return err
	}
	_, share, _ := aggregator.relinGen.AllocateShare()
	if err := share.UnmarshalBinary(wire); err != nil {
		return ErrCeremonyMaterial
	}
	aggregator.relinGen.AggregateShares(share, aggregator.relinCombineOne, &aggregator.relinCombineOne)
	aggregator.relinOneSeen[point] = struct{}{}
	if len(aggregator.relinOneSeen) == len(aggregator.roster.Operators) {
		encoded, err := aggregator.relinCombineOne.MarshalBinary()
		if err != nil {
			return err
		}
		aggregator.relinOneWire = encoded
		aggregator.stage = roundRelinTwo
	}
	return nil
}

// AggregatedRelinearizationRoundOne returns the aggregated first round that
// every operator needs for its second-round share.
func (aggregator *CeremonyAggregator) AggregatedRelinearizationRoundOne() ([]byte, error) {
	if aggregator.stage != roundRelinTwo || len(aggregator.relinOneWire) == 0 {
		return nil, ErrCeremonyState
	}
	return append([]byte(nil), aggregator.relinOneWire...), nil
}

// AcceptRelinearizationShareRoundTwo folds one second-round share and derives
// the collective relinearization key once every operator has contributed.
func (aggregator *CeremonyAggregator) AcceptRelinearizationShareRoundTwo(point uint64, wire []byte) error {
	if aggregator.stage != roundRelinTwo {
		return ErrCeremonyState
	}
	if err := aggregator.checkOrigin(point, aggregator.relinTwoSeen, wire); err != nil {
		return err
	}
	_, _, share := aggregator.relinGen.AllocateShare()
	if err := share.UnmarshalBinary(wire); err != nil {
		return ErrCeremonyMaterial
	}
	aggregator.relinGen.AggregateShares(share, aggregator.relinCombineTwo, &aggregator.relinCombineTwo)
	aggregator.relinTwoSeen[point] = struct{}{}
	if len(aggregator.relinTwoSeen) == len(aggregator.roster.Operators) {
		relinKey := rlwe.NewRelinearizationKey(aggregator.params)
		aggregator.relinGen.GenRelinearizationKey(aggregator.relinCombineOne, aggregator.relinCombineTwo, relinKey)
		aggregator.relinKey = relinKey
		aggregator.startGaloisElement()
		aggregator.stage = roundGalois
	}
	return nil
}

func (aggregator *CeremonyAggregator) startGaloisElement() {
	aggregator.galoisCRP = aggregator.galoisGen.SampleCRP(aggregator.crs)
	aggregator.galoisCombine = aggregator.galoisGen.AllocateShare()
	aggregator.galoisCombine.GaloisElement = aggregator.galoisElements[aggregator.galoisIndex]
	aggregator.galoisSeen = make(map[uint64]struct{}, len(aggregator.roster.Operators))
}

// CurrentGaloisElement reports which Galois element the operators must serve.
func (aggregator *CeremonyAggregator) CurrentGaloisElement() (uint64, bool) {
	if aggregator.stage != roundGalois || aggregator.galoisComplete {
		return 0, false
	}
	return aggregator.galoisElements[aggregator.galoisIndex], true
}

// AcceptGaloisShare folds one Galois share for the current element.
func (aggregator *CeremonyAggregator) AcceptGaloisShare(point uint64, wire []byte) error {
	if aggregator.stage != roundGalois || aggregator.galoisComplete {
		return ErrCeremonyState
	}
	if err := aggregator.checkOrigin(point, aggregator.galoisSeen, wire); err != nil {
		return err
	}
	share := aggregator.galoisGen.AllocateShare()
	if err := share.UnmarshalBinary(wire); err != nil {
		return ErrCeremonyMaterial
	}
	if share.GaloisElement != aggregator.galoisElements[aggregator.galoisIndex] {
		return ErrCeremonyBinding
	}
	if err := aggregator.galoisGen.AggregateShares(share, aggregator.galoisCombine, &aggregator.galoisCombine); err != nil {
		return err
	}
	aggregator.galoisSeen[point] = struct{}{}
	if len(aggregator.galoisSeen) != len(aggregator.roster.Operators) {
		return nil
	}
	key := rlwe.NewGaloisKey(aggregator.params)
	if err := aggregator.galoisGen.GenGaloisKey(aggregator.galoisCombine, aggregator.galoisCRP, key); err != nil {
		return err
	}
	aggregator.galoisKeys = append(aggregator.galoisKeys, key)
	aggregator.galoisIndex++
	if aggregator.galoisIndex == len(aggregator.galoisElements) {
		aggregator.galoisComplete = true
		return nil
	}
	aggregator.startGaloisElement()
	return nil
}

func (aggregator *CeremonyAggregator) checkOrigin(point uint64, seen map[uint64]struct{}, wire []byte) error {
	if !aggregator.roster.contains(point) {
		return ErrCeremonyBinding
	}
	if _, duplicate := seen[point]; duplicate {
		return ErrCeremonyReplay
	}
	if len(wire) == 0 || len(wire) > ceremonyPublicShareCap {
		return ErrCeremonyMaterial
	}
	return nil
}

// Complete reports whether every collective key has been derived.
func (aggregator *CeremonyAggregator) Complete() bool {
	return aggregator.galoisComplete && aggregator.publicKey != nil && aggregator.relinKey != nil
}

// CollectiveKeys returns the derived public and evaluation keys.
func (aggregator *CeremonyAggregator) CollectiveKeys() (*rlwe.PublicKey, *rlwe.RelinearizationKey, []*rlwe.GaloisKey, error) {
	if !aggregator.Complete() {
		return nil, nil, nil, ErrCeremonyState
	}
	return aggregator.publicKey, aggregator.relinKey, aggregator.galoisKeys, nil
}

// KeyDigests returns the public commitments the operators must countersign.
func (aggregator *CeremonyAggregator) KeyDigests(policyID [32]byte, policyVersion uint32) (CeremonyKeyDigests, error) {
	if !aggregator.Complete() {
		return CeremonyKeyDigests{}, ErrCeremonyState
	}
	publicKeyBytes, err := aggregator.publicKey.MarshalBinary()
	if err != nil {
		return CeremonyKeyDigests{}, err
	}
	relinBytes, err := aggregator.relinKey.MarshalBinary()
	if err != nil {
		return CeremonyKeyDigests{}, err
	}
	galoisHash := sha256.New()
	_, _ = galoisHash.Write([]byte(ceremonyGaloisDomain))
	for index, key := range aggregator.galoisKeys {
		encoded, marshalErr := key.MarshalBinary()
		if marshalErr != nil {
			return CeremonyKeyDigests{}, marshalErr
		}
		_ = binary.Write(galoisHash, binary.BigEndian, aggregator.galoisElements[index])
		digest := sha256.Sum256(encoded)
		_, _ = galoisHash.Write(digest[:])
	}
	policyCommitment, err := PolicyCircuitCommitment(aggregator.roster.ParameterFingerprint, policyID, policyVersion)
	if err != nil {
		return CeremonyKeyDigests{}, err
	}
	var galoisCommitment [32]byte
	copy(galoisCommitment[:], galoisHash.Sum(nil))
	return CeremonyKeyDigests{
		CRSCommitment:            aggregator.crsCommitment,
		PublicKeyCommitment:      domainDigest(ceremonyPublicKeyDomain, publicKeyBytes),
		RelinearizationKeyDigest: domainDigest(ceremonyRelinDomain, relinBytes),
		GaloisKeyCommitment:      galoisCommitment,
		PolicyCircuitCommitment:  policyCommitment,
	}, nil
}

func domainDigest(domain string, value []byte) [32]byte {
	hash := sha256.New()
	_, _ = hash.Write([]byte(domain))
	_, _ = hash.Write(value)
	var digest [32]byte
	copy(digest[:], hash.Sum(nil))
	return digest
}

// ErrCeremonyIncomplete is returned when collective material is requested from
// an unfinished ceremony.
var ErrCeremonyIncomplete = errors.New("ceremony incomplete")
