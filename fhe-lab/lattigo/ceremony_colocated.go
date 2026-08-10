package lattigospike

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"fmt"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

// ColocatedCeremonyMaterial is the output of one t-of-n key ceremony whose
// operators all ran inside a single process.
//
// Cryptographically the protocol is dealerless: no participant ever holds the
// collective secret, each seals only its own Shamir share, and every operator
// erases its transient RLWE secret before sealing. What a single process does
// NOT give is operational independence, because one address space holds every
// share at once. Treat this as the co-located deployment profile, and do not
// describe a run of it as institutionally decentralized.
type ColocatedCeremonyMaterial struct {
	PublicKey          *rlwe.PublicKey
	RelinearizationKey *rlwe.RelinearizationKey
	GaloisKeys         []*rlwe.GaloisKey
	Bundles            [][]byte
	Manifest           ThresholdManifest
}

// RunColocatedCeremony performs the dealerless t-of-n ceremony with every
// operator in this process. It is the single ceremony driver: the product
// keygen and the reference session runner both call it rather than each
// carrying their own copy of the round sequence.
func RunColocatedCeremony(params bgv.Parameters, threshold uint16, count int, policyID [32]byte) (*ColocatedCeremonyMaterial, error) {
	parameterBytes, err := params.MarshalBinary()
	if err != nil {
		return nil, err
	}
	var ceremonyID [32]byte
	if _, err := rand.Read(ceremonyID[:]); err != nil {
		return nil, err
	}

	signingKeys := make([]ed25519.PrivateKey, count)
	identities := make([]CeremonyOperatorIdentity, count)
	for index := range signingKeys {
		_, secret, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		signingKeys[index] = secret
		identities[index] = CeremonyOperatorIdentity{Point: uint64(index + 1)}
		copy(identities[index].SigningPublicKey[:], secret.Public().(ed25519.PublicKey))
	}
	roster := CeremonyRoster{
		ParameterFingerprint: sha256.Sum256(parameterBytes),
		Threshold:            threshold,
		CeremonyID:           ceremonyID,
		KeyEpoch:             1,
		Operators:            identities,
	}

	states := make([]*CeremonyOperatorState, count)
	for index := range states {
		state, err := NewCeremonyOperatorState(params, roster, uint64(index+1), signingKeys[index])
		if err != nil {
			return nil, err
		}
		states[index] = state
	}
	aggregator, err := NewCeremonyAggregator(params, roster)
	if err != nil {
		return nil, err
	}

	for _, source := range states {
		for _, target := range states {
			if err := target.AcceptCRSContribution(source.Point(), source.CRSContribution()); err != nil {
				return nil, err
			}
		}
		if err := aggregator.AcceptCRSContribution(source.Point(), source.CRSContribution()); err != nil {
			return nil, err
		}
	}
	for _, state := range states {
		if err := state.SealCRS(); err != nil {
			return nil, err
		}
	}
	if err := aggregator.SealCRS(); err != nil {
		return nil, err
	}
	for _, source := range states {
		for _, target := range states {
			share, err := source.PrivateShareFor(target.Point())
			if err != nil {
				return nil, err
			}
			if err := target.AcceptPrivateShare(share); err != nil {
				return nil, err
			}
		}
	}
	for _, state := range states {
		if err := state.SealThresholdShare(); err != nil {
			return nil, err
		}
	}
	for _, state := range states {
		wire, err := state.PublicKeyShare()
		if err != nil {
			return nil, err
		}
		if err := aggregator.AcceptPublicKeyShare(state.Point(), wire); err != nil {
			return nil, err
		}
	}
	for _, state := range states {
		wire, err := state.RelinearizationShareRoundOne()
		if err != nil {
			return nil, err
		}
		if err := aggregator.AcceptRelinearizationShareRoundOne(state.Point(), wire); err != nil {
			return nil, err
		}
	}
	combined, err := aggregator.AggregatedRelinearizationRoundOne()
	if err != nil {
		return nil, err
	}
	for _, state := range states {
		wire, err := state.RelinearizationShareRoundTwo(combined)
		if err != nil {
			return nil, err
		}
		if err := aggregator.AcceptRelinearizationShareRoundTwo(state.Point(), wire); err != nil {
			return nil, err
		}
	}
	for {
		element, pending := aggregator.CurrentGaloisElement()
		if !pending {
			break
		}
		for _, state := range states {
			wire, err := state.GaloisShare(element)
			if err != nil {
				return nil, err
			}
			if err := aggregator.AcceptGaloisShare(state.Point(), wire); err != nil {
				return nil, err
			}
		}
	}
	if !aggregator.Complete() {
		return nil, fmt.Errorf("ceremony did not complete")
	}

	publicKey, relinKey, galoisKeys, err := aggregator.CollectiveKeys()
	if err != nil {
		return nil, err
	}
	digests, err := aggregator.KeyDigests(policyID, PolicyVersion)
	if err != nil {
		return nil, err
	}
	keyID, err := CollectiveKeyID(publicKey)
	if err != nil {
		return nil, err
	}

	bundles := make([][]byte, 0, count)
	publics := make([]ThresholdOperatorPublic, 0, count)
	attestations := make([]CeremonyAttestation, 0, count)
	for _, state := range states {
		attestation, err := state.Seal(digests)
		if err != nil {
			return nil, err
		}
		if state.HoldsLocalSecretKey() {
			return nil, fmt.Errorf("operator %d retained its RLWE secret after seal", state.Point())
		}
		attestations = append(attestations, attestation)
		bundle, err := state.SealedOperatorBundle(keyID)
		if err != nil {
			return nil, err
		}
		bundles = append(bundles, bundle)
		imported, err := NewThresholdOperator(bundle)
		if err != nil {
			return nil, err
		}
		publics = append(publics, imported.Public())
	}
	if err := VerifyCeremonyAttestations(roster, digests, attestations); err != nil {
		return nil, fmt.Errorf("manifest attestations: %w", err)
	}

	return &ColocatedCeremonyMaterial{
		PublicKey: publicKey, RelinearizationKey: relinKey, GaloisKeys: galoisKeys, Bundles: bundles,
		Manifest: ThresholdManifest{
			KeyID:                keyID,
			ParameterFingerprint: roster.ParameterFingerprint,
			Threshold:            roster.Threshold,
			Operators:            publics,
		},
	}, nil
}
