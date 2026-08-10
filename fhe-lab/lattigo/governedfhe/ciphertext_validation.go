package governedfhe

import (
	"fmt"
	"time"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
	fhe "mordant.dev/fhe-lab/lattigo"
)

var participantCiphertextComponentNames = [...]string{
	"policyBits",
	"currencyBits",
	"amountBits",
	"obligationIdBits",
	"receivableIdBits",
}

type namedParticipantCiphertext struct {
	name       string
	ciphertext *rlwe.Ciphertext
}

func participantCiphertextComponents(pledge *fhe.CipherPledge) []namedParticipantCiphertext {
	if pledge == nil {
		return nil
	}
	return []namedParticipantCiphertext{
		{participantCiphertextComponentNames[0], pledge.PolicyBits},
		{participantCiphertextComponentNames[1], pledge.CurrencyBits},
		{participantCiphertextComponentNames[2], pledge.AmountBits},
		{participantCiphertextComponentNames[3], pledge.ObligationIDBits},
		{participantCiphertextComponentNames[4], pledge.ReceivableIDBits},
	}
}

type validatedFreshParticipants struct {
	artifactA EncryptedParticipantArtifact
	artifactB EncryptedParticipantArtifact
	pledgeA   *fhe.CipherPledge
	pledgeB   *fhe.CipherPledge
	digestA   Digest
	digestB   Digest
}

// loadAndValidateFreshParticipants is the sole fresh governed-input validator
// used by both evaluation and independent recomputation. It deliberately loads
// only parameters and the public encryption key; the large evaluation-key set
// remains behind the durable admission boundary.
func loadAndValidateFreshParticipants(store *objectStore, manifest FHECaseManifest, now time.Time) (validatedFreshParticipants, error) {
	var validated validatedFreshParticipants
	params, publicKey, err := loadPublicEncryptionMaterial(store, manifest.Crypto)
	if err != nil {
		return validated, err
	}
	client, expectedCustody, err := caseExternalClient(params, publicKey, manifest.Binding.ReleaseMode)
	if err != nil || client.CustodyModel() != expectedCustody ||
		Digest(client.KeyIDBytes()) != manifest.Binding.PublicKeyDigest ||
		Digest(client.ParameterFingerprint()) != manifest.Binding.ParameterFingerprint {
		return validated, ErrCiphertextValidation
	}

	validated.artifactA, validated.digestA, err = loadParticipantArtifactMetadata(store, manifest, RoleA, now)
	if err != nil {
		return validated, fmt.Errorf("participant A metadata: %w", err)
	}
	validated.artifactB, validated.digestB, err = loadParticipantArtifactMetadata(store, manifest, RoleB, now)
	if err != nil {
		return validated, fmt.Errorf("participant B metadata: %w", err)
	}
	if validated.artifactA.SubmissionNonce == validated.artifactB.SubmissionNonce || validated.digestA == validated.digestB {
		return validated, ErrBinding
	}

	validated.pledgeA, err = loadParticipantCiphertext(store, manifest, validated.artifactA)
	if err != nil {
		return validated, fmt.Errorf("participant A ciphertext: %w", err)
	}
	validated.pledgeB, err = loadParticipantCiphertext(store, manifest, validated.artifactB)
	if err != nil {
		return validated, fmt.Errorf("participant B ciphertext: %w", err)
	}
	expectedMetadata := bgv.NewPlaintext(params, params.MaxLevel()).MetaData.CopyNew()
	for _, participant := range []struct {
		role   string
		pledge *fhe.CipherPledge
	}{
		{RoleA, validated.pledgeA},
		{RoleB, validated.pledgeB},
	} {
		if participant.pledge.KeyID != client.KeyID() ||
			Digest(participant.pledge.ParameterFingerprint) != manifest.Binding.ParameterFingerprint {
			return validated, fmt.Errorf("%w: %s key binding", ErrCiphertextValidation, participant.role)
		}
		components := participantCiphertextComponents(participant.pledge)
		if len(components) != len(participantCiphertextComponentNames) {
			return validated, fmt.Errorf("%w: %s component count", ErrCiphertextValidation, participant.role)
		}
		for _, component := range components {
			if err := validateFreshGovernedCiphertext(params, expectedMetadata, component.ciphertext); err != nil {
				return validated, fmt.Errorf("%w: %s %s", ErrCiphertextValidation, participant.role, component.name)
			}
		}
	}
	return validated, nil
}

func validateFreshGovernedCiphertext(params bgv.Parameters, expectedMetadata *rlwe.MetaData, ciphertext *rlwe.Ciphertext) error {
	expectedLevel := params.MaxLevel()
	if ciphertext == nil || ciphertext.MetaData == nil || ciphertext.Degree() != 1 || len(ciphertext.Value) != 2 ||
		ciphertext.Level() != expectedLevel || ciphertext.N() != params.N() ||
		!equalExpectedBGVMetadata(ciphertext.MetaData, expectedMetadata) {
		return ErrCiphertextValidation
	}
	moduli := params.Q()
	if len(moduli) != expectedLevel+1 {
		return ErrCiphertextValidation
	}
	for _, polynomial := range ciphertext.Value {
		if polynomial.N() != params.N() || polynomial.Level() != expectedLevel || len(polynomial.Coeffs) != len(moduli) {
			return ErrCiphertextValidation
		}
		for level, coefficients := range polynomial.Coeffs {
			if len(coefficients) != params.N() {
				return ErrCiphertextValidation
			}
			for _, coefficient := range coefficients {
				if coefficient >= moduli[level] {
					return ErrCiphertextValidation
				}
			}
		}
	}
	return nil
}

func equalExpectedBGVMetadata(actual, expected *rlwe.MetaData) bool {
	if actual == nil || expected == nil || actual.Scale.Cmp(expected.Scale) != 0 ||
		actual.Scale.Mod == nil || expected.Scale.Mod == nil || actual.Scale.Mod.Cmp(expected.Scale.Mod) != 0 {
		return false
	}
	return actual.IsBatched == expected.IsBatched &&
		actual.IsBitReversed == expected.IsBitReversed &&
		actual.LogDimensions == expected.LogDimensions &&
		actual.IsNTT == expected.IsNTT &&
		actual.IsMontgomery == expected.IsMontgomery
}

// caseExternalClient builds the public-only encryption boundary a case's key
// calls for. The custody the client advertises follows the release mode, so a
// ceremony-produced coalition key is never labelled as a single-party governed
// case key, and vice versa.
func caseExternalClient(params bgv.Parameters, publicKey *rlwe.PublicKey, releaseMode string) (*fhe.ExternalClient, fhe.CustodyModel, error) {
	if releaseMode == ReleaseModeCoalitionV5 {
		client, err := fhe.NewCeremonyExternalClient(params, publicKey)
		return client, fhe.CustodyDealerlessCeremony, err
	}
	client, err := fhe.NewGovernedExternalClient(params, publicKey)
	return client, fhe.CustodyGovernedEphemeral, err
}
