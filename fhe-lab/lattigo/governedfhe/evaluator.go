package governedfhe

import (
	"crypto/ed25519"
	"fmt"
	"time"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	fhe "mordant.dev/fhe-lab/lattigo"
)

type EvaluatorConfig struct {
	PublicRoot string
	Provenance Digest
	Now        time.Time
}

type EvaluationReport struct {
	Duration              time.Duration `json:"duration"`
	ResultCiphertextBytes int64         `json:"resultCiphertextBytes"`
	ArtifactBytes         int64         `json:"artifactBytes"`
}

func loadParticipantArtifact(store *objectStore, manifest FHECaseManifest, role string, now time.Time) (EncryptedParticipantArtifact, *fhe.CipherPledge, Digest, error) {
	identity, err := expectedParticipant(manifest.Binding, role)
	if err != nil {
		return EncryptedParticipantArtifact{}, nil, Digest{}, err
	}
	_, expectedCiphertext, expectedManifest, err := participantFiles(role)
	if err != nil {
		return EncryptedParticipantArtifact{}, nil, Digest{}, err
	}
	var artifact EncryptedParticipantArtifact
	artifactBytes, _, err := store.readJSON(expectedManifest, &artifact)
	if err != nil {
		return artifact, nil, Digest{}, err
	}
	bindingDigest, err := manifest.Binding.Digest()
	if err != nil || artifact.SchemaVersion != ParticipantArtifactSchema || artifact.CaseBindingDigest != bindingDigest ||
		artifact.CaseID != manifest.Binding.CaseID || artifact.AssetIdentity != manifest.Binding.AssetIdentity ||
		artifact.ParticipantID != identity.ID || artifact.ParticipantRole != identity.Role || artifact.PublicKeyDigest != manifest.Binding.PublicKeyDigest ||
		artifact.ParameterProfile != ParameterProfile || artifact.ParameterFingerprint != manifest.Binding.ParameterFingerprint ||
		artifact.CircuitDigest != manifest.Binding.CircuitDigest || artifact.InputSchema != InputSchema || artifact.CiphertextObject.Path != expectedCiphertext ||
		!nonzero(artifact.SubmissionNonce) || artifact.ExpiresAtUnix <= now.Unix() || artifact.ExpiresAtUnix > manifest.Binding.ExpiresAtUnix {
		return artifact, nil, Digest{}, ErrBinding
	}
	if verifyCanonical(ed25519.PublicKey(identity.SigningPublicKey), "MordantEncryptedParticipantArtifact/v1", artifact.signingValue(), artifact.Signature) != nil {
		return artifact, nil, Digest{}, ErrBinding
	}
	ciphertextBytes, err := store.read(artifact.CiphertextObject, 192<<20)
	if err != nil {
		return artifact, nil, Digest{}, err
	}
	pledge, err := fhe.UnmarshalCipherPledge(ciphertextBytes)
	if err != nil || Digest(pledge.ParameterFingerprint) != manifest.Binding.ParameterFingerprint || pledge.ReceivableIDBits == nil || pledge.ReceivableCommitment != ([32]byte{}) {
		return artifact, nil, Digest{}, ErrArtifact
	}
	expectedComponents, err := componentRefs(pledge)
	if err != nil || len(expectedComponents) != len(artifact.Components) {
		return artifact, nil, Digest{}, ErrArtifact
	}
	for index := range expectedComponents {
		if expectedComponents[index] != artifact.Components[index] {
			return artifact, nil, Digest{}, ErrArtifact
		}
	}
	return artifact, pledge, DigestBytes(artifactBytes[:len(artifactBytes)-1]), nil
}

func loadEvaluationRuntime(store *objectStore, manifest FHECaseManifest) (*fhe.Runtime, error) {
	params, publicKey, err := loadPublicEncryptionMaterial(store, manifest.Crypto)
	if err != nil {
		return nil, err
	}
	relinearizationBytes, err := store.read(manifest.Crypto.EvaluationKeys.RelinearizationKey, 96<<20)
	if err != nil || manifest.Crypto.EvaluationKeys.RelinearizationKey.Path != relinearizationKeyObject {
		return nil, ErrArtifact
	}
	relinearizationKey := rlwe.NewRelinearizationKey(params)
	if relinearizationKey.UnmarshalBinary(relinearizationBytes) != nil {
		return nil, ErrArtifact
	}
	expectedElements, err := GaloisElements(params)
	if err != nil || len(manifest.Crypto.EvaluationKeys.GaloisKeys) != len(expectedElements) {
		return nil, ErrBinding
	}
	galoisKeys := make([]*rlwe.GaloisKey, len(expectedElements))
	for index, expectedElement := range expectedElements {
		entry := manifest.Crypto.EvaluationKeys.GaloisKeys[index]
		if entry.Index != uint32(index) || entry.Step != rotationSteps[index] || entry.Element != expectedElement || entry.Object.Path != galoisObject(index) {
			return nil, ErrBinding
		}
		encoded, err := store.read(entry.Object, 96<<20)
		if err != nil {
			return nil, err
		}
		key := rlwe.NewGaloisKey(params)
		if key.UnmarshalBinary(encoded) != nil || key.GaloisElement != expectedElement {
			return nil, ErrArtifact
		}
		galoisKeys[index] = key
	}
	runtime, err := fhe.NewGovernedEvaluationRuntime(params, publicKey, relinearizationKey, galoisKeys)
	if err != nil || runtime.HoldsThresholdParties() || Digest(runtime.KeyIDBytes()) != manifest.Binding.PublicKeyDigest ||
		Digest(runtime.ParameterFingerprint()) != manifest.Binding.ParameterFingerprint {
		return nil, ErrBinding
	}
	return runtime, nil
}

func EvaluateFixedConflict(config EvaluatorConfig) (EvaluatedConflictArtifact, EvaluationReport, error) {
	started := time.Now()
	var report EvaluationReport
	if config.Now.IsZero() {
		config.Now = time.Now().UTC()
	}
	if !nonzero(config.Provenance) {
		return EvaluatedConflictArtifact{}, report, ErrBinding
	}
	store, err := openObjectStore(config.PublicRoot, PublicCaseQuota, false)
	if err != nil {
		return EvaluatedConflictArtifact{}, report, err
	}
	manifest, err := loadCaseManifest(store)
	if err != nil || config.Now.Unix() < manifest.Binding.CreatedAtUnix || config.Now.Unix() > manifest.Binding.ExpiresAtUnix {
		return EvaluatedConflictArtifact{}, report, ErrBinding
	}
	artifactA, pledgeA, digestA, err := loadParticipantArtifact(store, manifest, RoleA, config.Now)
	if err != nil {
		return EvaluatedConflictArtifact{}, report, err
	}
	artifactB, pledgeB, digestB, err := loadParticipantArtifact(store, manifest, RoleB, config.Now)
	if err != nil || artifactA.SubmissionNonce == artifactB.SubmissionNonce || digestA == digestB {
		return EvaluatedConflictArtifact{}, report, ErrBinding
	}
	runtime, err := loadEvaluationRuntime(store, manifest)
	if err != nil {
		return EvaluatedConflictArtifact{}, report, err
	}
	if pledgeA.KeyID != runtime.KeyID() || pledgeB.KeyID != runtime.KeyID() {
		return EvaluatedConflictArtifact{}, report, ErrBinding
	}
	outputs, err := runtime.RecomputeCircuitV5(fhe.CircuitInputsV5{
		PolicyBitsA: pledgeA.PolicyBits, PolicyBitsB: pledgeB.PolicyBits,
		CurrencyBitsA: pledgeA.CurrencyBits, CurrencyBitsB: pledgeB.CurrencyBits,
		ReceivableIDsA: pledgeA.ReceivableIDBits, ReceivableIDsB: pledgeB.ReceivableIDBits,
	})
	if err != nil || outputs == nil || outputs.PolicyConflict == nil {
		return EvaluatedConflictArtifact{}, report, fmt.Errorf("fixed circuit: %w", err)
	}
	resultBytes, err := outputs.PolicyConflict.MarshalBinary()
	if err != nil {
		return EvaluatedConflictArtifact{}, report, err
	}
	resultRef, err := store.create(resultCiphertextObject, resultBytes)
	if err != nil {
		return EvaluatedConflictArtifact{}, report, err
	}
	commitment := DigestBytes(append([]byte("MordantFixedConflictCiphertext/v1\x00"), resultBytes...))
	bindingDigest, _ := manifest.Binding.Digest()
	artifact := EvaluatedConflictArtifact{
		SchemaVersion: EvaluatedArtifactSchema, CaseID: manifest.Binding.CaseID, CaseBindingDigest: bindingDigest,
		AssetIdentity: manifest.Binding.AssetIdentity, ParticipantArtifactDigests: []Digest{digestA, digestB},
		PublicKeyDigest: manifest.Binding.PublicKeyDigest, ParameterProfile: ParameterProfile,
		ParameterFingerprint: manifest.Binding.ParameterFingerprint, CircuitID: CircuitID, CircuitVersion: fhe.CircuitV5Version,
		CircuitDigest: FixedCircuitDigest(), ResultCiphertext: resultRef, ResultCiphertextCommitment: commitment,
		OutputSchema: ResultSchema, OutputSlot: ResultSlot, EvaluatorProvenance: config.Provenance, EvaluatedAtUnix: config.Now.Unix(),
	}
	artifactRef, _, err := store.createJSON(evaluatedArtifactObject, artifact)
	if err != nil {
		return EvaluatedConflictArtifact{}, report, err
	}
	report.Duration = time.Since(started)
	report.ResultCiphertextBytes = resultRef.Length
	report.ArtifactBytes = artifactRef.Length
	return artifact, report, nil
}

func validateEvaluatedArtifact(store *objectStore, manifest FHECaseManifest, artifact EvaluatedConflictArtifact) ([]byte, error) {
	bindingDigest, err := manifest.Binding.Digest()
	if err != nil || artifact.SchemaVersion != EvaluatedArtifactSchema || artifact.CaseID != manifest.Binding.CaseID ||
		artifact.CaseBindingDigest != bindingDigest || artifact.AssetIdentity != manifest.Binding.AssetIdentity ||
		assertDigestSlice(artifact.ParticipantArtifactDigests, 2) != nil || artifact.PublicKeyDigest != manifest.Binding.PublicKeyDigest ||
		artifact.ParameterProfile != ParameterProfile || artifact.ParameterFingerprint != manifest.Binding.ParameterFingerprint ||
		artifact.CircuitID != CircuitID || artifact.CircuitVersion != fhe.CircuitV5Version || artifact.CircuitDigest != FixedCircuitDigest() ||
		artifact.ResultCiphertext.Path != resultCiphertextObject || artifact.OutputSchema != ResultSchema || artifact.OutputSlot != ResultSlot ||
		!nonzero(artifact.EvaluatorProvenance, artifact.ResultCiphertextCommitment) || artifact.EvaluatedAtUnix <= 0 {
		return nil, ErrBinding
	}
	for index, role := range []string{RoleA, RoleB} {
		_, _, manifestName, _ := participantFiles(role)
		bytes, _, err := store.readNamed(manifestName, maxManifestBytes)
		if err != nil || DigestBytes(bytes[:len(bytes)-1]) != artifact.ParticipantArtifactDigests[index] {
			return nil, ErrBinding
		}
	}
	resultBytes, err := store.read(artifact.ResultCiphertext, 128<<20)
	if err != nil || DigestBytes(append([]byte("MordantFixedConflictCiphertext/v1\x00"), resultBytes...)) != artifact.ResultCiphertextCommitment {
		return nil, ErrArtifact
	}
	return resultBytes, nil
}

func LoadEvaluatedConflictArtifact(publicRoot string) (EvaluatedConflictArtifact, error) {
	store, err := openObjectStore(publicRoot, PublicCaseQuota, false)
	if err != nil {
		return EvaluatedConflictArtifact{}, err
	}
	manifest, err := loadCaseManifest(store)
	if err != nil {
		return EvaluatedConflictArtifact{}, err
	}
	artifact, _, _, err := loadEvaluatedArtifact(store, manifest)
	return artifact, err
}
