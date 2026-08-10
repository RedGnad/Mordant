package governedfhe

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"time"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
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

func loadParticipantArtifactMetadata(store *objectStore, manifest FHECaseManifest, role string, now time.Time) (EncryptedParticipantArtifact, Digest, error) {
	identity, err := expectedParticipant(manifest.Binding, role)
	if err != nil {
		return EncryptedParticipantArtifact{}, Digest{}, err
	}
	_, expectedCiphertext, expectedManifest, err := participantFiles(role)
	if err != nil {
		return EncryptedParticipantArtifact{}, Digest{}, err
	}
	var artifact EncryptedParticipantArtifact
	artifactBytes, _, err := store.readJSON(expectedManifest, &artifact)
	if err != nil {
		return artifact, Digest{}, err
	}
	bindingDigest, err := manifest.Binding.Digest()
	if err != nil || artifact.SchemaVersion != ParticipantArtifactSchema || artifact.CaseBindingDigest != bindingDigest ||
		artifact.CaseID != manifest.Binding.CaseID || artifact.AssetIdentity != manifest.Binding.AssetIdentity ||
		artifact.ParticipantID != identity.ID || artifact.ParticipantRole != identity.Role || artifact.PublicKeyDigest != manifest.Binding.PublicKeyDigest ||
		artifact.ParameterProfile != ParameterProfile || artifact.ParameterFingerprint != manifest.Binding.ParameterFingerprint ||
		artifact.CircuitDigest != manifest.Binding.CircuitDigest || artifact.InputSchema != InputSchema || artifact.CiphertextObject.Path != expectedCiphertext ||
		artifact.CiphertextObject.validate(expectedCiphertext, 192<<20) != nil || len(artifact.Components) != 5 ||
		!nonzero(artifact.SubmissionNonce) || artifact.ExpiresAtUnix <= now.Unix() || artifact.ExpiresAtUnix > manifest.Binding.ExpiresAtUnix {
		return artifact, Digest{}, ErrBinding
	}
	if verifyCanonical(ed25519.PublicKey(identity.SigningPublicKey), "MordantEncryptedParticipantArtifact/v1", artifact.signingValue(), artifact.Signature) != nil {
		return artifact, Digest{}, ErrBinding
	}
	for index, component := range artifact.Components {
		if component.Name != participantCiphertextComponentNames[index] || !nonzero(component.Digest) || component.Length <= 0 || component.Length > 64<<20 {
			return artifact, Digest{}, ErrArtifact
		}
	}
	return artifact, DigestBytes(artifactBytes[:len(artifactBytes)-1]), nil
}

func loadParticipantCiphertext(store *objectStore, manifest FHECaseManifest, artifact EncryptedParticipantArtifact) (*fhe.CipherPledge, error) {
	ciphertextBytes, err := store.read(artifact.CiphertextObject, 192<<20)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", artifact.CiphertextObject.Path, err)
	}
	pledge, err := fhe.UnmarshalCipherPledge(ciphertextBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: decode %s", ErrCiphertextValidation, artifact.CiphertextObject.Path)
	}
	canonicalBytes, err := pledge.MarshalBinary()
	if err != nil || !bytes.Equal(canonicalBytes, ciphertextBytes) {
		return nil, fmt.Errorf("%w: noncanonical %s", ErrCiphertextValidation, artifact.CiphertextObject.Path)
	}
	if Digest(pledge.ParameterFingerprint) != manifest.Binding.ParameterFingerprint || pledge.ReceivableIDBits == nil || pledge.ReceivableCommitment != ([32]byte{}) {
		return nil, ErrCiphertextValidation
	}
	expectedComponents, err := componentRefs(pledge)
	if err != nil || len(expectedComponents) != len(artifact.Components) {
		return nil, ErrArtifact
	}
	for index := range expectedComponents {
		if expectedComponents[index] != artifact.Components[index] {
			return nil, ErrCiphertextValidation
		}
	}
	return pledge, nil
}

func loadParticipantArtifact(store *objectStore, manifest FHECaseManifest, role string, now time.Time) (EncryptedParticipantArtifact, *fhe.CipherPledge, Digest, error) {
	artifact, digest, err := loadParticipantArtifactMetadata(store, manifest, role, now)
	if err != nil {
		return artifact, nil, Digest{}, err
	}
	pledge, err := loadParticipantCiphertext(store, manifest, artifact)
	return artifact, pledge, digest, err
}

func loadEvaluationKeyMaterial(store *objectStore, manifest FHECaseManifest, params bgv.Parameters) (*rlwe.RelinearizationKey, []*rlwe.GaloisKey, error) {
	relinearizationBytes, err := store.read(manifest.Crypto.EvaluationKeys.RelinearizationKey, 96<<20)
	if err != nil || manifest.Crypto.EvaluationKeys.RelinearizationKey.Path != relinearizationKeyObject {
		return nil, nil, ErrArtifact
	}
	relinearizationKey := rlwe.NewRelinearizationKey(params)
	if relinearizationKey.UnmarshalBinary(relinearizationBytes) != nil {
		return nil, nil, ErrArtifact
	}
	expectedElements, err := GaloisElements(params)
	if err != nil || len(manifest.Crypto.EvaluationKeys.GaloisKeys) != len(expectedElements) {
		return nil, nil, ErrBinding
	}
	galoisKeys := make([]*rlwe.GaloisKey, len(expectedElements))
	for index, expectedElement := range expectedElements {
		entry := manifest.Crypto.EvaluationKeys.GaloisKeys[index]
		if entry.Index != uint32(index) || entry.Step != rotationSteps[index] || entry.Element != expectedElement || entry.Object.Path != galoisObject(index) {
			return nil, nil, ErrBinding
		}
		encoded, err := store.read(entry.Object, 96<<20)
		if err != nil {
			return nil, nil, err
		}
		key := rlwe.NewGaloisKey(params)
		if key.UnmarshalBinary(encoded) != nil || key.GaloisElement != expectedElement {
			return nil, nil, ErrArtifact
		}
		galoisKeys[index] = key
	}
	return relinearizationKey, galoisKeys, nil
}

// loadEvaluationRuntime builds the case's evaluator. The constructor is chosen
// by release mode, because the key id advertises how the key was produced: a
// governed case key is generated for that one case, a coalition case key comes
// out of the ceremony and no single party ever held it.
func loadEvaluationRuntime(store *objectStore, manifest FHECaseManifest) (*fhe.Runtime, error) {
	params, publicKey, err := loadPublicEncryptionMaterial(store, manifest.Crypto)
	if err != nil {
		return nil, err
	}
	relinearizationKey, galoisKeys, err := loadEvaluationKeyMaterial(store, manifest, params)
	if err != nil {
		return nil, err
	}
	var runtime *fhe.Runtime
	switch manifest.Binding.ReleaseMode {
	case ReleaseModeCoalitionV5:
		runtime, err = fhe.NewCoalitionEvaluationRuntime(params, publicKey, relinearizationKey, galoisKeys)
	default:
		runtime, err = fhe.NewGovernedEvaluationRuntime(params, publicKey, relinearizationKey, galoisKeys)
	}
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
	defer store.close()
	manifest, err := loadCaseManifest(store)
	if err != nil || config.Now.Unix() < manifest.Binding.CreatedAtUnix || config.Now.Unix() > manifest.Binding.ExpiresAtUnix {
		return EvaluatedConflictArtifact{}, report, ErrBinding
	}
	participants, err := loadAndValidateFreshParticipants(store, manifest, config.Now)
	if err != nil {
		return EvaluatedConflictArtifact{}, report, err
	}
	if store.exists(evaluationAdmissionObject) || store.exists(evaluationCompletedObject) || store.exists(resultCiphertextObject) || store.exists(evaluatedArtifactObject) {
		return EvaluatedConflictArtifact{}, report, ErrEvaluationAdmission
	}
	releaseResource, err := admitN15(manifest.Binding.CaseID, "evaluation")
	if err != nil {
		return EvaluatedConflictArtifact{}, report, err
	}
	defer releaseResource()
	if store.exists(evaluationAdmissionObject) || store.exists(evaluationCompletedObject) || store.exists(resultCiphertextObject) || store.exists(evaluatedArtifactObject) {
		return EvaluatedConflictArtifact{}, report, ErrEvaluationAdmission
	}
	bindingDigest, _ := manifest.Binding.Digest()
	admission := evaluationAdmission{
		SchemaVersion: EvaluationAdmissionSchema, CaseID: manifest.Binding.CaseID, CaseBindingDigest: bindingDigest,
		ParticipantArtifactDigests: []Digest{participants.digestA, participants.digestB}, EvaluatorProvenance: config.Provenance, AdmittedAtUnix: config.Now.Unix(),
	}
	if _, _, err := store.createJSON(evaluationAdmissionObject, admission); err != nil {
		return EvaluatedConflictArtifact{}, report, fmt.Errorf("%w: %v", ErrEvaluationAdmission, err)
	}
	runtime, err := loadEvaluationRuntime(store, manifest)
	if err != nil {
		return EvaluatedConflictArtifact{}, report, fmt.Errorf("evaluation material: %w", err)
	}
	if participants.pledgeA.KeyID != runtime.KeyID() || participants.pledgeB.KeyID != runtime.KeyID() {
		return EvaluatedConflictArtifact{}, report, ErrBinding
	}
	evaluationExecutionCount.Add(1)
	outputs, err := runtime.RecomputeCircuitV5(fhe.CircuitInputsV5{
		PolicyBitsA: participants.pledgeA.PolicyBits, PolicyBitsB: participants.pledgeB.PolicyBits,
		CurrencyBitsA: participants.pledgeA.CurrencyBits, CurrencyBitsB: participants.pledgeB.CurrencyBits,
		ReceivableIDsA: participants.pledgeA.ReceivableIDBits, ReceivableIDsB: participants.pledgeB.ReceivableIDBits,
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
	artifact := EvaluatedConflictArtifact{
		SchemaVersion: EvaluatedArtifactSchema, CaseID: manifest.Binding.CaseID, CaseBindingDigest: bindingDigest,
		AssetIdentity: manifest.Binding.AssetIdentity, ParticipantArtifactDigests: []Digest{participants.digestA, participants.digestB},
		PublicKeyDigest: manifest.Binding.PublicKeyDigest, ParameterProfile: ParameterProfile,
		ParameterFingerprint: manifest.Binding.ParameterFingerprint, CircuitID: CircuitID, CircuitVersion: fhe.CircuitV5Version,
		CircuitDigest: FixedCircuitDigest(), ResultCiphertext: resultRef, ResultCiphertextCommitment: commitment,
		OutputSchema: ResultSchema, OutputSlot: ResultSlot, EvaluatorProvenance: config.Provenance, EvaluatedAtUnix: config.Now.Unix(),
	}
	artifactRef, _, err := store.createJSON(evaluatedArtifactObject, artifact)
	if err != nil {
		return EvaluatedConflictArtifact{}, report, err
	}
	artifactDigest, _ := artifact.Digest()
	completed := evaluationCompleted{
		SchemaVersion: EvaluationCompletedSchema, CaseID: manifest.Binding.CaseID, CaseBindingDigest: bindingDigest,
		EvaluatedArtifactDigest: artifactDigest, ResultCiphertextDigest: resultRef.Digest,
		ResultCiphertextCommitment: commitment, CompletedAtUnix: config.Now.Unix(),
	}
	if _, _, err := store.createJSON(evaluationCompletedObject, completed); err != nil {
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
	var admission evaluationAdmission
	if _, _, err := store.readJSON(evaluationAdmissionObject, &admission); err != nil ||
		admission.SchemaVersion != EvaluationAdmissionSchema || admission.CaseID != manifest.Binding.CaseID ||
		admission.CaseBindingDigest != bindingDigest || len(admission.ParticipantArtifactDigests) != 2 ||
		admission.ParticipantArtifactDigests[0] != artifact.ParticipantArtifactDigests[0] ||
		admission.ParticipantArtifactDigests[1] != artifact.ParticipantArtifactDigests[1] ||
		admission.EvaluatorProvenance != artifact.EvaluatorProvenance || admission.AdmittedAtUnix <= 0 {
		return nil, ErrArtifact
	}
	artifactDigest, _ := artifact.Digest()
	var completed evaluationCompleted
	if _, _, err := store.readJSON(evaluationCompletedObject, &completed); err != nil ||
		completed.SchemaVersion != EvaluationCompletedSchema || completed.CaseID != manifest.Binding.CaseID ||
		completed.CaseBindingDigest != bindingDigest || completed.EvaluatedArtifactDigest != artifactDigest ||
		completed.ResultCiphertextDigest != artifact.ResultCiphertext.Digest ||
		completed.ResultCiphertextCommitment != artifact.ResultCiphertextCommitment || completed.CompletedAtUnix <= 0 {
		return nil, ErrArtifact
	}
	return resultBytes, nil
}

func LoadEvaluatedConflictArtifact(publicRoot string) (EvaluatedConflictArtifact, error) {
	store, err := openObjectStore(publicRoot, PublicCaseQuota, false)
	if err != nil {
		return EvaluatedConflictArtifact{}, err
	}
	defer store.close()
	manifest, err := loadCaseManifest(store)
	if err != nil {
		return EvaluatedConflictArtifact{}, err
	}
	artifact, _, _, err := loadEvaluatedArtifact(store, manifest)
	return artifact, err
}
