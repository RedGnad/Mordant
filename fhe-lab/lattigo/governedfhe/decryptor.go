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

type GovernedDecryptorConfig struct {
	PublicRoot  string
	PrivateRoot string
	Provenance  Digest
	Now         time.Time
}

type GovernedDecryptor struct {
	publicStore  *objectStore
	privateStore *objectStore
	provenance   Digest
	now          time.Time
}

type ReleaseReport struct {
	Duration    time.Duration       `json:"duration"`
	ResultBytes int64               `json:"resultBytes"`
	ExactRetry  bool                `json:"exactRetry"`
	Pins        TrustedRecoursePins `json:"trustedRecoursePins"`
}

type releaseAdmission struct {
	SchemaVersion           string `json:"schemaVersion"`
	CaseID                  Digest `json:"caseId"`
	CaseBindingDigest       Digest `json:"caseBindingDigest"`
	EvaluatedArtifactDigest Digest `json:"evaluatedArtifactDigest"`
	ReleaseOrdinal          uint32 `json:"releaseOrdinal"`
	ReleaseMode             string `json:"releaseMode"`
	AdmittedAtUnix          int64  `json:"admittedAtUnix"`
}

type releaseConsumed struct {
	SchemaVersion           string `json:"schemaVersion"`
	CaseID                  Digest `json:"caseId"`
	EvaluatedArtifactDigest Digest `json:"evaluatedArtifactDigest"`
	ResultDigest            Digest `json:"resultDigest"`
	ConsumedAtUnix          int64  `json:"consumedAtUnix"`
}

func NewGovernedDecryptor(config GovernedDecryptorConfig) (*GovernedDecryptor, error) {
	if config.Now.IsZero() {
		config.Now = time.Now().UTC()
	}
	if !nonzero(config.Provenance) || !rootsDisjoint(config.PublicRoot, config.PrivateRoot) {
		return nil, ErrBinding
	}
	publicStore, err := openObjectStore(config.PublicRoot, PublicCaseQuota, false)
	if err != nil {
		return nil, err
	}
	privateStore, err := openObjectStore(config.PrivateRoot, PrivateCaseQuota, true)
	if err != nil {
		_ = publicStore.close()
		return nil, err
	}
	return &GovernedDecryptor{publicStore: publicStore, privateStore: privateStore, provenance: config.Provenance, now: config.Now}, nil
}

func (d *GovernedDecryptor) Close() error {
	if d == nil {
		return nil
	}
	publicErr := d.publicStore.close()
	privateErr := d.privateStore.close()
	if publicErr != nil || privateErr != nil {
		return ErrStore
	}
	return nil
}

func loadReleaseAuthority(store *objectStore, manifest FHECaseManifest) (ReleaseAuthorityManifest, error) {
	var authority ReleaseAuthorityManifest
	if _, _, err := store.readJSON(releaseAuthorityObject, &authority); err != nil {
		return authority, err
	}
	bindingDigest, _ := manifest.Binding.Digest()
	if authority.SchemaVersion != ReleaseAuthoritySchema || authority.CaseID != manifest.Binding.CaseID || authority.CaseBindingDigest != bindingDigest ||
		authority.ReleaseMode != manifest.Binding.ReleaseMode || authority.AuthorityID != manifest.Binding.ReleaseAuthorityID ||
		!bytes.Equal(authority.SigningPublicKey, manifest.Binding.ReleaseAuthorityPublicKey) ||
		!knownReleaseMode(authority.ReleaseMode) || !nonzero(authority.AuthorityID, authority.SourceProvenance) ||
		len(authority.SigningPublicKey) != ed25519.PublicKeySize ||
		verifyCanonical(ed25519.PublicKey(authority.SigningPublicKey), "MordantReleaseAuthority/v1", authority.signingValue(), authority.Signature) != nil {
		return authority, ErrBinding
	}
	expectedID := releaseAuthorityIdentity(authority.ReleaseMode, ed25519.PublicKey(authority.SigningPublicKey))
	if expectedID != authority.AuthorityID {
		return authority, ErrBinding
	}
	return authority, nil
}

func loadEvaluatedArtifact(store *objectStore, manifest FHECaseManifest) (EvaluatedConflictArtifact, []byte, Digest, error) {
	var artifact EvaluatedConflictArtifact
	artifactBytes, _, err := store.readJSON(evaluatedArtifactObject, &artifact)
	if err != nil {
		return artifact, nil, Digest{}, err
	}
	resultBytes, err := validateEvaluatedArtifact(store, manifest, artifact)
	if err != nil {
		return artifact, nil, Digest{}, err
	}
	return artifact, resultBytes, DigestBytes(artifactBytes[:len(artifactBytes)-1]), nil
}

func verifyGovernedResult(result GovernedConflictResult, manifest FHECaseManifest, artifact EvaluatedConflictArtifact, authority ReleaseAuthorityManifest) error {
	bindingDigest, _ := manifest.Binding.Digest()
	artifactDigest, _ := artifact.Digest()
	if result.SchemaVersion != GovernedResultSchema || result.CaseID != manifest.Binding.CaseID || result.CaseBindingDigest != bindingDigest ||
		result.AssetIdentity != manifest.Binding.AssetIdentity || result.ServiceID != ServiceID || result.ServiceVersion != ServiceVersion ||
		result.PolicyID != manifest.Binding.PolicyID || result.PolicyVersion != fhe.PolicyVersion || result.CircuitID != CircuitID ||
		result.CircuitVersion != fhe.CircuitV5Version || result.CircuitDigest != FixedCircuitDigest() || result.ParameterProfile != ParameterProfile ||
		result.ParameterFingerprint != manifest.Binding.ParameterFingerprint || len(result.ParticipantArtifactDigests) != 2 ||
		!bytes.Equal(result.ParticipantArtifactDigests[0][:], artifact.ParticipantArtifactDigests[0][:]) ||
		!bytes.Equal(result.ParticipantArtifactDigests[1][:], artifact.ParticipantArtifactDigests[1][:]) ||
		result.EvaluatedArtifactDigest != artifactDigest ||
		result.ResultCiphertextDigest != artifact.ResultCiphertext.Digest || result.ResultCiphertextCommitment != artifact.ResultCiphertextCommitment ||
		result.ReleaseOrdinal != ReleaseOrdinal || result.ReleaseMode != authority.ReleaseMode || !knownReleaseMode(result.ReleaseMode) || result.ReleaseAuthorityID != authority.AuthorityID ||
		!bytes.Equal(result.ReleaseAuthorityPublicKey, authority.SigningPublicKey) || result.ReleasedAtUnix <= 0 || !nonzero(result.SourceProvenance) ||
		verifyCanonical(ed25519.PublicKey(authority.SigningPublicKey), "MordantGovernedConflictResult/v1", result.signingValue(), result.Signature) != nil {
		return ErrBinding
	}
	return nil
}

func recoursePinsForResult(result GovernedConflictResult) TrustedRecoursePins {
	var digestA, digestB Digest
	if len(result.ParticipantArtifactDigests) == 2 {
		digestA, digestB = result.ParticipantArtifactDigests[0], result.ParticipantArtifactDigests[1]
	}
	return TrustedRecoursePins{
		ParticipantArtifactDigestA: digestA, ParticipantArtifactDigestB: digestB,
		EvaluatedArtifactDigest:          result.EvaluatedArtifactDigest,
		RecomputedResultCiphertextDigest: result.ResultCiphertextDigest,
		ResultCiphertextCommitment:       result.ResultCiphertextCommitment,
		DecryptorProvenance:              result.SourceProvenance, ReleaseMode: result.ReleaseMode,
		ReleaseAuthorityID: result.ReleaseAuthorityID,
	}
}

func validateRecomputeAdmission(admission recomputeAdmission, manifest FHECaseManifest, artifact EvaluatedConflictArtifact, artifactDigest Digest) error {
	bindingDigest, _ := manifest.Binding.Digest()
	if admission.SchemaVersion != RecomputeAdmissionSchema || admission.CaseID != manifest.Binding.CaseID ||
		admission.CaseBindingDigest != bindingDigest || admission.EvaluatedArtifactDigest != artifactDigest ||
		len(admission.ParticipantArtifactDigests) != 2 ||
		admission.ParticipantArtifactDigests[0] != artifact.ParticipantArtifactDigests[0] ||
		admission.ParticipantArtifactDigests[1] != artifact.ParticipantArtifactDigests[1] || admission.AdmittedAtUnix <= 0 {
		return ErrReleaseAmbiguous
	}
	return nil
}

func (d *GovernedDecryptor) loadVerifiedRecomputation(manifest FHECaseManifest, artifact EvaluatedConflictArtifact, artifactDigest Digest) ([]byte, recomputeVerified, error) {
	var admission recomputeAdmission
	if _, _, err := d.privateStore.readJSON(recomputeAdmissionObject, &admission); err != nil ||
		validateRecomputeAdmission(admission, manifest, artifact, artifactDigest) != nil {
		return nil, recomputeVerified{}, ErrReleaseAmbiguous
	}
	var verified recomputeVerified
	if _, _, err := d.privateStore.readJSON(recomputeVerifiedObject, &verified); err != nil {
		return nil, verified, ErrReleaseAmbiguous
	}
	bindingDigest, _ := manifest.Binding.Digest()
	if verified.SchemaVersion != RecomputeVerifiedSchema || verified.CaseID != manifest.Binding.CaseID ||
		verified.CaseBindingDigest != bindingDigest || verified.EvaluatedArtifactDigest != artifactDigest ||
		verified.RecomputedResultCiphertext.validate(recomputedResultObject, 128<<20) != nil ||
		!nonzero(verified.ResultCiphertextCommitment) || verified.VerifiedAtUnix <= 0 {
		return nil, verified, ErrReleaseAmbiguous
	}
	recomputedBytes, err := d.privateStore.read(verified.RecomputedResultCiphertext, 128<<20)
	if err != nil || DigestBytes(append([]byte("MordantFixedConflictCiphertext/v1\x00"), recomputedBytes...)) != verified.ResultCiphertextCommitment {
		return nil, verified, ErrReleaseAmbiguous
	}
	return recomputedBytes, verified, nil
}

func (d *GovernedDecryptor) prepareVerifiedRecomputation(manifest FHECaseManifest, artifact EvaluatedConflictArtifact, evaluatorResultBytes []byte, artifactDigest Digest) ([]byte, recomputeVerified, error) {
	participants, err := loadAndValidateFreshParticipants(d.publicStore, manifest, d.now)
	if err != nil {
		return nil, recomputeVerified{}, err
	}
	if participants.digestA != artifact.ParticipantArtifactDigests[0] || participants.digestB != artifact.ParticipantArtifactDigests[1] {
		return nil, recomputeVerified{}, ErrBinding
	}
	if d.privateStore.exists(recomputeMismatchObject) {
		return nil, recomputeVerified{}, ErrEvaluatorMismatch
	}
	if d.privateStore.exists(recomputeVerifiedObject) {
		return d.loadVerifiedRecomputation(manifest, artifact, artifactDigest)
	}
	if d.privateStore.exists(recomputeAdmissionObject) {
		return nil, recomputeVerified{}, ErrRecomputeAdmission
	}
	releaseResource, err := admitN15(manifest.Binding.CaseID, "recomputation")
	if err != nil {
		return nil, recomputeVerified{}, err
	}
	defer releaseResource()
	if d.privateStore.exists(recomputeMismatchObject) || d.privateStore.exists(recomputeVerifiedObject) || d.privateStore.exists(recomputeAdmissionObject) {
		return nil, recomputeVerified{}, ErrRecomputeAdmission
	}
	bindingDigest, _ := manifest.Binding.Digest()
	admission := recomputeAdmission{
		SchemaVersion: RecomputeAdmissionSchema, CaseID: manifest.Binding.CaseID, CaseBindingDigest: bindingDigest,
		ParticipantArtifactDigests: []Digest{participants.digestA, participants.digestB}, EvaluatedArtifactDigest: artifactDigest, AdmittedAtUnix: d.now.Unix(),
	}
	if _, _, err := d.privateStore.createJSON(recomputeAdmissionObject, admission); err != nil {
		return nil, recomputeVerified{}, fmt.Errorf("%w: %v", ErrRecomputeAdmission, err)
	}
	runtime, err := loadEvaluationRuntime(d.publicStore, manifest)
	if err != nil || participants.pledgeA.KeyID != runtime.KeyID() || participants.pledgeB.KeyID != runtime.KeyID() {
		return nil, recomputeVerified{}, ErrBinding
	}
	recomputationExecutionCount.Add(1)
	outputs, err := runtime.RecomputeCircuitV5(fhe.CircuitInputsV5{
		PolicyBitsA: participants.pledgeA.PolicyBits, PolicyBitsB: participants.pledgeB.PolicyBits,
		CurrencyBitsA: participants.pledgeA.CurrencyBits, CurrencyBitsB: participants.pledgeB.CurrencyBits,
		ReceivableIDsA: participants.pledgeA.ReceivableIDBits, ReceivableIDsB: participants.pledgeB.ReceivableIDBits,
	})
	if err != nil || outputs == nil || outputs.PolicyConflict == nil {
		return nil, recomputeVerified{}, ErrReleaseAmbiguous
	}
	recomputedBytes, err := outputs.PolicyConflict.MarshalBinary()
	if err != nil {
		return nil, recomputeVerified{}, ErrReleaseAmbiguous
	}
	recomputedDigest := DigestBytes(recomputedBytes)
	if !bytes.Equal(recomputedBytes, evaluatorResultBytes) {
		mismatch := recomputeMismatch{
			SchemaVersion: RecomputeMismatchSchema, CaseID: manifest.Binding.CaseID, CaseBindingDigest: bindingDigest,
			EvaluatedArtifactDigest: artifactDigest, EvaluatorResultCiphertextDigest: artifact.ResultCiphertext.Digest,
			RecomputedResultCiphertextDigest: recomputedDigest, ErrorCode: "EVALUATOR_RESULT_MISMATCH", DetectedAtUnix: d.now.Unix(),
		}
		if _, _, writeErr := d.privateStore.createJSON(recomputeMismatchObject, mismatch); writeErr != nil {
			return nil, recomputeVerified{}, ErrReleaseAmbiguous
		}
		return nil, recomputeVerified{}, ErrEvaluatorMismatch
	}
	recomputedRef, err := d.privateStore.create(recomputedResultObject, recomputedBytes)
	if err != nil {
		return nil, recomputeVerified{}, ErrReleaseAmbiguous
	}
	commitment := DigestBytes(append([]byte("MordantFixedConflictCiphertext/v1\x00"), recomputedBytes...))
	verified := recomputeVerified{
		SchemaVersion: RecomputeVerifiedSchema, CaseID: manifest.Binding.CaseID, CaseBindingDigest: bindingDigest,
		EvaluatedArtifactDigest: artifactDigest, RecomputedResultCiphertext: recomputedRef,
		ResultCiphertextCommitment: commitment, VerifiedAtUnix: d.now.Unix(),
	}
	if _, _, err := d.privateStore.createJSON(recomputeVerifiedObject, verified); err != nil {
		return nil, recomputeVerified{}, ErrReleaseAmbiguous
	}
	return recomputedBytes, verified, nil
}

func (d *GovernedDecryptor) exactRetry(manifest FHECaseManifest, artifact EvaluatedConflictArtifact, artifactDigest Digest, authority ReleaseAuthorityManifest) (GovernedConflictResult, []byte, bool, error) {
	if !d.privateStore.exists(retainedResultObject) {
		return GovernedConflictResult{}, nil, false, nil
	}
	var result GovernedConflictResult
	retainedBytes, _, err := d.privateStore.readJSON(retainedResultObject, &result)
	recomputedBytes, verified, recomputeErr := d.loadVerifiedRecomputation(manifest, artifact, artifactDigest)
	if err != nil || recomputeErr != nil || verifyGovernedResult(result, manifest, artifact, authority) != nil ||
		result.ResultCiphertextDigest != verified.RecomputedResultCiphertext.Digest ||
		result.ResultCiphertextCommitment != verified.ResultCiphertextCommitment || len(recomputedBytes) == 0 {
		return result, nil, true, ErrReleaseAmbiguous
	}
	var admission releaseAdmission
	if _, _, err := d.privateStore.readJSON(releaseAdmissionObject, &admission); err != nil ||
		admission.SchemaVersion != ReleaseAdmissionSchema || admission.CaseID != manifest.Binding.CaseID ||
		admission.CaseBindingDigest != artifact.CaseBindingDigest || admission.EvaluatedArtifactDigest != artifactDigest ||
		admission.ReleaseOrdinal != ReleaseOrdinal || admission.ReleaseMode != ReleaseModeGovernedDecryptor || admission.AdmittedAtUnix <= 0 {
		return result, nil, true, ErrReleaseConsumed
	}
	if d.publicStore.exists(publicResultObject) {
		publicBytes, _, err := d.publicStore.readNamed(publicResultObject, maxManifestBytes)
		if err != nil || !bytes.Equal(publicBytes, retainedBytes) {
			return result, nil, true, ErrReleaseAmbiguous
		}
	} else if _, err := d.publicStore.create(publicResultObject, retainedBytes); err != nil {
		return result, nil, true, err
	}
	resultDigest, _ := result.Digest()
	if !d.privateStore.exists(releaseConsumedObject) {
		consumed := releaseConsumed{SchemaVersion: ReleaseConsumedSchema, CaseID: result.CaseID, EvaluatedArtifactDigest: artifactDigest, ResultDigest: resultDigest, ConsumedAtUnix: d.now.Unix()}
		if _, _, err := d.privateStore.createJSON(releaseConsumedObject, consumed); err != nil {
			return result, nil, true, err
		}
	} else {
		var consumed releaseConsumed
		if _, _, err := d.privateStore.readJSON(releaseConsumedObject, &consumed); err != nil ||
			consumed.SchemaVersion != ReleaseConsumedSchema || consumed.CaseID != result.CaseID ||
			consumed.EvaluatedArtifactDigest != artifactDigest || consumed.ResultDigest != resultDigest || consumed.ConsumedAtUnix <= 0 {
			return result, nil, true, ErrReleaseAmbiguous
		}
	}
	return result, retainedBytes, true, nil
}

func (d *GovernedDecryptor) ReleaseFixedConflict(expected EvaluatedConflictArtifact) (GovernedConflictResult, []byte, error) {
	result, encoded, _, err := d.release(expected)
	return result, encoded, err
}

func (d *GovernedDecryptor) release(expected EvaluatedConflictArtifact) (GovernedConflictResult, []byte, ReleaseReport, error) {
	started := time.Now()
	var report ReleaseReport
	if d == nil {
		return GovernedConflictResult{}, nil, report, ErrBinding
	}
	// All public bindings and the fixed result location are verified before the
	// secret key is read from the private capability.
	manifest, err := loadCaseManifest(d.publicStore)
	if err != nil || d.now.Unix() < manifest.Binding.CreatedAtUnix || d.now.Unix() > manifest.Binding.ExpiresAtUnix {
		return GovernedConflictResult{}, nil, report, ErrBinding
	}
	artifact, resultBytes, artifactDigest, err := loadEvaluatedArtifact(d.publicStore, manifest)
	if err != nil {
		return GovernedConflictResult{}, nil, report, err
	}
	expectedDigest, _ := expected.Digest()
	storedDigest, _ := artifact.Digest()
	if expectedDigest != storedDigest {
		return GovernedConflictResult{}, nil, report, ErrBinding
	}
	authority, err := loadReleaseAuthority(d.publicStore, manifest)
	if err != nil {
		return GovernedConflictResult{}, nil, report, err
	}
	if authority.ReleaseMode != ReleaseModeGovernedDecryptor {
		return GovernedConflictResult{}, nil, report, ErrBinding
	}
	if result, retained, found, err := d.exactRetry(manifest, artifact, artifactDigest, authority); found {
		report.Duration, report.ResultBytes, report.ExactRetry, report.Pins = time.Since(started), int64(len(retained)), true, recoursePinsForResult(result)
		return result, retained, report, err
	}
	if d.privateStore.exists(releaseAdmissionObject) || d.privateStore.exists(releaseConsumedObject) {
		return GovernedConflictResult{}, nil, report, ErrReleaseAmbiguous
	}
	recomputedBytes, verified, err := d.prepareVerifiedRecomputation(manifest, artifact, resultBytes, artifactDigest)
	if err != nil {
		return GovernedConflictResult{}, nil, report, err
	}
	admission := releaseAdmission{
		SchemaVersion: ReleaseAdmissionSchema, CaseID: manifest.Binding.CaseID, CaseBindingDigest: artifact.CaseBindingDigest,
		EvaluatedArtifactDigest: artifactDigest, ReleaseOrdinal: ReleaseOrdinal, ReleaseMode: ReleaseModeGovernedDecryptor, AdmittedAtUnix: d.now.Unix(),
	}
	if _, _, err := d.privateStore.createJSON(releaseAdmissionObject, admission); err != nil {
		return GovernedConflictResult{}, nil, report, err
	}

	var privateCase PrivateCaseManifest
	if _, _, err := d.privateStore.readJSON(privateCaseObject, &privateCase); err != nil || privateCase.SchemaVersion != PrivateCaseSchema ||
		privateCase.CaseID != manifest.Binding.CaseID || privateCase.CaseBindingDigest != artifact.CaseBindingDigest || privateCase.ReleaseAuthorityID != authority.AuthorityID ||
		privateCase.SecretKey.Path != secretKeyObject || privateCase.SigningKey.Path != decryptorSigningKeyObject {
		return GovernedConflictResult{}, nil, report, ErrReleaseAmbiguous
	}
	params, _, err := loadPublicEncryptionMaterial(d.publicStore, manifest.Crypto)
	if err != nil {
		return GovernedConflictResult{}, nil, report, ErrReleaseAmbiguous
	}
	secretBytes, err := d.privateStore.read(privateCase.SecretKey, 32<<20)
	if err != nil {
		return GovernedConflictResult{}, nil, report, ErrReleaseAmbiguous
	}
	secretKey := rlwe.NewSecretKey(params)
	if secretKey.UnmarshalBinary(secretBytes) != nil {
		return GovernedConflictResult{}, nil, report, ErrReleaseAmbiguous
	}
	for index := range secretBytes {
		secretBytes[index] = 0
	}
	ciphertext := bgv.NewCiphertext(params, 1, 0)
	if ciphertext.UnmarshalBinary(recomputedBytes) != nil || ciphertext.Degree() != 1 || ciphertext.Value[0].N() != params.N() {
		return GovernedConflictResult{}, nil, report, ErrReleaseAmbiguous
	}
	plaintext := rlwe.NewDecryptor(params, secretKey).DecryptNew(ciphertext)
	decoded := make([]uint64, params.MaxSlots())
	if bgv.NewEncoder(params).Decode(plaintext, decoded) != nil || decoded[0] > 1 {
		return GovernedConflictResult{}, nil, report, ErrReleaseAmbiguous
	}
	for _, value := range decoded[1:] {
		if value != 0 {
			return GovernedConflictResult{}, nil, report, ErrReleaseAmbiguous
		}
	}
	signingBytes, err := d.privateStore.read(privateCase.SigningKey, 1<<20)
	if err != nil || len(signingBytes) != ed25519.PrivateKeySize {
		return GovernedConflictResult{}, nil, report, ErrReleaseAmbiguous
	}
	signingKey := ed25519.PrivateKey(signingBytes)
	result := GovernedConflictResult{
		SchemaVersion: GovernedResultSchema, CaseID: manifest.Binding.CaseID, CaseBindingDigest: artifact.CaseBindingDigest,
		AssetIdentity: manifest.Binding.AssetIdentity, ServiceID: ServiceID, ServiceVersion: ServiceVersion,
		PolicyID: manifest.Binding.PolicyID, PolicyVersion: fhe.PolicyVersion, CircuitID: CircuitID, CircuitVersion: fhe.CircuitV5Version,
		CircuitDigest: FixedCircuitDigest(), ParameterProfile: ParameterProfile, ParameterFingerprint: manifest.Binding.ParameterFingerprint,
		ParticipantArtifactDigests: append([]Digest(nil), artifact.ParticipantArtifactDigests...), EvaluatedArtifactDigest: artifactDigest,
		ResultCiphertextDigest:     verified.RecomputedResultCiphertext.Digest,
		ResultCiphertextCommitment: verified.ResultCiphertextCommitment, Conflict: decoded[0] == 1, ReleaseOrdinal: ReleaseOrdinal,
		ReleaseMode: ReleaseModeGovernedDecryptor, ReleaseAuthorityID: authority.AuthorityID,
		ReleaseAuthorityPublicKey: append([]byte(nil), authority.SigningPublicKey...), ReleasedAtUnix: d.now.Unix(), SourceProvenance: d.provenance,
	}
	releaseSignatureCount.Add(1)
	result.Signature, err = signCanonical(signingKey, "MordantGovernedConflictResult/v1", result.signingValue())
	for index := range signingBytes {
		signingBytes[index] = 0
	}
	if err != nil {
		return GovernedConflictResult{}, nil, report, ErrReleaseAmbiguous
	}
	resultRef, retainedBytes, err := d.privateStore.createJSON(retainedResultObject, result)
	if err != nil {
		return GovernedConflictResult{}, nil, report, ErrReleaseAmbiguous
	}
	if _, err := d.publicStore.create(publicResultObject, retainedBytes); err != nil {
		return GovernedConflictResult{}, nil, report, err
	}
	resultDigest, _ := result.Digest()
	consumed := releaseConsumed{SchemaVersion: ReleaseConsumedSchema, CaseID: result.CaseID, EvaluatedArtifactDigest: artifactDigest, ResultDigest: resultDigest, ConsumedAtUnix: d.now.Unix()}
	if _, _, err := d.privateStore.createJSON(releaseConsumedObject, consumed); err != nil {
		return GovernedConflictResult{}, nil, report, err
	}
	report.Duration, report.ResultBytes, report.Pins = time.Since(started), resultRef.Length, recoursePinsForResult(result)
	return result, retainedBytes, report, nil
}

func (d *GovernedDecryptor) ReleaseWithReport(expected EvaluatedConflictArtifact) (GovernedConflictResult, []byte, ReleaseReport, error) {
	return d.release(expected)
}

func ParseGovernedConflictResult(data []byte) (GovernedConflictResult, error) {
	var result GovernedConflictResult
	if decodeStrict(data, &result) != nil {
		return result, fmt.Errorf("%w: governed result", ErrArtifact)
	}
	return result, nil
}

func LoadGovernedConflictResult(publicRoot string) (GovernedConflictResult, []byte, error) {
	store, err := openObjectStore(publicRoot, PublicCaseQuota, false)
	if err != nil {
		return GovernedConflictResult{}, nil, err
	}
	defer store.close()
	manifest, err := loadCaseManifest(store)
	if err != nil {
		return GovernedConflictResult{}, nil, err
	}
	artifact, _, _, err := loadEvaluatedArtifact(store, manifest)
	if err != nil {
		return GovernedConflictResult{}, nil, err
	}
	authority, err := loadReleaseAuthority(store, manifest)
	if err != nil {
		return GovernedConflictResult{}, nil, err
	}
	var result GovernedConflictResult
	encoded, _, err := store.readJSON(publicResultObject, &result)
	if err != nil || verifyGovernedResult(result, manifest, artifact, authority) != nil {
		return GovernedConflictResult{}, nil, ErrArtifact
	}
	return result, encoded, nil
}

// LoadReleaseAuthorityManifest returns the case controller's validated public
// release identity. Recourse callers pin this identity separately from the
// signed result, so the result cannot nominate an arbitrary signing key.
func LoadReleaseAuthorityManifest(publicRoot string) (ReleaseAuthorityManifest, error) {
	store, err := openObjectStore(publicRoot, PublicCaseQuota, false)
	if err != nil {
		return ReleaseAuthorityManifest{}, err
	}
	defer store.close()
	manifest, err := loadCaseManifest(store)
	if err != nil {
		return ReleaseAuthorityManifest{}, err
	}
	return loadReleaseAuthority(store, manifest)
}
