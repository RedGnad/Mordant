package governedfhe

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"encoding/hex"
	"encoding/json"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
	fhe "mordant.dev/fhe-lab/lattigo"
)

// Coalition release on the product path.
//
// A coalition case has no secret key. Its collective key is produced by the
// t-of-n ceremony, each operator seals only its own Shamir share, and release
// requires a quorum of operators that each recompute the circuit for themselves
// and release a share against the ciphertext they produced.
//
// The structural difference from the governed decryptor is not that the release
// is checked more carefully. It is that there is no object anywhere in the case
// that could decrypt on its own, so there is nothing to fall back to. A
// coalition case whose quorum is unavailable does not release, and cannot.
//
// What this profile does NOT establish is stated in OperatorTopology and
// repeated in the evidence: every operator runs in this process. One address
// space holds every share at once, so this is not operational independence and
// not institutional decentralization.
const (
	// CoalitionThreshold is the quorum, and CoalitionOperators the roster size.
	// Two is also what CombineReleaseBitV5 accepts, so a case cannot be created
	// with a quorum the combiner would refuse.
	CoalitionThreshold uint16 = 2
	CoalitionOperators int    = 3

	// OperatorTopologyColocated records that every operator ran in one process.
	// Increment 3 changes this value, not this schema.
	OperatorTopologyColocated = "colocated-single-process"

	CoalitionThresholdManifestSchema = "mordant.fhe-coalition-threshold-manifest/1"
	CoalitionResultSchema            = "mordant.coalition-conflict-result/1"

	thresholdManifestObject  = "threshold-manifest.json"
	coalitionResultObject    = "coalition-conflict-result.json"
	operatorBundleObject     = "threshold-operator.bin"
	coalitionAdmissionObject = "coalition-release-admitted.json"
	coalitionConsumedObject  = "coalition-release-consumed.json"
)

// ErrCoalition reports a coalition case that could not be created or released.
var ErrCoalition = errors.New("coalition release")

// ErrCoalitionQuorumUnavailable reports that fewer operators than the threshold
// accepted the release. It is terminal for the attempt and there is no other
// way to release the case.
var ErrCoalitionQuorumUnavailable = errors.New("coalition quorum unavailable")

// ErrCoalitionOperatorDivergence reports that two operators recomputed
// different outputs. It is terminal: one of them is running something else.
var ErrCoalitionOperatorDivergence = errors.New("coalition operators recomputed different outputs")

// CoalitionOperatorStatement is one operator's signed attestation for one
// released bit. The signing key is the one the threshold manifest publishes for
// that point, so the statement is verifiable against the case's own authority.
type CoalitionOperatorStatement struct {
	Point           uint64 `json:"point"`
	Slot            uint8  `json:"slot"`
	StatementDigest string `json:"statementDigest"`
	Signature       string `json:"signature"`
}

type ThresholdOperatorRecord struct {
	OperatorID       Digest `json:"operatorId"`
	Point            uint64 `json:"point"`
	SigningPublicKey []byte `json:"signingPublicKey"`
}

// CoalitionThresholdManifest is the public description of the coalition that
// holds a case's key. Its digest is the case's release authority identity,
// which is why it deliberately does not carry the case binding digest: the
// binding commits to this manifest, not the other way round.
type CoalitionThresholdManifest struct {
	SchemaVersion        string                    `json:"schemaVersion"`
	CaseID               Digest                    `json:"caseId"`
	KeyID                Digest                    `json:"keyId"`
	ParameterFingerprint Digest                    `json:"parameterFingerprint"`
	Threshold            uint16                    `json:"threshold"`
	Operators            []ThresholdOperatorRecord `json:"operators"`
	OperatorTopology     string                    `json:"operatorTopology"`
}

func (m CoalitionThresholdManifest) Digest() (Digest, error) {
	digest, _, err := digestCanonical(m)
	return digest, err
}

func (m CoalitionThresholdManifest) validate() error {
	if m.SchemaVersion != CoalitionThresholdManifestSchema || !nonzero(m.CaseID, m.KeyID, m.ParameterFingerprint) ||
		m.Threshold != CoalitionThreshold || len(m.Operators) != CoalitionOperators ||
		m.OperatorTopology == "" {
		return fmt.Errorf("%w: malformed threshold manifest", ErrCoalition)
	}
	seen := map[uint64]bool{}
	for _, operator := range m.Operators {
		if !nonzero(operator.OperatorID) || operator.Point == 0 ||
			len(operator.SigningPublicKey) != ed25519.PublicKeySize || seen[operator.Point] {
			return fmt.Errorf("%w: malformed operator record", ErrCoalition)
		}
		seen[operator.Point] = true
	}
	return nil
}

func (m CoalitionThresholdManifest) thresholdManifest() fhe.ThresholdManifest {
	operators := make([]fhe.ThresholdOperatorPublic, 0, len(m.Operators))
	for _, record := range m.Operators {
		public := fhe.ThresholdOperatorPublic{OperatorID: [32]byte(record.OperatorID), Point: record.Point}
		copy(public.SigningPublicKey[:], record.SigningPublicKey)
		operators = append(operators, public)
	}
	return fhe.ThresholdManifest{
		KeyID:                [32]byte(m.KeyID),
		ParameterFingerprint: [32]byte(m.ParameterFingerprint),
		Threshold:            m.Threshold,
		Operators:            operators,
	}
}

// CoalitionConflictResult is the released result of a coalition case.
//
// It carries the two V5 bits as two separate facts. External audit finding H-02
// is that a single conjunction cannot distinguish "different receivable" from
// "same receivable, no policy conflict", and the governed result's single
// Conflict boolean has exactly that shape. Here SameEconomicAsset and
// PolicyConflict are released independently, each by its own quorum of shares
// against its own threshold session.
//
// It carries no release-authority signature, because a coalition has no single
// key and routing it through one would undo the property the coalition exists
// for. What authenticates it is the transcript: the operator statements, the
// coalition that served, and the digests every operator recomputed locally.
type CoalitionConflictResult struct {
	SchemaVersion     string `json:"schemaVersion"`
	CaseID            Digest `json:"caseId"`
	CaseBindingDigest Digest `json:"caseBindingDigest"`
	AssetIdentity     Digest `json:"assetIdentity"`
	ServiceID         string `json:"serviceId"`
	ServiceVersion    uint32 `json:"serviceVersion"`

	PolicyID             Digest `json:"policyId"`
	PolicyVersion        uint32 `json:"policyVersion"`
	CircuitID            string `json:"circuitId"`
	CircuitVersion       uint32 `json:"circuitVersion"`
	CircuitDigest        Digest `json:"circuitDigest"`
	ParameterProfile     string `json:"parameterProfile"`
	ParameterFingerprint Digest `json:"parameterFingerprint"`

	ParticipantArtifactDigests []Digest `json:"participantArtifactDigests"`
	EnrollmentDigestA          string   `json:"enrollmentDigestA"`
	EnrollmentDigestB          string   `json:"enrollmentDigestB"`
	EvaluatedArtifactDigest    Digest   `json:"evaluatedArtifactDigest"`

	// The two released bits, as two facts. PolicyConflict is only meaningful
	// where SameEconomicAsset holds; the pair (false, true) is structurally
	// impossible because identity equality is a factor of the conjunction.
	SameEconomicAsset bool `json:"sameEconomicAsset"`
	PolicyConflict    bool `json:"policyConflict"`

	ReleaseMode        string   `json:"releaseMode"`
	ReleaseAuthorityID Digest   `json:"releaseAuthorityId"`
	Threshold          uint16   `json:"threshold"`
	Coalition          []uint64 `json:"coalition"`
	OperatorTopology   string   `json:"operatorTopology"`
	// One signed statement per released bit per serving operator, and the
	// transcript commitment over the whole release. The signatures are what let
	// a third party check that this coalition actually attested, rather than
	// taking the coordinator's word that it verified them.
	OperatorStatements []CoalitionOperatorStatement `json:"operatorStatements"`
	ReleaseTranscript  string                       `json:"releaseTranscript"`
	// One per serving operator, each signed only after that operator recombined
	// the released bits for itself. This is what ties an operator's published key
	// to a value rather than to a share.
	SettlementAttestations  []CoalitionSettlementAttestation `json:"settlementAttestations"`
	RuntimeFingerprint      string                           `json:"runtimeFingerprint"`
	RecomputedByAllOfQuorum bool                             `json:"recomputedByAllOfQuorum"`

	ReleasedAtUnix   int64  `json:"releasedAtUnix"`
	SourceProvenance Digest `json:"sourceProvenance"`
}

func (r CoalitionConflictResult) Digest() (Digest, error) {
	digest, _, err := digestCanonical(r)
	return digest, err
}

type coalitionAdmission struct {
	SchemaVersion           string `json:"schemaVersion"`
	CaseID                  Digest `json:"caseId"`
	CaseBindingDigest       Digest `json:"caseBindingDigest"`
	EvaluatedArtifactDigest Digest `json:"evaluatedArtifactDigest"`
	ReleaseMode             string `json:"releaseMode"`
	AdmittedAtUnix          int64  `json:"admittedAtUnix"`
}

type coalitionConsumed struct {
	SchemaVersion           string `json:"schemaVersion"`
	CaseID                  Digest `json:"caseId"`
	EvaluatedArtifactDigest Digest `json:"evaluatedArtifactDigest"`
	ResultDigest            Digest `json:"resultDigest"`
	ConsumedAtUnix          int64  `json:"consumedAtUnix"`
}

func loadCoalitionThresholdManifest(store *objectStore, binding FHECaseBinding) (CoalitionThresholdManifest, error) {
	var manifest CoalitionThresholdManifest
	if _, _, err := store.readJSON(thresholdManifestObject, &manifest); err != nil {
		return manifest, fmt.Errorf("%w: %v", ErrCoalition, err)
	}
	if err := manifest.validate(); err != nil {
		return manifest, err
	}
	if manifest.CaseID != binding.CaseID || manifest.ParameterFingerprint != binding.ParameterFingerprint ||
		manifest.KeyID != binding.PublicKeyDigest {
		return manifest, fmt.Errorf("%w: threshold manifest does not describe this case", ErrCoalition)
	}
	// The binding's release authority is this manifest's digest. That is the
	// whole authority: there is no key behind it.
	digest, err := manifest.Digest()
	if err != nil {
		return manifest, err
	}
	if digest != binding.ReleaseAuthorityID {
		return manifest, fmt.Errorf("%w: threshold manifest is not the case's release authority", ErrCoalition)
	}
	return manifest, nil
}

// CoalitionDecryptorConfig names the operator roots this process may open.
//
// There is no private case root and no secret key path, because a coalition
// case has neither.
type CoalitionDecryptorConfig struct {
	PublicRoot string
	// One directory per operator, each holding that operator's sealed bundle.
	// At least CoalitionThreshold must be reachable for a release to happen.
	OperatorRoots []string
	// Where each operator keeps its own one-shot session ledger.
	LedgerRoot string
	Provenance Digest
	Now        time.Time
}

// CoalitionDecryptor releases a coalition case. It never opens a secret key,
// because none exists.
type CoalitionDecryptor struct {
	config      CoalitionDecryptorConfig
	publicStore *objectStore
}

func NewCoalitionDecryptor(config CoalitionDecryptorConfig) (*CoalitionDecryptor, error) {
	if config.Now.IsZero() {
		config.Now = time.Now().UTC()
	}
	if !nonzero(config.Provenance) || len(config.OperatorRoots) < int(CoalitionThreshold) || config.LedgerRoot == "" {
		return nil, ErrCoalition
	}
	for _, root := range config.OperatorRoots {
		if !rootsDisjoint(config.PublicRoot, root) {
			return nil, fmt.Errorf("%w: operator root overlaps the public root", ErrCoalition)
		}
	}
	publicStore, err := openObjectStore(config.PublicRoot, PublicCaseQuota, false)
	if err != nil {
		return nil, err
	}
	return &CoalitionDecryptor{config: config, publicStore: publicStore}, nil
}

func (d *CoalitionDecryptor) Close() error {
	if d == nil {
		return nil
	}
	if d.publicStore.close() != nil {
		return ErrStore
	}
	return nil
}

// coalitionOperator is one loaded operator and the resources it owns.
type coalitionOperator struct {
	point    uint64
	operator *fhe.ReleaseOperatorV5
	ledger   *fhe.SessionLedger
	verdict  fhe.OperatorVerdictV5
}

// Release runs the coalition release for one evaluated artifact.
//
// The sequence is deliberate. Everything that can refuse does so before any
// share is generated, and a share is only ever generated against the ciphertext
// the generating operator recomputed itself.
func (d *CoalitionDecryptor) Release(expected EvaluatedConflictArtifact) (CoalitionConflictResult, []byte, error) {
	var result CoalitionConflictResult
	if d == nil {
		return result, nil, ErrCoalition
	}
	manifest, err := loadCaseManifest(d.publicStore)
	if err != nil || d.config.Now.Unix() < manifest.Binding.CreatedAtUnix || d.config.Now.Unix() > manifest.Binding.ExpiresAtUnix {
		return result, nil, ErrBinding
	}
	if manifest.Binding.ReleaseMode != ReleaseModeCoalitionV5 {
		return result, nil, fmt.Errorf("%w: case is not a coalition case", ErrCoalition)
	}
	thresholdManifest, err := loadCoalitionThresholdManifest(d.publicStore, manifest.Binding)
	if err != nil {
		return result, nil, err
	}
	artifact, evaluatorResultBytes, artifactDigest, err := loadEvaluatedArtifact(d.publicStore, manifest)
	if err != nil {
		return result, nil, err
	}
	expectedDigest, _ := expected.Digest()
	storedDigest, _ := artifact.Digest()
	if expectedDigest != storedDigest {
		return result, nil, ErrBinding
	}
	bindingDigest, err := manifest.Binding.Digest()
	if err != nil {
		return result, nil, err
	}

	participants, err := loadAndValidateFreshParticipants(d.publicStore, manifest, d.config.Now)
	if err != nil {
		return result, nil, err
	}
	if participants.digestA != artifact.ParticipantArtifactDigests[0] || participants.digestB != artifact.ParticipantArtifactDigests[1] {
		return result, nil, ErrBinding
	}

	runtime, err := loadEvaluationRuntime(d.publicStore, manifest)
	if err != nil || participants.pledgeA.KeyID != runtime.KeyID() || participants.pledgeB.KeyID != runtime.KeyID() {
		return result, nil, ErrBinding
	}
	// The L1 enrollments are the pair authorization. The operators check them
	// again for themselves below; this refuses the case before any operator is
	// opened.
	recordA, recordB, err := loadCaseEnrollmentsV5(d.publicStore)
	if err != nil {
		return result, nil, err
	}
	enrollments, err := verifyCaseEnrollmentsV5(runtime, manifest.Binding, participants, recordA, recordB, d.config.Now)
	if err != nil {
		return result, nil, err
	}

	inputs := fhe.CircuitInputsV5{
		PolicyBitsA: participants.pledgeA.PolicyBits, PolicyBitsB: participants.pledgeB.PolicyBits,
		CurrencyBitsA: participants.pledgeA.CurrencyBits, CurrencyBitsB: participants.pledgeB.CurrencyBits,
		ReceivableIDsA: participants.pledgeA.ReceivableIDBits, ReceivableIDsB: participants.pledgeB.ReceivableIDBits,
	}
	inputsDigest, err := inputs.Digest()
	if err != nil {
		return result, nil, fmt.Errorf("%w: %v", ErrCoalition, err)
	}
	// The coordinator's proposal. No operator will decrypt it; each recomputes
	// the circuit and compares, and releases only against its own output.
	proposed, err := runtime.RecomputeCircuitV5(inputs)
	if err != nil || proposed == nil {
		return result, nil, fmt.Errorf("%w: coordinator recomputation failed", ErrCoalition)
	}
	outputsDigest, err := proposed.Digest()
	if err != nil {
		return result, nil, fmt.Errorf("%w: %v", ErrCoalition, err)
	}
	// External audit finding H-03 at the case level. The evaluator's published
	// result is never decrypted and never used as the release target: the
	// descriptor below carries what this process recomputed. It is still
	// compared, because a case whose published result disagrees with the circuit
	// is a case where one of the two is wrong, and releasing the other one
	// silently would leave that unresolved.
	//
	// The comparison is terminal. There is no retry that could make a divergent
	// evaluation agree.
	recomputedConflictBytes, err := proposed.PolicyConflict.MarshalBinary()
	if err != nil {
		return result, nil, fmt.Errorf("%w: %v", ErrCoalition, err)
	}
	if !bytes.Equal(recomputedConflictBytes, evaluatorResultBytes) {
		return result, nil, fmt.Errorf("%w: published evaluation does not match the recomputed circuit", ErrEvaluatorMismatch)
	}
	identity, err := coalitionRuntimeIdentity(d.publicStore, manifest)
	if err != nil {
		return result, nil, err
	}

	descriptor := fhe.ReleaseDescriptorV5{
		SessionCommitment:    enrollments.Paired.SessionCommitment,
		SessionNullifier:     enrollments.Paired.SessionNullifier,
		EnrollmentDigestA:    enrollments.Paired.EnrollmentDigestA,
		EnrollmentDigestB:    enrollments.Paired.EnrollmentDigestB,
		InputsDigest:         inputsDigest,
		OutputsDigest:        outputsDigest,
		CircuitVersion:       fhe.CircuitV5Version,
		RuntimeFingerprint:   identity.Fingerprint(),
		KeyID:                runtime.KeyIDBytes(),
		ParameterFingerprint: runtime.ParameterFingerprint(),
		PolicyID:             [32]byte(manifest.Binding.PolicyID),
		PolicyVersion:        fhe.PolicyVersion,
		ExpiresAt:            uint64(manifest.Binding.ExpiresAtUnix),
	}

	if d.publicStore.exists(coalitionConsumedObject) {
		return result, nil, ErrReleaseAmbiguous
	}
	admission := coalitionAdmission{
		SchemaVersion: CoalitionResultSchema, CaseID: manifest.Binding.CaseID, CaseBindingDigest: bindingDigest,
		EvaluatedArtifactDigest: artifactDigest, ReleaseMode: ReleaseModeCoalitionV5, AdmittedAtUnix: d.config.Now.Unix(),
	}
	if !d.publicStore.exists(coalitionAdmissionObject) {
		if _, _, err := d.publicStore.createJSON(coalitionAdmissionObject, admission); err != nil {
			return result, nil, err
		}
	}

	operators, err := d.openOperators(manifest, thresholdManifest, identity)
	if err != nil {
		return result, nil, err
	}
	defer func() {
		for _, held := range operators {
			_ = held.ledger.Close()
		}
	}()

	// The coalition is named before anyone verifies, because each operator
	// checks that it is a member of the coalition it is being asked to serve.
	// It is drawn from the operators that are reachable, which is how the case
	// survives losing one of three.
	//
	// One attempt per session, by construction: an operator's ledger admits a
	// session once, so a second coalition sharing a member could not be tried
	// afterwards. A refusal is therefore terminal for the session rather than
	// something to retry against a different pair.
	coalition := [2]uint64{operators[0].point, operators[1].point}
	request := fhe.OperatorReleaseRequestV5{
		Descriptor:  descriptor,
		EnrollmentA: enrollments.SignedA, EnrollmentB: enrollments.SignedB,
		Inputs:    inputs,
		Coalition: coalition,
	}
	quorum, err := verifyQuorum(operators[:CoalitionThreshold], request, outputsDigest, d.config.Now)
	if err != nil {
		return result, nil, err
	}
	sameAsset, policyConflict, statements, shares, err := releaseCoalitionBits(runtime.Params, thresholdManifest.thresholdManifest(), quorum, request)
	if err != nil {
		return result, nil, err
	}

	transcript := fhe.ReleaseTranscriptV5{
		SessionCommitment: descriptor.SessionCommitment, SessionNullifier: descriptor.SessionNullifier,
		EnrollmentDigestA: descriptor.EnrollmentDigestA, EnrollmentDigestB: descriptor.EnrollmentDigestB,
		InputsDigest: descriptor.InputsDigest, OutputsDigest: descriptor.OutputsDigest,
		CircuitVersion: descriptor.CircuitVersion, KeyID: descriptor.KeyID,
		ParameterFingerprint: descriptor.ParameterFingerprint, PolicyID: descriptor.PolicyID,
		PolicyVersion: descriptor.PolicyVersion, Coalition: coalition, Threshold: CoalitionThreshold,
		OperatorStatements: transcriptStatements(statements), SameEconomicAsset: sameAsset, PolicyConflict: policyConflict,
		ReleasedAt: uint64(d.config.Now.Unix()),
	}
	transcriptDigest, err := transcript.Digest()
	if err != nil {
		return result, nil, fmt.Errorf("%w: %v", ErrCoalition, err)
	}

	result = CoalitionConflictResult{
		SchemaVersion: CoalitionResultSchema, CaseID: manifest.Binding.CaseID, CaseBindingDigest: bindingDigest,
		AssetIdentity: manifest.Binding.AssetIdentity, ServiceID: ServiceID, ServiceVersion: ServiceVersion,
		PolicyID: manifest.Binding.PolicyID, PolicyVersion: fhe.PolicyVersion, CircuitID: CircuitID,
		CircuitVersion: fhe.CircuitV5Version, CircuitDigest: FixedCircuitDigest(), ParameterProfile: ParameterProfile,
		ParameterFingerprint:       manifest.Binding.ParameterFingerprint,
		ParticipantArtifactDigests: []Digest{participants.digestA, participants.digestB},
		EnrollmentDigestA:          bytes32Hex(descriptor.EnrollmentDigestA),
		EnrollmentDigestB:          bytes32Hex(descriptor.EnrollmentDigestB),
		EvaluatedArtifactDigest:    artifactDigest,
		SameEconomicAsset:          sameAsset,
		PolicyConflict:             policyConflict,
		ReleaseMode:                ReleaseModeCoalitionV5,
		ReleaseAuthorityID:         manifest.Binding.ReleaseAuthorityID,
		Threshold:                  CoalitionThreshold,
		Coalition:                  []uint64{coalition[0], coalition[1]},
		OperatorTopology:           thresholdManifest.OperatorTopology,
		OperatorStatements:         statements,
		ReleaseTranscript:          bytes32Hex(transcriptDigest),
		RuntimeFingerprint:         bytes32Hex(identity.Fingerprint()),
		RecomputedByAllOfQuorum:    true,
		ReleasedAtUnix:             d.config.Now.Unix(),
		SourceProvenance:           d.config.Provenance,
	}

	// The confirmation round. Each serving operator recombines both released bits
	// for itself, against the ciphertexts it recomputed, and signs a statement
	// naming this case, this release and those bits only if it obtains them.
	//
	// This is the binding a release share cannot carry: a share is generated
	// before any bit exists, which is the point of a threshold. Without this
	// round a downstream verifier authenticates the quorum and then has to trust
	// whoever combined the shares for what they decrypted to.
	attestations := make([]CoalitionSettlementAttestation, 0, len(quorum))
	for _, held := range quorum {
		statement := coalitionSettlementStatement(result, held.point)
		message, messageErr := statement.signingMessage()
		if messageErr != nil {
			return CoalitionConflictResult{}, nil, fmt.Errorf("%w: %v", ErrCoalition, messageErr)
		}
		signature, confirmErr := held.operator.ConfirmReleasedBits(
			runtime.Params, thresholdManifest.thresholdManifest(), request, held.verdict,
			shares[0], shares[1], sameAsset, policyConflict, message,
		)
		if confirmErr != nil {
			return CoalitionConflictResult{}, nil, fmt.Errorf(
				"%w: operator %d would not confirm the released bits: %v", ErrCoalition, held.point, confirmErr)
		}
		attestations = append(attestations, CoalitionSettlementAttestation{
			Point: held.point, Signature: append([]byte(nil), signature[:]...),
		})
	}
	result.SettlementAttestations = attestations

	_, encoded, err := d.publicStore.createJSON(coalitionResultObject, result)
	if err != nil {
		return CoalitionConflictResult{}, nil, err
	}
	resultDigest, _ := result.Digest()
	consumed := coalitionConsumed{
		SchemaVersion: CoalitionResultSchema, CaseID: result.CaseID, EvaluatedArtifactDigest: artifactDigest,
		ResultDigest: resultDigest, ConsumedAtUnix: d.config.Now.Unix(),
	}
	if _, _, err := d.publicStore.createJSON(coalitionConsumedObject, consumed); err != nil {
		return CoalitionConflictResult{}, nil, err
	}
	return result, encoded, nil
}

// openOperators loads every reachable operator. It does not require all of
// them: the point of a threshold is that the case survives losing one.
func (d *CoalitionDecryptor) openOperators(
	caseManifest FHECaseManifest,
	manifest CoalitionThresholdManifest,
	identity fhe.RuntimeIdentity,
) ([]*coalitionOperator, error) {
	operators := make([]*coalitionOperator, 0, len(d.config.OperatorRoots))
	// An unreachable operator is normal and survivable, so it does not abort the
	// release. The reason is kept anyway: an unavailable quorum whose cause is
	// three corrupt bundles reads the same as one whose cause is three offline
	// hosts, and those need different responses.
	unreachable := make([]string, 0, len(d.config.OperatorRoots))
	note := func(index int, reason string) {
		unreachable = append(unreachable, fmt.Sprintf("operator root %d: %s", index+1, reason))
	}
	for index, root := range d.config.OperatorRoots {
		store, err := openObjectStore(root, PrivateCaseQuota, true)
		if err != nil {
			note(index, "store did not open: "+err.Error())
			continue
		}
		bundle, _, readErr := store.readNamed(operatorBundleObject, 64<<20)
		_ = store.close()
		if readErr != nil {
			note(index, "no sealed share: "+readErr.Error())
			continue
		}
		threshold, err := fhe.NewThresholdOperator(bundle)
		for position := range bundle {
			bundle[position] = 0
		}
		if err != nil {
			note(index, "sealed share rejected: "+err.Error())
			continue
		}
		// Its own evaluator, built from the same published public material. The
		// operators then recompute independently rather than sharing one
		// evaluator object, which is what makes the digest comparison between
		// them worth making. The circuit constants are fixed, so two honest
		// evaluators produce identical bytes.
		operatorRuntime, err := loadEvaluationRuntime(d.publicStore, caseManifest)
		if err != nil {
			note(index, "evaluator did not load: "+err.Error())
			continue
		}
		// The operator derives its own enrollment trust store from the signed
		// binding rather than being told whom to trust.
		if err := RegisterCaseEnrollmentIssuers(operatorRuntime, caseManifest.Binding); err != nil {
			note(index, "trust store not derivable: "+err.Error())
			continue
		}
		ledger, err := fhe.OpenSessionLedger(filepath.Join(d.config.LedgerRoot, fmt.Sprintf("operator-%d.db", index+1)))
		if err != nil {
			note(index, "ledger did not open: "+err.Error())
			continue
		}
		operator, err := fhe.NewReleaseOperatorV5(operatorRuntime, threshold, ledger, identity, identity.Fingerprint())
		if err != nil {
			_ = ledger.Close()
			note(index, "operator refused to bind: "+err.Error())
			continue
		}
		// A share from another ceremony is not a member of this case's coalition.
		if !manifestContainsOperator(manifest, threshold.Public()) {
			_ = ledger.Close()
			note(index, "share is not in this case's published threshold manifest")
			continue
		}
		operators = append(operators, &coalitionOperator{point: threshold.Public().Point, operator: operator, ledger: ledger})
	}
	if len(operators) < int(CoalitionThreshold) {
		for _, held := range operators {
			_ = held.ledger.Close()
		}
		detail := ""
		if len(unreachable) > 0 {
			detail = "; " + strings.Join(unreachable, "; ")
		}
		return nil, fmt.Errorf("%w: %d of %d operators reachable, %d required%s",
			ErrCoalitionQuorumUnavailable, len(operators), len(d.config.OperatorRoots), CoalitionThreshold, detail)
	}
	return operators, nil
}

// verifyQuorum has every reachable operator verify and recompute concurrently,
// and returns exactly the threshold that accepted.
//
// Divergence between two accepting operators is terminal rather than resolved
// by majority: two operators that recompute different outputs are not running
// the same circuit, and picking one of them would be picking which one to
// trust.
func verifyQuorum(
	operators []*coalitionOperator,
	request fhe.OperatorReleaseRequestV5,
	proposedOutputs [32]byte,
	now time.Time,
) ([]*coalitionOperator, error) {
	var group sync.WaitGroup
	errs := make([]error, len(operators))
	for index := range operators {
		group.Add(1)
		go func(position int) {
			defer group.Done()
			verdict, err := operators[position].operator.VerifyAndRecompute(request, now)
			operators[position].verdict, errs[position] = verdict, err
		}(index)
	}
	group.Wait()

	accepted := make([]*coalitionOperator, 0, len(operators))
	for index, held := range operators {
		if errs[index] != nil || !held.verdict.Accepted {
			continue
		}
		accepted = append(accepted, held)
	}
	if len(accepted) < int(CoalitionThreshold) {
		// The named checks exist so a refusal can be read. Reporting the count
		// alone would leave an operator's reason inside a structure nobody sees.
		return nil, fmt.Errorf("%w: %d of %d operators accepted%s",
			ErrCoalitionQuorumUnavailable, len(accepted), len(operators), refusalDetail(operators, errs))
	}
	for _, held := range accepted {
		if held.verdict.RecomputedOutputsDigest != accepted[0].verdict.RecomputedOutputsDigest {
			return nil, ErrCoalitionOperatorDivergence
		}
		if held.verdict.RecomputedOutputsDigest != proposedOutputs {
			return nil, fmt.Errorf("%w: operator %d disagrees with the proposal", ErrCoalitionOperatorDivergence, held.point)
		}
	}
	return accepted[:CoalitionThreshold], nil
}

// releaseCoalitionBits generates each operator's shares and combines them, one
// released bit at a time.
// refusalDetail summarises why operators refused, naming the checks that failed.
// manifestContainsOperator checks a loaded share against the coalition the case
// published, by point, operator identity and signing key together.
func manifestContainsOperator(manifest CoalitionThresholdManifest, public fhe.ThresholdOperatorPublic) bool {
	for _, record := range manifest.Operators {
		if record.Point == public.Point && record.OperatorID == Digest(public.OperatorID) &&
			string(record.SigningPublicKey) == string(public.SigningPublicKey[:]) {
			return true
		}
	}
	return false
}

func refusalDetail(operators []*coalitionOperator, errs []error) string {
	details := make([]string, 0, len(operators))
	for index, held := range operators {
		failed := make([]string, 0, 4)
		for _, check := range held.verdict.Checks {
			if !check.Passed {
				if check.Detail != "" {
					failed = append(failed, check.Name+"("+check.Detail+")")
					continue
				}
				failed = append(failed, check.Name)
			}
		}
		reason := strings.Join(failed, ",")
		if reason == "" && errs[index] != nil {
			reason = errs[index].Error()
		}
		if reason == "" {
			continue
		}
		details = append(details, fmt.Sprintf("operator %d: %s", held.point, reason))
	}
	if len(details) == 0 {
		return ""
	}
	return "; " + strings.Join(details, "; ")
}

func releaseCoalitionBits(
	params bgv.Parameters,
	manifest fhe.ThresholdManifest,
	quorum []*coalitionOperator,
	request fhe.OperatorReleaseRequestV5,
) (bool, bool, []CoalitionOperatorStatement, [2][]fhe.ThresholdReleaseResponse, error) {
	var shares [2][]fhe.ThresholdReleaseResponse
	sameShares := make([]fhe.ThresholdReleaseResponse, 0, len(quorum))
	conflictShares := make([]fhe.ThresholdReleaseResponse, 0, len(quorum))
	statements := make([]CoalitionOperatorStatement, 0, len(quorum)*2)
	for _, held := range quorum {
		same, conflict, err := held.operator.ReleaseShares(request, held.verdict, time.Now())
		if err != nil {
			return false, false, nil, shares, fmt.Errorf("%w: operator %d refused to share: %v", ErrCoalition, held.point, err)
		}
		sameShares = append(sameShares, same)
		conflictShares = append(conflictShares, conflict)
		statements = append(statements,
			CoalitionOperatorStatement{
				Point: same.Point, Slot: 0,
				StatementDigest: bytes32Hex(same.StatementDigest),
				Signature:       "0x" + hex.EncodeToString(same.Signature[:]),
			},
			CoalitionOperatorStatement{
				Point: conflict.Point, Slot: 1,
				StatementDigest: bytes32Hex(conflict.StatementDigest),
				Signature:       "0x" + hex.EncodeToString(conflict.Signature[:]),
			})
	}
	outputs := quorum[0].verdict.RecomputedOutputs()
	if outputs == nil || outputs.SameEconomicAsset == nil || outputs.PolicyConflict == nil {
		return false, false, nil, shares, fmt.Errorf("%w: quorum carries no recomputed outputs", ErrCoalition)
	}
	sameAsset, err := combineCoalitionBit(params, manifest, request, outputs.SameEconomicAsset, sameShares, 0)
	if err != nil {
		return false, false, nil, shares, fmt.Errorf("%w: sameEconomicAsset: %v", ErrCoalition, err)
	}
	policyConflict, err := combineCoalitionBit(params, manifest, request, outputs.PolicyConflict, conflictShares, 1)
	if err != nil {
		return false, false, nil, shares, fmt.Errorf("%w: policyConflict: %v", ErrCoalition, err)
	}
	// H-02 is the reason both bits are released. It is not a reason to invent a
	// business consequence for their combination here: the two facts are
	// reported as they were released, and what they mean is a policy question
	// answered elsewhere.
	if policyConflict && !sameAsset {
		return false, false, nil, shares, fmt.Errorf("%w: policy conflict without asset match", ErrCoalition)
	}
	shares[0], shares[1] = sameShares, conflictShares
	return sameAsset, policyConflict, statements, shares, nil
}

func combineCoalitionBit(
	params bgv.Parameters,
	manifest fhe.ThresholdManifest,
	request fhe.OperatorReleaseRequestV5,
	ciphertext *rlwe.Ciphertext,
	shares []fhe.ThresholdReleaseResponse,
	slot uint8,
) (bool, error) {
	descriptor, err := fhe.ReleaseDescriptorForSlot(request.Descriptor, ciphertext, request.Coalition, slot, manifest.KeyID)
	if err != nil {
		return false, err
	}
	confirmed, transcript, err := fhe.CombineReleaseBitV5(params, descriptor, manifest, ciphertext, shares)
	if err != nil {
		return false, err
	}
	if transcript == ([32]byte{}) {
		return false, fmt.Errorf("%w: empty threshold transcript", ErrCoalition)
	}
	return confirmed, nil
}

func coalitionRuntimeIdentity(store *objectStore, manifest FHECaseManifest) (fhe.RuntimeIdentity, error) {
	params, publicKey, err := loadPublicEncryptionMaterial(store, manifest.Crypto)
	if err != nil {
		return fhe.RuntimeIdentity{}, err
	}
	relinearizationKey, galoisKeys, err := loadEvaluationKeyMaterial(store, manifest, params)
	if err != nil {
		return fhe.RuntimeIdentity{}, err
	}
	identity, err := fhe.LocalRuntimeIdentity(params, publicKey, relinearizationKey, galoisKeys, CoalitionEvaluationKeyEpoch)
	if err != nil {
		return fhe.RuntimeIdentity{}, fmt.Errorf("%w: %v", ErrCoalition, err)
	}
	return identity, nil
}

// CoalitionEvaluationKeyEpoch is the key epoch bound into the runtime identity.
// This profile performs no key rotation, so it is fixed and the operators
// refuse any other value rather than accepting an epoch nothing published.
const CoalitionEvaluationKeyEpoch uint32 = 1

func bytes32Hex(value [32]byte) string {
	return "0x" + hex.EncodeToString(value[:])
}

// transcriptStatements is what the release transcript commits to: the statement
// digests in the order they were produced.
func transcriptStatements(statements []CoalitionOperatorStatement) [][32]byte {
	digests := make([][32]byte, 0, len(statements))
	for _, statement := range statements {
		raw, err := hex.DecodeString(strings.TrimPrefix(statement.StatementDigest, "0x"))
		if err != nil || len(raw) != 32 {
			return nil
		}
		digests = append(digests, [32]byte(raw))
	}
	return digests
}

// buildCoalitionThresholdManifest derives the public coalition description from
// the ceremony's own output. Every operator record is read back out of the
// sealed bundle it belongs to, so the manifest cannot describe an operator the
// ceremony did not actually produce a share for.
func buildCoalitionThresholdManifest(
	caseID Digest,
	publicKeyDigest Digest,
	parameterFingerprint Digest,
	material *fhe.ColocatedCeremonyMaterial,
) (CoalitionThresholdManifest, error) {
	var manifest CoalitionThresholdManifest
	if material == nil || len(material.Bundles) != CoalitionOperators {
		return manifest, fmt.Errorf("%w: ceremony produced %d bundles, %d required", ErrCoalition, len(material.Bundles), CoalitionOperators)
	}
	if Digest(material.Manifest.KeyID) != publicKeyDigest {
		return manifest, fmt.Errorf("%w: ceremony key id is not the published public key", ErrCoalition)
	}
	if material.Manifest.Threshold != CoalitionThreshold {
		return manifest, fmt.Errorf("%w: ceremony threshold is %d", ErrCoalition, material.Manifest.Threshold)
	}
	operators := make([]ThresholdOperatorRecord, 0, len(material.Bundles))
	for index, bundle := range material.Bundles {
		imported, err := fhe.NewThresholdOperator(bundle)
		if err != nil {
			return manifest, fmt.Errorf("%w: bundle %d: %v", ErrCoalition, index, err)
		}
		public := imported.Public()
		operators = append(operators, ThresholdOperatorRecord{
			OperatorID:       Digest(public.OperatorID),
			Point:            public.Point,
			SigningPublicKey: append([]byte(nil), public.SigningPublicKey[:]...),
		})
	}
	manifest = CoalitionThresholdManifest{
		SchemaVersion: CoalitionThresholdManifestSchema, CaseID: caseID,
		KeyID: publicKeyDigest, ParameterFingerprint: parameterFingerprint,
		Threshold: CoalitionThreshold, Operators: operators,
		OperatorTopology: OperatorTopologyColocated,
	}
	return manifest, manifest.validate()
}

// writeCoalitionOperatorBundles gives each operator root exactly one sealed
// share. The roots must be distinct and empty: two shares in one root would put
// a quorum behind a single filesystem boundary, which is the thing the
// threshold is supposed to prevent.
func writeCoalitionOperatorBundles(roots []string, material *fhe.ColocatedCeremonyMaterial) error {
	if len(roots) != CoalitionOperators {
		return fmt.Errorf("%w: %d operator roots supplied, %d required", ErrCoalition, len(roots), CoalitionOperators)
	}
	for index, root := range roots {
		for other := index + 1; other < len(roots); other++ {
			if !rootsDisjoint(root, roots[other]) {
				return fmt.Errorf("%w: operator roots %d and %d overlap", ErrCoalition, index+1, other+1)
			}
		}
	}
	for index, root := range roots {
		store, err := openObjectStore(root, PrivateCaseQuota, true)
		if err != nil {
			return err
		}
		names, err := store.names()
		if err != nil || len(names) != 0 {
			_ = store.close()
			return fmt.Errorf("%w: operator root %d is not empty", ErrCoalition, index+1)
		}
		_, err = store.create(operatorBundleObject, material.Bundles[index])
		closeErr := store.close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return ErrStore
		}
	}
	return nil
}

/* ---------------------------------------------- settlement statement binding */

// CoalitionSettlementStatementSchema versions the one statement an operator
// signs about a released value.
const CoalitionSettlementStatementSchema = "mordant.coalition-settlement-statement/1"

// CoalitionSettlementStatementDomain is the signing domain, without the trailing
// separator that signCanonical adds.
const CoalitionSettlementStatementDomain = "MordantCoalitionSettlementStatement/v1"

// CoalitionSettlementStatement is what binds an operator's published key to the
// bits that were actually released.
//
// The release shares cannot carry this. An operator generates its share before
// any bit exists, which is the point of a threshold, so nothing it signs during
// the release can attest what the bits turned out to be. Without this statement
// a downstream verifier can authenticate the quorum and must then take the
// combining coordinator's word for the values.
//
// Every field a downstream verifier needs to rebuild independently is here, and
// nothing else. It carries no economic term: what a released conflict is worth
// comes from the pre-committed settlement profile and never from this.
type CoalitionSettlementStatement struct {
	SchemaVersion      string   `json:"schemaVersion"`
	CaseID             Digest   `json:"caseId"`
	CaseBindingDigest  Digest   `json:"caseBindingDigest"`
	AssetIdentity      Digest   `json:"assetIdentity"`
	ReleaseAuthorityID Digest   `json:"releaseAuthorityId"`
	ReleaseMode        string   `json:"releaseMode"`
	ReleaseTranscript  string   `json:"releaseTranscript"`
	Coalition          []uint64 `json:"coalition"`
	Threshold          uint16   `json:"threshold"`
	SameEconomicAsset  bool     `json:"sameEconomicAsset"`
	PolicyConflict     bool     `json:"policyConflict"`
	/// The operator attesting. Each serving operator signs its own statement, so
	/// a signature cannot be moved between points.
	Point uint64 `json:"point"`
}

// CoalitionSettlementAttestation is one operator's signature over its statement.
type CoalitionSettlementAttestation struct {
	Point     uint64 `json:"point"`
	Signature []byte `json:"signature"`
}

// signingMessage is the exact byte string the operator signs, in the same
// domain-separated shape signCanonical uses everywhere else in this package.
func (s CoalitionSettlementStatement) signingMessage() ([]byte, error) {
	encoded, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	message := make([]byte, 0, len(CoalitionSettlementStatementDomain)+1+len(encoded))
	message = append(message, []byte(CoalitionSettlementStatementDomain)...)
	message = append(message, 0)
	message = append(message, encoded...)
	return message, nil
}

// coalitionSettlementStatement builds the statement one operator will sign.
func coalitionSettlementStatement(
	result CoalitionConflictResult,
	point uint64,
) CoalitionSettlementStatement {
	return CoalitionSettlementStatement{
		SchemaVersion:      CoalitionSettlementStatementSchema,
		CaseID:             result.CaseID,
		CaseBindingDigest:  result.CaseBindingDigest,
		AssetIdentity:      result.AssetIdentity,
		ReleaseAuthorityID: result.ReleaseAuthorityID,
		ReleaseMode:        result.ReleaseMode,
		ReleaseTranscript:  result.ReleaseTranscript,
		Coalition:          append([]uint64(nil), result.Coalition...),
		Threshold:          result.Threshold,
		SameEconomicAsset:  result.SameEconomicAsset,
		PolicyConflict:     result.PolicyConflict,
		Point:              point,
	}
}
