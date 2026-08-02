package governedfhe

import (
	"fmt"
	"sync"
	"sync/atomic"
)

const (
	maximumActiveN15Cases = 8
	maximumConcurrentN15  = 1
)

type evaluationAdmission struct {
	SchemaVersion              string   `json:"schemaVersion"`
	CaseID                     Digest   `json:"caseId"`
	CaseBindingDigest          Digest   `json:"caseBindingDigest"`
	ParticipantArtifactDigests []Digest `json:"participantArtifactDigests"`
	EvaluatorProvenance        Digest   `json:"evaluatorProvenance"`
	AdmittedAtUnix             int64    `json:"admittedAtUnix"`
}

type evaluationCompleted struct {
	SchemaVersion              string `json:"schemaVersion"`
	CaseID                     Digest `json:"caseId"`
	CaseBindingDigest          Digest `json:"caseBindingDigest"`
	EvaluatedArtifactDigest    Digest `json:"evaluatedArtifactDigest"`
	ResultCiphertextDigest     Digest `json:"resultCiphertextDigest"`
	ResultCiphertextCommitment Digest `json:"resultCiphertextCommitment"`
	CompletedAtUnix            int64  `json:"completedAtUnix"`
}

type recomputeAdmission struct {
	SchemaVersion              string   `json:"schemaVersion"`
	CaseID                     Digest   `json:"caseId"`
	CaseBindingDigest          Digest   `json:"caseBindingDigest"`
	ParticipantArtifactDigests []Digest `json:"participantArtifactDigests"`
	EvaluatedArtifactDigest    Digest   `json:"evaluatedArtifactDigest"`
	AdmittedAtUnix             int64    `json:"admittedAtUnix"`
}

type recomputeVerified struct {
	SchemaVersion              string    `json:"schemaVersion"`
	CaseID                     Digest    `json:"caseId"`
	CaseBindingDigest          Digest    `json:"caseBindingDigest"`
	EvaluatedArtifactDigest    Digest    `json:"evaluatedArtifactDigest"`
	RecomputedResultCiphertext ObjectRef `json:"recomputedResultCiphertext"`
	ResultCiphertextCommitment Digest    `json:"resultCiphertextCommitment"`
	VerifiedAtUnix             int64     `json:"verifiedAtUnix"`
}

type recomputeMismatch struct {
	SchemaVersion                    string `json:"schemaVersion"`
	CaseID                           Digest `json:"caseId"`
	CaseBindingDigest                Digest `json:"caseBindingDigest"`
	EvaluatedArtifactDigest          Digest `json:"evaluatedArtifactDigest"`
	EvaluatorResultCiphertextDigest  Digest `json:"evaluatorResultCiphertextDigest"`
	RecomputedResultCiphertextDigest Digest `json:"recomputedResultCiphertextDigest"`
	ErrorCode                        string `json:"errorCode"`
	DetectedAtUnix                   int64  `json:"detectedAtUnix"`
}

var n15Resources = struct {
	sync.Mutex
	active    map[string]struct{}
	semaphore chan struct{}
}{active: make(map[string]struct{}), semaphore: make(chan struct{}, maximumConcurrentN15)}

var evaluationExecutionCount atomic.Uint64
var recomputationExecutionCount atomic.Uint64
var releaseSignatureCount atomic.Uint64

func admitN15(caseID Digest, operation string) (func(), error) {
	if !nonzero(caseID) || operation == "" {
		return nil, ErrResourceAdmission
	}
	key := fmt.Sprintf("%s/%x", operation, caseID[:])
	n15Resources.Lock()
	defer n15Resources.Unlock()
	if _, exists := n15Resources.active[key]; exists || len(n15Resources.active) >= maximumActiveN15Cases {
		return nil, ErrResourceAdmission
	}
	select {
	case n15Resources.semaphore <- struct{}{}:
		n15Resources.active[key] = struct{}{}
	default:
		return nil, ErrResourceAdmission
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			n15Resources.Lock()
			delete(n15Resources.active, key)
			<-n15Resources.semaphore
			n15Resources.Unlock()
		})
	}, nil
}
