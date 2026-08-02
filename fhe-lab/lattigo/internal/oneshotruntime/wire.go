package oneshotruntime

import (
	ceremony "mordant.dev/fhe-lab/lattigo/oneshotceremony"
)

const (
	maxWireBytes     = 96 << 20
	maxResponseBytes = int64(96 << 20)
)

type wireRequest struct {
	SchemaVersion string `json:"schemaVersion" required:"true"`
	Authorization []byte `json:"authorization,omitempty"`
	Request       []byte `json:"request,omitempty"`
	Payload       []byte `json:"payload" required:"true"`
}

type wireResponse struct {
	SchemaVersion string `json:"schemaVersion" required:"true"`
	OK            bool   `json:"ok" required:"true" allowzero:"true"`
	Payload       []byte `json:"payload,omitempty"`
	ErrorCode     string `json:"errorCode,omitempty"`
}

type EmptyRequest struct{}

type PrepareRequest struct {
	Context []byte `json:"context" required:"true"`
}

type HeadsRequest struct {
	Heads [][]byte `json:"heads" required:"true"`
}

type ReservationResponse struct {
	Reservation []byte `json:"reservation" required:"true"`
}

type ReservationsRequest struct {
	Reservations [][]byte `json:"reservations" required:"true"`
}

type HeadResponse struct {
	Head []byte `json:"head" required:"true"`
}

type TransitionProposalRequest struct {
	ToPhase      ceremony.Phase `json:"toPhase" required:"true"`
	ReasonDigest [32]byte       `json:"reasonDigest" required:"true" allowzero:"true"`
}

type TransitionProposalResponse struct {
	Statement []byte `json:"statement" required:"true"`
}

type SignTransitionRequest struct {
	Statement []byte   `json:"statement" required:"true"`
	Heads     [][]byte `json:"heads" required:"true"`
}

type SignTransitionResponse struct {
	Signature []byte `json:"signature" required:"true"`
}

type CommitTransitionRequest struct {
	Record []byte `json:"record" required:"true"`
}

type EnvelopesRequest struct {
	Envelopes [][]byte `json:"envelopes" required:"true"`
}

type EnvelopeResponse struct {
	Envelope []byte `json:"envelope" required:"true"`
}

type PrivateMessagesResponse struct {
	Messages [][]byte `json:"messages" required:"true"`
}

type PrivateMessagesRequest struct {
	Messages [][]byte `json:"messages" required:"true"`
	Heads    [][]byte `json:"heads" required:"true"`
}

type PrivateReceiptsResponse struct {
	Receipts [][]byte `json:"receipts" required:"true"`
}

type PrivateStageRequest struct {
	Messages [][]byte `json:"messages" required:"true"`
	Receipts [][]byte `json:"receipts" required:"true"`
}

type GaloisRequest struct {
	Index int      `json:"index" required:"true" allowzero:"true"`
	Heads [][]byte `json:"heads" required:"true"`
}

type AcceptGaloisRequest struct {
	Index     int      `json:"index" required:"true" allowzero:"true"`
	Envelopes [][]byte `json:"envelopes" required:"true"`
	Heads     [][]byte `json:"heads" required:"true"`
}

type PublicStateResponse struct {
	Transcript         []byte   `json:"transcript" required:"true"`
	PublicKey          []byte   `json:"publicKey" required:"true"`
	RelinearizationKey []byte   `json:"relinearizationKey" required:"true"`
	GaloisKeys         [][]byte `json:"galoisKeys" required:"true"`
	PreManifestWitness [32]byte `json:"preManifestWitness" required:"true"`
}

type DigestRequest struct {
	Digest [32]byte `json:"digest" required:"true"`
}

type UnsignedBundleRequest struct {
	UnsignedBundle []byte   `json:"unsignedBundle" required:"true"`
	Heads          [][]byte `json:"heads" required:"true"`
}

type PublishedRequest struct {
	Bundle  []byte `json:"bundle" required:"true"`
	Receipt []byte `json:"receipt" required:"true"`
}

type FinalizeRequest struct {
	Bundle   []byte     `json:"bundle" required:"true"`
	Receipt  []byte     `json:"receipt" required:"true"`
	Heads    [][]byte   `json:"heads" required:"true"`
	Replicas [][][]byte `json:"replicas" required:"true"`
}

type FinalizeResponse struct {
	Finalized bool `json:"finalized" required:"true"`
}

type EvidenceRequest struct {
	Context []byte `json:"context" required:"true"`
}

type OperatorEvidenceResponse struct {
	Identity          PublicIdentity `json:"identity" required:"true"`
	ConfigurationHash [32]byte       `json:"configurationHash" required:"true"`
	Phase             ceremony.Phase `json:"phase" required:"true" allowzero:"true"`
	Disposition       string         `json:"disposition" required:"true"`
	Records           [][]byte       `json:"records" required:"true" allowzero:"true"`
	TerminalTombstone []byte         `json:"terminalTombstone,omitempty"`
}

type PhaseResponse struct {
	Phase       ceremony.Phase `json:"phase" required:"true" allowzero:"true"`
	Disposition string         `json:"disposition" required:"true"`
}

func marshalEnvelopes(input []ceremony.SignedEnvelope) ([][]byte, error) {
	result := make([][]byte, len(input))
	for index := range input {
		encoded, err := input[index].MarshalBinary()
		if err != nil {
			return nil, err
		}
		result[index] = encoded
	}
	return result, nil
}

func parseEnvelopes(input [][]byte) ([]ceremony.SignedEnvelope, error) {
	result := make([]ceremony.SignedEnvelope, len(input))
	for index := range input {
		parsed, err := ceremony.ParseSignedEnvelope(input[index])
		if err != nil {
			return nil, err
		}
		result[index] = parsed
	}
	return result, nil
}

func marshalPrivateMessages(input []ceremony.SealedPrivateMessage) ([][]byte, error) {
	result := make([][]byte, len(input))
	for index := range input {
		encoded, err := input[index].MarshalBinary()
		if err != nil {
			return nil, err
		}
		result[index] = encoded
	}
	return result, nil
}

func parsePrivateMessages(input [][]byte) ([]ceremony.SealedPrivateMessage, error) {
	result := make([]ceremony.SealedPrivateMessage, len(input))
	for index := range input {
		parsed, err := ceremony.ParseSealedPrivateMessage(input[index])
		if err != nil {
			return nil, err
		}
		result[index] = parsed
	}
	return result, nil
}

func parseReservations(input [][]byte) ([]ceremony.AttemptReservation, error) {
	result := make([]ceremony.AttemptReservation, len(input))
	for index := range input {
		parsed, err := ceremony.ParseAttemptReservation(input[index])
		if err != nil {
			return nil, err
		}
		result[index] = parsed
	}
	return result, nil
}

func parseReplicas(input [][][]byte) ([][]ceremony.WitnessRecord, error) {
	result := make([][]ceremony.WitnessRecord, len(input))
	for replica := range input {
		result[replica] = make([]ceremony.WitnessRecord, len(input[replica]))
		for index := range input[replica] {
			parsed, err := ceremony.ParseWitnessRecord(input[replica][index])
			if err != nil {
				return nil, err
			}
			result[replica][index] = parsed
		}
	}
	return result, nil
}

func marshalRecords(input []ceremony.WitnessRecord) ([][]byte, error) {
	result := make([][]byte, len(input))
	for index := range input {
		encoded, err := input[index].MarshalBinary()
		if err != nil {
			return nil, err
		}
		result[index] = encoded
	}
	return result, nil
}

type wireLimits struct {
	Request  int64
	Response int64
}

func limitsForOperation(path string) (wireLimits, bool) {
	small := wireLimits{Request: 256 << 10, Response: 256 << 10}
	medium := wireLimits{Request: 8 << 20, Response: 8 << 20}
	large := wireLimits{Request: maxWireBytes, Response: maxResponseBytes}
	switch path {
	case "/v1/prepare", "/v1/head", "/v1/reserve", "/v1/propose-transition", "/v1/sign-transition", "/v1/commit-transition",
		"/v1/begin-secrets", "/v1/crs-commit", "/v1/crs-reveal", "/v1/set-manifest", "/v1/phase":
		return small, true
	case "/v1/accept-reservations", "/v1/accept-crs-commit", "/v1/accept-crs-reveal", "/v1/accept-public-key",
		"/v1/accept-relin-one", "/v1/accept-relin-two", "/v1/accept-galois", "/v1/attest-bundle", "/v1/private-ready",
		"/v1/public-key-share", "/v1/relin-one", "/v1/relin-two", "/v1/galois-share":
		return medium, true
	case "/v1/private-messages", "/v1/receive-private", "/v1/accept-private", "/v1/public-state", "/v1/install-published",
		"/v1/set-completed", "/v1/finalize-private", "/v1/evidence":
		return large, true
	default:
		return wireLimits{}, false
	}
}

func protectedOperation(path string) bool {
	switch path {
	case "/v1/phase":
		return false
	default:
		_, allowed := limitsForOperation(path)
		return allowed
	}
}
