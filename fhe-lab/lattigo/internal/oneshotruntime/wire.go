package oneshotruntime

import (
	"bytes"
	"encoding/json"
	"io"

	ceremony "mordant.dev/fhe-lab/lattigo/oneshotceremony"
)

const maxWireBytes = 96 << 20

type wireRequest struct {
	SchemaVersion string          `json:"schemaVersion"`
	Payload       json.RawMessage `json:"payload"`
}

type wireResponse struct {
	SchemaVersion string          `json:"schemaVersion"`
	OK            bool            `json:"ok"`
	Payload       json.RawMessage `json:"payload,omitempty"`
	ErrorCode     string          `json:"errorCode,omitempty"`
}

type EmptyRequest struct{}

type PrepareRequest struct {
	Context []byte `json:"context"`
}

type HeadsRequest struct {
	Heads []ceremony.ReplicaHeadAttestation `json:"heads"`
}

type ReservationResponse struct {
	Reservation []byte `json:"reservation"`
}

type ReservationsRequest struct {
	Reservations [][]byte `json:"reservations"`
}

type HeadResponse struct {
	Head ceremony.ReplicaHeadAttestation `json:"head"`
}

type TransitionProposalRequest struct {
	ToPhase      ceremony.Phase `json:"toPhase"`
	ReasonDigest [32]byte       `json:"reasonDigest"`
}

type TransitionProposalResponse struct {
	Statement ceremony.WitnessStatement `json:"statement"`
}

type SignTransitionRequest struct {
	Statement ceremony.WitnessStatement         `json:"statement"`
	Heads     []ceremony.ReplicaHeadAttestation `json:"heads"`
}

type SignTransitionResponse struct {
	Signature ceremony.WitnessSignature `json:"signature"`
}

type CommitTransitionRequest struct {
	Record []byte `json:"record"`
}

type EnvelopesRequest struct {
	Envelopes [][]byte `json:"envelopes"`
}

type EnvelopeResponse struct {
	Envelope []byte `json:"envelope"`
}

type PrivateMessagesResponse struct {
	Messages [][]byte `json:"messages"`
}

type PrivateMessagesRequest struct {
	Messages [][]byte                          `json:"messages"`
	Heads    []ceremony.ReplicaHeadAttestation `json:"heads"`
}

type PrivateReceiptsResponse struct {
	Receipts [][]byte `json:"receipts"`
}

type PrivateStageRequest struct {
	Messages [][]byte `json:"messages"`
	Receipts [][]byte `json:"receipts"`
}

type GaloisRequest struct {
	Index int                               `json:"index"`
	Heads []ceremony.ReplicaHeadAttestation `json:"heads"`
}

type AcceptGaloisRequest struct {
	Index     int                               `json:"index"`
	Envelopes [][]byte                          `json:"envelopes"`
	Heads     []ceremony.ReplicaHeadAttestation `json:"heads"`
}

type PublicStateResponse struct {
	Transcript         []byte   `json:"transcript"`
	PublicKey          []byte   `json:"publicKey"`
	RelinearizationKey []byte   `json:"relinearizationKey"`
	GaloisKeys         [][]byte `json:"galoisKeys"`
	PreManifestWitness [32]byte `json:"preManifestWitness"`
}

type DigestRequest struct {
	Digest [32]byte `json:"digest"`
}

type UnsignedBundleRequest struct {
	UnsignedBundle []byte                            `json:"unsignedBundle"`
	Heads          []ceremony.ReplicaHeadAttestation `json:"heads"`
}

type PublishedRequest struct {
	Bundle  []byte                      `json:"bundle"`
	Receipt ceremony.PublicationReceipt `json:"receipt"`
}

type FinalizeRequest struct {
	Bundle   []byte                            `json:"bundle"`
	Receipt  ceremony.PublicationReceipt       `json:"receipt"`
	Heads    []ceremony.ReplicaHeadAttestation `json:"heads"`
	Replicas [][][]byte                        `json:"replicas"`
}

type FinalizeResponse struct {
	Finalized bool `json:"finalized"`
}

type EvidenceRequest struct {
	Context []byte `json:"context"`
}

type OperatorEvidenceResponse struct {
	Identity          PublicIdentity `json:"identity"`
	ConfigurationHash [32]byte       `json:"configurationHash"`
	Phase             ceremony.Phase `json:"phase"`
	RuntimeState      string         `json:"runtimeState"`
	Records           [][]byte       `json:"records"`
	TerminalTombstone []byte         `json:"terminalTombstone,omitempty"`
}

type PhaseResponse struct {
	Phase        ceremony.Phase `json:"phase"`
	RuntimeState string         `json:"runtimeState"`
}

func strictDecode(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return ErrTransport
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return ErrTransport
	}
	return nil
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
