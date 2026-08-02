package oneshotruntime

import (
	"crypto/ecdh"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"path/filepath"
	"sync"

	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
	ceremony "mordant.dev/fhe-lab/lattigo/oneshotceremony"
)

type OperatorService struct {
	mu            sync.Mutex
	config        OperatorConfig
	configDigest  [32]byte
	params        bgv.Parameters
	identity      ceremony.OperatorIdentity
	signingKey    ed25519.PrivateKey
	encryptionKey *ecdh.PrivateKey
	storage       *ceremony.OperatorStorageCapability
	participant   *ceremony.Participant
	context       ceremony.Context
	runtimeState  string
}

func NewOperatorService(config OperatorConfig, params bgv.Parameters) (*OperatorService, error) {
	if config.validate() != nil {
		return nil, ErrConfig
	}
	identity, signing, encryption, storageIdentity, processInstance, err := config.localMaterial()
	if err != nil {
		return nil, err
	}
	boot, err := random32()
	if err != nil {
		return nil, err
	}
	storage, err := ceremony.OpenOperatorStorageCapability(ceremony.OperatorLocalStorageConfig{
		StateRoot:       config.StateRoot,
		StorageIdentity: storageIdentity,
		Identity:        identity,
		ProcessInstance: processInstance,
		BootSession:     encodeHex(boot[:]),
	})
	if err != nil {
		return nil, err
	}
	digest, err := OperatorConfigDigest(config)
	if err != nil {
		return nil, err
	}
	return &OperatorService{
		config:        config,
		configDigest:  digest,
		params:        params,
		identity:      identity,
		signingKey:    signing,
		encryptionKey: encryption,
		storage:       storage,
		runtimeState:  "READY",
	}, nil
}

func (s *OperatorService) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/prepare", s.handlePrepare)
	mux.HandleFunc("/v1/head", s.handleHead)
	mux.HandleFunc("/v1/reserve", s.handleReserve)
	mux.HandleFunc("/v1/accept-reservations", s.handleAcceptReservations)
	mux.HandleFunc("/v1/propose-transition", s.handleProposeTransition)
	mux.HandleFunc("/v1/sign-transition", s.handleSignTransition)
	mux.HandleFunc("/v1/commit-transition", s.handleCommitTransition)
	mux.HandleFunc("/v1/begin-secrets", s.handleBeginSecrets)
	mux.HandleFunc("/v1/crs-commit", s.handleCRSCommit)
	mux.HandleFunc("/v1/accept-crs-commit", s.handleAcceptCRSCommit)
	mux.HandleFunc("/v1/crs-reveal", s.handleCRSReveal)
	mux.HandleFunc("/v1/accept-crs-reveal", s.handleAcceptCRSReveal)
	mux.HandleFunc("/v1/private-messages", s.handlePrivateMessages)
	mux.HandleFunc("/v1/receive-private", s.handleReceivePrivate)
	mux.HandleFunc("/v1/accept-private", s.handleAcceptPrivate)
	mux.HandleFunc("/v1/public-key-share", s.handlePublicKeyShare)
	mux.HandleFunc("/v1/accept-public-key", s.handleAcceptPublicKey)
	mux.HandleFunc("/v1/relin-one", s.handleRelinOne)
	mux.HandleFunc("/v1/accept-relin-one", s.handleAcceptRelinOne)
	mux.HandleFunc("/v1/relin-two", s.handleRelinTwo)
	mux.HandleFunc("/v1/accept-relin-two", s.handleAcceptRelinTwo)
	mux.HandleFunc("/v1/galois-share", s.handleGaloisShare)
	mux.HandleFunc("/v1/accept-galois", s.handleAcceptGalois)
	mux.HandleFunc("/v1/public-state", s.handlePublicState)
	mux.HandleFunc("/v1/set-manifest", s.handleSetManifest)
	mux.HandleFunc("/v1/attest-bundle", s.handleAttestBundle)
	mux.HandleFunc("/v1/private-ready", s.handlePrivateReady)
	mux.HandleFunc("/v1/install-published", s.handleInstallPublished)
	mux.HandleFunc("/v1/set-completed", s.handleSetCompleted)
	mux.HandleFunc("/v1/finalize-private", s.handleFinalizePrivate)
	mux.HandleFunc("/v1/evidence", s.handleEvidence)
	mux.HandleFunc("/v1/phase", s.handlePhase)
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		response.Header().Set("Cache-Control", "no-store")
		response.Header().Set("X-Content-Type-Options", "nosniff")
		mux.ServeHTTP(response, request)
	})
}

func (s *OperatorService) withRequest(response http.ResponseWriter, request *http.Request, target any, operation func() (any, error)) {
	if request.Method != http.MethodPost || request.URL.RawQuery != "" || request.URL.Fragment != "" || request.Header.Get("Content-Type") != "application/json" {
		writeWireError(response, http.StatusBadRequest, "MALFORMED_REQUEST")
		return
	}
	request.Body = http.MaxBytesReader(response, request.Body, maxWireBytes)
	body, err := io.ReadAll(request.Body)
	if err != nil || len(body) == 0 {
		writeWireError(response, http.StatusBadRequest, "MALFORMED_REQUEST")
		return
	}
	var envelope wireRequest
	if strictDecode(body, &envelope) != nil || envelope.SchemaVersion != RuntimeWireSchema || len(envelope.Payload) == 0 || strictDecode(envelope.Payload, target) != nil {
		writeWireError(response, http.StatusBadRequest, "MALFORMED_REQUEST")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	result, err := operation()
	if err != nil {
		writeWireError(response, http.StatusConflict, publicErrorCode(err))
		return
	}
	writeWireSuccess(response, result)
}

func (s *OperatorService) requireParticipant() (*ceremony.Participant, error) {
	if s.participant == nil {
		return nil, ceremony.ErrState
	}
	return s.participant, nil
}

func (s *OperatorService) handlePrepare(w http.ResponseWriter, r *http.Request) {
	var input PrepareRequest
	s.withRequest(w, r, &input, func() (any, error) {
		if s.participant != nil || s.runtimeState != "READY" {
			return nil, ceremony.ErrReplay
		}
		context, err := ceremony.ParseContext(input.Context)
		if err != nil || !identitiesEqualContext(s.config.Roster, context) || context.Operators[s.identity.Point-1] != s.identity ||
			context.SchemaVersion != s.config.ContextSchema || context.ProtocolVersion != s.config.ProtocolVersion {
			return nil, ceremony.ErrBinding
		}
		participant, err := ceremony.NewParticipant(s.params, context, s.signingKey, s.encryptionKey, s.storage, cryptorand.Reader)
		if err != nil {
			return nil, err
		}
		s.participant = participant
		s.context = context
		s.runtimeState = "ACTIVE"
		return PhaseResponse{Phase: participant.Phase(), RuntimeState: s.runtimeState}, nil
	})
}

func (s *OperatorService) handleHead(w http.ResponseWriter, r *http.Request) {
	var input EmptyRequest
	s.withRequest(w, r, &input, func() (any, error) {
		participant, err := s.requireParticipant()
		if err != nil {
			return nil, err
		}
		head, err := participant.AttestReplicaHead()
		return HeadResponse{Head: head}, err
	})
}

func (s *OperatorService) handleReserve(w http.ResponseWriter, r *http.Request) {
	var input HeadsRequest
	s.withRequest(w, r, &input, func() (any, error) {
		participant, err := s.requireParticipant()
		if err != nil {
			return nil, err
		}
		if err := participant.Reserve(input.Heads); err != nil {
			s.runtimeState = "POISONED"
			return nil, err
		}
		reservation, err := participant.Reservation()
		if err != nil {
			return nil, err
		}
		encoded, err := reservation.MarshalBinary()
		return ReservationResponse{Reservation: encoded}, err
	})
}

func (s *OperatorService) handleAcceptReservations(w http.ResponseWriter, r *http.Request) {
	var input ReservationsRequest
	s.withRequest(w, r, &input, func() (any, error) {
		participant, err := s.requireParticipant()
		if err != nil {
			return nil, err
		}
		reservations, err := parseReservations(input.Reservations)
		if err != nil {
			return nil, err
		}
		return PhaseResponse{Phase: participant.Phase(), RuntimeState: s.runtimeState}, participant.AcceptReservations(reservations)
	})
}

func (s *OperatorService) handleProposeTransition(w http.ResponseWriter, r *http.Request) {
	var input TransitionProposalRequest
	s.withRequest(w, r, &input, func() (any, error) {
		participant, err := s.requireParticipant()
		if err != nil {
			return nil, err
		}
		statement, err := participant.ProposedTransition(input.ToPhase, input.ReasonDigest)
		return TransitionProposalResponse{Statement: statement}, err
	})
}

func (s *OperatorService) handleSignTransition(w http.ResponseWriter, r *http.Request) {
	var input SignTransitionRequest
	s.withRequest(w, r, &input, func() (any, error) {
		participant, err := s.requireParticipant()
		if err != nil {
			return nil, err
		}
		signature, err := participant.SignTransition(input.Statement, input.Heads)
		if err != nil {
			s.runtimeState = "POISONED"
		}
		return SignTransitionResponse{Signature: signature}, err
	})
}

func (s *OperatorService) handleCommitTransition(w http.ResponseWriter, r *http.Request) {
	var input CommitTransitionRequest
	s.withRequest(w, r, &input, func() (any, error) {
		participant, err := s.requireParticipant()
		if err != nil {
			return nil, err
		}
		record, err := ceremony.ParseWitnessRecord(input.Record)
		if err != nil {
			return nil, err
		}
		if err := participant.CommitTransition(record); err != nil {
			s.runtimeState = "POISONED"
			return nil, err
		}
		if participant.Phase() == ceremony.PhaseCompleted {
			s.runtimeState = "COMPLETED"
		} else if participant.Phase() == ceremony.PhaseAborted {
			s.runtimeState = "ABORTED"
		}
		return PhaseResponse{Phase: participant.Phase(), RuntimeState: s.runtimeState}, nil
	})
}

func (s *OperatorService) handleBeginSecrets(w http.ResponseWriter, r *http.Request) {
	var input HeadsRequest
	s.withGeneration(w, r, &input, func(p *ceremony.Participant) (any, error) {
		return PhaseResponse{Phase: p.Phase(), RuntimeState: s.runtimeState}, p.BeginSecrets(input.Heads)
	})
}

func (s *OperatorService) handleCRSCommit(w http.ResponseWriter, r *http.Request) {
	var input HeadsRequest
	s.withGeneration(w, r, &input, func(p *ceremony.Participant) (any, error) {
		envelope, err := p.CRSCommitEnvelope(input.Heads)
		if err != nil {
			return nil, err
		}
		encoded, err := envelope.MarshalBinary()
		return EnvelopeResponse{Envelope: encoded}, err
	})
}

func (s *OperatorService) handleAcceptCRSCommit(w http.ResponseWriter, r *http.Request) {
	var input EnvelopesRequest
	s.withMutation(w, r, &input, func(p *ceremony.Participant) (any, error) {
		envelopes, err := parseEnvelopes(input.Envelopes)
		if err != nil {
			return nil, err
		}
		return PhaseResponse{Phase: p.Phase(), RuntimeState: s.runtimeState}, p.AcceptCRSCommitStage(envelopes)
	})
}

func (s *OperatorService) handleCRSReveal(w http.ResponseWriter, r *http.Request) {
	var input HeadsRequest
	s.withGeneration(w, r, &input, func(p *ceremony.Participant) (any, error) {
		envelope, err := p.CRSRevealEnvelope(input.Heads)
		if err != nil {
			return nil, err
		}
		encoded, err := envelope.MarshalBinary()
		return EnvelopeResponse{Envelope: encoded}, err
	})
}

func (s *OperatorService) handleAcceptCRSReveal(w http.ResponseWriter, r *http.Request) {
	type request struct {
		Envelopes [][]byte                          `json:"envelopes"`
		Heads     []ceremony.ReplicaHeadAttestation `json:"heads"`
	}
	var input request
	s.withMutation(w, r, &input, func(p *ceremony.Participant) (any, error) {
		envelopes, err := parseEnvelopes(input.Envelopes)
		if err != nil {
			return nil, err
		}
		return PhaseResponse{Phase: p.Phase(), RuntimeState: s.runtimeState}, p.AcceptCRSRevealStage(envelopes, input.Heads)
	})
}

func (s *OperatorService) handlePrivateMessages(w http.ResponseWriter, r *http.Request) {
	var input HeadsRequest
	s.withGeneration(w, r, &input, func(p *ceremony.Participant) (any, error) {
		messages, err := p.PrivateMessages(input.Heads)
		if err != nil {
			return nil, err
		}
		encoded, err := marshalPrivateMessages(messages)
		return PrivateMessagesResponse{Messages: encoded}, err
	})
}

func (s *OperatorService) handleReceivePrivate(w http.ResponseWriter, r *http.Request) {
	var input PrivateMessagesRequest
	s.withGeneration(w, r, &input, func(p *ceremony.Participant) (any, error) {
		messages, err := parsePrivateMessages(input.Messages)
		if err != nil {
			return nil, err
		}
		receipts, err := p.ReceivePrivateMessages(messages, input.Heads)
		if err != nil {
			return nil, err
		}
		encoded, err := marshalEnvelopes(receipts)
		return PrivateReceiptsResponse{Receipts: encoded}, err
	})
}

func (s *OperatorService) handleAcceptPrivate(w http.ResponseWriter, r *http.Request) {
	var input PrivateStageRequest
	s.withMutation(w, r, &input, func(p *ceremony.Participant) (any, error) {
		messages, err := parsePrivateMessages(input.Messages)
		if err != nil {
			return nil, err
		}
		receipts, err := parseEnvelopes(input.Receipts)
		if err != nil {
			return nil, err
		}
		return PhaseResponse{Phase: p.Phase(), RuntimeState: s.runtimeState}, p.AcceptPrivateStage(messages, receipts)
	})
}

func (s *OperatorService) handlePublicKeyShare(w http.ResponseWriter, r *http.Request) {
	var input HeadsRequest
	s.withEnvelopeGeneration(w, r, &input, func(p *ceremony.Participant) (ceremony.SignedEnvelope, error) {
		return p.PublicKeyShareEnvelope(input.Heads)
	})
}

func (s *OperatorService) handleAcceptPublicKey(w http.ResponseWriter, r *http.Request) {
	s.handleAcceptEnvelopesWithHeads(w, r, func(p *ceremony.Participant, envelopes []ceremony.SignedEnvelope, heads []ceremony.ReplicaHeadAttestation) error {
		return p.AcceptPublicKeyStage(envelopes, heads)
	})
}

func (s *OperatorService) handleRelinOne(w http.ResponseWriter, r *http.Request) {
	var input HeadsRequest
	s.withEnvelopeGeneration(w, r, &input, func(p *ceremony.Participant) (ceremony.SignedEnvelope, error) {
		return p.RelinRoundOneEnvelope(input.Heads)
	})
}

func (s *OperatorService) handleAcceptRelinOne(w http.ResponseWriter, r *http.Request) {
	s.handleAcceptEnvelopesWithHeads(w, r, func(p *ceremony.Participant, envelopes []ceremony.SignedEnvelope, heads []ceremony.ReplicaHeadAttestation) error {
		return p.AcceptRelinRoundOneStage(envelopes, heads)
	})
}

func (s *OperatorService) handleRelinTwo(w http.ResponseWriter, r *http.Request) {
	var input HeadsRequest
	s.withEnvelopeGeneration(w, r, &input, func(p *ceremony.Participant) (ceremony.SignedEnvelope, error) {
		return p.RelinRoundTwoEnvelope(input.Heads)
	})
}

func (s *OperatorService) handleAcceptRelinTwo(w http.ResponseWriter, r *http.Request) {
	s.handleAcceptEnvelopesWithHeads(w, r, func(p *ceremony.Participant, envelopes []ceremony.SignedEnvelope, heads []ceremony.ReplicaHeadAttestation) error {
		return p.AcceptRelinRoundTwoStage(envelopes, heads)
	})
}

func (s *OperatorService) handleGaloisShare(w http.ResponseWriter, r *http.Request) {
	var input GaloisRequest
	s.withGeneration(w, r, &input, func(p *ceremony.Participant) (any, error) {
		envelope, err := p.GaloisShareEnvelope(input.Index, input.Heads)
		if err != nil {
			return nil, err
		}
		encoded, err := envelope.MarshalBinary()
		return EnvelopeResponse{Envelope: encoded}, err
	})
}

func (s *OperatorService) handleAcceptGalois(w http.ResponseWriter, r *http.Request) {
	var input AcceptGaloisRequest
	s.withMutation(w, r, &input, func(p *ceremony.Participant) (any, error) {
		envelopes, err := parseEnvelopes(input.Envelopes)
		if err != nil {
			return nil, err
		}
		return PhaseResponse{Phase: p.Phase(), RuntimeState: s.runtimeState}, p.AcceptGaloisStage(input.Index, envelopes, input.Heads)
	})
}

func (s *OperatorService) handlePublicState(w http.ResponseWriter, r *http.Request) {
	var input HeadsRequest
	s.withGeneration(w, r, &input, func(p *ceremony.Participant) (any, error) {
		material, err := p.PublicMaterial(input.Heads)
		if err != nil {
			return nil, err
		}
		transcript, err := p.Transcript().MarshalBinary()
		if err != nil {
			return nil, err
		}
		records := p.Records()
		if len(records) == 0 {
			return nil, ceremony.ErrState
		}
		return PublicStateResponse{Transcript: transcript, PublicKey: material.PublicKeyBytes, RelinearizationKey: material.RelinearizationBytes, GaloisKeys: material.GaloisKeyBytes, PreManifestWitness: records[len(records)-1].Digest()}, nil
	})
}

func (s *OperatorService) handleSetManifest(w http.ResponseWriter, r *http.Request) {
	var input DigestRequest
	s.withMutation(w, r, &input, func(p *ceremony.Participant) (any, error) {
		return PhaseResponse{Phase: p.Phase(), RuntimeState: s.runtimeState}, p.SetManifestPending(input.Digest)
	})
}

func (s *OperatorService) handleAttestBundle(w http.ResponseWriter, r *http.Request) {
	var input UnsignedBundleRequest
	s.withGeneration(w, r, &input, func(p *ceremony.Participant) (any, error) {
		unsigned, err := ceremony.ParseUnsignedPublicBundle(input.UnsignedBundle)
		if err != nil {
			return nil, err
		}
		envelope, err := p.AttestUnsignedBundle(unsigned, input.Heads)
		if err != nil {
			return nil, err
		}
		encoded, err := envelope.MarshalBinary()
		return EnvelopeResponse{Envelope: encoded}, err
	})
}

func (s *OperatorService) handlePrivateReady(w http.ResponseWriter, r *http.Request) {
	var input UnsignedBundleRequest
	s.withGeneration(w, r, &input, func(p *ceremony.Participant) (any, error) {
		unsigned, err := ceremony.ParseUnsignedPublicBundle(input.UnsignedBundle)
		if err != nil {
			return nil, err
		}
		envelope, err := p.AttestPrivateReadiness(unsigned, input.Heads)
		if err != nil {
			return nil, err
		}
		encoded, err := envelope.MarshalBinary()
		return EnvelopeResponse{Envelope: encoded}, err
	})
}

func (s *OperatorService) handleInstallPublished(w http.ResponseWriter, r *http.Request) {
	var input PublishedRequest
	s.withMutation(w, r, &input, func(p *ceremony.Participant) (any, error) {
		bundle, err := ceremony.ParsePublicBundle(input.Bundle)
		if err != nil || input.Receipt.ObjectPath != filepath.Join(s.config.PublicationRoot, "public.bundle") {
			return nil, ceremony.ErrPersistence
		}
		if ceremony.VerifyPublicationReceipt(input.Receipt, bundle) != nil {
			local, publishErr := ceremony.PublishPublicBundle(s.config.PublicationRoot, bundle)
			if publishErr != nil || local.Digest() != input.Receipt.Digest() {
				return nil, ceremony.ErrPersistence
			}
		}
		return PhaseResponse{Phase: p.Phase(), RuntimeState: s.runtimeState}, p.SetPublishedPending(bundle, input.Receipt)
	})
}

func (s *OperatorService) handleSetCompleted(w http.ResponseWriter, r *http.Request) {
	var input PublishedRequest
	s.withMutation(w, r, &input, func(p *ceremony.Participant) (any, error) {
		bundle, err := ceremony.ParsePublicBundle(input.Bundle)
		if err != nil {
			return nil, err
		}
		return PhaseResponse{Phase: p.Phase(), RuntimeState: s.runtimeState}, p.SetCompletedPending(bundle, input.Receipt)
	})
}

func (s *OperatorService) handleFinalizePrivate(w http.ResponseWriter, r *http.Request) {
	var input FinalizeRequest
	s.withMutation(w, r, &input, func(p *ceremony.Participant) (any, error) {
		bundle, err := ceremony.ParsePublicBundle(input.Bundle)
		if err != nil {
			return nil, err
		}
		replicas, err := parseReplicas(input.Replicas)
		if err != nil {
			return nil, err
		}
		_, err = p.FinalizeCompletedOperatorBundle(bundle, input.Receipt, input.Heads, replicas...)
		if err != nil {
			return nil, err
		}
		return FinalizeResponse{Finalized: true}, nil
	})
}

func (s *OperatorService) handleEvidence(w http.ResponseWriter, r *http.Request) {
	var input EvidenceRequest
	s.withRequest(w, r, &input, func() (any, error) {
		context, err := ceremony.ParseContext(input.Context)
		if err != nil || !identitiesEqualContext(s.config.Roster, context) || context.Operators[s.identity.Point-1] != s.identity {
			return nil, ceremony.ErrBinding
		}
		records, err := s.storage.PublicWitnessRecords(context.CeremonyID())
		if err != nil {
			return nil, err
		}
		encoded, err := marshalRecords(records)
		if err != nil {
			return nil, err
		}
		var tombstoneBytes []byte
		if tombstone, tombstoneErr := s.storage.PublicTerminalTombstone(context.CeremonyID()); tombstoneErr == nil {
			tombstoneBytes, err = tombstone.MarshalBinary()
			if err != nil {
				return nil, err
			}
		}
		phase := ceremony.PhaseNotStarted
		state := "DURABLE_EVIDENCE"
		if s.participant != nil && s.context.ContextDigest() == context.ContextDigest() {
			phase = s.participant.Phase()
			state = s.runtimeState
		} else if len(records) > 0 {
			phase = records[len(records)-1].Statement.ToPhase
		}
		return OperatorEvidenceResponse{Identity: s.config.Identity, ConfigurationHash: s.configDigest, Phase: phase, RuntimeState: state, Records: encoded, TerminalTombstone: tombstoneBytes}, nil
	})
}

func (s *OperatorService) handlePhase(w http.ResponseWriter, r *http.Request) {
	var input EmptyRequest
	s.withRequest(w, r, &input, func() (any, error) {
		if s.participant == nil {
			return PhaseResponse{Phase: ceremony.PhaseNotStarted, RuntimeState: s.runtimeState}, nil
		}
		return PhaseResponse{Phase: s.participant.Phase(), RuntimeState: s.runtimeState}, nil
	})
}

func (s *OperatorService) withMutation(w http.ResponseWriter, r *http.Request, input any, operation func(*ceremony.Participant) (any, error)) {
	s.withRequest(w, r, input, func() (any, error) {
		participant, err := s.requireParticipant()
		if err != nil {
			return nil, err
		}
		return operation(participant)
	})
}

func (s *OperatorService) withGeneration(w http.ResponseWriter, r *http.Request, input any, operation func(*ceremony.Participant) (any, error)) {
	s.withRequest(w, r, input, func() (any, error) {
		participant, err := s.requireParticipant()
		if err != nil {
			return nil, err
		}
		result, err := operation(participant)
		if err != nil {
			s.runtimeState = "POISONED"
		}
		return result, err
	})
}

func (s *OperatorService) withEnvelopeGeneration(w http.ResponseWriter, r *http.Request, input any, operation func(*ceremony.Participant) (ceremony.SignedEnvelope, error)) {
	s.withGeneration(w, r, input, func(p *ceremony.Participant) (any, error) {
		envelope, err := operation(p)
		if err != nil {
			return nil, err
		}
		encoded, err := envelope.MarshalBinary()
		return EnvelopeResponse{Envelope: encoded}, err
	})
}

func (s *OperatorService) handleAcceptEnvelopesWithHeads(w http.ResponseWriter, r *http.Request, accept func(*ceremony.Participant, []ceremony.SignedEnvelope, []ceremony.ReplicaHeadAttestation) error) {
	type request struct {
		Envelopes [][]byte                          `json:"envelopes"`
		Heads     []ceremony.ReplicaHeadAttestation `json:"heads"`
	}
	var input request
	s.withMutation(w, r, &input, func(p *ceremony.Participant) (any, error) {
		envelopes, err := parseEnvelopes(input.Envelopes)
		if err != nil {
			return nil, err
		}
		return PhaseResponse{Phase: p.Phase(), RuntimeState: s.runtimeState}, accept(p, envelopes, input.Heads)
	})
}

func writeWireSuccess(response http.ResponseWriter, value any) {
	payload, err := json.Marshal(value)
	if err != nil {
		writeWireError(response, http.StatusInternalServerError, "INTERNAL_REJECTED")
		return
	}
	response.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(response).Encode(wireResponse{SchemaVersion: RuntimeWireSchema, OK: true, Payload: payload})
}

func writeWireError(response http.ResponseWriter, status int, code string) {
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(wireResponse{SchemaVersion: RuntimeWireSchema, OK: false, ErrorCode: code})
}

func publicErrorCode(err error) string {
	switch {
	case errors.Is(err, ceremony.ErrBinding):
		return "BINDING_REJECTED"
	case errors.Is(err, ceremony.ErrState):
		return "STATE_REJECTED"
	case errors.Is(err, ceremony.ErrReplay):
		return "REPLAY_REJECTED"
	case errors.Is(err, ceremony.ErrSignature):
		return "SIGNATURE_REJECTED"
	case errors.Is(err, ceremony.ErrMaterial):
		return "MATERIAL_REJECTED"
	case errors.Is(err, ceremony.ErrTerminal):
		return "TERMINAL_REJECTED"
	case errors.Is(err, ceremony.ErrPersistence):
		return "PERSISTENCE_REJECTED"
	case errors.Is(err, ceremony.ErrSecretAccess):
		return "SECRET_ACCESS_REJECTED"
	default:
		return "OPERATION_REJECTED"
	}
}
