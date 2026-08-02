package oneshotruntime

import (
	"crypto/ecdh"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

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
	journal       *requestJournal
	journalFailed bool
	authority     ed25519.PublicKey
	participant   *ceremony.Participant
	context       ceremony.Context
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
	journal, err := openRequestJournal(config.StateRoot, identity.Point)
	if err != nil {
		return nil, err
	}
	authority, err := decodePublicKey(config.SessionAuthorityPublicKey)
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
		journal:       journal,
		authority:     authority,
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
	limits, known := limitsForOperation(request.URL.Path)
	if !known || request.Method != http.MethodPost || request.URL.RawQuery != "" || request.URL.Fragment != "" || request.Header.Get("Content-Type") != "application/json" {
		writeWireError(response, http.StatusBadRequest, "MALFORMED_REQUEST")
		return
	}
	request.Body = http.MaxBytesReader(response, request.Body, limits.Request)
	body, err := io.ReadAll(request.Body)
	if err != nil || len(body) == 0 || int64(len(body)) > limits.Request {
		writeWireError(response, http.StatusBadRequest, "MALFORMED_REQUEST")
		return
	}
	var envelope wireRequest
	if decodeStrictJSON(body, &envelope) != nil || envelope.SchemaVersion != RuntimeWireSchema || len(envelope.Payload) == 0 || decodeCanonicalPayload(envelope.Payload, target) != nil {
		writeWireError(response, http.StatusBadRequest, "MALFORMED_REQUEST")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if protectedOperation(request.URL.Path) {
		contextValue := s.context
		if request.URL.Path == "/v1/prepare" {
			prepare, ok := target.(*PrepareRequest)
			if !ok {
				writeWireError(response, http.StatusBadRequest, "MALFORMED_REQUEST")
				return
			}
			contextValue, err = ceremony.ParseContext(prepare.Context)
			if err != nil {
				writeWireError(response, http.StatusBadRequest, "MALFORMED_REQUEST")
				return
			}
		}
		authorization, authorizationErr := ParseSessionAuthorization(envelope.Authorization)
		authorizedRequest, requestErr := ParseAuthorizedRequest(envelope.Request)
		now := time.Now().UTC()
		if authorizationErr != nil || requestErr != nil || verifySessionAuthorizationSignature(s.authority, authorization, now) != nil ||
			VerifyAuthorizedRequest(authorization, authorizedRequest, request.URL.Path, envelope.Payload, now) != nil {
			writeWireError(response, http.StatusUnauthorized, "AUTHORIZATION_REJECTED")
			return
		}
		binding := journalBinding(authorization, authorizedRequest, s.identity.Point)
		prior, journalErr := s.journal.lookupExact(binding)
		if journalErr != nil {
			if errors.Is(journalErr, ErrRequestPending) {
				writeWireError(response, http.StatusConflict, "REQUEST_PENDING")
				return
			}
			writeWireError(response, http.StatusConflict, publicErrorCode(journalErr))
			return
		}
		if prior.Found {
			writeWireBytesStatus(response, prior.HTTPStatus, prior.Response)
			return
		}
		if VerifySessionAuthorization(s.authority, contextValue, authorization, now) != nil {
			writeWireError(response, http.StatusUnauthorized, "AUTHORIZATION_REJECTED")
			return
		}
		s.runtimeFault(runtimeFaultAfterAuthorization, request.URL.Path)
		prior, journalErr = s.journal.lookup(binding, now)
		if journalErr != nil {
			if errors.Is(journalErr, ErrRequestPending) {
				writeWireError(response, http.StatusConflict, "REQUEST_PENDING")
				return
			}
			writeWireError(response, http.StatusConflict, publicErrorCode(journalErr))
			return
		}
		if prior.Found {
			writeWireBytesStatus(response, prior.HTTPStatus, prior.Response)
			return
		}
		if s.journalFailed {
			writeWireError(response, http.StatusInternalServerError, "JOURNAL_REJECTED")
			return
		}
		if journalErr := s.journal.admit(binding, limits.Response, now); journalErr != nil {
			writeWireError(response, http.StatusConflict, publicErrorCode(journalErr))
			return
		}
		s.runtimeFault(runtimeFaultAfterPending, request.URL.Path)
		result, operationErr := operation()
		s.runtimeFault(runtimeFaultAfterOperation, request.URL.Path)
		status := http.StatusOK
		var encoded []byte
		var encodeErr error
		if operationErr != nil {
			status = http.StatusConflict
			encoded, encodeErr = marshalWireError(publicErrorCode(operationErr), limits.Response)
		} else {
			encoded, encodeErr = marshalWireSuccess(result, limits.Response)
		}
		if encodeErr != nil {
			s.journalFailed = true
			writeWireError(response, http.StatusInternalServerError, "JOURNAL_REJECTED")
			return
		}
		s.runtimeFault(runtimeFaultAfterResponseCreation, request.URL.Path)
		if s.journal.persistResponse(binding, encoded) != nil {
			s.journalFailed = true
			writeWireError(response, http.StatusInternalServerError, "JOURNAL_REJECTED")
			return
		}
		s.runtimeFault(runtimeFaultAfterResponseArtifact, request.URL.Path)
		if s.journal.complete(binding, encoded, status, now) != nil {
			s.journalFailed = true
			writeWireError(response, http.StatusInternalServerError, "JOURNAL_REJECTED")
			return
		}
		s.runtimeFault(runtimeFaultAfterCompleted, request.URL.Path)
		writeWireBytesStatus(response, status, encoded)
		return
	}
	if len(envelope.Authorization) != 0 || len(envelope.Request) != 0 {
		writeWireError(response, http.StatusBadRequest, "MALFORMED_REQUEST")
		return
	}
	result, err := operation()
	if err != nil {
		writeWireError(response, http.StatusConflict, publicErrorCode(err))
		return
	}
	encoded, err := marshalWireSuccess(result, limits.Response)
	if err != nil {
		writeWireError(response, http.StatusInternalServerError, "RESPONSE_REJECTED")
		return
	}
	writeWireBytes(response, encoded)
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
		if s.participant != nil {
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
		return s.phaseResponse(participant)
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
		if err != nil {
			return nil, err
		}
		encoded, err := marshalReplicaHead(head)
		return HeadResponse{Head: encoded}, err
	})
}

func (s *OperatorService) handleReserve(w http.ResponseWriter, r *http.Request) {
	var input HeadsRequest
	s.withRequest(w, r, &input, func() (any, error) {
		participant, err := s.requireParticipant()
		if err != nil {
			return nil, err
		}
		heads, err := parseHeads(input.Heads)
		if err != nil {
			return nil, err
		}
		if err := participant.Reserve(heads); err != nil {
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
		return s.phaseResult(participant, participant.AcceptReservations(reservations))
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
		if err != nil {
			return nil, err
		}
		encoded, err := statement.MarshalBinary()
		return TransitionProposalResponse{Statement: encoded}, err
	})
}

func (s *OperatorService) handleSignTransition(w http.ResponseWriter, r *http.Request) {
	var input SignTransitionRequest
	s.withRequest(w, r, &input, func() (any, error) {
		participant, err := s.requireParticipant()
		if err != nil {
			return nil, err
		}
		statement, err := parseWitnessStatementBytes(input.Statement)
		if err != nil {
			return nil, err
		}
		heads, err := parseHeads(input.Heads)
		if err != nil {
			return nil, err
		}
		signature, err := participant.SignTransition(statement, heads)
		if err != nil {
			return nil, err
		}
		encoded, err := marshalWitnessSignature(signature)
		return SignTransitionResponse{Signature: encoded}, err
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
			return nil, err
		}
		return s.phaseResponse(participant)
	})
}

func (s *OperatorService) handleBeginSecrets(w http.ResponseWriter, r *http.Request) {
	var input HeadsRequest
	s.withGeneration(w, r, &input, func(p *ceremony.Participant) (any, error) {
		heads, err := parseHeads(input.Heads)
		if err != nil {
			return nil, err
		}
		return s.phaseResult(p, p.BeginSecrets(heads))
	})
}

func (s *OperatorService) handleCRSCommit(w http.ResponseWriter, r *http.Request) {
	var input HeadsRequest
	s.withGeneration(w, r, &input, func(p *ceremony.Participant) (any, error) {
		heads, err := parseHeads(input.Heads)
		if err != nil {
			return nil, err
		}
		envelope, err := p.CRSCommitEnvelope(heads)
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
		return s.phaseResult(p, p.AcceptCRSCommitStage(envelopes))
	})
}

func (s *OperatorService) handleCRSReveal(w http.ResponseWriter, r *http.Request) {
	var input HeadsRequest
	s.withGeneration(w, r, &input, func(p *ceremony.Participant) (any, error) {
		heads, err := parseHeads(input.Heads)
		if err != nil {
			return nil, err
		}
		envelope, err := p.CRSRevealEnvelope(heads)
		if err != nil {
			return nil, err
		}
		encoded, err := envelope.MarshalBinary()
		return EnvelopeResponse{Envelope: encoded}, err
	})
}

func (s *OperatorService) handleAcceptCRSReveal(w http.ResponseWriter, r *http.Request) {
	type request struct {
		Envelopes [][]byte `json:"envelopes" required:"true"`
		Heads     [][]byte `json:"heads" required:"true"`
	}
	var input request
	s.withMutation(w, r, &input, func(p *ceremony.Participant) (any, error) {
		envelopes, err := parseEnvelopes(input.Envelopes)
		if err != nil {
			return nil, err
		}
		heads, err := parseHeads(input.Heads)
		if err != nil {
			return nil, err
		}
		return s.phaseResult(p, p.AcceptCRSRevealStage(envelopes, heads))
	})
}

func (s *OperatorService) handlePrivateMessages(w http.ResponseWriter, r *http.Request) {
	var input HeadsRequest
	s.withGeneration(w, r, &input, func(p *ceremony.Participant) (any, error) {
		heads, err := parseHeads(input.Heads)
		if err != nil {
			return nil, err
		}
		messages, err := p.PrivateMessages(heads)
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
		heads, err := parseHeads(input.Heads)
		if err != nil {
			return nil, err
		}
		receipts, err := p.ReceivePrivateMessages(messages, heads)
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
		return s.phaseResult(p, p.AcceptPrivateStage(messages, receipts))
	})
}

func (s *OperatorService) handlePublicKeyShare(w http.ResponseWriter, r *http.Request) {
	var input HeadsRequest
	s.withEnvelopeGeneration(w, r, &input, func(p *ceremony.Participant) (ceremony.SignedEnvelope, error) {
		heads, err := parseHeads(input.Heads)
		if err != nil {
			return ceremony.SignedEnvelope{}, err
		}
		return p.PublicKeyShareEnvelope(heads)
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
		heads, err := parseHeads(input.Heads)
		if err != nil {
			return ceremony.SignedEnvelope{}, err
		}
		return p.RelinRoundOneEnvelope(heads)
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
		heads, err := parseHeads(input.Heads)
		if err != nil {
			return ceremony.SignedEnvelope{}, err
		}
		return p.RelinRoundTwoEnvelope(heads)
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
		heads, err := parseHeads(input.Heads)
		if err != nil {
			return nil, err
		}
		envelope, err := p.GaloisShareEnvelope(input.Index, heads)
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
		heads, err := parseHeads(input.Heads)
		if err != nil {
			return nil, err
		}
		return s.phaseResult(p, p.AcceptGaloisStage(input.Index, envelopes, heads))
	})
}

func (s *OperatorService) handlePublicState(w http.ResponseWriter, r *http.Request) {
	var input HeadsRequest
	s.withGeneration(w, r, &input, func(p *ceremony.Participant) (any, error) {
		heads, err := parseHeads(input.Heads)
		if err != nil {
			return nil, err
		}
		material, err := p.PublicMaterial(heads)
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
		return s.phaseResult(p, p.SetManifestPending(input.Digest))
	})
}

func (s *OperatorService) handleAttestBundle(w http.ResponseWriter, r *http.Request) {
	var input UnsignedBundleRequest
	s.withGeneration(w, r, &input, func(p *ceremony.Participant) (any, error) {
		unsigned, err := ceremony.ParseUnsignedPublicBundle(input.UnsignedBundle)
		if err != nil {
			return nil, err
		}
		heads, err := parseHeads(input.Heads)
		if err != nil {
			return nil, err
		}
		envelope, err := p.AttestUnsignedBundle(unsigned, heads)
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
		heads, err := parseHeads(input.Heads)
		if err != nil {
			return nil, err
		}
		envelope, err := p.AttestPrivateReadiness(unsigned, heads)
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
		if err != nil {
			return nil, err
		}
		receipt, err := parsePublicationReceipt(input.Receipt)
		if err != nil || receipt.ObjectPath != filepath.Join(s.config.PublicationRoot, "public.bundle") {
			return nil, ceremony.ErrPersistence
		}
		if ceremony.VerifyPublicationReceipt(receipt, bundle) != nil {
			local, publishErr := ceremony.PublishPublicBundle(s.config.PublicationRoot, bundle)
			if publishErr != nil || local.Digest() != receipt.Digest() {
				return nil, ceremony.ErrPersistence
			}
		}
		return s.phaseResult(p, p.SetPublishedPending(bundle, receipt))
	})
}

func (s *OperatorService) handleSetCompleted(w http.ResponseWriter, r *http.Request) {
	var input PublishedRequest
	s.withMutation(w, r, &input, func(p *ceremony.Participant) (any, error) {
		bundle, err := ceremony.ParsePublicBundle(input.Bundle)
		if err != nil {
			return nil, err
		}
		receipt, err := parsePublicationReceipt(input.Receipt)
		if err != nil {
			return nil, err
		}
		return s.phaseResult(p, p.SetCompletedPending(bundle, receipt))
	})
}

func (s *OperatorService) handleFinalizePrivate(w http.ResponseWriter, r *http.Request) {
	var input FinalizeRequest
	s.withMutation(w, r, &input, func(p *ceremony.Participant) (any, error) {
		bundle, err := ceremony.ParsePublicBundle(input.Bundle)
		if err != nil {
			return nil, err
		}
		receipt, err := parsePublicationReceipt(input.Receipt)
		if err != nil {
			return nil, err
		}
		heads, err := parseHeads(input.Heads)
		if err != nil {
			return nil, err
		}
		replicas, err := parseReplicas(input.Replicas)
		if err != nil {
			return nil, err
		}
		_, err = p.FinalizeCompletedOperatorBundle(bundle, receipt, heads, replicas...)
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
		phase := ceremony.PhaseNotStarted
		if s.participant != nil && s.context.ContextDigest() == context.ContextDigest() {
			phase = s.participant.Phase()
		} else if len(records) > 0 {
			phase = records[len(records)-1].Statement.ToPhase
		}
		disposition, tombstoneBytes, err := s.durableDisposition(context, phase)
		if err != nil {
			return nil, err
		}
		return OperatorEvidenceResponse{Identity: s.config.Identity, ConfigurationHash: s.configDigest, Phase: phase, Disposition: disposition, Records: encoded, TerminalTombstone: tombstoneBytes}, nil
	})
}

func (s *OperatorService) handlePhase(w http.ResponseWriter, r *http.Request) {
	var input EmptyRequest
	s.withRequest(w, r, &input, func() (any, error) {
		if s.participant == nil {
			return PhaseResponse{Phase: ceremony.PhaseNotStarted, Disposition: "READY"}, nil
		}
		return s.phaseResponse(s.participant)
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
		return operation(participant)
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
		Envelopes [][]byte `json:"envelopes" required:"true"`
		Heads     [][]byte `json:"heads" required:"true"`
	}
	var input request
	s.withMutation(w, r, &input, func(p *ceremony.Participant) (any, error) {
		envelopes, err := parseEnvelopes(input.Envelopes)
		if err != nil {
			return nil, err
		}
		heads, err := parseHeads(input.Heads)
		if err != nil {
			return nil, err
		}
		return s.phaseResult(p, accept(p, envelopes, heads))
	})
}

func (s *OperatorService) phaseResult(participant *ceremony.Participant, err error) (any, error) {
	if err != nil {
		return nil, err
	}
	return s.phaseResponse(participant)
}

func (s *OperatorService) phaseResponse(participant *ceremony.Participant) (any, error) {
	phase := participant.Phase()
	disposition, _, err := s.durableDisposition(s.context, phase)
	if err != nil {
		return nil, err
	}
	return PhaseResponse{Phase: phase, Disposition: disposition}, nil
}

func (s *OperatorService) durableDisposition(contextValue ceremony.Context, phase ceremony.Phase) (string, []byte, error) {
	if contextValue.Validate() != nil {
		if phase == ceremony.PhaseNotStarted {
			return "READY", nil, nil
		}
		return "", nil, ceremony.ErrPersistence
	}
	ceremonyID := contextValue.CeremonyID()
	tombstonePath := filepath.Join(s.config.StateRoot, "witness", "terminal-"+encodeHex(ceremonyID[:])+".bin")
	_, statErr := os.Lstat(tombstonePath)
	tombstonePresent := statErr == nil
	if statErr != nil && !os.IsNotExist(statErr) {
		return "", nil, ceremony.ErrPersistence
	}
	tombstone, err := s.storage.PublicTerminalTombstone(ceremonyID)
	if tombstonePresent {
		if err != nil {
			return "", nil, ceremony.ErrPersistence
		}
		encoded, marshalErr := tombstone.MarshalBinary()
		if marshalErr != nil || tombstone.CeremonyID != ceremonyID || tombstone.SessionBindingDigest != contextValue.SessionBindingDigest() {
			return "", nil, ceremony.ErrPersistence
		}
		switch tombstone.Disposition {
		case ceremony.DispositionPoisoned:
			return "POISONED", encoded, nil
		case ceremony.DispositionAborted:
			return "ABORTED", encoded, nil
		case ceremony.DispositionCompleted:
			return "COMPLETED", encoded, nil
		default:
			return "", nil, ceremony.ErrPersistence
		}
	}
	if err == nil {
		// The capability found a tombstone where the fixed local path did not.
		return "", nil, ceremony.ErrPersistence
	}
	if phase == ceremony.PhaseCompleted || phase == ceremony.PhaseAborted {
		return "", nil, ceremony.ErrPersistence
	}
	if phase == ceremony.PhaseNotStarted && s.participant == nil {
		return "READY", nil, nil
	}
	return "ACTIVE", nil, nil
}

func marshalWireSuccess(value any, maximum int64) ([]byte, error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return nil, ErrTransport
	}
	encoded, err := json.Marshal(wireResponse{SchemaVersion: RuntimeWireSchema, OK: true, Payload: payload})
	if err != nil || len(encoded) == 0 || int64(len(encoded)+1) > maximum {
		return nil, ErrTransport
	}
	return append(encoded, '\n'), nil
}

func marshalWireError(code string, maximum int64) ([]byte, error) {
	if code == "" {
		return nil, ErrTransport
	}
	encoded, err := json.Marshal(wireResponse{SchemaVersion: RuntimeWireSchema, OK: false, ErrorCode: code})
	if err != nil || len(encoded) == 0 || int64(len(encoded)+1) > maximum {
		return nil, ErrTransport
	}
	return append(encoded, '\n'), nil
}

func writeWireError(response http.ResponseWriter, status int, code string) {
	encoded, err := json.Marshal(wireResponse{SchemaVersion: RuntimeWireSchema, OK: false, ErrorCode: code})
	if err != nil || int64(len(encoded)+1) > maxResponseBytes {
		status = http.StatusInternalServerError
		encoded = []byte(`{"schemaVersion":"mordant.oneshot-runtime-wire/1","ok":false,"errorCode":"INTERNAL_REJECTED"}`)
	}
	response.WriteHeader(status)
	_, _ = response.Write(append(encoded, '\n'))
}

func writeWireBytes(response http.ResponseWriter, encoded []byte) {
	writeWireBytesStatus(response, http.StatusOK, encoded)
}

func writeWireBytesStatus(response http.ResponseWriter, status int, encoded []byte) {
	response.WriteHeader(status)
	_, _ = response.Write(encoded)
}

func publicErrorCode(err error) string {
	switch {
	case errors.Is(err, ceremony.ErrBinding):
		return "BINDING_REJECTED"
	case errors.Is(err, ceremony.ErrState):
		return "STATE_REJECTED"
	case errors.Is(err, ceremony.ErrReplay):
		return "REPLAY_REJECTED"
	case errors.Is(err, ErrRequestReplay):
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
	case errors.Is(err, ErrAuthorization):
		return "AUTHORIZATION_REJECTED"
	case errors.Is(err, ErrJournalExhausted):
		return "JOURNAL_EXHAUSTED"
	case errors.Is(err, ErrSessionIndeterminate):
		return indeterminateCode
	case errors.Is(err, ErrJournal):
		return "JOURNAL_REJECTED"
	default:
		return "OPERATION_REJECTED"
	}
}
