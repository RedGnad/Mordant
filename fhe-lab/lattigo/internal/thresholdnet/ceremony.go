package thresholdnet

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"sync"
	"time"

	spike "mordant.dev/fhe-lab/lattigo"
)

// This file carries the dealerless ceremony over the network. Two channels are
// deliberately distinct:
//
//   - the coordinator channel (/v1/ceremony) drives the public rounds. Every
//     payload it carries is a public protocol share.
//   - the peer channel (/v1/ceremony/peer) carries the Shamir re-sharing. It is
//     operator-to-operator, mutually authenticated by pinned roster keys, and
//     the coordinator is not a party to it.
//
// The coordinator can therefore never observe a Shamir share, and no endpoint
// on this server will emit one.

const (
	ceremonyWireMagic   = "MCW1"
	ceremonyWireDomain  = "mordant.ceremony.network-request/v4"
	ceremonyContentType = "application/vnd.mordant.ceremony-v4"
	ceremonyPath        = "/v1/ceremony"
	ceremonyPeerPath    = "/v1/ceremony/peer"
	ceremonyStatusPath  = "/v1/ceremony/status"

	maxCeremonyPayloadBytes  = 320 << 20
	maxCeremonyResponseBytes = 320 << 20
	maxCeremonyPeerBytes     = 32 << 20
)

// CeremonyProtocolVersion is the existing Gate 1 coordinator/operator wire
// authority. It is exported only so the immutable runner context can name the
// exact protocol it is preparing.
const CeremonyProtocolVersion = ceremonyWireDomain

// CeremonyOperation identifies one coordinator-driven ceremony step.
type CeremonyOperation uint8

const (
	OpContribution   CeremonyOperation = 1
	OpSealCRS        CeremonyOperation = 2
	OpReshare        CeremonyOperation = 3
	OpSealShares     CeremonyOperation = 4
	OpPublicKeyShare CeremonyOperation = 5
	OpRelinOne       CeremonyOperation = 6
	OpRelinTwo       CeremonyOperation = 7
	OpGalois         CeremonyOperation = 8
	OpSealManifest   CeremonyOperation = 9
)

var (
	ErrCeremonyUnauthorized = errors.New("unauthorized ceremony peer")
	ErrCeremonyRequest      = errors.New("malformed ceremony request")
	ErrCeremonyRejected     = errors.New("ceremony step rejected")
)

// CeremonyServer owns exactly one operator's ceremony state. It is mounted on
// the same mTLS listener as the release service but before any operator bundle
// exists.
type CeremonyServer struct {
	State                *spike.CeremonyOperatorState
	CoordinatorPublicKey ed25519.PublicKey
	// Recovery is the operator-local immutable checkpoint ledger. When set,
	// every mutating result is fsynced before any response leaves this process,
	// and an already completed request returns its exact cached bytes.
	Recovery *CeremonyPrivateLedger
	// PeerDialer builds the client used to push private shares to peers. It is
	// injected so the operator process controls its own client identity.
	PeerDialer func(point uint64, endpoint string) (*http.Client, error)
	// Persist stores this operator's own sealed bundle in its own directory. It
	// receives exactly one operator's material and is never called with another.
	Persist func(bundle []byte) error
	// KeyID binds the sealed bundle to the collective key epoch.
	KeyID func() ([32]byte, error)

	protocolMu sync.Mutex
	mu         sync.Mutex
	steps      []CeremonyStepRecord
	consumed   map[CeremonyOperation]int
	peers      map[uint64]struct{}
}

// CeremonyStepRecord is the operator's own account of a completed round. The
// parent orchestrator reads it from the operator, not from the coordinator, so
// operator state is never a coordinator-authored constant.
type CeremonyStepRecord struct {
	Operation CeremonyOperation `json:"operation"`
	Name      string            `json:"name"`
	At        string            `json:"at"`
	Detail    string            `json:"detail,omitempty"`
}

var ceremonyOperationNames = map[CeremonyOperation]string{
	OpContribution:   "crs-contribution",
	OpSealCRS:        "crs-sealed",
	OpReshare:        "private-reshare-sent",
	OpSealShares:     "threshold-share-sealed",
	OpPublicKeyShare: "collective-public-key-share",
	OpRelinOne:       "relinearization-round-one",
	OpRelinTwo:       "relinearization-round-two",
	OpGalois:         "galois-share",
	OpSealManifest:   "manifest-sealed",
}

// CeremonyHandler returns the ceremony protocol handler.
func (server *CeremonyServer) CeremonyHandler(mux *http.ServeMux) *http.ServeMux {
	if mux == nil {
		mux = http.NewServeMux()
	}
	mux.HandleFunc(ceremonyPath, server.handleCeremony)
	mux.HandleFunc(ceremonyPeerPath, server.handlePeerShare)
	mux.HandleFunc(ceremonyStatusPath, server.handleCeremonyStatus)
	return mux
}

// handleCeremonyStatus is the authenticated read the parent orchestrator uses
// for independent operator evidence. It exposes round transitions and public
// commitments only.
func (server *CeremonyServer) handleCeremonyStatus(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet || !server.authenticatedReader(request) {
		writeBoundedError(writer, http.StatusUnauthorized, "authentication required")
		return
	}
	server.protocolMu.Lock()
	defer server.protocolMu.Unlock()
	var steps []CeremonyStepRecord
	if server.Recovery != nil {
		steps = server.Recovery.Steps()
	} else {
		server.mu.Lock()
		steps = append([]CeremonyStepRecord(nil), server.steps...)
		server.mu.Unlock()
	}
	crs := server.State.CRSCommitment()
	roster := server.State.RosterDigest()
	publicKeyDigest, evaluationKeyDigest, manifestDigest := "", "", ""
	if server.Recovery != nil {
		if digests, present, err := server.Recovery.FinalKeyDigests(); err != nil {
			writeBoundedError(writer, http.StatusConflict, "operator ledger unavailable")
			return
		} else if present {
			publicKeyDigest = hex.EncodeToString(digests.PublicKeyCommitment[:])
			evaluation := spike.CeremonyEvaluationKeyDigest(digests)
			evaluationKeyDigest = hex.EncodeToString(evaluation[:])
			manifest := spike.CeremonyManifestDigest(server.State.Roster(), digests)
			manifestDigest = hex.EncodeToString(manifest[:])
		}
	}
	statement := OperatorStatement{
		Point:               server.State.Point(),
		RosterDigest:        hex.EncodeToString(roster[:]),
		CRSCommitment:       hex.EncodeToString(crs[:]),
		Sealed:              server.State.Sealed(),
		HoldsLocalSecretKey: server.State.HoldsLocalSecretKey(),
		HoldsOwnShareOnly:   true,
		PublicKeyDigest:     publicKeyDigest,
		EvaluationKeyDigest: evaluationKeyDigest,
		ManifestDigest:      manifestDigest,
		Steps:               steps,
		ObservedAt:          time.Now().UTC().Format(time.RFC3339Nano),
	}
	// The statement is signed with the operator's own ceremony key, so a verifier
	// holding the roster can check operator state without trusting whoever
	// relayed it. This is what makes node 3's state operator-authored evidence
	// rather than a coordinator constant.
	payload, err := json.Marshal(statement)
	if err != nil {
		writeBoundedError(writer, http.StatusInternalServerError, "statement encoding failed")
		return
	}
	signature := server.State.SignOperatorStatement(payload)
	writer.Header().Set("Content-Type", "application/json")
	response, err := json.Marshal(SignedOperatorStatement{
		Statement: json.RawMessage(payload),
		Point:     statement.Point,
		Signature: hex.EncodeToString(signature[:]),
	})
	if err != nil {
		writeBoundedError(writer, http.StatusInternalServerError, "statement encoding failed")
		return
	}
	_, _ = writer.Write(append(response, '\n'))
}

// OperatorStatement is one operator's own account of its ceremony state.
type OperatorStatement struct {
	Point               uint64               `json:"point"`
	RosterDigest        string               `json:"rosterDigest"`
	CRSCommitment       string               `json:"crsCommitment"`
	Sealed              bool                 `json:"sealed"`
	HoldsLocalSecretKey bool                 `json:"holdsLocalSecretKey"`
	HoldsOwnShareOnly   bool                 `json:"holdsOwnShareOnly"`
	PublicKeyDigest     string               `json:"publicKeyDigest,omitempty"`
	EvaluationKeyDigest string               `json:"evaluationKeyDigest,omitempty"`
	ManifestDigest      string               `json:"manifestDigest,omitempty"`
	Steps               []CeremonyStepRecord `json:"steps"`
	ObservedAt          string               `json:"observedAt"`
}

// SignedOperatorStatement wraps an operator statement with its signature.
type SignedOperatorStatement struct {
	Statement json.RawMessage `json:"statement"`
	Point     uint64          `json:"point"`
	Signature string          `json:"signature"`
}

// authenticatedReader gates the status endpoint on a valid mTLS client
// certificate. It deliberately does not restrict the reader to the coordinator
// or a roster peer: the statement carries no secret, and its authenticity comes
// from the operator's own signature rather than from the transport. That lets
// the parent orchestrator read operator state directly instead of receiving it
// relayed by the coordinator.
func (server *CeremonyServer) authenticatedReader(request *http.Request) bool {
	if request.TLS == nil || len(request.TLS.VerifiedChains) == 0 || server.State == nil {
		return false
	}
	_, ok := request.TLS.PeerCertificates[0].PublicKey.(ed25519.PublicKey)
	return ok
}

// handlePeerShare receives one Shamir re-sharing from another operator. The
// mTLS client identity must be a roster operator, and the message signature
// must come from that same operator.
func (server *CeremonyServer) handlePeerShare(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost || request.TLS == nil || len(request.TLS.VerifiedChains) == 0 || server.State == nil {
		writeBoundedError(writer, http.StatusUnauthorized, "peer authentication required")
		return
	}
	peerKey, ok := request.TLS.PeerCertificates[0].PublicKey.(ed25519.PublicKey)
	if !ok {
		writeBoundedError(writer, http.StatusUnauthorized, "peer authentication required")
		return
	}
	// The coordinator must never be able to inject a private share.
	if len(server.CoordinatorPublicKey) == ed25519.PublicKeySize &&
		subtle.ConstantTimeCompare(peerKey, server.CoordinatorPublicKey) == 1 {
		writeBoundedError(writer, http.StatusForbidden, "coordinator is not a re-sharing peer")
		return
	}
	senderPoint, isPeer := server.State.RosterSigningPoint(peerKey)
	if !isPeer {
		writeBoundedError(writer, http.StatusUnauthorized, "peer authentication required")
		return
	}
	request.Body = http.MaxBytesReader(writer, request.Body, maxCeremonyPeerBytes)
	body, err := io.ReadAll(request.Body)
	if err != nil {
		writeBoundedError(writer, http.StatusBadRequest, "invalid peer message")
		return
	}
	share, err := spike.UnmarshalCeremonyPrivateShare(body)
	if err != nil {
		writeBoundedError(writer, http.StatusBadRequest, "invalid private share")
		return
	}
	// The transport identity and the signed message author must agree.
	if share.Sender != senderPoint {
		writeBoundedError(writer, http.StatusForbidden, "private share author does not match the peer identity")
		return
	}
	server.protocolMu.Lock()
	defer server.protocolMu.Unlock()
	if server.Recovery != nil {
		digest := sha256.Sum256(body)
		persisted, exists, ledgerErr := server.Recovery.InboundDigest(senderPoint)
		if ledgerErr != nil {
			writeBoundedError(writer, http.StatusConflict, "operator ledger unavailable")
			return
		}
		if exists {
			if persisted != digest {
				writeBoundedError(writer, http.StatusConflict, "private share conflicts with persisted input")
				return
			}
			writer.WriteHeader(http.StatusNoContent)
			return
		}
	}
	if err := server.State.AcceptPrivateShare(share); err != nil {
		writeBoundedError(writer, http.StatusConflict, "private share rejected")
		return
	}
	if server.Recovery != nil {
		if err := server.Recovery.SaveInbound(senderPoint, body); err != nil {
			writeBoundedError(writer, http.StatusConflict, "operator ledger unavailable")
			return
		}
	}
	server.mu.Lock()
	if server.peers == nil {
		server.peers = make(map[uint64]struct{})
	}
	server.peers[senderPoint] = struct{}{}
	server.mu.Unlock()
	writer.WriteHeader(http.StatusNoContent)
}

func (server *CeremonyServer) handleCeremony(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost || request.TLS == nil || len(request.TLS.VerifiedChains) == 0 ||
		server.State == nil || len(server.CoordinatorPublicKey) != ed25519.PublicKeySize {
		writeBoundedError(writer, http.StatusUnauthorized, "coordinator authentication required")
		return
	}
	peerKey, ok := request.TLS.PeerCertificates[0].PublicKey.(ed25519.PublicKey)
	if !ok || subtle.ConstantTimeCompare(peerKey, server.CoordinatorPublicKey) != 1 {
		writeBoundedError(writer, http.StatusUnauthorized, "coordinator authentication required")
		return
	}
	request.Body = http.MaxBytesReader(writer, request.Body, maxCeremonyPayloadBytes+1024)
	body, err := io.ReadAll(request.Body)
	if err != nil {
		writeBoundedError(writer, http.StatusBadRequest, "invalid ceremony request")
		return
	}
	parsed, err := unmarshalCeremonyRequest(body)
	if err != nil || !verifyCeremonyRequest(parsed, server.CoordinatorPublicKey) {
		writeBoundedError(writer, http.StatusUnauthorized, "invalid signed ceremony request")
		return
	}
	server.protocolMu.Lock()
	response, err := server.step(request.Context(), parsed)
	server.protocolMu.Unlock()
	if err != nil {
		writeBoundedError(writer, http.StatusConflict, "ceremony step rejected")
		return
	}
	writer.Header().Set("Content-Type", ceremonyContentType)
	writer.Header().Set("Content-Length", fmt.Sprintf("%d", len(response)))
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(response)
}

func (server *CeremonyServer) step(ctx context.Context, request ceremonyRequest) ([]byte, error) {
	if server.Recovery != nil {
		cached, exists, err := server.Recovery.Cached(request.Operation, request.Payload)
		if err != nil {
			return nil, err
		}
		if exists {
			if request.Operation == OpSealManifest && server.Persist != nil {
				bundle, present, err := server.Recovery.SealedBundle()
				if err != nil || !present {
					return nil, ErrCeremonyRejected
				}
				if err := server.Persist(bundle); err != nil {
					return nil, err
				}
			}
			return cached, nil
		}
		if request.Operation == OpReshare {
			cached, completed, err := server.Recovery.CachedReshare()
			if err != nil {
				return nil, err
			}
			if completed {
				if _, err := server.peerEndpointsForRoster(request.Payload); err != nil {
					return nil, err
				}
				return cached, nil
			}
		}
	}
	switch request.Operation {
	case OpContribution:
		contribution := server.State.CRSContribution()
		return server.finish(request, contribution[:], "", nil)
	case OpSealCRS:
		if err := server.applyContributions(request.Payload); err != nil {
			return nil, err
		}
		if err := server.State.SealCRS(); err != nil {
			return nil, err
		}
		commitment := server.State.CRSCommitment()
		return server.finish(request, commitment[:], fmt.Sprintf("crs=%x", commitment[:8]), nil)
	case OpReshare:
		sent, err := server.pushPrivateShares(ctx, request.Payload)
		if err != nil {
			return nil, err
		}
		return server.finish(request, []byte{byte(sent)}, fmt.Sprintf("recipients=%d", sent), nil)
	case OpSealShares:
		if err := server.State.SealThresholdShare(); err != nil {
			return nil, err
		}
		return server.finish(request, nil, "", nil)
	case OpPublicKeyShare:
		wire, err := server.State.PublicKeyShare()
		if err != nil {
			return nil, err
		}
		return server.finish(request, wire, fmt.Sprintf("bytes=%d", len(wire)), nil)
	case OpRelinOne:
		wire, err := server.State.RelinearizationShareRoundOne()
		if err != nil {
			return nil, err
		}
		return server.finish(request, wire, fmt.Sprintf("bytes=%d", len(wire)), nil)
	case OpRelinTwo:
		wire, err := server.State.RelinearizationShareRoundTwo(request.Payload)
		if err != nil {
			return nil, err
		}
		return server.finish(request, wire, fmt.Sprintf("bytes=%d", len(wire)), nil)
	case OpGalois:
		if len(request.Payload) != 8 {
			return nil, ErrCeremonyRequest
		}
		element := binary.BigEndian.Uint64(request.Payload)
		wire, err := server.State.GaloisShare(element)
		if err != nil {
			return nil, err
		}
		return server.finish(request, wire, fmt.Sprintf("element=%d", element), nil)
	case OpSealManifest:
		return server.sealManifest(request)
	default:
		return nil, ErrCeremonyRequest
	}
}

func (server *CeremonyServer) finish(request ceremonyRequest, response []byte, detail string, aux []byte) ([]byte, error) {
	if server.Recovery != nil {
		if err := server.Recovery.CommitOperation(request.Operation, request.Payload, response, detail, aux); err != nil {
			return nil, err
		}
	} else {
		server.record(request.Operation, detail)
	}
	return response, nil
}

func (server *CeremonyServer) applyContributions(payload []byte) error {
	if len(payload)%40 != 0 || len(payload) == 0 {
		return ErrCeremonyRequest
	}
	for offset := 0; offset < len(payload); offset += 40 {
		point := binary.BigEndian.Uint64(payload[offset : offset+8])
		var value [32]byte
		copy(value[:], payload[offset+8:offset+40])
		if point == server.State.Point() {
			continue
		}
		if err := server.State.AcceptCRSContribution(point, value); err != nil {
			return err
		}
	}
	return nil
}

// pushPrivateShares dials every peer directly. The shares never traverse the
// coordinator connection: the coordinator only learns how many recipients were
// served.
func (server *CeremonyServer) pushPrivateShares(ctx context.Context, payload []byte) (int, error) {
	endpoints, err := server.peerEndpointsForRoster(payload)
	if err != nil {
		return 0, err
	}
	if server.PeerDialer == nil {
		return 0, ErrCeremonyRejected
	}
	sent := 0
	for _, endpoint := range endpoints {
		var wire []byte
		if server.Recovery != nil {
			cached, exists, err := server.Recovery.Outbound(endpoint.Point)
			if err != nil {
				return 0, err
			}
			if exists {
				wire = cached
			} else {
				share, err := server.State.PrivateShareFor(endpoint.Point)
				if err != nil {
					return 0, err
				}
				wire, err = share.MarshalBinary()
				if err != nil {
					return 0, err
				}
				if err := server.Recovery.SaveOutbound(endpoint.Point, wire); err != nil {
					return 0, err
				}
			}
		} else {
			share, err := server.State.PrivateShareFor(endpoint.Point)
			if err != nil {
				return 0, err
			}
			wire, err = share.MarshalBinary()
			if err != nil {
				return 0, err
			}
		}
		if endpoint.Point == server.State.Point() {
			// The operator's own contribution to itself never leaves the process.
			persisted := false
			if server.Recovery != nil {
				digest := sha256.Sum256(wire)
				seen, exists, err := server.Recovery.InboundDigest(endpoint.Point)
				if err != nil {
					return 0, err
				}
				if exists {
					if seen != digest {
						return 0, ErrCeremonyRejected
					}
					persisted = true
				}
			}
			if !persisted {
				share, err := spike.UnmarshalCeremonyPrivateShare(wire)
				if err != nil || server.State.AcceptPrivateShare(share) != nil {
					return 0, ErrCeremonyRejected
				}
				if server.Recovery != nil {
					if err := server.Recovery.SaveInbound(endpoint.Point, wire); err != nil {
						return 0, err
					}
				}
			}
			sent++
			continue
		}
		client, err := server.PeerDialer(endpoint.Point, endpoint.URL)
		if err != nil {
			return 0, err
		}
		httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.URL+ceremonyPeerPath, bytes.NewReader(wire))
		if err != nil {
			return 0, err
		}
		httpRequest.Header.Set("Content-Type", ceremonyContentType)
		response, err := client.Do(httpRequest)
		if err != nil {
			return 0, err
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1024))
		_ = response.Body.Close()
		if response.StatusCode != http.StatusNoContent {
			return 0, fmt.Errorf("%w: peer %d returned %d", ErrCeremonyRejected, endpoint.Point, response.StatusCode)
		}
		sent++
	}
	return sent, nil
}

// peerEndpointsForRoster accepts changed process URLs after a restart, but it
// requires the exact canonical participant set. A completed re-sharing can
// therefore be acknowledged from its durable result without re-dialling any
// peer, while a substituted, missing, duplicated, or reordered point fails.
func (server *CeremonyServer) peerEndpointsForRoster(payload []byte) ([]PeerEndpoint, error) {
	if server == nil || server.State == nil {
		return nil, ErrCeremonyRejected
	}
	endpoints, err := decodePeerEndpoints(payload)
	if err != nil {
		return nil, err
	}
	expected := server.State.RosterOperatorPoints()
	if len(endpoints) != len(expected) {
		return nil, ErrCeremonyRequest
	}
	for index, point := range expected {
		if endpoints[index].Point != point {
			return nil, ErrCeremonyRequest
		}
	}
	return endpoints, nil
}

func (server *CeremonyServer) sealManifest(request ceremonyRequest) ([]byte, error) {
	payload := request.Payload
	if len(payload) != 160 {
		return nil, ErrCeremonyRequest
	}
	var digests spike.CeremonyKeyDigests
	copy(digests.CRSCommitment[:], payload[0:32])
	copy(digests.PublicKeyCommitment[:], payload[32:64])
	copy(digests.RelinearizationKeyDigest[:], payload[64:96])
	copy(digests.GaloisKeyCommitment[:], payload[96:128])
	copy(digests.PolicyCircuitCommitment[:], payload[128:160])
	attestation, err := server.State.Seal(digests)
	if err != nil {
		return nil, err
	}
	var bundle []byte
	if server.KeyID != nil && server.Persist != nil {
		keyID, err := server.KeyID()
		if err != nil {
			return nil, err
		}
		bundle, err = server.State.SealedOperatorBundle(keyID)
		if err != nil {
			return nil, err
		}
	}
	response := attestation.Signature[:]
	if _, err := server.finish(request, response, "", bundle); err != nil {
		return nil, err
	}
	if server.Persist != nil && len(bundle) != 0 {
		if err := server.Persist(bundle); err != nil {
			return nil, err
		}
	}
	return response, nil
}

func (server *CeremonyServer) record(operation CeremonyOperation, detail string) {
	server.mu.Lock()
	defer server.mu.Unlock()
	if server.consumed == nil {
		server.consumed = make(map[CeremonyOperation]int)
	}
	server.consumed[operation]++
	server.steps = append(server.steps, CeremonyStepRecord{
		Operation: operation,
		Name:      ceremonyOperationNames[operation],
		At:        time.Now().UTC().Format(time.RFC3339Nano),
		Detail:    detail,
	})
}

// PeerEndpoint locates one roster operator on the private channel.
type PeerEndpoint struct {
	Point uint64
	URL   string
}

// EncodePeerEndpoints serialises the private-channel roster for OpReshare.
func EncodePeerEndpoints(endpoints []PeerEndpoint) ([]byte, error) {
	sorted := append([]PeerEndpoint(nil), endpoints...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Point < sorted[j].Point })
	var out bytes.Buffer
	_ = binary.Write(&out, binary.BigEndian, uint16(len(sorted)))
	for _, endpoint := range sorted {
		if endpoint.Point == 0 || endpoint.URL == "" || len(endpoint.URL) > 512 {
			return nil, ErrCeremonyRequest
		}
		_ = binary.Write(&out, binary.BigEndian, endpoint.Point)
		_ = binary.Write(&out, binary.BigEndian, uint16(len(endpoint.URL)))
		out.WriteString(endpoint.URL)
	}
	return out.Bytes(), nil
}

func decodePeerEndpoints(payload []byte) ([]PeerEndpoint, error) {
	reader := bytes.NewReader(payload)
	var count uint16
	if binary.Read(reader, binary.BigEndian, &count) != nil || count == 0 || count > 16 {
		return nil, ErrCeremonyRequest
	}
	endpoints := make([]PeerEndpoint, 0, count)
	for index := 0; index < int(count); index++ {
		var point uint64
		var length uint16
		if binary.Read(reader, binary.BigEndian, &point) != nil ||
			binary.Read(reader, binary.BigEndian, &length) != nil ||
			length == 0 || int(length) > reader.Len() {
			return nil, ErrCeremonyRequest
		}
		raw := make([]byte, length)
		if _, err := io.ReadFull(reader, raw); err != nil {
			return nil, ErrCeremonyRequest
		}
		endpoints = append(endpoints, PeerEndpoint{Point: point, URL: string(raw)})
	}
	if reader.Len() != 0 {
		return nil, ErrCeremonyRequest
	}
	return endpoints, nil
}

// CeremonyClient is the coordinator's driver for one operator.
type CeremonyClient struct {
	BaseURL    string
	HTTPClient *http.Client
	SigningKey ed25519.PrivateKey
}

// Step sends one signed ceremony operation and returns the bounded response.
func (client *CeremonyClient) Step(ctx context.Context, operation CeremonyOperation, payload []byte) ([]byte, error) {
	if client == nil || client.HTTPClient == nil || client.BaseURL == "" || len(client.SigningKey) != ed25519.PrivateKeySize {
		return nil, ErrCeremonyUnauthorized
	}
	if len(payload) > maxCeremonyPayloadBytes {
		return nil, ErrCeremonyRequest
	}
	request := ceremonyRequest{Operation: operation, Payload: payload}
	if _, err := rand.Read(request.Nonce[:]); err != nil {
		return nil, err
	}
	digest := ceremonyRequestDigest(request)
	copy(request.Signature[:], ed25519.Sign(client.SigningKey, digest[:]))
	wire, err := request.marshalBinary()
	if err != nil {
		return nil, err
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, client.BaseURL+ceremonyPath, bytes.NewReader(wire))
	if err != nil {
		return nil, err
	}
	httpRequest.Header.Set("Content-Type", ceremonyContentType)
	response, err := client.HTTPClient.Do(httpRequest)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxCeremonyResponseBytes+1))
	if err != nil {
		return nil, err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("%w: operator returned %d", ErrCeremonyRejected, response.StatusCode)
	}
	return body, nil
}

// CeremonyStatus fetches the operator's own account of its ceremony state.
func (client *CeremonyClient) CeremonyStatus(ctx context.Context) ([]byte, error) {
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, client.BaseURL+ceremonyStatusPath, nil)
	if err != nil {
		return nil, err
	}
	response, err := client.HTTPClient.Do(httpRequest)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: status %d", ErrCeremonyRejected, response.StatusCode)
	}
	return body, nil
}

// PeerTLSConfig pins the peer operator's roster key on the client side, so an
// operator will not hand its Shamir re-sharing to a substituted endpoint even
// if that endpoint holds a CA-issued certificate.
func PeerTLSConfig(certificate tls.Certificate, roots *x509.CertPool, serverName string, expected ed25519.PublicKey) *tls.Config {
	config := ClientTLSConfig(certificate, roots, serverName)
	config.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return ErrCeremonyUnauthorized
		}
		parsed, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return err
		}
		presented, ok := parsed.PublicKey.(ed25519.PublicKey)
		if !ok || subtle.ConstantTimeCompare(presented, expected) != 1 {
			return fmt.Errorf("%w: peer key is not the roster key", ErrCeremonyUnauthorized)
		}
		return nil
	}
	return config
}

type ceremonyRequest struct {
	Operation CeremonyOperation
	Payload   []byte
	Nonce     [32]byte
	Signature [ed25519.SignatureSize]byte
}

func (request ceremonyRequest) marshalBinary() ([]byte, error) {
	if request.Operation < OpContribution || request.Operation > OpSealManifest ||
		len(request.Payload) > maxCeremonyPayloadBytes || request.Nonce == ([32]byte{}) {
		return nil, ErrCeremonyRequest
	}
	var out bytes.Buffer
	out.WriteString(ceremonyWireMagic)
	out.WriteByte(byte(request.Operation))
	_ = binary.Write(&out, binary.BigEndian, uint32(len(request.Payload)))
	out.Write(request.Payload)
	out.Write(request.Nonce[:])
	out.Write(request.Signature[:])
	return out.Bytes(), nil
}

func unmarshalCeremonyRequest(data []byte) (ceremonyRequest, error) {
	var request ceremonyRequest
	reader := bytes.NewReader(data)
	magic := make([]byte, len(ceremonyWireMagic))
	if _, err := io.ReadFull(reader, magic); err != nil || string(magic) != ceremonyWireMagic {
		return request, ErrCeremonyRequest
	}
	operation, err := reader.ReadByte()
	if err != nil {
		return request, ErrCeremonyRequest
	}
	request.Operation = CeremonyOperation(operation)
	var length uint32
	if binary.Read(reader, binary.BigEndian, &length) != nil ||
		length > maxCeremonyPayloadBytes || uint64(length) > uint64(reader.Len()) {
		return request, ErrCeremonyRequest
	}
	request.Payload = make([]byte, length)
	if _, err := io.ReadFull(reader, request.Payload); err != nil {
		return request, ErrCeremonyRequest
	}
	if _, err := io.ReadFull(reader, request.Nonce[:]); err != nil {
		return request, ErrCeremonyRequest
	}
	if _, err := io.ReadFull(reader, request.Signature[:]); err != nil || reader.Len() != 0 {
		return request, ErrCeremonyRequest
	}
	if request.Operation < OpContribution || request.Operation > OpSealManifest || request.Nonce == ([32]byte{}) {
		return request, ErrCeremonyRequest
	}
	return request, nil
}

func ceremonyRequestDigest(request ceremonyRequest) [32]byte {
	payloadDigest := sha256.Sum256(request.Payload)
	hash := sha256.New()
	_, _ = hash.Write([]byte(ceremonyWireDomain))
	_, _ = hash.Write([]byte{0, byte(request.Operation)})
	_, _ = hash.Write(payloadDigest[:])
	_, _ = hash.Write(request.Nonce[:])
	var digest [32]byte
	copy(digest[:], hash.Sum(nil))
	return digest
}

func verifyCeremonyRequest(request ceremonyRequest, publicKey ed25519.PublicKey) bool {
	if request.Nonce == ([32]byte{}) || len(publicKey) != ed25519.PublicKeySize {
		return false
	}
	digest := ceremonyRequestDigest(request)
	return ed25519.Verify(publicKey, digest[:], request.Signature[:])
}

// EncodeCRSContributions packs the public contribution table for OpSealCRS.
func EncodeCRSContributions(contributions map[uint64][32]byte) []byte {
	points := make([]uint64, 0, len(contributions))
	for point := range contributions {
		points = append(points, point)
	}
	sort.Slice(points, func(i, j int) bool { return points[i] < points[j] })
	out := make([]byte, 0, len(points)*40)
	for _, point := range points {
		var header [8]byte
		binary.BigEndian.PutUint64(header[:], point)
		value := contributions[point]
		out = append(out, header[:]...)
		out = append(out, value[:]...)
	}
	return out
}

// EncodeKeyDigests packs the manifest commitments for OpSealManifest.
func EncodeKeyDigests(digests spike.CeremonyKeyDigests) []byte {
	out := make([]byte, 0, 160)
	out = append(out, digests.CRSCommitment[:]...)
	out = append(out, digests.PublicKeyCommitment[:]...)
	out = append(out, digests.RelinearizationKeyDigest[:]...)
	out = append(out, digests.GaloisKeyCommitment[:]...)
	out = append(out, digests.PolicyCircuitCommitment[:]...)
	return out
}
