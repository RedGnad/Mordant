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
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"time"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	spike "mordant.dev/fhe-lab/lattigo"
)

const (
	wireMagic           = "MTN1"
	wireDomain          = "mordant.threshold.network-request/v1"
	contentType         = "application/vnd.mordant.threshold-v1"
	maxDescriptorBytes  = 4 << 10
	maxCiphertextBytes  = 128 << 20
	maxNetworkBodyBytes = maxDescriptorBytes + maxCiphertextBytes + 512
	preparePath         = "/v1/prepare"
	commitPath          = "/v1/commit"
	ackPath             = "/v1/ack"
)

type operation uint8

const (
	operationPrepare operation = 1
	operationCommit  operation = 2
	operationAck     operation = 3
)

var (
	ErrUnauthorizedCoordinator = errors.New("unauthorized threshold coordinator")
	ErrMalformedRequest        = errors.New("malformed threshold network request")
	ErrProtocolState           = errors.New("invalid threshold network state")
)

type signedRequest struct {
	Operation      operation
	Descriptor     []byte
	Ciphertext     []byte
	ResponseDigest [32]byte
	Nonce          [32]byte
	Signature      [ed25519.SignatureSize]byte
}

// OperatorServer owns one threshold operator and its durable one-shot ledger.
// It must be mounted only on a TLS 1.3 server configured by ServerTLSConfig.
type OperatorServer struct {
	Operator             *spike.ThresholdOperator
	Ledger               *Store
	CoordinatorPublicKey ed25519.PublicKey
	Now                  func() time.Time
}

// Handler returns the binary threshold protocol handler.
func (server *OperatorServer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(preparePath, server.handlePrepare)
	mux.HandleFunc(commitPath, server.handleCommit)
	mux.HandleFunc(ackPath, server.handleAck)
	return mux
}

// ServerTLSConfig enforces TLS 1.3 and a client certificate rooted in clientCAs.
func ServerTLSConfig(certificate tls.Certificate, clientCAs *x509.CertPool) *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{certificate},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAs,
	}
}

// ClientTLSConfig enforces TLS 1.3 and verifies the operator hostname.
func ClientTLSConfig(certificate tls.Certificate, roots *x509.CertPool, serverName string) *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{certificate},
		RootCAs:      roots,
		ServerName:   serverName,
	}
}

func (server *OperatorServer) handlePrepare(writer http.ResponseWriter, request *http.Request) {
	parsed, descriptor, ciphertext, ok := server.authorize(writer, request, operationPrepare, true)
	if !ok {
		return
	}
	if err := server.Operator.ValidateReleaseRequest(descriptor, ciphertext); err != nil {
		writeBoundedError(writer, http.StatusUnprocessableEntity, "release request rejected")
		return
	}
	coalition := coalitionDigest(descriptor.Coalition)
	if _, err := server.Ledger.Prepare(Descriptor{
		SessionID:       descriptor.SessionID,
		Binding:         descriptor.ProtocolBinding,
		CoalitionDigest: coalition,
	}); err != nil {
		if errors.Is(err, ErrBindingConsumed) || errors.Is(err, ErrSessionExists) {
			writeBoundedError(writer, http.StatusConflict, "protocol binding consumed")
			return
		}
		writeBoundedError(writer, http.StatusInternalServerError, "ledger prepare failed")
		return
	}
	_ = parsed
	writer.WriteHeader(http.StatusNoContent)
}

func (server *OperatorServer) handleCommit(writer http.ResponseWriter, request *http.Request) {
	_, descriptor, ciphertext, ok := server.authorize(writer, request, operationCommit, true)
	if !ok {
		return
	}
	if err := server.Operator.ValidateReleaseRequest(descriptor, ciphertext); err != nil {
		writeBoundedError(writer, http.StatusUnprocessableEntity, "release request rejected")
		return
	}
	record, err := server.Ledger.Get(descriptor.SessionID)
	if err != nil || record.Binding != descriptor.ProtocolBinding || record.CoalitionDigest != coalitionDigest(descriptor.Coalition) || record.State != StatePrepared {
		writeBoundedError(writer, http.StatusConflict, "session is not prepared")
		return
	}
	// This synchronous bbolt transition is the commit barrier. No FHE share is
	// generated until it has returned successfully.
	if _, err := server.Ledger.Commit(descriptor.SessionID); err != nil {
		writeBoundedError(writer, http.StatusConflict, "session commit rejected")
		return
	}
	response, err := server.Operator.GenerateReleaseShare(descriptor, ciphertext)
	if err != nil {
		_, _ = server.Ledger.FailTerminal(descriptor.SessionID, FailureGeneration)
		writeBoundedError(writer, http.StatusUnprocessableEntity, "share generation failed")
		return
	}
	wire, err := response.MarshalBinary()
	if err != nil {
		_, _ = server.Ledger.FailTerminal(descriptor.SessionID, FailureGeneration)
		writeBoundedError(writer, http.StatusInternalServerError, "share encoding failed")
		return
	}
	responseDigest := sha256.Sum256(wire)
	if _, err := server.Ledger.MarkGenerated(descriptor.SessionID, responseDigest); err != nil {
		_, _ = server.Ledger.FailTerminal(descriptor.SessionID, FailureGeneration)
		writeBoundedError(writer, http.StatusInternalServerError, "share state failed")
		return
	}
	// RELEASED is durable before bytes leave the process. A dropped response is
	// terminal and cannot be retried with this or a substitute coalition.
	if _, err := server.Ledger.MarkReleased(descriptor.SessionID); err != nil {
		_, _ = server.Ledger.FailTerminal(descriptor.SessionID, FailureRelease)
		writeBoundedError(writer, http.StatusInternalServerError, "release state failed")
		return
	}
	writer.Header().Set("Content-Type", contentType)
	writer.Header().Set("Content-Length", fmt.Sprintf("%d", len(wire)))
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(wire)
}

func (server *OperatorServer) handleAck(writer http.ResponseWriter, request *http.Request) {
	parsed, descriptor, _, ok := server.authorize(writer, request, operationAck, false)
	if !ok {
		return
	}
	record, err := server.Ledger.Get(descriptor.SessionID)
	if err != nil || record.Binding != descriptor.ProtocolBinding || record.State != StateReleased ||
		subtle.ConstantTimeCompare(record.ResponseDigest[:], parsed.ResponseDigest[:]) != 1 {
		writeBoundedError(writer, http.StatusConflict, "release acknowledgement rejected")
		return
	}
	if _, err := server.Ledger.MarkAcked(descriptor.SessionID); err != nil {
		writeBoundedError(writer, http.StatusConflict, "release acknowledgement rejected")
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

func (server *OperatorServer) authorize(writer http.ResponseWriter, request *http.Request, expected operation, needsCiphertext bool) (signedRequest, spike.ReleaseDescriptor, *rlwe.Ciphertext, bool) {
	if request.Method != http.MethodPost || request.TLS == nil || len(request.TLS.VerifiedChains) == 0 ||
		server.Operator == nil || server.Ledger == nil || len(server.CoordinatorPublicKey) != ed25519.PublicKeySize {
		writeBoundedError(writer, http.StatusUnauthorized, "coordinator authentication required")
		return signedRequest{}, spike.ReleaseDescriptor{}, nil, false
	}
	peerKey, ok := request.TLS.PeerCertificates[0].PublicKey.(ed25519.PublicKey)
	if !ok || subtle.ConstantTimeCompare(peerKey, server.CoordinatorPublicKey) != 1 {
		writeBoundedError(writer, http.StatusUnauthorized, "coordinator authentication required")
		return signedRequest{}, spike.ReleaseDescriptor{}, nil, false
	}
	request.Body = http.MaxBytesReader(writer, request.Body, maxNetworkBodyBytes)
	body, err := io.ReadAll(request.Body)
	if err != nil {
		writeBoundedError(writer, http.StatusBadRequest, "invalid binary request")
		return signedRequest{}, spike.ReleaseDescriptor{}, nil, false
	}
	parsed, err := unmarshalSignedRequest(body)
	if err != nil || parsed.Operation != expected || !verifySignedRequest(parsed, server.CoordinatorPublicKey) {
		writeBoundedError(writer, http.StatusUnauthorized, "invalid signed request")
		return signedRequest{}, spike.ReleaseDescriptor{}, nil, false
	}
	descriptor, err := spike.UnmarshalReleaseDescriptor(parsed.Descriptor)
	if err != nil {
		writeBoundedError(writer, http.StatusBadRequest, "invalid release descriptor")
		return signedRequest{}, spike.ReleaseDescriptor{}, nil, false
	}
	now := time.Now()
	if server.Now != nil {
		now = server.Now()
	}
	if descriptor.ValidUntil < uint64(now.Unix()) {
		writeBoundedError(writer, http.StatusGone, "release descriptor expired")
		return signedRequest{}, spike.ReleaseDescriptor{}, nil, false
	}
	if !needsCiphertext {
		if len(parsed.Ciphertext) != 0 || parsed.ResponseDigest == ([32]byte{}) {
			writeBoundedError(writer, http.StatusBadRequest, "invalid acknowledgement")
			return signedRequest{}, spike.ReleaseDescriptor{}, nil, false
		}
		return parsed, descriptor, nil, true
	}
	if len(parsed.Ciphertext) == 0 || parsed.ResponseDigest != ([32]byte{}) {
		writeBoundedError(writer, http.StatusBadRequest, "invalid release payload")
		return signedRequest{}, spike.ReleaseDescriptor{}, nil, false
	}
	ciphertext := new(rlwe.Ciphertext)
	if err := ciphertext.UnmarshalBinary(parsed.Ciphertext); err != nil {
		writeBoundedError(writer, http.StatusBadRequest, "invalid result ciphertext")
		return signedRequest{}, spike.ReleaseDescriptor{}, nil, false
	}
	return parsed, descriptor, ciphertext, true
}

// OperatorClient sends signed binary requests to exactly one selected node.
// It has no discovery or fallback logic by design.
type OperatorClient struct {
	BaseURL    string
	HTTPClient *http.Client
	SigningKey ed25519.PrivateKey
}

func (client *OperatorClient) Prepare(ctx context.Context, descriptor spike.ReleaseDescriptor, ciphertext *rlwe.Ciphertext) error {
	_, err := client.call(ctx, operationPrepare, descriptor, ciphertext, [32]byte{})
	return err
}

func (client *OperatorClient) Commit(ctx context.Context, descriptor spike.ReleaseDescriptor, ciphertext *rlwe.Ciphertext) (spike.ThresholdReleaseResponse, [32]byte, error) {
	var zero [32]byte
	wire, err := client.call(ctx, operationCommit, descriptor, ciphertext, zero)
	if err != nil {
		return spike.ThresholdReleaseResponse{}, zero, err
	}
	response, err := spike.UnmarshalThresholdReleaseResponse(wire)
	if err != nil {
		return spike.ThresholdReleaseResponse{}, zero, err
	}
	return response, sha256.Sum256(wire), nil
}

func (client *OperatorClient) Ack(ctx context.Context, descriptor spike.ReleaseDescriptor, responseDigest [32]byte) error {
	_, err := client.call(ctx, operationAck, descriptor, nil, responseDigest)
	return err
}

// ReleaseSelectedCoalition runs PREPARE and COMMIT against exactly the two
// clients selected by the descriptor. There is deliberately no discovery or
// fallback parameter. persist must durably journal both response wires (for
// example, write+fsync) before either operator receives ACK.
func ReleaseSelectedCoalition(
	ctx context.Context,
	clients [2]*OperatorClient,
	descriptor spike.ReleaseDescriptor,
	ciphertext *rlwe.Ciphertext,
	persist func([2][]byte) error,
) ([2]spike.ThresholdReleaseResponse, error) {
	var responses [2]spike.ThresholdReleaseResponse
	var digests [2][32]byte
	var wires [2][]byte
	if clients[0] == nil || clients[1] == nil || persist == nil {
		return responses, ErrProtocolState
	}
	for _, client := range clients {
		if err := client.Prepare(ctx, descriptor, ciphertext); err != nil {
			return responses, err
		}
	}
	for index, client := range clients {
		response, digest, err := client.Commit(ctx, descriptor, ciphertext)
		if err != nil {
			return responses, err
		}
		wire, err := response.MarshalBinary()
		if err != nil || sha256.Sum256(wire) != digest {
			return responses, ErrMalformedRequest
		}
		responses[index], digests[index], wires[index] = response, digest, wire
	}
	if err := persist(wires); err != nil {
		return responses, fmt.Errorf("persist threshold responses: %w", err)
	}
	for index, client := range clients {
		if err := client.Ack(ctx, descriptor, digests[index]); err != nil {
			return responses, err
		}
	}
	return responses, nil
}

func (client *OperatorClient) call(ctx context.Context, op operation, descriptor spike.ReleaseDescriptor, ciphertext *rlwe.Ciphertext, responseDigest [32]byte) ([]byte, error) {
	if client == nil || client.HTTPClient == nil || client.BaseURL == "" || len(client.SigningKey) != ed25519.PrivateKeySize {
		return nil, ErrUnauthorizedCoordinator
	}
	descriptorWire, err := descriptor.MarshalBinary()
	if err != nil {
		return nil, err
	}
	var ciphertextWire []byte
	if ciphertext != nil {
		ciphertextWire, err = ciphertext.MarshalBinary()
		if err != nil || len(ciphertextWire) > maxCiphertextBytes {
			return nil, ErrMalformedRequest
		}
	}
	request := signedRequest{Operation: op, Descriptor: descriptorWire, Ciphertext: ciphertextWire, ResponseDigest: responseDigest}
	if _, err := rand.Read(request.Nonce[:]); err != nil {
		return nil, err
	}
	digest := signedRequestDigest(request)
	copy(request.Signature[:], ed25519.Sign(client.SigningKey, digest[:]))
	wire, err := request.marshalBinary()
	if err != nil {
		return nil, err
	}
	path := map[operation]string{operationPrepare: preparePath, operationCommit: commitPath, operationAck: ackPath}[op]
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, client.BaseURL+path, bytes.NewReader(wire))
	if err != nil {
		return nil, err
	}
	httpRequest.Header.Set("Content-Type", contentType)
	response, err := client.HTTPClient.Do(httpRequest)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	responseBody, readErr := io.ReadAll(io.LimitReader(response.Body, maxReleaseResponseBytes+1))
	if readErr != nil {
		return nil, readErr
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("%w: operator returned %d", ErrProtocolState, response.StatusCode)
	}
	if op == operationCommit {
		if len(responseBody) == 0 || len(responseBody) > maxReleaseResponseBytes {
			return nil, ErrMalformedRequest
		}
		return responseBody, nil
	}
	if len(responseBody) != 0 {
		return nil, ErrMalformedRequest
	}
	return nil, nil
}

const maxReleaseResponseBytes = 64<<20 + 512

func (request signedRequest) marshalBinary() ([]byte, error) {
	if request.Operation < operationPrepare || request.Operation > operationAck ||
		len(request.Descriptor) == 0 || len(request.Descriptor) > maxDescriptorBytes ||
		len(request.Ciphertext) > maxCiphertextBytes || request.Nonce == ([32]byte{}) {
		return nil, ErrMalformedRequest
	}
	var out bytes.Buffer
	out.WriteString(wireMagic)
	out.WriteByte(byte(request.Operation))
	_ = binary.Write(&out, binary.BigEndian, uint32(len(request.Descriptor)))
	out.Write(request.Descriptor)
	_ = binary.Write(&out, binary.BigEndian, uint32(len(request.Ciphertext)))
	out.Write(request.Ciphertext)
	out.Write(request.ResponseDigest[:])
	out.Write(request.Nonce[:])
	out.Write(request.Signature[:])
	return out.Bytes(), nil
}

func unmarshalSignedRequest(data []byte) (signedRequest, error) {
	reader := bytes.NewReader(data)
	magic := make([]byte, len(wireMagic))
	if _, err := io.ReadFull(reader, magic); err != nil || string(magic) != wireMagic {
		return signedRequest{}, ErrMalformedRequest
	}
	op, err := reader.ReadByte()
	if err != nil {
		return signedRequest{}, ErrMalformedRequest
	}
	request := signedRequest{Operation: operation(op)}
	var descriptorLength, ciphertextLength uint32
	if binary.Read(reader, binary.BigEndian, &descriptorLength) != nil || descriptorLength == 0 || descriptorLength > maxDescriptorBytes || uint64(descriptorLength) > uint64(reader.Len()) {
		return signedRequest{}, ErrMalformedRequest
	}
	request.Descriptor = make([]byte, descriptorLength)
	if _, err := io.ReadFull(reader, request.Descriptor); err != nil || binary.Read(reader, binary.BigEndian, &ciphertextLength) != nil || ciphertextLength > maxCiphertextBytes || uint64(ciphertextLength) > uint64(reader.Len()) {
		return signedRequest{}, ErrMalformedRequest
	}
	request.Ciphertext = make([]byte, ciphertextLength)
	if _, err := io.ReadFull(reader, request.Ciphertext); err != nil ||
		readFull(reader, request.ResponseDigest[:], request.Nonce[:], request.Signature[:]) != nil || reader.Len() != 0 {
		return signedRequest{}, ErrMalformedRequest
	}
	return request, nil
}

func signedRequestDigest(request signedRequest) [32]byte {
	descriptorDigest := sha256.Sum256(request.Descriptor)
	ciphertextDigest := sha256.Sum256(request.Ciphertext)
	hash := sha256.New()
	_, _ = hash.Write([]byte(wireDomain))
	_, _ = hash.Write([]byte{0, byte(request.Operation)})
	_, _ = hash.Write(descriptorDigest[:])
	_, _ = hash.Write(ciphertextDigest[:])
	_, _ = hash.Write(request.ResponseDigest[:])
	_, _ = hash.Write(request.Nonce[:])
	var digest [32]byte
	copy(digest[:], hash.Sum(nil))
	return digest
}

func verifySignedRequest(request signedRequest, publicKey ed25519.PublicKey) bool {
	if request.Nonce == ([32]byte{}) || len(publicKey) != ed25519.PublicKeySize {
		return false
	}
	digest := signedRequestDigest(request)
	return ed25519.Verify(publicKey, digest[:], request.Signature[:])
}

func coalitionDigest(coalition [2]uint64) [32]byte {
	points := []uint64{coalition[0], coalition[1]}
	sort.Slice(points, func(i, j int) bool { return points[i] < points[j] })
	var encoded [16]byte
	binary.BigEndian.PutUint64(encoded[:8], points[0])
	binary.BigEndian.PutUint64(encoded[8:], points[1])
	return sha256.Sum256(append([]byte("mordant.threshold.coalition/v1\x00"), encoded[:]...))
}

func writeBoundedError(writer http.ResponseWriter, status int, message string) {
	writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
	writer.WriteHeader(status)
	_, _ = io.WriteString(writer, message)
}

func readFull(reader io.Reader, values ...[]byte) error {
	for _, value := range values {
		if _, err := io.ReadFull(reader, value); err != nil {
			return err
		}
	}
	return nil
}
