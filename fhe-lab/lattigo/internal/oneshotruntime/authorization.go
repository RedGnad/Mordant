package oneshotruntime

import (
	"bytes"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
	ceremony "mordant.dev/fhe-lab/lattigo/oneshotceremony"
)

const (
	SessionAuthoritySchema     = "mordant.oneshot-session-authority/1"
	SessionAuthorizationSchema = "mordant.oneshot-session-authorization/1"
	AuthorizedRequestSchema    = "mordant.oneshot-authorized-request/1"
	AuthorizedSessionSchema    = "mordant.oneshot-authorized-session/1"
)

var ErrAuthorization = errors.New("one-shot runtime authorization rejected")

type SessionAuthorityDocument struct {
	SchemaVersion string `json:"schemaVersion" required:"true"`
	PublicKey     string `json:"publicKey" required:"true"`
}

type SessionAuthorization struct {
	SchemaVersion           string
	AuthorizationID         [32]byte
	ContextDigest           [32]byte
	CeremonyID              [32]byte
	SessionBindingDigest    [32]byte
	SessionIdentity         [32]byte
	SessionCommitment       [32]byte
	RosterDigest            [32]byte
	OrderedRoster           [ceremony.PartyCount][32]byte
	PrivacyDomain           [32]byte
	ServiceID               [32]byte
	ServiceVersion          uint32
	ChainID                 uint64
	PolicyID                [32]byte
	PolicyVersion           uint32
	CircuitVersion          uint32
	CircuitDigest           [32]byte
	ReleaseLayout           uint32
	MaximumReleaseQueries   uint32
	ContextActivatesAtUnix  int64
	ContextExpiresAtUnix    int64
	RequestSigningPublicKey [ed25519.PublicKeySize]byte
	NotBeforeUnix           int64
	ExpiresAtUnix           int64
	Signature               [ed25519.SignatureSize]byte
}

type AuthorizedRequest struct {
	SchemaVersion   string
	AuthorizationID [32]byte
	CeremonyID      [32]byte
	ContextDigest   [32]byte
	Operation       string
	PayloadDigest   [32]byte
	RequestID       [32]byte
	Sequence        uint64
	ExpiresAtUnix   int64
	Signature       [ed25519.SignatureSize]byte
}

type AuthorizedSessionFile struct {
	SchemaVersion            string `json:"schemaVersion" required:"true"`
	Context                  []byte `json:"context" required:"true"`
	Authorization            []byte `json:"authorization" required:"true"`
	RequestSigningPrivateKey string `json:"requestSigningPrivateKey" required:"true"`
}

type AuthorizedSession struct {
	Context            ceremony.Context
	ContextBytes       []byte
	Authorization      SessionAuthorization
	AuthorizationBytes []byte
	RequestSigningKey  ed25519.PrivateKey
}

func InitializeSessionAuthority(directory string) (SessionAuthorityDocument, error) {
	if !filepath.IsAbs(directory) {
		return SessionAuthorityDocument{}, ErrConfig
	}
	if err := os.Mkdir(directory, 0o700); err != nil {
		return SessionAuthorityDocument{}, ErrConfig
	}
	publicKey, privateKey, err := ed25519.GenerateKey(cryptorand.Reader)
	if err != nil {
		return SessionAuthorityDocument{}, ErrConfig
	}
	document := SessionAuthorityDocument{SchemaVersion: SessionAuthoritySchema, PublicKey: hex.EncodeToString(publicKey)}
	if err := writeNoReplace(filepath.Join(directory, "session-authority.key"), privateKey, 0o600); err != nil {
		return SessionAuthorityDocument{}, err
	}
	if err := writeJSONNoReplace(filepath.Join(directory, "session-authority-public.json"), document, 0o600); err != nil {
		return SessionAuthorityDocument{}, err
	}
	return document, nil
}

func LoadSessionAuthorityPublic(path string) (SessionAuthorityDocument, error) {
	var document SessionAuthorityDocument
	if err := readStrictJSON(path, &document, maxConfigBytes, false); err != nil || document.SchemaVersion != SessionAuthoritySchema {
		return SessionAuthorityDocument{}, ErrConfig
	}
	if _, err := document.publicKey(); err != nil {
		return SessionAuthorityDocument{}, err
	}
	return document, nil
}

func LoadSessionAuthorityPrivate(path string) (ed25519.PrivateKey, error) {
	data, err := readRestrictedExact(path, ed25519.PrivateKeySize, 0o600)
	if err != nil || len(data) != ed25519.PrivateKeySize {
		return nil, ErrConfig
	}
	privateKey := ed25519.PrivateKey(slices.Clone(data))
	publicKey := privateKey.Public().(ed25519.PublicKey)
	if len(publicKey) != ed25519.PublicKeySize || bytes.Equal(publicKey, make([]byte, ed25519.PublicKeySize)) {
		return nil, ErrConfig
	}
	return privateKey, nil
}

func (d SessionAuthorityDocument) publicKey() (ed25519.PublicKey, error) {
	if d.SchemaVersion != SessionAuthoritySchema {
		return nil, ErrConfig
	}
	decoded, err := hex.DecodeString(d.PublicKey)
	if err != nil || len(decoded) != ed25519.PublicKeySize || bytes.Equal(decoded, make([]byte, ed25519.PublicKeySize)) {
		return nil, ErrConfig
	}
	return ed25519.PublicKey(decoded), nil
}

func NewAuthorizedSession(config RunnerConfig, params bgv.Parameters, authority ed25519.PrivateKey, values SessionValues, now time.Time) (AuthorizedSession, error) {
	contextValue, err := buildContext(config, params, values, now)
	if err != nil {
		return AuthorizedSession{}, err
	}
	return AuthorizeContext(config, authority, contextValue, now)
}

func AuthorizeContext(config RunnerConfig, authority ed25519.PrivateKey, contextValue ceremony.Context, now time.Time) (AuthorizedSession, error) {
	if config.validate() != nil || contextValue.Validate() != nil || len(authority) != ed25519.PrivateKeySize {
		return AuthorizedSession{}, ErrAuthorization
	}
	configuredAuthority, err := decodePublicKey(config.SessionAuthorityPublicKey)
	if err != nil || !slices.Equal(configuredAuthority, authority.Public().(ed25519.PublicKey)) || !contextMatchesRunner(config, contextValue) {
		return AuthorizedSession{}, ErrAuthorization
	}
	requestPublic, requestPrivate, err := ed25519.GenerateKey(cryptorand.Reader)
	if err != nil {
		return AuthorizedSession{}, ErrAuthorization
	}
	authorizationID, err := random32()
	if err != nil {
		return AuthorizedSession{}, err
	}
	authorization := authorizationForContext(contextValue, authorizationID, requestPublic, now)
	unsigned, err := authorization.signingBytes()
	if err != nil {
		return AuthorizedSession{}, err
	}
	copy(authorization.Signature[:], ed25519.Sign(authority, authorizationSigningMessage(unsigned)))
	authorizationBytes, err := authorization.MarshalBinary()
	if err != nil {
		return AuthorizedSession{}, err
	}
	contextBytes, err := contextValue.MarshalBinary()
	if err != nil {
		return AuthorizedSession{}, err
	}
	return AuthorizedSession{
		Context: contextValue, ContextBytes: contextBytes, Authorization: authorization,
		AuthorizationBytes: authorizationBytes, RequestSigningKey: requestPrivate,
	}, nil
}

func authorizationForContext(contextValue ceremony.Context, authorizationID [32]byte, requestPublic ed25519.PublicKey, now time.Time) SessionAuthorization {
	authorization := SessionAuthorization{
		SchemaVersion:          SessionAuthorizationSchema,
		AuthorizationID:        authorizationID,
		ContextDigest:          contextValue.ContextDigest(),
		CeremonyID:             contextValue.CeremonyID(),
		SessionBindingDigest:   contextValue.SessionBindingDigest(),
		SessionIdentity:        contextValue.SessionIdentity,
		SessionCommitment:      contextValue.SessionCommitment,
		RosterDigest:           contextValue.RosterDigest(),
		PrivacyDomain:          contextValue.PrivacyDomain,
		ServiceID:              contextValue.ServiceID,
		ServiceVersion:         contextValue.ServiceVersion,
		ChainID:                contextValue.ChainID,
		PolicyID:               contextValue.PolicyID,
		PolicyVersion:          contextValue.PolicyVersion,
		CircuitVersion:         contextValue.CircuitVersion,
		CircuitDigest:          contextValue.CircuitDigest,
		ReleaseLayout:          contextValue.ReleaseLayout,
		MaximumReleaseQueries:  contextValue.MaximumReleaseQueries,
		ContextActivatesAtUnix: contextValue.ActivatesAtUnix,
		ContextExpiresAtUnix:   contextValue.ExpiresAtUnix,
		NotBeforeUnix:          now.Add(-30 * time.Second).Unix(),
		ExpiresAtUnix:          contextValue.ExpiresAtUnix,
	}
	copy(authorization.RequestSigningPublicKey[:], requestPublic)
	for index := range contextValue.Operators {
		authorization.OrderedRoster[index] = operatorIdentityDigest(contextValue.Operators[index])
	}
	return authorization
}

func WriteAuthorizedSession(path string, session AuthorizedSession) error {
	if err := session.Validate(time.Now().UTC()); err != nil {
		return err
	}
	file := AuthorizedSessionFile{
		SchemaVersion: AuthorizedSessionSchema, Context: slices.Clone(session.ContextBytes),
		Authorization: slices.Clone(session.AuthorizationBytes), RequestSigningPrivateKey: hex.EncodeToString(session.RequestSigningKey),
	}
	return writeJSONNoReplace(path, file, 0o600)
}

func LoadAuthorizedSession(path string, config RunnerConfig) (AuthorizedSession, error) {
	var file AuthorizedSessionFile
	if err := readStrictJSONExact(path, &file, maxConfigBytes, 0o600); err != nil || file.SchemaVersion != AuthorizedSessionSchema {
		return AuthorizedSession{}, ErrAuthorization
	}
	contextValue, err := ceremony.ParseContext(file.Context)
	if err != nil || !contextMatchesRunner(config, contextValue) {
		return AuthorizedSession{}, ErrAuthorization
	}
	authorization, err := ParseSessionAuthorization(file.Authorization)
	if err != nil {
		return AuthorizedSession{}, err
	}
	privateBytes, err := hex.DecodeString(file.RequestSigningPrivateKey)
	if err != nil || len(privateBytes) != ed25519.PrivateKeySize {
		return AuthorizedSession{}, ErrAuthorization
	}
	session := AuthorizedSession{
		Context: contextValue, ContextBytes: slices.Clone(file.Context), Authorization: authorization,
		AuthorizationBytes: slices.Clone(file.Authorization), RequestSigningKey: ed25519.PrivateKey(privateBytes),
	}
	if err := session.Validate(time.Now().UTC()); err != nil {
		return AuthorizedSession{}, err
	}
	configuredAuthority, err := decodePublicKey(config.SessionAuthorityPublicKey)
	if err != nil || VerifySessionAuthorization(configuredAuthority, contextValue, authorization, time.Now().UTC()) != nil {
		return AuthorizedSession{}, ErrAuthorization
	}
	return session, nil
}

func (s AuthorizedSession) Validate(now time.Time) error {
	if s.Context.Validate() != nil || len(s.ContextBytes) == 0 || len(s.AuthorizationBytes) == 0 || len(s.RequestSigningKey) != ed25519.PrivateKeySize {
		return ErrAuthorization
	}
	parsedContext, err := ceremony.ParseContext(s.ContextBytes)
	if err != nil || parsedContext.ContextDigest() != s.Context.ContextDigest() {
		return ErrAuthorization
	}
	parsedAuthorization, err := ParseSessionAuthorization(s.AuthorizationBytes)
	if err != nil || parsedAuthorization != s.Authorization || now.Unix() < s.Authorization.NotBeforeUnix || now.Unix() > s.Authorization.ExpiresAtUnix {
		return ErrAuthorization
	}
	if !slices.Equal(s.RequestSigningKey.Public().(ed25519.PublicKey), s.Authorization.RequestSigningPublicKey[:]) {
		return ErrAuthorization
	}
	return nil
}

func (a SessionAuthorization) signingBytes() ([]byte, error) {
	if a.SchemaVersion != SessionAuthorizationSchema || zero32(a.AuthorizationID) || zero32(a.ContextDigest) || zero32(a.CeremonyID) ||
		zero32(a.SessionBindingDigest) || zero32(a.SessionIdentity) || zero32(a.SessionCommitment) || zero32(a.RosterDigest) ||
		zero32(a.PrivacyDomain) || zero32(a.ServiceID) || a.ServiceVersion == 0 || a.ChainID == 0 || zero32(a.PolicyID) ||
		a.PolicyVersion == 0 || a.CircuitVersion == 0 || zero32(a.CircuitDigest) || a.ReleaseLayout == 0 ||
		a.MaximumReleaseQueries == 0 || a.ContextActivatesAtUnix <= 0 || a.ContextExpiresAtUnix <= a.ContextActivatesAtUnix ||
		a.NotBeforeUnix <= 0 || a.ExpiresAtUnix <= a.NotBeforeUnix || a.ExpiresAtUnix > a.ContextExpiresAtUnix ||
		bytes.Equal(a.RequestSigningPublicKey[:], make([]byte, ed25519.PublicKeySize)) {
		return nil, ErrAuthorization
	}
	var encoder canonicalEncoder
	encoder.text(SessionAuthorizationSchema)
	encoder.text(a.SchemaVersion)
	encoder.fixed(a.AuthorizationID[:])
	encoder.fixed(a.ContextDigest[:])
	encoder.fixed(a.CeremonyID[:])
	encoder.fixed(a.SessionBindingDigest[:])
	encoder.fixed(a.SessionIdentity[:])
	encoder.fixed(a.SessionCommitment[:])
	encoder.fixed(a.RosterDigest[:])
	for _, identity := range a.OrderedRoster {
		if zero32(identity) {
			return nil, ErrAuthorization
		}
		encoder.fixed(identity[:])
	}
	encoder.fixed(a.PrivacyDomain[:])
	encoder.fixed(a.ServiceID[:])
	encoder.u32(a.ServiceVersion)
	encoder.u64(a.ChainID)
	encoder.fixed(a.PolicyID[:])
	encoder.u32(a.PolicyVersion)
	encoder.u32(a.CircuitVersion)
	encoder.fixed(a.CircuitDigest[:])
	encoder.u32(a.ReleaseLayout)
	encoder.u32(a.MaximumReleaseQueries)
	encoder.i64(a.ContextActivatesAtUnix)
	encoder.i64(a.ContextExpiresAtUnix)
	encoder.fixed(a.RequestSigningPublicKey[:])
	encoder.i64(a.NotBeforeUnix)
	encoder.i64(a.ExpiresAtUnix)
	return encoder.bytes(), nil
}

func (a SessionAuthorization) MarshalBinary() ([]byte, error) {
	unsigned, err := a.signingBytes()
	if err != nil || bytes.Equal(a.Signature[:], make([]byte, ed25519.SignatureSize)) {
		return nil, ErrAuthorization
	}
	var encoder canonicalEncoder
	encoder.field(unsigned)
	encoder.fixed(a.Signature[:])
	return encoder.bytes(), nil
}

func ParseSessionAuthorization(data []byte) (SessionAuthorization, error) {
	var authorization SessionAuthorization
	decoder := newCanonicalDecoder(data)
	unsigned, err := decoder.field(maxConfigBytes)
	if err != nil {
		return authorization, ErrAuthorization
	}
	signature, err := decoder.fixed(ed25519.SignatureSize)
	if err != nil || decoder.done() != nil {
		return authorization, ErrAuthorization
	}
	unsignedDecoder := newCanonicalDecoder(unsigned)
	if magic, parseErr := unsignedDecoder.text(256); parseErr != nil || magic != SessionAuthorizationSchema {
		return authorization, ErrAuthorization
	}
	if authorization.SchemaVersion, err = unsignedDecoder.text(256); err != nil {
		return authorization, ErrAuthorization
	}
	for _, target := range []*[32]byte{&authorization.AuthorizationID, &authorization.ContextDigest, &authorization.CeremonyID,
		&authorization.SessionBindingDigest, &authorization.SessionIdentity, &authorization.SessionCommitment, &authorization.RosterDigest} {
		if err := unsignedDecoder.copy32(target); err != nil {
			return SessionAuthorization{}, ErrAuthorization
		}
	}
	for index := range authorization.OrderedRoster {
		if err := unsignedDecoder.copy32(&authorization.OrderedRoster[index]); err != nil {
			return SessionAuthorization{}, ErrAuthorization
		}
	}
	for _, target := range []*[32]byte{&authorization.PrivacyDomain, &authorization.ServiceID} {
		if err := unsignedDecoder.copy32(target); err != nil {
			return SessionAuthorization{}, ErrAuthorization
		}
	}
	if authorization.ServiceVersion, err = unsignedDecoder.u32(); err != nil || authorization.ServiceVersion == 0 {
		return SessionAuthorization{}, ErrAuthorization
	}
	if authorization.ChainID, err = unsignedDecoder.u64(); err != nil || authorization.ChainID == 0 {
		return SessionAuthorization{}, ErrAuthorization
	}
	if err := unsignedDecoder.copy32(&authorization.PolicyID); err != nil {
		return SessionAuthorization{}, ErrAuthorization
	}
	if authorization.PolicyVersion, err = unsignedDecoder.u32(); err != nil || authorization.PolicyVersion == 0 {
		return SessionAuthorization{}, ErrAuthorization
	}
	if authorization.CircuitVersion, err = unsignedDecoder.u32(); err != nil || authorization.CircuitVersion == 0 {
		return SessionAuthorization{}, ErrAuthorization
	}
	if err := unsignedDecoder.copy32(&authorization.CircuitDigest); err != nil {
		return SessionAuthorization{}, ErrAuthorization
	}
	if authorization.ReleaseLayout, err = unsignedDecoder.u32(); err != nil || authorization.ReleaseLayout == 0 {
		return SessionAuthorization{}, ErrAuthorization
	}
	if authorization.MaximumReleaseQueries, err = unsignedDecoder.u32(); err != nil || authorization.MaximumReleaseQueries == 0 {
		return SessionAuthorization{}, ErrAuthorization
	}
	if authorization.ContextActivatesAtUnix, err = unsignedDecoder.i64(); err != nil {
		return SessionAuthorization{}, ErrAuthorization
	}
	if authorization.ContextExpiresAtUnix, err = unsignedDecoder.i64(); err != nil {
		return SessionAuthorization{}, ErrAuthorization
	}
	publicKey, err := unsignedDecoder.fixed(ed25519.PublicKeySize)
	if err != nil {
		return SessionAuthorization{}, ErrAuthorization
	}
	copy(authorization.RequestSigningPublicKey[:], publicKey)
	if authorization.NotBeforeUnix, err = unsignedDecoder.i64(); err != nil {
		return SessionAuthorization{}, ErrAuthorization
	}
	if authorization.ExpiresAtUnix, err = unsignedDecoder.i64(); err != nil || unsignedDecoder.done() != nil {
		return SessionAuthorization{}, ErrAuthorization
	}
	copy(authorization.Signature[:], signature)
	canonical, err := authorization.MarshalBinary()
	if err != nil || !bytes.Equal(canonical, data) {
		return SessionAuthorization{}, ErrAuthorization
	}
	return authorization, nil
}

func VerifySessionAuthorization(authority ed25519.PublicKey, contextValue ceremony.Context, authorization SessionAuthorization, now time.Time) error {
	if len(authority) != ed25519.PublicKeySize || contextValue.Validate() != nil || now.Unix() < authorization.NotBeforeUnix ||
		now.Unix() > authorization.ExpiresAtUnix || authorization.ExpiresAtUnix > contextValue.ExpiresAtUnix {
		return ErrAuthorization
	}
	expected := authorizationForContext(contextValue, authorization.AuthorizationID, ed25519.PublicKey(authorization.RequestSigningPublicKey[:]), time.Unix(authorization.NotBeforeUnix+30, 0))
	expected.NotBeforeUnix = authorization.NotBeforeUnix
	expected.ExpiresAtUnix = authorization.ExpiresAtUnix
	expected.Signature = authorization.Signature
	if expected != authorization {
		return ErrAuthorization
	}
	unsigned, err := authorization.signingBytes()
	if err != nil || !ed25519.Verify(authority, authorizationSigningMessage(unsigned), authorization.Signature[:]) {
		return ErrAuthorization
	}
	return nil
}

func NewAuthorizedRequest(session AuthorizedSession, operation string, payload []byte, requestID [32]byte, sequence uint64, now time.Time) (AuthorizedRequest, error) {
	if session.Validate(now) != nil || !protectedOperation(operation) || len(payload) == 0 || zero32(requestID) || sequence == 0 {
		return AuthorizedRequest{}, ErrAuthorization
	}
	expires := now.Add(2 * time.Minute).Unix()
	if expires > session.Authorization.ExpiresAtUnix {
		expires = session.Authorization.ExpiresAtUnix
	}
	request := AuthorizedRequest{
		SchemaVersion: AuthorizedRequestSchema, AuthorizationID: session.Authorization.AuthorizationID,
		CeremonyID: session.Context.CeremonyID(), ContextDigest: session.Context.ContextDigest(), Operation: operation,
		PayloadDigest: canonicalPayloadDigest(payload), RequestID: requestID, Sequence: sequence, ExpiresAtUnix: expires,
	}
	unsigned, err := request.signingBytes()
	if err != nil {
		return AuthorizedRequest{}, err
	}
	copy(request.Signature[:], ed25519.Sign(session.RequestSigningKey, authorizedRequestSigningMessage(unsigned)))
	return request, nil
}

func (a AuthorizedRequest) signingBytes() ([]byte, error) {
	if a.SchemaVersion != AuthorizedRequestSchema || zero32(a.AuthorizationID) || zero32(a.CeremonyID) || zero32(a.ContextDigest) ||
		!protectedOperation(a.Operation) || zero32(a.PayloadDigest) || zero32(a.RequestID) || a.Sequence == 0 || a.ExpiresAtUnix <= 0 {
		return nil, ErrAuthorization
	}
	var encoder canonicalEncoder
	encoder.text(AuthorizedRequestSchema)
	encoder.text(a.SchemaVersion)
	encoder.fixed(a.AuthorizationID[:])
	encoder.fixed(a.CeremonyID[:])
	encoder.fixed(a.ContextDigest[:])
	encoder.text(a.Operation)
	encoder.fixed(a.PayloadDigest[:])
	encoder.fixed(a.RequestID[:])
	encoder.u64(a.Sequence)
	encoder.i64(a.ExpiresAtUnix)
	return encoder.bytes(), nil
}

func (a AuthorizedRequest) MarshalBinary() ([]byte, error) {
	unsigned, err := a.signingBytes()
	if err != nil || bytes.Equal(a.Signature[:], make([]byte, ed25519.SignatureSize)) {
		return nil, ErrAuthorization
	}
	var encoder canonicalEncoder
	encoder.field(unsigned)
	encoder.fixed(a.Signature[:])
	return encoder.bytes(), nil
}

func ParseAuthorizedRequest(data []byte) (AuthorizedRequest, error) {
	var request AuthorizedRequest
	decoder := newCanonicalDecoder(data)
	unsigned, err := decoder.field(maxConfigBytes)
	if err != nil {
		return request, ErrAuthorization
	}
	signature, err := decoder.fixed(ed25519.SignatureSize)
	if err != nil || decoder.done() != nil {
		return request, ErrAuthorization
	}
	unsignedDecoder := newCanonicalDecoder(unsigned)
	if magic, parseErr := unsignedDecoder.text(256); parseErr != nil || magic != AuthorizedRequestSchema {
		return request, ErrAuthorization
	}
	if request.SchemaVersion, err = unsignedDecoder.text(256); err != nil {
		return request, ErrAuthorization
	}
	for _, target := range []*[32]byte{&request.AuthorizationID, &request.CeremonyID, &request.ContextDigest} {
		if err := unsignedDecoder.copy32(target); err != nil {
			return AuthorizedRequest{}, ErrAuthorization
		}
	}
	if request.Operation, err = unsignedDecoder.text(256); err != nil {
		return AuthorizedRequest{}, ErrAuthorization
	}
	for _, target := range []*[32]byte{&request.PayloadDigest, &request.RequestID} {
		if err := unsignedDecoder.copy32(target); err != nil {
			return AuthorizedRequest{}, ErrAuthorization
		}
	}
	if request.Sequence, err = unsignedDecoder.u64(); err != nil {
		return AuthorizedRequest{}, ErrAuthorization
	}
	if request.ExpiresAtUnix, err = unsignedDecoder.i64(); err != nil || unsignedDecoder.done() != nil {
		return AuthorizedRequest{}, ErrAuthorization
	}
	copy(request.Signature[:], signature)
	canonical, err := request.MarshalBinary()
	if err != nil || !bytes.Equal(canonical, data) {
		return AuthorizedRequest{}, ErrAuthorization
	}
	return request, nil
}

func VerifyAuthorizedRequest(authorization SessionAuthorization, request AuthorizedRequest, operation string, payload []byte, now time.Time) error {
	if request.AuthorizationID != authorization.AuthorizationID || request.CeremonyID != authorization.CeremonyID ||
		request.ContextDigest != authorization.ContextDigest || request.Operation != operation || request.PayloadDigest != canonicalPayloadDigest(payload) ||
		now.Unix() > request.ExpiresAtUnix || request.ExpiresAtUnix > authorization.ExpiresAtUnix {
		return ErrAuthorization
	}
	unsigned, err := request.signingBytes()
	if err != nil || !ed25519.Verify(authorization.RequestSigningPublicKey[:], authorizedRequestSigningMessage(unsigned), request.Signature[:]) {
		return ErrAuthorization
	}
	return nil
}

func authorizationSigningMessage(unsigned []byte) []byte {
	digest := sha256.Sum256(append([]byte("MordantOneShotSessionAuthorizationSignature/v1\x00"), unsigned...))
	return digest[:]
}

func authorizedRequestSigningMessage(unsigned []byte) []byte {
	digest := sha256.Sum256(append([]byte("MordantOneShotAuthorizedRequestSignature/v1\x00"), unsigned...))
	return digest[:]
}

func canonicalPayloadDigest(payload []byte) [32]byte {
	return sha256.Sum256(append([]byte("MordantOneShotCanonicalRequestPayload/v1\x00"), payload...))
}

func operatorIdentityDigest(identity ceremony.OperatorIdentity) [32]byte {
	var encoder canonicalEncoder
	encoder.u64(identity.Point)
	encoder.text(identity.AdministratorID)
	encoder.fixed(identity.SigningPublicKey[:])
	encoder.fixed(identity.EncryptionPublicKey[:])
	encoder.fixed(identity.TransportCertFingerprint[:])
	encoder.fixed(identity.StorageBindingDigest[:])
	encoder.fixed(identity.RuntimeBinaryDigest[:])
	encoder.text(identity.GoVersion)
	encoder.text(identity.OperatingSystem)
	encoder.text(identity.Architecture)
	return sha256.Sum256(encoder.bytes())
}

func decodePublicKey(value string) (ed25519.PublicKey, error) {
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != ed25519.PublicKeySize || bytes.Equal(decoded, make([]byte, ed25519.PublicKeySize)) {
		return nil, ErrConfig
	}
	return ed25519.PublicKey(decoded), nil
}

func contextMatchesRunner(config RunnerConfig, contextValue ceremony.Context) bool {
	if config.validate() != nil || contextValue.Validate() != nil || len(contextValue.Operators) != len(config.Operators) {
		return false
	}
	for index := range config.Operators {
		identity, err := config.Operators[index].Identity.operatorIdentity()
		if err != nil || identity != contextValue.Operators[index] {
			return false
		}
	}
	return true
}

func zero32(value [32]byte) bool { return value == ([32]byte{}) }

type canonicalEncoder struct{ buffer bytes.Buffer }

func (e *canonicalEncoder) fixed(value []byte) { _, _ = e.buffer.Write(value) }
func (e *canonicalEncoder) u32(value uint32)   { _ = binary.Write(&e.buffer, binary.BigEndian, value) }
func (e *canonicalEncoder) u64(value uint64)   { _ = binary.Write(&e.buffer, binary.BigEndian, value) }
func (e *canonicalEncoder) i64(value int64)    { _ = binary.Write(&e.buffer, binary.BigEndian, value) }
func (e *canonicalEncoder) text(value string)  { e.field([]byte(value)) }
func (e *canonicalEncoder) field(value []byte) {
	e.u64(uint64(len(value)))
	e.fixed(value)
}
func (e *canonicalEncoder) bytes() []byte { return slices.Clone(e.buffer.Bytes()) }

type canonicalDecoder struct {
	data   []byte
	offset int
}

func newCanonicalDecoder(data []byte) *canonicalDecoder { return &canonicalDecoder{data: data} }
func (d *canonicalDecoder) fixed(length int) ([]byte, error) {
	if length < 0 || d.offset > len(d.data)-length {
		return nil, io.ErrUnexpectedEOF
	}
	value := d.data[d.offset : d.offset+length]
	d.offset += length
	return value, nil
}
func (d *canonicalDecoder) u32() (uint32, error) {
	value, err := d.fixed(4)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(value), nil
}
func (d *canonicalDecoder) u64() (uint64, error) {
	value, err := d.fixed(8)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(value), nil
}
func (d *canonicalDecoder) i64() (int64, error) {
	value, err := d.u64()
	return int64(value), err
}
func (d *canonicalDecoder) field(maximum int64) ([]byte, error) {
	length, err := d.u64()
	if err != nil || length == 0 || length > uint64(maximum) {
		return nil, io.ErrUnexpectedEOF
	}
	return d.fixed(int(length))
}
func (d *canonicalDecoder) text(maximum int64) (string, error) {
	value, err := d.field(maximum)
	return string(value), err
}
func (d *canonicalDecoder) copy32(target *[32]byte) error {
	value, err := d.fixed(32)
	if err != nil {
		return err
	}
	copy(target[:], value)
	return nil
}
func (d *canonicalDecoder) done() error {
	if d.offset != len(d.data) {
		return errors.New("trailing canonical data")
	}
	return nil
}
