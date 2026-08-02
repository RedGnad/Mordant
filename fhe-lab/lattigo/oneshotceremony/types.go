// Package oneshotceremony implements Mordant's ephemeral, terminal 2-of-3
// Lattigo key ceremony. It is transport-agnostic so each Participant can run
// on a separately administered host. It deliberately has no recovery API.
package oneshotceremony

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

const (
	ProtocolVersion       = "mordant.fhe-ceremony/oneshot-v1"
	ContextSchema         = "mordant.fhe-ceremony-context/oneshot-v1"
	EnvelopeSchema        = "mordant.fhe-ceremony-envelope/oneshot-v1"
	WitnessSchema         = "mordant.fhe-ceremony-witness/oneshot-v1"
	ManifestSchema        = "mordant.fhe-key-manifest/oneshot-v1"
	PublicBundleSchema    = "mordant.fhe-public-bundle/oneshot-v1"
	PrivateBundleSchema   = "mordant.fhe-private-bundle/oneshot-v1"
	StatusSchema          = "mordant.fhe-key-status/oneshot-v1"
	CRSSchema             = "mordant.fhe-crs/oneshot-v1"
	SignatureDomain       = "MordantOneShotEnvelopeSignature/v1"
	SignatureAlgorithm    = "Ed25519"
	SerializationVersion  = uint32(1)
	LattigoVersion        = "github.com/tuneinsight/lattigo/v6 v6.2.0"
	LattigoModuleChecksum = "h1:HZrksD5u87bOr/4hWHI1Jhps14Tafdvb84Fxmi3dou0="
	KeyScope              = "BILATERAL_SESSION"
	PartyCount            = 3
	Threshold             = 2
	MaximumSessions       = 1
	EphemeralKeyEpoch     = uint64(0)
)

var (
	ErrBinding      = errors.New("one-shot ceremony binding rejected")
	ErrState        = errors.New("one-shot ceremony state rejected")
	ErrReplay       = errors.New("one-shot ceremony replay rejected")
	ErrSignature    = errors.New("one-shot ceremony signature rejected")
	ErrMaterial     = errors.New("one-shot ceremony material rejected")
	ErrTerminal     = errors.New("one-shot ceremony is terminal")
	ErrPersistence  = errors.New("one-shot ceremony persistence rejected")
	ErrSecretAccess = errors.New("one-shot ceremony secret access rejected")
)

type Phase uint16

const (
	PhaseNotStarted Phase = iota
	PhaseReserved
	PhaseRunning
	PhaseCRSCommitted
	PhaseCRSRevealed
	PhasePrivateShares
	PhasePublicKey
	PhaseRelinOne
	PhaseRelinTwo
	PhaseGalois
	PhaseManifest
	PhasePublished
	PhaseCompleted
	PhaseAborted
)

func (p Phase) Terminal() bool { return p == PhaseCompleted || p == PhaseAborted }

type Operation uint16

const (
	OperationInvalid Operation = iota
	OperationCRSCommit
	OperationCRSReveal
	OperationPrivateShamirShare
	OperationPrivateShareReceipt
	OperationPublicKeyShare
	OperationRelinShare
	OperationGaloisShare
	OperationManifestAttestation
	OperationPrivateReady
	OperationStatus
)

type OperatorIdentity struct {
	Point                    uint64
	AdministratorID          string
	SigningPublicKey         [ed25519.PublicKeySize]byte
	EncryptionPublicKey      [32]byte
	TransportCertFingerprint [32]byte
	RuntimeBinaryDigest      [32]byte
	GoVersion                string
	OperatingSystem          string
	Architecture             string
}

type Context struct {
	SchemaVersion         string
	ProtocolVersion       string
	Serialization         uint32
	LattigoVersion        string
	KeyScope              string
	PrivacyDomain         [32]byte
	SessionIdentity       [32]byte
	SessionCommitment     [32]byte
	Nonce                 [32]byte
	AttemptOrdinal        uint64
	ChainID               uint64
	PolicyID              [32]byte
	PolicyVersion         uint32
	CircuitVersion        uint32
	CircuitDigest         [32]byte
	ReleaseLayout         uint32
	MaximumReleaseQueries uint32
	ParameterFingerprint  [32]byte
	GaloisElements        []uint64
	ActivatesAtUnix       int64
	ExpiresAtUnix         int64
	SourceCommit          string
	LattigoModuleChecksum string
	Operators             []OperatorIdentity
}

func NewContext(params bgv.Parameters, input Context) (Context, error) {
	parameterBytes, err := params.MarshalBinary()
	if err != nil {
		return Context{}, fmt.Errorf("%w: parameters", ErrMaterial)
	}
	input.ParameterFingerprint = sha256.Sum256(parameterBytes)
	if input.SchemaVersion == "" {
		input.SchemaVersion = ContextSchema
	}
	if input.ProtocolVersion == "" {
		input.ProtocolVersion = ProtocolVersion
	}
	if input.Serialization == 0 {
		input.Serialization = SerializationVersion
	}
	if input.LattigoVersion == "" {
		input.LattigoVersion = LattigoVersion
	}
	if input.LattigoModuleChecksum == "" {
		input.LattigoModuleChecksum = LattigoModuleChecksum
	}
	if input.KeyScope == "" {
		input.KeyScope = KeyScope
	}
	if err := input.Validate(); err != nil {
		return Context{}, err
	}
	input.Operators = slices.Clone(input.Operators)
	input.GaloisElements = slices.Clone(input.GaloisElements)
	return input, nil
}

func (c Context) Validate() error {
	if c.SchemaVersion != ContextSchema || c.ProtocolVersion != ProtocolVersion ||
		c.Serialization != SerializationVersion || c.LattigoVersion != LattigoVersion || c.LattigoModuleChecksum != LattigoModuleChecksum ||
		c.KeyScope != KeyScope {
		return fmt.Errorf("%w: schema or version", ErrBinding)
	}
	if isZero32(c.PrivacyDomain) || isZero32(c.SessionIdentity) ||
		isZero32(c.SessionCommitment) || isZero32(c.Nonce) || isZero32(c.PolicyID) ||
		isZero32(c.CircuitDigest) || isZero32(c.ParameterFingerprint) || c.ChainID == 0 ||
		c.AttemptOrdinal == 0 || c.PolicyVersion == 0 || c.CircuitVersion == 0 || c.ReleaseLayout == 0 || c.MaximumReleaseQueries == 0 ||
		c.ActivatesAtUnix <= 0 || c.ExpiresAtUnix <= c.ActivatesAtUnix {
		return fmt.Errorf("%w: empty context field", ErrBinding)
	}
	if !validCommit(c.SourceCommit) {
		return fmt.Errorf("%w: source commit", ErrBinding)
	}
	if len(c.Operators) != PartyCount {
		return fmt.Errorf("%w: exactly three operators required", ErrBinding)
	}
	adminIDs := map[string]struct{}{}
	signing := map[[ed25519.PublicKeySize]byte]struct{}{}
	encryption := map[[32]byte]struct{}{}
	transport := map[[32]byte]struct{}{}
	var previous uint64
	for index, operator := range c.Operators {
		if operator.Point == 0 || (index > 0 && operator.Point <= previous) ||
			operator.AdministratorID == "" || isZero32(operator.EncryptionPublicKey) ||
			isZero32(operator.TransportCertFingerprint) || isZero32(operator.RuntimeBinaryDigest) ||
			operator.SigningPublicKey == ([ed25519.PublicKeySize]byte{}) {
			return fmt.Errorf("%w: operator %d", ErrBinding, index)
		}
		if operator.GoVersion == "" || operator.OperatingSystem == "" || operator.Architecture == "" {
			return fmt.Errorf("%w: operator runtime platform %d", ErrBinding, index)
		}
		if _, ok := adminIDs[operator.AdministratorID]; ok {
			return fmt.Errorf("%w: administrators must be distinct", ErrBinding)
		}
		if _, ok := signing[operator.SigningPublicKey]; ok {
			return fmt.Errorf("%w: duplicate signing key", ErrBinding)
		}
		if _, ok := encryption[operator.EncryptionPublicKey]; ok {
			return fmt.Errorf("%w: duplicate encryption key", ErrBinding)
		}
		if _, ok := transport[operator.TransportCertFingerprint]; ok {
			return fmt.Errorf("%w: duplicate transport identity", ErrBinding)
		}
		adminIDs[operator.AdministratorID] = struct{}{}
		signing[operator.SigningPublicKey] = struct{}{}
		encryption[operator.EncryptionPublicKey] = struct{}{}
		transport[operator.TransportCertFingerprint] = struct{}{}
		previous = operator.Point
	}
	if len(c.GaloisElements) == 0 || len(c.GaloisElements) > 64 {
		return fmt.Errorf("%w: galois elements", ErrBinding)
	}
	for i, element := range c.GaloisElements {
		if element == 0 || (i > 0 && element <= c.GaloisElements[i-1]) {
			return fmt.Errorf("%w: non-canonical galois order", ErrBinding)
		}
	}
	return nil
}

func (c Context) Operator(point uint64) (OperatorIdentity, bool) {
	for _, operator := range c.Operators {
		if operator.Point == point {
			return operator, true
		}
	}
	return OperatorIdentity{}, false
}

func (c Context) MarshalBinary() ([]byte, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	var e encoder
	e.text(ContextSchema)
	e.text(c.SchemaVersion)
	e.text(c.ProtocolVersion)
	e.u32(c.Serialization)
	e.text(c.LattigoVersion)
	e.text(c.KeyScope)
	e.u64(EphemeralKeyEpoch)
	e.u32(MaximumSessions)
	e.fixed(c.PrivacyDomain[:])
	e.fixed(c.SessionIdentity[:])
	e.fixed(c.SessionCommitment[:])
	e.fixed(c.Nonce[:])
	e.u64(c.AttemptOrdinal)
	e.u64(c.ChainID)
	e.fixed(c.PolicyID[:])
	e.u32(c.PolicyVersion)
	e.u32(c.CircuitVersion)
	e.fixed(c.CircuitDigest[:])
	e.u32(c.ReleaseLayout)
	e.u32(c.MaximumReleaseQueries)
	e.fixed(c.ParameterFingerprint[:])
	e.u32(uint32(len(c.GaloisElements)))
	for _, element := range c.GaloisElements {
		e.u64(element)
	}
	e.i64(c.ActivatesAtUnix)
	e.i64(c.ExpiresAtUnix)
	e.text(c.SourceCommit)
	e.text(c.LattigoModuleChecksum)
	e.u32(uint32(len(c.Operators)))
	for _, operator := range c.Operators {
		e.u64(operator.Point)
		e.text(operator.AdministratorID)
		e.fixed(operator.SigningPublicKey[:])
		e.fixed(operator.EncryptionPublicKey[:])
		e.fixed(operator.TransportCertFingerprint[:])
		e.fixed(operator.RuntimeBinaryDigest[:])
		e.text(operator.GoVersion)
		e.text(operator.OperatingSystem)
		e.text(operator.Architecture)
	}
	return e.Bytes(), nil
}

func ParseContext(data []byte) (Context, error) {
	var c Context
	d := newDecoder(data)
	magic, err := d.text()
	if err != nil || magic != ContextSchema {
		return c, errCanonical
	}
	if c.SchemaVersion, err = d.text(); err != nil {
		return c, err
	}
	if c.ProtocolVersion, err = d.text(); err != nil {
		return c, err
	}
	if c.Serialization, err = d.u32(); err != nil {
		return c, err
	}
	if c.LattigoVersion, err = d.text(); err != nil {
		return c, err
	}
	if c.KeyScope, err = d.text(); err != nil {
		return c, err
	}
	epoch, err := d.u64()
	if err != nil || epoch != EphemeralKeyEpoch {
		return c, errCanonical
	}
	maximum, err := d.u32()
	if err != nil || maximum != MaximumSessions {
		return c, errCanonical
	}
	for _, target := range []*[32]byte{&c.PrivacyDomain, &c.SessionIdentity, &c.SessionCommitment, &c.Nonce} {
		value, readErr := d.fixed(32)
		if readErr != nil || copy32(target, value) != nil {
			return c, errCanonical
		}
	}
	if c.AttemptOrdinal, err = d.u64(); err != nil {
		return c, err
	}
	if c.ChainID, err = d.u64(); err != nil {
		return c, err
	}
	value, err := d.fixed(32)
	if err != nil || copy32(&c.PolicyID, value) != nil {
		return c, errCanonical
	}
	if c.PolicyVersion, err = d.u32(); err != nil {
		return c, err
	}
	if c.CircuitVersion, err = d.u32(); err != nil {
		return c, err
	}
	value, err = d.fixed(32)
	if err != nil || copy32(&c.CircuitDigest, value) != nil {
		return c, errCanonical
	}
	if c.ReleaseLayout, err = d.u32(); err != nil {
		return c, err
	}
	if c.MaximumReleaseQueries, err = d.u32(); err != nil {
		return c, err
	}
	value, err = d.fixed(32)
	if err != nil || copy32(&c.ParameterFingerprint, value) != nil {
		return c, errCanonical
	}
	galoisCount, err := d.u32()
	if err != nil || galoisCount == 0 || galoisCount > 64 {
		return c, errCanonical
	}
	c.GaloisElements = make([]uint64, galoisCount)
	for i := range c.GaloisElements {
		if c.GaloisElements[i], err = d.u64(); err != nil {
			return c, err
		}
	}
	if c.ActivatesAtUnix, err = d.i64(); err != nil {
		return c, err
	}
	if c.ExpiresAtUnix, err = d.i64(); err != nil {
		return c, err
	}
	if c.SourceCommit, err = d.text(); err != nil {
		return c, err
	}
	if c.LattigoModuleChecksum, err = d.text(); err != nil {
		return c, err
	}
	operatorCount, err := d.u32()
	if err != nil || operatorCount != PartyCount {
		return c, errCanonical
	}
	c.Operators = make([]OperatorIdentity, operatorCount)
	for i := range c.Operators {
		op := &c.Operators[i]
		if op.Point, err = d.u64(); err != nil {
			return c, err
		}
		if op.AdministratorID, err = d.text(); err != nil {
			return c, err
		}
		for _, target := range [][]byte{op.SigningPublicKey[:], op.EncryptionPublicKey[:], op.TransportCertFingerprint[:], op.RuntimeBinaryDigest[:]} {
			v, readErr := d.fixed(len(target))
			if readErr != nil {
				return c, readErr
			}
			copy(target, v)
		}
		if op.GoVersion, err = d.text(); err != nil {
			return c, err
		}
		if op.OperatingSystem, err = d.text(); err != nil {
			return c, err
		}
		if op.Architecture, err = d.text(); err != nil {
			return c, err
		}
	}
	if err := d.done(); err != nil {
		return c, err
	}
	if err := c.Validate(); err != nil {
		return c, err
	}
	reencoded, err := c.MarshalBinary()
	if err != nil || !slices.Equal(reencoded, data) {
		return Context{}, errCanonical
	}
	return c, nil
}

func (c Context) ContextDigest() [32]byte {
	encoded, err := c.MarshalBinary()
	if err != nil {
		return [32]byte{}
	}
	return hashDomain("MordantOneShotContext/v1", encoded)
}

func (c Context) CeremonyID() [32]byte {
	digest := c.ContextDigest()
	return hashDomain("MordantOneShotCeremonyId/v1", digest[:])
}

func (c Context) RosterDigest() [32]byte {
	var e encoder
	e.text("MordantOneShotRoster/v1")
	ceremonyID := c.CeremonyID()
	e.fixed(ceremonyID[:])
	e.fixed(c.ParameterFingerprint[:])
	e.u16(Threshold)
	e.u16(PartyCount)
	e.u32(uint32(len(c.Operators)))
	for _, operator := range c.Operators {
		e.u64(operator.Point)
		e.text(operator.AdministratorID)
		e.fixed(operator.SigningPublicKey[:])
		e.fixed(operator.EncryptionPublicKey[:])
		e.fixed(operator.TransportCertFingerprint[:])
		e.fixed(operator.RuntimeBinaryDigest[:])
		e.text(operator.GoVersion)
		e.text(operator.OperatingSystem)
		e.text(operator.Architecture)
	}
	return sha256.Sum256(e.Bytes())
}

func (c Context) ScopeOrdinalDigest() [32]byte {
	var e encoder
	e.text("MordantOneShotScopeOrdinal/v1")
	e.text(c.KeyScope)
	e.fixed(c.PrivacyDomain[:])
	e.fixed(c.SessionIdentity[:])
	e.fixed(c.SessionCommitment[:])
	e.u64(c.AttemptOrdinal)
	e.u64(EphemeralKeyEpoch)
	return sha256.Sum256(e.Bytes())
}

func ParameterFingerprint(params bgv.Parameters) ([32]byte, error) {
	encoded, err := params.MarshalBinary()
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(encoded), nil
}

func hashDomain(domain string, chunks ...[]byte) [32]byte {
	var e encoder
	e.text(domain)
	for _, chunk := range chunks {
		e.field(chunk)
	}
	return sha256.Sum256(e.Bytes())
}

func validCommit(commit string) bool {
	if len(commit) != 40 || commit != strings.ToLower(commit) {
		return false
	}
	decoded, err := hex.DecodeString(commit)
	return err == nil && len(decoded) == 20
}
