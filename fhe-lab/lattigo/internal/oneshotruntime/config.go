package oneshotruntime

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
	ceremony "mordant.dev/fhe-lab/lattigo/oneshotceremony"
)

const (
	OperatorBootstrapSchema = "mordant.oneshot-operator-bootstrap/1"
	OperatorConfigSchema    = "mordant.oneshot-operator-config/1"
	PublicIdentitySchema    = "mordant.oneshot-public-operator-identity/1"
	RosterSchema            = "mordant.oneshot-operator-roster/1"
	RunnerConfigSchema      = "mordant.oneshot-runner-config/1"
	RuntimeWireSchema       = "mordant.oneshot-runtime-wire/1"
	EvidenceSchema          = "mordant.oneshot-network-public-evidence/1"
	ParameterProfile        = "mordant.oneshot-mvp-functional-parameters/1"

	maxConfigBytes = 4 << 20
)

var (
	ErrConfig    = errors.New("one-shot runtime configuration rejected")
	ErrTransport = errors.New("one-shot runtime transport rejected")
	ErrProtocol  = errors.New("one-shot runtime protocol rejected")
	ErrEvidence  = errors.New("one-shot runtime evidence rejected")
)

type PublicIdentity struct {
	SchemaVersion            string `json:"schemaVersion"`
	Point                    uint64 `json:"point"`
	AdministratorID          string `json:"administratorId"`
	SigningPublicKey         string `json:"signingPublicKey"`
	EncryptionPublicKey      string `json:"encryptionPublicKey"`
	TransportCertFingerprint string `json:"transportCertFingerprint"`
	StorageBindingDigest     string `json:"storageBindingDigest"`
	RuntimeBinaryDigest      string `json:"runtimeBinaryDigest"`
	GoVersion                string `json:"goVersion"`
	OperatingSystem          string `json:"operatingSystem"`
	Architecture             string `json:"architecture"`
	SourceRevision           string `json:"sourceRevision"`
	SourceModified           bool   `json:"sourceModified"`
	DependencyDigest         string `json:"dependencyDigest"`
}

type RosterDocument struct {
	SchemaVersion string           `json:"schemaVersion"`
	Operators     []PublicIdentity `json:"operators"`
}

type OperatorBootstrap struct {
	SchemaVersion       string         `json:"schemaVersion"`
	ListenAddress       string         `json:"listenAddress"`
	StateRoot           string         `json:"stateRoot"`
	PublicationRoot     string         `json:"publicationRoot"`
	Identity            PublicIdentity `json:"identity"`
	SigningKeyPath      string         `json:"signingKeyPath"`
	EncryptionKeyPath   string         `json:"encryptionKeyPath"`
	TLSCertificatePath  string         `json:"tlsCertificatePath"`
	TLSPrivateKeyPath   string         `json:"tlsPrivateKeyPath"`
	StorageIdentityPath string         `json:"storageIdentityPath"`
	ProcessInstancePath string         `json:"processInstancePath"`
}

type OperatorConfig struct {
	SchemaVersion       string           `json:"schemaVersion"`
	ProtocolVersion     string           `json:"protocolVersion"`
	ContextSchema       string           `json:"contextSchema"`
	ParameterProfile    string           `json:"parameterProfile"`
	ListenAddress       string           `json:"listenAddress"`
	StateRoot           string           `json:"stateRoot"`
	PublicationRoot     string           `json:"publicationRoot"`
	Identity            PublicIdentity   `json:"identity"`
	Roster              []PublicIdentity `json:"roster"`
	SigningKeyPath      string           `json:"signingKeyPath"`
	EncryptionKeyPath   string           `json:"encryptionKeyPath"`
	TLSCertificatePath  string           `json:"tlsCertificatePath"`
	TLSPrivateKeyPath   string           `json:"tlsPrivateKeyPath"`
	StorageIdentityPath string           `json:"storageIdentityPath"`
	ProcessInstancePath string           `json:"processInstancePath"`
}

type RunnerOperator struct {
	Endpoint string         `json:"endpoint"`
	Identity PublicIdentity `json:"identity"`
}

type ContextTemplate struct {
	PrivacyDomain         string `json:"privacyDomain"`
	ServiceID             string `json:"serviceId"`
	ServiceVersion        uint32 `json:"serviceVersion"`
	ChainID               uint64 `json:"chainId"`
	PolicyID              string `json:"policyId"`
	PolicyVersion         uint32 `json:"policyVersion"`
	CircuitVersion        uint32 `json:"circuitVersion"`
	CircuitDigest         string `json:"circuitDigest"`
	ReleaseLayout         uint32 `json:"releaseLayout"`
	MaximumReleaseQueries uint32 `json:"maximumReleaseQueries"`
	LifetimeSeconds       int64  `json:"lifetimeSeconds"`
}

type RunnerConfig struct {
	SchemaVersion    string           `json:"schemaVersion"`
	ProtocolVersion  string           `json:"protocolVersion"`
	ContextSchema    string           `json:"contextSchema"`
	ParameterProfile string           `json:"parameterProfile"`
	PublicationRoot  string           `json:"publicationRoot"`
	EvidenceRoot     string           `json:"evidenceRoot"`
	Operators        []RunnerOperator `json:"operators"`
	Context          ContextTemplate  `json:"context"`
}

type InitOptions struct {
	Directory       string
	Point           uint64
	AdministratorID string
	ListenAddress   string
	StateRoot       string
	PublicationRoot string
}

func RuntimeParameters() (bgv.Parameters, error) {
	// This small profile is the explicitly non-production hackathon functional
	// profile already exercised by the accepted one-shot implementation tests.
	return bgv.NewParametersFromLiteral(bgv.ParametersLiteral{
		LogN:             10,
		Q:                []uint64{0x3fffffa8001, 0x1000090001, 0x10000c8001, 0x10000f0001, 0xffff00001},
		P:                []uint64{0x7fffffd8001},
		PlaintextModulus: 0x101,
	})
}

func publicIdentity(identity ceremony.OperatorIdentity, provenance ceremony.ExecutableProvenance) PublicIdentity {
	return PublicIdentity{
		SchemaVersion:            PublicIdentitySchema,
		Point:                    identity.Point,
		AdministratorID:          identity.AdministratorID,
		SigningPublicKey:         encodeHex(identity.SigningPublicKey[:]),
		EncryptionPublicKey:      encodeHex(identity.EncryptionPublicKey[:]),
		TransportCertFingerprint: encodeHex(identity.TransportCertFingerprint[:]),
		StorageBindingDigest:     encodeHex(identity.StorageBindingDigest[:]),
		RuntimeBinaryDigest:      encodeHex(identity.RuntimeBinaryDigest[:]),
		GoVersion:                identity.GoVersion,
		OperatingSystem:          identity.OperatingSystem,
		Architecture:             identity.Architecture,
		SourceRevision:           provenance.SourceRevision,
		SourceModified:           provenance.SourceModified,
		DependencyDigest:         encodeHex(provenance.DependencyDigest[:]),
	}
}

func (p PublicIdentity) operatorIdentity() (ceremony.OperatorIdentity, error) {
	var identity ceremony.OperatorIdentity
	if p.SchemaVersion != PublicIdentitySchema || p.Point == 0 || p.AdministratorID == "" || p.GoVersion == "" ||
		p.OperatingSystem == "" || p.Architecture == "" || len(p.SourceRevision) != 40 {
		return identity, ErrConfig
	}
	identity.Point = p.Point
	identity.AdministratorID = p.AdministratorID
	if decodeFixed(p.SigningPublicKey, identity.SigningPublicKey[:]) != nil ||
		decodeFixed(p.EncryptionPublicKey, identity.EncryptionPublicKey[:]) != nil ||
		decodeFixed(p.TransportCertFingerprint, identity.TransportCertFingerprint[:]) != nil ||
		decodeFixed(p.StorageBindingDigest, identity.StorageBindingDigest[:]) != nil ||
		decodeFixed(p.RuntimeBinaryDigest, identity.RuntimeBinaryDigest[:]) != nil {
		return ceremony.OperatorIdentity{}, ErrConfig
	}
	identity.GoVersion = p.GoVersion
	identity.OperatingSystem = p.OperatingSystem
	identity.Architecture = p.Architecture
	if _, err := hex.DecodeString(p.SourceRevision); err != nil {
		return ceremony.OperatorIdentity{}, ErrConfig
	}
	dependency := make([]byte, 32)
	if decodeFixed(p.DependencyDigest, dependency) != nil {
		return ceremony.OperatorIdentity{}, ErrConfig
	}
	return identity, nil
}

func (p PublicIdentity) provenance(path string) (ceremony.ExecutableProvenance, error) {
	identity, err := p.operatorIdentity()
	if err != nil {
		return ceremony.ExecutableProvenance{}, err
	}
	var dependency [32]byte
	if decodeFixed(p.DependencyDigest, dependency[:]) != nil {
		return ceremony.ExecutableProvenance{}, ErrConfig
	}
	return ceremony.ExecutableProvenance{
		SchemaVersion:    "mordant.fhe-executable-provenance/oneshot-v2",
		ExecutablePath:   path,
		ExecutableSHA256: identity.RuntimeBinaryDigest,
		SourceRevision:   p.SourceRevision,
		SourceModified:   p.SourceModified,
		GoVersion:        p.GoVersion,
		OperatingSystem:  p.OperatingSystem,
		Architecture:     p.Architecture,
		DependencyDigest: dependency,
	}, nil
}

func InitializeOperator(options InitOptions) (OperatorBootstrap, error) {
	var bootstrap OperatorBootstrap
	if !filepath.IsAbs(options.Directory) || !filepath.IsAbs(options.StateRoot) || !filepath.IsAbs(options.PublicationRoot) ||
		options.Point < 1 || options.Point > ceremony.PartyCount || options.AdministratorID == "" || validateListenAddress(options.ListenAddress) != nil {
		return bootstrap, ErrConfig
	}
	if err := os.Mkdir(options.Directory, 0o700); err != nil {
		return bootstrap, ErrConfig
	}
	provenance, err := ceremony.CurrentExecutableProvenance()
	if err != nil {
		return bootstrap, err
	}
	publicSigning, privateSigning, err := ed25519.GenerateKey(cryptorand.Reader)
	if err != nil {
		return bootstrap, ErrConfig
	}
	encryption, err := ecdh.X25519().GenerateKey(cryptorand.Reader)
	if err != nil {
		return bootstrap, ErrConfig
	}
	tlsPublic, tlsPrivate, err := ed25519.GenerateKey(cryptorand.Reader)
	if err != nil {
		return bootstrap, ErrConfig
	}
	certDER, certPEM, keyPEM, err := selfSignedCertificate(options.ListenAddress, options.AdministratorID, tlsPublic, tlsPrivate)
	if err != nil {
		return bootstrap, err
	}
	storageIdentity, err := random32()
	if err != nil {
		return bootstrap, err
	}
	processInstance, err := random32()
	if err != nil {
		return bootstrap, err
	}
	identity := ceremony.OperatorIdentity{
		Point:                    options.Point,
		AdministratorID:          options.AdministratorID,
		TransportCertFingerprint: sha256.Sum256(certDER),
		RuntimeBinaryDigest:      provenance.ExecutableSHA256,
		GoVersion:                provenance.GoVersion,
		OperatingSystem:          provenance.OperatingSystem,
		Architecture:             provenance.Architecture,
	}
	copy(identity.SigningPublicKey[:], publicSigning)
	copy(identity.EncryptionPublicKey[:], encryption.PublicKey().Bytes())
	identity.StorageBindingDigest, err = ceremony.DeriveOperatorStorageBinding(options.StateRoot, storageIdentity, identity)
	if err != nil {
		return bootstrap, err
	}
	paths := func(name string) string { return filepath.Join(options.Directory, name) }
	bootstrap = OperatorBootstrap{
		SchemaVersion:       OperatorBootstrapSchema,
		ListenAddress:       options.ListenAddress,
		StateRoot:           filepath.Clean(options.StateRoot),
		PublicationRoot:     filepath.Clean(options.PublicationRoot),
		Identity:            publicIdentity(identity, provenance),
		SigningKeyPath:      paths("signing.key"),
		EncryptionKeyPath:   paths("x25519.key"),
		TLSCertificatePath:  paths("tls.crt"),
		TLSPrivateKeyPath:   paths("tls.key"),
		StorageIdentityPath: paths("storage.id"),
		ProcessInstancePath: paths("process.id"),
	}
	writes := []struct {
		path string
		data []byte
		mode os.FileMode
	}{
		{bootstrap.SigningKeyPath, privateSigning, 0o600},
		{bootstrap.EncryptionKeyPath, encryption.Bytes(), 0o600},
		{bootstrap.TLSCertificatePath, certPEM, 0o600},
		{bootstrap.TLSPrivateKeyPath, keyPEM, 0o600},
		{bootstrap.StorageIdentityPath, storageIdentity[:], 0o600},
		{bootstrap.ProcessInstancePath, processInstance[:], 0o600},
	}
	for _, write := range writes {
		if err := writeNoReplace(write.path, write.data, write.mode); err != nil {
			return OperatorBootstrap{}, err
		}
	}
	if err := writeJSONNoReplace(paths("public-identity.json"), bootstrap.Identity, 0o600); err != nil {
		return OperatorBootstrap{}, err
	}
	if err := writeJSONNoReplace(paths("operator.bootstrap.json"), bootstrap, 0o600); err != nil {
		return OperatorBootstrap{}, err
	}
	return bootstrap, nil
}

func ConfigureOperator(bootstrapPath, rosterPath, outputPath string) (OperatorConfig, error) {
	var bootstrap OperatorBootstrap
	var roster RosterDocument
	if err := readStrictJSON(bootstrapPath, &bootstrap, maxConfigBytes, true); err != nil ||
		readStrictJSON(rosterPath, &roster, maxConfigBytes, false) != nil || bootstrap.SchemaVersion != OperatorBootstrapSchema ||
		roster.SchemaVersion != RosterSchema || len(roster.Operators) != ceremony.PartyCount {
		return OperatorConfig{}, ErrConfig
	}
	config := OperatorConfig{
		SchemaVersion:       OperatorConfigSchema,
		ProtocolVersion:     ceremony.ProtocolVersion,
		ContextSchema:       ceremony.ContextSchema,
		ParameterProfile:    ParameterProfile,
		ListenAddress:       bootstrap.ListenAddress,
		StateRoot:           bootstrap.StateRoot,
		PublicationRoot:     bootstrap.PublicationRoot,
		Identity:            bootstrap.Identity,
		Roster:              slices.Clone(roster.Operators),
		SigningKeyPath:      bootstrap.SigningKeyPath,
		EncryptionKeyPath:   bootstrap.EncryptionKeyPath,
		TLSCertificatePath:  bootstrap.TLSCertificatePath,
		TLSPrivateKeyPath:   bootstrap.TLSPrivateKeyPath,
		StorageIdentityPath: bootstrap.StorageIdentityPath,
		ProcessInstancePath: bootstrap.ProcessInstancePath,
	}
	if err := config.validate(); err != nil {
		return OperatorConfig{}, err
	}
	if err := writeJSONNoReplace(outputPath, config, 0o400); err != nil {
		return OperatorConfig{}, err
	}
	return config, nil
}

func LoadOperatorConfig(path string) (OperatorConfig, error) {
	var config OperatorConfig
	if err := readStrictJSON(path, &config, maxConfigBytes, true); err != nil || config.validate() != nil {
		return OperatorConfig{}, ErrConfig
	}
	return config, nil
}

func LoadRunnerConfig(path string) (RunnerConfig, error) {
	var config RunnerConfig
	if err := readStrictJSON(path, &config, maxConfigBytes, false); err != nil || config.validate() != nil {
		return RunnerConfig{}, ErrConfig
	}
	return config, nil
}

func LoadPublicIdentity(path string) (PublicIdentity, error) {
	var identity PublicIdentity
	if err := readStrictJSON(path, &identity, maxConfigBytes, false); err != nil {
		return PublicIdentity{}, ErrConfig
	}
	if _, err := identity.operatorIdentity(); err != nil {
		return PublicIdentity{}, err
	}
	return identity, nil
}

func WriteRoster(path string, identities []PublicIdentity) error {
	roster := RosterDocument{SchemaVersion: RosterSchema, Operators: slices.Clone(identities)}
	if validateRoster(roster.Operators) != nil {
		return ErrConfig
	}
	return writeJSONNoReplace(path, roster, 0o600)
}

func WriteRunnerConfig(path string, config RunnerConfig) error {
	if config.validate() != nil {
		return ErrConfig
	}
	return writeJSONNoReplace(path, config, 0o600)
}

func DefaultContextTemplate() ContextTemplate {
	return ContextTemplate{
		PrivacyDomain:         digestHex("mordant-mvp-private-matching"),
		ServiceID:             digestHex("mordant-private-conflict-checking"),
		ServiceVersion:        1,
		ChainID:               31337,
		PolicyID:              digestHex("mordant-mvp-policy-v5"),
		PolicyVersion:         5,
		CircuitVersion:        5,
		CircuitDigest:         digestHex("mordant-mvp-circuit-v5"),
		ReleaseLayout:         5,
		MaximumReleaseQueries: 1,
		LifetimeSeconds:       3600,
	}
}

func (c OperatorConfig) validate() error {
	if c.SchemaVersion != OperatorConfigSchema || c.ProtocolVersion != ceremony.ProtocolVersion || c.ContextSchema != ceremony.ContextSchema ||
		c.ParameterProfile != ParameterProfile || validateListenAddress(c.ListenAddress) != nil || !filepath.IsAbs(c.StateRoot) ||
		!filepath.IsAbs(c.PublicationRoot) || validateRoster(c.Roster) != nil {
		return ErrConfig
	}
	local, err := c.Identity.operatorIdentity()
	if err != nil || local.Point < 1 || local.Point > ceremony.PartyCount {
		return ErrConfig
	}
	registered, err := c.Roster[local.Point-1].operatorIdentity()
	if err != nil || registered != local || c.Roster[local.Point-1] != c.Identity {
		return ErrConfig
	}
	for _, path := range []string{c.SigningKeyPath, c.EncryptionKeyPath, c.TLSCertificatePath, c.TLSPrivateKeyPath, c.StorageIdentityPath, c.ProcessInstancePath} {
		if !filepath.IsAbs(path) {
			return ErrConfig
		}
	}
	return nil
}

func (c RunnerConfig) validate() error {
	if c.SchemaVersion != RunnerConfigSchema || c.ProtocolVersion != ceremony.ProtocolVersion || c.ContextSchema != ceremony.ContextSchema ||
		c.ParameterProfile != ParameterProfile || !filepath.IsAbs(c.PublicationRoot) || !filepath.IsAbs(c.EvidenceRoot) ||
		len(c.Operators) != ceremony.PartyCount || validateContextTemplate(c.Context) != nil {
		return ErrConfig
	}
	identities := make([]PublicIdentity, len(c.Operators))
	for index, operator := range c.Operators {
		if validateEndpoint(operator.Endpoint) != nil {
			return ErrConfig
		}
		identities[index] = operator.Identity
	}
	return validateRoster(identities)
}

func validateContextTemplate(c ContextTemplate) error {
	for _, value := range []string{c.PrivacyDomain, c.ServiceID, c.PolicyID, c.CircuitDigest} {
		var decoded [32]byte
		if decodeFixed(value, decoded[:]) != nil {
			return ErrConfig
		}
	}
	if c.ServiceVersion == 0 || c.ChainID == 0 || c.PolicyVersion == 0 || c.CircuitVersion == 0 || c.ReleaseLayout == 0 ||
		c.MaximumReleaseQueries == 0 || c.LifetimeSeconds < 60 || c.LifetimeSeconds > 86400 {
		return ErrConfig
	}
	return nil
}

func validateRoster(roster []PublicIdentity) error {
	if len(roster) != ceremony.PartyCount {
		return ErrConfig
	}
	admins := map[string]struct{}{}
	signers := map[string]struct{}{}
	encryption := map[string]struct{}{}
	for index, public := range roster {
		identity, err := public.operatorIdentity()
		if err != nil || identity.Point != uint64(index+1) {
			return ErrConfig
		}
		if _, ok := admins[public.AdministratorID]; ok {
			// The MVP permits one human administrator, but each operator still
			// needs a distinct immutable administrator/identity label.
			return ErrConfig
		}
		admins[public.AdministratorID] = struct{}{}
		if _, ok := signers[public.SigningPublicKey]; ok {
			return ErrConfig
		}
		signers[public.SigningPublicKey] = struct{}{}
		if _, ok := encryption[public.EncryptionPublicKey]; ok {
			return ErrConfig
		}
		encryption[public.EncryptionPublicKey] = struct{}{}
	}
	return nil
}

func OperatorConfigDigest(config OperatorConfig) ([32]byte, error) {
	if config.validate() != nil {
		return [32]byte{}, ErrConfig
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		return [32]byte{}, ErrConfig
	}
	return sha256.Sum256(encoded), nil
}

func (c OperatorConfig) localMaterial() (ceremony.OperatorIdentity, ed25519.PrivateKey, *ecdh.PrivateKey, [32]byte, string, error) {
	identity, err := c.Identity.operatorIdentity()
	if err != nil {
		return identity, nil, nil, [32]byte{}, "", err
	}
	signingBytes, err := readRestricted(c.SigningKeyPath, ed25519.PrivateKeySize)
	if err != nil || len(signingBytes) != ed25519.PrivateKeySize {
		return identity, nil, nil, [32]byte{}, "", ErrConfig
	}
	signing := ed25519.PrivateKey(slices.Clone(signingBytes))
	if !slices.Equal(signing.Public().(ed25519.PublicKey), identity.SigningPublicKey[:]) {
		return identity, nil, nil, [32]byte{}, "", ErrConfig
	}
	encryptionBytes, err := readRestricted(c.EncryptionKeyPath, 32)
	if err != nil || len(encryptionBytes) != 32 {
		return identity, nil, nil, [32]byte{}, "", ErrConfig
	}
	encryption, err := ecdh.X25519().NewPrivateKey(encryptionBytes)
	if err != nil || !slices.Equal(encryption.PublicKey().Bytes(), identity.EncryptionPublicKey[:]) {
		return identity, nil, nil, [32]byte{}, "", ErrConfig
	}
	storageBytes, err := readRestricted(c.StorageIdentityPath, 32)
	if err != nil || len(storageBytes) != 32 {
		return identity, nil, nil, [32]byte{}, "", ErrConfig
	}
	var storage [32]byte
	copy(storage[:], storageBytes)
	processBytes, err := readRestricted(c.ProcessInstancePath, 32)
	if err != nil || len(processBytes) != 32 {
		return identity, nil, nil, [32]byte{}, "", ErrConfig
	}
	return identity, signing, encryption, storage, encodeHex(processBytes), nil
}

func (c OperatorConfig) TLSCertificate() (tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(c.TLSCertificatePath, c.TLSPrivateKeyPath)
	if err != nil || len(cert.Certificate) == 0 || sha256.Sum256(cert.Certificate[0]) != mustDecode32(c.Identity.TransportCertFingerprint) {
		return tls.Certificate{}, ErrConfig
	}
	return cert, nil
}

func readStrictJSON(path string, target any, maximum int64, restricted bool) error {
	var data []byte
	var err error
	if restricted {
		data, err = readRestricted(path, maximum)
	} else {
		data, err = readRegular(path, maximum)
	}
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return ErrConfig
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return ErrConfig
	}
	return nil
}

func readRestricted(path string, maximum int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 || info.Size() <= 0 || info.Size() > maximum {
		return nil, ErrConfig
	}
	data, err := os.ReadFile(path)
	if err != nil || int64(len(data)) != info.Size() {
		return nil, ErrConfig
	}
	return data, nil
}

func readRegular(path string, maximum int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > maximum {
		return nil, ErrConfig
	}
	data, err := os.ReadFile(path)
	if err != nil || int64(len(data)) != info.Size() {
		return nil, ErrConfig
	}
	return data, nil
}

func writeJSONNoReplace(path string, value any, mode os.FileMode) error {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return ErrConfig
	}
	encoded = append(encoded, '\n')
	return writeNoReplace(path, encoded, mode)
}

func writeNoReplace(path string, data []byte, mode os.FileMode) error {
	if !filepath.IsAbs(path) || len(data) == 0 {
		return ErrConfig
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return ErrConfig
	}
	ok := false
	defer func() {
		_ = file.Close()
		if !ok {
			_ = os.Remove(path)
		}
	}()
	if _, err := file.Write(data); err != nil || file.Sync() != nil || file.Close() != nil {
		return ErrConfig
	}
	ok = true
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return ErrConfig
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return ErrConfig
	}
	return nil
}

func selfSignedCertificate(listen, administrator string, public ed25519.PublicKey, private ed25519.PrivateKey) ([]byte, []byte, []byte, error) {
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return nil, nil, nil, ErrConfig
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := cryptorand.Int(cryptorand.Reader, serialLimit)
	if err != nil {
		return nil, nil, nil, ErrConfig
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "mordant-oneshot-" + administrator},
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     now.Add(30 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(cryptorand.Reader, template, template, public, private)
	if err != nil {
		return nil, nil, nil, ErrConfig
	}
	key, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		return nil, nil, nil, ErrConfig
	}
	return der, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), nil
}

func validateListenAddress(address string) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil || net.ParseIP(host) == nil || port == "" {
		return ErrConfig
	}
	return nil
}

func validateEndpoint(endpoint string) error {
	if !strings.HasPrefix(endpoint, "https://") {
		return ErrConfig
	}
	remaining := strings.TrimPrefix(endpoint, "https://")
	if strings.ContainsAny(remaining, "/?#@") || validateListenAddress(remaining) != nil {
		return ErrConfig
	}
	return nil
}

func random32() ([32]byte, error) {
	var value [32]byte
	_, err := io.ReadFull(cryptorand.Reader, value[:])
	if err != nil {
		return [32]byte{}, ErrConfig
	}
	return value, nil
}

func decodeFixed(value string, target []byte) error {
	if len(value) != len(target)*2 {
		return ErrConfig
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != len(target) {
		return ErrConfig
	}
	copy(target, decoded)
	return nil
}

func mustDecode32(value string) [32]byte {
	var out [32]byte
	_ = decodeFixed(value, out[:])
	return out
}

func encodeHex(value []byte) string { return hex.EncodeToString(value) }

func digestHex(label string) string {
	digest := sha256.Sum256([]byte(label))
	return encodeHex(digest[:])
}

func sameIdentity(a, b PublicIdentity) bool { return a == b }

func sourceRevision(roster []PublicIdentity) (string, error) {
	if validateRoster(roster) != nil {
		return "", ErrConfig
	}
	revision := roster[0].SourceRevision
	for _, identity := range roster[1:] {
		if identity.SourceRevision != revision {
			return "", ErrConfig
		}
	}
	return revision, nil
}

func identitiesFromRunner(config RunnerConfig) []PublicIdentity {
	result := make([]PublicIdentity, len(config.Operators))
	for index := range config.Operators {
		result[index] = config.Operators[index].Identity
	}
	return result
}

func identitiesEqualContext(roster []PublicIdentity, context ceremony.Context) bool {
	if len(roster) != len(context.Operators) {
		return false
	}
	for index := range roster {
		identity, err := roster[index].operatorIdentity()
		if err != nil || identity != context.Operators[index] {
			return false
		}
	}
	return true
}

func rejectPrivateFieldName(name string) bool {
	lower := strings.ToLower(name)
	for _, forbidden := range []string{"privatekey", "private_key", "signingkey", "signing_key", "sealingkey", "sealing_key", "thresholdshare", "threshold_share", "x25519private", "transportprivate", "memorydump", "memory_dump"} {
		if strings.Contains(lower, forbidden) {
			return true
		}
	}
	return false
}
