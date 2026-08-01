// Command ceremony-operator runs exactly one dealerless threshold operator.
//
// It has two modes. `identity` generates the operator's own long-lived signing
// key inside its own storage directory and publishes only the public half, so
// the lab CA can issue it a certificate without ever holding its private key.
// `serve` runs the ceremony and, once sealed, the release protocol.
//
// The operator samples its own RLWE secret and its own Shamir polynomial in
// this process. No secret material is ever supplied to it, and none is ever
// emitted: the only secret that leaves is the Shamir re-sharing addressed to a
// named peer over a mutually authenticated private channel.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
	fhe "mordant.dev/fhe-lab/lattigo"
	"mordant.dev/fhe-lab/lattigo/internal/thresholdnet"
)

const (
	maxCertificateBytes = 1 << 20
	identityKeyFile     = "identity.key"
	identityPublicFile  = "identity.pub"
	operatorBundleFile  = "operator.bin"
	ledgerFile          = "ledger.db"
)

type options struct {
	mode           string
	storage        string
	listen         string
	certificate    string
	privateKeyPath string
	peerCA         string
	coordinatorKey string
	evaluatorKey   string
	roster         string
	point          uint64
}

// rosterFile is the public roster the orchestrator distributes. It carries no
// secret material.
type rosterFile struct {
	ParameterFingerprint string   `json:"parameterFingerprint"`
	Threshold            uint16   `json:"threshold"`
	CeremonyID           string   `json:"ceremonyId"`
	KeyEpoch             uint64   `json:"keyEpoch"`
	Points               []uint64 `json:"points"`
	SigningPublicKeys    []string `json:"signingPublicKeys"`
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "CEREMONY_OPERATOR_FAILED")
		os.Exit(1)
	}
}

func run(arguments []string) error {
	settings, err := parseOptions(arguments)
	if err != nil {
		return err
	}
	switch settings.mode {
	case "identity":
		return generateIdentity(settings.storage)
	case "serve":
		return serve(settings)
	default:
		return errors.New("invalid mode")
	}
}

// generateIdentity creates the operator's signing key locally. The private half
// never leaves this directory; only the 32-byte public key is published.
func generateIdentity(storage string) error {
	if err := os.MkdirAll(storage, 0o700); err != nil {
		return err
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	if err := writeExclusive(filepath.Join(storage, identityKeyFile), private, 0o600); err != nil {
		return err
	}
	if err := writeExclusive(filepath.Join(storage, identityPublicFile), public, 0o644); err != nil {
		return err
	}
	fmt.Println("CEREMONY_OPERATOR_IDENTITY_READY")
	return nil
}

func serve(settings options) error {
	identity, err := readSecretFile(filepath.Join(settings.storage, identityKeyFile), ed25519.PrivateKeySize)
	if err != nil || len(identity) != ed25519.PrivateKeySize {
		return errors.New("invalid operator identity")
	}
	signingKey := ed25519.PrivateKey(identity)

	params, err := ceremonyParameters()
	if err != nil {
		return err
	}
	roster, err := loadRoster(settings.roster)
	if err != nil {
		return err
	}
	state, err := fhe.NewCeremonyOperatorState(params, roster, settings.point, signingKey)
	if err != nil {
		return err
	}

	coordinatorKey, err := os.ReadFile(settings.coordinatorKey)
	if err != nil || len(coordinatorKey) != ed25519.PublicKeySize {
		return errors.New("invalid coordinator key")
	}
	certificate, err := loadCertificate(settings.certificate, signingKey)
	if err != nil {
		return err
	}
	caBytes, err := os.ReadFile(settings.peerCA)
	if err != nil || len(caBytes) == 0 || len(caBytes) > maxCertificateBytes {
		return errors.New("invalid peer CA")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caBytes) {
		return errors.New("invalid peer CA")
	}
	ledger, err := thresholdnet.Open(filepath.Join(settings.storage, ledgerFile))
	if err != nil {
		return err
	}
	defer ledger.Close()

	evaluatorKey, err := os.ReadFile(settings.evaluatorKey)
	if err != nil || len(evaluatorKey) != ed25519.PublicKeySize {
		return errors.New("invalid evaluator key")
	}
	// The ceremony coordinator and the evaluator are separate identities. The
	// coordinator may drive ceremony rounds and publish the key epoch; only the
	// evaluator may ask for a release share.
	gate := &releaseGate{
		ledger:         ledger,
		coordinatorKey: append(ed25519.PublicKey(nil), coordinatorKey...),
		evaluatorKey:   append(ed25519.PublicKey(nil), evaluatorKey...),
	}
	ceremonyServer := &thresholdnet.CeremonyServer{
		State:                state,
		CoordinatorPublicKey: append(ed25519.PublicKey(nil), coordinatorKey...),
		PeerDialer: func(point uint64, endpoint string) (*http.Client, error) {
			expected, ok := rosterKeyFor(roster, point)
			if !ok {
				return nil, errors.New("unknown peer")
			}
			config := thresholdnet.PeerTLSConfig(certificate, roots, fmt.Sprintf("node%d.local", point), expected)
			return &http.Client{
				Transport: &http.Transport{TLSClientConfig: config},
				Timeout:   60 * time.Second,
			}, nil
		},
		KeyID: gate.keyID,
		Persist: func(bundle []byte) error {
			path := filepath.Join(settings.storage, operatorBundleFile)
			if err := writeExclusive(path, bundle, 0o600); err != nil {
				return err
			}
			return gate.install(bundle)
		},
	}

	mux := http.NewServeMux()
	ceremonyServer.CeremonyHandler(mux)
	gate.mount(mux)

	server := &http.Server{
		Addr:              settings.listen,
		Handler:           mux,
		TLSConfig:         thresholdnet.ServerTLSConfig(certificate, roots),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       5 * time.Minute,
		WriteTimeout:      5 * time.Minute,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    8 << 10,
	}
	listener, err := net.Listen("tcp", settings.listen)
	if err != nil {
		return err
	}
	tlsListener := tls.NewListener(listener, server.TLSConfig)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(stop)
	serveError := make(chan error, 1)
	go func() { serveError <- server.Serve(tlsListener) }()

	select {
	case <-stop:
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return server.Shutdown(ctx)
	case err := <-serveError:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

// releaseGate exposes the release protocol only after the ceremony sealed this
// operator's own bundle. Before that there is no share to release with, so the
// release endpoints fail closed.
type releaseGate struct {
	mu             sync.RWMutex
	server         *thresholdnet.OperatorServer
	ledger         *thresholdnet.Store
	coordinatorKey ed25519.PublicKey
	evaluatorKey   ed25519.PublicKey
	keyIDValue     [32]byte
	keyIDSet       bool
}

func (gate *releaseGate) setKeyID(value [32]byte) {
	gate.mu.Lock()
	gate.keyIDValue, gate.keyIDSet = value, true
	gate.mu.Unlock()
}

func (gate *releaseGate) keyID() ([32]byte, error) {
	gate.mu.RLock()
	defer gate.mu.RUnlock()
	if !gate.keyIDSet {
		return [32]byte{}, errors.New("collective key id unknown")
	}
	return gate.keyIDValue, nil
}

func (gate *releaseGate) install(bundle []byte) error {
	operator, err := fhe.NewThresholdOperator(bundle)
	if err != nil {
		return err
	}
	gate.mu.Lock()
	gate.server = &thresholdnet.OperatorServer{
		Operator:             operator,
		Ledger:               gate.ledger,
		CoordinatorPublicKey: gate.evaluatorKey,
	}
	gate.mu.Unlock()
	return nil
}

func (gate *releaseGate) mount(mux *http.ServeMux) {
	for _, path := range []string{"/v1/prepare", "/v1/commit", "/v1/ack", "/v1/status"} {
		mux.HandleFunc(path, gate.dispatch)
	}
	mux.HandleFunc("/v1/key-epoch", gate.handleKeyEpoch)
}

func (gate *releaseGate) dispatch(writer http.ResponseWriter, request *http.Request) {
	gate.mu.RLock()
	server := gate.server
	gate.mu.RUnlock()
	if server == nil {
		writer.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(writer, "operator has no sealed share")
		return
	}
	server.Handler().ServeHTTP(writer, request)
}

// handleKeyEpoch lets the coordinator publish the collective key id before the
// operator seals. It carries no secret and is bound to the coordinator identity.
func (gate *releaseGate) handleKeyEpoch(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost || request.TLS == nil || len(request.TLS.PeerCertificates) == 0 {
		writer.WriteHeader(http.StatusUnauthorized)
		return
	}
	peerKey, ok := request.TLS.PeerCertificates[0].PublicKey.(ed25519.PublicKey)
	if !ok || !peerKey.Equal(gate.coordinatorKey) {
		writer.WriteHeader(http.StatusUnauthorized)
		return
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, 33))
	if err != nil || len(body) != 32 {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	var value [32]byte
	copy(value[:], body)
	gate.setKeyID(value)
	writer.WriteHeader(http.StatusNoContent)
}

// ceremonyParameters returns the unchanged production-candidate BGV parameters.
// The ceremony must not alter them: the policy circuit depth depends on them.
func ceremonyParameters() (bgv.Parameters, error) {
	return bgv.NewParametersFromLiteral(bgv.ParametersLiteral{
		LogN:             15,
		LogQ:             []int{60, 60, 59, 58, 58, 58, 58, 58, 58, 58, 58, 58},
		LogP:             []int{60, 60, 60},
		PlaintextModulus: 65537,
	})
}

func loadRoster(path string) (fhe.CeremonyRoster, error) {
	var roster fhe.CeremonyRoster
	raw, err := os.ReadFile(path)
	if err != nil {
		return roster, err
	}
	var file rosterFile
	if err := json.Unmarshal(raw, &file); err != nil {
		return roster, err
	}
	if len(file.Points) != len(file.SigningPublicKeys) || len(file.Points) == 0 {
		return roster, errors.New("invalid roster")
	}
	fingerprint, err := decodeHex32(file.ParameterFingerprint)
	if err != nil {
		return roster, err
	}
	ceremonyID, err := decodeHex32(file.CeremonyID)
	if err != nil {
		return roster, err
	}
	operators := make([]fhe.CeremonyOperatorIdentity, len(file.Points))
	for index, encoded := range file.SigningPublicKeys {
		raw, err := decodeHexBytes(encoded, ed25519.PublicKeySize)
		if err != nil {
			return roster, err
		}
		operators[index] = fhe.CeremonyOperatorIdentity{Point: file.Points[index]}
		copy(operators[index].SigningPublicKey[:], raw)
	}
	return fhe.CeremonyRoster{
		ParameterFingerprint: fingerprint,
		Threshold:            file.Threshold,
		CeremonyID:           ceremonyID,
		KeyEpoch:             file.KeyEpoch,
		Operators:            operators,
	}, nil
}

func rosterKeyFor(roster fhe.CeremonyRoster, point uint64) (ed25519.PublicKey, bool) {
	for _, operator := range roster.Operators {
		if operator.Point == point {
			return ed25519.PublicKey(append([]byte(nil), operator.SigningPublicKey[:]...)), true
		}
	}
	return nil, false
}

// loadCertificate pairs the CA-issued certificate with the operator's own
// private key, which never left this directory.
func loadCertificate(certificatePath string, signingKey ed25519.PrivateKey) (tls.Certificate, error) {
	certificatePEM, err := os.ReadFile(certificatePath)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(signingKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return tls.X509KeyPair(certificatePEM, keyPEM)
}

func parseOptions(arguments []string) (options, error) {
	var settings options
	flags := flag.NewFlagSet("ceremony-operator", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&settings.mode, "mode", "serve", "identity or serve")
	flags.StringVar(&settings.storage, "storage", "", "operator-private storage directory")
	flags.StringVar(&settings.listen, "listen", "127.0.0.1:9443", "TLS listen address")
	flags.StringVar(&settings.certificate, "tls-cert", "", "CA-issued certificate over this operator's key")
	flags.StringVar(&settings.privateKeyPath, "tls-key", "", "unused; the operator uses its own identity key")
	flags.StringVar(&settings.peerCA, "peer-ca", "", "CA trusted for peers and the coordinator")
	flags.StringVar(&settings.coordinatorKey, "coordinator-key", "", "raw Ed25519 ceremony coordinator public key")
	flags.StringVar(&settings.evaluatorKey, "evaluator-key", "", "raw Ed25519 evaluator public key authorised for releases")
	flags.StringVar(&settings.roster, "roster", "", "public ceremony roster")
	flags.Uint64Var(&settings.point, "point", 0, "this operator's Shamir point")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || settings.storage == "" {
		return options{}, errors.New("invalid ceremony-operator configuration")
	}
	if settings.mode == "identity" {
		return settings, nil
	}
	if settings.listen == "" || settings.certificate == "" || settings.peerCA == "" ||
		settings.coordinatorKey == "" || settings.evaluatorKey == "" || settings.roster == "" || settings.point == 0 {
		return options{}, errors.New("invalid ceremony-operator configuration")
	}
	return settings, nil
}

func decodeHex32(value string) ([32]byte, error) {
	var out [32]byte
	raw, err := decodeHexBytes(value, 32)
	if err != nil {
		return out, err
	}
	copy(out[:], raw)
	return out, nil
}

func decodeHexBytes(value string, size int) ([]byte, error) {
	if len(value) >= 2 && value[:2] == "0x" {
		value = value[2:]
	}
	if len(value) != size*2 {
		return nil, errors.New("invalid hex length")
	}
	out := make([]byte, size)
	for index := 0; index < size; index++ {
		high, err := hexNibble(value[index*2])
		if err != nil {
			return nil, err
		}
		low, err := hexNibble(value[index*2+1])
		if err != nil {
			return nil, err
		}
		out[index] = high<<4 | low
	}
	return out, nil
}

func hexNibble(character byte) (byte, error) {
	switch {
	case character >= '0' && character <= '9':
		return character - '0', nil
	case character >= 'a' && character <= 'f':
		return character - 'a' + 10, nil
	case character >= 'A' && character <= 'F':
		return character - 'A' + 10, nil
	default:
		return 0, errors.New("invalid hex")
	}
}

func writeExclusive(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err := file.Write(data); err != nil {
		return err
	}
	return file.Sync()
}

func readSecretFile(path string, maximum int64) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maximum || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("invalid secret file")
	}
	contents, err := os.ReadFile(path)
	if err != nil || int64(len(contents)) != info.Size() {
		return nil, errors.New("invalid secret file")
	}
	return contents, nil
}
