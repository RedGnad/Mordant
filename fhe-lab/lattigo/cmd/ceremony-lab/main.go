// Command ceremony-lab is the parent orchestrator for the dealerless custody
// gate. It builds the binaries, issues the lab PKI, launches every process,
// drives the run, then verifies the outcome and writes a commit-bound evidence
// bundle.
//
// It is deliberately not a participant: it holds no RLWE secret, no Shamir
// share and no operator identity key. Operator state in the evidence is copied
// from statements each operator signed with its own ceremony key, and the
// orchestrator verifies those signatures against the roster before recording
// them.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	fhe "mordant.dev/fhe-lab/lattigo"
)

const operatorCount = 3

type processRecord struct {
	Role      string   `json:"role"`
	PID       int      `json:"pid"`
	Command   []string `json:"command"`
	StartTime string   `json:"startTime"`
	ExitTime  string   `json:"exitTime,omitempty"`
	Exit      string   `json:"exit,omitempty"`
}

type evidence struct {
	SchemaVersion    string            `json:"schemaVersion"`
	Classification   string            `json:"classification"`
	LattigoVersion   string            `json:"lattigoVersion"`
	CustodyModel     string            `json:"custodyModel"`
	Source           sourceBinding     `json:"sourceBinding"`
	Processes        []processRecord   `json:"processes"`
	Roster           json.RawMessage   `json:"roster"`
	RosterDigest     string            `json:"rosterDigest"`
	Ceremony         json.RawMessage   `json:"ceremonyEvidence"`
	KeyManifest      json.RawMessage   `json:"keyManifest"`
	OperatorProof    []operatorProof   `json:"operatorStatements"`
	Evaluator        json.RawMessage   `json:"evaluatorOutput"`
	ShareIsolation   shareIsolation    `json:"shareIsolation"`
	Negatives        map[string]string `json:"negativeChecks"`
	Limitations      []string          `json:"limitations"`
	CompletedAtUTC   string            `json:"completedAtUtc"`
	ThresholdEpoch   uint64            `json:"keyEpoch"`
	SelectedCoalitio []uint64          `json:"selectedCoalition"`
}

type sourceBinding struct {
	Commit          string            `json:"commit"`
	WorkingTree     string            `json:"workingTree"`
	ModifiedTracked []string          `json:"modifiedTrackedFiles,omitempty"`
	UntrackedPaths  int               `json:"untrackedPathCount"`
	SourceTreeHash  string            `json:"sourceTreeSha256"`
	BinarySha256    map[string]string `json:"binarySha256"`
}

type operatorProof struct {
	Point               uint64          `json:"point"`
	SignatureVerified   bool            `json:"signatureVerifiedAgainstRoster"`
	Sealed              bool            `json:"sealed"`
	HoldsLocalSecretKey bool            `json:"holdsLocalSecretKey"`
	Statement           json.RawMessage `json:"statement"`
}

type shareIsolation struct {
	Method          string   `json:"method"`
	BundleFiles     []string `json:"operatorBundleFiles"`
	BundlePoints    []uint64 `json:"declaredPoints"`
	FilesScanned    int      `json:"filesScanned"`
	ForeignShareHit []string `json:"filesHoldingAForeignShare"`
	MultiShareFiles []string `json:"filesHoldingMoreThanOneShare"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "CEREMONY_LAB_FAILED: "+err.Error())
		os.Exit(1)
	}
}

func run() error {
	var root, out, repo string
	var keepRunning bool
	flag.StringVar(&root, "root", "", "lab working directory (default: temp dir)")
	flag.StringVar(&out, "out", "", "evidence output directory")
	flag.StringVar(&repo, "repo", "", "repository root for commit binding")
	flag.BoolVar(&keepRunning, "keep", false, "leave the working directory in place")
	flag.Parse()
	if out == "" {
		return errors.New("--out is required")
	}
	if root == "" {
		created, err := os.MkdirTemp("", "mordant-ceremony-v4-")
		if err != nil {
			return err
		}
		root = created
	}
	if repo == "" {
		repo = "."
	}
	lab := &lab{root: root, out: out, repo: repo}
	return lab.execute()
}

type lab struct {
	root, out, repo string
	processes       []processRecord
	running         []*exec.Cmd
	binaries        map[string]string
	caPEM           []byte
	caCert          *x509.Certificate
	caKey           ed25519.PrivateKey
	roster          fhe.CeremonyRoster
	rosterRaw       []byte
	ports           map[uint64]int
	labCert         tls.Certificate
	roots           *x509.CertPool
}

func (l *lab) execute() (runErr error) {
	defer func() {
		for _, command := range l.running {
			if command.Process != nil {
				_ = command.Process.Kill()
				_ = command.Wait()
			}
		}
	}()
	for _, directory := range []string{"bin", "public", "operators", "coordinator", "evaluator", "clients", "pki"} {
		if err := os.MkdirAll(filepath.Join(l.root, directory), 0o700); err != nil {
			return err
		}
	}
	if err := l.build(); err != nil {
		return fmt.Errorf("build: %w", err)
	}
	if err := l.makeCA(); err != nil {
		return fmt.Errorf("pki: %w", err)
	}
	if err := l.makeIdentities(); err != nil {
		return fmt.Errorf("identities: %w", err)
	}
	if err := l.makeRoster(); err != nil {
		return fmt.Errorf("roster: %w", err)
	}
	if err := l.launchOperators(); err != nil {
		return fmt.Errorf("operators: %w", err)
	}
	if err := l.runCoordinator(); err != nil {
		return fmt.Errorf("coordinator: %w", err)
	}
	if err := l.runClientsAndEvaluator(); err != nil {
		return fmt.Errorf("evaluation: %w", err)
	}
	return l.writeEvidence()
}

func (l *lab) build() error {
	l.binaries = map[string]string{}
	for _, name := range []string{"ceremony-operator", "ceremony-coordinator", "ceremony-client", "ceremony-evaluator"} {
		target := filepath.Join(l.root, "bin", name)
		command := exec.Command("go", "build", "-o", target, "./cmd/"+name)
		command.Dir = l.repo
		command.Stderr = os.Stderr
		if err := command.Run(); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		l.binaries[name] = target
	}
	return nil
}

func (l *lab) makeCA() error {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Mordant dealerless lab CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		return err
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return err
	}
	l.caCert, l.caKey = certificate, private
	l.caPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	l.roots = x509.NewCertPool()
	l.roots.AddCert(certificate)
	return os.WriteFile(filepath.Join(l.root, "pki", "ca.pem"), l.caPEM, 0o644)
}

// issue signs a certificate over a public key the holder generated itself. The
// lab CA never sees the corresponding private key.
func (l *lab) issue(name string, public ed25519.PublicKey) ([]byte, error) {
	serial := sha256.Sum256([]byte(name))
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: new(big.Int).SetBytes(serial[:16]),
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{name},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, l.caCert, public, l.caKey)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

func (l *lab) makeIdentities() error {
	// Each operator generates its own identity key in its own directory.
	for index := 1; index <= operatorCount; index++ {
		storage := filepath.Join(l.root, "operators", fmt.Sprintf("%d", index))
		if err := l.runToCompletion(fmt.Sprintf("operator-%d-identity", index), l.binaries["ceremony-operator"],
			"-mode", "identity", "-storage", storage); err != nil {
			return err
		}
		public, err := os.ReadFile(filepath.Join(storage, "identity.pub"))
		if err != nil || len(public) != ed25519.PublicKeySize {
			return errors.New("operator identity missing")
		}
		certificate, err := l.issue(fmt.Sprintf("node%d.local", index), ed25519.PublicKey(public))
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(storage, "tls.crt"), certificate, 0o644); err != nil {
			return err
		}
	}
	// The coordinator generates its own identity too.
	coordinatorStorage := filepath.Join(l.root, "coordinator")
	if err := l.runToCompletion("coordinator-identity", l.binaries["ceremony-coordinator"],
		"-mode", "identity", "-storage", coordinatorStorage); err != nil {
		return err
	}
	coordinatorPublic, err := os.ReadFile(filepath.Join(coordinatorStorage, "identity.pub"))
	if err != nil {
		return err
	}
	coordinatorCert, err := l.issue("coordinator.local", ed25519.PublicKey(coordinatorPublic))
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(coordinatorStorage, "tls.crt"), coordinatorCert, 0o644); err != nil {
		return err
	}

	// The evaluator holds no FHE secret; its identity is a transport key only.
	evaluatorPublic, evaluatorPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	evaluatorStorage := filepath.Join(l.root, "evaluator")
	if err := os.WriteFile(filepath.Join(evaluatorStorage, "identity.key"), evaluatorPrivate, 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(evaluatorStorage, "identity.pub"), evaluatorPublic, 0o644); err != nil {
		return err
	}
	evaluatorCert, err := l.issue("evaluator.local", evaluatorPublic)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(evaluatorStorage, "tls.crt"), evaluatorCert, 0o644); err != nil {
		return err
	}

	// The orchestrator's own read-only identity, used to fetch signed operator
	// statements directly rather than through the coordinator.
	labPublic, labPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	labCertPEM, err := l.issue("lab.local", labPublic)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(labPrivate)
	if err != nil {
		return err
	}
	l.labCert, err = tls.X509KeyPair(labCertPEM, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	return err
}

func (l *lab) makeRoster() error {
	params, err := labParameters()
	if err != nil {
		return err
	}
	parameterBytes, err := params.MarshalBinary()
	if err != nil {
		return err
	}
	fingerprint := sha256.Sum256(parameterBytes)
	var ceremonyID [32]byte
	if _, err := rand.Read(ceremonyID[:]); err != nil {
		return err
	}
	points := make([]uint64, 0, operatorCount)
	keys := make([]string, 0, operatorCount)
	identities := make([]fhe.CeremonyOperatorIdentity, 0, operatorCount)
	for index := 1; index <= operatorCount; index++ {
		public, err := os.ReadFile(filepath.Join(l.root, "operators", fmt.Sprintf("%d", index), "identity.pub"))
		if err != nil {
			return err
		}
		points = append(points, uint64(index))
		keys = append(keys, hex.EncodeToString(public))
		identity := fhe.CeremonyOperatorIdentity{Point: uint64(index)}
		copy(identity.SigningPublicKey[:], public)
		identities = append(identities, identity)
	}
	l.roster = fhe.CeremonyRoster{
		ParameterFingerprint: fingerprint,
		Threshold:            2,
		CeremonyID:           ceremonyID,
		KeyEpoch:             1,
		Operators:            identities,
	}
	raw, err := json.MarshalIndent(map[string]any{
		"parameterFingerprint": hex.EncodeToString(fingerprint[:]),
		"threshold":            2,
		"ceremonyId":           hex.EncodeToString(ceremonyID[:]),
		"keyEpoch":             1,
		"points":               points,
		"signingPublicKeys":    keys,
	}, "", "  ")
	if err != nil {
		return err
	}
	l.rosterRaw = raw
	return os.WriteFile(filepath.Join(l.root, "public", "roster.json"), raw, 0o644)
}

func (l *lab) launchOperators() error {
	l.ports = map[uint64]int{}
	for index := 1; index <= operatorCount; index++ {
		port, err := freePort()
		if err != nil {
			return err
		}
		l.ports[uint64(index)] = port
		storage := filepath.Join(l.root, "operators", fmt.Sprintf("%d", index))
		command := exec.Command(l.binaries["ceremony-operator"],
			"-mode", "serve",
			"-storage", storage,
			"-listen", fmt.Sprintf("127.0.0.1:%d", port),
			"-tls-cert", filepath.Join(storage, "tls.crt"),
			"-peer-ca", filepath.Join(l.root, "pki", "ca.pem"),
			"-coordinator-key", filepath.Join(l.root, "coordinator", "identity.pub"),
			"-evaluator-key", filepath.Join(l.root, "evaluator", "identity.pub"),
			"-roster", filepath.Join(l.root, "public", "roster.json"),
			"-point", fmt.Sprintf("%d", index),
		)
		if err := l.spawn(fmt.Sprintf("threshold-operator-%d", index), command); err != nil {
			return err
		}
	}
	// Wait for every listener before the ceremony starts.
	deadline := time.Now().Add(30 * time.Second)
	for point, port := range l.ports {
		for {
			if time.Now().After(deadline) {
				return fmt.Errorf("operator %d did not start", point)
			}
			connection, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
			if err == nil {
				_ = connection.Close()
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	return nil
}

func (l *lab) operatorEndpoints() string {
	parts := make([]string, 0, operatorCount)
	for point := uint64(1); point <= operatorCount; point++ {
		parts = append(parts, fmt.Sprintf("%d=https://127.0.0.1:%d", point, l.ports[point]))
	}
	return strings.Join(parts, ",")
}

func (l *lab) runCoordinator() error {
	policyID := sha256.Sum256([]byte("mordant.dealerless.policy/v4"))
	return l.runToCompletion("ceremony-coordinator", l.binaries["ceremony-coordinator"],
		"-mode", "conduct",
		"-storage", filepath.Join(l.root, "coordinator"),
		"-tls-cert", filepath.Join(l.root, "coordinator", "tls.crt"),
		"-peer-ca", filepath.Join(l.root, "pki", "ca.pem"),
		"-roster", filepath.Join(l.root, "public", "roster.json"),
		"-operators", l.operatorEndpoints(),
		"-out", filepath.Join(l.root, "public"),
		"-chain-id", "10143",
		"-policy-id", hex.EncodeToString(policyID[:]),
		"-validity-seconds", "3600",
	)
}

func (l *lab) runClientsAndEvaluator() error {
	policyID := sha256.Sum256([]byte("mordant.dealerless.policy/v4"))
	rosterDigest := l.roster.Digest()
	var sessionID [32]byte
	if _, err := rand.Read(sessionID[:]); err != nil {
		return err
	}
	issuerPublic, issuerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	issuerDir := filepath.Join(l.root, "clients")
	if err := os.WriteFile(filepath.Join(issuerDir, "issuer.key"), issuerPrivate, 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(issuerDir, "issuer.pub"), issuerPublic, 0o644); err != nil {
		return err
	}
	validUntil := time.Now().Add(30 * time.Minute).Unix()
	nonce := time.Now().UnixNano() % 1_000_000_007
	public := filepath.Join(l.root, "public")
	for _, party := range []string{"a", "b"} {
		if err := l.runToCompletion("ceremony-client-"+party, l.binaries["ceremony-client"],
			"-party", party,
			"-public-material", filepath.Join(public, "collective-public-material.bin"),
			"-key-manifest", filepath.Join(public, "key-manifest.json"),
			"-evaluation-keys", filepath.Join(public, "collective-evaluation-keys.bin"),
			"-issuer-key", filepath.Join(issuerDir, "issuer.key"),
			"-out", filepath.Join(public, "envelopes", party+".bin"),
			"-private-manifest", filepath.Join(l.root, "clients", "private-"+party, "canaries.json"),
			"-roster-digest", hex.EncodeToString(rosterDigest[:]),
			"-vault", "0x7531d467F19d1055AcCF6B0D22286184f87adBd8",
			"-policy-id", hex.EncodeToString(policyID[:]),
			"-session-id", hex.EncodeToString(sessionID[:]),
			"-chain-id", "10143",
			"-policy-version", "1",
			"-nonce", fmt.Sprintf("%d", nonce),
			"-valid-until", fmt.Sprintf("%d", validUntil),
			"-key-epoch", "1",
			"-threshold", "2",
		); err != nil {
			return err
		}
	}
	var releaseSession [32]byte
	if _, err := rand.Read(releaseSession[:]); err != nil {
		return err
	}
	return l.runToCompletion("ceremony-evaluator", l.binaries["ceremony-evaluator"],
		"-public-material", filepath.Join(public, "collective-public-material.bin"),
		"-evaluation-keys", filepath.Join(public, "collective-evaluation-keys.bin"),
		"-key-manifest", filepath.Join(public, "key-manifest.json"),
		"-issuer-public", filepath.Join(issuerDir, "issuer.pub"),
		"-input-a", filepath.Join(public, "envelopes", "a.bin"),
		"-input-b", filepath.Join(public, "envelopes", "b.bin"),
		"-out", filepath.Join(public, "evaluator-result.json"),
		"-storage", filepath.Join(l.root, "evaluator"),
		"-tls-cert", filepath.Join(l.root, "evaluator", "tls.crt"),
		"-peer-ca", filepath.Join(l.root, "pki", "ca.pem"),
		"-operators", l.operatorEndpoints(),
		"-coalition", "1,2",
		"-session-id", hex.EncodeToString(releaseSession[:]),
		"-vault", "0x7531d467F19d1055AcCF6B0D22286184f87adBd8",
		"-policy-id", hex.EncodeToString(policyID[:]),
		"-chain-id", "10143",
		"-policy-version", "1",
		"-nonce", fmt.Sprintf("%d", nonce),
		"-valid-until", fmt.Sprintf("%d", validUntil),
	)
}

func (l *lab) spawn(role string, command *exec.Cmd) error {
	logDirectory := filepath.Join(l.root, "public", "logs")
	if err := os.MkdirAll(logDirectory, 0o755); err != nil {
		return err
	}
	stdout, err := os.Create(filepath.Join(logDirectory, role+".stdout"))
	if err != nil {
		return err
	}
	stderr, err := os.Create(filepath.Join(logDirectory, role+".stderr"))
	if err != nil {
		return err
	}
	command.Stdout, command.Stderr = stdout, stderr
	if err := command.Start(); err != nil {
		return err
	}
	l.processes = append(l.processes, processRecord{
		Role: role, PID: command.Process.Pid, Command: redact(command.Args),
		StartTime: time.Now().UTC().Format(time.RFC3339Nano),
	})
	l.running = append(l.running, command)
	return nil
}

func (l *lab) runToCompletion(role, binary string, arguments ...string) error {
	command := exec.Command(binary, arguments...)
	logDirectory := filepath.Join(l.root, "public", "logs")
	if err := os.MkdirAll(logDirectory, 0o755); err != nil {
		return err
	}
	stdout, err := os.Create(filepath.Join(logDirectory, role+".stdout"))
	if err != nil {
		return err
	}
	stderr, err := os.Create(filepath.Join(logDirectory, role+".stderr"))
	if err != nil {
		return err
	}
	command.Stdout, command.Stderr = stdout, stderr
	started := time.Now().UTC()
	runErr := command.Run()
	record := processRecord{
		Role: role, Command: redact(command.Args),
		StartTime: started.Format(time.RFC3339Nano),
		ExitTime:  time.Now().UTC().Format(time.RFC3339Nano),
	}
	if command.ProcessState != nil {
		record.PID = command.ProcessState.Pid()
		record.Exit = fmt.Sprintf("%d", command.ProcessState.ExitCode())
	}
	l.processes = append(l.processes, record)
	if runErr != nil {
		message, _ := os.ReadFile(filepath.Join(logDirectory, role+".stderr"))
		return fmt.Errorf("%s: %w: %s", role, runErr, strings.TrimSpace(string(message)))
	}
	return nil
}

func redact(arguments []string) []string {
	out := make([]string, 0, len(arguments))
	skip := false
	for _, argument := range arguments {
		if skip {
			out = append(out, "[redacted]")
			skip = false
			continue
		}
		if argument == "-issuer-key" || argument == "-private-manifest" {
			skip = true
		}
		out = append(out, argument)
	}
	return out
}

func freePort() (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port, nil
}
