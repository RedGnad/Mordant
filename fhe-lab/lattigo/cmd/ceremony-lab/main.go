//go:build obsolete_recoverable_ceremony

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
	"runtime"
	"sort"
	"strings"
	"time"

	fhe "mordant.dev/fhe-lab/lattigo"
	"mordant.dev/fhe-lab/lattigo/internal/thresholdnet"
)

const operatorCount = 3

type processRecord struct {
	Role               string   `json:"role"`
	PID                int      `json:"pid"`
	ParentPID          int      `json:"parentPid"`
	Command            []string `json:"command"`
	WorkingDirectory   string   `json:"workingDirectory"`
	EnvironmentKeys    []string `json:"environmentKeys"`
	TemporaryDirectory string   `json:"temporaryDirectory,omitempty"`
	StartTime          string   `json:"startTime"`
	ExitTime           string   `json:"exitTime,omitempty"`
	Exit               string   `json:"exit,omitempty"`
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

const ceremonyContextDomain = "mordant.ceremony.context/v1"

type ceremonyContextBase struct {
	SchemaVersion     string `json:"schemaVersion"`
	ChainID           uint64 `json:"chainId"`
	PolicyID          string `json:"policyId"`
	PolicyVersion     uint32 `json:"policyVersion"`
	SessionCommitment string `json:"sessionCommitment"`
	ContextNonce      string `json:"contextNonce"`
}

type ceremonyContext struct {
	SchemaVersion         string            `json:"schemaVersion"`
	CeremonyProtocol      string            `json:"ceremonyProtocol"`
	ManifestSchema        string            `json:"manifestSchema"`
	KeyScheme             string            `json:"keyScheme"`
	LattigoVersion        string            `json:"lattigoVersion"`
	GoRuntimeVersion      string            `json:"goRuntimeVersion"`
	Threshold             uint16            `json:"threshold"`
	OperatorPoints        []uint64          `json:"operatorPoints"`
	OperatorSigningKeys   []string          `json:"operatorSigningKeys"`
	ParameterFingerprint  string            `json:"parameterFingerprint"`
	CircuitVersion        uint32            `json:"circuitVersion"`
	CircuitHash           string            `json:"circuitHash"`
	ReleaseLayoutVersion  uint16            `json:"releaseLayoutVersion"`
	SerializationVersion  uint32            `json:"serializationVersion"`
	RuntimeBinarySHA256   map[string]string `json:"runtimeBinarySha256"`
	ChainID               uint64            `json:"chainId"`
	PolicyID              string            `json:"policyId"`
	PolicyVersion         uint32            `json:"policyVersion"`
	SessionCommitment     string            `json:"sessionCommitment"`
	ContextNonce          string            `json:"contextNonce"`
	OneHostCustodyWarning string            `json:"oneHostCustodyWarning"`
	CeremonyID            string            `json:"ceremonyId"`
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
	var root, out, repo, vault, policyLabel, anchorRootHex string
	var identityMode, assetIDFile, bindingAHex, bindingBHex, contextBaseFile string
	var keepRunning, ceremonyOnly, setupOnly, readyOnly, resume, retainReadyOperators bool
	var readyThrough int
	var stopAfter string
	var auditRoots multiStringFlag
	flag.StringVar(&root, "root", "", "lab working directory (default: temp dir)")
	flag.StringVar(&out, "out", "", "evidence output directory")
	flag.StringVar(&repo, "repo", "", "repository root for commit binding")
	flag.BoolVar(&keepRunning, "keep", false, "leave the working directory in place")
	flag.BoolVar(&ceremonyOnly, "ceremony-only", false, "stop after the public ceremony bundle; do not encrypt or evaluate")
	flag.BoolVar(&setupOnly, "setup-only", false, "prepare immutable binaries, identities, certificates, and roster without starting a ceremony")
	flag.BoolVar(&readyOnly, "ready-only", false, "start and attest all three recovered operators without driving a ceremony round")
	flag.IntVar(&readyThrough, "ready-through", operatorCount,
		"with --ready-only, start and attest the canonical operator prefix through this point")
	flag.BoolVar(&resume, "resume", false, "reuse the immutable identities, roster, certificates, and binaries already under root")
	flag.BoolVar(&retainReadyOperators, "retain-ready-operators", false,
		"recovery test only: return after the ready snapshot while the three operators remain live")
	flag.StringVar(&stopAfter, "stop-after", "", "controlled coordinator checkpoint for recovery testing")
	flag.StringVar(&contextBaseFile, "context-base", "", "canonical runner context base used to derive and bind the ceremony identifier")
	flag.Var(&auditRoots, "audit-root", "additional runner-public file or directory scanned independently by every operator")
	flag.StringVar(&vault, "vault", "0x7531d467F19d1055AcCF6B0D22286184f87adBd8", "policy-scope vault or receivable anchor address")
	flag.StringVar(&policyLabel, "policy-label", "mordant.dealerless.policy/v4", "policy identity label")
	flag.StringVar(&anchorRootHex, "anchor-root", "", "invoice root of a deployed receivable anchor")
	flag.StringVar(&identityMode, "identity-mode", "public_salted_commitment",
		"public_salted_commitment or full_fhe_256")
	flag.StringVar(&assetIDFile, "asset-id-file", "",
		"file holding the strict stable asset identity, required in full_fhe_256")
	flag.StringVar(&bindingAHex, "enrollment-binding-a", "", "runner-computed enrollment binding for side A")
	flag.StringVar(&bindingBHex, "enrollment-binding-b", "", "runner-computed enrollment binding for side B")
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
	policyID := sha256.Sum256([]byte(policyLabel))
	anchorRoot := sha256.Sum256([]byte("ceremony-lab-unanchored-root"))
	if anchorRootHex != "" {
		raw, err := hex.DecodeString(strings.TrimPrefix(anchorRootHex, "0x"))
		if err != nil || len(raw) != 32 {
			return errors.New("invalid --anchor-root")
		}
		copy(anchorRoot[:], raw)
	}
	if identityMode != "public_salted_commitment" && identityMode != "full_fhe_256" {
		return errors.New("unsupported identity mode")
	}
	if identityMode == "full_fhe_256" && (assetIDFile == "" || bindingAHex == "" || bindingBHex == "") {
		return errors.New("full_fhe_256 requires an asset id and both enrollment bindings")
	}
	if retainReadyOperators && (!resume || !ceremonyOnly || !readyOnly || stopAfter != "") {
		return errors.New("--retain-ready-operators requires --resume --ceremony-only --ready-only")
	}
	if readyOnly && (readyThrough < 1 || readyThrough > operatorCount) {
		return errors.New("--ready-through must be between 1 and 3")
	}
	lab := &lab{
		root: root, out: out, repo: repo, vault: vault, policyID: policyID, anchorRoot: anchorRoot,
		chainID:      10143,
		identityMode: identityMode, assetIDFile: assetIDFile, bindingA: bindingAHex, bindingB: bindingBHex,
		ceremonyOnly: ceremonyOnly, setupOnly: setupOnly, readyOnly: readyOnly, resume: resume, stopAfter: stopAfter,
		retainReadyOperators: retainReadyOperators, readyThrough: readyThrough,
		contextBaseFile: contextBaseFile,
		auditRoots:      append([]string(nil), auditRoots...),
	}
	return lab.execute()
}

type lab struct {
	root, out, repo      string
	vault                string
	policyID             [32]byte
	chainID              uint64
	anchorRoot           [32]byte
	identityMode         string
	assetIDFile          string
	bindingA             string
	bindingB             string
	ceremonyOnly         bool
	setupOnly            bool
	readyOnly            bool
	resume               bool
	retainReadyOperators bool
	readyThrough         int
	stopAfter            string
	contextBaseFile      string
	auditRoots           []string
	startedAt            time.Time
	processes            []processRecord
	running              []*exec.Cmd
	binaries             map[string]string
	caPEM                []byte
	caCert               *x509.Certificate
	caKey                ed25519.PrivateKey
	roster               fhe.CeremonyRoster
	rosterRaw            []byte
	ports                map[uint64]int
	labCert              tls.Certificate
	roots                *x509.CertPool
}

type multiStringFlag []string

func (values *multiStringFlag) String() string { return strings.Join(*values, ",") }

func (values *multiStringFlag) Set(value string) error {
	if value == "" {
		return errors.New("empty repeated path")
	}
	*values = append(*values, value)
	return nil
}

// enrollmentBinding returns the runner-computed binding for one side. It is
// carried as that side's signed enrollment nonce, so both enrollments provably
// name the same committed session.
func (l *lab) enrollmentBinding(party string) string {
	if party == "a" {
		return l.bindingA
	}
	return l.bindingB
}

func (l *lab) execute() (runErr error) {
	l.startedAt = time.Now().UTC()
	defer func() {
		if runErr == nil && l.retainReadyOperators {
			return
		}
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
	if l.resume {
		if !l.ceremonyOnly {
			return errors.New("--resume is restricted to --ceremony-only")
		}
		if err := l.loadBinaries(); err != nil {
			return fmt.Errorf("resume binaries: %w", err)
		}
		if err := l.loadResumeContext(); err != nil {
			return fmt.Errorf("resume context: %w", err)
		}
		if err := l.launchOperators(); err != nil {
			return fmt.Errorf("resume operators: %w", err)
		}
		if l.readyOnly {
			return l.writeRecoverySnapshot()
		}
		if err := l.runCoordinator(); err != nil {
			return err
		}
		return l.writeRecoverySnapshot()
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
	if l.setupOnly {
		return nil
	}
	if err := l.launchOperators(); err != nil {
		return fmt.Errorf("operators: %w", err)
	}
	if l.readyOnly {
		return l.writeRecoverySnapshot()
	}
	if err := l.runCoordinator(); err != nil {
		return fmt.Errorf("coordinator: %w", err)
	}
	if l.ceremonyOnly {
		return l.writeRecoverySnapshot()
	}
	if err := l.runClientsAndEvaluator(); err != nil {
		return fmt.Errorf("evaluation: %w", err)
	}
	return l.writeEvidence()
}

func (l *lab) loadBinaries() error {
	l.binaries = map[string]string{}
	for _, name := range []string{"ceremony-operator", "ceremony-coordinator", "ceremony-client", "ceremony-evaluator"} {
		path := filepath.Join(l.root, "bin", name)
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
			return fmt.Errorf("missing immutable binary %s", name)
		}
		l.binaries[name] = path
	}
	return nil
}

func (l *lab) loadResumeContext() error {
	raw, err := os.ReadFile(filepath.Join(l.root, "public", "roster.json"))
	if err != nil {
		return err
	}
	var file struct {
		ParameterFingerprint string   `json:"parameterFingerprint"`
		Threshold            uint16   `json:"threshold"`
		CeremonyID           string   `json:"ceremonyId"`
		KeyEpoch             uint64   `json:"keyEpoch"`
		Points               []uint64 `json:"points"`
		SigningPublicKeys    []string `json:"signingPublicKeys"`
	}
	if err := json.Unmarshal(raw, &file); err != nil || len(file.Points) != operatorCount || len(file.SigningPublicKeys) != operatorCount {
		return errors.New("invalid persisted roster")
	}
	fingerprint, err := decodeHex32(file.ParameterFingerprint)
	if err != nil {
		return err
	}
	ceremonyID, err := decodeHex32(file.CeremonyID)
	if err != nil {
		return err
	}
	operators := make([]fhe.CeremonyOperatorIdentity, operatorCount)
	for index := range operators {
		key, err := hex.DecodeString(file.SigningPublicKeys[index])
		if err != nil || len(key) != ed25519.PublicKeySize {
			return errors.New("invalid persisted operator identity")
		}
		operators[index].Point = file.Points[index]
		copy(operators[index].SigningPublicKey[:], key)
	}
	l.roster = fhe.CeremonyRoster{
		ParameterFingerprint: fingerprint, Threshold: file.Threshold, CeremonyID: ceremonyID,
		KeyEpoch: file.KeyEpoch, Operators: operators,
	}
	l.rosterRaw = raw
	if err := l.verifyPersistedCeremonyContext(); err != nil {
		return err
	}
	caBytes, err := os.ReadFile(filepath.Join(l.root, "pki", "ca.pem"))
	if err != nil {
		return err
	}
	l.roots = x509.NewCertPool()
	if !l.roots.AppendCertsFromPEM(caBytes) {
		return errors.New("invalid persisted CA")
	}
	key, err := os.ReadFile(filepath.Join(l.root, "coordinator", "identity.key"))
	if err != nil || len(key) != ed25519.PrivateKeySize {
		return errors.New("invalid persisted coordinator identity")
	}
	certificate, err := os.ReadFile(filepath.Join(l.root, "coordinator", "tls.crt"))
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(ed25519.PrivateKey(key))
	if err != nil {
		return err
	}
	l.labCert, err = tls.X509KeyPair(certificate, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	return err
}

func (l *lab) verifyPersistedCeremonyContext() error {
	path := filepath.Join(l.root, "public", "ceremony-context.json")
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil // Backward-compatible for the pre-runner lab workflow.
	}
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	var context ceremonyContext
	if err := decoder.Decode(&context); err != nil {
		return err
	}
	declared, err := decodeHex32(context.CeremonyID)
	if err != nil || declared != l.roster.CeremonyID || context.Threshold != l.roster.Threshold ||
		context.ParameterFingerprint != hex.EncodeToString(l.roster.ParameterFingerprint[:]) ||
		len(context.OperatorPoints) != len(l.roster.Operators) || len(context.OperatorSigningKeys) != len(l.roster.Operators) {
		return errors.New("persisted ceremony context does not match the roster")
	}
	for index, operator := range l.roster.Operators {
		if context.OperatorPoints[index] != operator.Point || context.OperatorSigningKeys[index] != hex.EncodeToString(operator.SigningPublicKey[:]) {
			return errors.New("persisted ceremony operator set drifted")
		}
	}
	context.CeremonyID = ""
	payload, err := json.Marshal(context)
	if err != nil {
		return err
	}
	observed := sha256.Sum256(append([]byte(ceremonyContextDomain+"\x00"), payload...))
	if observed != declared {
		return errors.New("persisted ceremony context digest drifted")
	}
	for name, expected := range context.RuntimeBinarySHA256 {
		path, ok := l.binaries[name]
		if !ok {
			return errors.New("persisted runtime binary set drifted")
		}
		binary, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		digest := sha256.Sum256(binary)
		if hex.EncodeToString(digest[:]) != expected {
			return fmt.Errorf("persisted runtime binary %s drifted", name)
		}
	}
	policyID, err := decodeHex32(context.PolicyID)
	if err != nil || context.ChainID == 0 || context.PolicyVersion != fhe.PolicyVersion {
		return errors.New("persisted ceremony policy context is invalid")
	}
	l.policyID = policyID
	l.chainID = context.ChainID
	return nil
}

func decodeHex32(value string) ([32]byte, error) {
	var out [32]byte
	raw, err := hex.DecodeString(strings.TrimPrefix(value, "0x"))
	if err != nil || len(raw) != len(out) {
		return out, errors.New("expected an exact 32-byte hexadecimal value")
	}
	copy(out[:], raw)
	return out, nil
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
	var ceremonyID [32]byte
	if l.contextBaseFile != "" {
		ceremonyID, err = l.writeBoundCeremonyContext(fingerprint, points, keys)
		if err != nil {
			return err
		}
	} else if _, err := rand.Read(ceremonyID[:]); err != nil {
		return err
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

func (l *lab) writeBoundCeremonyContext(fingerprint [32]byte, points []uint64, keys []string) ([32]byte, error) {
	var zero [32]byte
	file, err := os.Open(l.contextBaseFile)
	if err != nil {
		return zero, err
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	var base ceremonyContextBase
	if err := decoder.Decode(&base); err != nil {
		return zero, err
	}
	if base.SchemaVersion != "mordant.ceremony-context-base/1" || base.ChainID == 0 || base.PolicyVersion != fhe.PolicyVersion {
		return zero, errors.New("invalid ceremony context base")
	}
	if _, err := decodeHex32(base.PolicyID); err != nil {
		return zero, errors.New("invalid context policy id")
	}
	if _, err := decodeHex32(base.SessionCommitment); err != nil {
		return zero, errors.New("invalid context session commitment")
	}
	if _, err := decodeHex32(base.ContextNonce); err != nil {
		return zero, errors.New("invalid context nonce")
	}
	binaryDigests := make(map[string]string, len(l.binaries))
	for name, path := range l.binaries {
		raw, err := os.ReadFile(path)
		if err != nil {
			return zero, err
		}
		digest := sha256.Sum256(raw)
		binaryDigests[name] = hex.EncodeToString(digest[:])
	}
	circuitHash := fhe.CircuitHashV5()
	context := ceremonyContext{
		SchemaVersion: "mordant.ceremony-context/1", CeremonyProtocol: thresholdnet.CeremonyProtocolVersion,
		ManifestSchema: fhe.CollectiveKeyManifestSchema, KeyScheme: "Lattigo BGV dealerless multiparty 2-of-3",
		LattigoVersion: fhe.LattigoVersion, GoRuntimeVersion: runtime.Version(), Threshold: 2,
		OperatorPoints: append([]uint64(nil), points...), OperatorSigningKeys: append([]string(nil), keys...),
		ParameterFingerprint: hex.EncodeToString(fingerprint[:]), CircuitVersion: fhe.CircuitV5Version,
		CircuitHash: hex.EncodeToString(circuitHash[:]), ReleaseLayoutVersion: fhe.ReleaseLayoutVersion,
		SerializationVersion: fhe.SerializationVersion, RuntimeBinarySHA256: binaryDigests,
		ChainID: base.ChainID, PolicyID: strings.TrimPrefix(base.PolicyID, "0x"), PolicyVersion: base.PolicyVersion,
		SessionCommitment: strings.TrimPrefix(base.SessionCommitment, "0x"), ContextNonce: strings.TrimPrefix(base.ContextNonce, "0x"),
		OneHostCustodyWarning: "process separation on one host is not independent organizational custody",
	}
	policyID, _ := decodeHex32(base.PolicyID)
	l.policyID = policyID
	l.chainID = base.ChainID
	payload, err := json.Marshal(context)
	if err != nil {
		return zero, err
	}
	digestInput := append([]byte(ceremonyContextDomain+"\x00"), payload...)
	ceremonyID := sha256.Sum256(digestInput)
	context.CeremonyID = hex.EncodeToString(ceremonyID[:])
	encoded, err := json.MarshalIndent(context, "", "  ")
	if err != nil {
		return zero, err
	}
	path := filepath.Join(l.root, "public", "ceremony-context.json")
	if err := os.WriteFile(path, append(encoded, '\n'), 0o644); err != nil {
		return zero, err
	}
	return ceremonyID, nil
}

func (l *lab) launchOperators() error {
	l.ports = map[uint64]int{}
	operatorLimit := operatorCount
	if l.readyOnly {
		operatorLimit = l.readyThrough
	}
	for index := 1; index <= operatorLimit; index++ {
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
		command.Env = isolatedProcessEnvironment(filepath.Join(storage, "tmp"))
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
	policyID := l.policyID
	arguments := []string{
		"-mode", "conduct",
		"-storage", filepath.Join(l.root, "coordinator"),
		"-tls-cert", filepath.Join(l.root, "coordinator", "tls.crt"),
		"-peer-ca", filepath.Join(l.root, "pki", "ca.pem"),
		"-roster", filepath.Join(l.root, "public", "roster.json"),
		"-operators", l.operatorEndpoints(),
		"-out", filepath.Join(l.root, "public"),
		"-chain-id", fmt.Sprintf("%d", l.chainID),
		"-policy-id", hex.EncodeToString(policyID[:]),
		"-validity-seconds", "3600",
	}
	if l.stopAfter != "" {
		arguments = append(arguments, "-stop-after", l.stopAfter)
	}
	return l.runToCompletion("ceremony-coordinator", l.binaries["ceremony-coordinator"], arguments...)
}

func (l *lab) runClientsAndEvaluator() error {
	policyID := l.policyID
	rosterDigest := l.roster.Digest()
	var sessionID [32]byte
	if _, err := rand.Read(sessionID[:]); err != nil {
		return err
	}
	// The product gate supplies the real invoice root of a deployed receivable.
	// A standalone ceremony run falls back to a placeholder, which exercises the
	// client's binding path without implying an anchor.
	anchorRoot := l.anchorRoot
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
			"-coverage-out", filepath.Join(public, "coverage-"+party+".json"),
			"-anchor-root", hex.EncodeToString(anchorRoot[:]),
			"-currency-code", "USD",
			"-roster-digest", hex.EncodeToString(rosterDigest[:]),
			"-vault", l.vault,
			"-policy-id", hex.EncodeToString(policyID[:]),
			"-session-id", hex.EncodeToString(sessionID[:]),
			"-chain-id", "10143",
			"-policy-version", "1",
			"-nonce", fmt.Sprintf("%d", nonce),
			"-valid-until", fmt.Sprintf("%d", validUntil),
			"-key-epoch", "1",
			"-threshold", "2",
			"-identity-mode", l.identityMode,
			"-asset-id-file", l.assetIDFile,
			"-enrollment-binding", l.enrollmentBinding(party),
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
		"-vault", l.vault,
		"-policy-id", hex.EncodeToString(policyID[:]),
		"-chain-id", "10143",
		"-policy-version", "1",
		"-nonce", fmt.Sprintf("%d", nonce),
		"-valid-until", fmt.Sprintf("%d", validUntil),
		"-identity-mode", l.identityMode,
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
	if command.Env == nil {
		command.Env = isolatedProcessEnvironment(filepath.Join(l.root, "process-tmp", role))
	}
	if err := command.Start(); err != nil {
		return err
	}
	l.processes = append(l.processes, processRecord{
		Role: role, PID: command.Process.Pid, ParentPID: os.Getpid(), Command: redact(command.Args),
		WorkingDirectory: processWorkingDirectory(command), EnvironmentKeys: processEnvironmentKeys(command.Env),
		TemporaryDirectory: processTemporaryDirectory(command.Env), StartTime: time.Now().UTC().Format(time.RFC3339Nano),
	})
	l.running = append(l.running, command)
	return nil
}

func (l *lab) runToCompletion(role, binary string, arguments ...string) error {
	command := exec.Command(binary, arguments...)
	command.Env = isolatedProcessEnvironment(filepath.Join(l.root, "process-tmp", role))
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
		Role: role, ParentPID: os.Getpid(), Command: redact(command.Args),
		WorkingDirectory: processWorkingDirectory(command), EnvironmentKeys: processEnvironmentKeys(command.Env),
		TemporaryDirectory: processTemporaryDirectory(command.Env), StartTime: started.Format(time.RFC3339Nano),
		ExitTime: time.Now().UTC().Format(time.RFC3339Nano),
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

func processWorkingDirectory(command *exec.Cmd) string {
	if command.Dir != "" {
		return command.Dir
	}
	directory, _ := os.Getwd()
	return directory
}

func processEnvironmentKeys(environment []string) []string {
	keys := make([]string, 0, len(environment))
	for _, entry := range environment {
		if index := strings.IndexByte(entry, '='); index > 0 {
			keys = append(keys, entry[:index])
		}
	}
	sort.Strings(keys)
	return keys
}

func processTemporaryDirectory(environment []string) string {
	for _, entry := range environment {
		if strings.HasPrefix(entry, "TMPDIR=") {
			return strings.TrimPrefix(entry, "TMPDIR=")
		}
	}
	return ""
}

func isolatedProcessEnvironment(temporary string) []string {
	_ = os.MkdirAll(temporary, 0o700)
	_ = os.Chmod(temporary, 0o700)
	return []string{
		"PATH=" + os.Getenv("PATH"),
		"TMPDIR=" + temporary,
		"GOMAXPROCS=" + fmt.Sprintf("%d", runtime.GOMAXPROCS(0)),
	}
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
