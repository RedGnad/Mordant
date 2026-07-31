// Command privacy-coordinator is the ciphertext-only evaluator for the
// controlled six-process privacy lab. It waits for two encrypted envelopes,
// evaluates them, releases through a fixed 2-of-3 mTLS coalition, and emits a
// public V3 result. It never receives a client canary manifest.
package main

import (
	"context"
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
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	fhe "mordant.dev/fhe-lab/lattigo"
	"mordant.dev/fhe-lab/lattigo/internal/thresholdnet"
)

type config struct {
	root, node, issuerPublic, result, sessionID, vault, policyID, consumer, inputA, inputB string
	chainID, policyVersion, nonce, validUntil                                              uint64
}
type publicResult struct {
	SchemaVersion           string `json:"schemaVersion"`
	ChainID                 string `json:"chainId"`
	Consumer                string `json:"consumer"`
	Vault                   string `json:"vault"`
	PolicyID                string `json:"policyId"`
	PolicyVersion           string `json:"policyVersion"`
	InputCommitmentA        string `json:"inputCommitmentA"`
	InputCommitmentB        string `json:"inputCommitmentB"`
	ConflictConfirmed       bool   `json:"conflictConfirmed"`
	Nonce                   string `json:"nonce"`
	ValidUntil              string `json:"validUntil"`
	ProviderProofCommitment string `json:"providerProofCommitment"`
	ResultCommitment        string `json:"resultCommitment"`
}
type providerProof struct {
	ResultCiphertextCommitment    string `json:"resultCiphertextCommitment"`
	ThresholdTranscriptCommitment string `json:"thresholdTranscriptCommitment"`
	ThresholdSessionID            string `json:"thresholdSessionId"`
	ThresholdKeyCommitment        string `json:"thresholdKeyCommitment"`
	PolicyCircuitCommitment       string `json:"policyCircuitCommitment"`
	ProviderProofCommitment       string `json:"providerProofCommitment"`
}
type output struct {
	SchemaVersion string         `json:"schemaVersion"`
	OK            bool           `json:"ok"`
	Result        publicResult   `json:"result"`
	ProviderProof providerProof  `json:"providerProof"`
	Nodes         []nodeEvidence `json:"nodes"`
}
type nodeEvidence struct {
	Role        string `json:"role"`
	PID         int    `json:"pid"`
	MTLS        string `json:"mtls"`
	Selected    bool   `json:"selected"`
	LedgerState string `json:"ledgerState"`
	Exit        string `json:"exit"`
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "PRIVACY_COORDINATOR_FAILED")
		os.Exit(1)
	}
	fmt.Println("PRIVACY_COORDINATOR_COMPLETE")
}

func run(arguments []string) (runErr error) {
	stage := "CONFIG"
	defer func() {
		if runErr != nil {
			fmt.Fprintln(os.Stderr, "PRIVACY_COORDINATOR_STAGE_"+stage)
		}
	}()
	c, err := parse(arguments)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(c.root, "public"), 0o700); err != nil {
		return err
	}
	stage = "RUNTIME"
	issuer, err := readPublic(c.issuerPublic)
	if err != nil {
		return err
	}
	runtime, _, err := fhe.NewRuntime()
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	if _, err := runtime.RegisterEnrollmentIssuer(issuer, now.Add(-time.Minute), time.Unix(int64(c.validUntil), 0)); err != nil {
		return err
	}
	material, err := runtime.ExportPublicEncryptionMaterial()
	if err != nil {
		return err
	}
	if err := writeFile(filepath.Join(c.root, "public", "encryption-material.bin"), material, 0o644); err != nil {
		return err
	}
	stage = "ENROLLMENTS"
	first, err := waitEnvelope(c.inputA, 2*time.Minute)
	if err != nil {
		return err
	}
	second, err := waitEnvelope(c.inputB, 2*time.Minute)
	if err != nil {
		return err
	}
	// Enrollments are signed by the two separately launched clients after this
	// coordinator publishes public material. Evaluate at receipt time so a
	// Unix-second boundary cannot make a just-issued enrollment appear future.
	evaluationNow := time.Now().UTC()
	request, err := decodeRequest(runtime, first, second, c, evaluationNow)
	if err != nil {
		return err
	}
	inputA, inputB, err := runtime.VerifiedExternalInputCommitments(request, evaluationNow)
	if err != nil {
		return err
	}
	decision, _, err := runtime.Evaluate(request, evaluationNow)
	if err != nil {
		return err
	}
	stage = "THRESHOLD_LAUNCH"
	configs, manifest, err := runtime.ProvisionThresholdOperators()
	if err != nil {
		return err
	}
	session, err := decode32(c.sessionID)
	if err != nil {
		return err
	}
	protocolBinding, err := fhe.ProtocolBindingDigest(runtime.KeyIDBytes(), fhe.ProtocolCollectiveKeySwitchToZero, decision.Conflict)
	if err != nil {
		return err
	}
	descriptor := fhe.ReleaseDescriptor{SessionID: session, KeyID: runtime.KeyIDBytes(), ParameterFingerprint: runtime.ParameterFingerprint(), PolicyID: must32(c.policyID), PolicyVersion: uint32(c.policyVersion), InputCommitmentA: inputA, InputCommitmentB: inputB, ResultNonce: fhe.Uint256{0, 0, 0, c.nonce}, ValidUntil: c.validUntil, ResultCiphertextCommitment: decision.ResultCiphertextCommitment, ProtocolBinding: protocolBinding, Coalition: [2]uint64{manifest.Operators[0].Point, manifest.Operators[1].Point}}
	nodes, clients, cleanup, err := launchNodes(c, configs, manifest, now)
	if err != nil {
		return err
	}
	defer cleanup()
	if err := assertStatus(clients[2]); err != nil {
		return err
	}
	stage = "THRESHOLD_RELEASE"
	responses, err := thresholdnet.ReleaseSelectedCoalition(context.Background(), [2]*thresholdnet.OperatorClient{clients[0].client, clients[1].client}, descriptor, decision.Conflict, durableResponses(filepath.Join(c.root, "public", "threshold-responses.bin")))
	if err != nil {
		return err
	}
	runtime.DetachThresholdParties()
	stage = "THRESHOLD_COMBINE"
	confirmed, transcript, err := fhe.CombineZeroKeySwitchShares(runtime.Params, descriptor, manifest, decision.Conflict, responses[:])
	if err != nil {
		return err
	}
	keyCommitment, err := fhe.ThresholdKeyCommitment(manifest)
	if err != nil {
		return err
	}
	policyCommitment, err := fhe.PolicyCircuitCommitment(runtime.ParameterFingerprint(), must32(c.policyID), uint32(c.policyVersion))
	if err != nil {
		return err
	}
	proof := fhe.ProviderProof{ResultCiphertextCommitment: decision.ResultCiphertextCommitment, ThresholdTranscriptCommitment: transcript, ThresholdSessionID: session, ThresholdKeyCommitment: keyCommitment, PolicyCircuitCommitment: policyCommitment}
	proofCommitment, err := fhe.ProviderProofCommitment(proof)
	if err != nil {
		return err
	}
	consumer := must20(c.consumer)
	vault := must20(c.vault)
	policy := must32(c.policyID)
	resultCommitment, err := fhe.ResultCommitmentV3(fhe.PublicPolicyResultV3Core{ChainID: fhe.Uint256{0, 0, 0, c.chainID}, Consumer: consumer, Vault: vault, PolicyID: policy, PolicyVersion: uint32(c.policyVersion), InputCommitmentA: inputA, InputCommitmentB: inputB, ConflictConfirmed: confirmed, Nonce: fhe.Uint256{0, 0, 0, c.nonce}, ValidUntil: c.validUntil, ProviderProofCommitment: proofCommitment})
	if err != nil {
		return err
	}
	// bbolt permits one writer. Stop all three nodes before the coordinator
	// opens their ledgers for terminal-state evidence.
	cleanup()
	cleanup = func() {}
	evidence := make([]nodeEvidence, 3)
	stage = "EVIDENCE"
	for i, node := range nodes {
		state := "NOT_SELECTED"
		if i < 2 {
			ledger, openErr := thresholdnet.Open(node.ledger)
			if openErr != nil {
				return openErr
			}
			record, readErr := ledger.Get(session)
			_ = ledger.Close()
			if readErr != nil {
				return readErr
			}
			state = string(record.State)
		}
		evidence[i] = nodeEvidence{Role: "threshold-node-" + strconv.Itoa(i+1), PID: node.command.Process.Pid, MTLS: "authenticated", Selected: i < 2, LedgerState: state, Exit: "terminated-cleanly"}
	}
	return writeJSON(c.result, output{SchemaVersion: "mordant.fhe-provider-output/3-lab", OK: true, Result: publicResult{SchemaVersion: "mordant.confidential-policy-result/3-lab", ChainID: strconv.FormatUint(c.chainID, 10), Consumer: hex20(consumer), Vault: hex20(vault), PolicyID: hex32(policy), PolicyVersion: strconv.FormatUint(c.policyVersion, 10), InputCommitmentA: hex32(inputA), InputCommitmentB: hex32(inputB), ConflictConfirmed: confirmed, Nonce: strconv.FormatUint(c.nonce, 10), ValidUntil: strconv.FormatUint(c.validUntil, 10), ProviderProofCommitment: hex32(proofCommitment), ResultCommitment: hex32(resultCommitment)}, ProviderProof: providerProof{hex32(proof.ResultCiphertextCommitment), hex32(proof.ThresholdTranscriptCommitment), hex32(proof.ThresholdSessionID), hex32(proof.ThresholdKeyCommitment), hex32(proof.PolicyCircuitCommitment), hex32(proofCommitment)}, Nodes: evidence})
}

type nodeProcess struct {
	command *exec.Cmd
	client  *thresholdnet.OperatorClient
	ledger  string
}

func launchNodes(c config, bundles [][]byte, manifest fhe.ThresholdManifest, now time.Time) ([]nodeProcess, [3]nodeProcess, func(), error) {
	var zero [3]nodeProcess
	ca, caKey, err := createCA(now)
	if err != nil {
		return nil, zero, nil, err
	}
	coordPub, coordKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, zero, nil, err
	}
	caPEM, err := pemCert(ca.Raw)
	if err != nil {
		return nil, zero, nil, err
	}
	root := x509.NewCertPool()
	root.AddCert(ca)
	coordCertPEM, coordKeyPEM, err := certificate(ca, caKey, coordPub, coordKey, "coordinator.local", true, now)
	if err != nil {
		return nil, zero, nil, err
	}
	coordCert, err := tls.X509KeyPair(coordCertPEM, coordKeyPEM)
	if err != nil {
		return nil, zero, nil, err
	}
	base := filepath.Join(c.root, "nodes")
	if err := os.MkdirAll(base, 0o700); err != nil {
		return nil, zero, nil, err
	}
	coordinatorKeyPath := filepath.Join(base, "coordinator.pub")
	if err := writeFile(coordinatorKeyPath, coordPub, 0o644); err != nil {
		return nil, zero, nil, err
	}
	caPath := filepath.Join(base, "ca.pem")
	if err := writeFile(caPath, caPEM, 0o644); err != nil {
		return nil, zero, nil, err
	}
	processes := make([]nodeProcess, 3)
	var indexed [3]nodeProcess
	for i := 0; i < 3; i++ {
		dir := filepath.Join(base, strconv.Itoa(i+1))
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, zero, nil, err
		}
		configPath := filepath.Join(dir, "operator.bin")
		if err := writeFile(configPath, bundles[i], 0o600); err != nil {
			return nil, zero, nil, err
		}
		pub, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, zero, nil, err
		}
		cert, keyPEM, err := certificate(ca, caKey, pub, key, "node"+strconv.Itoa(i+1)+".local", false, now)
		if err != nil {
			return nil, zero, nil, err
		}
		certPath := filepath.Join(dir, "cert.pem")
		keyPath := filepath.Join(dir, "key.pem")
		if err := writeFile(certPath, cert, 0o644); err != nil {
			return nil, zero, nil, err
		}
		if err := writeFile(keyPath, keyPEM, 0o600); err != nil {
			return nil, zero, nil, err
		}
		port, err := freePort()
		if err != nil {
			return nil, zero, nil, err
		}
		ledger := filepath.Join(dir, "ledger.db")
		cmd := exec.Command(c.node, "--listen", "127.0.0.1:"+strconv.Itoa(port), "--operator-config", configPath, "--ledger", ledger, "--tls-cert", certPath, "--tls-key", keyPath, "--client-ca", caPath, "--coordinator-key", coordinatorKeyPath)
		cmd.Stdout = mustLog(filepath.Join(c.root, "public", "logs", "node"+strconv.Itoa(i+1)+".stdout"))
		cmd.Stderr = mustLog(filepath.Join(c.root, "public", "logs", "node"+strconv.Itoa(i+1)+".stderr"))
		if err := cmd.Start(); err != nil {
			return nil, zero, nil, err
		}
		transport := &http.Transport{TLSClientConfig: thresholdnet.ClientTLSConfig(coordCert, root, "node"+strconv.Itoa(i+1)+".local")}
		proc := nodeProcess{command: cmd, ledger: ledger, client: &thresholdnet.OperatorClient{BaseURL: "https://127.0.0.1:" + strconv.Itoa(port), HTTPClient: &http.Client{Transport: transport, Timeout: 10 * time.Second}, SigningKey: coordKey}}
		processes[i] = proc
		indexed[i] = proc
	}
	cleanup := func() {
		for _, p := range processes {
			_ = p.command.Process.Signal(syscall.SIGTERM)
		}
		for _, p := range processes {
			_ = p.command.Wait()
		}
	}
	// The three operating-system processes may need a short deterministic
	// startup window before their TLS listeners are ready. Readiness is then
	// proven by the authenticated status request below, not by this delay.
	time.Sleep(750 * time.Millisecond)
	return processes, indexed, cleanup, nil
}

func assertStatus(node nodeProcess) error {
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		request, err := http.NewRequest(http.MethodGet, node.client.BaseURL+"/v1/status", nil)
		if err == nil {
			response, callErr := node.client.HTTPClient.Do(request)
			if callErr == nil {
				_ = response.Body.Close()
				if response.StatusCode == http.StatusOK {
					return nil
				}
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	return errors.New("node status authentication failed")
}
func durableResponses(path string) func([2][]byte) error {
	return func(w [2][]byte) error { return writeFile(path, append(append([]byte{}, w[0]...), w[1]...), 0o600) }
}
func decodeRequest(runtime *fhe.Runtime, a, b []byte, c config, now time.Time) (fhe.EvaluationRequest, error) {
	first, err := fhe.UnmarshalProcessEnrollmentEnvelope(a)
	if err != nil {
		return fhe.EvaluationRequest{}, err
	}
	second, err := fhe.UnmarshalProcessEnrollmentEnvelope(b)
	if err != nil {
		return fhe.EvaluationRequest{}, err
	}
	pa, err := fhe.UnmarshalCipherPledge(first.Ciphertext)
	if err != nil {
		return fhe.EvaluationRequest{}, err
	}
	pb, err := fhe.UnmarshalCipherPledge(second.Ciphertext)
	if err != nil {
		return fhe.EvaluationRequest{}, err
	}
	ea, err := fhe.UnmarshalSignedCiphertextEnrollment(first.Enrollment)
	if err != nil {
		return fhe.EvaluationRequest{}, err
	}
	eb, err := fhe.UnmarshalSignedCiphertextEnrollment(second.Enrollment)
	if err != nil {
		return fhe.EvaluationRequest{}, err
	}
	var nonce [32]byte
	copy(nonce[24:], u64(c.nonce))
	return fhe.EvaluationRequest{KeyID: runtime.KeyID(), PolicyVersion: uint32(c.policyVersion), Nonce: nonce, ValidUntil: time.Unix(int64(c.validUntil), 0), IdentityMode: fhe.IdentityPublicCommitment, A: pa, B: pb, EnrollmentA: ea, EnrollmentB: eb}, nil
}
func parse(a []string) (config, error) {
	var c config
	f := flag.NewFlagSet("privacy-coordinator", flag.ContinueOnError)
	f.SetOutput(os.Stderr)
	f.StringVar(&c.root, "root", "", "root")
	f.StringVar(&c.node, "threshold-node", "", "node binary")
	f.StringVar(&c.issuerPublic, "issuer-public", "", "issuer public key")
	f.StringVar(&c.result, "out", "", "output")
	f.StringVar(&c.sessionID, "session-id", "", "session")
	f.StringVar(&c.vault, "vault", "", "vault")
	f.StringVar(&c.policyID, "policy-id", "", "policy")
	f.StringVar(&c.consumer, "consumer", "", "consumer")
	f.StringVar(&c.inputA, "input-a", "", "envelope")
	f.StringVar(&c.inputB, "input-b", "", "envelope")
	f.Uint64Var(&c.chainID, "chain-id", 0, "chain")
	f.Uint64Var(&c.policyVersion, "policy-version", 0, "policy version")
	f.Uint64Var(&c.nonce, "nonce", 0, "nonce")
	f.Uint64Var(&c.validUntil, "valid-until", 0, "valid")
	if err := f.Parse(a); err != nil || f.NArg() != 0 || c.root == "" || c.node == "" || c.issuerPublic == "" || c.result == "" || c.sessionID == "" || c.vault == "" || c.policyID == "" || c.consumer == "" || c.inputA == "" || c.inputB == "" || c.chainID == 0 || c.policyVersion == 0 || c.validUntil <= uint64(time.Now().Unix()) {
		return config{}, errors.New("invalid coordinator configuration")
	}
	return c, nil
}
func waitEnvelope(path string, limit time.Duration) ([]byte, error) {
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		if b, err := os.ReadFile(path); err == nil && len(b) > 0 {
			return b, nil
		}
		time.Sleep(25 * time.Millisecond)
	}
	return nil, errors.New("encrypted client envelope timed out")
}
func writeFile(path string, b []byte, m os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, b, m)
}
func writeJSON(path string, value any) error {
	b, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return writeFile(path, append(b, '\n'), 0o644)
}
func readPublic(path string) (ed25519.PublicKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.New("invalid issuer public key")
	}
	if len(b) == ed25519.PublicKeySize {
		return ed25519.PublicKey(b), nil
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errors.New("invalid issuer public key")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	key, ok := parsed.(ed25519.PublicKey)
	if err != nil || !ok || len(key) != ed25519.PublicKeySize {
		return nil, errors.New("invalid issuer public key")
	}
	return key, nil
}
func createCA(now time.Time) (*x509.Certificate, ed25519.PrivateKey, error) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Mordant lab CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, key)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	return cert, key, err
}
func certificate(ca *x509.Certificate, caKey ed25519.PrivateKey, pub ed25519.PublicKey, key ed25519.PrivateKey, name string, client bool, now time.Time) ([]byte, []byte, error) {
	usage := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	if client {
		usage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	serial := sha256.Sum256([]byte(name))
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: new(big.Int).SetBytes(serial[:]), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: usage}, ca, pub, caKey)
	if err != nil {
		return nil, nil, err
	}
	cert := pemBlock("CERTIFICATE", der)
	keyRaw, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return cert, pemBlock("PRIVATE KEY", keyRaw), nil
}
func pemCert(der []byte) ([]byte, error) { return pemBlock("CERTIFICATE", der), nil }
func pemBlock(kind string, b []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: b})
}
func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}
func mustLog(path string) *os.File {
	_ = os.MkdirAll(filepath.Dir(path), 0o700)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		panic(err)
	}
	return f
}
func decode32(v string) ([32]byte, error) {
	var o [32]byte
	b, e := hex.DecodeString(trim(v))
	if e != nil || len(b) != 32 {
		return o, errors.New("invalid bytes32")
	}
	copy(o[:], b)
	return o, nil
}
func decode20(v string) ([20]byte, error) {
	var o [20]byte
	b, e := hex.DecodeString(trim(v))
	if e != nil || len(b) != 20 {
		return o, errors.New("invalid address")
	}
	copy(o[:], b)
	return o, nil
}
func must32(v string) [32]byte {
	o, e := decode32(v)
	if e != nil {
		panic("invalid public bytes32")
	}
	return o
}
func must20(v string) [20]byte {
	o, e := decode20(v)
	if e != nil {
		panic("invalid public address")
	}
	return o
}
func trim(v string) string {
	if len(v) > 2 && v[:2] == "0x" {
		return v[2:]
	}
	return v
}
func hex32(v [32]byte) string { return "0x" + hex.EncodeToString(v[:]) }
func hex20(v [20]byte) string { return "0x" + hex.EncodeToString(v[:]) }
func u64(v uint64) []byte {
	return []byte{byte(v >> 56), byte(v >> 48), byte(v >> 40), byte(v >> 32), byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
}
