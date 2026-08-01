package thresholdnet

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	spike "mordant.dev/fhe-lab/lattigo"
)

func TestMTLSSelectedCoalitionDurablyReleasesOnce(t *testing.T) {
	runtime, _, err := spike.NewRuntime()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	decision, descriptor, manifest, configs := thresholdFixture(t, runtime, now)

	ca, caKey := testCA(t, now)
	coordinatorPublic, coordinatorKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	coordinatorCertificate := testCertificate(t, ca, caKey, coordinatorPublic, coordinatorKey, "coordinator.test", true, now)
	serverRoots := x509.NewCertPool()
	serverRoots.AddCert(ca)
	clientRoots := x509.NewCertPool()
	clientRoots.AddCert(ca)

	var ledgers [3]*Store
	var servers [2]*httptest.Server
	var clients [2]*OperatorClient
	for index := range ledgers {
		ledgers[index], err = Open(filepath.Join(t.TempDir(), "ledger.db"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = ledgers[index].Close() })
		if index == 2 {
			continue
		}
		operator, err := spike.NewThresholdOperator(configs[index])
		if err != nil {
			t.Fatal(err)
		}
		serverPublic, serverKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		serverCertificate := testCertificate(t, ca, caKey, serverPublic, serverKey, "threshold.test", false, now)
		service := &OperatorServer{
			Operator:             operator,
			Ledger:               ledgers[index],
			CoordinatorPublicKey: coordinatorPublic,
			Now:                  func() time.Time { return now },
		}
		server := httptest.NewUnstartedServer(service.Handler())
		server.TLS = ServerTLSConfig(serverCertificate, clientRoots)
		server.StartTLS()
		servers[index] = server
		t.Cleanup(server.Close)
		clients[index] = &OperatorClient{
			BaseURL: server.URL,
			HTTPClient: &http.Client{Transport: &http.Transport{TLSClientConfig: ClientTLSConfig(
				coordinatorCertificate, serverRoots, "threshold.test",
			)}},
			SigningKey: coordinatorKey,
		}
	}

	journalPath := filepath.Join(t.TempDir(), "coordinator-responses.bin")
	persisted := false
	responses, err := ReleaseSelectedCoalition(
		context.Background(),
		clients,
		descriptor,
		decision.Conflict,
		func(wires [2][]byte) error {
			file, err := os.OpenFile(journalPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
			if err != nil {
				return err
			}
			defer file.Close()
			for _, wire := range wires {
				if err := binary.Write(file, binary.BigEndian, uint32(len(wire))); err != nil {
					return err
				}
				if _, err := file.Write(wire); err != nil {
					return err
				}
			}
			if err := file.Sync(); err != nil {
				return err
			}
			persisted = true
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !persisted {
		t.Fatal("coordinator acknowledged before durable response persistence")
	}
	for index := 0; index < 2; index++ {
		record, err := ledgers[index].Get(descriptor.SessionID)
		if err != nil || record.State != StateAcked || record.ResponseDigest == ([32]byte{}) {
			t.Fatalf("operator %d did not reach ACKED: %+v %v", index, record, err)
		}
	}
	if _, err := ledgers[2].Get(descriptor.SessionID); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("unselected third operator was contacted: %v", err)
	}
	confirmed, transcript, err := spike.CombineZeroKeySwitchShares(runtime.Params, descriptor, manifest, decision.Conflict, responses[:])
	if err != nil || !confirmed || transcript == ([32]byte{}) {
		t.Fatalf("network responses did not reconstruct the decision: confirmed=%t transcript=%x err=%v", confirmed, transcript, err)
	}

	// A new session and reordered coalition cannot bypass the global c1 binding.
	replay := descriptor
	replay.SessionID = sha256.Sum256([]byte("threshold-network-replay"))
	replay.Coalition = [2]uint64{descriptor.Coalition[1], descriptor.Coalition[0]}
	if err := clients[0].Prepare(context.Background(), replay, decision.Conflict); !errors.Is(err, ErrProtocolState) {
		t.Fatalf("consumed c1 binding was accepted: %v", err)
	}

	// A CA-valid client certificate with a different signing identity is denied
	// before descriptor or ledger processing.
	wrongPublic, wrongKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrongCertificate := testCertificate(t, ca, caKey, wrongPublic, wrongKey, "wrong-coordinator.test", true, now)
	wrongClient := &OperatorClient{
		BaseURL: servers[0].URL,
		HTTPClient: &http.Client{Transport: &http.Transport{TLSClientConfig: ClientTLSConfig(
			wrongCertificate, serverRoots, "threshold.test",
		)}},
		SigningKey: wrongKey,
	}
	if err := wrongClient.Prepare(context.Background(), replay, decision.Conflict); !errors.Is(err, ErrProtocolState) {
		t.Fatalf("wrong coordinator identity was accepted: %v", err)
	}
}

func TestSignedRequestBindsOperationAndPayload(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	request := signedRequest{
		Operation:  operationPrepare,
		Descriptor: []byte("descriptor"),
		Ciphertext: []byte("ciphertext"),
		Nonce:      sha256.Sum256([]byte("nonce")),
	}
	digest := signedRequestDigest(request)
	copy(request.Signature[:], ed25519.Sign(privateKey, digest[:]))
	if !verifySignedRequest(request, publicKey) {
		t.Fatal("valid request signature rejected")
	}
	request.Operation = operationCommit
	if verifySignedRequest(request, publicKey) {
		t.Fatal("operation substitution retained a valid signature")
	}
	request.Operation = operationPrepare
	request.Ciphertext[0] ^= 1
	if verifySignedRequest(request, publicKey) {
		t.Fatal("ciphertext substitution retained a valid signature")
	}
}

func thresholdFixture(t *testing.T, runtime *spike.Runtime, now time.Time) (*spike.EncryptedDecision, spike.ReleaseDescriptor, spike.ThresholdManifest, [][]byte) {
	t.Helper()
	receivable := sha256.Sum256([]byte("network-receivable"))
	a := spike.PlainPledge{
		ActiveFrom: 100, ActiveUntil: 400, Amount: spike.Uint256{0, 0, 0, 1_000},
		Currency: sha256.Sum256([]byte("USD")), ObligationID: sha256.Sum256([]byte("network-a")),
		ReceivableID: sha256.Sum256([]byte("private-network-receivable")), Exclusive: true,
		ReceivableCommitment: receivable, AuthorizationCommitment: sha256.Sum256([]byte("network-auth-a")),
		PrivateMetadataCommitment: sha256.Sum256([]byte("network-private-a")),
	}
	b := spike.PlainPledge{
		ActiveFrom: 200, ActiveUntil: 500, Amount: spike.Uint256{0, 0, 0, 900},
		Currency: sha256.Sum256([]byte("USD")), ObligationID: sha256.Sum256([]byte("network-b")),
		ReceivableID: sha256.Sum256([]byte("private-network-receivable")), Exclusive: true,
		ReceivableCommitment: receivable, AuthorizationCommitment: sha256.Sum256([]byte("network-auth-b")),
		PrivateMetadataCommitment: sha256.Sum256([]byte("network-private-b")),
	}
	for _, commitment := range [][32]byte{a.AuthorizationCommitment, b.AuthorizationCommitment} {
		if err := runtime.GrantIngress(commitment, spike.PolicyVersion, now.Add(2*time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	encA, _, err := runtime.EncryptPledge(a)
	if err != nil {
		t.Fatal(err)
	}
	encB, _, err := runtime.EncryptPledge(b)
	if err != nil {
		t.Fatal(err)
	}
	request := spike.EvaluationRequest{
		KeyID: runtime.KeyID(), PolicyVersion: spike.PolicyVersion,
		Nonce: sha256.Sum256([]byte("network-evaluation")), ValidUntil: now.Add(time.Hour),
		IdentityMode: spike.IdentityPublicCommitment, A: encA, B: encB,
	}
	decision, _, err := runtime.Evaluate(request, now)
	if err != nil {
		t.Fatal(err)
	}
	configs, manifest, err := runtime.ProvisionThresholdOperators()
	if err != nil {
		t.Fatal(err)
	}
	vault := [20]byte{}
	copy(vault[:], bytes.Repeat([]byte{0x11}, len(vault)))
	policyID := sha256.Sum256([]byte("network-policy"))
	contextA := spike.InputCommitmentContext{
		ChainID: spike.Uint256{0, 0, 0, 31_337}, Vault: vault, PolicyID: policyID,
		PolicyVersion: spike.PolicyVersion, InputSlot: 0, ClientNonce: spike.Uint256{0, 0, 0, 41},
	}
	contextB := contextA
	contextB.InputSlot, contextB.ClientNonce = 1, spike.Uint256{0, 0, 0, 42}
	inputA, err := runtime.CanonicalInputCommitment(encA, contextA)
	if err != nil {
		t.Fatal(err)
	}
	inputB, err := runtime.CanonicalInputCommitment(encB, contextB)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := spike.ProtocolBindingDigest(runtime.KeyIDBytes(), spike.ProtocolCollectiveKeySwitchToZero, decision.Conflict)
	if err != nil {
		t.Fatal(err)
	}
	descriptor := spike.ReleaseDescriptor{
		SessionID: sha256.Sum256([]byte("threshold-network-session")), KeyID: runtime.KeyIDBytes(),
		ParameterFingerprint: runtime.ParameterFingerprint(), PolicyID: policyID, PolicyVersion: spike.PolicyVersion,
		InputCommitmentA: inputA, InputCommitmentB: inputB, ResultNonce: spike.Uint256{0, 0, 0, 77},
		ValidUntil: uint64(now.Add(time.Hour).Unix()), ResultCiphertextCommitment: decision.ResultCiphertextCommitment,
		ProtocolBinding: binding, Coalition: [2]uint64{manifest.Operators[0].Point, manifest.Operators[1].Point},
	}
	return decision, descriptor, manifest, configs
}

func testCA(t *testing.T, now time.Time) (*x509.Certificate, ed25519.PrivateKey) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Mordant threshold test CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certificate, privateKey
}

func testCertificate(t *testing.T, ca *x509.Certificate, caKey ed25519.PrivateKey, publicKey ed25519.PublicKey, privateKey ed25519.PrivateKey, name string, client bool, now time.Time) tls.Certificate {
	t.Helper()
	serialDigest := sha256.Sum256([]byte(name))
	serial := new(big.Int).SetBytes(serialDigest[:])
	usage := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	if client {
		usage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(12 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: usage,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, publicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der, ca.Raw}, PrivateKey: privateKey, Leaf: leaf}
}
