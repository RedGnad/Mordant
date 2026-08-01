// Command ceremony-evaluator is the V4 evaluator.
//
// It loads only public artifacts written by the ceremony: the collective public
// material and the collective evaluation keys. It has no flag, no file format
// and no code path that accepts an RLWE secret key, a Shamir secret share or an
// operator bundle. It evaluates the policy homomorphically and then asks a
// selected 2-of-3 coalition of separate operator processes to release the
// Boolean; it cannot produce that Boolean on its own.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
	fhe "mordant.dev/fhe-lab/lattigo"
	"mordant.dev/fhe-lab/lattigo/internal/thresholdnet"
)

type config struct {
	publicMaterial, evaluationKeys, manifest, issuerPublic string
	inputA, inputB, out, storage, certificate, peerCA      string
	operators, coalition, sessionID, vault, policyID       string
	identityMode                                           string
	chainID, policyVersion, nonce, validUntil              uint64
}

type evaluatorOutput struct {
	SchemaVersion           string   `json:"schemaVersion"`
	OK                      bool     `json:"ok"`
	CustodyModel            string   `json:"custodyModel"`
	KeyID                   string   `json:"keyId"`
	ConflictConfirmed       bool     `json:"conflictConfirmed"`
	IdentityMode            string   `json:"identityMode"`
	EnrollmentNonceA        string   `json:"enrollmentNonceA"`
	EnrollmentNonceB        string   `json:"enrollmentNonceB"`
	InputCommitmentA        string   `json:"inputCommitmentA"`
	InputCommitmentB        string   `json:"inputCommitmentB"`
	ResultCommitment        string   `json:"resultCommitment"`
	ProviderProofCommitment string   `json:"providerProofCommitment"`
	ThresholdTranscript     string   `json:"thresholdTranscriptCommitment"`
	Coalition               []uint64 `json:"coalition"`
	EvaluatorCapabilities   struct {
		HoldsThresholdParties     bool     `json:"holdsThresholdParties"`
		LocalDecryptAttempt       string   `json:"localDecryptAttempt"`
		ProvisionOperatorsAttempt string   `json:"provisionOperatorsAttempt"`
		ReleaseShareAttempt       string   `json:"releaseShareAttempt"`
		LoadedArtifacts           []string `json:"loadedArtifacts"`
	} `json:"evaluatorCapabilities"`
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "CEREMONY_EVALUATOR_FAILED:"+err.Error())
		os.Exit(1)
	}
	fmt.Println("CEREMONY_EVALUATOR_COMPLETE")
}

func run(arguments []string) error {
	c, err := parse(arguments)
	if err != nil {
		return err
	}
	params, err := evaluatorParameters()
	if err != nil {
		return err
	}

	// Public artifacts only. These are the sole key inputs this process reads.
	materialBytes, err := os.ReadFile(c.publicMaterial)
	if err != nil {
		return errors.New("collective public material unavailable")
	}
	evaluationKeyBytes, err := os.ReadFile(c.evaluationKeys)
	if err != nil {
		return errors.New("collective evaluation keys unavailable")
	}
	relinKey, galoisKeys, _, err := fhe.UnmarshalEvaluationKeys(params, evaluationKeyBytes)
	if err != nil {
		return err
	}
	client, err := fhe.NewExternalClient(materialBytes)
	if err != nil {
		return err
	}
	if client.CustodyModel() != fhe.CustodyDealerlessCeremony {
		return fmt.Errorf("refusing custody model %q", client.CustodyModel())
	}
	publicKeyBytes, err := client.CollectivePublicKeyBytes()
	if err != nil {
		return err
	}
	publicKey := rlwe.NewPublicKey(params)
	if err := publicKey.UnmarshalBinary(publicKeyBytes); err != nil {
		return err
	}
	runtime, err := fhe.NewEvaluationRuntime(params, publicKey, relinKey, galoisKeys)
	if err != nil {
		return err
	}

	issuer, err := readPublicKey(c.issuerPublic)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	if _, err := runtime.RegisterEnrollmentIssuer(issuer, now.Add(-time.Minute), time.Unix(int64(c.validUntil), 0)); err != nil {
		return err
	}

	first, err := waitEnvelope(c.inputA, 3*time.Minute)
	if err != nil {
		return err
	}
	second, err := waitEnvelope(c.inputB, 3*time.Minute)
	if err != nil {
		return err
	}
	evaluationNow := time.Now().UTC()
	request, err := decodeRequest(runtime, first, second, c)
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

	// Recorded negative capability checks, performed in this process against the
	// live result ciphertext before it is released.
	var output evaluatorOutput
	output.EvaluatorCapabilities.HoldsThresholdParties = runtime.HoldsThresholdParties()
	_, _, decryptErr := runtime.DecryptThresholdWithCoalition(decision, 0, 1)
	output.EvaluatorCapabilities.LocalDecryptAttempt = describeError(decryptErr)
	_, _, provisionErr := runtime.ProvisionThresholdOperators()
	output.EvaluatorCapabilities.ProvisionOperatorsAttempt = describeError(provisionErr)
	// The evaluator holds only public artifacts, so it cannot instantiate an
	// operator from any of them and therefore cannot mint a release share.
	_, operatorErr := fhe.NewThresholdOperator(materialBytes)
	if operatorErr == nil {
		return errors.New("evaluator built a threshold operator from public material")
	}
	_, evaluationOperatorErr := fhe.NewThresholdOperator(evaluationKeyBytes)
	if evaluationOperatorErr == nil {
		return errors.New("evaluator built a threshold operator from evaluation keys")
	}
	output.EvaluatorCapabilities.ReleaseShareAttempt = describeError(operatorErr)
	output.EvaluatorCapabilities.LoadedArtifacts = []string{
		filepath.Base(c.publicMaterial), filepath.Base(c.evaluationKeys), filepath.Base(c.manifest),
	}
	if output.EvaluatorCapabilities.HoldsThresholdParties {
		return errors.New("evaluator holds threshold parties")
	}
	if decryptErr == nil || provisionErr == nil {
		return errors.New("evaluator retained a decryption capability")
	}

	// Network release against the selected 2-of-3 coalition.
	coalition, err := parsePoints(c.coalition)
	if err != nil || len(coalition) != 2 {
		return errors.New("invalid coalition")
	}
	endpoints, err := parseOperators(c.operators)
	if err != nil {
		return err
	}
	clients, certificate, roots, err := releaseClients(c, endpoints)
	if err != nil {
		return err
	}
	_ = certificate
	_ = roots

	session, err := decode32(c.sessionID)
	if err != nil {
		return err
	}
	policy, err := decode32(c.policyID)
	if err != nil {
		return err
	}
	keyID := runtime.KeyIDBytes()
	binding, err := fhe.ProtocolBindingDigest(keyID, fhe.ProtocolCollectiveKeySwitchToZero, decision.Conflict)
	if err != nil {
		return err
	}
	descriptor := fhe.ReleaseDescriptor{
		SessionID: session, KeyID: keyID,
		ParameterFingerprint:       runtime.ParameterFingerprint(),
		PolicyID:                   policy,
		PolicyVersion:              uint32(c.policyVersion),
		InputCommitmentA:           inputA,
		InputCommitmentB:           inputB,
		ResultNonce:                fhe.Uint256{0, 0, 0, c.nonce},
		ValidUntil:                 c.validUntil,
		ResultCiphertextCommitment: decision.ResultCiphertextCommitment,
		ProtocolBinding:            binding,
		Coalition:                  [2]uint64{coalition[0], coalition[1]},
	}
	manifest, err := operatorManifest(c.manifest, keyID, runtime.ParameterFingerprint())
	if err != nil {
		return err
	}
	responses, err := thresholdnet.ReleaseSelectedCoalition(
		context.Background(),
		[2]*thresholdnet.OperatorClient{clients[coalition[0]], clients[coalition[1]]},
		descriptor, decision.Conflict,
		func(wires [2][]byte) error {
			return os.WriteFile(filepath.Join(c.storage, "threshold-responses.bin"),
				append(append([]byte{}, wires[0]...), wires[1]...), 0o600)
		},
	)
	if err != nil {
		return err
	}
	confirmed, transcript, err := fhe.CombineZeroKeySwitchShares(params, descriptor, manifest, decision.Conflict, responses[:])
	if err != nil {
		return err
	}

	keyCommitment, err := fhe.ThresholdKeyCommitment(manifest)
	if err != nil {
		return err
	}
	policyCommitment, err := fhe.PolicyCircuitCommitment(runtime.ParameterFingerprint(), policy, uint32(c.policyVersion))
	if err != nil {
		return err
	}
	proof := fhe.ProviderProof{
		ResultCiphertextCommitment:    decision.ResultCiphertextCommitment,
		ThresholdTranscriptCommitment: transcript,
		ThresholdSessionID:            session,
		ThresholdKeyCommitment:        keyCommitment,
		PolicyCircuitCommitment:       policyCommitment,
	}
	proofCommitment, err := fhe.ProviderProofCommitment(proof)
	if err != nil {
		return err
	}

	output.SchemaVersion = "mordant.dealerless-evaluator-output/4"
	output.OK = true
	output.CustodyModel = string(fhe.CustodyDealerlessCeremony)
	output.KeyID = hex.EncodeToString(keyID[:])
	output.ConflictConfirmed = confirmed
	// Recorded so the evidence proves which identity mode produced the bit. In
	// full_fhe_256 the released bit is the conjunction overlap AND flags AND
	// currency AND encrypted-identity-equality, so a true bit proves strict
	// identity equality without ever releasing it separately.
	output.IdentityMode = c.identityMode
	// Reported by the evaluator, not by either client: the runner uses these to
	// prove both sides enrolled against the same opaque session commitment and
	// the same frozen governance records. The nonce is inside the issuer-signed
	// enrollment, so it cannot be edited after the fact.
	output.EnrollmentNonceA = "0x" + hex.EncodeToString(request.EnrollmentA.Enrollment.Nonce[:])
	output.EnrollmentNonceB = "0x" + hex.EncodeToString(request.EnrollmentB.Enrollment.Nonce[:])
	output.InputCommitmentA = "0x" + hex.EncodeToString(inputA[:])
	output.InputCommitmentB = "0x" + hex.EncodeToString(inputB[:])
	output.ResultCommitment = "0x" + hex.EncodeToString(decision.ResultCiphertextCommitment[:])
	output.ProviderProofCommitment = "0x" + hex.EncodeToString(proofCommitment[:])
	output.ThresholdTranscript = "0x" + hex.EncodeToString(transcript[:])
	output.Coalition = coalition
	encoded, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(c.out, append(encoded, '\n'), 0o644)
}

func describeError(err error) string {
	if err == nil {
		return "SUCCEEDED (capability present)"
	}
	return "REFUSED: " + err.Error()
}

// operatorManifest rebuilds the public threshold manifest from the signed key
// manifest. It carries operator identities and points only.
func operatorManifest(path string, keyID, fingerprint [32]byte) (fhe.ThresholdManifest, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fhe.ThresholdManifest{}, err
	}
	manifest, err := fhe.UnmarshalCollectiveKeyManifest(raw)
	if err != nil {
		return fhe.ThresholdManifest{}, err
	}
	operators := make([]fhe.ThresholdOperatorPublic, len(manifest.Operators))
	for index, encoded := range manifest.Operators {
		key, err := hex.DecodeString(encoded)
		if err != nil || len(key) != ed25519.PublicKeySize {
			return fhe.ThresholdManifest{}, errors.New("invalid manifest operator")
		}
		operators[index] = fhe.ThresholdOperatorPublic{
			OperatorID: sha256.Sum256(key),
			Point:      manifest.OperatorPoints[index],
		}
		copy(operators[index].SigningPublicKey[:], key)
	}
	return fhe.ThresholdManifest{
		KeyID:                keyID,
		ParameterFingerprint: fingerprint,
		Threshold:            manifest.Threshold,
		Operators:            operators,
	}, nil
}

func releaseClients(c config, endpoints map[uint64]string) (map[uint64]*thresholdnet.OperatorClient, tls.Certificate, *x509.CertPool, error) {
	signingKey, err := os.ReadFile(filepath.Join(c.storage, "identity.key"))
	if err != nil || len(signingKey) != ed25519.PrivateKeySize {
		return nil, tls.Certificate{}, nil, errors.New("invalid evaluator identity")
	}
	certificatePEM, err := os.ReadFile(c.certificate)
	if err != nil {
		return nil, tls.Certificate{}, nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(ed25519.PrivateKey(signingKey))
	if err != nil {
		return nil, tls.Certificate{}, nil, err
	}
	certificate, err := tls.X509KeyPair(certificatePEM, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	if err != nil {
		return nil, tls.Certificate{}, nil, err
	}
	caBytes, err := os.ReadFile(c.peerCA)
	if err != nil {
		return nil, tls.Certificate{}, nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caBytes) {
		return nil, tls.Certificate{}, nil, errors.New("invalid CA")
	}
	clients := make(map[uint64]*thresholdnet.OperatorClient, len(endpoints))
	for point, url := range endpoints {
		transport := &http.Transport{
			TLSClientConfig: thresholdnet.ClientTLSConfig(certificate, roots, fmt.Sprintf("node%d.local", point)),
		}
		clients[point] = &thresholdnet.OperatorClient{
			BaseURL:    url,
			HTTPClient: &http.Client{Transport: transport, Timeout: 5 * time.Minute},
			SigningKey: ed25519.PrivateKey(signingKey),
		}
	}
	return clients, certificate, roots, nil
}

func decodeRequest(runtime *fhe.Runtime, a, b []byte, c config) (fhe.EvaluationRequest, error) {
	first, err := fhe.UnmarshalProcessEnrollmentEnvelope(a)
	if err != nil {
		return fhe.EvaluationRequest{}, err
	}
	second, err := fhe.UnmarshalProcessEnrollmentEnvelope(b)
	if err != nil {
		return fhe.EvaluationRequest{}, err
	}
	pledgeA, err := fhe.UnmarshalCipherPledge(first.Ciphertext)
	if err != nil {
		return fhe.EvaluationRequest{}, err
	}
	pledgeB, err := fhe.UnmarshalCipherPledge(second.Ciphertext)
	if err != nil {
		return fhe.EvaluationRequest{}, err
	}
	enrollmentA, err := fhe.UnmarshalSignedCiphertextEnrollment(first.Enrollment)
	if err != nil {
		return fhe.EvaluationRequest{}, err
	}
	enrollmentB, err := fhe.UnmarshalSignedCiphertextEnrollment(second.Enrollment)
	if err != nil {
		return fhe.EvaluationRequest{}, err
	}
	var nonce [32]byte
	for index := 0; index < 8; index++ {
		nonce[24+index] = byte(c.nonce >> (56 - 8*index))
	}
	return fhe.EvaluationRequest{
		KeyID: runtime.KeyID(), PolicyVersion: uint32(c.policyVersion), Nonce: nonce,
		ValidUntil: time.Unix(int64(c.validUntil), 0), IdentityMode: fhe.IdentityMode(c.identityMode),
		A: pledgeA, B: pledgeB, EnrollmentA: enrollmentA, EnrollmentB: enrollmentB,
	}, nil
}

func evaluatorParameters() (bgv.Parameters, error) {
	return bgv.NewParametersFromLiteral(bgv.ParametersLiteral{
		LogN:             15,
		LogQ:             []int{60, 60, 59, 58, 58, 58, 58, 58, 58, 58, 58, 58},
		LogP:             []int{60, 60, 60},
		PlaintextModulus: 65537,
	})
}

func waitEnvelope(path string, limit time.Duration) ([]byte, error) {
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		if raw, err := os.ReadFile(path); err == nil && len(raw) > 0 {
			return raw, nil
		}
		time.Sleep(25 * time.Millisecond)
	}
	return nil, errors.New("encrypted client envelope timed out")
}

func readPublicKey(path string) (ed25519.PublicKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.New("invalid issuer public key")
	}
	if len(raw) == ed25519.PublicKeySize {
		return ed25519.PublicKey(raw), nil
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("invalid issuer public key")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	key, ok := parsed.(ed25519.PublicKey)
	if err != nil || !ok {
		return nil, errors.New("invalid issuer public key")
	}
	return key, nil
}

func parsePoints(value string) ([]uint64, error) {
	parts := strings.Split(value, ",")
	points := make([]uint64, 0, len(parts))
	for _, part := range parts {
		point, err := strconv.ParseUint(strings.TrimSpace(part), 10, 64)
		if err != nil || point == 0 {
			return nil, errors.New("invalid point")
		}
		points = append(points, point)
	}
	return points, nil
}

func parseOperators(value string) (map[uint64]string, error) {
	endpoints := make(map[uint64]string)
	for _, entry := range strings.Split(value, ",") {
		parts := strings.SplitN(strings.TrimSpace(entry), "=", 2)
		if len(parts) != 2 {
			return nil, errors.New("invalid operator endpoint")
		}
		point, err := strconv.ParseUint(parts[0], 10, 64)
		if err != nil || point == 0 || parts[1] == "" {
			return nil, errors.New("invalid operator endpoint")
		}
		endpoints[point] = parts[1]
	}
	return endpoints, nil
}

func decode32(value string) ([32]byte, error) {
	var out [32]byte
	raw, err := hex.DecodeString(strings.TrimPrefix(value, "0x"))
	if err != nil || len(raw) != 32 {
		return out, errors.New("invalid bytes32")
	}
	copy(out[:], raw)
	return out, nil
}

func parse(arguments []string) (config, error) {
	var c config
	f := flag.NewFlagSet("ceremony-evaluator", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	f.StringVar(&c.publicMaterial, "public-material", "", "collective public material")
	f.StringVar(&c.evaluationKeys, "evaluation-keys", "", "collective evaluation keys")
	f.StringVar(&c.manifest, "key-manifest", "", "operator-signed key manifest")
	f.StringVar(&c.issuerPublic, "issuer-public", "", "issuer public key")
	f.StringVar(&c.inputA, "input-a", "", "client A envelope")
	f.StringVar(&c.inputB, "input-b", "", "client B envelope")
	f.StringVar(&c.out, "out", "", "public result output")
	f.StringVar(&c.storage, "storage", "", "evaluator identity directory")
	f.StringVar(&c.certificate, "tls-cert", "", "evaluator certificate")
	f.StringVar(&c.peerCA, "peer-ca", "", "CA trusted for operators")
	f.StringVar(&c.operators, "operators", "", "point=url,...")
	f.StringVar(&c.coalition, "coalition", "", "two selected points")
	f.StringVar(&c.sessionID, "session-id", "", "release session id")
	f.StringVar(&c.vault, "vault", "", "vault address")
	f.StringVar(&c.policyID, "policy-id", "", "policy id")
	f.StringVar(&c.identityMode, "identity-mode", string(fhe.IdentityPublicCommitment),
		"public_salted_commitment or full_fhe_256")
	f.Uint64Var(&c.chainID, "chain-id", 0, "chain id")
	f.Uint64Var(&c.policyVersion, "policy-version", 0, "policy version")
	f.Uint64Var(&c.nonce, "nonce", 0, "result nonce")
	f.Uint64Var(&c.validUntil, "valid-until", 0, "unix seconds")
	if err := f.Parse(arguments); err != nil || f.NArg() != 0 ||
		c.publicMaterial == "" || c.evaluationKeys == "" || c.manifest == "" || c.issuerPublic == "" ||
		c.inputA == "" || c.inputB == "" || c.out == "" || c.storage == "" || c.certificate == "" ||
		c.peerCA == "" || c.operators == "" || c.coalition == "" || c.sessionID == "" ||
		c.policyID == "" || c.chainID == 0 || c.policyVersion == 0 || c.validUntil == 0 ||
		(c.identityMode != string(fhe.IdentityPublicCommitment) && c.identityMode != string(fhe.IdentityFullFHE256)) {
		return config{}, errors.New("invalid ceremony-evaluator configuration")
	}
	return c, nil
}
