// Command privacy-client materializes exactly one synthetic pledge in its own
// process, encrypts it with public material, and emits a ciphertext-only
// envelope for the evaluator. It never writes plaintext to stdout or stderr.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	fhe "mordant.dev/fhe-lab/lattigo"
)

type config struct {
	party, publicMaterial, issuerKey, output, privateManifest string
	chainID, policyVersion, nonce, validUntil                 uint64
	vault, policyID, sessionID                                string
}

type privateCanaries struct {
	Party  string            `json:"party"`
	Fields map[string]string `json:"fields"`
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "PRIVACY_CLIENT_FAILED")
		os.Exit(1)
	}
	fmt.Println("PRIVACY_CLIENT_COMPLETE")
}

func run(arguments []string) error {
	c, err := parse(arguments)
	if err != nil {
		return err
	}
	material, err := os.ReadFile(c.publicMaterial)
	if err != nil || len(material) == 0 {
		return errors.New("public material unavailable")
	}
	issuer, err := readPrivateKey(c.issuerKey)
	if err != nil {
		return err
	}
	client, err := fhe.NewExternalClient(material)
	if err != nil {
		return err
	}
	vault, err := decode20(c.vault)
	if err != nil {
		return err
	}
	policy, err := decode32(c.policyID)
	if err != nil {
		return err
	}
	session, err := decode32(c.sessionID)
	if err != nil {
		return err
	}
	canaries, err := freshCanaries(c.party)
	if err != nil {
		return err
	}
	pledge, claim, context, err := makePledge(c, vault, policy, session, canaries)
	if err != nil {
		return err
	}
	pledge.AuthorizationCommitment, err = client.SubmitterAuthorizationCommitment(claim)
	if err != nil {
		return err
	}
	cipher, _, err := client.EncryptPledgeForMode(pledge, fhe.IdentityPublicCommitment)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	enrollment, err := fhe.SignCiphertextEnrollment(client, cipher, fhe.IdentityPublicCommitment, context, claim, now.Add(-time.Second), time.Unix(int64(c.validUntil), 0), sha256.Sum256(append(session[:], []byte("enrollment-"+c.party)...)), issuer)
	if err != nil {
		return err
	}
	cipherWire, err := cipher.MarshalBinary()
	if err != nil {
		return err
	}
	enrollmentWire, err := enrollment.MarshalBinary()
	if err != nil {
		return err
	}
	wire, err := (fhe.ProcessEnrollmentEnvelope{Ciphertext: cipherWire, Enrollment: enrollmentWire}).MarshalBinary()
	if err != nil {
		return err
	}
	if err := writeExclusive(c.output, wire, 0o600); err != nil {
		return err
	}
	manifest := privateCanaries{Party: c.party, Fields: canaries}
	manifestWire, err := json.Marshal(manifest)
	if err != nil {
		return err
	}
	return writeExclusive(c.privateManifest, manifestWire, 0o600)
}

func parse(arguments []string) (config, error) {
	var c config
	f := flag.NewFlagSet("privacy-client", flag.ContinueOnError)
	f.SetOutput(os.Stderr)
	f.StringVar(&c.party, "party", "", "a or b")
	f.StringVar(&c.publicMaterial, "public-material", "", "public bundle")
	f.StringVar(&c.issuerKey, "issuer-key", "", "0600 issuer private key")
	f.StringVar(&c.output, "out", "", "ciphertext-only output")
	f.StringVar(&c.privateManifest, "private-manifest", "", "0600 private canary manifest")
	f.Uint64Var(&c.chainID, "chain-id", 0, "chain id")
	f.StringVar(&c.vault, "vault", "", "vault address")
	f.StringVar(&c.policyID, "policy-id", "", "policy id")
	f.Uint64Var(&c.policyVersion, "policy-version", 0, "policy version")
	f.Uint64Var(&c.nonce, "nonce", 0, "public nonce")
	f.Uint64Var(&c.validUntil, "valid-until", 0, "unix seconds")
	f.StringVar(&c.sessionID, "session-id", "", "session commitment")
	if err := f.Parse(arguments); err != nil || f.NArg() != 0 || (c.party != "a" && c.party != "b") || c.chainID == 0 || c.policyVersion == 0 || c.validUntil <= uint64(time.Now().Unix()) || c.publicMaterial == "" || c.issuerKey == "" || c.output == "" || c.privateManifest == "" || c.vault == "" || c.policyID == "" || c.sessionID == "" {
		return config{}, errors.New("invalid privacy client configuration")
	}
	return c, nil
}

func makePledge(c config, vault [20]byte, policy, session [32]byte, values map[string]string) (fhe.PlainPledge, fhe.AuthorizationClaim, fhe.InputCommitmentContext, error) {
	var zero fhe.PlainPledge
	invoice, err := decode32(values["invoice_identifier"])
	if err != nil {
		return zero, fhe.AuthorizationClaim{}, fhe.InputCommitmentContext{}, err
	}
	// Currency must match across the two selected claims for the frozen policy
	// to evaluate a conflict. The client-specific high-entropy currency canary
	// remains private in the audit manifest and is not placed in public output.
	currency := sha256.Sum256([]byte("controlled-lab-currency"))
	obligation, err := decode32(values["obligation_id"])
	if err != nil {
		return zero, fhe.AuthorizationClaim{}, fhe.InputCommitmentContext{}, err
	}
	authSubject, err := decode32(values["identity_authorization"])
	if err != nil {
		return zero, fhe.AuthorizationClaim{}, fhe.InputCommitmentContext{}, err
	}
	metadata, err := decode32(values["exclusivity"])
	if err != nil {
		return zero, fhe.AuthorizationClaim{}, fhe.InputCommitmentContext{}, err
	}
	linkSalt := sha256.Sum256(append(session[:], []byte("public-receivable-link")...))
	link := fhe.ReceivableLinkCommitment(vault, uint32(c.policyVersion), sha256.Sum256([]byte("controlled-lab-receivable")), linkSalt)
	slot := uint8(0)
	if c.party == "b" {
		slot = 1
	}
	claim := fhe.AuthorizationClaim{SubjectCommitment: authSubject, Role: sha256.Sum256([]byte("mordant.role.authorized-submitter.v1")), Vault: vault, PolicyID: policy, PolicyVersion: uint32(c.policyVersion), ValidUntil: c.validUntil, Nonce: fhe.Uint256{0, 0, 0, c.nonce*2 + uint64(slot) + 1}}
	context := fhe.InputCommitmentContext{ChainID: fhe.Uint256{0, 0, 0, c.chainID}, Vault: vault, PolicyID: policy, PolicyVersion: uint32(c.policyVersion), InputSlot: slot, ClientNonce: fhe.Uint256{0, 0, 0, c.nonce*2 + uint64(slot) + 1}}
	from, until := uint64(100), uint64(500)
	if c.party == "a" {
		until = 400
	} else {
		from = 200
	}
	return fhe.PlainPledge{ActiveFrom: from, ActiveUntil: until, Amount: fhe.Uint256{0, 0, 0, 1_000_000 - uint64(slot)*100_000}, Currency: currency, ObligationID: obligation, ReceivableID: invoice, Exclusive: true, ReceivableCommitment: link, PrivateMetadataCommitment: metadata}, claim, context, nil
}

func freshCanaries(party string) (map[string]string, error) {
	fields := []string{"invoice_identifier", "amount", "currency", "active_periods", "obligation_id", "exclusivity", "identity_authorization"}
	result := make(map[string]string, len(fields))
	for _, field := range fields {
		raw := make([]byte, 32)
		if _, err := rand.Read(raw); err != nil {
			return nil, err
		}
		result[field] = hex.EncodeToString(raw)
	}
	return result, nil
}

func decode32(value string) ([32]byte, error) {
	var out [32]byte
	b, err := hex.DecodeString(trimHex(value))
	if err != nil || len(b) != 32 {
		return out, errors.New("invalid bytes32")
	}
	copy(out[:], b)
	return out, nil
}
func decode20(value string) ([20]byte, error) {
	var out [20]byte
	b, err := hex.DecodeString(trimHex(value))
	if err != nil || len(b) != 20 {
		return out, errors.New("invalid address")
	}
	copy(out[:], b)
	return out, nil
}
func trimHex(value string) string {
	if len(value) >= 2 && value[:2] == "0x" {
		return value[2:]
	}
	return value
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
func readPrivateKey(path string) (ed25519.PrivateKey, error) {
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("invalid issuer private key")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.New("invalid issuer private key")
	}
	if len(b) == ed25519.PrivateKeySize {
		return ed25519.PrivateKey(b), nil
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errors.New("invalid issuer private key")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	key, ok := parsed.(ed25519.PrivateKey)
	if err != nil || !ok || len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid issuer private key")
	}
	return key, nil
}
