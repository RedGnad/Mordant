//go:build obsolete_recoverable_ceremony

package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"time"

	fhe "mordant.dev/fhe-lab/lattigo"
)

func parse(arguments []string) (config, error) {
	var c config
	f := flag.NewFlagSet("ceremony-client", flag.ContinueOnError)
	f.SetOutput(os.Stderr)
	f.StringVar(&c.party, "party", "", "a or b")
	f.StringVar(&c.publicMaterial, "public-material", "", "collective public material")
	f.StringVar(&c.manifest, "key-manifest", "", "operator-signed key manifest")
	f.StringVar(&c.evaluationKeys, "evaluation-keys", "", "collective evaluation keys")
	f.StringVar(&c.issuerKey, "issuer-key", "", "0600 issuer private key")
	f.StringVar(&c.output, "out", "", "ciphertext-only output")
	f.StringVar(&c.privateManifest, "private-manifest", "", "0600 private canary manifest")
	f.StringVar(&c.rosterDigest, "roster-digest", "", "expected operator set digest")
	f.StringVar(&c.vault, "vault", "", "vault address")
	f.StringVar(&c.policyID, "policy-id", "", "policy id")
	f.StringVar(&c.sessionID, "session-id", "", "dispute session secret shared by the two facilities")
	f.StringVar(&c.coverage, "coverage-out", "", "public commercial-term coverage assertion")
	f.StringVar(&c.anchorRoot, "anchor-root", "", "invoice root of the deployed receivable anchor")
	f.StringVar(&c.currencyCode, "currency-code", "USD", "settlement currency code of the anchor")
	f.Uint64Var(&c.chainID, "chain-id", 0, "chain id")
	f.Uint64Var(&c.policyVersion, "policy-version", 0, "policy version")
	f.Uint64Var(&c.nonce, "nonce", 0, "public nonce")
	f.Uint64Var(&c.validUntil, "valid-until", 0, "unix seconds")
	f.Uint64Var(&c.keyEpoch, "key-epoch", 0, "expected key epoch")
	f.Uint64Var(&c.threshold, "threshold", 0, "expected threshold")
	f.StringVar(&c.identityMode, "identity-mode", string(fhe.IdentityPublicCommitment),
		"public_salted_commitment or full_fhe_256")
	// The strict stable asset identity is the secret the mode exists to protect,
	// so it is read from a 0600 file rather than passed as an argument: a command
	// line is visible to every local process and is recorded in the evidence.
	f.StringVar(&c.assetIDFile, "asset-id-file", "",
		"file holding the strict stable asset identity, required in full_fhe_256")
	f.StringVar(&c.enrollmentBinding, "enrollment-binding", "",
		"32-byte binding carried as the signed enrollment nonce")
	if err := f.Parse(arguments); err != nil || f.NArg() != 0 ||
		(c.party != "a" && c.party != "b") || c.chainID == 0 || c.policyVersion == 0 ||
		c.validUntil <= uint64(time.Now().Unix()) || c.publicMaterial == "" || c.manifest == "" ||
		c.evaluationKeys == "" || c.issuerKey == "" || c.output == "" || c.privateManifest == "" ||
		c.rosterDigest == "" || c.vault == "" || c.policyID == "" || c.sessionID == "" ||
		c.keyEpoch == 0 || c.threshold < 2 || c.coverage == "" || c.anchorRoot == "" || c.currencyCode == "" ||
		(c.identityMode != string(fhe.IdentityPublicCommitment) && c.identityMode != string(fhe.IdentityFullFHE256)) ||
		(c.identityMode == string(fhe.IdentityFullFHE256) && (c.assetIDFile == "" || c.enrollmentBinding == "")) {
		return config{}, errors.New("invalid ceremony client configuration")
	}
	return c, nil
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

func decode20(value string) ([20]byte, error) {
	var out [20]byte
	raw, err := hex.DecodeString(strings.TrimPrefix(value, "0x"))
	if err != nil || len(raw) != 20 {
		return out, errors.New("invalid address")
	}
	copy(out[:], raw)
	return out, nil
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

func readIssuerKey(path string) (ed25519.PrivateKey, error) {
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("invalid issuer private key")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.New("invalid issuer private key")
	}
	if len(raw) == ed25519.PrivateKeySize {
		return ed25519.PrivateKey(raw), nil
	}
	block, _ := pem.Decode(raw)
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
