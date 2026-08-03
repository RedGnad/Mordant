package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	fhe "mordant.dev/fhe-lab/lattigo"
	"mordant.dev/fhe-lab/lattigo/governedfhe"
)

type pledgeInput struct {
	ActiveFrom                uint64    `json:"activeFrom"`
	ActiveUntil               uint64    `json:"activeUntil"`
	Amount                    [4]uint64 `json:"amount"`
	Currency                  string    `json:"currency"`
	ObligationID              string    `json:"obligationId"`
	ReceivableID              string    `json:"receivableId"`
	Exclusive                 bool      `json:"exclusive"`
	AuthorizationCommitment   string    `json:"authorizationCommitment"`
	PrivateMetadataCommitment string    `json:"privateMetadataCommitment"`
}

func main() {
	publicRoot := flag.String("public-root", "", "absolute public case root")
	role := flag.String("role", "", "PARTICIPANT_A or PARTICIPANT_B")
	signingKeyPath := flag.String("signing-key", "", "participant Ed25519 private-key file")
	pledgePath := flag.String("pledge", "", "private pledge JSON file")
	nonceText := flag.String("submission-nonce", "", "sha256:<64 hex>")
	expires := flag.Int64("expires-at", 0, "submission expiry Unix timestamp")
	flag.Parse()
	if *publicRoot == "" || *role == "" || *signingKeyPath == "" || *pledgePath == "" || *nonceText == "" || *expires <= 0 {
		fail(fmt.Errorf("all flags are required"))
	}
	if _, err := governedfhe.VerifyProtectionAuthorization(*publicRoot); err != nil {
		fail(err)
	}
	key, err := os.ReadFile(*signingKeyPath)
	if err != nil || len(key) != ed25519.PrivateKeySize {
		fail(fmt.Errorf("invalid participant signing key"))
	}
	pledgeData, err := os.ReadFile(*pledgePath)
	if err != nil {
		fail(err)
	}
	var input pledgeInput
	decoder := json.NewDecoder(strings.NewReader(string(pledgeData)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		fail(err)
	}
	var nonce governedfhe.Digest
	if nonce.UnmarshalText([]byte(*nonceText)) != nil {
		fail(fmt.Errorf("invalid submission nonce"))
	}
	pledge := fhe.PlainPledge{
		ActiveFrom: input.ActiveFrom, ActiveUntil: input.ActiveUntil, Amount: fhe.Uint256(input.Amount), Exclusive: input.Exclusive,
		Currency: parse32(input.Currency), ObligationID: parse32(input.ObligationID), ReceivableID: parse32(input.ReceivableID),
		AuthorizationCommitment: parse32(input.AuthorizationCommitment), PrivateMetadataCommitment: parse32(input.PrivateMetadataCommitment),
	}
	artifact, report, err := governedfhe.SubmitParticipant(governedfhe.ParticipantSubmissionOptions{
		PublicRoot: *publicRoot, Role: *role, SigningKey: ed25519.PrivateKey(key), Pledge: pledge,
		SubmissionNonce: nonce, ExpiresAtUnix: *expires, Now: time.Now().UTC(),
	})
	if err != nil {
		fail(err)
	}
	digest, _ := artifact.Digest()
	if err := json.NewEncoder(os.Stdout).Encode(struct {
		ArtifactDigest  governedfhe.Digest `json:"artifactDigest"`
		DurationNanos   int64              `json:"durationNanos"`
		CiphertextBytes int64              `json:"ciphertextBytes"`
		ArtifactBytes   int64              `json:"artifactBytes"`
	}{digest, report.Duration.Nanoseconds(), report.CiphertextBytes, report.ArtifactBytes}); err != nil {
		fail(err)
	}
	for index := range key {
		key[index] = 0
	}
}

func parse32(value string) (out [32]byte) {
	value = strings.TrimPrefix(value, "0x")
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != 32 {
		fail(fmt.Errorf("invalid bytes32 pledge field"))
	}
	copy(out[:], decoded)
	return
}

func fail(err error) {
	fmt.Fprintf(os.Stderr, "mordant-fhe-client: %v\n", err)
	os.Exit(1)
}
