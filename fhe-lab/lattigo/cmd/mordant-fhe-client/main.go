package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	fhe "mordant.dev/fhe-lab/lattigo"
	"mordant.dev/fhe-lab/lattigo/governedfhe"
)

const (
	defaultClientMode                        = "submit"
	participantBundleExpectationsInputSchema = "mordant.participant-originated-bundle-expectations/1"
	participantLocalPledgeSchema             = "mordant.participant-originated-local-pledge/1"
	participantPreparationRequestSchema      = "mordant.participant-originated-preparation-request/1"
)

var strictLowerBytes32 = regexp.MustCompile(`^0x[0-9a-f]{64}$`)

// pledgeInput is the retained managed/direct input shape. Its behavior remains
// the default when -mode is omitted.
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

// participantLocalPledge is accepted only by participant-local modes. It is
// intentionally incompatible with coordinator request schemas and contains no
// authorization/private-metadata commitment inputs; the client derives those.
type participantLocalPledge struct {
	SchemaVersion        string    `json:"schemaVersion"`
	ActiveFrom           uint64    `json:"activeFrom"`
	ActiveUntil          uint64    `json:"activeUntil"`
	Amount               [4]uint64 `json:"amount"`
	Currency             string    `json:"currency"`
	ObligationID         string    `json:"obligationId"`
	ReceivableID         string    `json:"receivableId"`
	Exclusive            bool      `json:"exclusive"`
	ReceivableCommitment string    `json:"receivableCommitment"`
}

type participantBundleExpectationsInput struct {
	SchemaVersion               string             `json:"schemaVersion"`
	RunID                       string             `json:"runId"`
	Role                        string             `json:"role"`
	CaseID                      governedfhe.Digest `json:"caseId"`
	AssetIdentity               governedfhe.Digest `json:"assetIdentity"`
	ExpectedSourceDigest        governedfhe.Digest `json:"expectedSourceDigest"`
	ExpectedBuildManifestDigest governedfhe.Digest `json:"expectedBuildManifestDigest"`
	ExpectedClientBinaryDigest  governedfhe.Digest `json:"expectedClientBinaryDigest"`
}

func (input participantBundleExpectationsInput) expectations(now time.Time, executableDigest governedfhe.Digest) (governedfhe.ParticipantOriginatedBundleExpectations, error) {
	if input.ExpectedClientBinaryDigest != executableDigest {
		return governedfhe.ParticipantOriginatedBundleExpectations{}, fmt.Errorf("bundle expectations do not pin this qualified client binary")
	}
	return governedfhe.ParticipantOriginatedBundleExpectations{
		RunID: input.RunID, Role: input.Role, CaseID: input.CaseID, AssetIdentity: input.AssetIdentity,
		ExpectedSourceDigest: input.ExpectedSourceDigest, ExpectedBuildManifestDigest: input.ExpectedBuildManifestDigest,
		ExpectedClientBinaryDigest: input.ExpectedClientBinaryDigest, Now: now,
	}, nil
}

// participantPreparationRequest is produced only after Phase 1 is verified.
// All bytes32 values use the exact lower-case 0x representation consumed by
// the TypeScript EIP-712 layer.
type participantPreparationRequest struct {
	SchemaVersion          string `json:"schemaVersion"`
	ClientBundleDigest     string `json:"clientBundleDigest"`
	ClaimCommitment        string `json:"claimCommitment"`
	EncryptionIntentDigest string `json:"encryptionIntentDigest"`
	SubmissionNonce        string `json:"submissionNonce"`
	ExpiresAtUnix          int64  `json:"expiresAtUnix"`
}

type participantKeygenResult struct {
	SchemaVersion               string `json:"schemaVersion"`
	ParticipantSigningPublicKey string `json:"participantSigningPublicKey"`
	ParticipantSigningKeyDigest string `json:"participantSigningKeyDigest"`
}

func main() {
	mode := flag.String("mode", defaultClientMode, "submit, participant-keygen, participant-ceremony-sign, participant-claim, or participant-prepare")
	publicRoot := flag.String("public-root", "", "absolute managed public case root")
	bundleRoot := flag.String("bundle-root", "", "absolute participant client bundle root")
	outputRoot := flag.String("output-root", "", "absolute create-only participant artifact output root")
	role := flag.String("role", "", "PARTICIPANT_A or PARTICIPANT_B")
	signingKeyPath := flag.String("signing-key", "", "participant-local raw Ed25519 private-key file")
	pledgePath := flag.String("pledge", "", "participant-local private pledge JSON file")
	claimSaltPath := flag.String("claim-salt", "", "participant-local raw 32-byte salt file")
	bundleExpectationsPath := flag.String("bundle-expectations", "", "canonical pinned bundle expectations JSON")
	requestPath := flag.String("request", "", "canonical ceremony or artifact-preparation request JSON")
	nonceText := flag.String("submission-nonce", "", "sha256:<64 hex>")
	expires := flag.Int64("expires-at", 0, "submission expiry Unix timestamp")
	flag.Parse()
	switch *mode {
	case "submit":
		runManagedSubmit(*publicRoot, *role, *signingKeyPath, *pledgePath, *nonceText, *expires)
	case "participant-keygen":
		runParticipantKeygen(*signingKeyPath)
	case "participant-ceremony-sign":
		runParticipantCeremonySign(*requestPath, *signingKeyPath)
	case "participant-claim":
		runParticipantClaim(*bundleRoot, *bundleExpectationsPath, *pledgePath, *claimSaltPath)
	case "participant-prepare":
		runParticipantPrepare(*bundleRoot, *bundleExpectationsPath, *outputRoot, *pledgePath, *claimSaltPath, *signingKeyPath, *requestPath)
	default:
		fail(fmt.Errorf("unsupported mode"))
	}
}

func runManagedSubmit(publicRoot, role, signingKeyPath, pledgePath, nonceText string, expires int64) {
	if publicRoot == "" || role == "" || signingKeyPath == "" || pledgePath == "" || nonceText == "" || expires <= 0 {
		fail(fmt.Errorf("all flags are required"))
	}
	if _, err := governedfhe.VerifyProtectionAuthorization(publicRoot); err != nil {
		fail(err)
	}
	key, err := os.ReadFile(signingKeyPath)
	if err != nil || len(key) != ed25519.PrivateKeySize {
		fail(fmt.Errorf("invalid participant signing key"))
	}
	defer clear(key)
	pledgeData, err := os.ReadFile(pledgePath)
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
	if nonce.UnmarshalText([]byte(nonceText)) != nil {
		fail(fmt.Errorf("invalid submission nonce"))
	}
	pledge := fhe.PlainPledge{
		ActiveFrom: input.ActiveFrom, ActiveUntil: input.ActiveUntil, Amount: fhe.Uint256(input.Amount), Exclusive: input.Exclusive,
		Currency: parse32(input.Currency), ObligationID: parse32(input.ObligationID), ReceivableID: parse32(input.ReceivableID),
		AuthorizationCommitment: parse32(input.AuthorizationCommitment), PrivateMetadataCommitment: parse32(input.PrivateMetadataCommitment),
	}
	artifact, report, err := governedfhe.SubmitParticipant(governedfhe.ParticipantSubmissionOptions{
		PublicRoot: publicRoot, Role: role, SigningKey: ed25519.PrivateKey(key), Pledge: pledge,
		SubmissionNonce: nonce, ExpiresAtUnix: expires, Now: time.Now().UTC(),
	})
	if err != nil {
		fail(err)
	}
	digest, _ := artifact.Digest()
	writeJSON(struct {
		ArtifactDigest  governedfhe.Digest `json:"artifactDigest"`
		DurationNanos   int64              `json:"durationNanos"`
		CiphertextBytes int64              `json:"ciphertextBytes"`
		ArtifactBytes   int64              `json:"artifactBytes"`
	}{digest, report.Duration.Nanoseconds(), report.CiphertextBytes, report.ArtifactBytes})
}

func runParticipantKeygen(signingKeyPath string) {
	if !filepath.IsAbs(signingKeyPath) {
		fail(fmt.Errorf("participant-keygen requires absolute -signing-key"))
	}
	result, err := generateParticipantSigningKey(signingKeyPath)
	if err != nil {
		fail(err)
	}
	writeJSON(result)
}

func generateParticipantSigningKey(signingKeyPath string) (participantKeygenResult, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return participantKeygenResult{}, err
	}
	defer clear(privateKey)
	if err := createLocalSecret(signingKeyPath, privateKey); err != nil {
		return participantKeygenResult{}, err
	}
	digest, err := governedfhe.ParticipantOriginatedSigningKeyDigest(publicKey)
	if err != nil {
		return participantKeygenResult{}, err
	}
	return participantKeygenResult{
		"mordant.participant-originated-key-generation-result/1",
		"0x" + hex.EncodeToString(publicKey), digest0x(digest),
	}, nil
}

func runParticipantCeremonySign(requestPath, signingKeyPath string) {
	if !filepath.IsAbs(requestPath) || !filepath.IsAbs(signingKeyPath) {
		fail(fmt.Errorf("participant-ceremony-sign requires absolute -request and -signing-key"))
	}
	var request governedfhe.ParticipantOriginatedCeremonyRequest
	readCanonicalJSON(requestPath, &request)
	executableDigest, err := governedfhe.ExecutableDigest()
	if err != nil || request.ExpectedClientBinaryDigest != executableDigest {
		fail(fmt.Errorf("ceremony request does not pin this qualified client binary"))
	}
	key := readLocalSigningKey(signingKeyPath)
	defer clear(key)
	approval, err := governedfhe.SignParticipantOriginatedCeremony(request, ed25519.PrivateKey(key), time.Now().UTC())
	if err != nil {
		fail(err)
	}
	writeJSON(approval)
}

func runParticipantClaim(bundleRoot, expectationsPath, pledgePath, saltPath string) {
	if !allAbsolute(bundleRoot, expectationsPath, pledgePath, saltPath) {
		fail(fmt.Errorf("participant-claim requires absolute -bundle-root, -bundle-expectations, -pledge, and -claim-salt"))
	}
	now := time.Now().UTC()
	expectations := readParticipantBundleExpectations(expectationsPath, now)
	bundle, bundleDigest, err := governedfhe.VerifyParticipantOriginatedClientBundle(bundleRoot, expectations)
	if err != nil {
		fail(err)
	}
	pledge := readParticipantLocalPledge(pledgePath)
	salt := readOrCreateClaimSalt(saltPath)
	commitment, err := governedfhe.ParticipantOriginatedClaimCommitment(bundle, pledge, salt)
	clear(salt[:])
	if err != nil {
		fail(err)
	}
	writeJSON(struct {
		SchemaVersion      string `json:"schemaVersion"`
		RunID              string `json:"runId"`
		Role               string `json:"role"`
		ClientBundleDigest string `json:"clientBundleDigest"`
		ClaimCommitment    string `json:"claimCommitment"`
	}{"mordant.participant-originated-claim-result/1", bundle.RunID, bundle.Role, digest0x(bundleDigest), digest0x(commitment)})
}

func runParticipantPrepare(bundleRoot, expectationsPath, outputRoot, pledgePath, saltPath, signingKeyPath, requestPath string) {
	if !allAbsolute(bundleRoot, expectationsPath, outputRoot, pledgePath, saltPath, signingKeyPath, requestPath) {
		fail(fmt.Errorf("participant-prepare requires absolute bundle, expectations, output, pledge, salt, signing-key, and request paths"))
	}
	now := time.Now().UTC()
	expectations := readParticipantBundleExpectations(expectationsPath, now)
	var request participantPreparationRequest
	readCanonicalJSON(requestPath, &request)
	if request.SchemaVersion != participantPreparationRequestSchema || request.ExpiresAtUnix <= now.Unix() {
		fail(fmt.Errorf("invalid participant preparation request"))
	}
	bundle, bundleDigest, err := governedfhe.VerifyParticipantOriginatedClientBundle(bundleRoot, expectations)
	if err != nil {
		fail(err)
	}
	pledge := readParticipantLocalPledge(pledgePath)
	salt := readClaimSalt(saltPath)
	defer clear(salt[:])
	commitment, err := governedfhe.ParticipantOriginatedClaimCommitment(bundle, pledge, salt)
	if err != nil {
		fail(err)
	}
	if exactBytes32(request.ClientBundleDigest) != [32]byte(bundleDigest) ||
		exactBytes32(request.ClaimCommitment) != [32]byte(commitment) {
		fail(fmt.Errorf("preparation request does not match the verified bundle or local claim commitment"))
	}
	intentDigest := parseAuthorizationDigest(request.EncryptionIntentDigest)
	submissionNonce := governedfhe.Digest(exactBytes32(request.SubmissionNonce))
	key := readLocalSigningKey(signingKeyPath)
	defer clear(key)
	prepared, err := governedfhe.PrepareParticipantOriginatedArtifact(governedfhe.ParticipantOriginatedPreparationOptions{
		BundleRoot: bundleRoot, OutputRoot: outputRoot, BundleExpectations: expectations,
		SigningKey: ed25519.PrivateKey(key), Pledge: pledge, ClaimSalt: salt,
		EncryptionIntentDigest: intentDigest, SubmissionNonce: submissionNonce, ExpiresAtUnix: request.ExpiresAtUnix,
	})
	if err != nil {
		fail(err)
	}
	writeJSON(struct {
		SchemaVersion           string                                               `json:"schemaVersion"`
		RunID                   string                                               `json:"runId"`
		Role                    string                                               `json:"role"`
		ClientBundleDigest      string                                               `json:"clientBundleDigest"`
		EncryptionIntentDigest  governedfhe.ParticipantOriginatedAuthorizationDigest `json:"encryptionIntentDigest"`
		ClaimCommitment         string                                               `json:"claimCommitment"`
		SubmissionNonce         string                                               `json:"submissionNonce"`
		EncryptedArtifactDigest string                                               `json:"encryptedArtifactDigest"`
		CiphertextObjectDigest  string                                               `json:"ciphertextObjectDigest"`
		CiphertextObjectLength  int64                                                `json:"ciphertextObjectLength"`
		EnrollmentSignature     string                                               `json:"enrollmentSignature"`
		ExpiresAtUnix           int64                                                `json:"expiresAtUnix"`
		ArtifactObject          governedfhe.ObjectRef                                `json:"artifactObject"`
		CiphertextObject        governedfhe.ObjectRef                                `json:"ciphertextObject"`
		Report                  governedfhe.SubmissionReport                         `json:"report"`
	}{
		"mordant.participant-originated-preparation-result/2", bundle.RunID, bundle.Role,
		digest0x(bundleDigest), prepared.EncryptionIntentDigest, digest0x(prepared.ClaimCommitment),
		digest0x(prepared.Artifact.SubmissionNonce), digest0x(prepared.ArtifactDigest), digest0x(prepared.CiphertextDigest),
		prepared.CiphertextObject.Length, "0x" + hex.EncodeToString(prepared.EnrollmentSignature),
		prepared.Artifact.ExpiresAtUnix, prepared.ArtifactObject,
		prepared.CiphertextObject, prepared.Report,
	})
}

func readParticipantBundleExpectations(path string, now time.Time) governedfhe.ParticipantOriginatedBundleExpectations {
	var input participantBundleExpectationsInput
	readCanonicalJSON(path, &input)
	if input.SchemaVersion != participantBundleExpectationsInputSchema {
		fail(fmt.Errorf("unsupported bundle expectations schema"))
	}
	executableDigest, err := governedfhe.ExecutableDigest()
	if err != nil {
		fail(err)
	}
	expectations, err := input.expectations(now, executableDigest)
	if err != nil {
		fail(err)
	}
	return expectations
}

func readParticipantLocalPledge(path string) fhe.PlainPledge {
	var input participantLocalPledge
	readCanonicalJSON(path, &input)
	pledge, err := participantPledgeFromInput(input)
	if err != nil {
		fail(err)
	}
	return pledge
}

func participantPledgeFromInput(input participantLocalPledge) (fhe.PlainPledge, error) {
	if input.SchemaVersion != participantLocalPledgeSchema {
		return fhe.PlainPledge{}, fmt.Errorf("unsupported participant-local pledge schema")
	}
	receivableCommitment, err := decodeExactBytes32(input.ReceivableCommitment)
	if err != nil {
		return fhe.PlainPledge{}, err
	}
	if receivableCommitment != ([32]byte{}) {
		return fhe.PlainPledge{}, fmt.Errorf("receivableCommitment must be canonical zero for IdentityFullFHE256")
	}
	currency, err := decodeExactBytes32(input.Currency)
	if err != nil {
		return fhe.PlainPledge{}, err
	}
	obligationID, err := decodeExactBytes32(input.ObligationID)
	if err != nil {
		return fhe.PlainPledge{}, err
	}
	receivableID, err := decodeExactBytes32(input.ReceivableID)
	if err != nil {
		return fhe.PlainPledge{}, err
	}
	return fhe.PlainPledge{
		ActiveFrom: input.ActiveFrom, ActiveUntil: input.ActiveUntil, Amount: fhe.Uint256(input.Amount),
		Currency: currency, ObligationID: obligationID, ReceivableID: receivableID, Exclusive: input.Exclusive,
		ReceivableCommitment: receivableCommitment,
	}, nil
}

func readLocalSigningKey(path string) []byte {
	key, err := readPrivateLocalSecret(path, ed25519.PrivateKeySize, "participant signing key")
	if err != nil {
		fail(err)
	}
	return key
}

// readPrivateLocalSecret pins the participant-local inode with O_NOFOLLOW and
// rejects shared, non-owned or group/world-accessible files. It is local CLI
// hygiene, not a hardware-backed key-custody claim.
func readPrivateLocalSecret(path string, exactLength int, label string) ([]byte, error) {
	if !filepath.IsAbs(path) || exactLength <= 0 {
		return nil, fmt.Errorf("invalid %s path", label)
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", label, err)
	}
	file := os.NewFile(uintptr(fd), label)
	if file == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("open %s", label)
	}
	var before, after unix.Stat_t
	if unix.Fstat(fd, &before) != nil || before.Mode&unix.S_IFMT != unix.S_IFREG ||
		before.Uid != uint32(os.Geteuid()) || before.Nlink != 1 || uint32(before.Mode)&0o077 != 0 ||
		before.Size != int64(exactLength) {
		_ = file.Close()
		return nil, fmt.Errorf("%s must be a private owned regular file", label)
	}
	data, readErr := io.ReadAll(io.LimitReader(file, int64(exactLength)+1))
	statErr := unix.Fstat(fd, &after)
	closeErr := file.Close()
	if readErr != nil || statErr != nil || closeErr != nil || len(data) != exactLength ||
		before.Dev != after.Dev || before.Ino != after.Ino || before.Size != after.Size || before.Mode != after.Mode {
		clear(data)
		return nil, fmt.Errorf("read stable %s", label)
	}
	return data, nil
}

func createLocalSecret(path string, secret []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create local secret: %w", err)
	}
	written, writeErr := file.Write(secret)
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil || written != len(secret) {
		return fmt.Errorf("write local secret")
	}
	return nil
}

func readOrCreateClaimSalt(path string) [32]byte {
	salt, err := readClaimSaltValue(path)
	if err == nil {
		return salt
	}
	if !errors.Is(err, os.ErrNotExist) {
		fail(err)
	}
	generated, err := governedfhe.GenerateParticipantOriginatedClaimSalt()
	if err != nil {
		fail(err)
	}
	if err := createLocalSecret(path, generated[:]); err != nil {
		clear(generated[:])
		fail(err)
	}
	return generated
}

func readClaimSalt(path string) [32]byte {
	salt, err := readClaimSaltValue(path)
	if err != nil {
		fail(err)
	}
	return salt
}

func readClaimSaltValue(path string) ([32]byte, error) {
	var salt [32]byte
	data, err := readPrivateLocalSecret(path, len(salt), "claim salt")
	if err != nil {
		return salt, err
	}
	copy(salt[:], data)
	clear(data)
	if salt == ([32]byte{}) {
		return salt, fmt.Errorf("claim salt must be non-zero")
	}
	return salt, nil
}

func exactBytes32(value string) (out [32]byte) {
	out, err := decodeExactBytes32(value)
	if err != nil {
		fail(err)
	}
	return out
}

func decodeExactBytes32(value string) (out [32]byte, err error) {
	if !strictLowerBytes32.MatchString(value) {
		return out, fmt.Errorf("bytes32 values must use exact lower-case 0x encoding")
	}
	decoded, err := hex.DecodeString(value[2:])
	if err != nil || len(decoded) != len(out) {
		return out, fmt.Errorf("invalid bytes32 value")
	}
	copy(out[:], decoded)
	return out, nil
}

func parseAuthorizationDigest(value string) governedfhe.ParticipantOriginatedAuthorizationDigest {
	var digest governedfhe.ParticipantOriginatedAuthorizationDigest
	if !strictLowerBytes32.MatchString(value) || digest.UnmarshalText([]byte(value)) != nil ||
		digest == (governedfhe.ParticipantOriginatedAuthorizationDigest{}) {
		fail(fmt.Errorf("invalid authorization digest"))
	}
	return digest
}

func digest0x(value governedfhe.Digest) string {
	return "0x" + hex.EncodeToString(value[:])
}

func allAbsolute(paths ...string) bool {
	for _, path := range paths {
		if !filepath.IsAbs(path) {
			return false
		}
	}
	return true
}

func readCanonicalJSON(path string, target any) {
	data, err := os.ReadFile(path)
	if err != nil {
		fail(err)
	}
	if err := decodeCanonicalJSON(data, target); err != nil {
		fail(err)
	}
}

func decodeCanonicalJSON(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("invalid canonical JSON: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("invalid canonical JSON: trailing value")
	}
	canonical, err := json.Marshal(target)
	if err != nil {
		return err
	}
	withNewline := append(append([]byte(nil), canonical...), '\n')
	if !bytes.Equal(data, canonical) && !bytes.Equal(data, withNewline) {
		return fmt.Errorf("input JSON is not canonical")
	}
	return nil
}

func writeJSON(value any) {
	if err := json.NewEncoder(os.Stdout).Encode(value); err != nil {
		fail(err)
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
