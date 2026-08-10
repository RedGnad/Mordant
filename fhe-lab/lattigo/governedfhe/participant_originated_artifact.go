package governedfhe

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
	"golang.org/x/sys/unix"
	fhe "mordant.dev/fhe-lab/lattigo"
)

const (
	ParticipantOriginatedArtifactVerificationSchema        = "mordant.participant-originated-artifact-verification/1"
	ParticipantOriginatedImportAdmissionSchema             = "mordant.participant-originated-import-admission/1"
	ParticipantOriginatedImportCompletionSchema            = "mordant.participant-originated-import-completion/1"
	ParticipantOriginatedNonceClaimSchema                  = "mordant.participant-originated-nonce-claim/1"
	participantOriginatedClaimDomain                       = "MordantParticipantOriginatedClaim/v1"
	participantOriginatedMaximumCiphertextBytes     int64  = 192 << 20
	participantOriginatedMaximumJSONInteger         uint64 = 1<<53 - 1
)

var (
	ErrParticipantImportReplay   = errors.New("participant-originated import replay rejected")
	ErrParticipantRoleOccupied   = errors.New("participant-originated role already occupied")
	ErrParticipantImportMismatch = errors.New("participant-originated import binding mismatch")
)

// ParticipantOriginatedAuthorizationDigest is an opaque EIP-712 bytes32
// value. Unlike Digest (which is rendered as sha256:...), authorization
// digests are Keccak-derived by the wallet service and cross the Go boundary
// as the exact lower-case 0x-prefixed 32 bytes used by TypeScript.
type ParticipantOriginatedAuthorizationDigest [32]byte

func (d ParticipantOriginatedAuthorizationDigest) String() string {
	return participantOriginatedBytes32Hex([32]byte(d))
}

func (d ParticipantOriginatedAuthorizationDigest) MarshalText() ([]byte, error) {
	return []byte(d.String()), nil
}

func (d *ParticipantOriginatedAuthorizationDigest) UnmarshalText(text []byte) error {
	if d == nil || len(text) != 66 || string(text[:2]) != "0x" {
		return ErrParticipantOriginated
	}
	decoded, err := hex.DecodeString(string(text[2:]))
	if err != nil || len(decoded) != 32 {
		return ErrParticipantOriginated
	}
	var exact ParticipantOriginatedAuthorizationDigest
	copy(exact[:], decoded)
	if exact.String() != string(text) {
		return ErrParticipantOriginated
	}
	*d = exact
	return nil
}

func nonzeroParticipantOriginatedAuthorizationDigest(value ParticipantOriginatedAuthorizationDigest) bool {
	return value != (ParticipantOriginatedAuthorizationDigest{})
}

func ParticipantOriginatedSigningKeyDigest(publicKey []byte) (Digest, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return Digest{}, ErrParticipantOriginated
	}
	// This is deliberately SHA-256 over the exact raw 32 Ed25519 bytes. It is
	// the byte-identical counterpart of participantSigningPublicKeyDigest in
	// the authorization service, not a governed-FHE domain digest.
	return DigestBytes(publicKey), nil
}

func GenerateParticipantOriginatedClaimSalt() ([32]byte, error) {
	for {
		var salt [32]byte
		if _, err := rand.Read(salt[:]); err != nil {
			return salt, err
		}
		if salt != ([32]byte{}) {
			return salt, nil
		}
	}
}

// ParticipantOriginatedClaimCommitment is computed entirely at the participant
// boundary. The 32-byte salt and all plaintext fields remain local; only this
// hiding commitment is placed in CipherPledge.PrivateMetadataCommitment. The
// retained primitives do not prove that the encrypted plaintext equals this
// commitment's preimage; the qualified profile discloses that semantic gap.
func participantOriginatedBytes32Hex(value [32]byte) string {
	return "0x" + hex.EncodeToString(value[:])
}

func ParticipantOriginatedClaimCommitment(bundle ParticipantOriginatedClientBundle, pledge fhe.PlainPledge, salt [32]byte) (Digest, error) {
	if bundle.SchemaVersion != ParticipantOriginatedClientBundleSchema || !validParticipantOriginatedRunID(bundle.RunID) ||
		(bundle.Role != RoleA && bundle.Role != RoleB) || !nonzero(bundle.CaseID) || salt == ([32]byte{}) ||
		pledge.ActiveFrom >= pledge.ActiveUntil || pledge.ActiveFrom > participantOriginatedMaximumJSONInteger ||
		pledge.ActiveUntil > participantOriginatedMaximumJSONInteger || pledge.Amount == (fhe.Uint256{}) ||
		pledge.Currency == ([32]byte{}) || pledge.ObligationID == ([32]byte{}) || pledge.ReceivableID == ([32]byte{}) ||
		pledge.ReceivableCommitment != ([32]byte{}) {
		return Digest{}, ErrParticipantOriginated
	}
	for _, limb := range pledge.Amount {
		if limb > participantOriginatedMaximumJSONInteger {
			return Digest{}, ErrParticipantOriginated
		}
	}
	// Field declaration order is lexicographic at both levels, matching the
	// authorization service's canonicalJson key ordering exactly. Byte strings
	// use lower-case 0x-prefixed hex rather than Go's native byte-array JSON.
	claim := struct {
		ActiveFrom           uint64      `json:"activeFrom"`
		ActiveUntil          uint64      `json:"activeUntil"`
		Amount               fhe.Uint256 `json:"amount"`
		Currency             string      `json:"currency"`
		Exclusive            bool        `json:"exclusive"`
		ObligationID         string      `json:"obligationId"`
		ReceivableCommitment string      `json:"receivableCommitment"`
		ReceivableID         string      `json:"receivableId"`
	}{
		ActiveFrom: pledge.ActiveFrom, ActiveUntil: pledge.ActiveUntil, Amount: pledge.Amount,
		Currency: participantOriginatedBytes32Hex(pledge.Currency), Exclusive: pledge.Exclusive,
		ObligationID:         participantOriginatedBytes32Hex(pledge.ObligationID),
		ReceivableCommitment: participantOriginatedBytes32Hex(pledge.ReceivableCommitment),
		ReceivableID:         participantOriginatedBytes32Hex(pledge.ReceivableID),
	}
	projection := struct {
		Claim     any    `json:"claim"`
		FHECaseID string `json:"fheCaseId"`
		Role      string `json:"role"`
		RunID     string `json:"runId"`
		Salt      string `json:"salt"`
	}{
		Claim: claim, FHECaseID: participantOriginatedBytes32Hex([32]byte(bundle.CaseID)), Role: bundle.Role,
		RunID: bundle.RunID, Salt: participantOriginatedBytes32Hex(salt),
	}
	return digestDomainCanonical(participantOriginatedClaimDomain, projection)
}

type ParticipantOriginatedPreparationOptions struct {
	BundleRoot             string
	OutputRoot             string
	BundleExpectations     ParticipantOriginatedBundleExpectations
	SigningKey             ed25519.PrivateKey
	Pledge                 fhe.PlainPledge
	ClaimSalt              [32]byte
	EncryptionIntentDigest ParticipantOriginatedAuthorizationDigest
	SubmissionNonce        Digest
	ExpiresAtUnix          int64
}

type ParticipantOriginatedPreparedArtifact struct {
	Artifact               EncryptedParticipantArtifact             `json:"artifact"`
	ArtifactDigest         Digest                                   `json:"artifactDigest"`
	CiphertextDigest       Digest                                   `json:"ciphertextDigest"`
	ArtifactObject         ObjectRef                                `json:"artifactObject"`
	CiphertextObject       ObjectRef                                `json:"ciphertextObject"`
	ClaimCommitment        Digest                                   `json:"claimCommitment"`
	EncryptionIntentDigest ParticipantOriginatedAuthorizationDigest `json:"encryptionIntentDigest"`
	// The participant's signature over its own V5 enrollment, produced here on
	// the participant's machine. It is the only enrollment material that travels;
	// everything else the coordinator re-derives from the case and the artifact.
	EnrollmentSignature []byte           `json:"enrollmentSignature"`
	Report              SubmissionReport `json:"report"`
}

// PrepareParticipantOriginatedArtifact invokes the retained public-only
// encryption engine and emits the retained submission-{a,b}.bin/json bytes into
// a participant-owned output root. It never publishes into the coordinator root
// and never writes the participant key, salt or plaintext pledge.
func PrepareParticipantOriginatedArtifact(options ParticipantOriginatedPreparationOptions) (ParticipantOriginatedPreparedArtifact, error) {
	started := time.Now()
	var prepared ParticipantOriginatedPreparedArtifact
	if !rootsDisjoint(options.BundleRoot, options.OutputRoot) ||
		!nonzeroParticipantOriginatedAuthorizationDigest(options.EncryptionIntentDigest) || !nonzero(options.SubmissionNonce) ||
		len(options.SigningKey) != ed25519.PrivateKeySize {
		return prepared, ErrParticipantOriginated
	}
	bundleStore, err := openObjectStore(options.BundleRoot, PublicCaseQuota, false)
	if err != nil {
		return prepared, err
	}
	defer bundleStore.close()
	verified, err := verifyParticipantOriginatedClientBundleStore(bundleStore, options.BundleExpectations)
	if err != nil {
		return prepared, err
	}
	identity, err := expectedParticipant(verified.manifest.Binding, verified.bundle.Role)
	if err != nil || !bytes.Equal(options.SigningKey.Public().(ed25519.PublicKey), identity.SigningPublicKey) {
		return prepared, ErrParticipantOriginated
	}
	now := options.BundleExpectations.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if options.ExpiresAtUnix <= now.Unix() || options.ExpiresAtUnix > verified.manifest.Binding.ExpiresAtUnix {
		return prepared, ErrParticipantOriginated
	}
	claimCommitment, err := ParticipantOriginatedClaimCommitment(verified.bundle, options.Pledge, options.ClaimSalt)
	if err != nil {
		return prepared, err
	}
	pledge := options.Pledge
	pledge.AuthorizationCommitment = [32]byte(options.EncryptionIntentDigest)
	pledge.PrivateMetadataCommitment = [32]byte(claimCommitment)
	params, publicKey, err := loadPublicEncryptionMaterial(bundleStore, verified.manifest.Crypto)
	if err != nil {
		return prepared, err
	}
	client, expectedCustody, err := caseExternalClient(params, publicKey, verified.manifest.Binding.ReleaseMode)
	if err != nil || client.CustodyModel() != expectedCustody ||
		Digest(client.KeyIDBytes()) != verified.manifest.Binding.PublicKeyDigest ||
		Digest(client.ParameterFingerprint()) != verified.manifest.Binding.ParameterFingerprint {
		return prepared, ErrParticipantOriginated
	}
	cipherPledge, _, err := client.EncryptPledgeForMode(pledge, fhe.IdentityFullFHE256)
	if err != nil {
		return prepared, fmt.Errorf("participant-originated encryption: %w", err)
	}
	ciphertextBytes, err := cipherPledge.MarshalBinary()
	if err != nil {
		return prepared, err
	}
	output, err := openParticipantOriginatedArtifactStore(options.OutputRoot, PublicCaseQuota, false, verified.bundle.Role)
	if err != nil {
		return prepared, err
	}
	defer output.close()
	if names, _ := output.names(); len(names) != 0 {
		return prepared, ErrStore
	}
	_, ciphertextName, manifestName, err := participantFiles(verified.bundle.Role)
	if err != nil {
		return prepared, err
	}
	ciphertextRef, err := output.create(ciphertextName, ciphertextBytes)
	if err != nil {
		return prepared, err
	}
	components, err := componentRefs(cipherPledge)
	if err != nil {
		return prepared, err
	}
	artifact := EncryptedParticipantArtifact{
		SchemaVersion: ParticipantArtifactSchema, CaseBindingDigest: verified.bundle.CaseBindingDigest,
		CaseID: verified.bundle.CaseID, AssetIdentity: verified.bundle.AssetIdentity, ParticipantID: identity.ID,
		ParticipantRole: identity.Role, PublicKeyDigest: verified.bundle.FHEPublicKeyDigest,
		ParameterProfile: verified.bundle.ParameterProfile, ParameterFingerprint: verified.bundle.ParameterFingerprint,
		CircuitDigest: verified.bundle.CircuitDigest, InputSchema: InputSchema, CiphertextObject: ciphertextRef,
		Components: components, SubmissionNonce: options.SubmissionNonce, ExpiresAtUnix: options.ExpiresAtUnix,
	}
	artifact.Signature, err = signCanonical(options.SigningKey, "MordantEncryptedParticipantArtifact/v1", artifact.signingValue())
	if err != nil {
		return prepared, err
	}
	artifactRef, _, err := output.createJSON(manifestName, artifact)
	if err != nil {
		return prepared, err
	}
	artifactDigest, _ := artifact.Digest()
	// The participant enrolls its own ciphertext into the bilateral session
	// before the artifact leaves this machine. The signing key never does.
	facts, err := EnrollmentCaseFactsFromBundle(verified.bundle)
	if err != nil {
		return prepared, err
	}
	circuitInputs, err := ParticipantCircuitSideDigest(cipherPledge)
	if err != nil {
		return prepared, err
	}
	enrollmentSignature, err := SignParticipantEnrollmentV5(facts, artifact, identity.Role, circuitInputs, options.SigningKey)
	if err != nil {
		return prepared, err
	}
	prepared = ParticipantOriginatedPreparedArtifact{
		Artifact: artifact, ArtifactDigest: artifactDigest, CiphertextDigest: ciphertextRef.Digest,
		ArtifactObject: artifactRef, CiphertextObject: ciphertextRef,
		ClaimCommitment: claimCommitment, EncryptionIntentDigest: options.EncryptionIntentDigest,
		EnrollmentSignature: enrollmentSignature,
		Report:              SubmissionReport{Duration: time.Since(started), CiphertextBytes: ciphertextRef.Length, ArtifactBytes: artifactRef.Length},
	}
	return prepared, nil
}

type ParticipantOriginatedStageObjectKind string

const (
	ParticipantOriginatedStageManifest   ParticipantOriginatedStageObjectKind = "manifest"
	ParticipantOriginatedStageCiphertext ParticipantOriginatedStageObjectKind = "ciphertext"
)

type ParticipantOriginatedStageObjectOptions struct {
	QuarantineRoot string
	Role           string
	Kind           ParticipantOriginatedStageObjectKind
	Expected       ObjectRef
	Reader         io.Reader
}

func participantOriginatedStageObjectSpec(role string, kind ParticipantOriginatedStageObjectKind) (name, otherName string, maximum, otherMaximum int64, err error) {
	_, ciphertextName, manifestName, fileErr := participantFiles(role)
	if fileErr != nil {
		return "", "", 0, 0, fileErr
	}
	switch kind {
	case ParticipantOriginatedStageManifest:
		return manifestName, ciphertextName, maxManifestBytes, participantOriginatedMaximumCiphertextBytes, nil
	case ParticipantOriginatedStageCiphertext:
		return ciphertextName, manifestName, participantOriginatedMaximumCiphertextBytes, maxManifestBytes, nil
	default:
		return "", "", 0, 0, ErrParticipantOriginated
	}
}

// StageParticipantOriginatedObject is the hardened HTTP streaming boundary.
// The server-selected role and kind derive the only accepted filename and size
// cap. The exact authenticated ObjectRef is checked before the temporary inode
// is linked into the pinned quarantine directory.
func StageParticipantOriginatedObject(options ParticipantOriginatedStageObjectOptions) (ObjectRef, error) {
	name, otherName, maximum, otherMaximum, err := participantOriginatedStageObjectSpec(options.Role, options.Kind)
	if err != nil || options.Reader == nil || options.Expected.validate(name, maximum) != nil {
		return ObjectRef{}, ErrParticipantOriginated
	}
	store, err := openParticipantOriginatedArtifactStore(options.QuarantineRoot, PublicCaseQuota, false, options.Role)
	if err != nil {
		return ObjectRef{}, err
	}
	defer store.close()
	allowed, _ := stagedArtifactAllowedNames(options.Role)
	if store.rejectUnknown(allowed) != nil {
		return ObjectRef{}, ErrParticipantOriginated
	}
	if store.exists(name) {
		return ObjectRef{}, ErrParticipantRoleOccupied
	}
	names, err := store.names()
	if err != nil {
		return ObjectRef{}, err
	}
	switch options.Kind {
	case ParticipantOriginatedStageCiphertext:
		// Ciphertext is the only legal first object. A manifest (or any other
		// entry) makes this a replay/ordering violation.
		if len(names) != 0 {
			return ObjectRef{}, ErrParticipantRoleOccupied
		}
	case ParticipantOriginatedStageManifest:
		// Manifest-last is the quarantine commit marker. It is accepted only
		// after the hardened path has already created the sole ciphertext
		// sibling as a pinned regular object.
		if len(names) != 1 || names[0] != otherName {
			return ObjectRef{}, ErrParticipantImportMismatch
		}
		if _, err := streamedObjectRef(store, otherName, otherMaximum); err != nil {
			return ObjectRef{}, err
		}
	}
	created, err := store.createFromReaderExpected(name, options.Reader, maximum, &options.Expected)
	if err != nil {
		return ObjectRef{}, err
	}
	if store.rejectUnknown(allowed) != nil {
		return ObjectRef{}, ErrParticipantOriginated
	}
	return created, nil
}

type ParticipantOriginatedArtifactExpectations struct {
	Role                          string
	CaseID                        Digest
	AssetIdentity                 Digest
	CaseBindingDigest             Digest
	SigningKeyDigest              Digest
	BundleDigest                  Digest
	EncryptionIntentDigest        ParticipantOriginatedAuthorizationDigest
	ClaimCommitment               Digest
	SubmissionNonce               Digest
	ArtifactDigest                Digest
	CiphertextDigest              Digest
	FinalEncryptedAdmissionDigest ParticipantOriginatedAuthorizationDigest
	// EnrollmentSignature is the participant's signature over its own V5
	// enrollment. It is self-authenticating: publication re-derives the
	// enrollment locally and refuses a signature that does not verify, so it is
	// never trusted for being present in an authenticated request.
	EnrollmentSignature []byte
	Now                 time.Time
}

type ParticipantOriginatedArtifactVerification struct {
	SchemaVersion                 string                                   `json:"schemaVersion"`
	Role                          string                                   `json:"role"`
	CaseID                        Digest                                   `json:"caseId"`
	AssetIdentity                 Digest                                   `json:"assetIdentity"`
	CaseBindingDigest             Digest                                   `json:"caseBindingDigest"`
	ParticipantID                 Digest                                   `json:"participantId"`
	SigningKeyDigest              Digest                                   `json:"signingKeyDigest"`
	BundleDigest                  Digest                                   `json:"bundleDigest"`
	ParameterProfile              string                                   `json:"parameterProfile"`
	ParameterFingerprint          Digest                                   `json:"parameterFingerprint"`
	FHEPublicKeyDigest            Digest                                   `json:"fhePublicKeyDigest"`
	CircuitDigest                 Digest                                   `json:"circuitDigest"`
	EncryptionIntentDigest        ParticipantOriginatedAuthorizationDigest `json:"encryptionIntentDigest"`
	ClaimCommitment               Digest                                   `json:"claimCommitment"`
	SubmissionNonce               Digest                                   `json:"submissionNonce"`
	ArtifactDigest                Digest                                   `json:"artifactDigest"`
	CiphertextDigest              Digest                                   `json:"ciphertextDigest"`
	FinalEncryptedAdmissionDigest ParticipantOriginatedAuthorizationDigest `json:"finalEncryptedAdmissionDigest"`
	ArtifactObject                ObjectRef                                `json:"artifactObject"`
	CiphertextObject              ObjectRef                                `json:"ciphertextObject"`
	ExpiresAtUnix                 int64                                    `json:"expiresAtUnix"`
	VerifiedAtUnix                int64                                    `json:"verifiedAtUnix"`
}

func (v ParticipantOriginatedArtifactVerification) Digest() (Digest, error) {
	if v.validate() != nil {
		return Digest{}, ErrParticipantOriginated
	}
	// Verification time is audit metadata, not part of the durable import
	// identity. Excluding it makes crash reconciliation stable across a later
	// authenticated retry while every case/artifact/authorization fact remains
	// bound into the digest.
	v.VerifiedAtUnix = 0
	digest, _, err := digestCanonical(v)
	return digest, err
}

// ReconcileParticipantOriginatedImport is the explicit crash-recovery read
// path. It re-verifies the staged pair against authenticated expectations and
// returns a prior completion only when the journal and both published objects
// bind to that exact stable verification digest. Ordinary Publish retries still
// return ErrParticipantImportReplay.
func ReconcileParticipantOriginatedImport(options ParticipantOriginatedPublicationOptions) (ParticipantOriginatedImportReport, error) {
	var report ParticipantOriginatedImportReport
	if options.Now.IsZero() {
		options.Now = time.Now().UTC()
	}
	expected := options.Expected
	if validateParticipantOriginatedArtifactExpectations(expected) != nil ||
		!rootsDisjoint(options.PublicRoot, options.QuarantineRoot) ||
		!rootsDisjoint(options.PublicRoot, options.JournalRoot) || !rootsDisjoint(options.QuarantineRoot, options.JournalRoot) {
		return report, ErrParticipantOriginated
	}
	journal, err := openParticipantOriginatedJournalStore(options.JournalRoot, expected.Role, expected.SubmissionNonce)
	if err != nil {
		return report, err
	}
	defer journal.close()
	admissionName, completionName, _ := participantOriginatedImportJournalNames(expected.Role)
	admission, admitted, err := readParticipantOriginatedJournal[participantOriginatedImportAdmission](journal, admissionName)
	if err != nil || !admitted || admission.SchemaVersion != ParticipantOriginatedImportAdmissionSchema ||
		admission.CaseID != expected.CaseID || admission.Role != expected.Role || admission.SubmissionNonce != expected.SubmissionNonce ||
		admission.ArtifactDigest != expected.ArtifactDigest || admission.CiphertextDigest != expected.CiphertextDigest ||
		admission.AdmittedAtUnix <= 0 || admission.AdmittedAtUnix > options.Now.Unix() {
		return report, ErrParticipantImportMismatch
	}
	completion, completed, err := readParticipantOriginatedJournal[participantOriginatedImportCompletion](journal, completionName)
	if err != nil || !completed || completion.SchemaVersion != ParticipantOriginatedImportCompletionSchema ||
		completion.VerificationDigest != admission.VerificationDigest || completion.CaseID != expected.CaseID ||
		completion.Role != expected.Role || completion.ImportedAtUnix < admission.AdmittedAtUnix ||
		completion.ImportedAtUnix > options.Now.Unix() {
		return report, ErrParticipantImportMismatch
	}
	// Re-verify at the durable admission instant, not the retry instant. This
	// permits an exact read of a completed import after artifact expiry while
	// preserving the exclusive expiry check for the original admission and for
	// every new Publish call.
	expected.Now = time.Unix(admission.AdmittedAtUnix, 0).UTC()
	verification, err := VerifyStagedParticipantOriginatedArtifact(ParticipantOriginatedVerificationOptions{
		PublicRoot: options.PublicRoot, QuarantineRoot: options.QuarantineRoot, Expected: expected,
	})
	if err != nil {
		return report, err
	}
	verificationDigest, err := verification.Digest()
	if err != nil || verificationDigest != admission.VerificationDigest ||
		completion.ArtifactObject != verification.ArtifactObject || completion.CiphertextObject != verification.CiphertextObject {
		return report, ErrParticipantImportMismatch
	}
	publicStore, err := openParticipantOriginatedArtifactStore(options.PublicRoot, PublicCaseQuota, false, expected.Role)
	if err != nil {
		return report, err
	}
	defer publicStore.close()
	artifactRef, err := streamedObjectRef(publicStore, completion.ArtifactObject.Path, maxManifestBytes)
	if err != nil || artifactRef != completion.ArtifactObject {
		return report, ErrParticipantImportMismatch
	}
	ciphertextRef, err := streamedObjectRef(publicStore, completion.CiphertextObject.Path, participantOriginatedMaximumCiphertextBytes)
	if err != nil || ciphertextRef != completion.CiphertextObject {
		return report, ErrParticipantImportMismatch
	}
	return ParticipantOriginatedImportReport{
		VerificationDigest: verificationDigest, ArtifactObject: artifactRef, CiphertextObject: ciphertextRef,
		Reconciled: true, ImportedAtUnix: completion.ImportedAtUnix,
	}, nil
}

func (v ParticipantOriginatedArtifactVerification) validate() error {
	_, ciphertextName, artifactName, err := participantFiles(v.Role)
	if err != nil || v.SchemaVersion != ParticipantOriginatedArtifactVerificationSchema ||
		!nonzero(v.CaseID, v.AssetIdentity, v.CaseBindingDigest, v.ParticipantID, v.SigningKeyDigest,
			v.BundleDigest, v.ParameterFingerprint, v.FHEPublicKeyDigest, v.CircuitDigest, v.ClaimCommitment,
			v.SubmissionNonce, v.ArtifactDigest, v.CiphertextDigest) || v.ParameterProfile != ParameterProfile ||
		!nonzeroParticipantOriginatedAuthorizationDigest(v.EncryptionIntentDigest) ||
		!nonzeroParticipantOriginatedAuthorizationDigest(v.FinalEncryptedAdmissionDigest) ||
		v.ArtifactObject.validate(artifactName, maxManifestBytes) != nil ||
		v.CiphertextObject.validate(ciphertextName, participantOriginatedMaximumCiphertextBytes) != nil ||
		v.CiphertextObject.Digest != v.CiphertextDigest ||
		v.ExpiresAtUnix <= 0 || v.VerifiedAtUnix <= 0 || v.VerifiedAtUnix >= v.ExpiresAtUnix {
		return ErrParticipantOriginated
	}
	return nil
}

type ParticipantOriginatedVerificationOptions struct {
	PublicRoot     string
	QuarantineRoot string
	Expected       ParticipantOriginatedArtifactExpectations
}

func validateParticipantOriginatedArtifactExpectations(expected ParticipantOriginatedArtifactExpectations) error {
	if expected.Now.IsZero() {
		expected.Now = time.Now().UTC()
	}
	if _, _, _, err := participantFiles(expected.Role); err != nil || !nonzero(
		expected.CaseID, expected.AssetIdentity, expected.CaseBindingDigest, expected.SigningKeyDigest,
		expected.BundleDigest, expected.ClaimCommitment, expected.SubmissionNonce, expected.ArtifactDigest, expected.CiphertextDigest,
	) || !nonzeroParticipantOriginatedAuthorizationDigest(expected.EncryptionIntentDigest) ||
		!nonzeroParticipantOriginatedAuthorizationDigest(expected.FinalEncryptedAdmissionDigest) {
		return ErrParticipantOriginated
	}
	return nil
}

func validateFreshImportedParticipant(store *objectStore, manifest FHECaseManifest, role string, pledge *fhe.CipherPledge) error {
	params, publicKey, err := loadPublicEncryptionMaterial(store, manifest.Crypto)
	if err != nil {
		return err
	}
	client, expectedCustody, err := caseExternalClient(params, publicKey, manifest.Binding.ReleaseMode)
	if err != nil || client.CustodyModel() != expectedCustody ||
		Digest(client.KeyIDBytes()) != manifest.Binding.PublicKeyDigest ||
		Digest(client.ParameterFingerprint()) != manifest.Binding.ParameterFingerprint || pledge == nil ||
		pledge.KeyID != client.KeyID() || Digest(pledge.ParameterFingerprint) != manifest.Binding.ParameterFingerprint {
		return ErrCiphertextValidation
	}
	expectedMetadata := bgv.NewPlaintext(params, params.MaxLevel()).MetaData.CopyNew()
	components := participantCiphertextComponents(pledge)
	if len(components) != len(participantCiphertextComponentNames) {
		return ErrCiphertextValidation
	}
	for _, component := range components {
		if err := validateFreshGovernedCiphertext(params, expectedMetadata, component.ciphertext); err != nil {
			return fmt.Errorf("%w: %s %s", ErrCiphertextValidation, role, component.name)
		}
	}
	return nil
}

func stagedArtifactAllowedNames(role string) (map[string]bool, error) {
	_, ciphertextName, manifestName, err := participantFiles(role)
	if err != nil {
		return nil, err
	}
	return map[string]bool{ciphertextName: true, manifestName: true}, nil
}

func participantOriginatedArtifactRecoveryPolicy(role string) (*participantTemporaryRecoveryPolicy, error) {
	if _, _, _, err := participantFiles(role); err != nil {
		return nil, err
	}
	limits := map[string]int64{
		submissionAObject:   participantOriginatedMaximumCiphertextBytes,
		submissionBObject:   participantOriginatedMaximumCiphertextBytes,
		submissionAManifest: maxManifestBytes,
		submissionBManifest: maxManifestBytes,
		enrollmentAObject:   maxManifestBytes,
		enrollmentBObject:   maxManifestBytes,
	}
	return &participantTemporaryRecoveryPolicy{
		maximum: participantOriginatedMaximumCiphertextBytes,
		targetLimit: func(name string) (int64, bool) {
			limit, ok := limits[name]
			return limit, ok
		},
	}, nil
}

func openParticipantOriginatedArtifactStore(root string, quota int64, private bool, role string) (*objectStore, error) {
	policy, err := participantOriginatedArtifactRecoveryPolicy(role)
	if err != nil {
		return nil, err
	}
	return openObjectStoreWithParticipantRecovery(root, quota, private, policy)
}

func validParticipantOriginatedNonceClaimObjectName(name string) bool {
	const prefix = "participant-originated-nonce-"
	const suffix = ".json"
	if len(name) != len(prefix)+64+len(suffix) || name[:len(prefix)] != prefix || name[len(name)-len(suffix):] != suffix {
		return false
	}
	encoded := name[len(prefix) : len(name)-len(suffix)]
	for _, value := range []byte(encoded) {
		if (value < '0' || value > '9') && (value < 'a' || value > 'f') {
			return false
		}
	}
	_, err := hex.DecodeString(encoded)
	return err == nil
}

func participantOriginatedJournalRecoveryPolicy(role string, nonce Digest) (*participantTemporaryRecoveryPolicy, error) {
	if _, _, err := participantOriginatedImportJournalNames(role); err != nil || !nonzero(nonce) {
		return nil, ErrParticipantOriginated
	}
	fixed := map[string]bool{
		"participant-a-import-admitted.json":  true,
		"participant-a-import-completed.json": true,
		"participant-b-import-admitted.json":  true,
		"participant-b-import-completed.json": true,
	}
	return &participantTemporaryRecoveryPolicy{
		maximum: maxManifestBytes,
		targetLimit: func(name string) (int64, bool) {
			return maxManifestBytes, fixed[name] || validParticipantOriginatedNonceClaimObjectName(name)
		},
	}, nil
}

func openParticipantOriginatedJournalStore(root, role string, nonce Digest) (*objectStore, error) {
	policy, err := participantOriginatedJournalRecoveryPolicy(role, nonce)
	if err != nil {
		return nil, err
	}
	return openObjectStoreWithParticipantRecovery(root, PrivateCaseQuota, true, policy)
}

// VerifyStagedParticipantOriginatedArtifact is the verify-only boundary used
// after transport authentication and before publication. It returns the opaque
// intent and salted-claim facts parsed from the exact signed CipherPledge.
func VerifyStagedParticipantOriginatedArtifact(options ParticipantOriginatedVerificationOptions) (ParticipantOriginatedArtifactVerification, error) {
	var result ParticipantOriginatedArtifactVerification
	expected := options.Expected
	if expected.Now.IsZero() {
		expected.Now = time.Now().UTC()
	}
	if validateParticipantOriginatedArtifactExpectations(expected) != nil || !rootsDisjoint(options.PublicRoot, options.QuarantineRoot) {
		return result, ErrParticipantOriginated
	}
	publicStore, err := openParticipantOriginatedArtifactStore(options.PublicRoot, PublicCaseQuota, false, expected.Role)
	if err != nil {
		return result, err
	}
	defer publicStore.close()
	manifest, err := loadCaseManifest(publicStore)
	if err != nil {
		return result, err
	}
	if _, err := loadProtectionAuthorization(publicStore, manifest.Binding); err != nil {
		return result, err
	}
	bindingDigest, _ := manifest.Binding.Digest()
	identity, err := expectedParticipant(manifest.Binding, expected.Role)
	keyDigest, keyErr := ParticipantOriginatedSigningKeyDigest(identity.SigningPublicKey)
	if err != nil || keyErr != nil || manifest.Binding.CaseID != expected.CaseID ||
		manifest.Binding.AssetIdentity != expected.AssetIdentity || bindingDigest != expected.CaseBindingDigest ||
		keyDigest != expected.SigningKeyDigest || expected.Now.Unix() < manifest.Binding.CreatedAtUnix ||
		expected.Now.Unix() >= manifest.Binding.ExpiresAtUnix {
		return result, ErrParticipantImportMismatch
	}
	quarantine, err := openParticipantOriginatedArtifactStore(options.QuarantineRoot, PublicCaseQuota, false, expected.Role)
	if err != nil {
		return result, err
	}
	defer quarantine.close()
	allowed, _ := stagedArtifactAllowedNames(expected.Role)
	if quarantine.rejectUnknown(allowed) != nil {
		return result, ErrParticipantOriginated
	}
	artifact, artifactDigest, err := loadParticipantArtifactMetadata(quarantine, manifest, expected.Role, expected.Now)
	if err != nil {
		return result, err
	}
	if artifact.ExpiresAtUnix <= expected.Now.Unix() || artifact.ExpiresAtUnix > manifest.Binding.ExpiresAtUnix {
		return result, ErrParticipantImportMismatch
	}
	_, _, artifactName, _ := participantFiles(expected.Role)
	_, artifactRef, err := quarantine.readNamed(artifactName, maxManifestBytes)
	if err != nil || artifactDigest != expected.ArtifactDigest || artifact.CiphertextObject.Digest != expected.CiphertextDigest ||
		artifact.SubmissionNonce != expected.SubmissionNonce {
		return result, ErrParticipantImportMismatch
	}
	pledge, err := loadParticipantCiphertext(quarantine, manifest, artifact)
	if err != nil {
		return result, err
	}
	if err := validateFreshImportedParticipant(publicStore, manifest, expected.Role, pledge); err != nil {
		return result, err
	}
	if ParticipantOriginatedAuthorizationDigest(pledge.AuthorizationCommitment) != expected.EncryptionIntentDigest ||
		Digest(pledge.PrivateMetadataCommitment) != expected.ClaimCommitment {
		return result, ErrParticipantImportMismatch
	}
	result = ParticipantOriginatedArtifactVerification{
		SchemaVersion: ParticipantOriginatedArtifactVerificationSchema, Role: expected.Role,
		CaseID: manifest.Binding.CaseID, AssetIdentity: manifest.Binding.AssetIdentity, CaseBindingDigest: bindingDigest,
		ParticipantID: identity.ID, SigningKeyDigest: keyDigest, BundleDigest: expected.BundleDigest,
		ParameterProfile: artifact.ParameterProfile, ParameterFingerprint: artifact.ParameterFingerprint,
		FHEPublicKeyDigest: artifact.PublicKeyDigest, CircuitDigest: artifact.CircuitDigest,
		EncryptionIntentDigest: ParticipantOriginatedAuthorizationDigest(pledge.AuthorizationCommitment), ClaimCommitment: Digest(pledge.PrivateMetadataCommitment),
		SubmissionNonce: artifact.SubmissionNonce, ArtifactDigest: artifactDigest,
		CiphertextDigest: artifact.CiphertextObject.Digest, FinalEncryptedAdmissionDigest: expected.FinalEncryptedAdmissionDigest,
		ArtifactObject: artifactRef, CiphertextObject: artifact.CiphertextObject,
		ExpiresAtUnix: artifact.ExpiresAtUnix, VerifiedAtUnix: expected.Now.Unix(),
	}
	return result, nil
}

type participantOriginatedImportAdmission struct {
	SchemaVersion      string `json:"schemaVersion"`
	VerificationDigest Digest `json:"verificationDigest"`
	CaseID             Digest `json:"caseId"`
	Role               string `json:"role"`
	SubmissionNonce    Digest `json:"submissionNonce"`
	ArtifactDigest     Digest `json:"artifactDigest"`
	CiphertextDigest   Digest `json:"ciphertextDigest"`
	AdmittedAtUnix     int64  `json:"admittedAtUnix"`
}

type participantOriginatedImportCompletion struct {
	SchemaVersion      string    `json:"schemaVersion"`
	VerificationDigest Digest    `json:"verificationDigest"`
	CaseID             Digest    `json:"caseId"`
	Role               string    `json:"role"`
	ArtifactObject     ObjectRef `json:"artifactObject"`
	CiphertextObject   ObjectRef `json:"ciphertextObject"`
	ImportedAtUnix     int64     `json:"importedAtUnix"`
}

type participantOriginatedNonceClaim struct {
	SchemaVersion      string `json:"schemaVersion"`
	VerificationDigest Digest `json:"verificationDigest"`
	CaseID             Digest `json:"caseId"`
	Role               string `json:"role"`
	SubmissionNonce    Digest `json:"submissionNonce"`
	ArtifactDigest     Digest `json:"artifactDigest"`
}

func participantOriginatedNonceClaimName(nonce Digest) string {
	return "participant-originated-nonce-" + hex.EncodeToString(nonce[:]) + ".json"
}

// claimParticipantOriginatedNonce uses the journal store's create-only object
// primitive as the case-wide nonce lock. Two roles racing on one nonce target
// the same name, so at most one distinct verification can be admitted.
func claimParticipantOriginatedNonce(store *objectStore, verificationDigest Digest, verification ParticipantOriginatedArtifactVerification) (bool, error) {
	claim := participantOriginatedNonceClaim{
		SchemaVersion: ParticipantOriginatedNonceClaimSchema, VerificationDigest: verificationDigest,
		CaseID: verification.CaseID, Role: verification.Role, SubmissionNonce: verification.SubmissionNonce,
		ArtifactDigest: verification.ArtifactDigest,
	}
	name := participantOriginatedNonceClaimName(verification.SubmissionNonce)
	if _, _, err := store.createJSON(name, claim); err == nil {
		return false, nil
	} else if !store.exists(name) {
		return false, err
	}
	existing, exists, err := readParticipantOriginatedJournal[participantOriginatedNonceClaim](store, name)
	if err != nil || !exists {
		return false, err
	}
	if existing != claim {
		return false, ErrParticipantImportReplay
	}
	return true, nil
}

func participantOriginatedImportJournalNames(role string) (admission, completion string, err error) {
	switch role {
	case RoleA:
		return "participant-a-import-admitted.json", "participant-a-import-completed.json", nil
	case RoleB:
		return "participant-b-import-admitted.json", "participant-b-import-completed.json", nil
	default:
		return "", "", ErrParticipantOriginated
	}
}

type ParticipantOriginatedPublicationOptions struct {
	PublicRoot     string
	QuarantineRoot string
	JournalRoot    string
	Expected       ParticipantOriginatedArtifactExpectations
	Now            time.Time
}

type ParticipantOriginatedImportReport struct {
	VerificationDigest Digest    `json:"verificationDigest"`
	ArtifactObject     ObjectRef `json:"artifactObject"`
	CiphertextObject   ObjectRef `json:"ciphertextObject"`
	Reconciled         bool      `json:"reconciled"`
	ImportedAtUnix     int64     `json:"importedAtUnix"`
}

func streamedObjectRef(store *objectStore, name string, maximum int64) (ObjectRef, error) {
	fd, stat, err := store.openRegular(name)
	if err != nil {
		return ObjectRef{}, err
	}
	if stat.Size <= 0 || stat.Size > maximum {
		_ = unix.Close(fd)
		return ObjectRef{}, ErrArtifact
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = unix.Close(fd)
		return ObjectRef{}, ErrStore
	}
	hash := sha256.New()
	count, readErr := io.Copy(hash, io.LimitReader(file, maximum+1))
	var after unix.Stat_t
	statErr := unix.Fstat(fd, &after)
	closeErr := file.Close()
	if readErr != nil || statErr != nil || closeErr != nil || count != stat.Size || count > maximum ||
		after.Size != stat.Size || uint64(after.Dev) != uint64(stat.Dev) || uint64(after.Ino) != uint64(stat.Ino) {
		return ObjectRef{}, ErrArtifact
	}
	var digest Digest
	copy(digest[:], hash.Sum(nil))
	return ObjectRef{Path: name, Digest: digest, Length: count}, nil
}

func publishStagedObject(destination, source *objectStore, name string, expected ObjectRef, maximum int64, allowExisting bool) (ObjectRef, error) {
	if destination.exists(name) {
		if !allowExisting {
			return ObjectRef{}, ErrParticipantRoleOccupied
		}
		actual, err := streamedObjectRef(destination, name, maximum)
		if err != nil || actual != expected {
			return ObjectRef{}, ErrParticipantImportMismatch
		}
		return actual, nil
	}
	fd, _, err := source.openRegular(name)
	if err != nil {
		return ObjectRef{}, err
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = unix.Close(fd)
		return ObjectRef{}, ErrStore
	}
	// Re-authenticate the exact digest and length while copying, before the
	// temporary inode is linked into the create-only public root. A quarantine
	// path replacement after verification must fail without poisoning the
	// destination name.
	created, createErr := destination.createFromReaderExpected(name, file, maximum, &expected)
	closeErr := file.Close()
	if createErr != nil || closeErr != nil || created != expected {
		return ObjectRef{}, ErrParticipantImportMismatch
	}
	return created, nil
}

func readParticipantOriginatedJournal[T any](store *objectStore, name string) (T, bool, error) {
	var value T
	if !store.exists(name) {
		return value, false, nil
	}
	if _, _, err := store.readJSON(name, &value); err != nil {
		return value, true, err
	}
	return value, true, nil
}

// PublishParticipantOriginatedArtifact publishes a previously verified staged
// object pair. The durable admission consumes the role/nonce before publication;
// the ciphertext is create-only first and the manifest is the final commit
// marker. A crash can resume only the exact admitted verification.
func PublishParticipantOriginatedArtifact(options ParticipantOriginatedPublicationOptions) (ParticipantOriginatedImportReport, error) {
	var report ParticipantOriginatedImportReport
	if options.Now.IsZero() {
		options.Now = time.Now().UTC()
	}
	// Publication never trusts an exported, caller-constructible verification
	// report. Re-run the full staged artifact/ciphertext/FHE/opaque-fact checks
	// against the authenticated expectations, then publish only those exact
	// object digests. This preserves a useful JSON verify-only report without
	// turning it into a bearer capability.
	expected := options.Expected
	expected.Now = options.Now
	verification, err := VerifyStagedParticipantOriginatedArtifact(ParticipantOriginatedVerificationOptions{
		PublicRoot: options.PublicRoot, QuarantineRoot: options.QuarantineRoot, Expected: expected,
	})
	if err != nil {
		return report, err
	}
	verificationDigest, err := verification.Digest()
	if err != nil || !rootsDisjoint(options.PublicRoot, options.QuarantineRoot) ||
		!rootsDisjoint(options.PublicRoot, options.JournalRoot) || !rootsDisjoint(options.QuarantineRoot, options.JournalRoot) {
		return report, ErrParticipantOriginated
	}
	publicStore, err := openParticipantOriginatedArtifactStore(options.PublicRoot, PublicCaseQuota, false, verification.Role)
	if err != nil {
		return report, err
	}
	defer publicStore.close()
	manifest, err := loadCaseManifest(publicStore)
	if err != nil {
		return report, err
	}
	if _, err := loadProtectionAuthorization(publicStore, manifest.Binding); err != nil {
		return report, err
	}
	bindingDigest, _ := manifest.Binding.Digest()
	identity, err := expectedParticipant(manifest.Binding, verification.Role)
	keyDigest, keyErr := ParticipantOriginatedSigningKeyDigest(identity.SigningPublicKey)
	if err != nil || keyErr != nil || verification.CaseID != manifest.Binding.CaseID ||
		verification.AssetIdentity != manifest.Binding.AssetIdentity || verification.CaseBindingDigest != bindingDigest ||
		verification.ParticipantID != identity.ID || verification.SigningKeyDigest != keyDigest ||
		verification.ExpiresAtUnix <= options.Now.Unix() || verification.ExpiresAtUnix > manifest.Binding.ExpiresAtUnix {
		return report, ErrParticipantImportMismatch
	}
	quarantine, err := openParticipantOriginatedArtifactStore(options.QuarantineRoot, PublicCaseQuota, false, verification.Role)
	if err != nil {
		return report, err
	}
	defer quarantine.close()
	allowed, _ := stagedArtifactAllowedNames(verification.Role)
	if quarantine.rejectUnknown(allowed) != nil {
		return report, ErrParticipantOriginated
	}
	_, ciphertextName, artifactName, _ := participantFiles(verification.Role)
	artifact, artifactDigest, err := loadParticipantArtifactMetadata(quarantine, manifest, verification.Role, options.Now)
	if err != nil {
		return report, err
	}
	artifactRef, err := streamedObjectRef(quarantine, artifactName, maxManifestBytes)
	if err != nil {
		return report, err
	}
	ciphertextRef, err := streamedObjectRef(quarantine, ciphertextName, participantOriginatedMaximumCiphertextBytes)
	if err != nil || artifactDigest != verification.ArtifactDigest || artifactRef != verification.ArtifactObject ||
		ciphertextRef != verification.CiphertextObject || artifact.CiphertextObject != ciphertextRef ||
		artifact.SubmissionNonce != verification.SubmissionNonce {
		return report, ErrParticipantImportMismatch
	}
	journal, err := openParticipantOriginatedJournalStore(options.JournalRoot, verification.Role, verification.SubmissionNonce)
	if err != nil {
		return report, err
	}
	defer journal.close()
	admissionName, completionName, _ := participantOriginatedImportJournalNames(verification.Role)
	if _, exists, err := readParticipantOriginatedJournal[participantOriginatedImportCompletion](journal, completionName); err != nil {
		return report, err
	} else if exists {
		return report, ErrParticipantImportReplay
	}
	admission := participantOriginatedImportAdmission{
		SchemaVersion: ParticipantOriginatedImportAdmissionSchema, VerificationDigest: verificationDigest,
		CaseID: verification.CaseID, Role: verification.Role, SubmissionNonce: verification.SubmissionNonce,
		ArtifactDigest: verification.ArtifactDigest, CiphertextDigest: verification.CiphertextDigest,
		AdmittedAtUnix: options.Now.Unix(),
	}
	reconciled, err := claimParticipantOriginatedNonce(journal, verificationDigest, verification)
	if err != nil {
		return report, err
	}
	otherRole := RoleA
	if verification.Role == RoleA {
		otherRole = RoleB
	}
	if existing, exists, readErr := readParticipantOriginatedJournal[participantOriginatedImportAdmission](journal, admissionName); readErr != nil {
		return report, readErr
	} else if exists {
		if existing.SchemaVersion != admission.SchemaVersion || existing.VerificationDigest != admission.VerificationDigest ||
			existing.CaseID != admission.CaseID || existing.Role != admission.Role || existing.SubmissionNonce != admission.SubmissionNonce ||
			existing.ArtifactDigest != admission.ArtifactDigest || existing.CiphertextDigest != admission.CiphertextDigest {
			return report, ErrParticipantRoleOccupied
		}
		reconciled = true
	} else if _, _, err := journal.createJSON(admissionName, admission); err != nil {
		return report, err
	}
	if otherManifest := func() string {
		_, _, name, _ := participantFiles(otherRole)
		return name
	}(); publicStore.exists(otherManifest) {
		var other EncryptedParticipantArtifact
		if _, _, err := publicStore.readJSON(otherManifest, &other); err != nil || other.SubmissionNonce == verification.SubmissionNonce {
			return report, ErrParticipantImportReplay
		}
	}
	if !reconciled && (publicStore.exists(ciphertextName) || publicStore.exists(artifactName)) {
		return report, ErrParticipantRoleOccupied
	}
	publishedCiphertext, err := publishStagedObject(publicStore, quarantine, ciphertextName, ciphertextRef,
		participantOriginatedMaximumCiphertextBytes, reconciled)
	if err != nil {
		return report, err
	}
	// The enrollment is written before the manifest for the same reason the
	// ciphertext is: manifest-last must remain the single marker that says a
	// complete, releasable participant input exists. A signature that does not
	// verify against the locally re-derived enrollment stops publication here,
	// before anything durable is committed for this role.
	facts, factsErr := EnrollmentCaseFactsFromBinding(manifest.Binding)
	if factsErr != nil {
		return report, factsErr
	}
	stagedPledge, pledgeErr := loadParticipantCiphertext(quarantine, manifest, artifact)
	if pledgeErr != nil {
		return report, pledgeErr
	}
	publishedInputs, inputsErr := ParticipantCircuitSideDigest(stagedPledge)
	if inputsErr != nil {
		return report, inputsErr
	}
	enrollmentRecord, err := AdoptParticipantEnrollmentV5(facts, artifact, artifactDigest, verification.Role, publishedInputs, expected.EnrollmentSignature)
	if err != nil {
		return report, err
	}
	enrollmentName, err := enrollmentObjectForRole(verification.Role)
	if err != nil {
		return report, err
	}
	if existing, exists, readErr := readParticipantOriginatedJournal[ParticipantEnrollmentV5](publicStore, enrollmentName); readErr != nil {
		return report, readErr
	} else if exists {
		// A reconciled retry republishes identical bytes; anything else would be
		// a second enrollment for a role that already has one.
		if existing.EnrollmentSigningDigest != enrollmentRecord.EnrollmentSigningDigest {
			return report, ErrParticipantRoleOccupied
		}
	} else if _, _, err := publicStore.createJSON(enrollmentName, enrollmentRecord); err != nil {
		return report, err
	}
	// Manifest-last is the durable commit marker observed by the unchanged
	// evaluator. A partial ciphertext alone is never a valid participant input.
	publishedArtifact, err := publishStagedObject(publicStore, quarantine, artifactName, artifactRef, maxManifestBytes, reconciled)
	if err != nil {
		return report, err
	}
	completion := participantOriginatedImportCompletion{
		SchemaVersion: ParticipantOriginatedImportCompletionSchema, VerificationDigest: verificationDigest,
		CaseID: verification.CaseID, Role: verification.Role, ArtifactObject: publishedArtifact,
		CiphertextObject: publishedCiphertext, ImportedAtUnix: options.Now.Unix(),
	}
	if _, _, err := journal.createJSON(completionName, completion); err != nil {
		return report, err
	}
	return ParticipantOriginatedImportReport{
		VerificationDigest: verificationDigest, ArtifactObject: publishedArtifact, CiphertextObject: publishedCiphertext,
		Reconciled: reconciled, ImportedAtUnix: options.Now.Unix(),
	}, nil
}
