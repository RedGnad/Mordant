// Command ceremony-client materializes exactly one synthetic pledge in its own
// process and encrypts it under the collective ceremony key.
//
// Unlike the V3 client it refuses to encrypt until it has verified the key
// manifest: it checks that every roster operator signed the exact public-key and
// evaluation-key commitments, that the operator set is the one it was told to
// expect, and that the key epoch, threshold, policy scope and validity window
// all match. A public key handed over by the evaluator alone is not enough.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
	fhe "mordant.dev/fhe-lab/lattigo"
)

type config struct {
	party, publicMaterial, manifest, evaluationKeys, issuerKey, output, privateManifest string
	rosterDigest, vault, policyID, sessionID, coverage, anchorRoot, currencyCode        string
	identityMode, assetID, enrollmentBinding                                            string
	chainID, policyVersion, nonce, validUntil, keyEpoch, windowBase                     uint64
	threshold                                                                           uint64
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "CEREMONY_CLIENT_FAILED:"+err.Error())
		os.Exit(1)
	}
	fmt.Println("CEREMONY_CLIENT_COMPLETE")
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
	client, err := fhe.NewExternalClient(material)
	if err != nil {
		return err
	}
	// The client must be encrypting under a dealerless ceremony key.
	if client.CustodyModel() != fhe.CustodyDealerlessCeremony {
		return fmt.Errorf("refusing custody model %q", client.CustodyModel())
	}
	if err := c.verifyManifest(client); err != nil {
		return err
	}

	issuer, err := readIssuerKey(c.issuerKey)
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
	anchorRoot, err := decode32(c.anchorRoot)
	if err != nil {
		return err
	}
	// The dispute session secret is shared by the two facilities and never
	// reaches the evaluator. It fixes the currency both must agree on and the
	// salt that binds both pledges to the same deployed receivable.
	shared := sharedSession{
		secret:       session,
		currencyCode: c.currencyCode,
		windowBase:   deriveWindowBase(session),
		nonce:        c.nonce,
		validUntil:   c.validUntil,
		anchorRoot:   anchorRoot,
	}
	terms, err := freshTerms(shared, c.party)
	if err != nil {
		return err
	}
	mode := fhe.IdentityMode(c.identityMode)
	pledge, claim, context, err := makePledge(c, vault, policy, shared, terms)
	if err != nil {
		return err
	}
	// In full_fhe_256 the strict stable asset identity is encrypted bit by bit
	// and there is no public link commitment at all, so nothing about the
	// receivable is testable by anyone holding only the ciphertext.
	if mode == fhe.IdentityFullFHE256 {
		assetID, assetErr := decode32(c.assetID)
		if assetErr != nil {
			return assetErr
		}
		pledge.ReceivableID = assetID
		pledge.ReceivableCommitment = [32]byte{}
	}
	if pledge.AuthorizationCommitment, err = client.SubmitterAuthorizationCommitment(claim); err != nil {
		return err
	}
	cipher, _, err := client.EncryptPledgeForMode(pledge, mode)
	if err != nil {
		return err
	}
	// The enrollment nonce carries the runner-computed binding: the opaque
	// session commitment, this side's frozen governance record, its source
	// registration, scope, policy and key epoch. The issuer signs the enrollment,
	// so the binding is authenticated and the runner can verify that both sides
	// enrolled against the same committed session.
	enrollmentNonce := sha256.Sum256(append(session[:], []byte("enrollment-"+c.party)...))
	if c.enrollmentBinding != "" {
		if enrollmentNonce, err = decode32(c.enrollmentBinding); err != nil {
			return err
		}
	}
	now := time.Now().UTC()
	enrollment, err := fhe.SignCiphertextEnrollment(
		client, cipher, mode, context, claim,
		now.Add(-time.Second), time.Unix(int64(c.validUntil), 0), enrollmentNonce, issuer,
	)
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
	// The coverage assertion is public: it names every commercial term, its
	// confidentiality class and its consuming path, and carries only digests.
	coverage, err := marshalCoverage(buildCoverage(c.party, terms, anchorRoot))
	if err != nil {
		return err
	}
	if err := writeExclusive(c.coverage, append(coverage, '\n'), 0o644); err != nil {
		return err
	}
	// Only genuinely confidential canaries go to the offline auditor.
	manifest, err := json.Marshal(scannableManifest(c.party, terms))
	if err != nil {
		return err
	}
	return writeExclusive(c.privateManifest, manifest, 0o600)
}

// verifyManifest is the client-side gate described in the mission: unknown
// operator set, wrong threshold, wrong key epoch, expired manifest, mismatched
// public key, mismatched evaluation keys and insufficient authentication all
// stop the client before any plaintext is encrypted.
func (c config) verifyManifest(client *fhe.ExternalClient) error {
	raw, err := os.ReadFile(c.manifest)
	if err != nil {
		return errors.New("key manifest unavailable")
	}
	manifest, err := fhe.UnmarshalCollectiveKeyManifest(raw)
	if err != nil {
		return err
	}
	expectedRoster, err := decode32(c.rosterDigest)
	if err != nil {
		return err
	}
	policy, err := decode32(c.policyID)
	if err != nil {
		return err
	}
	publicKeyBytes, err := client.CollectivePublicKeyBytes()
	if err != nil {
		return err
	}
	keyIDBytes := client.KeyIDBytes()
	if err := fhe.VerifyCollectiveKeyManifest(manifest, fhe.ClientKeyExpectation{
		RosterDigest:  expectedRoster,
		Threshold:     uint16(c.threshold),
		KeyEpoch:      c.keyEpoch,
		ChainID:       c.chainID,
		PolicyID:      policy,
		PolicyVersion: uint32(c.policyVersion),
		Now:           time.Now().UTC(),
	}, keyIDBytes, fhe.PublicKeyCommitmentFor(publicKeyBytes)); err != nil {
		return err
	}
	// The evaluation keys the evaluator will use must also be the ones the
	// operators signed, otherwise a substituted key set could change the circuit.
	evaluationKeyBytes, err := os.ReadFile(c.evaluationKeys)
	if err != nil {
		return errors.New("evaluation key material unavailable")
	}
	params, err := clientParameters()
	if err != nil {
		return err
	}
	relinDigest, galoisDigest, err := fhe.EvaluationKeyDigestsFrom(params, evaluationKeyBytes)
	if err != nil {
		return err
	}
	if manifest.RelinearizationKeyDigest != hex.EncodeToString(relinDigest[:]) ||
		manifest.GaloisKeyCommitment != hex.EncodeToString(galoisDigest[:]) {
		return errors.New("evaluation key commitments do not match the signed manifest")
	}
	return nil
}

func clientParameters() (bgv.Parameters, error) {
	return bgv.NewParametersFromLiteral(bgv.ParametersLiteral{
		LogN:             15,
		LogQ:             []int{60, 60, 59, 58, 58, 58, 58, 58, 58, 58, 58, 58},
		LogP:             []int{60, 60, 60},
		PlaintextModulus: 65537,
	})
}

// makePledge builds the facility's pledge from the materialised commercial
// terms. Every confidential term is placed into the pledge or into a commitment
// whose preimage stays here; nothing is generated and left unused.
func makePledge(c config, vault [20]byte, policy [32]byte, shared sharedSession, values map[string]canaryValue) (fhe.PlainPledge, fhe.AuthorizationClaim, fhe.InputCommitmentContext, error) {
	var zero fhe.PlainPledge
	var zeroClaim fhe.AuthorizationClaim
	var zeroContext fhe.InputCommitmentContext
	get := func(field string) ([32]byte, error) { return decode32(values[field].Value) }

	receivablePreimage, err := get("receivable_identifier")
	if err != nil {
		return zero, zeroClaim, zeroContext, err
	}
	// ReceivableIDBits is nil in IdentityPublicCommitment mode, so the receivable
	// identifier is protected by the public link commitment rather than by
	// encryption. The canary is the preimage of that commitment.
	receivable := sha256.Sum256(receivablePreimage[:])
	obligation, err := get("obligation_id")
	if err != nil {
		return zero, zeroClaim, zeroContext, err
	}
	metadataPreimage, err := get("exclusivity_metadata")
	if err != nil {
		return zero, zeroClaim, zeroContext, err
	}
	// PrivateMetadataCommitment is carried in cleartext by the CipherPledge, so
	// only its commitment may cross the evaluator boundary.
	metadata := sha256.Sum256(metadataPreimage[:])
	currency, err := get("currency")
	if err != nil {
		return zero, zeroClaim, zeroContext, err
	}
	// The identity and credential canaries are preimages: the evaluator receives
	// the enrollment in cleartext, so only their commitments may cross that
	// boundary.
	identityPreimage, err := get("submitter_identity")
	if err != nil {
		return zero, zeroClaim, zeroContext, err
	}
	credentialPreimage, err := get("authorization_credential")
	if err != nil {
		return zero, zeroClaim, zeroContext, err
	}
	subjectCommitment := sha256.Sum256(identityPreimage[:])
	roleCommitment := sha256.Sum256(credentialPreimage[:])

	amount, err := numericOf(values, "amount")
	if err != nil {
		return zero, zeroClaim, zeroContext, err
	}
	activeFrom, err := numericOf(values, "active_from")
	if err != nil {
		return zero, zeroClaim, zeroContext, err
	}
	activeUntil, err := numericOf(values, "active_until")
	if err != nil {
		return zero, zeroClaim, zeroContext, err
	}

	// The public receivable link binds both facilities' pledges to the same
	// deployed receivable. Its salt comes from the dispute session secret the
	// facilities share, so the link cannot be tested against a guessed invoice
	// root by anyone who lacks that secret, including the evaluator.
	linkSalt := sha256.Sum256(append(append([]byte{}, shared.secret[:]...), []byte("receivable-link-salt")...))
	// Both facilities derive the same link because they share the dispute session
	// secret and reference the same deployed receivable.
	linkReceivable := sha256.Sum256(append(append([]byte{}, shared.secret[:]...), shared.anchorRoot[:]...))
	link := fhe.ReceivableLinkCommitment(vault, uint32(c.policyVersion), linkReceivable, linkSalt)

	slot := uint8(0)
	if c.party == "b" {
		slot = 1
	}
	claim := fhe.AuthorizationClaim{
		SubjectCommitment: subjectCommitment,
		Role:              roleCommitment,
		Vault:             vault, PolicyID: policy, PolicyVersion: uint32(c.policyVersion),
		ValidUntil: shared.validUntil, Nonce: fhe.Uint256{0, 0, 0, shared.nonce*2 + uint64(slot) + 1},
	}
	context := fhe.InputCommitmentContext{
		ChainID: fhe.Uint256{0, 0, 0, c.chainID}, Vault: vault, PolicyID: policy,
		PolicyVersion: uint32(c.policyVersion), InputSlot: slot,
		ClientNonce: fhe.Uint256{0, 0, 0, shared.nonce*2 + uint64(slot) + 1},
	}
	return fhe.PlainPledge{
		ActiveFrom: activeFrom, ActiveUntil: activeUntil,
		Amount:       fhe.Uint256{0, 0, 0, amount},
		Currency:     currency,
		ObligationID: obligation, ReceivableID: receivable, Exclusive: true,
		ReceivableCommitment: link, PrivateMetadataCommitment: metadata,
	}, claim, context, nil
}

func numericOf(values map[string]canaryValue, field string) (uint64, error) {
	entry, present := values[field]
	if !present || entry.Numeric == "" {
		return 0, errors.New("missing numeric term: " + field)
	}
	parsed, err := strconv.ParseUint(entry.Numeric, 10, 64)
	if err != nil {
		return 0, err
	}
	return parsed, nil
}
