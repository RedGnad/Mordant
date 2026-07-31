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
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
	fhe "mordant.dev/fhe-lab/lattigo"
)

type config struct {
	party, publicMaterial, manifest, evaluationKeys, issuerKey, output, privateManifest string
	rosterDigest, vault, policyID, sessionID                                            string
	chainID, policyVersion, nonce, validUntil, keyEpoch                                 uint64
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
	canaries, err := freshCanaries()
	if err != nil {
		return err
	}
	pledge, claim, context, err := makePledge(c, vault, policy, session, canaries)
	if err != nil {
		return err
	}
	if pledge.AuthorizationCommitment, err = client.SubmitterAuthorizationCommitment(claim); err != nil {
		return err
	}
	cipher, _, err := client.EncryptPledgeForMode(pledge, fhe.IdentityPublicCommitment)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	enrollment, err := fhe.SignCiphertextEnrollment(
		client, cipher, fhe.IdentityPublicCommitment, context, claim,
		now.Add(-time.Second), time.Unix(int64(c.validUntil), 0),
		sha256.Sum256(append(session[:], []byte("enrollment-"+c.party)...)), issuer,
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
	return writeCanaryManifest(c.privateManifest, c.party, canaries)
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

// makePledge builds the synthetic pledge. Every field that the audit treats as
// a confidential term is a fresh high-entropy canary actually placed into the
// encrypted pledge, so a canary sweep is meaningful for all of them.
func makePledge(c config, vault [20]byte, policy, session [32]byte, values map[string]string) (fhe.PlainPledge, fhe.AuthorizationClaim, fhe.InputCommitmentContext, error) {
	var zero fhe.PlainPledge
	invoice, err := decode32(values["invoice_identifier"])
	if err != nil {
		return zero, fhe.AuthorizationClaim{}, fhe.InputCommitmentContext{}, err
	}
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
	// Currency must match across both claims for the frozen policy to find a
	// conflict, so it is derived from a shared session secret rather than a
	// per-client canary. It is still not a repository constant.
	currency := sha256.Sum256(append(session[:], []byte("shared-currency")...))
	linkSalt := sha256.Sum256(append(session[:], []byte("public-receivable-link")...))
	link := fhe.ReceivableLinkCommitment(vault, uint32(c.policyVersion), sha256.Sum256(append(session[:], []byte("receivable")...)), linkSalt)
	slot := uint8(0)
	if c.party == "b" {
		slot = 1
	}
	// Amounts and active periods are drawn from the client's own canary bytes so
	// that they are genuinely client-private, while still producing the strict
	// interval overlap the policy needs.
	amountCanary, err := decode32(values["amount"])
	if err != nil {
		return zero, fhe.AuthorizationClaim{}, fhe.InputCommitmentContext{}, err
	}
	periodCanary, err := decode32(values["active_periods"])
	if err != nil {
		return zero, fhe.AuthorizationClaim{}, fhe.InputCommitmentContext{}, err
	}
	amount := 500_000 + (uint64(amountCanary[0])<<8|uint64(amountCanary[1]))%400_000
	// Strict overlap is preserved for every canary draw: A spans [100, 400+s]
	// and B spans [200+s, 500] with s < 50, so a.from < b.until and b.from < a.until.
	spread := uint64(periodCanary[0]) % 50
	from, until := uint64(200)+spread, uint64(500)
	if c.party == "a" {
		from, until = uint64(100), uint64(400)+spread
	}
	claim := fhe.AuthorizationClaim{
		SubjectCommitment: authSubject,
		Role:              sha256.Sum256([]byte("mordant.role.authorized-submitter.v1")),
		Vault:             vault, PolicyID: policy, PolicyVersion: uint32(c.policyVersion),
		ValidUntil: c.validUntil, Nonce: fhe.Uint256{0, 0, 0, c.nonce*2 + uint64(slot) + 1},
	}
	context := fhe.InputCommitmentContext{
		ChainID: fhe.Uint256{0, 0, 0, c.chainID}, Vault: vault, PolicyID: policy,
		PolicyVersion: uint32(c.policyVersion), InputSlot: slot,
		ClientNonce: fhe.Uint256{0, 0, 0, c.nonce*2 + uint64(slot) + 1},
	}
	return fhe.PlainPledge{
		ActiveFrom: from, ActiveUntil: until,
		Amount:       fhe.Uint256{0, 0, 0, amount},
		Currency:     currency,
		ObligationID: obligation, ReceivableID: invoice, Exclusive: true,
		ReceivableCommitment: link, PrivateMetadataCommitment: metadata,
	}, claim, context, nil
}
