package lattigospike

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// CollectiveKeyManifest is the public, jointly authenticated description of one
// ceremony's output. A client verifies it before encrypting anything, so it
// never has to trust a public key handed to it by the evaluator alone.
type CollectiveKeyManifest struct {
	SchemaVersion            string   `json:"schemaVersion"`
	LattigoVersion           string   `json:"lattigoVersion"`
	CustodyModel             string   `json:"custodyModel"`
	ParameterFingerprint     string   `json:"parameterFingerprint"`
	Threshold                uint16   `json:"threshold"`
	CeremonyID               string   `json:"ceremonyId"`
	KeyEpoch                 uint64   `json:"keyEpoch"`
	RosterDigest             string   `json:"rosterDigest"`
	Operators                []string `json:"operators"`
	OperatorPoints           []uint64 `json:"operatorPoints"`
	ChainID                  uint64   `json:"chainId"`
	PolicyID                 string   `json:"policyId"`
	PolicyVersion            uint32   `json:"policyVersion"`
	KeyID                    string   `json:"keyId"`
	CRSCommitment            string   `json:"crsCommitment"`
	PublicKeyCommitment      string   `json:"publicKeyCommitment"`
	RelinearizationKeyDigest string   `json:"relinearizationKeyCommitment"`
	GaloisKeyCommitment      string   `json:"galoisKeyCommitment"`
	PolicyCircuitCommitment  string   `json:"policyCircuitCommitment"`
	ActivatesAtUnix          int64    `json:"activatesAtUnix"`
	ExpiresAtUnix            int64    `json:"expiresAtUnix"`
	Revoked                  bool     `json:"revoked"`
	Attestations             []string `json:"attestations"`
}

// LattigoVersion is the pinned multiparty implementation this ceremony ran on.
const LattigoVersion = "github.com/tuneinsight/lattigo/v6 v6.2.0"

// CollectiveKeyManifestSchema identifies the manifest wire format.
const CollectiveKeyManifestSchema = "mordant.collective-key-manifest/4"

var (
	// ErrManifestRejected is returned when a client refuses a key manifest.
	ErrManifestRejected = errors.New("collective key manifest rejected")
)

// BuildCollectiveKeyManifest assembles the public manifest from the ceremony
// output and the operator attestations. It is written by the ceremony
// coordinator, which holds no secret material.
func BuildCollectiveKeyManifest(
	roster CeremonyRoster,
	digests CeremonyKeyDigests,
	attestations []CeremonyAttestation,
	keyID [32]byte,
	chainID uint64,
	policyID [32]byte,
	policyVersion uint32,
	activatesAt, expiresAt time.Time,
) (CollectiveKeyManifest, error) {
	if err := VerifyCeremonyAttestations(roster, digests, attestations); err != nil {
		return CollectiveKeyManifest{}, err
	}
	if expiresAt.Before(activatesAt) || expiresAt.IsZero() || activatesAt.IsZero() {
		return CollectiveKeyManifest{}, ErrManifestRejected
	}
	rosterDigest := roster.Digest()
	operators := make([]string, len(roster.Operators))
	points := make([]uint64, len(roster.Operators))
	for index, operator := range roster.Operators {
		operators[index] = hex.EncodeToString(operator.SigningPublicKey[:])
		points[index] = operator.Point
	}
	signatures := make([]string, 0, len(attestations))
	for _, operator := range roster.Operators {
		for _, attestation := range attestations {
			if attestation.Point == operator.Point {
				signatures = append(signatures, fmt.Sprintf("%d:%s", attestation.Point, hex.EncodeToString(attestation.Signature[:])))
			}
		}
	}
	return CollectiveKeyManifest{
		SchemaVersion:            CollectiveKeyManifestSchema,
		LattigoVersion:           LattigoVersion,
		CustodyModel:             string(CustodyDealerlessCeremony),
		ParameterFingerprint:     hex.EncodeToString(roster.ParameterFingerprint[:]),
		Threshold:                roster.Threshold,
		CeremonyID:               hex.EncodeToString(roster.CeremonyID[:]),
		KeyEpoch:                 roster.KeyEpoch,
		RosterDigest:             hex.EncodeToString(rosterDigest[:]),
		Operators:                operators,
		OperatorPoints:           points,
		ChainID:                  chainID,
		PolicyID:                 hex.EncodeToString(policyID[:]),
		PolicyVersion:            policyVersion,
		KeyID:                    hex.EncodeToString(keyID[:]),
		CRSCommitment:            hex.EncodeToString(digests.CRSCommitment[:]),
		PublicKeyCommitment:      hex.EncodeToString(digests.PublicKeyCommitment[:]),
		RelinearizationKeyDigest: hex.EncodeToString(digests.RelinearizationKeyDigest[:]),
		GaloisKeyCommitment:      hex.EncodeToString(digests.GaloisKeyCommitment[:]),
		PolicyCircuitCommitment:  hex.EncodeToString(digests.PolicyCircuitCommitment[:]),
		ActivatesAtUnix:          activatesAt.Unix(),
		ExpiresAtUnix:            expiresAt.Unix(),
		Revoked:                  false,
		Attestations:             signatures,
	}, nil
}

// ClientKeyExpectation is what a client independently knows before it sees any
// manifest: which operator set, which threshold, which key epoch and which
// policy scope it is willing to encrypt for. Everything else is checked against
// the manifest itself.
type ClientKeyExpectation struct {
	RosterDigest  [32]byte
	Threshold     uint16
	KeyEpoch      uint64
	ChainID       uint64
	PolicyID      [32]byte
	PolicyVersion uint32
	Now           time.Time
}

// VerifyCollectiveKeyManifest is the client-side gate. It reconstructs the
// roster from the manifest, requires an attestation from every operator over
// the exact key commitments, and checks that the public material the client is
// about to encrypt under is the material those operators signed.
//
// A public key supplied by the evaluator without matching operator signatures
// is refused here, which is what stops an evaluator-substituted key.
func VerifyCollectiveKeyManifest(
	manifest CollectiveKeyManifest,
	expectation ClientKeyExpectation,
	publicMaterialKeyID [32]byte,
	publicKeyCommitment [32]byte,
) error {
	if manifest.SchemaVersion != CollectiveKeyManifestSchema ||
		manifest.LattigoVersion != LattigoVersion ||
		manifest.CustodyModel != string(CustodyDealerlessCeremony) {
		return fmt.Errorf("%w: schema or custody model", ErrManifestRejected)
	}
	if manifest.Revoked {
		return fmt.Errorf("%w: revoked", ErrManifestRejected)
	}
	if manifest.Threshold != expectation.Threshold {
		return fmt.Errorf("%w: threshold %d", ErrManifestRejected, manifest.Threshold)
	}
	if manifest.KeyEpoch != expectation.KeyEpoch {
		return fmt.Errorf("%w: key epoch %d", ErrManifestRejected, manifest.KeyEpoch)
	}
	if manifest.ChainID != expectation.ChainID || manifest.PolicyVersion != expectation.PolicyVersion ||
		manifest.PolicyID != hex.EncodeToString(expectation.PolicyID[:]) {
		return fmt.Errorf("%w: policy scope", ErrManifestRejected)
	}
	now := expectation.Now.Unix()
	if now < manifest.ActivatesAtUnix || now > manifest.ExpiresAtUnix {
		return fmt.Errorf("%w: outside activation window", ErrManifestRejected)
	}
	roster, digests, err := manifest.reconstruct()
	if err != nil {
		return err
	}
	rosterDigest := roster.Digest()
	if rosterDigest != expectation.RosterDigest {
		return fmt.Errorf("%w: unknown operator set", ErrManifestRejected)
	}
	if manifest.RosterDigest != hex.EncodeToString(rosterDigest[:]) {
		return fmt.Errorf("%w: roster digest", ErrManifestRejected)
	}
	attestations, err := manifest.parseAttestations()
	if err != nil {
		return err
	}
	if err := VerifyCeremonyAttestations(roster, digests, attestations); err != nil {
		return fmt.Errorf("%w: %v", ErrManifestRejected, err)
	}
	// Bind the signed commitments to the concrete public material in hand.
	if manifest.KeyID != hex.EncodeToString(publicMaterialKeyID[:]) {
		return fmt.Errorf("%w: public key id", ErrManifestRejected)
	}
	if digests.PublicKeyCommitment != publicKeyCommitment {
		return fmt.Errorf("%w: public key commitment", ErrManifestRejected)
	}
	return nil
}

func (manifest CollectiveKeyManifest) reconstruct() (CeremonyRoster, CeremonyKeyDigests, error) {
	var roster CeremonyRoster
	var digests CeremonyKeyDigests
	if len(manifest.Operators) != len(manifest.OperatorPoints) || len(manifest.Operators) == 0 {
		return roster, digests, fmt.Errorf("%w: operator set", ErrManifestRejected)
	}
	fingerprint, err := decodeManifestDigest(manifest.ParameterFingerprint)
	if err != nil {
		return roster, digests, err
	}
	ceremonyID, err := decodeManifestDigest(manifest.CeremonyID)
	if err != nil {
		return roster, digests, err
	}
	identities := make([]CeremonyOperatorIdentity, len(manifest.Operators))
	for index, encoded := range manifest.Operators {
		raw, decodeErr := hex.DecodeString(encoded)
		if decodeErr != nil || len(raw) != ed25519.PublicKeySize {
			return roster, digests, fmt.Errorf("%w: operator key", ErrManifestRejected)
		}
		identities[index] = CeremonyOperatorIdentity{Point: manifest.OperatorPoints[index]}
		copy(identities[index].SigningPublicKey[:], raw)
	}
	roster = CeremonyRoster{
		ParameterFingerprint: fingerprint,
		Threshold:            manifest.Threshold,
		CeremonyID:           ceremonyID,
		KeyEpoch:             manifest.KeyEpoch,
		Operators:            identities,
	}
	if err := roster.validate(); err != nil {
		return roster, digests, fmt.Errorf("%w: %v", ErrManifestRejected, err)
	}
	for target, encoded := range map[*[32]byte]string{
		&digests.CRSCommitment:            manifest.CRSCommitment,
		&digests.PublicKeyCommitment:      manifest.PublicKeyCommitment,
		&digests.RelinearizationKeyDigest: manifest.RelinearizationKeyDigest,
		&digests.GaloisKeyCommitment:      manifest.GaloisKeyCommitment,
		&digests.PolicyCircuitCommitment:  manifest.PolicyCircuitCommitment,
	} {
		value, decodeErr := decodeManifestDigest(encoded)
		if decodeErr != nil {
			return roster, digests, decodeErr
		}
		*target = value
	}
	return roster, digests, nil
}

func (manifest CollectiveKeyManifest) parseAttestations() ([]CeremonyAttestation, error) {
	attestations := make([]CeremonyAttestation, 0, len(manifest.Attestations))
	for _, encoded := range manifest.Attestations {
		var point uint64
		var signatureHex string
		if _, err := fmt.Sscanf(encoded, "%d:%s", &point, &signatureHex); err != nil {
			return nil, fmt.Errorf("%w: attestation format", ErrManifestRejected)
		}
		raw, err := hex.DecodeString(signatureHex)
		if err != nil || len(raw) != ed25519.SignatureSize {
			return nil, fmt.Errorf("%w: attestation signature", ErrManifestRejected)
		}
		attestation := CeremonyAttestation{Point: point}
		copy(attestation.Signature[:], raw)
		attestations = append(attestations, attestation)
	}
	return attestations, nil
}

func decodeManifestDigest(encoded string) ([32]byte, error) {
	var digest [32]byte
	raw, err := hex.DecodeString(encoded)
	if err != nil || len(raw) != 32 {
		return digest, fmt.Errorf("%w: digest encoding", ErrManifestRejected)
	}
	copy(digest[:], raw)
	return digest, nil
}

// MarshalCollectiveKeyManifest writes the canonical manifest bytes.
func MarshalCollectiveKeyManifest(manifest CollectiveKeyManifest) ([]byte, error) {
	var out bytes.Buffer
	encoder := json.NewEncoder(&out)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(manifest); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// UnmarshalCollectiveKeyManifest reads a manifest emitted by the ceremony.
func UnmarshalCollectiveKeyManifest(data []byte) (CollectiveKeyManifest, error) {
	var manifest CollectiveKeyManifest
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return CollectiveKeyManifest{}, fmt.Errorf("%w: %v", ErrManifestRejected, err)
	}
	return manifest, nil
}

// PublicKeyCommitmentFor recomputes the commitment a client compares against
// the manifest, from the public key it actually holds.
func PublicKeyCommitmentFor(publicKeyBytes []byte) [32]byte {
	return domainDigest(ceremonyPublicKeyDomain, publicKeyBytes)
}

// EvaluationKeyCommitments recomputes the relinearization and Galois
// commitments from evaluation-key material, so a verifier that holds the keys
// can confirm they are the ones the operators signed.
func EvaluationKeyCommitments(relinearizationKeyBytes []byte, galoisKeyBytes [][]byte, galoisElements []uint64) ([32]byte, [32]byte, error) {
	var relinDigest, galoisDigest [32]byte
	if len(galoisKeyBytes) != len(galoisElements) {
		return relinDigest, galoisDigest, ErrCeremonyMaterial
	}
	relinDigest = domainDigest(ceremonyRelinDomain, relinearizationKeyBytes)
	hash := sha256.New()
	_, _ = hash.Write([]byte(ceremonyGaloisDomain))
	for index, encoded := range galoisKeyBytes {
		var element [8]byte
		value := galoisElements[index]
		for byteIndex := 0; byteIndex < 8; byteIndex++ {
			element[byteIndex] = byte(value >> (56 - 8*byteIndex))
		}
		_, _ = hash.Write(element[:])
		digest := sha256.Sum256(encoded)
		_, _ = hash.Write(digest[:])
	}
	copy(galoisDigest[:], hash.Sum(nil))
	return relinDigest, galoisDigest, nil
}
