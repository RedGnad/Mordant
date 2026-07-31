// Command ceremony-coordinator drives the dealerless key ceremony.
//
// It aggregates public protocol shares and writes public artifacts. It holds no
// RLWE secret, no Shamir share and no operator identity key. The private
// re-sharing round travels operator-to-operator and never crosses this process:
// the only thing this command learns about that round is how many recipients
// each operator served.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
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
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
	fhe "mordant.dev/fhe-lab/lattigo"
	"mordant.dev/fhe-lab/lattigo/internal/thresholdnet"
)

type options struct {
	mode           string
	storage        string
	certificate    string
	peerCA         string
	roster         string
	operators      string
	out            string
	chainID        uint64
	policyID       string
	validitySecond int64
}

type rosterFile struct {
	ParameterFingerprint string   `json:"parameterFingerprint"`
	Threshold            uint16   `json:"threshold"`
	CeremonyID           string   `json:"ceremonyId"`
	KeyEpoch             uint64   `json:"keyEpoch"`
	Points               []uint64 `json:"points"`
	SigningPublicKeys    []string `json:"signingPublicKeys"`
}

// ceremonyEvidence is the coordinator's public record. Operator state inside it
// is copied verbatim from each operator's own authenticated status endpoint, so
// it is an operator-authored statement rather than a coordinator constant.
type ceremonyEvidence struct {
	SchemaVersion       string            `json:"schemaVersion"`
	LattigoVersion      string            `json:"lattigoVersion"`
	CustodyModel        string            `json:"custodyModel"`
	CeremonyID          string            `json:"ceremonyId"`
	KeyEpoch            uint64            `json:"keyEpoch"`
	RosterDigest        string            `json:"rosterDigest"`
	Threshold           uint16            `json:"threshold"`
	CRSCommitment       string            `json:"crsCommitment"`
	CRSDerivation       string            `json:"crsDerivation"`
	KeyID               string            `json:"keyId"`
	PublicKeyBytes      int               `json:"publicKeyBytes"`
	EvaluationKeyBytes  int               `json:"evaluationKeyBytes"`
	GaloisElements      []uint64          `json:"galoisElements"`
	RoundDurationMillis map[string]int64  `json:"roundDurationMillis"`
	OperatorStatus      []json.RawMessage `json:"operatorStatus"`
	PrivateShareChannel string            `json:"privateShareChannel"`
	CoordinatorHolds    []string          `json:"coordinatorHoldsOnly"`
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "CEREMONY_COORDINATOR_FAILED:"+err.Error())
		os.Exit(1)
	}
	fmt.Println("CEREMONY_COORDINATOR_COMPLETE")
}

func run(arguments []string) error {
	settings, err := parseOptions(arguments)
	if err != nil {
		return err
	}
	if settings.mode == "identity" {
		return generateIdentity(settings.storage)
	}
	return conduct(settings)
}

func generateIdentity(storage string) error {
	if err := os.MkdirAll(storage, 0o700); err != nil {
		return err
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(storage, "identity.key"), private, 0o600); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(storage, "identity.pub"), public, 0o644)
}

func conduct(settings options) error {
	signingKey, err := os.ReadFile(filepath.Join(settings.storage, "identity.key"))
	if err != nil || len(signingKey) != ed25519.PrivateKeySize {
		return errors.New("invalid coordinator identity")
	}
	params, err := bgv.NewParametersFromLiteral(bgv.ParametersLiteral{
		LogN:             15,
		LogQ:             []int{60, 60, 59, 58, 58, 58, 58, 58, 58, 58, 58, 58},
		LogP:             []int{60, 60, 60},
		PlaintextModulus: 65537,
	})
	if err != nil {
		return err
	}
	roster, err := loadRoster(settings.roster)
	if err != nil {
		return err
	}
	endpoints, err := parseOperators(settings.operators)
	if err != nil {
		return err
	}
	certificate, err := loadCertificate(settings.certificate, ed25519.PrivateKey(signingKey))
	if err != nil {
		return err
	}
	caBytes, err := os.ReadFile(settings.peerCA)
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caBytes) {
		return errors.New("invalid CA")
	}
	clients := make(map[uint64]*thresholdnet.CeremonyClient, len(endpoints))
	for point, url := range endpoints {
		transport := &http.Transport{
			TLSClientConfig: thresholdnet.ClientTLSConfig(certificate, roots, fmt.Sprintf("node%d.local", point)),
		}
		clients[point] = &thresholdnet.CeremonyClient{
			BaseURL:    url,
			HTTPClient: &http.Client{Transport: transport, Timeout: 10 * time.Minute},
			SigningKey: ed25519.PrivateKey(signingKey),
		}
	}
	points := sortedPoints(endpoints)
	aggregator, err := fhe.NewCeremonyAggregator(params, roster)
	if err != nil {
		return err
	}
	ctx := context.Background()
	durations := map[string]int64{}
	timed := func(name string, action func() error) error {
		started := time.Now()
		if err := action(); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		durations[name] = time.Since(started).Milliseconds()
		return nil
	}

	// Round 1: collect public CRS contributions and hand the full table back so
	// every operator derives the identical stream.
	contributions := make(map[uint64][32]byte, len(points))
	if err := timed("crs-contributions", func() error {
		for _, point := range points {
			raw, err := clients[point].Step(ctx, thresholdnet.OpContribution, nil)
			if err != nil {
				return err
			}
			if len(raw) != 32 {
				return errors.New("invalid contribution")
			}
			var value [32]byte
			copy(value[:], raw)
			contributions[point] = value
			if err := aggregator.AcceptCRSContribution(point, value); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return err
	}
	table := thresholdnet.EncodeCRSContributions(contributions)
	if err := timed("crs-seal", func() error {
		if err := aggregator.SealCRS(); err != nil {
			return err
		}
		for _, point := range points {
			raw, err := clients[point].Step(ctx, thresholdnet.OpSealCRS, table)
			if err != nil {
				return err
			}
			if len(raw) != 32 || !bytes.Equal(raw, commitmentBytes(aggregator.CRSCommitment())) {
				return fmt.Errorf("operator %d derived a different CRS", point)
			}
		}
		return nil
	}); err != nil {
		return err
	}

	// Round 2: instruct each operator to push its Shamir re-sharing directly to
	// its peers. The payload below is a public address book, not a share.
	peerTable, err := thresholdnet.EncodePeerEndpoints(peerEndpoints(endpoints))
	if err != nil {
		return err
	}
	if err := timed("private-reshare", func() error {
		for _, point := range points {
			raw, err := clients[point].Step(ctx, thresholdnet.OpReshare, peerTable)
			if err != nil {
				return err
			}
			if len(raw) != 1 || int(raw[0]) != len(points) {
				return fmt.Errorf("operator %d served %v recipients", point, raw)
			}
		}
		for _, point := range points {
			if _, err := clients[point].Step(ctx, thresholdnet.OpSealShares, nil); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return err
	}

	// Round 3: collective public key.
	if err := timed("collective-public-key", func() error {
		for _, point := range points {
			wire, err := clients[point].Step(ctx, thresholdnet.OpPublicKeyShare, nil)
			if err != nil {
				return err
			}
			if err := aggregator.AcceptPublicKeyShare(point, wire); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return err
	}

	// Rounds 4 and 5: two-round collective relinearization key.
	if err := timed("relinearization-key", func() error {
		for _, point := range points {
			wire, err := clients[point].Step(ctx, thresholdnet.OpRelinOne, nil)
			if err != nil {
				return err
			}
			if err := aggregator.AcceptRelinearizationShareRoundOne(point, wire); err != nil {
				return err
			}
		}
		combined, err := aggregator.AggregatedRelinearizationRoundOne()
		if err != nil {
			return err
		}
		for _, point := range points {
			wire, err := clients[point].Step(ctx, thresholdnet.OpRelinTwo, combined)
			if err != nil {
				return err
			}
			if err := aggregator.AcceptRelinearizationShareRoundTwo(point, wire); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return err
	}

	// Round 6: one collective Galois key per circuit rotation.
	if err := timed("galois-keys", func() error {
		for {
			element, pending := aggregator.CurrentGaloisElement()
			if !pending {
				return nil
			}
			var encoded [8]byte
			binary.BigEndian.PutUint64(encoded[:], element)
			for _, point := range points {
				wire, err := clients[point].Step(ctx, thresholdnet.OpGalois, encoded[:])
				if err != nil {
					return err
				}
				if err := aggregator.AcceptGaloisShare(point, wire); err != nil {
					return err
				}
			}
		}
	}); err != nil {
		return err
	}

	publicKey, relinKey, galoisKeys, err := aggregator.CollectiveKeys()
	if err != nil {
		return err
	}
	keyID, err := fhe.CollectiveKeyID(publicKey)
	if err != nil {
		return err
	}
	policyID, err := decodeHex32(settings.policyID)
	if err != nil {
		return err
	}
	digests, err := aggregator.KeyDigests(policyID, fhe.PolicyVersion)
	if err != nil {
		return err
	}

	// Publish the key epoch so each operator can bind its own sealed bundle to
	// it, then collect the attestations.
	if err := publishKeyEpoch(ctx, certificate, roots, endpoints, keyID); err != nil {
		return err
	}
	attestations := make([]fhe.CeremonyAttestation, 0, len(points))
	if err := timed("seal-manifest", func() error {
		payload := thresholdnet.EncodeKeyDigests(digests)
		for _, point := range points {
			raw, err := clients[point].Step(ctx, thresholdnet.OpSealManifest, payload)
			if err != nil {
				return err
			}
			if len(raw) != ed25519.SignatureSize {
				return errors.New("invalid attestation")
			}
			attestation := fhe.CeremonyAttestation{Point: point}
			copy(attestation.Signature[:], raw)
			attestations = append(attestations, attestation)
		}
		return nil
	}); err != nil {
		return err
	}
	if err := fhe.VerifyCeremonyAttestations(roster, digests, attestations); err != nil {
		return err
	}

	now := time.Now().UTC()
	manifest, err := fhe.BuildCollectiveKeyManifest(
		roster, digests, attestations, keyID, settings.chainID, policyID, fhe.PolicyVersion,
		now.Add(-time.Minute), now.Add(time.Duration(settings.validitySecond)*time.Second),
	)
	if err != nil {
		return err
	}

	// Public artifacts. Only public material is written here; the coordinator
	// has no secret to leak into them.
	runtime, err := fhe.NewEvaluationRuntime(params, publicKey, relinKey, galoisKeys)
	if err != nil {
		return err
	}
	material, err := runtime.ExportPublicEncryptionMaterial()
	if err != nil {
		return err
	}
	evaluationKeys, err := fhe.MarshalEvaluationKeys(relinKey, galoisKeys, aggregator.GaloisElements())
	if err != nil {
		return err
	}
	if err := os.MkdirAll(settings.out, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(settings.out, "collective-public-material.bin"), material, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(settings.out, "collective-evaluation-keys.bin"), evaluationKeys, 0o644); err != nil {
		return err
	}
	manifestBytes, err := fhe.MarshalCollectiveKeyManifest(manifest)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(settings.out, "key-manifest.json"), manifestBytes, 0o644); err != nil {
		return err
	}

	// Independent operator evidence: read each operator's own account.
	statuses := make([]json.RawMessage, 0, len(points))
	for _, point := range points {
		raw, err := clients[point].CeremonyStatus(ctx)
		if err != nil {
			return err
		}
		statuses = append(statuses, json.RawMessage(bytes.TrimSpace(raw)))
	}
	rosterDigest := roster.Digest()
	evidence := ceremonyEvidence{
		SchemaVersion:  "mordant.dealerless-ceremony-evidence/4",
		LattigoVersion: fhe.LattigoVersion,
		CustodyModel:   string(fhe.CustodyDealerlessCeremony),
		CeremonyID:     hex.EncodeToString(roster.CeremonyID[:]),
		KeyEpoch:       roster.KeyEpoch,
		RosterDigest:   hex.EncodeToString(rosterDigest[:]),
		Threshold:      roster.Threshold,
		CRSCommitment:  hex.EncodeToString(commitmentBytes(aggregator.CRSCommitment())),
		CRSDerivation: "collaborative: sha256(domain, rosterDigest, parameterFingerprint, ceremonyId, keyEpoch, " +
			"each operator contribution in point order); no fixed kill-test seed",
		KeyID:               hex.EncodeToString(keyID[:]),
		PublicKeyBytes:      len(material),
		EvaluationKeyBytes:  len(evaluationKeys),
		GaloisElements:      aggregator.GaloisElements(),
		RoundDurationMillis: durations,
		OperatorStatus:      statuses,
		PrivateShareChannel: "operator-to-operator mTLS with pinned roster keys; coordinator excluded",
		CoordinatorHolds: []string{
			"public protocol shares", "collective public key", "collective evaluation keys",
			"public commitments", "operator attestations",
		},
	}
	encoded, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(settings.out, "ceremony-evidence.json"), append(encoded, '\n'), 0o644)
}

func publishKeyEpoch(ctx context.Context, certificate tls.Certificate, roots *x509.CertPool, endpoints map[uint64]string, keyID [32]byte) error {
	for point, url := range endpoints {
		transport := &http.Transport{
			TLSClientConfig: thresholdnet.ClientTLSConfig(certificate, roots, fmt.Sprintf("node%d.local", point)),
		}
		client := &http.Client{Transport: transport, Timeout: time.Minute}
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, url+"/v1/key-epoch", bytes.NewReader(keyID[:]))
		if err != nil {
			return err
		}
		response, err := client.Do(request)
		if err != nil {
			return err
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1024))
		_ = response.Body.Close()
		if response.StatusCode != http.StatusNoContent {
			return fmt.Errorf("operator %d rejected the key epoch: %d", point, response.StatusCode)
		}
	}
	return nil
}

func commitmentBytes(value [32]byte) []byte { return value[:] }

func peerEndpoints(endpoints map[uint64]string) []thresholdnet.PeerEndpoint {
	out := make([]thresholdnet.PeerEndpoint, 0, len(endpoints))
	for point, url := range endpoints {
		out = append(out, thresholdnet.PeerEndpoint{Point: point, URL: url})
	}
	return out
}

func sortedPoints(endpoints map[uint64]string) []uint64 {
	points := make([]uint64, 0, len(endpoints))
	for point := range endpoints {
		points = append(points, point)
	}
	sort.Slice(points, func(i, j int) bool { return points[i] < points[j] })
	return points
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
	if len(endpoints) < 2 {
		return nil, errors.New("invalid operator endpoints")
	}
	return endpoints, nil
}

func loadRoster(path string) (fhe.CeremonyRoster, error) {
	var roster fhe.CeremonyRoster
	raw, err := os.ReadFile(path)
	if err != nil {
		return roster, err
	}
	var file rosterFile
	if err := json.Unmarshal(raw, &file); err != nil {
		return roster, err
	}
	fingerprint, err := decodeHex32(file.ParameterFingerprint)
	if err != nil {
		return roster, err
	}
	ceremonyID, err := decodeHex32(file.CeremonyID)
	if err != nil {
		return roster, err
	}
	operators := make([]fhe.CeremonyOperatorIdentity, len(file.Points))
	for index, encoded := range file.SigningPublicKeys {
		raw, err := hex.DecodeString(strings.TrimPrefix(encoded, "0x"))
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return roster, errors.New("invalid roster key")
		}
		operators[index] = fhe.CeremonyOperatorIdentity{Point: file.Points[index]}
		copy(operators[index].SigningPublicKey[:], raw)
	}
	return fhe.CeremonyRoster{
		ParameterFingerprint: fingerprint,
		Threshold:            file.Threshold,
		CeremonyID:           ceremonyID,
		KeyEpoch:             file.KeyEpoch,
		Operators:            operators,
	}, nil
}

func loadCertificate(certificatePath string, signingKey ed25519.PrivateKey) (tls.Certificate, error) {
	certificatePEM, err := os.ReadFile(certificatePath)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(signingKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return tls.X509KeyPair(certificatePEM, keyPEM)
}

func decodeHex32(value string) ([32]byte, error) {
	var out [32]byte
	raw, err := hex.DecodeString(strings.TrimPrefix(value, "0x"))
	if err != nil || len(raw) != 32 {
		return out, errors.New("invalid 32-byte hex")
	}
	copy(out[:], raw)
	return out, nil
}

func parseOptions(arguments []string) (options, error) {
	var settings options
	flags := flag.NewFlagSet("ceremony-coordinator", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&settings.mode, "mode", "conduct", "identity or conduct")
	flags.StringVar(&settings.storage, "storage", "", "coordinator identity directory")
	flags.StringVar(&settings.certificate, "tls-cert", "", "CA-issued coordinator certificate")
	flags.StringVar(&settings.peerCA, "peer-ca", "", "CA trusted for operators")
	flags.StringVar(&settings.roster, "roster", "", "public ceremony roster")
	flags.StringVar(&settings.operators, "operators", "", "point=url,point=url,...")
	flags.StringVar(&settings.out, "out", "", "public artifact directory")
	flags.Uint64Var(&settings.chainID, "chain-id", 0, "policy scope chain id")
	flags.StringVar(&settings.policyID, "policy-id", "", "policy id")
	flags.Int64Var(&settings.validitySecond, "validity-seconds", 3600, "manifest validity")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || settings.storage == "" {
		return options{}, errors.New("invalid ceremony-coordinator configuration")
	}
	if settings.mode == "identity" {
		return settings, nil
	}
	if settings.certificate == "" || settings.peerCA == "" || settings.roster == "" ||
		settings.operators == "" || settings.out == "" || settings.chainID == 0 || settings.policyID == "" {
		return options{}, errors.New("invalid ceremony-coordinator configuration")
	}
	return settings, nil
}
