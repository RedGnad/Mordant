//go:build obsolete_recoverable_ceremony

package thresholdnet

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
	spike "mordant.dev/fhe-lab/lattigo"
)

func recoveryLedgerFixture(t *testing.T) (bgv.Parameters, spike.CeremonyRoster, []ed25519.PrivateKey) {
	t.Helper()
	params, err := bgv.NewParametersFromLiteral(bgv.ParametersLiteral{
		LogN: 15, LogQ: []int{60, 60, 59, 58, 58, 58, 58, 58, 58, 58, 58, 58},
		LogP: []int{60, 60, 60}, PlaintextModulus: 65537,
	})
	if err != nil {
		t.Fatal(err)
	}
	parameterBytes, err := params.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	keys := make([]ed25519.PrivateKey, 3)
	identities := make([]spike.CeremonyOperatorIdentity, 3)
	for index := range keys {
		_, keys[index], err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		identities[index].Point = uint64(index + 1)
		copy(identities[index].SigningPublicKey[:], keys[index].Public().(ed25519.PublicKey))
	}
	return params, spike.CeremonyRoster{
		ParameterFingerprint: sha256.Sum256(parameterBytes), Threshold: 2,
		CeremonyID: sha256.Sum256([]byte(t.Name())), KeyEpoch: 1, Operators: identities,
	}, keys
}

func TestCeremonyPrivateLedgerRecoversExactCachedOperation(t *testing.T) {
	params, roster, keys := recoveryLedgerFixture(t)
	directory := filepath.Join(t.TempDir(), "operator-ledger")
	ledger, err := OpenCeremonyPrivateLedger(directory, params, roster, 1, keys[0])
	if err != nil {
		t.Fatal(err)
	}
	contribution := ledger.State().CRSContribution()
	payload := []byte("canonical-request")
	response := append([]byte("public-response:"), contribution[:]...)
	if err := ledger.CommitOperation(OpContribution, payload, response, "contribution-generated", nil); err != nil {
		t.Fatal(err)
	}
	count := ledger.CheckpointCount()
	if err := ledger.CommitOperation(OpContribution, payload, response, "retry", nil); err != nil {
		t.Fatal(err)
	}
	if ledger.CheckpointCount() != count {
		t.Fatal("an exact retry appended a duplicate checkpoint")
	}

	reopened, err := OpenCeremonyPrivateLedger(directory, params, roster, 1, keys[0])
	if err != nil {
		t.Fatal(err)
	}
	if reopened.State().CRSContribution() != contribution {
		t.Fatal("reopen regenerated the contribution")
	}
	cached, present, err := reopened.Cached(OpContribution, payload)
	if err != nil || !present || !bytes.Equal(cached, response) {
		t.Fatalf("exact response was not recovered: present=%t err=%v", present, err)
	}
	if reopened.CheckpointCount() != count {
		t.Fatal("reopen changed the checkpoint sequence")
	}
	info, err := os.Stat(directory)
	if err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("private ledger directory mode = %v, err=%v", info.Mode().Perm(), err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != int(count) {
		t.Fatalf("checkpoint listing: %d %v", len(entries), err)
	}
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("checkpoint %s mode = %v, err=%v", entry.Name(), info.Mode().Perm(), err)
		}
	}
	first, err := readCeremonyLedgerCapsule(filepath.Join(directory, ceremonyLedgerFilename(1)))
	if err != nil || len(first.State) != 0 || first.StateDigest == ([32]byte{}) {
		t.Fatalf("historical state was not safely compacted: state=%d err=%v", len(first.State), err)
	}
}

func TestCeremonyPrivateLedgerCachesCompletedReshareAcrossEndpointChanges(t *testing.T) {
	params, roster, keys := recoveryLedgerFixture(t)
	directory := filepath.Join(t.TempDir(), "operator-ledger")
	ledger, err := OpenCeremonyPrivateLedger(directory, params, roster, 1, keys[0])
	if err != nil {
		t.Fatal(err)
	}
	firstPayload, err := EncodePeerEndpoints([]PeerEndpoint{
		{Point: 1, URL: "https://127.0.0.1:41001"},
		{Point: 2, URL: "https://127.0.0.1:41002"},
		{Point: 3, URL: "https://127.0.0.1:41003"},
	})
	if err != nil {
		t.Fatal(err)
	}
	response := []byte{3}
	if err := ledger.CommitOperation(OpReshare, firstPayload, response, "recipients=3", nil); err != nil {
		t.Fatal(err)
	}
	count := ledger.CheckpointCount()
	secondPayload, err := EncodePeerEndpoints([]PeerEndpoint{
		{Point: 1, URL: "https://127.0.0.1:42001"},
		{Point: 2, URL: "https://127.0.0.1:42002"},
		{Point: 3, URL: "https://127.0.0.1:42003"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := ledger.CommitOperation(OpReshare, secondPayload, response, "retry", nil); err != nil {
		t.Fatal(err)
	}
	if ledger.CheckpointCount() != count {
		t.Fatal("changed transport endpoints duplicated a completed re-sharing checkpoint")
	}

	reopened, err := OpenCeremonyPrivateLedger(directory, params, roster, 1, keys[0])
	if err != nil {
		t.Fatal(err)
	}
	cached, present, err := reopened.CachedReshare()
	if err != nil || !present || !bytes.Equal(cached, response) {
		t.Fatalf("completed re-sharing response was not recovered: present=%t err=%v", present, err)
	}
	if err := reopened.CommitOperation(OpReshare, secondPayload, []byte{2}, "drift", nil); !errors.Is(err, ErrCeremonyLedger) {
		t.Fatalf("re-sharing response drift was accepted: %v", err)
	}
}

func TestCeremonyServerRequiresExactCanonicalReshareRoster(t *testing.T) {
	params, roster, keys := recoveryLedgerFixture(t)
	state, err := spike.NewCeremonyOperatorState(params, roster, 1, keys[0])
	if err != nil {
		t.Fatal(err)
	}
	server := &CeremonyServer{State: state}
	valid, err := EncodePeerEndpoints([]PeerEndpoint{
		{Point: 3, URL: "https://127.0.0.1:3"},
		{Point: 1, URL: "https://127.0.0.1:1"},
		{Point: 2, URL: "https://127.0.0.1:2"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := server.peerEndpointsForRoster(valid); err != nil {
		t.Fatalf("canonical roster was rejected: %v", err)
	}
	for name, endpoints := range map[string][]PeerEndpoint{
		"missing":     {{Point: 1, URL: "https://127.0.0.1:1"}, {Point: 2, URL: "https://127.0.0.1:2"}},
		"duplicate":   {{Point: 1, URL: "https://127.0.0.1:1"}, {Point: 1, URL: "https://127.0.0.1:2"}, {Point: 3, URL: "https://127.0.0.1:3"}},
		"substituted": {{Point: 1, URL: "https://127.0.0.1:1"}, {Point: 2, URL: "https://127.0.0.1:2"}, {Point: 4, URL: "https://127.0.0.1:4"}},
	} {
		t.Run(name, func(t *testing.T) {
			payload, err := EncodePeerEndpoints(endpoints)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := server.peerEndpointsForRoster(payload); !errors.Is(err, ErrCeremonyRequest) {
				t.Fatalf("non-canonical roster was accepted: %v", err)
			}
		})
	}
}

func TestCeremonyServerResumesCompletedReshareWithoutRedial(t *testing.T) {
	params, roster, keys := recoveryLedgerFixture(t)
	ledger, err := OpenCeremonyPrivateLedger(filepath.Join(t.TempDir(), "operator-ledger"), params, roster, 1, keys[0])
	if err != nil {
		t.Fatal(err)
	}
	endpoints := func(portBase int) []byte {
		t.Helper()
		payload, err := EncodePeerEndpoints([]PeerEndpoint{
			{Point: 1, URL: fmt.Sprintf("https://127.0.0.1:%d", portBase+1)},
			{Point: 2, URL: fmt.Sprintf("https://127.0.0.1:%d", portBase+2)},
			{Point: 3, URL: fmt.Sprintf("https://127.0.0.1:%d", portBase+3)},
		})
		if err != nil {
			t.Fatal(err)
		}
		return payload
	}
	if err := ledger.CommitOperation(OpReshare, endpoints(41000), []byte{3}, "recipients=3", nil); err != nil {
		t.Fatal(err)
	}
	count := ledger.CheckpointCount()
	dials := 0
	server := &CeremonyServer{
		State:    ledger.State(),
		Recovery: ledger,
		PeerDialer: func(uint64, string) (*http.Client, error) {
			dials++
			return nil, errors.New("completed re-sharing must not dial")
		},
	}
	response, err := server.step(context.Background(), ceremonyRequest{Operation: OpReshare, Payload: endpoints(42000)})
	if err != nil || !bytes.Equal(response, []byte{3}) {
		t.Fatalf("semantic re-sharing retry failed: response=%x err=%v", response, err)
	}
	if dials != 0 || ledger.CheckpointCount() != count {
		t.Fatalf("completed re-sharing was repeated: dials=%d checkpoints=%d", dials, ledger.CheckpointCount())
	}
}

func TestCeremonyPrivateLedgerPersistsFinalDigestsAndBundle(t *testing.T) {
	params, roster, keys := recoveryLedgerFixture(t)
	directory := filepath.Join(t.TempDir(), "operator-ledger")
	ledger, err := OpenCeremonyPrivateLedger(directory, params, roster, 1, keys[0])
	if err != nil {
		t.Fatal(err)
	}
	var digests spike.CeremonyKeyDigests
	values := []*[32]byte{&digests.CRSCommitment, &digests.PublicKeyCommitment, &digests.RelinearizationKeyDigest,
		&digests.GaloisKeyCommitment, &digests.PolicyCircuitCommitment}
	payload := make([]byte, 0, 160)
	for index, target := range values {
		*target = sha256.Sum256([]byte{byte(index + 1)})
		payload = append(payload, target[:]...)
	}
	bundle := []byte("operator-private-sealed-bundle")
	response := []byte("manifest-signature")
	if err := ledger.CommitOperation(OpSealManifest, payload, response, "manifest-sealed", bundle); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenCeremonyPrivateLedger(directory, params, roster, 1, keys[0])
	if err != nil {
		t.Fatal(err)
	}
	observed, present, err := reopened.FinalKeyDigests()
	if err != nil || !present || observed != digests {
		t.Fatalf("final key digests were not recovered: present=%t err=%v", present, err)
	}
	observedBundle, present, err := reopened.SealedBundle()
	if err != nil || !present || !bytes.Equal(observedBundle, bundle) {
		t.Fatalf("sealed bundle was not recovered: present=%t err=%v", present, err)
	}
}

func TestCeremonyPrivateLedgerFailsClosedOnDriftAndCorruption(t *testing.T) {
	params, roster, keys := recoveryLedgerFixture(t)
	newLedger := func(t *testing.T) string {
		t.Helper()
		directory := filepath.Join(t.TempDir(), "operator-ledger")
		ledger, err := OpenCeremonyPrivateLedger(directory, params, roster, 1, keys[0])
		if err != nil {
			t.Fatal(err)
		}
		if err := ledger.SaveState("durable-boundary"); err != nil {
			t.Fatal(err)
		}
		return directory
	}
	t.Run("ceremony identifier", func(t *testing.T) {
		directory := newLedger(t)
		changed := roster
		changed.CeremonyID = sha256.Sum256([]byte("substituted"))
		if _, err := OpenCeremonyPrivateLedger(directory, params, changed, 1, keys[0]); !errors.Is(err, ErrCeremonyLedger) {
			t.Fatalf("mixed ceremony state was accepted: %v", err)
		}
	})
	t.Run("checkpoint bytes", func(t *testing.T) {
		directory := newLedger(t)
		path := filepath.Join(directory, ceremonyLedgerFilename(2))
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		raw[len(raw)-1] ^= 1
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenCeremonyPrivateLedger(directory, params, roster, 1, keys[0]); !errors.Is(err, ErrCeremonyLedger) {
			t.Fatalf("corrupted checkpoint was accepted: %v", err)
		}
	})
	t.Run("checkpoint gap", func(t *testing.T) {
		directory := newLedger(t)
		if err := os.Rename(filepath.Join(directory, ceremonyLedgerFilename(2)), filepath.Join(directory, ceremonyLedgerFilename(3))); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenCeremonyPrivateLedger(directory, params, roster, 1, keys[0]); !errors.Is(err, ErrCeremonyLedger) {
			t.Fatalf("checkpoint gap was accepted: %v", err)
		}
	})
	t.Run("unexpected entry", func(t *testing.T) {
		directory := newLedger(t)
		if err := os.WriteFile(filepath.Join(directory, "foreign-share.bin"), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenCeremonyPrivateLedger(directory, params, roster, 1, keys[0]); !errors.Is(err, ErrCeremonyLedger) {
			t.Fatalf("unknown operator state was accepted: %v", err)
		}
	})
}
