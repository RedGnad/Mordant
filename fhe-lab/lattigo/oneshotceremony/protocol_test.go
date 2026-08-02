package oneshotceremony

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/multiparty"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

type ceremonyFixture struct {
	t                 *testing.T
	params            bgv.Parameters
	context           Context
	participants      []*Participant
	signingKeys       []ed25519.PrivateKey
	encryptionKey     []*ecdh.PrivateKey
	stores            []*WitnessStore
	storage           []*OperatorStorageCapability
	storageConfigs    []OperatorLocalStorageConfig
	abortAfterStaging bool
}

type ceremonyResult struct {
	fixture      *ceremonyFixture
	bundle       PublicBundle
	sealed       []SealedOperatorBundle
	shareNeedles [][]byte
	receipt      PublicationReceipt
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("test-only random failure") }

func testParameters(t *testing.T) bgv.Parameters {
	t.Helper()
	params, err := bgv.NewParametersFromLiteral(bgv.ParametersLiteral{
		LogN:             10,
		Q:                []uint64{0x3fffffa8001, 0x1000090001, 0x10000c8001, 0x10000f0001, 0xffff00001},
		P:                []uint64{0x7fffffd8001},
		PlaintextModulus: 0x101,
	})
	if err != nil {
		t.Fatalf("parameters: %v", err)
	}
	return params
}

func digestLabel(label string) [32]byte { return sha256.Sum256([]byte(label)) }

func strictTempPath(t *testing.T, name string) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("resolve temporary directory: %v", err)
	}
	return filepath.Join(root, name)
}

func newFixture(t *testing.T, seed string) *ceremonyFixture {
	t.Helper()
	params := testParameters(t)
	startup, err := CurrentExecutableProvenance()
	if err != nil {
		t.Fatalf("measure test operator executable: %v", err)
	}
	signingKeys := make([]ed25519.PrivateKey, PartyCount)
	encryptionKeys := make([]*ecdh.PrivateKey, PartyCount)
	operators := make([]OperatorIdentity, PartyCount)
	storageConfigs := make([]OperatorLocalStorageConfig, PartyCount)
	curve := ecdh.X25519()
	for index := 0; index < PartyCount; index++ {
		edSeed := digestLabel(fmt.Sprintf("%s/signing/%d", seed, index))
		signingKeys[index] = ed25519.NewKeyFromSeed(edSeed[:])
		xSeed := digestLabel(fmt.Sprintf("%s/encryption/%d", seed, index))
		key, err := curve.NewPrivateKey(xSeed[:])
		if err != nil {
			t.Fatalf("x25519 key: %v", err)
		}
		encryptionKeys[index] = key
		operators[index] = OperatorIdentity{
			Point:                    uint64(index + 1),
			AdministratorID:          fmt.Sprintf("administrator-%d", index+1),
			TransportCertFingerprint: digestLabel(fmt.Sprintf("%s/transport/%d", seed, index)),
			RuntimeBinaryDigest:      startup.ExecutableSHA256,
			GoVersion:                startup.GoVersion,
			OperatingSystem:          startup.OperatingSystem,
			Architecture:             startup.Architecture,
		}
		copy(operators[index].SigningPublicKey[:], signingKeys[index].Public().(ed25519.PublicKey))
		copy(operators[index].EncryptionPublicKey[:], key.PublicKey().Bytes())
		storageConfigs[index] = OperatorLocalStorageConfig{
			StateRoot:       strictTempPath(t, fmt.Sprintf("operator-%d-state", index+1)),
			StorageIdentity: digestLabel(fmt.Sprintf("%s/storage/%d", seed, index)),
			Identity:        operators[index],
			ProcessInstance: fmt.Sprintf("%s/operator-%d-process", seed, index+1),
			BootSession:     fmt.Sprintf("%s/operator-%d-boot", seed, index+1),
		}
		operators[index].StorageBindingDigest, err = DeriveOperatorStorageBinding(
			storageConfigs[index].StateRoot, storageConfigs[index].StorageIdentity, operators[index])
		if err != nil {
			t.Fatalf("storage binding %d: %v", index+1, err)
		}
		storageConfigs[index].Identity = operators[index]
	}
	galois := params.GaloisElementForColRotation(1)
	context, err := NewContext(params, Context{
		PrivacyDomain:         digestLabel(seed + "/privacy-domain"),
		ServiceID:             digestLabel("private-conflict-checking"),
		ServiceVersion:        1,
		SessionIdentity:       digestLabel(seed + "/session-identity"),
		SessionCommitment:     digestLabel(seed + "/session-commitment"),
		Nonce:                 digestLabel(seed + "/nonce"),
		AttemptOrdinal:        1,
		ChainID:               31337,
		PolicyID:              digestLabel("policy"),
		PolicyVersion:         5,
		CircuitVersion:        5,
		CircuitDigest:         digestLabel("circuit"),
		ReleaseLayout:         5,
		MaximumReleaseQueries: 1,
		GaloisElements:        []uint64{galois},
		ActivatesAtUnix:       1_800_000_000,
		ExpiresAtUnix:         1_800_003_600,
		SourceCommit:          startup.SourceRevision,
		Operators:             operators,
	})
	if err != nil {
		t.Fatalf("context: %v", err)
	}
	storage := make([]*OperatorStorageCapability, PartyCount)
	for index := range storage {
		storage[index], err = OpenOperatorStorageCapability(storageConfigs[index])
		if err != nil {
			t.Fatalf("operator storage %d: %v", index+1, err)
		}
	}
	return newFixtureForContext(t, params, context, signingKeys, encryptionKeys, storage, storageConfigs)
}

func newFixtureForContext(t *testing.T, params bgv.Parameters, context Context, signingKeys []ed25519.PrivateKey, encryptionKeys []*ecdh.PrivateKey, storage []*OperatorStorageCapability, storageConfigs []OperatorLocalStorageConfig) *ceremonyFixture {
	t.Helper()
	participants := make([]*Participant, PartyCount)
	if len(storage) != PartyCount {
		t.Fatal("three operator storage capabilities required")
	}
	for index := range participants {
		participant, err := NewParticipant(params, context, signingKeys[index], encryptionKeys[index], storage[index], cryptorand.Reader)
		if err != nil {
			t.Fatalf("participant %d: %v", index+1, err)
		}
		participants[index] = participant
	}
	return &ceremonyFixture{
		t:              t,
		params:         params,
		context:        context,
		participants:   participants,
		signingKeys:    signingKeys,
		encryptionKey:  encryptionKeys,
		stores:         []*WitnessStore{storage[0].witness, storage[1].witness, storage[2].witness},
		storage:        storage,
		storageConfigs: storageConfigs,
	}
}

func (f *ceremonyFixture) heads() []ReplicaHeadAttestation {
	f.t.Helper()
	heads := make([]ReplicaHeadAttestation, PartyCount)
	for index, participant := range f.participants {
		var err error
		heads[index], err = participant.AttestReplicaHead()
		if err != nil {
			f.t.Fatalf("attest replica head %d: %v", index+1, err)
		}
	}
	return heads
}

func (f *ceremonyFixture) reserveAndStart() {
	f.reserveAndWitnessStart()
	heads := f.heads()
	for _, participant := range f.participants {
		if err := participant.BeginSecrets(heads); err != nil {
			f.t.Fatalf("begin secrets: %v", err)
		}
	}
}

func (f *ceremonyFixture) reserveAndWitnessStart() {
	heads := f.heads()
	for index, participant := range f.participants {
		if err := participant.Reserve(heads); err != nil {
			f.t.Fatalf("reserve %d: %v", index+1, err)
		}
	}
	reservations := make([]AttemptReservation, PartyCount)
	for index, participant := range f.participants {
		reservation, err := participant.Reservation()
		if err != nil {
			f.t.Fatal(err)
		}
		reservations[index] = reservation
	}
	for _, participant := range f.participants {
		if err := participant.AcceptReservations(reservations); err != nil {
			f.t.Fatalf("accept reservations: %v", err)
		}
	}
	f.transition(PhaseReserved, [32]byte{}, f.participants)
	f.transition(PhaseRunning, [32]byte{}, f.participants)
}

func (f *ceremonyFixture) transition(to Phase, reason [32]byte, participants []*Participant) WitnessRecord {
	f.t.Helper()
	statement, err := participants[0].ProposedTransition(to, reason)
	if err != nil {
		f.t.Fatalf("propose phase %d: %v", to, err)
	}
	signatures := make([]WitnessSignature, len(participants))
	heads := f.heads()
	for index, participant := range participants {
		if signatures[index], err = participant.SignTransition(statement, heads); err != nil {
			f.t.Fatalf("sign phase %d operator %d: %v", to, participant.Point(), err)
		}
	}
	record, err := AssembleWitnessRecord(f.context, statement, signatures)
	if err != nil {
		f.t.Fatalf("assemble phase %d: %v", to, err)
	}
	for _, participant := range participants {
		if err := participant.CommitTransition(record); err != nil {
			f.t.Fatalf("commit phase %d operator %d: %v", to, participant.Point(), err)
		}
	}
	return record
}

func envelopes(t *testing.T, participants []*Participant, makeEnvelope func(*Participant) (SignedEnvelope, error)) []SignedEnvelope {
	t.Helper()
	result := make([]SignedEnvelope, len(participants))
	for index, participant := range participants {
		var err error
		if result[index], err = makeEnvelope(participant); err != nil {
			t.Fatalf("operator %d envelope: %v", participant.Point(), err)
		}
	}
	return result
}

func verifyThresholdShareCorrespondence(t *testing.T, fixture *ceremonyFixture, publicKeyBytes []byte) {
	t.Helper()
	points := make([]multiparty.ShamirPublicPoint, PartyCount)
	for index, operator := range fixture.context.Operators {
		points[index] = multiparty.ShamirPublicPoint(operator.Point)
	}
	active := points[:Threshold]
	collective := rlwe.NewSecretKey(fixture.params)
	for index := 0; index < Threshold; index++ {
		combiner := multiparty.NewCombiner(fixture.params, points[index], points, Threshold)
		additive := rlwe.NewSecretKey(fixture.params)
		if err := combiner.GenAdditiveShare(active, points[index], fixture.participants[index].thresholdShare, additive); err != nil {
			t.Fatalf("threshold share %d: %v", index+1, err)
		}
		fixture.params.RingQP().Add(collective.Value, additive.Value, collective.Value)
	}
	oneCombiner := multiparty.NewCombiner(fixture.params, points[0], points, Threshold)
	if err := oneCombiner.GenAdditiveShare(points[:1], points[0], fixture.participants[0].thresholdShare, rlwe.NewSecretKey(fixture.params)); err == nil {
		t.Fatal("one operator reconstructed a threshold secret")
	}
	publicKey := rlwe.NewPublicKey(fixture.params)
	if err := publicKey.UnmarshalBinary(publicKeyBytes); err != nil {
		t.Fatalf("public key parse: %v", err)
	}
	values := make([]uint64, fixture.params.MaxSlots())
	values[0] = 73
	plaintext := bgv.NewPlaintext(fixture.params, fixture.params.MaxLevel())
	encoder := bgv.NewEncoder(fixture.params)
	if err := encoder.Encode(values, plaintext); err != nil {
		t.Fatalf("encode correspondence probe: %v", err)
	}
	ciphertext, err := rlwe.NewEncryptor(fixture.params, publicKey).EncryptNew(plaintext)
	if err != nil {
		t.Fatalf("encrypt correspondence probe: %v", err)
	}
	decoded := make([]uint64, fixture.params.MaxSlots())
	if err := encoder.Decode(rlwe.NewDecryptor(fixture.params, collective).DecryptNew(ciphertext), decoded); err != nil {
		t.Fatalf("decrypt correspondence probe: %v", err)
	}
	if decoded[0] != values[0] {
		t.Fatalf("threshold shares do not correspond to reconstructed public key: got %d", decoded[0])
	}
}

func (f *ceremonyFixture) runSuccess() ceremonyResult {
	f.reserveAndStart()
	heads := f.heads()
	commits := envelopes(f.t, f.participants, func(p *Participant) (SignedEnvelope, error) { return p.CRSCommitEnvelope(heads) })
	for _, participant := range f.participants {
		if err := participant.AcceptCRSCommitStage(commits); err != nil {
			f.t.Fatal(err)
		}
	}
	f.transition(PhaseCRSCommitted, [32]byte{}, f.participants)

	heads = f.heads()
	reveals := envelopes(f.t, f.participants, func(p *Participant) (SignedEnvelope, error) { return p.CRSRevealEnvelope(heads) })
	for _, participant := range f.participants {
		if err := participant.AcceptCRSRevealStage(reveals, heads); err != nil {
			f.t.Fatal(err)
		}
	}
	f.transition(PhaseCRSRevealed, [32]byte{}, f.participants)

	privateMessages := make([]SealedPrivateMessage, 0, PartyCount*PartyCount)
	heads = f.heads()
	for _, participant := range f.participants {
		messages, err := participant.PrivateMessages(heads)
		if err != nil {
			f.t.Fatal(err)
		}
		privateMessages = append(privateMessages, messages...)
	}
	receiptByPair := make(map[[2]uint64]SignedEnvelope, PartyCount*PartyCount)
	heads = f.heads()
	for _, participant := range f.participants {
		receipts, err := participant.ReceivePrivateMessages(privateMessages, heads)
		if err != nil {
			f.t.Fatal(err)
		}
		for _, receipt := range receipts {
			sender, recipient, _, parseErr := parsePrivateReceipt(receipt.Payload)
			if parseErr != nil {
				f.t.Fatal(parseErr)
			}
			receiptByPair[[2]uint64{sender, recipient}] = receipt
		}
	}
	receipts := make([]SignedEnvelope, 0, PartyCount*PartyCount)
	for _, sender := range f.context.Operators {
		for _, recipient := range f.context.Operators {
			receipts = append(receipts, receiptByPair[[2]uint64{sender.Point, recipient.Point}])
		}
	}
	for _, participant := range f.participants {
		if err := participant.AcceptPrivateStage(privateMessages, receipts); err != nil {
			f.t.Fatal(err)
		}
	}
	f.transition(PhasePrivateShares, [32]byte{}, f.participants)

	heads = f.heads()
	pkShares := envelopes(f.t, f.participants, func(p *Participant) (SignedEnvelope, error) { return p.PublicKeyShareEnvelope(heads) })
	for _, participant := range f.participants {
		if err := participant.AcceptPublicKeyStage(pkShares, heads); err != nil {
			f.t.Fatal(err)
		}
	}
	f.transition(PhasePublicKey, [32]byte{}, f.participants)

	heads = f.heads()
	relinOne := envelopes(f.t, f.participants, func(p *Participant) (SignedEnvelope, error) { return p.RelinRoundOneEnvelope(heads) })
	for _, participant := range f.participants {
		if err := participant.AcceptRelinRoundOneStage(relinOne, heads); err != nil {
			f.t.Fatal(err)
		}
	}
	f.transition(PhaseRelinOne, [32]byte{}, f.participants)

	heads = f.heads()
	relinTwo := envelopes(f.t, f.participants, func(p *Participant) (SignedEnvelope, error) { return p.RelinRoundTwoEnvelope(heads) })
	for _, participant := range f.participants {
		if err := participant.AcceptRelinRoundTwoStage(relinTwo, heads); err != nil {
			f.t.Fatal(err)
		}
	}
	f.transition(PhaseRelinTwo, [32]byte{}, f.participants)

	for index := range f.context.GaloisElements {
		heads = f.heads()
		shares := envelopes(f.t, f.participants, func(p *Participant) (SignedEnvelope, error) { return p.GaloisShareEnvelope(index, heads) })
		for _, participant := range f.participants {
			if err := participant.AcceptGaloisStage(index, shares, heads); err != nil {
				f.t.Fatal(err)
			}
		}
		f.transition(PhaseGalois, [32]byte{}, f.participants)
	}

	heads = f.heads()
	material, err := f.participants[0].PublicMaterial(heads)
	if err != nil {
		f.t.Fatal(err)
	}
	for _, participant := range f.participants[1:] {
		other, materialErr := participant.PublicMaterial(heads)
		if materialErr != nil || !publicMaterialEqual(material, other) {
			f.t.Fatalf("independent public reconstruction mismatch: %v", materialErr)
		}
	}
	verifyThresholdShareCorrespondence(f.t, f, material.PublicKeyBytes)
	preManifest := f.participants[0].records[len(f.participants[0].records)-1].Digest()
	unsigned, err := BuildUnsignedPublicBundle(f.params, f.context, f.participants[0].Transcript(), material, preManifest)
	if err != nil {
		f.t.Fatalf("unsigned bundle: %v", err)
	}
	for _, participant := range f.participants {
		if err := participant.SetManifestPending(unsigned.Digest()); err != nil {
			f.t.Fatal(err)
		}
	}
	f.transition(PhaseManifest, [32]byte{}, f.participants)

	heads = f.heads()
	attestations := envelopes(f.t, f.participants, func(p *Participant) (SignedEnvelope, error) { return p.AttestUnsignedBundle(unsigned, heads) })
	ready := make([]SignedEnvelope, PartyCount)
	needles := make([][]byte, PartyCount)
	heads = f.heads()
	for index, participant := range f.participants {
		needles[index], err = participant.thresholdShareBytes()
		if err != nil {
			f.t.Fatal(err)
		}
		if ready[index], err = participant.AttestPrivateReadiness(unsigned, heads); err != nil {
			f.t.Fatal(err)
		}
	}
	bundle, err := BuildPublicBundle(unsigned, attestations, ready)
	if err != nil {
		f.t.Fatalf("public bundle: %v", err)
	}
	publicRoot := strictTempPath(f.t, "public-publication")
	receipt, err := PublishPublicBundle(publicRoot, bundle)
	if err != nil {
		f.t.Fatalf("publish public: %v", err)
	}
	for _, participant := range f.participants {
		if err := participant.SetPublishedPending(bundle, receipt); err != nil {
			f.t.Fatal(err)
		}
	}
	f.transition(PhasePublished, [32]byte{}, f.participants)
	if f.abortAfterStaging {
		preAbortHeads := f.heads()
		abortRecord := f.transition(PhaseAborted, digestLabel("audit-f07-abort-after-valid-publication"), f.participants[:Threshold])
		if err := f.participants[2].CommitTransition(abortRecord); err != nil {
			f.t.Fatalf("third operator accept terminal abort: %v", err)
		}
		replicas := [][]WitnessRecord{f.participants[0].Records(), f.participants[1].Records(), f.participants[2].Records()}
		for index, participant := range f.participants {
			if _, finalErr := participant.FinalizeCompletedOperatorBundle(bundle, receipt, preAbortHeads, replicas...); !errors.Is(finalErr, ErrSecretAccess) {
				f.t.Fatalf("aborted ceremony created private authority: %v", finalErr)
			}
			entries, readErr := os.ReadDir(f.storage[index].completedRoot)
			if readErr != nil || len(entries) != 0 {
				f.t.Fatalf("aborted operator retained completed-private artifact: %v", readErr)
			}
		}
		return ceremonyResult{fixture: f, bundle: bundle, shareNeedles: needles, receipt: receipt}
	}
	for _, participant := range f.participants {
		if err := participant.SetCompletedPending(bundle, receipt); err != nil {
			f.t.Fatal(err)
		}
	}
	f.transition(PhaseCompleted, [32]byte{}, f.participants)
	replicas := [][]WitnessRecord{f.participants[0].Records(), f.participants[1].Records(), f.participants[2].Records()}
	if err := VerifyPublishedCeremony(f.context, bundle, receipt, replicas...); err != nil {
		f.t.Fatalf("published ceremony: %v", err)
	}
	sealed := make([]SealedOperatorBundle, PartyCount)
	heads = f.heads()
	for index, participant := range f.participants {
		sealed[index], err = participant.FinalizeCompletedOperatorBundle(bundle, receipt, heads, replicas...)
		if err != nil {
			f.t.Fatalf("finalize completed private bundle: %v", err)
		}
		opened, openErr := participant.openCompletedOperatorBundle(bundle, receipt, replicas...)
		if openErr != nil || !slices.Equal(opened.thresholdShare, needles[index]) || opened.OperatorPoint != participant.Point() {
			f.t.Fatalf("completed private bundle readback: %v", openErr)
		}
	}
	return ceremonyResult{fixture: f, bundle: bundle, sealed: sealed, shareNeedles: needles, receipt: receipt}
}

func TestOneShotCeremonyRequirements(t *testing.T) {
	result := newFixture(t, "successful-fresh").runSuccess()

	t.Run("01 successful fresh three-operator ceremony", func(t *testing.T) {
		if result.fixture.participants[0].Phase() != PhaseCompleted || result.bundle.Unsigned.Context.KeyScope != KeyScope || MaximumSessions != 1 || EphemeralKeyEpoch != 0 {
			t.Fatal("one-shot ceremony did not finish with the fixed ephemeral scope")
		}
		if err := VerifyPublicBundle(result.bundle); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("02 ceremony identifiers are unique", func(t *testing.T) {
		left, right := newFixture(t, "unique-left"), newFixture(t, "unique-right")
		if left.context.CeremonyID() == right.context.CeremonyID() {
			t.Fatal("distinct contexts produced one identifier")
		}
	})

	t.Run("03 identifier and scope ordinal reuse are rejected", func(t *testing.T) {
		f := result.fixture
		if _, err := NewParticipant(f.params, f.context, f.signingKeys[0], f.encryptionKey[0], f.storage[0], cryptorand.Reader); !errors.Is(err, ErrReplay) {
			t.Fatalf("completed identifier reopened: %v", err)
		}
		changed := f.context
		changed.Nonce = digestLabel("different-id-same-scope-ordinal")
		context, err := NewContext(f.params, changed)
		if err != nil {
			t.Fatal(err)
		}
		participant, err := NewParticipant(f.params, context, f.signingKeys[0], f.encryptionKey[0], f.storage[0], cryptorand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if err := participant.Reserve(nil); err == nil {
			t.Fatalf("scope ordinal reopened: %v", err)
		}
	})

	t.Run("04 cross-ceremony contribution mixing is rejected", func(t *testing.T) {
		left, right := newFixture(t, "cross-left"), newFixture(t, "cross-right")
		left.reserveAndStart()
		right.reserveAndStart()
		leftHeads := left.heads()
		foreign := envelopes(t, left.participants, func(p *Participant) (SignedEnvelope, error) { return p.CRSCommitEnvelope(leftHeads) })
		if err := right.participants[0].AcceptCRSCommitStage(foreign); err == nil {
			t.Fatal("foreign contribution accepted")
		}
	})

	t.Run("05 privacy-domain mixing is rejected", func(t *testing.T) {
		foreign := result.bundle.Attestations[0]
		context := result.fixture.context
		context.PrivacyDomain = digestLabel("foreign-domain")
		if _, err := VerifySignedEnvelope(context, foreign); err == nil {
			t.Fatal("privacy-domain mix accepted")
		}
	})

	t.Run("06 session mixing is rejected", func(t *testing.T) {
		context := result.fixture.context
		context.SessionCommitment = digestLabel("foreign-session")
		if _, err := VerifySignedEnvelope(context, result.bundle.Attestations[0]); err == nil {
			t.Fatal("session mix accepted")
		}
	})

	t.Run("07 parameter and version mixing is rejected", func(t *testing.T) {
		context := result.fixture.context
		context.LattigoVersion = "github.com/tuneinsight/lattigo/v6 v6.1.1"
		if context.Validate() == nil {
			t.Fatal("mixed Lattigo version accepted")
		}
		other := testParameters(t)
		literal := other.ParametersLiteral()
		literal.PlaintextModulus = 0xffc001
		other, err := bgv.NewParametersFromLiteral(literal)
		if err != nil {
			t.Fatal(err)
		}
		f := result.fixture
		if _, err := NewParticipant(other, f.context, f.signingKeys[0], f.encryptionKey[0], f.storage[0], cryptorand.Reader); !errors.Is(err, ErrBinding) {
			t.Fatalf("mixed parameters accepted: %v", err)
		}
	})

	t.Run("08 reordered operator identities are rejected", func(t *testing.T) {
		context := result.fixture.context
		context.Operators = slices.Clone(context.Operators)
		context.Operators[0], context.Operators[1] = context.Operators[1], context.Operators[0]
		if context.Validate() == nil {
			t.Fatal("reordered roster accepted")
		}
	})

	t.Run("09 repeated phase execution is rejected", func(t *testing.T) {
		participant := result.fixture.participants[0]
		if _, err := participant.GaloisShareEnvelope(0, nil); !errors.Is(err, ErrState) {
			t.Fatalf("completed phase repeated: %v", err)
		}
		f := newFixture(t, "expired")
		f.context.ActivatesAtUnix = 1
		f.context.ExpiresAtUnix = 2
		if _, err := NewParticipant(f.params, f.context, f.signingKeys[0], f.encryptionKey[0], f.storage[0], cryptorand.Reader); !errors.Is(err, ErrTerminal) {
			t.Fatalf("expired ceremony reopened: %v", err)
		}
	})

	t.Run("random failure permanently prevents regeneration under one identity", func(t *testing.T) {
		f := newFixture(t, "random-failure")
		f.reserveAndWitnessStart()
		f.participants[0].random = failingReader{}
		heads := f.heads()
		if err := f.participants[0].BeginSecrets(heads); !errors.Is(err, ErrMaterial) {
			t.Fatalf("random failure was not rejected: %v", err)
		}
		if err := f.participants[0].BeginSecrets(heads); !errors.Is(err, ErrState) {
			t.Fatalf("randomized action regenerated: %v", err)
		}
		if _, err := f.participants[0].ProposedTransition(PhaseRunning, [32]byte{}); !errors.Is(err, ErrTerminal) {
			t.Fatalf("poisoned attempt continued: %v", err)
		}
		if _, err := f.participants[0].ProposedTransition(PhaseAborted, digestLabel("random-failure")); err != nil {
			t.Fatalf("poisoned attempt could not sign abort: %v", err)
		}
	})

	t.Run("10 conflicting signatures are rejected", func(t *testing.T) {
		f := newFixture(t, "conflicting-signatures")
		heads := f.heads()
		for _, participant := range f.participants {
			if err := participant.Reserve(heads); err != nil {
				t.Fatal(err)
			}
		}
		reservations := make([]AttemptReservation, PartyCount)
		for index, participant := range f.participants {
			reservations[index], _ = participant.Reservation()
		}
		for _, participant := range f.participants {
			if err := participant.AcceptReservations(reservations); err != nil {
				t.Fatal(err)
			}
		}
		reserved, err := f.participants[0].ProposedTransition(PhaseReserved, [32]byte{})
		if err != nil {
			t.Fatal(err)
		}
		heads = f.heads()
		if _, err := f.participants[0].SignTransition(reserved, heads); err != nil {
			t.Fatal(err)
		}
		abort, err := f.participants[0].ProposedTransition(PhaseAborted, digestLabel("conflict"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.participants[0].SignTransition(abort, heads); !errors.Is(err, ErrReplay) {
			t.Fatalf("second decision signed: %v", err)
		}
	})

	t.Run("11 public bundle substitution is rejected", func(t *testing.T) {
		encoded, _ := result.bundle.MarshalBinary()
		bundle, err := ParsePublicBundle(encoded)
		if err != nil {
			t.Fatal(err)
		}
		bundle.Unsigned.PublicKey[0] ^= 1
		if VerifyPublicBundle(bundle) == nil {
			t.Fatal("substituted public key accepted")
		}
	})

	t.Run("12 transcript truncation and reordering are rejected", func(t *testing.T) {
		context := result.fixture.context
		transcript := result.bundle.Unsigned.Transcript
		encoded, _ := transcript.MarshalBinary()
		if _, err := ParseTranscript(context, encoded[:len(encoded)-1]); err == nil {
			t.Fatal("truncated transcript accepted")
		}
		reordered := cloneTranscript(transcript)
		reordered.Stages[0], reordered.Stages[1] = reordered.Stages[1], reordered.Stages[0]
		encoded, _ = reordered.MarshalBinary()
		if _, err := ParseTranscript(context, encoded); err == nil {
			t.Fatal("reordered transcript accepted")
		}
	})

	t.Run("13 witness rollback is detected", func(t *testing.T) {
		records := result.fixture.participants[0].Records()
		if err := VerifyReplicaAgreement(result.fixture.context, records, records[:len(records)-1], records); !errors.Is(err, ErrPersistence) {
			t.Fatalf("rollback not detected: %v", err)
		}
	})

	t.Run("14 forked witness history is detected", func(t *testing.T) {
		f := result.fixture
		original := f.participants[0].Records()
		prefix := slices.Clone(original[:2])
		root := prefix[len(prefix)-1].Statement.TranscriptDigest
		reason := digestLabel("forked-abort")
		material := hashDomain("MordantOneShotAbortMaterial/v1", root[:], reason[:])
		statement, err := NewWitnessStatement(f.context, prefix, PhaseAborted, 0, root, material, reason)
		if err != nil {
			t.Fatal(err)
		}
		signatures := make([]WitnessSignature, Threshold)
		for index := range signatures {
			signatures[index], err = SignWitnessStatement(statement, uint64(index+1), f.signingKeys[index])
			if err != nil {
				t.Fatal(err)
			}
		}
		abort, err := AssembleWitnessRecord(f.context, statement, signatures)
		if err != nil {
			t.Fatal(err)
		}
		fork := append(prefix, abort)
		accepted := slices.Clone(original[:3])
		if err := VerifyReplicaAgreement(f.context, accepted, fork, accepted); !errors.Is(err, ErrPersistence) {
			t.Fatalf("fork not detected: %v", err)
		}
	})

	t.Run("15 one abandoned operator produces terminal abort without disclosure", func(t *testing.T) {
		f := newFixture(t, "abandonment")
		f.reserveAndStart()
		reason := digestLabel("operator-3-abandoned")
		record := f.transition(PhaseAborted, reason, f.participants[:2])
		if f.participants[0].Phase() != PhaseAborted || f.participants[1].Phase() != PhaseAborted || record.Statement.ReasonDigest != reason {
			t.Fatal("survivors did not terminally witness abandonment")
		}
		encoded, _ := record.MarshalBinary()
		if bytes.Contains(encoded, f.signingKeys[0]) || bytes.Contains(encoded, f.signingKeys[1]) {
			t.Fatal("abort witness disclosed a private key")
		}
	})

	t.Run("16 aborted ceremony cannot resume", func(t *testing.T) {
		f := newFixture(t, "aborted-no-resume")
		f.reserveAndStart()
		f.transition(PhaseAborted, digestLabel("terminal"), f.participants[:2])
		if err := f.participants[0].BeginSecrets(nil); !errors.Is(err, ErrState) {
			t.Fatalf("aborted attempt resumed: %v", err)
		}
		if _, err := f.participants[0].ProposedTransition(PhaseRunning, [32]byte{}); !errors.Is(err, ErrTerminal) {
			t.Fatalf("aborted witness extended: %v", err)
		}
	})

	t.Run("17 completed ceremony cannot resume", func(t *testing.T) {
		participant := result.fixture.participants[0]
		if _, err := participant.ProposedTransition(PhaseAborted, digestLabel("late")); !errors.Is(err, ErrTerminal) {
			t.Fatalf("completed witness extended: %v", err)
		}
		if _, err := participant.thresholdShareBytes(); !errors.Is(err, ErrSecretAccess) {
			t.Fatalf("completed in-memory share remained accessible: %v", err)
		}
	})

	t.Run("18 retry requires a new identity and fresh material", func(t *testing.T) {
		old := result.fixture
		contextInput := old.context
		contextInput.Nonce = digestLabel("retry-fresh-nonce")
		contextInput.SessionIdentity = digestLabel("retry-new-bilateral-session")
		contextInput.SessionCommitment = digestLabel("retry-new-bilateral-commitment")
		context, err := NewContext(old.params, contextInput)
		if err != nil {
			t.Fatal(err)
		}
		retry := newFixtureForContext(t, old.params, context, old.signingKeys, old.encryptionKey, old.storage, old.storageConfigs)
		retryResult := retry.runSuccess()
		if context.CeremonyID() == old.context.CeremonyID() || retryResult.bundle.Unsigned.KeyID == result.bundle.Unsigned.KeyID ||
			slices.Equal(retryResult.bundle.Unsigned.PublicKey, result.bundle.Unsigned.PublicKey) {
			t.Fatal("retry reused identity or cryptographic material")
		}
	})

	t.Run("19 public evidence and diagnostics contain no aggregate shares", func(t *testing.T) {
		publicBytes, _ := result.bundle.MarshalBinary()
		for _, needle := range result.shareNeedles {
			if bytes.Contains(publicBytes, needle) || strings.Contains(ErrMaterial.Error(), fmt.Sprintf("%x", needle)) {
				t.Fatal("aggregate share escaped into public evidence or errors")
			}
			for _, participant := range result.fixture.participants {
				for _, record := range participant.Records() {
					recordBytes, _ := record.MarshalBinary()
					if bytes.Contains(recordBytes, needle) {
						t.Fatal("aggregate share escaped into witness")
					}
				}
			}
		}
	})

	t.Run("20 corrupt or incomplete persisted state fails closed", func(t *testing.T) {
		root := strictTempPath(t, "corrupt-store")
		store, err := openWitnessStore(root, strictTempPath(t, "corrupt-session-registry"))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "unexpected.partial"), []byte("partial"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Records(result.fixture.context.CeremonyID()); !errors.Is(err, ErrPersistence) {
			t.Fatalf("corrupt store accepted: %v", err)
		}
	})

	t.Run("21 canonical serialization is deterministic and strict", func(t *testing.T) {
		first, _ := result.bundle.MarshalBinary()
		second, _ := result.bundle.MarshalBinary()
		if !slices.Equal(first, second) {
			t.Fatal("bundle encoding is nondeterministic")
		}
		parsed, err := ParsePublicBundle(first)
		if err != nil {
			t.Fatal(err)
		}
		third, _ := parsed.MarshalBinary()
		if !slices.Equal(first, third) {
			t.Fatal("parse and reserialization changed canonical bytes")
		}
		if _, err := ParsePublicBundle(append(slices.Clone(first), 0)); err == nil {
			t.Fatal("alternative trailing encoding accepted")
		}
	})

	t.Run("22 current supported environment round-trip is local non-acceptance only", func(t *testing.T) {
		encoded, _ := result.bundle.MarshalBinary()
		parsed, err := ParsePublicBundle(encoded)
		if err != nil || VerifyPublicBundle(parsed) != nil {
			t.Fatalf("%s/%s round-trip: %v", runtime.GOOS, runtime.GOARCH, err)
		}
		for _, operator := range parsed.Unsigned.Context.Operators {
			if operator.OperatingSystem != runtime.GOOS || operator.Architecture != runtime.GOARCH {
				t.Fatal("runtime fingerprint lost")
			}
		}
		// This test deliberately produces no topology attestation. Three local
		// stores are functional coverage, never three-host acceptance evidence.
	})

	t.Run("terminal status is monotone and needs two operators", func(t *testing.T) {
		initial := result.bundle.Unsigned.InitialStatus
		terminal, err := NewTerminalKeyStatus(initial, StatusRevoked, initial.EffectiveAt+10, digestLabel("emergency"))
		if err != nil {
			t.Fatal(err)
		}
		signatures := make([]StatusSignature, Threshold)
		for index := range signatures {
			signatures[index], err = SignKeyStatus(result.fixture.context, initial, terminal, uint64(index+1), result.fixture.signingKeys[index], result.fixture.stores[index])
			if err != nil {
				t.Fatal(err)
			}
		}
		record, err := AssembleStatusRecord(result.fixture.context, initial, terminal, signatures)
		if err != nil {
			t.Fatal(err)
		}
		for _, store := range result.fixture.stores {
			if err := store.AppendStatus(result.fixture.context, initial, record); err != nil {
				t.Fatal(err)
			}
		}
		replicas := make([][]StatusRecord, PartyCount)
		for index, store := range result.fixture.stores {
			replicas[index], err = store.StatusRecords(result.fixture.context, initial)
			if err != nil {
				t.Fatal(err)
			}
		}
		if err := VerifyStatusReplicaAgreement(result.fixture.context, initial, replicas...); err != nil {
			t.Fatalf("status replicas disagree: %v", err)
		}
		if _, err := NewTerminalKeyStatus(terminal, StatusActive, terminal.EffectiveAt+1, digestLabel("reactivate")); err == nil {
			t.Fatal("terminal status reactivated")
		}
		conflict, err := NewTerminalKeyStatus(initial, StatusExpired, terminal.EffectiveAt+1, digestLabel("conflicting-expiry"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := SignKeyStatus(result.fixture.context, initial, conflict, 1, result.fixture.signingKeys[0], result.fixture.stores[0]); !errors.Is(err, ErrReplay) {
			t.Fatalf("conflicting status signed: %v", err)
		}
	})
}
