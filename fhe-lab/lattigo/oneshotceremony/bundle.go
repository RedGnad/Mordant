package oneshotceremony

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"io"
	"os"
	"path/filepath"
	"slices"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/multiparty"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

type KeyStatus uint8

const (
	StatusActive KeyStatus = iota + 1
	StatusRevoked
	StatusExpired
)

type KeyStatusStatement struct {
	SchemaVersion  string
	KeyID          [32]byte
	Sequence       uint64
	Status         KeyStatus
	EffectiveAt    int64
	ReasonDigest   [32]byte
	PreviousDigest [32]byte
}

type UnsignedPublicBundle struct {
	SchemaVersion            string
	Context                  Context
	Parameters               []byte
	Transcript               Transcript
	CRSCommitment            [32]byte
	PublicKey                []byte
	RelinearizationKey       []byte
	GaloisKeys               [][]byte
	KeyID                    [32]byte
	PreManifestWitnessDigest [32]byte
	InitialStatus            KeyStatusStatement
}

type PublicBundle struct {
	SchemaVersion string
	Unsigned      UnsignedPublicBundle
	Attestations  []SignedEnvelope
	PrivateReady  []SignedEnvelope
}

type PrivateBundle struct {
	SchemaVersion         string
	SourceCommit          string
	LattigoModuleChecksum string
	CeremonyID            [32]byte
	ContextDigest         [32]byte
	RosterDigest          [32]byte
	ScopeOrdinalDigest    [32]byte
	SessionCommitment     [32]byte
	AttemptOrdinal        uint64
	OperatorPoint         uint64
	OperatorRuntimeDigest [32]byte
	GoVersion             string
	OperatingSystem       string
	Architecture          string
	SigningKeyReference   [32]byte
	TransportKeyReference [32]byte
	ParameterFingerprint  [32]byte
	CircuitVersion        uint32
	CircuitDigest         [32]byte
	ReleaseLayout         uint32
	MaximumReleaseQueries uint32
	KeyID                 [32]byte
	UnsignedBundleDigest  [32]byte
	TranscriptDigest      [32]byte
	PublicKeyDigest       [32]byte
	EvaluationKeyDigest   [32]byte
	WitnessHeadDigest     [32]byte
	StatusDigest          [32]byte
	ActivatesAtUnix       int64
	ExpiresAtUnix         int64
	ThresholdShare        []byte
}

type SealedOperatorBundle struct {
	SchemaVersion        string
	CeremonyID           [32]byte
	OperatorPoint        uint64
	KeyID                [32]byte
	UnsignedBundleDigest [32]byte
	Nonce                [12]byte
	Ciphertext           []byte
}

type PublicationReceipt struct {
	SchemaVersion        string
	CeremonyID           [32]byte
	BundleDigest         [32]byte
	CanonicalBytesSHA256 [32]byte
	ObjectPath           string
	ObjectSize           uint64
}

func (r PublicationReceipt) MarshalBinary() ([]byte, error) {
	if r.SchemaVersion != "mordant.fhe-publication-receipt/oneshot-v2" || isZero32(r.CeremonyID) ||
		isZero32(r.BundleDigest) || isZero32(r.CanonicalBytesSHA256) || !filepath.IsAbs(r.ObjectPath) || r.ObjectSize == 0 {
		return nil, ErrBinding
	}
	var e encoder
	e.text(r.SchemaVersion)
	e.fixed(r.CeremonyID[:])
	e.fixed(r.BundleDigest[:])
	e.fixed(r.CanonicalBytesSHA256[:])
	e.text(filepath.Clean(r.ObjectPath))
	e.u64(r.ObjectSize)
	return e.Bytes(), nil
}

func (r PublicationReceipt) Digest() [32]byte {
	encoded, err := r.MarshalBinary()
	if err != nil {
		return [32]byte{}
	}
	return hashDomain("MordantOneShotPublicationReceipt/v2", encoded)
}

func completionMaterialDigest(bundle PublicBundle, receipt PublicationReceipt) [32]byte {
	bundleDigest, receiptDigest := bundle.Digest(), receipt.Digest()
	return hashDomain("MordantOneShotCompletedPublication/v2", bundleDigest[:], receiptDigest[:])
}

func BuildUnsignedPublicBundle(params bgv.Parameters, context Context, transcript Transcript, material PublicMaterial, preManifestWitness [32]byte) (UnsignedPublicBundle, error) {
	if !transcript.Complete(context) || isZero32(preManifestWitness) {
		return UnsignedPublicBundle{}, ErrState
	}
	parameterBytes, err := params.MarshalBinary()
	if err != nil || sha256.Sum256(parameterBytes) != context.ParameterFingerprint {
		return UnsignedPublicBundle{}, ErrBinding
	}
	reconstructed, crsCommitment, err := ReconstructPublicMaterial(params, context, transcript)
	if err != nil || !publicMaterialEqual(reconstructed, material) {
		return UnsignedPublicBundle{}, ErrMaterial
	}
	keyID := deriveKeyID(context, material)
	ceremonyID := context.CeremonyID()
	status := KeyStatusStatement{
		SchemaVersion: StatusSchema,
		KeyID:         keyID,
		Sequence:      1,
		Status:        StatusActive,
		EffectiveAt:   context.ActivatesAtUnix,
		ReasonDigest:  hashDomain("MordantOneShotInitialStatusReason/v1", ceremonyID[:]),
	}
	return UnsignedPublicBundle{
		SchemaVersion:            PublicBundleSchema,
		Context:                  context,
		Parameters:               parameterBytes,
		Transcript:               cloneTranscript(transcript),
		CRSCommitment:            crsCommitment,
		PublicKey:                slices.Clone(material.PublicKeyBytes),
		RelinearizationKey:       slices.Clone(material.RelinearizationBytes),
		GaloisKeys:               cloneByteSlices(material.GaloisKeyBytes),
		KeyID:                    keyID,
		PreManifestWitnessDigest: preManifestWitness,
		InitialStatus:            status,
	}, nil
}

func (b UnsignedPublicBundle) MarshalBinary() ([]byte, error) {
	contextBytes, err := b.Context.MarshalBinary()
	if err != nil || b.SchemaVersion != PublicBundleSchema || len(b.Parameters) == 0 || len(b.PublicKey) == 0 ||
		len(b.RelinearizationKey) == 0 || len(b.GaloisKeys) != len(b.Context.GaloisElements) ||
		isZero32(b.CRSCommitment) || isZero32(b.KeyID) || isZero32(b.PreManifestWitnessDigest) {
		return nil, ErrBinding
	}
	transcriptBytes, err := b.Transcript.MarshalBinary()
	if err != nil {
		return nil, err
	}
	statusBytes, err := b.InitialStatus.MarshalBinary()
	if err != nil || b.InitialStatus.KeyID != b.KeyID {
		return nil, ErrBinding
	}
	var e encoder
	e.text(PublicBundleSchema)
	e.text(b.SchemaVersion)
	e.text(ManifestSchema)
	e.text(EnvelopeSchema)
	e.text(SignatureDomain)
	e.text(SignatureAlgorithm)
	e.text(CRSSchema)
	e.u32(SerializationVersion)
	e.text(LattigoVersion)
	e.text(KeyScope)
	e.u64(EphemeralKeyEpoch)
	e.u32(MaximumSessions)
	e.u16(Threshold)
	e.u16(PartyCount)
	e.text(StatusSchema)
	e.field(contextBytes)
	e.field(b.Parameters)
	e.field(transcriptBytes)
	e.fixed(b.CRSCommitment[:])
	e.field(b.PublicKey)
	e.field(b.RelinearizationKey)
	e.u32(uint32(len(b.GaloisKeys)))
	for index, key := range b.GaloisKeys {
		e.u64(b.Context.GaloisElements[index])
		e.field(key)
	}
	e.fixed(b.KeyID[:])
	e.fixed(b.PreManifestWitnessDigest[:])
	e.field(statusBytes)
	return e.Bytes(), nil
}

func ParseUnsignedPublicBundle(data []byte) (UnsignedPublicBundle, error) {
	var bundle UnsignedPublicBundle
	d := newDecoder(data)
	magic, err := d.text()
	if err != nil || magic != PublicBundleSchema {
		return bundle, errCanonical
	}
	if bundle.SchemaVersion, err = d.text(); err != nil || bundle.SchemaVersion != PublicBundleSchema {
		return bundle, errCanonical
	}
	manifest, err := d.text()
	if err != nil || manifest != ManifestSchema {
		return bundle, errCanonical
	}
	envelopeSchema, err := d.text()
	if err != nil || envelopeSchema != EnvelopeSchema {
		return bundle, errCanonical
	}
	signatureDomain, err := d.text()
	if err != nil || signatureDomain != SignatureDomain {
		return bundle, errCanonical
	}
	signatureAlgorithm, err := d.text()
	if err != nil || signatureAlgorithm != SignatureAlgorithm {
		return bundle, errCanonical
	}
	crsSchema, err := d.text()
	if err != nil || crsSchema != CRSSchema {
		return bundle, errCanonical
	}
	serialization, err := d.u32()
	if err != nil || serialization != SerializationVersion {
		return bundle, errCanonical
	}
	lattigo, err := d.text()
	if err != nil || lattigo != LattigoVersion {
		return bundle, errCanonical
	}
	scope, err := d.text()
	if err != nil || scope != KeyScope {
		return bundle, errCanonical
	}
	epoch, err := d.u64()
	if err != nil || epoch != EphemeralKeyEpoch {
		return bundle, errCanonical
	}
	maximum, err := d.u32()
	if err != nil || maximum != MaximumSessions {
		return bundle, errCanonical
	}
	threshold, err := d.u16()
	if err != nil || threshold != Threshold {
		return bundle, errCanonical
	}
	parties, err := d.u16()
	if err != nil || parties != PartyCount {
		return bundle, errCanonical
	}
	statusSchema, err := d.text()
	if err != nil || statusSchema != StatusSchema {
		return bundle, errCanonical
	}
	contextBytes, err := d.field()
	if err != nil {
		return bundle, err
	}
	if bundle.Context, err = ParseContext(contextBytes); err != nil {
		return bundle, err
	}
	if bundle.Parameters, err = d.field(); err != nil || len(bundle.Parameters) == 0 {
		return bundle, errCanonical
	}
	transcriptBytes, err := d.field()
	if err != nil {
		return bundle, err
	}
	if bundle.Transcript, err = ParseTranscript(bundle.Context, transcriptBytes); err != nil {
		return bundle, err
	}
	value, err := d.fixed(32)
	if err != nil || copy32(&bundle.CRSCommitment, value) != nil {
		return bundle, errCanonical
	}
	if bundle.PublicKey, err = d.field(); err != nil || len(bundle.PublicKey) == 0 {
		return bundle, errCanonical
	}
	if bundle.RelinearizationKey, err = d.field(); err != nil || len(bundle.RelinearizationKey) == 0 {
		return bundle, errCanonical
	}
	count, err := d.u32()
	if err != nil || count != uint32(len(bundle.Context.GaloisElements)) {
		return bundle, errCanonical
	}
	bundle.GaloisKeys = make([][]byte, count)
	for index := range bundle.GaloisKeys {
		element, readErr := d.u64()
		if readErr != nil || element != bundle.Context.GaloisElements[index] {
			return UnsignedPublicBundle{}, errCanonical
		}
		if bundle.GaloisKeys[index], readErr = d.field(); readErr != nil || len(bundle.GaloisKeys[index]) == 0 {
			return UnsignedPublicBundle{}, errCanonical
		}
	}
	for _, target := range []*[32]byte{&bundle.KeyID, &bundle.PreManifestWitnessDigest} {
		value, readErr := d.fixed(32)
		if readErr != nil || copy32(target, value) != nil {
			return UnsignedPublicBundle{}, errCanonical
		}
	}
	statusBytes, err := d.field()
	if err != nil {
		return bundle, err
	}
	if bundle.InitialStatus, err = ParseKeyStatusStatement(statusBytes); err != nil || d.done() != nil {
		return UnsignedPublicBundle{}, errCanonical
	}
	reencoded, err := bundle.MarshalBinary()
	if err != nil || !slices.Equal(reencoded, data) {
		return UnsignedPublicBundle{}, errCanonical
	}
	return bundle, nil
}

func (b UnsignedPublicBundle) Digest() [32]byte {
	encoded, err := b.MarshalBinary()
	if err != nil {
		return [32]byte{}
	}
	return hashDomain("MordantOneShotUnsignedPublicBundle/v1", encoded)
}

func VerifyUnsignedPublicBundle(bundle UnsignedPublicBundle) (bgv.Parameters, error) {
	if err := bundle.Context.Validate(); err != nil || !bundle.Transcript.Complete(bundle.Context) {
		return bgv.Parameters{}, ErrBinding
	}
	var params bgv.Parameters
	if err := params.UnmarshalBinary(bundle.Parameters); err != nil {
		return params, ErrMaterial
	}
	fingerprint, err := ParameterFingerprint(params)
	if err != nil || fingerprint != bundle.Context.ParameterFingerprint {
		return params, ErrBinding
	}
	material := PublicMaterial{bundle.PublicKey, bundle.RelinearizationKey, bundle.GaloisKeys}
	reconstructed, crs, err := ReconstructPublicMaterial(params, bundle.Context, bundle.Transcript)
	if err != nil || crs != bundle.CRSCommitment || !publicMaterialEqual(reconstructed, material) || deriveKeyID(bundle.Context, material) != bundle.KeyID {
		return params, ErrMaterial
	}
	ceremonyID := bundle.Context.CeremonyID()
	expectedInitialReason := hashDomain("MordantOneShotInitialStatusReason/v1", ceremonyID[:])
	if bundle.InitialStatus.SchemaVersion != StatusSchema || bundle.InitialStatus.KeyID != bundle.KeyID || bundle.InitialStatus.Sequence != 1 ||
		bundle.InitialStatus.Status != StatusActive || bundle.InitialStatus.EffectiveAt != bundle.Context.ActivatesAtUnix ||
		bundle.InitialStatus.PreviousDigest != ([32]byte{}) || bundle.InitialStatus.ReasonDigest != expectedInitialReason {
		return params, ErrBinding
	}
	return params, nil
}

func (p *Participant) AttestUnsignedBundle(bundle UnsignedPublicBundle) (SignedEnvelope, error) {
	if p.phase != PhaseManifest || p.poisoned || p.wasGenerated("manifest-attestation") {
		return SignedEnvelope{}, ErrState
	}
	if _, err := VerifyUnsignedPublicBundle(bundle); err != nil || bundle.Context.CeremonyID() != p.context.CeremonyID() ||
		!participantMaterialMatches(p, bundle) {
		return SignedEnvelope{}, p.poison(ErrMaterial)
	}
	digest := bundle.Digest()
	if err := p.markGenerated("manifest-attestation"); err != nil {
		return SignedEnvelope{}, p.poison(err)
	}
	return NewSignedEnvelope(p.context, p.signingKey, p.Point(), 0, OperationManifestAttestation, 0, 0,
		p.transcript.Root(p.context), bundle.KeyID, digest[:])
}

func (p *Participant) SealOperatorBundle(bundle UnsignedPublicBundle, sealingKey []byte) (SealedOperatorBundle, SignedEnvelope, error) {
	if p.phase != PhaseManifest || p.poisoned || p.wasGenerated("private-bundle") || len(sealingKey) != 32 || !p.hasThreshold || !participantMaterialMatches(p, bundle) {
		return SealedOperatorBundle{}, SignedEnvelope{}, ErrState
	}
	if err := p.markGenerated("private-bundle"); err != nil {
		return SealedOperatorBundle{}, SignedEnvelope{}, p.poison(err)
	}
	share, err := p.thresholdShare.MarshalBinary()
	if err != nil {
		return SealedOperatorBundle{}, SignedEnvelope{}, p.poison(ErrMaterial)
	}
	private := PrivateBundle{
		SchemaVersion:         PrivateBundleSchema,
		SourceCommit:          p.context.SourceCommit,
		LattigoModuleChecksum: p.context.LattigoModuleChecksum,
		CeremonyID:            p.context.CeremonyID(),
		ContextDigest:         p.context.ContextDigest(),
		RosterDigest:          p.context.RosterDigest(),
		ScopeOrdinalDigest:    p.context.ScopeOrdinalDigest(),
		SessionCommitment:     p.context.SessionCommitment,
		AttemptOrdinal:        p.context.AttemptOrdinal,
		OperatorPoint:         p.Point(),
		OperatorRuntimeDigest: p.identity.RuntimeBinaryDigest,
		GoVersion:             p.identity.GoVersion,
		OperatingSystem:       p.identity.OperatingSystem,
		Architecture:          p.identity.Architecture,
		SigningKeyReference:   hashDomain("MordantOneShotSigningKeyReference/v1", p.identity.SigningPublicKey[:]),
		TransportKeyReference: hashDomain("MordantOneShotTransportKeyReference/v1", p.identity.EncryptionPublicKey[:]),
		ParameterFingerprint:  p.context.ParameterFingerprint,
		CircuitVersion:        p.context.CircuitVersion,
		CircuitDigest:         p.context.CircuitDigest,
		ReleaseLayout:         p.context.ReleaseLayout,
		MaximumReleaseQueries: p.context.MaximumReleaseQueries,
		KeyID:                 bundle.KeyID,
		UnsignedBundleDigest:  bundle.Digest(),
		TranscriptDigest:      p.transcript.Root(p.context),
		PublicKeyDigest:       sha256.Sum256(p.publicKeyBytes),
		EvaluationKeyDigest:   evaluationKeyDigest(p.relinKeyBytes, p.galoisKeyBytes, p.context.GaloisElements),
		WitnessHeadDigest:     bundle.PreManifestWitnessDigest,
		StatusDigest:          bundle.InitialStatus.Digest(),
		ActivatesAtUnix:       p.context.ActivatesAtUnix,
		ExpiresAtUnix:         p.context.ExpiresAtUnix,
		ThresholdShare:        share,
	}
	plaintext, err := private.MarshalBinary()
	if err != nil {
		return SealedOperatorBundle{}, SignedEnvelope{}, p.poison(err)
	}
	sealed := SealedOperatorBundle{
		SchemaVersion:        PrivateBundleSchema,
		CeremonyID:           private.CeremonyID,
		OperatorPoint:        p.Point(),
		KeyID:                private.KeyID,
		UnsignedBundleDigest: private.UnsignedBundleDigest,
	}
	if _, err := io.ReadFull(p.random, sealed.Nonce[:]); err != nil {
		return SealedOperatorBundle{}, SignedEnvelope{}, p.poison(ErrMaterial)
	}
	aead, err := operatorBundleAEAD(sealingKey)
	if err != nil {
		return SealedOperatorBundle{}, SignedEnvelope{}, p.poison(err)
	}
	sealed.Ciphertext = aead.Seal(nil, sealed.Nonce[:], plaintext, sealed.additionalData())
	digest := sealed.Digest()
	readyPayload := privateReadyPayload(bundle.Digest(), digest)
	ready, err := NewSignedEnvelope(p.context, p.signingKey, p.Point(), 0, OperationPrivateReady, 0, 0,
		p.transcript.Root(p.context), bundle.KeyID, readyPayload)
	if err != nil {
		return SealedOperatorBundle{}, SignedEnvelope{}, p.poison(err)
	}
	return sealed, ready, nil
}

func BuildPublicBundle(unsigned UnsignedPublicBundle, attestations, privateReady []SignedEnvelope) (PublicBundle, error) {
	bundle := PublicBundle{
		SchemaVersion: PublicBundleSchema,
		Unsigned:      unsigned,
		Attestations:  sortEnvelopes(attestations),
		PrivateReady:  sortEnvelopes(privateReady),
	}
	if err := VerifyPublicBundle(bundle); err != nil {
		return PublicBundle{}, err
	}
	return bundle, nil
}

func (b PublicBundle) MarshalBinary() ([]byte, error) {
	unsigned, err := b.Unsigned.MarshalBinary()
	if err != nil || b.SchemaVersion != PublicBundleSchema {
		return nil, ErrBinding
	}
	var e encoder
	e.text("MordantOneShotPublishedBundle/v1")
	e.text(b.SchemaVersion)
	e.field(unsigned)
	for _, list := range [][]SignedEnvelope{b.Attestations, b.PrivateReady} {
		e.u32(uint32(len(list)))
		for _, envelope := range list {
			encoded, marshalErr := envelope.MarshalBinary()
			if marshalErr != nil {
				return nil, marshalErr
			}
			e.field(encoded)
		}
	}
	return e.Bytes(), nil
}

func ParsePublicBundle(data []byte) (PublicBundle, error) {
	var bundle PublicBundle
	d := newDecoder(data)
	magic, err := d.text()
	if err != nil || magic != "MordantOneShotPublishedBundle/v1" {
		return bundle, errCanonical
	}
	if bundle.SchemaVersion, err = d.text(); err != nil || bundle.SchemaVersion != PublicBundleSchema {
		return bundle, errCanonical
	}
	unsigned, err := d.field()
	if err != nil {
		return bundle, err
	}
	if bundle.Unsigned, err = ParseUnsignedPublicBundle(unsigned); err != nil {
		return bundle, err
	}
	for _, target := range []*[]SignedEnvelope{&bundle.Attestations, &bundle.PrivateReady} {
		count, readErr := d.u32()
		if readErr != nil || count != PartyCount {
			return PublicBundle{}, errCanonical
		}
		*target = make([]SignedEnvelope, count)
		for i := range *target {
			encoded, fieldErr := d.field()
			if fieldErr != nil {
				return PublicBundle{}, fieldErr
			}
			if (*target)[i], fieldErr = ParseSignedEnvelope(encoded); fieldErr != nil {
				return PublicBundle{}, fieldErr
			}
		}
	}
	if err := d.done(); err != nil {
		return PublicBundle{}, err
	}
	reencoded, err := bundle.MarshalBinary()
	if err != nil || !slices.Equal(reencoded, data) {
		return PublicBundle{}, errCanonical
	}
	return bundle, nil
}

func (b PublicBundle) Digest() [32]byte {
	encoded, err := b.MarshalBinary()
	if err != nil {
		return [32]byte{}
	}
	return hashDomain("MordantOneShotPublishedBundleDigest/v1", encoded)
}

func VerifyPublicBundle(bundle PublicBundle) error {
	if _, err := VerifyUnsignedPublicBundle(bundle.Unsigned); err != nil || bundle.SchemaVersion != PublicBundleSchema ||
		len(bundle.Attestations) != PartyCount || len(bundle.PrivateReady) != PartyCount {
		return ErrBinding
	}
	unsignedDigest := bundle.Unsigned.Digest()
	previous := bundle.Unsigned.Transcript.Root(bundle.Unsigned.Context)
	for index, attestation := range bundle.Attestations {
		if _, err := VerifySignedEnvelope(bundle.Unsigned.Context, attestation); err != nil ||
			attestation.Header.Operation != OperationManifestAttestation || attestation.Header.SenderPoint != bundle.Unsigned.Context.Operators[index].Point ||
			attestation.Header.PreviousTranscriptDigest != previous || attestation.Header.InputDigest != bundle.Unsigned.KeyID ||
			!slices.Equal(attestation.Payload, unsignedDigest[:]) {
			return ErrSignature
		}
	}
	for index, ready := range bundle.PrivateReady {
		if _, err := VerifySignedEnvelope(bundle.Unsigned.Context, ready); err != nil || ready.Header.Operation != OperationPrivateReady ||
			ready.Header.SenderPoint != bundle.Unsigned.Context.Operators[index].Point || ready.Header.PreviousTranscriptDigest != previous ||
			ready.Header.InputDigest != bundle.Unsigned.KeyID {
			return ErrSignature
		}
		readyUnsigned, sealedDigest, err := parsePrivateReady(ready.Payload)
		if err != nil || readyUnsigned != unsignedDigest || isZero32(sealedDigest) {
			return ErrBinding
		}
	}
	return nil
}

func VerifyPublishedCeremony(context Context, bundle PublicBundle, receipt PublicationReceipt, replicas ...[]WitnessRecord) error {
	if err := VerifyPublicBundle(bundle); err != nil || bundle.Unsigned.Context.CeremonyID() != context.CeremonyID() {
		return ErrBinding
	}
	if err := VerifyPublicationReceipt(receipt, bundle); err != nil {
		return err
	}
	if err := VerifyReplicaAgreement(context, replicas...); err != nil {
		return err
	}
	records := replicas[0]
	manifestIndex := -1
	for index := range records {
		if records[index].Statement.ToPhase == PhaseManifest {
			manifestIndex = index
			break
		}
	}
	if manifestIndex < 1 || records[manifestIndex-1].Digest() != bundle.Unsigned.PreManifestWitnessDigest ||
		records[manifestIndex].Statement.MaterialDigest != bundle.Unsigned.Digest() {
		return ErrBinding
	}
	if manifestIndex+2 >= len(records) || records[manifestIndex+1].Statement.ToPhase != PhasePublished ||
		records[manifestIndex+1].Statement.MaterialDigest != receipt.Digest() {
		return ErrState
	}
	last := records[len(records)-1].Statement
	if last.ToPhase != PhaseCompleted || last.MaterialDigest != completionMaterialDigest(bundle, receipt) || last.TranscriptDigest != bundle.Unsigned.Transcript.Root(context) {
		return ErrState
	}
	return nil
}

// PublishPublicBundle creates one restricted publication directory and uses a
// no-replace, fsynced write. It never treats a cross-host operation as atomic.
func PublishPublicBundle(root string, bundle PublicBundle) (PublicationReceipt, error) {
	if !filepath.IsAbs(root) || VerifyPublicBundle(bundle) != nil {
		return PublicationReceipt{}, ErrPersistence
	}
	if err := ensureNoSymlinkPath(root); err != nil {
		return PublicationReceipt{}, err
	}
	if err := os.Mkdir(root, 0o700); err != nil && !os.IsExist(err) {
		return PublicationReceipt{}, ErrPersistence
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return PublicationReceipt{}, ErrPersistence
	}
	encoded, err := bundle.MarshalBinary()
	if err != nil {
		return PublicationReceipt{}, err
	}
	store := &WitnessStore{root: root}
	if err := store.writeNoReplace("public.bundle", encoded); err != nil {
		return PublicationReceipt{}, err
	}
	objectPath := filepath.Join(root, "public.bundle")
	readback, err := readNoSymlinkFile(objectPath)
	if err != nil || !slices.Equal(readback, encoded) {
		return PublicationReceipt{}, ErrPersistence
	}
	parsed, err := ParsePublicBundle(readback)
	if err != nil || parsed.Digest() != bundle.Digest() {
		return PublicationReceipt{}, ErrPersistence
	}
	receipt := PublicationReceipt{
		SchemaVersion:        "mordant.fhe-publication-receipt/oneshot-v2",
		CeremonyID:           bundle.Unsigned.Context.CeremonyID(),
		BundleDigest:         bundle.Digest(),
		CanonicalBytesSHA256: sha256.Sum256(readback),
		ObjectPath:           objectPath,
		ObjectSize:           uint64(len(readback)),
	}
	if err := VerifyPublicationReceipt(receipt, bundle); err != nil {
		return PublicationReceipt{}, err
	}
	return receipt, nil
}

func VerifyPublicationReceipt(receipt PublicationReceipt, bundle PublicBundle) error {
	if VerifyPublicBundle(bundle) != nil || receipt.CeremonyID != bundle.Unsigned.Context.CeremonyID() || receipt.BundleDigest != bundle.Digest() {
		return ErrBinding
	}
	if _, err := receipt.MarshalBinary(); err != nil || ensureNoSymlinkPath(receipt.ObjectPath) != nil {
		return ErrPersistence
	}
	readback, err := readNoSymlinkFile(receipt.ObjectPath)
	if err != nil || uint64(len(readback)) != receipt.ObjectSize || sha256.Sum256(readback) != receipt.CanonicalBytesSHA256 {
		return ErrPersistence
	}
	parsed, err := ParsePublicBundle(readback)
	if err != nil || parsed.Digest() != receipt.BundleDigest || !slices.Equal(readback, mustPublicBundleBytes(bundle)) {
		return ErrPersistence
	}
	return nil
}

func mustPublicBundleBytes(bundle PublicBundle) []byte {
	encoded, err := bundle.MarshalBinary()
	if err != nil {
		return nil
	}
	return encoded
}

func (b PrivateBundle) MarshalBinary() ([]byte, error) {
	if b.SchemaVersion != PrivateBundleSchema || !validCommit(b.SourceCommit) || b.LattigoModuleChecksum != LattigoModuleChecksum ||
		isZero32(b.CeremonyID) || isZero32(b.ContextDigest) || isZero32(b.RosterDigest) || isZero32(b.ScopeOrdinalDigest) ||
		isZero32(b.SessionCommitment) || b.AttemptOrdinal == 0 || b.OperatorPoint == 0 || isZero32(b.OperatorRuntimeDigest) ||
		b.GoVersion == "" || b.OperatingSystem == "" || b.Architecture == "" || isZero32(b.SigningKeyReference) ||
		isZero32(b.TransportKeyReference) || isZero32(b.ParameterFingerprint) || b.CircuitVersion == 0 || isZero32(b.CircuitDigest) ||
		b.ReleaseLayout == 0 || b.MaximumReleaseQueries == 0 || isZero32(b.KeyID) || isZero32(b.UnsignedBundleDigest) || isZero32(b.TranscriptDigest) ||
		isZero32(b.PublicKeyDigest) || isZero32(b.EvaluationKeyDigest) || isZero32(b.WitnessHeadDigest) || isZero32(b.StatusDigest) ||
		b.ActivatesAtUnix <= 0 || b.ExpiresAtUnix <= b.ActivatesAtUnix || len(b.ThresholdShare) == 0 {
		return nil, ErrBinding
	}
	var e encoder
	e.text(PrivateBundleSchema)
	e.text(b.SchemaVersion)
	e.text(b.SourceCommit)
	e.text(b.LattigoModuleChecksum)
	e.u32(SerializationVersion)
	e.text(LattigoVersion)
	e.text(KeyScope)
	e.u64(EphemeralKeyEpoch)
	e.u32(MaximumSessions)
	e.u16(Threshold)
	e.u16(PartyCount)
	e.fixed(b.CeremonyID[:])
	e.fixed(b.ContextDigest[:])
	e.fixed(b.RosterDigest[:])
	e.fixed(b.ScopeOrdinalDigest[:])
	e.fixed(b.SessionCommitment[:])
	e.u64(b.AttemptOrdinal)
	e.u64(b.OperatorPoint)
	e.fixed(b.OperatorRuntimeDigest[:])
	e.text(b.GoVersion)
	e.text(b.OperatingSystem)
	e.text(b.Architecture)
	e.fixed(b.SigningKeyReference[:])
	e.fixed(b.TransportKeyReference[:])
	e.fixed(b.ParameterFingerprint[:])
	e.u32(b.CircuitVersion)
	e.fixed(b.CircuitDigest[:])
	e.u32(b.ReleaseLayout)
	e.u32(b.MaximumReleaseQueries)
	e.fixed(b.KeyID[:])
	e.fixed(b.UnsignedBundleDigest[:])
	e.fixed(b.TranscriptDigest[:])
	e.fixed(b.PublicKeyDigest[:])
	e.fixed(b.EvaluationKeyDigest[:])
	e.fixed(b.WitnessHeadDigest[:])
	e.fixed(b.StatusDigest[:])
	e.i64(b.ActivatesAtUnix)
	e.i64(b.ExpiresAtUnix)
	e.field(b.ThresholdShare)
	return e.Bytes(), nil
}

func ParsePrivateBundle(data []byte) (PrivateBundle, error) {
	var bundle PrivateBundle
	d := newDecoder(data)
	magic, err := d.text()
	if err != nil || magic != PrivateBundleSchema {
		return bundle, errCanonical
	}
	if bundle.SchemaVersion, err = d.text(); err != nil || bundle.SchemaVersion != PrivateBundleSchema {
		return bundle, errCanonical
	}
	if bundle.SourceCommit, err = d.text(); err != nil {
		return bundle, err
	}
	if bundle.LattigoModuleChecksum, err = d.text(); err != nil {
		return bundle, err
	}
	serialization, _ := d.u32()
	lattigo, _ := d.text()
	scope, _ := d.text()
	epoch, _ := d.u64()
	maximum, _ := d.u32()
	threshold, _ := d.u16()
	parties, _ := d.u16()
	if serialization != SerializationVersion || lattigo != LattigoVersion || scope != KeyScope || epoch != 0 || maximum != MaximumSessions || threshold != Threshold || parties != PartyCount {
		return PrivateBundle{}, errCanonical
	}
	for _, target := range []*[32]byte{&bundle.CeremonyID, &bundle.ContextDigest, &bundle.RosterDigest, &bundle.ScopeOrdinalDigest, &bundle.SessionCommitment} {
		value, readErr := d.fixed(32)
		if readErr != nil || copy32(target, value) != nil {
			return PrivateBundle{}, errCanonical
		}
	}
	if bundle.AttemptOrdinal, err = d.u64(); err != nil {
		return bundle, err
	}
	if bundle.OperatorPoint, err = d.u64(); err != nil {
		return bundle, err
	}
	value, err := d.fixed(32)
	if err != nil || copy32(&bundle.OperatorRuntimeDigest, value) != nil {
		return bundle, errCanonical
	}
	if bundle.GoVersion, err = d.text(); err != nil {
		return bundle, err
	}
	if bundle.OperatingSystem, err = d.text(); err != nil {
		return bundle, err
	}
	if bundle.Architecture, err = d.text(); err != nil {
		return bundle, err
	}
	for _, target := range []*[32]byte{&bundle.SigningKeyReference, &bundle.TransportKeyReference, &bundle.ParameterFingerprint} {
		value, readErr := d.fixed(32)
		if readErr != nil || copy32(target, value) != nil {
			return PrivateBundle{}, errCanonical
		}
	}
	if bundle.CircuitVersion, err = d.u32(); err != nil {
		return bundle, err
	}
	value, err = d.fixed(32)
	if err != nil || copy32(&bundle.CircuitDigest, value) != nil {
		return bundle, errCanonical
	}
	if bundle.ReleaseLayout, err = d.u32(); err != nil {
		return bundle, err
	}
	if bundle.MaximumReleaseQueries, err = d.u32(); err != nil {
		return bundle, err
	}
	for _, target := range []*[32]byte{&bundle.KeyID, &bundle.UnsignedBundleDigest, &bundle.TranscriptDigest, &bundle.PublicKeyDigest, &bundle.EvaluationKeyDigest, &bundle.WitnessHeadDigest, &bundle.StatusDigest} {
		value, readErr := d.fixed(32)
		if readErr != nil || copy32(target, value) != nil {
			return PrivateBundle{}, errCanonical
		}
	}
	if bundle.ActivatesAtUnix, err = d.i64(); err != nil {
		return bundle, err
	}
	if bundle.ExpiresAtUnix, err = d.i64(); err != nil {
		return bundle, err
	}
	if bundle.ThresholdShare, err = d.field(); err != nil || len(bundle.ThresholdShare) == 0 || d.done() != nil {
		return PrivateBundle{}, errCanonical
	}
	reencoded, err := bundle.MarshalBinary()
	if err != nil || !slices.Equal(reencoded, data) {
		return PrivateBundle{}, errCanonical
	}
	return bundle, nil
}

func (s SealedOperatorBundle) MarshalBinary() ([]byte, error) {
	if s.SchemaVersion != PrivateBundleSchema || isZero32(s.CeremonyID) || s.OperatorPoint == 0 || isZero32(s.KeyID) || isZero32(s.UnsignedBundleDigest) || len(s.Ciphertext) == 0 {
		return nil, ErrBinding
	}
	var e encoder
	e.text("MordantOneShotSealedOperatorBundle/v1")
	e.text(s.SchemaVersion)
	e.fixed(s.CeremonyID[:])
	e.u64(s.OperatorPoint)
	e.fixed(s.KeyID[:])
	e.fixed(s.UnsignedBundleDigest[:])
	e.fixed(s.Nonce[:])
	e.field(s.Ciphertext)
	return e.Bytes(), nil
}

func ParseSealedOperatorBundle(data []byte) (SealedOperatorBundle, error) {
	var sealed SealedOperatorBundle
	d := newDecoder(data)
	magic, err := d.text()
	if err != nil || magic != "MordantOneShotSealedOperatorBundle/v1" {
		return sealed, errCanonical
	}
	if sealed.SchemaVersion, err = d.text(); err != nil || sealed.SchemaVersion != PrivateBundleSchema {
		return sealed, errCanonical
	}
	value, err := d.fixed(32)
	if err != nil || copy32(&sealed.CeremonyID, value) != nil {
		return sealed, errCanonical
	}
	if sealed.OperatorPoint, err = d.u64(); err != nil {
		return sealed, err
	}
	for _, target := range []*[32]byte{&sealed.KeyID, &sealed.UnsignedBundleDigest} {
		value, readErr := d.fixed(32)
		if readErr != nil || copy32(target, value) != nil {
			return SealedOperatorBundle{}, errCanonical
		}
	}
	value, err = d.fixed(12)
	if err != nil {
		return sealed, err
	}
	copy(sealed.Nonce[:], value)
	if sealed.Ciphertext, err = d.field(); err != nil || len(sealed.Ciphertext) == 0 || d.done() != nil {
		return SealedOperatorBundle{}, errCanonical
	}
	reencoded, err := sealed.MarshalBinary()
	if err != nil || !slices.Equal(reencoded, data) {
		return SealedOperatorBundle{}, errCanonical
	}
	return sealed, nil
}

func (s SealedOperatorBundle) Digest() [32]byte {
	encoded, err := s.MarshalBinary()
	if err != nil {
		return [32]byte{}
	}
	return hashDomain("MordantOneShotSealedOperatorBundleDigest/v1", encoded)
}

func (s SealedOperatorBundle) additionalData() []byte {
	var e encoder
	e.text(s.SchemaVersion)
	e.fixed(s.CeremonyID[:])
	e.u64(s.OperatorPoint)
	e.fixed(s.KeyID[:])
	e.fixed(s.UnsignedBundleDigest[:])
	return e.Bytes()
}

func OpenCompletedOperatorBundle(
	sealed SealedOperatorBundle,
	sealingKey []byte,
	context Context,
	bundle PublicBundle,
	receipt PublicationReceipt,
	store *WitnessStore,
	replicas ...[]WitnessRecord,
) (PrivateBundle, error) {
	if len(sealingKey) != 32 || store == nil || sealed.CeremonyID != context.CeremonyID() ||
		sealed.UnsignedBundleDigest != bundle.Unsigned.Digest() || sealed.KeyID != bundle.Unsigned.KeyID {
		return PrivateBundle{}, ErrSecretAccess
	}
	if err := VerifyPublishedCeremony(context, bundle, receipt, replicas...); err != nil {
		return PrivateBundle{}, ErrSecretAccess
	}
	sealedDigest := sealed.Digest()
	readyBound := false
	for _, ready := range bundle.PrivateReady {
		unsigned, candidate, err := parsePrivateReady(ready.Payload)
		if err == nil && ready.Header.SenderPoint == sealed.OperatorPoint && unsigned == bundle.Unsigned.Digest() && candidate == sealedDigest {
			readyBound = true
			break
		}
	}
	if !readyBound {
		return PrivateBundle{}, ErrSecretAccess
	}
	tombstone, err := store.TerminalTombstone(context.CeremonyID())
	lastEvent := replicas[0][len(replicas[0])-1].EventDigest()
	if err != nil || tombstone.Disposition != DispositionCompleted || tombstone.SessionBindingDigest != context.SessionBindingDigest() ||
		tombstone.WitnessEventDigest != lastEvent || tombstone.KeyID != sealed.KeyID ||
		tombstone.PublishedBundleDigest != bundle.Digest() || tombstone.PublicationReceiptDigest != receipt.Digest() {
		return PrivateBundle{}, ErrSecretAccess
	}
	aead, err := operatorBundleAEAD(sealingKey)
	if err != nil {
		return PrivateBundle{}, err
	}
	plaintext, err := aead.Open(nil, sealed.Nonce[:], sealed.Ciphertext, sealed.additionalData())
	if err != nil {
		return PrivateBundle{}, ErrSecretAccess
	}
	privateBundle, err := ParsePrivateBundle(plaintext)
	if err != nil || privateBundle.CeremonyID != context.CeremonyID() || privateBundle.ContextDigest != context.ContextDigest() ||
		privateBundle.RosterDigest != context.RosterDigest() || privateBundle.ScopeOrdinalDigest != context.ScopeOrdinalDigest() ||
		privateBundle.SessionCommitment != context.SessionCommitment || privateBundle.AttemptOrdinal != context.AttemptOrdinal ||
		privateBundle.OperatorPoint != sealed.OperatorPoint || privateBundle.KeyID != sealed.KeyID ||
		privateBundle.UnsignedBundleDigest != sealed.UnsignedBundleDigest {
		return PrivateBundle{}, ErrBinding
	}
	return privateBundle, nil
}

func PublishSealedOperatorBundle(root string, sealed SealedOperatorBundle) error {
	if !filepath.IsAbs(root) {
		return ErrPersistence
	}
	if err := ensureNoSymlinkPath(root); err != nil {
		return err
	}
	if err := os.Mkdir(root, 0o700); err != nil && !os.IsExist(err) {
		return ErrPersistence
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return ErrPersistence
	}
	encoded, err := sealed.MarshalBinary()
	if err != nil {
		return err
	}
	store := &WitnessStore{root: root}
	return store.writeNoReplace("operator.bundle", encoded)
}

func (s KeyStatusStatement) MarshalBinary() ([]byte, error) {
	if s.SchemaVersion != StatusSchema || isZero32(s.KeyID) || s.Sequence == 0 || s.Status < StatusActive || s.Status > StatusExpired || s.EffectiveAt <= 0 || isZero32(s.ReasonDigest) {
		return nil, ErrBinding
	}
	var e encoder
	e.text(StatusSchema)
	e.text(s.SchemaVersion)
	e.fixed(s.KeyID[:])
	e.u64(s.Sequence)
	e.u8(uint8(s.Status))
	e.i64(s.EffectiveAt)
	e.fixed(s.ReasonDigest[:])
	e.fixed(s.PreviousDigest[:])
	return e.Bytes(), nil
}

func ParseKeyStatusStatement(data []byte) (KeyStatusStatement, error) {
	var status KeyStatusStatement
	d := newDecoder(data)
	magic, err := d.text()
	if err != nil || magic != StatusSchema {
		return status, errCanonical
	}
	if status.SchemaVersion, err = d.text(); err != nil {
		return status, err
	}
	value, err := d.fixed(32)
	if err != nil || copy32(&status.KeyID, value) != nil {
		return status, errCanonical
	}
	if status.Sequence, err = d.u64(); err != nil {
		return status, err
	}
	state, err := d.u8()
	if err != nil {
		return status, err
	}
	status.Status = KeyStatus(state)
	if status.EffectiveAt, err = d.i64(); err != nil {
		return status, err
	}
	for _, target := range []*[32]byte{&status.ReasonDigest, &status.PreviousDigest} {
		value, readErr := d.fixed(32)
		if readErr != nil || copy32(target, value) != nil {
			return KeyStatusStatement{}, errCanonical
		}
	}
	if err := d.done(); err != nil {
		return KeyStatusStatement{}, err
	}
	reencoded, err := status.MarshalBinary()
	if err != nil || !slices.Equal(reencoded, data) {
		return KeyStatusStatement{}, errCanonical
	}
	return status, nil
}

func (s KeyStatusStatement) Digest() [32]byte {
	encoded, err := s.MarshalBinary()
	if err != nil {
		return [32]byte{}
	}
	return hashDomain("MordantOneShotKeyStatusDigest/v1", encoded)
}

func ReconstructPublicMaterial(params bgv.Parameters, context Context, transcript Transcript) (PublicMaterial, [32]byte, error) {
	if !transcript.Complete(context) {
		return PublicMaterial{}, [32]byte{}, ErrState
	}
	seed, commitment, err := crsFromTranscript(context, transcript)
	if err != nil {
		return PublicMaterial{}, [32]byte{}, err
	}
	publicKey, err := reconstructPublicKey(params, context, seed, transcript.Stages[3])
	if err != nil {
		return PublicMaterial{}, [32]byte{}, err
	}
	publicBytes, err := publicKey.MarshalBinary()
	if err != nil {
		return PublicMaterial{}, [32]byte{}, ErrMaterial
	}
	roundOne, err := aggregateRelinShare(params, transcript.Stages[4], 1)
	if err != nil {
		return PublicMaterial{}, [32]byte{}, err
	}
	roundTwo, err := aggregateRelinShare(params, transcript.Stages[5], 2)
	if err != nil {
		return PublicMaterial{}, [32]byte{}, err
	}
	relinProtocol := multiparty.NewRelinearizationKeyGenProtocol(params)
	relinKey := rlwe.NewRelinearizationKey(params)
	relinProtocol.GenRelinearizationKey(roundOne, roundTwo, relinKey)
	relinBytes, err := relinKey.MarshalBinary()
	if err != nil {
		return PublicMaterial{}, [32]byte{}, ErrMaterial
	}
	galois := make([][]byte, len(context.GaloisElements))
	for index := range context.GaloisElements {
		key, keyErr := reconstructGaloisKey(params, context, seed, transcript.Stages[6+index])
		if keyErr != nil {
			return PublicMaterial{}, [32]byte{}, keyErr
		}
		if galois[index], keyErr = key.MarshalBinary(); keyErr != nil {
			return PublicMaterial{}, [32]byte{}, ErrMaterial
		}
	}
	return PublicMaterial{publicBytes, relinBytes, galois}, commitment, nil
}

func crsFromTranscript(context Context, transcript Transcript) ([32]byte, [32]byte, error) {
	commits, reveals := transcript.Stages[0].Envelopes, transcript.Stages[1].Envelopes
	if len(commits) != PartyCount || len(reveals) != PartyCount {
		return [32]byte{}, [32]byte{}, ErrBinding
	}
	var e encoder
	e.text("MordantOneShotCRS/v1")
	ceremonyID := context.CeremonyID()
	e.fixed(ceremonyID[:])
	for index, reveal := range reveals {
		if len(reveal.Payload) != 32 || crsContributionCommitment(context, reveal.Header.SenderPoint, bytes32(reveal.Payload)) != bytes32(commits[index].Payload) {
			return [32]byte{}, [32]byte{}, ErrBinding
		}
		e.u64(reveal.Header.SenderPoint)
		e.fixed(reveal.Payload)
	}
	seed := sha256.Sum256(e.Bytes())
	commitment := hashDomain("MordantOneShotCRSCommitment/v1", seed[:], ceremonyID[:])
	return seed, commitment, nil
}

func deriveKeyID(context Context, material PublicMaterial) [32]byte {
	publicDigest := sha256.Sum256(material.PublicKeyBytes)
	relinDigest := sha256.Sum256(material.RelinearizationBytes)
	galoisDigest := evaluationKeyDigest(nil, material.GaloisKeyBytes, context.GaloisElements)
	contextDigest := context.ContextDigest()
	rosterDigest := context.RosterDigest()
	var e encoder
	e.text(KeyScope)
	e.fixed(context.SessionCommitment[:])
	e.u64(EphemeralKeyEpoch)
	return hashDomain("MordantFheKeyId/v2", contextDigest[:], rosterDigest[:], context.ParameterFingerprint[:],
		publicDigest[:], relinDigest[:], galoisDigest[:], e.Bytes())
}

func evaluationKeyDigest(relin []byte, galois [][]byte, elements []uint64) [32]byte {
	var e encoder
	e.text("MordantOneShotEvaluationKeys/v1")
	e.field(relin)
	e.u32(uint32(len(galois)))
	for index, key := range galois {
		e.u64(elements[index])
		e.field(key)
	}
	return sha256.Sum256(e.Bytes())
}

func publicMaterialEqual(left, right PublicMaterial) bool {
	if !slices.Equal(left.PublicKeyBytes, right.PublicKeyBytes) || !slices.Equal(left.RelinearizationBytes, right.RelinearizationBytes) || len(left.GaloisKeyBytes) != len(right.GaloisKeyBytes) {
		return false
	}
	for index := range left.GaloisKeyBytes {
		if !slices.Equal(left.GaloisKeyBytes[index], right.GaloisKeyBytes[index]) {
			return false
		}
	}
	return true
}

func participantMaterialMatches(participant *Participant, bundle UnsignedPublicBundle) bool {
	if participant == nil || bundle.Context.CeremonyID() != participant.context.CeremonyID() || bundle.Transcript.Root(bundle.Context) != participant.transcript.Root(participant.context) {
		return false
	}
	if len(participant.records) < 2 || participant.records[len(participant.records)-1].Statement.ToPhase != PhaseManifest ||
		participant.records[len(participant.records)-1].Statement.MaterialDigest != bundle.Digest() ||
		participant.records[len(participant.records)-2].Digest() != bundle.PreManifestWitnessDigest {
		return false
	}
	material := PublicMaterial{participant.publicKeyBytes, participant.relinKeyBytes, participant.galoisKeyBytes}
	return publicMaterialEqual(material, PublicMaterial{bundle.PublicKey, bundle.RelinearizationKey, bundle.GaloisKeys})
}

func privateReadyPayload(unsigned, sealed [32]byte) []byte {
	var e encoder
	e.text("MordantOneShotPrivateReady/v1")
	e.fixed(unsigned[:])
	e.fixed(sealed[:])
	return e.Bytes()
}

func parsePrivateReady(data []byte) ([32]byte, [32]byte, error) {
	var unsigned, sealed [32]byte
	d := newDecoder(data)
	magic, err := d.text()
	if err != nil || magic != "MordantOneShotPrivateReady/v1" {
		return unsigned, sealed, errCanonical
	}
	for _, target := range []*[32]byte{&unsigned, &sealed} {
		value, readErr := d.fixed(32)
		if readErr != nil || copy32(target, value) != nil {
			return unsigned, sealed, errCanonical
		}
	}
	if err := d.done(); err != nil {
		return unsigned, sealed, err
	}
	return unsigned, sealed, nil
}

func operatorBundleAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, ErrSecretAccess
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrSecretAccess
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrSecretAccess
	}
	return aead, nil
}

func sortEnvelopes(input []SignedEnvelope) []SignedEnvelope {
	out := slices.Clone(input)
	slices.SortFunc(out, func(a, b SignedEnvelope) int {
		if a.Header.SenderPoint < b.Header.SenderPoint {
			return -1
		}
		if a.Header.SenderPoint > b.Header.SenderPoint {
			return 1
		}
		return 0
	})
	return out
}
