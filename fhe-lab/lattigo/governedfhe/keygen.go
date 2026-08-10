package governedfhe

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	fhe "mordant.dev/fhe-lab/lattigo"
)

type CreateCaseOptions struct {
	PublicRoot  string
	PrivateRoot string
	Spec        CaseSpec
	// ReleaseMode selects how the case's key is held. Empty means
	// ReleaseModeGovernedDecryptor, which is what every existing caller gets.
	//
	// ReleaseModeCoalitionV5 runs the t-of-n ceremony instead of generating a
	// case secret key, and writes one sealed share per OperatorRoot. No secret
	// key object is created for such a case, so there is nothing to fall back to
	// if the quorum cannot be assembled.
	ReleaseMode string
	// OperatorRoots is required for a coalition case and must be empty
	// otherwise. Each root receives exactly one operator's sealed bundle.
	OperatorRoots    []string
	SourceProvenance Digest
}

type KeyGenerationReport struct {
	Duration                time.Duration `json:"duration"`
	ParameterBytes          int64         `json:"parameterBytes"`
	PublicKeyBytes          int64         `json:"publicKeyBytes"`
	RelinearizationKeyBytes int64         `json:"relinearizationKeyBytes"`
	GaloisKeyBytes          []int64       `json:"galoisKeyBytes"`
	PublicArtifactBytes     int64         `json:"publicArtifactBytes"`
	PrivateArtifactBytes    int64         `json:"privateArtifactBytes"`
}

func ExecutableDigest() (Digest, error) {
	path, err := os.Executable()
	if err != nil {
		return Digest{}, err
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return Digest{}, err
	}
	data, err := os.ReadFile(resolved)
	if err != nil {
		return Digest{}, err
	}
	return DigestBytes(data), nil
}

func rootsDisjoint(publicRoot, privateRoot string) bool {
	publicRoot, privateRoot = filepath.Clean(publicRoot), filepath.Clean(privateRoot)
	relPrivate, errPrivate := filepath.Rel(publicRoot, privateRoot)
	relPublic, errPublic := filepath.Rel(privateRoot, publicRoot)
	isDescendant := func(value string, err error) bool {
		return err == nil && value != "." && value != ".." && !strings.HasPrefix(value, ".."+string(filepath.Separator))
	}
	return publicRoot != privateRoot && !isDescendant(relPrivate, errPrivate) && !isDescendant(relPublic, errPublic)
}

func CreateCase(options CreateCaseOptions) (FHECaseBinding, KeyGenerationReport, error) {
	started := time.Now()
	var report KeyGenerationReport
	if options.Spec.validate() != nil || !nonzero(options.SourceProvenance) || !rootsDisjoint(options.PublicRoot, options.PrivateRoot) {
		return FHECaseBinding{}, report, ErrBinding
	}
	publicStore, err := openObjectStore(options.PublicRoot, PublicCaseQuota, false)
	if err != nil {
		return FHECaseBinding{}, report, err
	}
	defer publicStore.close()
	privateStore, err := openObjectStore(options.PrivateRoot, PrivateCaseQuota, true)
	if err != nil {
		return FHECaseBinding{}, report, err
	}
	defer privateStore.close()
	if publicNames, _ := publicStore.names(); len(publicNames) != 0 {
		return FHECaseBinding{}, report, ErrStore
	}
	if privateNames, _ := privateStore.names(); len(privateNames) != 0 {
		return FHECaseBinding{}, report, ErrStore
	}

	params, err := Parameters()
	if err != nil {
		return FHECaseBinding{}, report, err
	}
	parameterBytes, err := params.MarshalBinary()
	if err != nil {
		return FHECaseBinding{}, report, err
	}
	parameterRef, err := publicStore.create(parametersObject, parameterBytes)
	if err != nil {
		return FHECaseBinding{}, report, err
	}
	report.ParameterBytes = parameterRef.Length

	coalition := options.ReleaseMode == ReleaseModeCoalitionV5

	var (
		secretRef          ObjectRef
		publicKey          *rlwe.PublicKey
		relinearizationKey *rlwe.RelinearizationKey
		galoisKeys         []*rlwe.GaloisKey
		ceremonyMaterial   *fhe.ColocatedCeremonyMaterial
	)
	elements, err := GaloisElements(params)
	if err != nil {
		return FHECaseBinding{}, report, err
	}
	if coalition {
		ceremonyMaterial, err = fhe.RunColocatedCeremony(params, CoalitionThreshold, CoalitionOperators, [32]byte(options.Spec.PolicyID))
		if err != nil {
			return FHECaseBinding{}, report, fmt.Errorf("%w: %v", ErrCoalition, err)
		}
		publicKey = ceremonyMaterial.PublicKey
		relinearizationKey = ceremonyMaterial.RelinearizationKey
		galoisKeys = ceremonyMaterial.GaloisKeys
		if len(galoisKeys) != len(elements) {
			return FHECaseBinding{}, report, fmt.Errorf("%w: ceremony produced %d galois keys, %d required", ErrCoalition, len(galoisKeys), len(elements))
		}
	} else {
		var secretKey *rlwe.SecretKey
		keyGenerator := rlwe.NewKeyGenerator(params)
		secretKey, publicKey = keyGenerator.GenKeyPairNew()
		secretBytes, err := secretKey.MarshalBinary()
		if err != nil {
			return FHECaseBinding{}, report, err
		}
		secretRef, err = privateStore.create(secretKeyObject, secretBytes)
		if err != nil {
			return FHECaseBinding{}, report, err
		}
		for index := range secretBytes {
			secretBytes[index] = 0
		}
		relinearizationKey = keyGenerator.GenRelinearizationKeyNew(secretKey)
		galoisKeys = make([]*rlwe.GaloisKey, len(elements))
		for index, element := range elements {
			galoisKeys[index] = keyGenerator.GenGaloisKeyNew(element, secretKey)
		}
	}
	publicBytes, err := publicKey.MarshalBinary()
	if err != nil {
		return FHECaseBinding{}, report, err
	}
	publicRef, err := publicStore.create(publicKeyObject, publicBytes)
	if err != nil {
		return FHECaseBinding{}, report, err
	}
	report.PublicKeyBytes = publicRef.Length

	relinearizationBytes, err := relinearizationKey.MarshalBinary()
	if err != nil {
		return FHECaseBinding{}, report, err
	}
	relinearizationRef, err := publicStore.create(relinearizationKeyObject, relinearizationBytes)
	if err != nil {
		return FHECaseBinding{}, report, err
	}
	report.RelinearizationKeyBytes = relinearizationRef.Length

	galoisRefs := make([]GaloisKeyRef, len(elements))
	report.GaloisKeyBytes = make([]int64, len(elements))
	for index, element := range elements {
		key := galoisKeys[index]
		if key.GaloisElement != element {
			return FHECaseBinding{}, report, fmt.Errorf("%w: galois key %d is for another element", ErrCoalition, index)
		}
		encoded, err := key.MarshalBinary()
		if err != nil {
			return FHECaseBinding{}, report, err
		}
		ref, err := publicStore.create(galoisObject(index), encoded)
		if err != nil {
			return FHECaseBinding{}, report, fmt.Errorf("galois key %d publication (%d bytes): %w", index, len(encoded), err)
		}
		galoisRefs[index] = GaloisKeyRef{Index: uint32(index), Step: rotationSteps[index], Element: element, Object: ref}
		report.GaloisKeyBytes[index] = ref.Length
	}

	evaluationManifest := EvaluationKeyManifest{RelinearizationKey: relinearizationRef, GaloisKeys: galoisRefs}
	evaluationDigest, err := evaluationManifest.Digest()
	if err != nil {
		return FHECaseBinding{}, report, err
	}
	parameterFingerprint := Digest(sha256.Sum256(parameterBytes))
	releaseMode := options.ReleaseMode
	if releaseMode == "" {
		releaseMode = ReleaseModeGovernedDecryptor
	}

	// The authority a coalition case publishes is its threshold manifest, and
	// the case's authority identity is that manifest's digest. There is no
	// authority key, because a key is exactly what the coalition removes.
	var (
		decryptorPublic   ed25519.PublicKey
		decryptorPrivate  ed25519.PrivateKey
		authorityID       Digest
		coalitionManifest CoalitionThresholdManifest
	)
	if coalition {
		coalitionManifest, err = buildCoalitionThresholdManifest(options.Spec.CaseID, publicRef.Digest, parameterFingerprint, ceremonyMaterial)
		if err != nil {
			return FHECaseBinding{}, report, err
		}
		authorityID, err = coalitionManifest.Digest()
		if err != nil {
			return FHECaseBinding{}, report, err
		}
	} else {
		decryptorPublic, decryptorPrivate, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return FHECaseBinding{}, report, err
		}
		authorityID = releaseAuthorityIdentity(ReleaseModeGovernedDecryptor, decryptorPublic)
	}
	binding := FHECaseBinding{
		SchemaVersion: CaseBindingSchema, CaseID: options.Spec.CaseID, AssetIdentity: options.Spec.AssetIdentity,
		ServiceID: ServiceID, ServiceVersion: ServiceVersion, PolicyID: options.Spec.PolicyID, PolicyVersion: fhe.PolicyVersion,
		CircuitID: CircuitID, CircuitVersion: fhe.CircuitV5Version, CircuitDigest: FixedCircuitDigest(), ParameterProfile: ParameterProfile,
		ParameterFingerprint: parameterFingerprint, PublicKeyDigest: publicRef.Digest, EvaluationKeyManifestDigest: evaluationDigest,
		ParticipantA: options.Spec.ParticipantA, ParticipantB: options.Spec.ParticipantB,
		ParticipantOrder: []Digest{options.Spec.ParticipantA.ID, options.Spec.ParticipantB.ID}, InputSchema: InputSchema, ResultSchema: ResultSchema,
		ReleaseMode: releaseMode, ReleaseAuthorityID: authorityID, ReleaseAuthorityPublicKey: decryptorPublic,
		CaseNonce: options.Spec.CaseNonce, CreatedAtUnix: options.Spec.CreatedAtUnix, ExpiresAtUnix: options.Spec.ExpiresAtUnix,
	}
	if binding.validate() != nil {
		return FHECaseBinding{}, report, ErrBinding
	}
	bindingDigest, err := binding.Digest()
	if err != nil {
		return FHECaseBinding{}, report, err
	}
	cryptoManifest := CaseCryptoManifest{SchemaVersion: CaseCryptoSchema, Parameters: parameterRef, PublicKey: publicRef, EvaluationKeys: evaluationManifest}
	if _, _, err := publicStore.createJSON(caseCryptoObject, cryptoManifest); err != nil {
		return FHECaseBinding{}, report, err
	}
	if _, _, err := publicStore.createJSON(caseBindingObject, binding); err != nil {
		return FHECaseBinding{}, report, err
	}

	if coalition {
		if _, _, err := publicStore.createJSON(thresholdManifestObject, coalitionManifest); err != nil {
			return FHECaseBinding{}, report, err
		}
		if err := writeCoalitionOperatorBundles(options.OperatorRoots, ceremonyMaterial); err != nil {
			return FHECaseBinding{}, report, err
		}
		publicBytesUsed, err := publicStore.usedBytes()
		if err != nil {
			return FHECaseBinding{}, report, err
		}
		report.PublicArtifactBytes = publicBytesUsed
		report.Duration = time.Since(started)
		return binding, report, nil
	}

	signingRef, err := privateStore.create(decryptorSigningKeyObject, decryptorPrivate)
	if err != nil {
		return FHECaseBinding{}, report, err
	}
	authority := ReleaseAuthorityManifest{
		SchemaVersion: ReleaseAuthoritySchema, CaseID: binding.CaseID, CaseBindingDigest: bindingDigest,
		ReleaseMode: ReleaseModeGovernedDecryptor, AuthorityID: authorityID, SigningPublicKey: decryptorPublic,
		SourceProvenance: options.SourceProvenance,
	}
	authority.Signature, err = signCanonical(decryptorPrivate, "MordantReleaseAuthority/v1", authority.signingValue())
	if err != nil {
		return FHECaseBinding{}, report, err
	}
	if _, _, err := publicStore.createJSON(releaseAuthorityObject, authority); err != nil {
		return FHECaseBinding{}, report, err
	}
	privateCase := PrivateCaseManifest{
		SchemaVersion: PrivateCaseSchema, CaseID: binding.CaseID, CaseBindingDigest: bindingDigest,
		SecretKey: secretRef, SigningKey: signingRef, ReleaseAuthorityID: authorityID,
	}
	if _, _, err := privateStore.createJSON(privateCaseObject, privateCase); err != nil {
		return FHECaseBinding{}, report, err
	}

	publicBytesUsed, err := publicStore.usedBytes()
	if err != nil {
		return FHECaseBinding{}, report, err
	}
	privateBytesUsed, err := privateStore.usedBytes()
	if err != nil {
		return FHECaseBinding{}, report, err
	}
	report.PublicArtifactBytes = publicBytesUsed
	report.PrivateArtifactBytes = privateBytesUsed
	report.Duration = time.Since(started)
	return binding, report, nil
}

func loadCaseFoundation(publicStore *objectStore) (FHECaseBinding, CaseCryptoManifest, error) {
	var binding FHECaseBinding
	if _, _, err := publicStore.readJSON(caseBindingObject, &binding); err != nil || binding.validate() != nil {
		return binding, CaseCryptoManifest{}, ErrBinding
	}
	var cryptoManifest CaseCryptoManifest
	if _, _, err := publicStore.readJSON(caseCryptoObject, &cryptoManifest); err != nil || cryptoManifest.SchemaVersion != CaseCryptoSchema {
		return binding, cryptoManifest, ErrArtifact
	}
	if validateCryptoManifest(binding, cryptoManifest) != nil {
		return binding, cryptoManifest, ErrBinding
	}
	return binding, cryptoManifest, nil
}

func validateCryptoManifest(binding FHECaseBinding, cryptoManifest CaseCryptoManifest) error {
	if cryptoManifest.SchemaVersion != CaseCryptoSchema ||
		cryptoManifest.Parameters.validate(parametersObject, 1<<20) != nil ||
		cryptoManifest.PublicKey.validate(publicKeyObject, 64<<20) != nil ||
		cryptoManifest.PublicKey.Digest != binding.PublicKeyDigest ||
		cryptoManifest.EvaluationKeys.RelinearizationKey.validate(relinearizationKeyObject, 96<<20) != nil ||
		len(cryptoManifest.EvaluationKeys.GaloisKeys) != len(rotationSteps) {
		return ErrBinding
	}
	for index, entry := range cryptoManifest.EvaluationKeys.GaloisKeys {
		if entry.Index != uint32(index) || entry.Step != rotationSteps[index] || entry.Element == 0 ||
			entry.Object.validate(galoisObject(index), 96<<20) != nil {
			return ErrBinding
		}
	}
	evaluationDigest, err := cryptoManifest.EvaluationKeys.Digest()
	if err != nil || evaluationDigest != binding.EvaluationKeyManifestDigest {
		return ErrBinding
	}
	return nil
}

func verifyBindingSignature(binding FHECaseBinding, signature ParticipantBindingSignature, identity ParticipantIdentity) error {
	bindingDigest, err := binding.Digest()
	if err != nil || signature.Role != identity.Role || signature.ParticipantID != identity.ID || signature.BindingDigest != bindingDigest {
		return ErrBinding
	}
	value := struct {
		Role          string `json:"role"`
		ParticipantID Digest `json:"participantId"`
		BindingDigest Digest `json:"bindingDigest"`
	}{signature.Role, signature.ParticipantID, signature.BindingDigest}
	return verifyCanonical(ed25519.PublicKey(identity.SigningPublicKey), "MordantFHECaseBindingSignature/v1", value, signature.Signature)
}

func FinalizeCase(publicRoot string) (FHECaseManifest, error) {
	store, err := openObjectStore(publicRoot, PublicCaseQuota, false)
	if err != nil {
		return FHECaseManifest{}, err
	}
	defer store.close()
	binding, cryptoManifest, err := loadCaseFoundation(store)
	if err != nil {
		return FHECaseManifest{}, err
	}
	var signatureA, signatureB ParticipantBindingSignature
	if _, _, err := store.readJSON(bindingSignatureAObject, &signatureA); err != nil {
		return FHECaseManifest{}, err
	}
	if _, _, err := store.readJSON(bindingSignatureBObject, &signatureB); err != nil {
		return FHECaseManifest{}, err
	}
	if verifyBindingSignature(binding, signatureA, binding.ParticipantA) != nil || verifyBindingSignature(binding, signatureB, binding.ParticipantB) != nil {
		return FHECaseManifest{}, ErrBinding
	}
	manifest := FHECaseManifest{SchemaVersion: CaseManifestSchema, Binding: binding, Crypto: cryptoManifest, SignatureA: signatureA, SignatureB: signatureB}
	if _, _, err := store.createJSON(caseManifestObject, manifest); err != nil {
		return FHECaseManifest{}, err
	}
	return manifest, nil
}

func loadCaseManifest(store *objectStore) (FHECaseManifest, error) {
	var manifest FHECaseManifest
	if _, _, err := store.readJSON(caseManifestObject, &manifest); err != nil || manifest.SchemaVersion != CaseManifestSchema || manifest.Binding.validate() != nil {
		return manifest, ErrArtifact
	}
	foundationBinding, foundationCrypto, err := loadCaseFoundation(store)
	if err != nil {
		return manifest, err
	}
	manifestBindingDigest, _, bindingErr := digestCanonical(manifest.Binding)
	foundationBindingDigest, _, foundationBindingErr := digestCanonical(foundationBinding)
	manifestCryptoDigest, _, cryptoErr := digestCanonical(manifest.Crypto)
	foundationCryptoDigest, _, foundationCryptoErr := digestCanonical(foundationCrypto)
	if bindingErr != nil || foundationBindingErr != nil || cryptoErr != nil || foundationCryptoErr != nil ||
		manifestBindingDigest != foundationBindingDigest || manifestCryptoDigest != foundationCryptoDigest ||
		validateCryptoManifest(manifest.Binding, manifest.Crypto) != nil {
		return manifest, ErrBinding
	}
	if verifyBindingSignature(manifest.Binding, manifest.SignatureA, manifest.Binding.ParticipantA) != nil ||
		verifyBindingSignature(manifest.Binding, manifest.SignatureB, manifest.Binding.ParticipantB) != nil {
		return manifest, ErrBinding
	}
	evaluationDigest, err := manifest.Crypto.EvaluationKeys.Digest()
	if err != nil || evaluationDigest != manifest.Binding.EvaluationKeyManifestDigest || manifest.Crypto.PublicKey.Digest != manifest.Binding.PublicKeyDigest {
		return manifest, ErrBinding
	}
	return manifest, nil
}
