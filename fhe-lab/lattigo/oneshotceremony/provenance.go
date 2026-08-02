package oneshotceremony

import (
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"slices"
	"sort"
	"strconv"
)

type ExecutableProvenance struct {
	SchemaVersion    string   `json:"schemaVersion"`
	ExecutablePath   string   `json:"executablePath"`
	ExecutableSHA256 [32]byte `json:"executableSha256"`
	SourceRevision   string   `json:"sourceRevision"`
	SourceModified   bool     `json:"sourceModified"`
	GoVersion        string   `json:"goVersion"`
	OperatingSystem  string   `json:"operatingSystem"`
	Architecture     string   `json:"architecture"`
	DependencyDigest [32]byte `json:"dependencyDigest"`
}

func InspectExecutable(path string) (ExecutableProvenance, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return ExecutableProvenance{}, ErrPersistence
	}
	abs, err = filepath.EvalSymlinks(abs)
	if err != nil || ensureNoSymlinkPath(abs) != nil {
		return ExecutableProvenance{}, ErrPersistence
	}
	fileInfo, err := os.Lstat(abs)
	if err != nil || !fileInfo.Mode().IsRegular() || fileInfo.Mode()&os.ModeSymlink != 0 {
		return ExecutableProvenance{}, ErrPersistence
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		return ExecutableProvenance{}, ErrPersistence
	}
	info, err := buildinfo.ReadFile(abs)
	if err != nil || info == nil {
		return ExecutableProvenance{}, fmt.Errorf("%w: executable build info", ErrBinding)
	}
	settings := make(map[string]string, len(info.Settings))
	for _, setting := range info.Settings {
		settings[setting.Key] = setting.Value
	}
	revision := settings["vcs.revision"]
	modified, modifiedErr := strconv.ParseBool(settings["vcs.modified"])
	if !validCommit(revision) || modifiedErr != nil {
		// `go test` executables do not carry VCS settings. They still measure
		// their exact bytes, but receive a deterministic non-acceptance source
		// identifier and are always classified modified. Release executables
		// retain the build-stamped VCS revision above.
		executableDigest := sha256.Sum256(data)
		revision = hex.EncodeToString(executableDigest[:20])
		modified = true
	}
	goos, goarch := settings["GOOS"], settings["GOARCH"]
	if goos == "" {
		goos = runtime.GOOS
	}
	if goarch == "" {
		goarch = runtime.GOARCH
	}
	provenance := ExecutableProvenance{
		SchemaVersion:    "mordant.fhe-executable-provenance/oneshot-v2",
		ExecutablePath:   abs,
		ExecutableSHA256: sha256.Sum256(data),
		SourceRevision:   revision,
		SourceModified:   modified,
		GoVersion:        info.GoVersion,
		OperatingSystem:  goos,
		Architecture:     goarch,
		DependencyDigest: dependencyDigest(info),
	}
	if _, err := provenance.MarshalBinary(); err != nil {
		return ExecutableProvenance{}, err
	}
	return provenance, nil
}

func (p ExecutableProvenance) MarshalBinary() ([]byte, error) {
	if p.SchemaVersion != "mordant.fhe-executable-provenance/oneshot-v2" || !filepath.IsAbs(p.ExecutablePath) ||
		isZero32(p.ExecutableSHA256) || !validCommit(p.SourceRevision) || p.GoVersion == "" || p.OperatingSystem == "" ||
		p.Architecture == "" || isZero32(p.DependencyDigest) {
		return nil, ErrBinding
	}
	var e encoder
	e.text(p.SchemaVersion)
	e.text(filepath.Clean(p.ExecutablePath))
	e.fixed(p.ExecutableSHA256[:])
	e.text(p.SourceRevision)
	if p.SourceModified {
		e.u8(1)
	} else {
		e.u8(0)
	}
	e.text(p.GoVersion)
	e.text(p.OperatingSystem)
	e.text(p.Architecture)
	e.fixed(p.DependencyDigest[:])
	return e.Bytes(), nil
}

func ParseExecutableProvenance(data []byte) (ExecutableProvenance, error) {
	var provenance ExecutableProvenance
	d := newDecoder(data)
	var err error
	if provenance.SchemaVersion, err = d.text(); err != nil || provenance.SchemaVersion != "mordant.fhe-executable-provenance/oneshot-v2" {
		return provenance, errCanonical
	}
	if provenance.ExecutablePath, err = d.text(); err != nil {
		return provenance, errCanonical
	}
	value, err := d.fixed(32)
	if err != nil || copy32(&provenance.ExecutableSHA256, value) != nil {
		return ExecutableProvenance{}, errCanonical
	}
	if provenance.SourceRevision, err = d.text(); err != nil {
		return ExecutableProvenance{}, errCanonical
	}
	modified, err := d.u8()
	if err != nil || modified > 1 {
		return ExecutableProvenance{}, errCanonical
	}
	provenance.SourceModified = modified == 1
	if provenance.GoVersion, err = d.text(); err != nil {
		return ExecutableProvenance{}, errCanonical
	}
	if provenance.OperatingSystem, err = d.text(); err != nil {
		return ExecutableProvenance{}, errCanonical
	}
	if provenance.Architecture, err = d.text(); err != nil {
		return ExecutableProvenance{}, errCanonical
	}
	value, err = d.fixed(32)
	if err != nil || copy32(&provenance.DependencyDigest, value) != nil || d.done() != nil {
		return ExecutableProvenance{}, errCanonical
	}
	reencoded, err := provenance.MarshalBinary()
	if err != nil || !slices.Equal(reencoded, data) {
		return ExecutableProvenance{}, errCanonical
	}
	return provenance, nil
}

func (p ExecutableProvenance) Digest() [32]byte {
	encoded, err := p.MarshalBinary()
	if err != nil {
		return [32]byte{}
	}
	return hashDomain("MordantOneShotExecutableProvenance/v2", encoded)
}

func VerifyExecutableProvenance(expected ExecutableProvenance) error {
	actual, err := InspectExecutable(expected.ExecutablePath)
	if err != nil || actual.Digest() != expected.Digest() {
		return fmt.Errorf("%w: executable provenance drift", ErrPersistence)
	}
	return nil
}

type EvidenceManifest struct {
	SchemaVersion       string
	Classification      string
	CeremonyID          [32]byte
	ContextDigest       [32]byte
	KeyID               [32]byte
	BundleDigest        [32]byte
	BundleBytesSHA256   [32]byte
	PublicationReceipt  [32]byte
	WitnessEventHeads   [PartyCount][32]byte
	WitnessArtifactHash [PartyCount][32]byte
	Executables         [PartyCount]ExecutableProvenance
	ProvenanceVerified  bool
}

func BuildEvidenceManifest(context Context, bundle PublicBundle, receipt PublicationReceipt, replicas [][]WitnessRecord, reservations []AttemptReservation) (EvidenceManifest, error) {
	var manifest EvidenceManifest
	if len(replicas) != PartyCount || len(reservations) != PartyCount || VerifyPublishedCeremony(context, bundle, receipt, replicas...) != nil {
		return manifest, ErrBinding
	}
	if _, err := reservationSetDigest(context, reservations); err != nil {
		return manifest, ErrBinding
	}
	bundleBytes, err := bundle.MarshalBinary()
	if err != nil {
		return manifest, err
	}
	manifest = EvidenceManifest{
		SchemaVersion:      "mordant.fhe-evidence-manifest/oneshot-v2",
		Classification:     "NON_ACCEPTANCE_PROVENANCE_MISMATCH",
		CeremonyID:         context.CeremonyID(),
		ContextDigest:      context.ContextDigest(),
		KeyID:              bundle.Unsigned.KeyID,
		BundleDigest:       bundle.Digest(),
		BundleBytesSHA256:  sha256.Sum256(bundleBytes),
		PublicationReceipt: receipt.Digest(),
	}
	eligible := true
	for index := 0; index < PartyCount; index++ {
		if len(replicas[index]) == 0 {
			return EvidenceManifest{}, ErrBinding
		}
		last := replicas[index][len(replicas[index])-1]
		manifest.WitnessEventHeads[index] = last.EventDigest()
		manifest.WitnessArtifactHash[index] = last.AttestationDigest()
		provenance := reservations[index].StartupProvenance
		manifest.Executables[index] = provenance
		operator := context.Operators[index]
		eligible = eligible && !provenance.SourceModified && provenance.SourceRevision == context.SourceCommit &&
			provenance.ExecutableSHA256 == operator.RuntimeBinaryDigest && provenance.GoVersion == operator.GoVersion &&
			provenance.OperatingSystem == operator.OperatingSystem && provenance.Architecture == operator.Architecture
	}
	manifest.ProvenanceVerified = eligible
	if eligible {
		// Exact provenance is necessary but cannot prove independent hosts,
		// deployment topology, or an acceptance run by itself.
		manifest.Classification = "PROVENANCE_VERIFIED_TOPOLOGY_UNPROVEN"
	} else if slices.ContainsFunc(manifest.Executables[:], func(p ExecutableProvenance) bool { return p.SourceModified }) {
		manifest.Classification = "DIRTY_TREE_NON_ACCEPTANCE"
	}
	return manifest, nil
}

func dependencyDigest(info *debug.BuildInfo) [32]byte {
	entries := []string{info.GoVersion, info.Main.Path + "@" + info.Main.Version + "#" + info.Main.Sum}
	var addModule func(module *debug.Module)
	addModule = func(module *debug.Module) {
		if module == nil {
			return
		}
		entries = append(entries, module.Path+"@"+module.Version+"#"+module.Sum)
		if module.Replace != nil {
			addModule(module.Replace)
		}
	}
	for _, dependency := range info.Deps {
		addModule(dependency)
	}
	sort.Strings(entries)
	var e encoder
	e.text("MordantOneShotDependencyState/v2")
	for _, entry := range entries {
		e.text(entry)
	}
	return hashDomain("MordantOneShotDependencyStateDigest/v2", e.Bytes())
}

func (p ExecutableProvenance) String() string {
	return hex.EncodeToString(p.ExecutableSHA256[:]) + "@" + p.SourceRevision
}

func CurrentExecutableProvenance() (ExecutableProvenance, error) {
	path, err := os.Executable()
	if err != nil {
		return ExecutableProvenance{}, ErrPersistence
	}
	return InspectExecutable(path)
}
