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
	if !validCommit(revision) {
		return ExecutableProvenance{}, fmt.Errorf("%w: executable VCS revision", ErrBinding)
	}
	modified, err := strconv.ParseBool(settings["vcs.modified"])
	if err != nil {
		return ExecutableProvenance{}, fmt.Errorf("%w: executable VCS dirty state", ErrBinding)
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

func BuildEvidenceManifest(context Context, bundle PublicBundle, receipt PublicationReceipt, replicas [][]WitnessRecord, executablePaths []string) (EvidenceManifest, error) {
	var manifest EvidenceManifest
	if len(replicas) != PartyCount || len(executablePaths) != PartyCount || VerifyPublishedCeremony(context, bundle, receipt, replicas...) != nil {
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
		provenance, inspectErr := InspectExecutable(executablePaths[index])
		if inspectErr != nil {
			return EvidenceManifest{}, inspectErr
		}
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
