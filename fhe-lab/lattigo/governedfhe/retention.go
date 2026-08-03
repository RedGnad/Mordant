package governedfhe

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
)

const retainedProtectionEvidenceSchema = "mordant.protection-evidence/4"

type retainedEvidenceProjection struct {
	SchemaVersion  string `json:"schemaVersion"`
	ManifestDigest Digest `json:"manifestDigest"`
	Scenario       string `json:"scenario"`
	ProtectionCase struct {
		FHECaseID Digest `json:"fheCaseId"`
	} `json:"protectionCase"`
}

// RetainPublicEvidence publishes one verified public manifest through a pinned
// directory capability. The root must already exist in immutable local
// operator configuration; this function never creates or follows it.
func RetainPublicEvidence(root, scenario string, expectedManifest, expectedCase Digest, data []byte) (bool, error) {
	return retainPublicEvidence(root, scenario, expectedManifest, expectedCase, data, nil)
}

func retainPublicEvidence(root, scenario string, expectedManifest, expectedCase Digest, data []byte, afterPin func()) (bool, error) {
	name := ""
	if scenario == "conflict" {
		name = "conflict.json"
	} else if scenario == "no-conflict" {
		name = "no-conflict.json"
	} else {
		return false, ErrStore
	}
	if !filepath.IsAbs(root) || len(data) == 0 {
		return false, ErrStore
	}
	info, err := os.Lstat(root)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return false, ErrStore
	}
	var projection retainedEvidenceProjection
	if json.Unmarshal(data, &projection) != nil || projection.SchemaVersion != retainedProtectionEvidenceSchema ||
		projection.Scenario != scenario || projection.ManifestDigest != expectedManifest ||
		projection.ProtectionCase.FHECaseID != expectedCase || !nonzero(expectedManifest, expectedCase) {
		return false, ErrArtifact
	}
	store, err := openObjectStore(root, PublicCaseQuota, false)
	if err != nil {
		return false, err
	}
	defer store.close()
	if store.verifyPathIdentity() != nil {
		return false, ErrStore
	}
	if afterPin != nil {
		afterPin()
	}
	if store.exists(name) {
		prior, _, err := store.readNamed(name, PublicCaseQuota)
		if err != nil || !bytes.Equal(prior, data) || store.verifyPathIdentity() != nil {
			return false, ErrStore
		}
		return true, nil
	}
	if _, err := store.create(name, data); err != nil {
		return false, err
	}
	retained, _, err := store.readNamed(name, PublicCaseQuota)
	if err != nil || !bytes.Equal(retained, data) || store.verifyPathIdentity() != nil {
		return false, ErrStore
	}
	return false, nil
}
