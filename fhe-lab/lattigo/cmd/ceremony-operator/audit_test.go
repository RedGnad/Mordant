package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func auditTestBundle(t *testing.T, identity ed25519.PrivateKey, share []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	out.WriteString("MTO1")
	_ = binary.Write(&out, binary.BigEndian, uint32(4))
	out.WriteString("test")
	out.Write(make([]byte, 64))
	_ = binary.Write(&out, binary.BigEndian, uint16(2))
	_ = binary.Write(&out, binary.BigEndian, uint64(1))
	_ = binary.Write(&out, binary.BigEndian, uint16(3))
	for point := uint64(1); point <= 3; point++ {
		_ = binary.Write(&out, binary.BigEndian, point)
	}
	_ = binary.Write(&out, binary.BigEndian, uint32(len(share)))
	out.Write(share)
	_ = binary.Write(&out, binary.BigEndian, uint32(len(identity)))
	out.Write(identity)
	return out.Bytes()
}

func TestOperatorSecretAuditPositiveControlAndLeakDetection(t *testing.T) {
	storage := filepath.Join(t.TempDir(), "operator")
	public := filepath.Join(t.TempDir(), "public")
	if err := os.MkdirAll(storage, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(public, 0o755); err != nil {
		t.Fatal(err)
	}
	_, identity, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	share := make([]byte, 256)
	if _, err := rand.Read(share); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(storage, identityKeyFile), identity, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(storage, operatorBundleFile), auditTestBundle(t, identity, share), 0o600); err != nil {
		t.Fatal(err)
	}
	reportPath := filepath.Join(public, "audit.json")
	settings := options{mode: "audit", storage: storage, point: 1, auditRoots: []string{public}, auditOut: reportPath}
	if err := auditPrivateSurfaces(settings); err != nil {
		t.Fatal(err)
	}
	var wrapper signedPrivateAuditReport
	if raw, err := os.ReadFile(reportPath); err != nil || json.Unmarshal(raw, &wrapper) != nil {
		t.Fatalf("audit report: %v", err)
	}
	var report privateAuditReport
	if err := json.Unmarshal(wrapper.Report, &report); err != nil {
		t.Fatal(err)
	}
	if !report.NoLeaks || !report.PositiveControlDetected || !report.PositiveControlRemoved || len(report.LeakHits) != 0 {
		t.Fatalf("unexpected clean report: %+v", report)
	}
	if _, err := os.Stat(filepath.Join(storage, ".audit-positive-control.tmp")); !os.IsNotExist(err) {
		t.Fatal("positive-control share was retained")
	}

	// Plant a required alternate representation of the actual synthetic share.
	if err := os.WriteFile(filepath.Join(public, "planted.txt"), []byte(base64.RawURLEncoding.EncodeToString(share)), 0o644); err != nil {
		t.Fatal(err)
	}
	settings.auditOut = filepath.Join(filepath.Dir(public), "leaking-audit.json")
	if err := auditPrivateSurfaces(settings); err == nil {
		t.Fatal("planted operator share was not detected")
	}
	raw, err := os.ReadFile(settings.auditOut)
	if err != nil || json.Unmarshal(raw, &wrapper) != nil || json.Unmarshal(wrapper.Report, &report) != nil {
		t.Fatalf("leak report unavailable: %v", err)
	}
	if report.NoLeaks || len(report.LeakHits) == 0 {
		t.Fatal("leak report did not retain bounded failure evidence")
	}
}

func TestOperatorSecretAuditRefusesPrivateTreeAsSurface(t *testing.T) {
	storage := filepath.Join(t.TempDir(), "operator")
	if err := os.MkdirAll(storage, 0o700); err != nil {
		t.Fatal(err)
	}
	_, identity, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	share := bytes.Repeat([]byte{0x5a}, 256)
	if err := os.WriteFile(filepath.Join(storage, identityKeyFile), identity, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(storage, operatorBundleFile), auditTestBundle(t, identity, share), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := auditPrivateSurfaces(options{
		storage: storage, point: 1, auditRoots: []string{storage}, auditOut: filepath.Join(t.TempDir(), "audit.json"),
	}); err == nil {
		t.Fatal("scanner was allowed to traverse an operator-private tree")
	}
}
