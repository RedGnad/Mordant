//go:build obsolete_recoverable_ceremony

package main

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const operatorAuditDomain = "mordant.ceremony.operator-secret-audit/v1"

type auditNeedle struct {
	Label          string
	Representation string
	Value          []byte
}

type auditHit struct {
	Path           string `json:"path"`
	Label          string `json:"label"`
	Representation string `json:"representation"`
}

type privateAuditReport struct {
	SchemaVersion           string            `json:"schemaVersion"`
	Point                   uint64            `json:"point"`
	BundleSHA256            string            `json:"bundleSha256"`
	CanarySHA256            map[string]string `json:"canarySha256"`
	Roots                   []string          `json:"roots"`
	FilesScanned            int               `json:"filesScanned"`
	BytesScanned            uint64            `json:"bytesScanned"`
	RepresentationsPerValue int               `json:"representationsPerValue"`
	WindowBytes             int               `json:"representativeWindowBytes"`
	LeakHits                []auditHit        `json:"leakHits"`
	PositiveControlDetected bool              `json:"positiveControlDetected"`
	PositiveControlRemoved  bool              `json:"positiveControlRemoved"`
	NoLeaks                 bool              `json:"noLeaks"`
	OneHostLimitation       string            `json:"oneHostLimitation"`
	CompletedAtUTC          string            `json:"completedAtUtc"`
}

type signedPrivateAuditReport struct {
	Report    json.RawMessage `json:"report"`
	Point     uint64          `json:"point"`
	Signature string          `json:"signature"`
}

func auditPrivateSurfaces(settings options) error {
	identity, err := readSecretFile(filepath.Join(settings.storage, identityKeyFile), ed25519.PrivateKeySize)
	if err != nil {
		return errors.New("operator audit identity unavailable")
	}
	bundle, err := readSecretFile(filepath.Join(settings.storage, operatorBundleFile), 384<<20)
	if err != nil {
		return errors.New("operator audit bundle unavailable")
	}
	share, bundleSigningKey, err := operatorBundleSecrets(bundle)
	if err != nil || !bytes.Equal(bundleSigningKey, identity) {
		return errors.New("operator audit bundle binding failed")
	}
	storage, err := filepath.Abs(settings.storage)
	if err != nil {
		return err
	}
	roots := make([]string, 0, len(settings.auditRoots))
	for _, candidate := range settings.auditRoots {
		absolute, err := filepath.Abs(candidate)
		if err != nil {
			return err
		}
		if pathContains(absolute, storage) || pathContains(storage, absolute) {
			return errors.New("operator audit cannot open an operator-private tree")
		}
		roots = append(roots, absolute)
	}
	sort.Strings(roots)
	needles := auditRepresentations("final-threshold-share", share)
	needles = append(needles, auditWholeRepresentations("operator-identity", identity)...)
	needles = append(needles, auditRepresentations("operator-identity-private-seed", identity[:ed25519.SeedSize])...)
	needles = append(needles, auditWholeRepresentations("sealed-operator-bundle", bundle)...)
	files, err := auditFiles(roots)
	if err != nil {
		return err
	}
	hits := make([]auditHit, 0)
	var bytesScanned uint64
	for _, path := range files {
		info, err := os.Stat(path)
		if err != nil {
			return err
		}
		bytesScanned += uint64(info.Size())
		matched, err := scanFileForNeedles(path, needles)
		if err != nil {
			return err
		}
		for _, needle := range matched {
			hits = append(hits, auditHit{Path: path, Label: needle.Label, Representation: needle.Representation})
		}
	}

	// The positive control is private to this operator and is removed before any
	// public report is written. It proves the exact live scanner catches a real
	// synthetic threshold share, not merely a fixture string.
	positivePath := filepath.Join(settings.storage, ".audit-positive-control.tmp")
	if err := os.WriteFile(positivePath, share, 0o600); err != nil {
		return err
	}
	positive, positiveErr := scanFileForNeedles(positivePath, auditRepresentations("final-threshold-share", share))
	removeErr := os.Remove(positivePath)
	if positiveErr != nil || removeErr != nil || len(positive) == 0 {
		return errors.New("operator audit positive control failed")
	}
	if _, err := os.Stat(positivePath); !errors.Is(err, os.ErrNotExist) {
		return errors.New("operator audit positive control was not removed")
	}
	bundleDigest := sha256.Sum256(bundle)
	shareDigest := sha256.Sum256(share)
	identityDigest := sha256.Sum256(identity)
	report := privateAuditReport{
		SchemaVersion: "mordant.ceremony-operator-secret-audit/1", Point: settings.point,
		BundleSHA256: hex.EncodeToString(bundleDigest[:]),
		CanarySHA256: map[string]string{
			"finalThresholdShare": hex.EncodeToString(shareDigest[:]),
			"operatorIdentity":    hex.EncodeToString(identityDigest[:]),
		},
		Roots: roots, FilesScanned: len(files), BytesScanned: bytesScanned,
		RepresentationsPerValue: 6, WindowBytes: 32, LeakHits: hits,
		PositiveControlDetected: true, PositiveControlRemoved: true, NoLeaks: len(hits) == 0,
		OneHostLimitation: "process separation on one host is not independent organizational custody",
		CompletedAtUTC:    time.Now().UTC().Format(time.RFC3339Nano),
	}
	payload, err := json.Marshal(report)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(append([]byte(operatorAuditDomain), payload...))
	signature := ed25519.Sign(ed25519.PrivateKey(identity), digest[:])
	wrapper, err := json.MarshalIndent(signedPrivateAuditReport{
		Report: payload, Point: settings.point, Signature: hex.EncodeToString(signature),
	}, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(settings.auditOut, append(wrapper, '\n'), 0o644); err != nil {
		return err
	}
	if len(hits) != 0 {
		return errors.New("operator secret found on an allowed public surface")
	}
	return nil
}

func operatorBundleSecrets(bundle []byte) (share, signingKey []byte, err error) {
	reader := bytes.NewReader(bundle)
	magic := make([]byte, 4)
	if _, err = io.ReadFull(reader, magic); err != nil || string(magic) != "MTO1" {
		return nil, nil, errors.New("invalid operator bundle")
	}
	if _, err = auditReadSized(reader, 1<<20); err != nil { // parameters
		return nil, nil, err
	}
	fixed := make([]byte, 32+32+2+8)
	if _, err = io.ReadFull(reader, fixed); err != nil {
		return nil, nil, err
	}
	var count uint16
	if err = binary.Read(reader, binary.BigEndian, &count); err != nil || count < 2 || count > 255 {
		return nil, nil, errors.New("invalid operator bundle points")
	}
	points := make([]byte, int(count)*8)
	if _, err = io.ReadFull(reader, points); err != nil {
		return nil, nil, err
	}
	if share, err = auditReadSized(reader, 64<<20); err != nil || len(share) < 64 {
		return nil, nil, errors.New("invalid operator share")
	}
	if signingKey, err = auditReadSized(reader, ed25519.PrivateKeySize); err != nil ||
		len(signingKey) != ed25519.PrivateKeySize || reader.Len() != 0 {
		return nil, nil, errors.New("invalid operator signing key")
	}
	return share, signingKey, nil
}

func auditReadSized(reader *bytes.Reader, limit uint32) ([]byte, error) {
	var size uint32
	if binary.Read(reader, binary.BigEndian, &size) != nil || size == 0 || size > limit || uint64(size) > uint64(reader.Len()) {
		return nil, errors.New("invalid sized audit field")
	}
	out := make([]byte, size)
	_, err := io.ReadFull(reader, out)
	return out, err
}

func auditRepresentations(label string, raw []byte) []auditNeedle {
	values := []struct {
		name string
		raw  []byte
	}{{name: label, raw: raw}}
	if len(raw) > 32 {
		offsets := []int{0, len(raw) / 4, len(raw) / 2, (3 * len(raw)) / 4, len(raw) - 32}
		seen := map[int]struct{}{}
		for index, offset := range offsets {
			if offset+32 > len(raw) {
				offset = len(raw) - 32
			}
			if _, ok := seen[offset]; ok {
				continue
			}
			seen[offset] = struct{}{}
			values = append(values, struct {
				name string
				raw  []byte
			}{name: fmt.Sprintf("%s-window-%d", label, index+1), raw: raw[offset : offset+32]})
		}
	}
	needles := make([]auditNeedle, 0, len(values)*6)
	for _, value := range values {
		needles = append(needles, auditWholeRepresentations(value.name, value.raw)...)
	}
	return needles
}

func auditWholeRepresentations(label string, raw []byte) []auditNeedle {
	lower := hex.EncodeToString(raw)
	return []auditNeedle{
		{Label: label, Representation: "raw", Value: append([]byte(nil), raw...)},
		{Label: label, Representation: "hex-lower", Value: []byte(lower)},
		{Label: label, Representation: "hex-upper", Value: []byte(strings.ToUpper(lower))},
		{Label: label, Representation: "hex-prefixed", Value: []byte("0x" + lower)},
		{Label: label, Representation: "base64", Value: []byte(base64.StdEncoding.EncodeToString(raw))},
		{Label: label, Representation: "base64url", Value: []byte(base64.RawURLEncoding.EncodeToString(raw))},
	}
}

func auditFiles(roots []string) ([]string, error) {
	files := make([]string, 0)
	seen := map[string]struct{}{}
	for _, root := range roots {
		info, err := os.Lstat(root)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("invalid audit root")
		}
		if info.Mode().IsRegular() {
			seen[root] = struct{}{}
			files = append(files, root)
			continue
		}
		if !info.IsDir() {
			return nil, errors.New("invalid audit root type")
		}
		if err := filepath.Walk(root, func(path string, entry os.FileInfo, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.Mode()&os.ModeSymlink != 0 {
				return errors.New("audit refuses symlinks")
			}
			if entry.Mode().IsRegular() {
				if _, ok := seen[path]; !ok {
					seen[path] = struct{}{}
					files = append(files, path)
				}
			}
			return nil
		}); err != nil {
			return nil, err
		}
	}
	sort.Strings(files)
	return files, nil
}

func scanFileForNeedles(path string, needles []auditNeedle) ([]auditNeedle, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	maximum := 0
	for _, needle := range needles {
		if len(needle.Value) > maximum {
			maximum = len(needle.Value)
		}
	}
	if maximum == 0 {
		return nil, errors.New("empty audit needle set")
	}
	chunkSize := 1 << 20
	if maximum > chunkSize {
		chunkSize = maximum
	}
	reader := bufio.NewReaderSize(file, chunkSize)
	tail := make([]byte, 0, maximum-1)
	matched := map[string]auditNeedle{}
	for {
		chunk := make([]byte, chunkSize)
		count, readErr := reader.Read(chunk)
		if count > 0 {
			window := append(append([]byte(nil), tail...), chunk[:count]...)
			for _, needle := range needles {
				key := needle.Label + "\x00" + needle.Representation
				if _, found := matched[key]; !found && bytes.Contains(window, needle.Value) {
					matched[key] = needle
				}
			}
			keep := maximum - 1
			if keep > len(window) {
				keep = len(window)
			}
			tail = append(tail[:0], window[len(window)-keep:]...)
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return nil, readErr
		}
	}
	out := make([]auditNeedle, 0, len(matched))
	for _, needle := range matched {
		out = append(out, needle)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Label == out[j].Label {
			return out[i].Representation < out[j].Representation
		}
		return out[i].Label < out[j].Label
	})
	return out, nil
}

func pathContains(parent, child string) bool {
	relative, err := filepath.Rel(parent, child)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}
