// Command mordant-fhe-retain is the narrow public-evidence retention boundary.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
	"mordant.dev/fhe-lab/lattigo/governedfhe"
)

func main() {
	root := flag.String("retention-root", "", "pre-existing absolute retention root")
	scenario := flag.String("scenario", "", "conflict or no-conflict")
	source := flag.String("source", "", "absolute regular source manifest")
	manifest := flag.String("manifest-digest", "", "expected protection manifest digest")
	caseID := flag.String("case-id", "", "expected FHE case ID")
	flag.Parse()
	if flag.NArg() != 0 || !filepath.IsAbs(*root) || !filepath.IsAbs(*source) {
		fail(governedfhe.ErrStore)
	}
	data := readRegularNoFollow(*source)
	var manifestDigest, expectedCase governedfhe.Digest
	if manifestDigest.UnmarshalText([]byte(*manifest)) != nil || expectedCase.UnmarshalText([]byte(*caseID)) != nil {
		fail(governedfhe.ErrArtifact)
	}
	reconciled, err := governedfhe.RetainPublicEvidence(*root, *scenario, manifestDigest, expectedCase, data)
	if err != nil {
		fail(err)
	}
	if err := json.NewEncoder(os.Stdout).Encode(struct {
		Reconciled bool `json:"reconciled"`
	}{reconciled}); err != nil {
		fail(err)
	}
}

func readRegularNoFollow(path string) []byte {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		fail(err)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		fail(governedfhe.ErrStore)
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Sys() == nil {
		_ = file.Close()
		fail(governedfhe.ErrStore)
	}
	data, err := io.ReadAll(file)
	if err != nil {
		_ = file.Close()
		fail(err)
	}
	after, err := file.Stat()
	if err != nil || !after.Mode().IsRegular() || after.Size() != int64(len(data)) || !os.SameFile(info, after) {
		_ = file.Close()
		fail(governedfhe.ErrStore)
	}
	if err := file.Close(); err != nil {
		fail(err)
	}
	return data
}

func fail(err error) {
	fmt.Fprintf(os.Stderr, "mordant-fhe-retain: %v\n", err)
	os.Exit(1)
}
