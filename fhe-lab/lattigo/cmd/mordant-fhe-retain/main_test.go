package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestReadRegularNoFollow(t *testing.T) {
	t.Run("regular source", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "manifest.json")
		if err := os.WriteFile(path, []byte("manifest"), 0o600); err != nil {
			t.Fatal(err)
		}
		data, err := readRegularNoFollow(path)
		if err != nil || string(data) != "manifest" {
			t.Fatalf("data=%q err=%v", data, err)
		}
	})

	t.Run("symlink source", func(t *testing.T) {
		root := t.TempDir()
		target := filepath.Join(root, "target")
		link := filepath.Join(root, "manifest.json")
		if err := os.WriteFile(target, []byte("manifest"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		if _, err := readRegularNoFollow(link); err == nil {
			t.Fatal("source symlink accepted")
		}
	})

	t.Run("FIFO source does not block", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "manifest.json")
		if err := unix.Mkfifo(path, 0o600); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() {
			_, err := readRegularNoFollow(path)
			done <- err
		}()
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("FIFO source accepted")
			}
		case <-time.After(time.Second):
			t.Fatal("FIFO source open blocked")
		}
	})
}
