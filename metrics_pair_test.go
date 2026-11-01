//go:build !windows

package main

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func mkfifoPair(path string) error { return syscall.Mkfifo(path, 0o600) }

// TestLoadMetricsPairAcceptsValidPair is the happy path: a 0600 pair loads.
func TestLoadMetricsPairAcceptsValidPair(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "tls.crt")
	key := filepath.Join(dir, "tls.key")
	writeTestCert(t, cert, key, "valid-metrics", 1)

	got, err := loadMetricsPair(cert, key)
	if err != nil {
		t.Fatalf("loadMetricsPair refused a valid pair: %v", err)
	}
	if len(got.Certificate) == 0 {
		t.Fatal("loaded pair carries no certificate")
	}
}

// TestLoadMetricsPairRefusesExposedKey pins the mode rule: a group/world-
// readable private key is what a local reader uses to impersonate the
// endpoint, and the old code accepted it silently.
func TestLoadMetricsPairRefusesExposedKey(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "tls.crt")
	key := filepath.Join(dir, "tls.key")
	writeTestCert(t, cert, key, "exposed-metrics", 2)
	// pi-lens-ignore: go-path-traversal
	if err := os.Chmod(key, 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := loadMetricsPair(cert, key)
	if err == nil {
		t.Fatal("loadMetricsPair accepted a world-readable private key")
	}
	if !strings.Contains(err.Error(), "exposes") {
		t.Errorf("error should name the exposure, got: %v", err)
	}
}

// TestLoadMetricsPairRefusesSymlink pins the symlink rule the targets file and
// log sink already enforce.
func TestLoadMetricsPairRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	realCert := filepath.Join(dir, "real.crt")
	realKey := filepath.Join(dir, "real.key")
	writeTestCert(t, realCert, realKey, "real", 3)

	linkCert := filepath.Join(dir, "tls.crt")
	if err := os.Symlink(realCert, linkCert); err != nil {
		t.Fatal(err)
	}
	if _, err := loadMetricsPair(linkCert, realKey); err == nil {
		t.Fatal("loadMetricsPair followed a symlinked certificate")
	}
}

// TestLoadMetricsPairRefusesFIFOWithoutHanging pins the availability half: a
// FIFO at the key path used to block the reloader inside tls.LoadX509KeyPair
// while it held the mutex that serialises every handshake, and a FIFO planted
// before startup blocked the process before any bind.
func TestLoadMetricsPairRefusesFIFOWithoutHanging(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "tls.crt")
	key := filepath.Join(dir, "tls.key")
	writeTestCert(t, cert, key, "fifo", 4)
	if err := os.Remove(key); err != nil {
		t.Fatal(err)
	}
	if err := mkfifoPair(key); err != nil {
		t.Skipf("mkfifo unavailable: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := loadMetricsPair(cert, key)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("loadMetricsPair adopted a FIFO as the private key")
		}
		if !strings.Contains(err.Error(), "non-regular") {
			t.Errorf("error should name the non-regular object, got: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("loadMetricsPair blocked on a reader-less FIFO instead of refusing it")
	}
}

// TestLoadMetricsPairRefusesDirectory keeps the type gate honest for the other
// non-regular object a path can name.
func TestLoadMetricsPairRefusesDirectory(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "certs")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := loadMetricsPair(sub, sub); err == nil {
		t.Fatal("loadMetricsPair accepted a directory")
	}
}
