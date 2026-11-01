//go:build !windows

package prober

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func testFIFO(t *testing.T, path string) {
	t.Helper()
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Skipf("mkfifo unavailable: %v", err)
	}
}

func TestReadTrustedFileRefusesFIFOWithoutBlocking(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "targets.json")
	testFIFO(t, path)

	done := make(chan error, 1)
	go func() {
		_, _, err := ReadTrustedFile(path, MaxTargetsFileSize)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("ReadTrustedFile adopted a FIFO")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ReadTrustedFile blocked on a reader-less FIFO instead of refusing it")
	}
}

func TestReadTrustedFileRefusesSymlinkAndDirectory(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real.json")
	if err := os.WriteFile(real, []byte("[]"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}
	if _, _, err := ReadTrustedFile(link, MaxTargetsFileSize); err == nil {
		t.Fatal("ReadTrustedFile followed a symlink")
	}
	if _, _, err := ReadTrustedFile(dir, MaxTargetsFileSize); err == nil {
		t.Fatal("ReadTrustedFile accepted a directory")
	}
}

func TestReadTrustedFileBoundsSize(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "big.json")
	if err := os.WriteFile(path, make([]byte, 64), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReadTrustedFile(path, 16); err == nil {
		t.Fatal("ReadTrustedFile accepted a file above its byte limit")
	}
}

// TestLoadTargetsRejectsNull pins the second, undocumented spelling of "probe
// nothing": `null` unmarshalled into a nil slice with no error, blanking the
// probe set and purging every series exactly like [] (which warns). Only an
// array is a targets document.
func TestLoadTargetsRejectsNull(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "targets.json")
	if err := os.WriteFile(path, []byte("null"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadTargets(path); err == nil {
		t.Fatal("LoadTargets accepted a null document as an empty target set")
	}
}
