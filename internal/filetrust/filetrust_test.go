//go:build !windows

package filetrust

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

func TestReadFileRefusesFIFOWithoutBlocking(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "targets.json")
	testFIFO(t, path)

	done := make(chan error, 1)
	go func() {
		_, _, err := ReadFile(path, 1<<20)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("ReadFile adopted a FIFO")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ReadFile blocked on a reader-less FIFO instead of refusing it")
	}
}

func TestReadFileRefusesSymlinkAndDirectory(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real.json")
	if err := os.WriteFile(real, []byte("[]"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}
	if _, _, err := ReadFile(link, 1<<20); err == nil {
		t.Fatal("ReadFile followed a symlink")
	}
	if _, _, err := ReadFile(dir, 1<<20); err == nil {
		t.Fatal("ReadFile accepted a directory")
	}
}

func TestReadFileBoundsSize(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "big.json")
	if err := os.WriteFile(path, make([]byte, 64), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReadFile(path, 16); err == nil {
		t.Fatal("ReadFile accepted a file above its byte limit")
	}
}
