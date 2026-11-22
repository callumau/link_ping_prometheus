//go:build !windows

package main

import (
	"os"
	"testing"
)

func verifyLogFileHardened(t *testing.T, path string) {
	t.Helper()
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("stat log file %q: %v", path, err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("log file %q mode = %04o, want 0600", path, fi.Mode().Perm())
	}
}
