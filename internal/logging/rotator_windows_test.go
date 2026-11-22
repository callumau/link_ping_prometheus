//go:build windows

package logging

import (
	"os"
	"testing"
)

func verifyLogFileHardened(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("stat log file %q: %v", path, err)
	}
	verifyLogDACLRestricted(t, path)
}
