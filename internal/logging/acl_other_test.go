//go:build !windows

package logging

import "testing"

// verifyLogDACLRestricted exists only so Windows-only call sites stay
// isolated from unix; it must never run on unix.
func verifyLogDACLRestricted(t *testing.T, path string) {
	t.Helper()
	t.Fatalf("log DACL verification is windows-only (verified %q)", path)
}

// dumpLogDACLTables is the Windows-only diagnostic dump (see
// acl_windows_test.go); a no-op on unix.
func dumpLogDACLTables(t *testing.T, path string) {
	t.Helper()
	t.Log("log DACL dump is windows-only")
}
