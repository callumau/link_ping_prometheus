//go:build !windows

package main

import "testing"

// verifyLogDACLRestricted exists only so the runtime.GOOS-gated call sites
// in TestHardenLogSink compile on unix; it must never run there (the unix
// branches assert POSIX perm bits instead).
func verifyLogDACLRestricted(t *testing.T, path string) {
	t.Helper()
	t.Fatalf("log DACL verification is windows-only (verified %q)", path)
}

// dumpLogDACLTables is the Windows-only diagnostic dump (see
// logacl_windows_test.go); a no-op on unix so TestHardenLogSink's
// windows branch never calls it.
func dumpLogDACLTables(t *testing.T, path string) {
	t.Helper()
	t.Log("log DACL dump is windows-only")
}
