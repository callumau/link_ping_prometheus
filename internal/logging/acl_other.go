//go:build !windows

package logging

import (
	"context"
	"os"
)

// restrictLogDACL is the Windows-only part of HardenSink (see
// acl_windows.go). On unix, log confidentiality is enforced by the POSIX
// perm bits HardenSink repairs; the hook is a no-op there. OpenFile
// gates the call on runtime.GOOS, but the symbol must exist on every
// platform that compiles package logging.
func restrictLogDACL(_ *os.File) (changed bool, err error) {
	return false, nil
}

// StartDACLRecheck is the Windows-only periodic DACL re-apply (see
// acl_windows.go); a no-op on unix, where POSIX perm bits never
// regress on rotation.
func StartDACLRecheck(_ context.Context, _ string) {}
