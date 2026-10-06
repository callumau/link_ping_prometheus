//go:build !windows

package main

import "os"

// restrictLogDACL is the Windows-only part of hardenLogSink (see
// logacl_windows.go). On unix, log confidentiality is enforced by the POSIX
// perm bits hardenLogSink repairs; the hook is a no-op there. hardenLogSink
// gates the call on runtime.GOOS, but the symbol must exist on every
// platform that compiles package main.
func restrictLogDACL(_ *os.File) (changed bool, err error) {
	return false, nil
}
