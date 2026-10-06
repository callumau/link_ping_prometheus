//go:build windows

package main

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// logACLSDDLTemplate is the DACL applied to the log sink, with the current
// process token's user SID spliced in at the %s slot:
//
//	"SY"  SYSTEM                 full control
//	"BA"  builtin Administrators full control
//	%s    the account the agent runs as — full control, so the process
//	      keeps write access to its own log; the set cannot be static
//	      because a manually installed agent may run as LocalSystem,
//	      LocalService, NetworkService or an operator account
//
// File-all-access ("FA") with object+container inheritance keeps every entry
// self-contained, and the "P" flag protects the DACL from parent-directory
// inheritance, so wherever -log-file happens to point, its wide directory
// entries cannot re-leak the file.
const logACLSDDLTemplate = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;%s)"

// restrictLogDACL enforces log confidentiality on Windows, where the POSIX
// mode-bit repair in hardenLogSink is a no-op: os.OpenFile's 0600 mode has no
// DACL effect, os.Stat always reports 0666 and f.Chmod only toggles the
// read-only attribute. Manual installs can point -log-file into a
// Users-writable directory, so both hardenLogSink paths (create and repair)
// get their file's DACL compared against the restricted set above and
// replaced only when it differs (idempotent: a compliant file is not
// rewritten and restrictLogDACL reports false).
//
// The current DACL is read from the OPEN descriptor (the O_WRONLY handle
// carries READ_CONTROL via STANDARD_RIGHTS_WRITE), so the comparison is
// pinned to the exact file hardenLogSink verified. The replacement itself
// goes through SetNamedSecurityInfo because that open write handle does not
// carry WRITE_DAC: the named call re-opens the file under the caller's
// token, where the object owner's implicit WRITE_DAC applies. If the agent
// runs to neither owner nor a WRITE_DAC grantee, the call fails and the
// caller exits non-zero — fail-closed, exactly like the symlink refusal and
// the unix chmod repair.
func restrictLogDACL(f *os.File) (changed bool, err error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return false, fmt.Errorf("log DACL: read token user: %w", err)
	}
	want, err := windows.SecurityDescriptorFromString(fmt.Sprintf(logACLSDDLTemplate, user.User.Sid.String()))
	if err != nil {
		return false, fmt.Errorf("log DACL: build restricted descriptor: %w", err)
	}
	cur, err := windows.GetSecurityInfo(windows.Handle(f.Fd()), windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return false, fmt.Errorf("log DACL: read current descriptor: %w", err)
	}
	if cur != nil && cur.String() == want.String() {
		return false, nil
	}
	dacl, _, err := want.DACL()
	if err != nil {
		return false, fmt.Errorf("log DACL: extract restricted ACL: %w", err)
	}
	if err := windows.SetNamedSecurityInfo(f.Name(), windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil); err != nil {
		return false, fmt.Errorf("log DACL: apply restricted ACL to %q: %w", f.Name(), err)
	}
	return true, nil
}
