//go:build windows

package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"golang.org/x/sys/windows"
)

// logDACLRecheckInterval is how often the live log file's DACL is
// re-compared against the restricted set. Idempotent, so a compliant
// file costs one GetSecurityInfo read per tick.
const logDACLRecheckInterval = 5 * time.Minute

// reapplyLogDACL re-restricts the CURRENT live log file's DACL.
// restrictLogDACL runs once at startup against the file that exists
// then; after the first lumberjack rotation the fresh live file is
// created by the framework and inherits the (possibly wide) parent
// directory DACL, silently regressing the restricted set. Called from a
// fixed ticker so a manual install into a wide directory regains the
// "never world-readable" invariant within one interval of each rotation.
// A file that does not exist right now (mid-rotation gap) is skipped;
// the next tick covers it once lumberjack recreates it.
func reapplyLogDACL(path string) error {
	if path == "" {
		return nil
	}
	// pi-lens-ignore: go-path-traversal
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("log DACL recheck: open %q: %w", path, err)
	}
	defer f.Close()
	changed, err := restrictLogDACL(f)
	if err != nil {
		return fmt.Errorf("log DACL recheck %q: %w", path, err)
	}
	if changed {
		slog.Warn("Log file had wider permissions; re-applied restricted DACL", "path", path)
	}
	return nil
}

// startLogDACLRecheck re-applies the restricted DACL on a fixed ticker.
// The goroutine exits with ctx so it stops on shutdown in every mode.
func startLogDACLRecheck(ctx context.Context, path string) {
	if path == "" {
		return
	}
	go func() {
		ticker := time.NewTicker(logDACLRecheckInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
			if err := reapplyLogDACL(path); err != nil {
				slog.Error("Log DACL recheck failed", "path", path, "err", err)
			}
		}
	}()
}

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
