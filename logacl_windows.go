//go:build windows

package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// logDACLRecheckInterval is how often the live log file's DACL is
// re-compared against the restricted set. Idempotent, so a compliant
// file costs one GetSecurityInfo read per tick. A var so tests can run
// the ticker at a short interval (the stragglerStopTimeout/DynClientTTL
// precedent).
var logDACLRecheckInterval = 5 * time.Minute

// logACE summarizes one allow ACE of the log DACL for comparison.
type logACE struct {
	// sid is the trustee in RAW SID-string form (SID.String()): the
	// ConvertSecurityDescriptorToStringSecurityDescriptor renderer
	// name-resolves well-known accounts into SDDL aliases (observed on
	// the native Windows CI runner: the machine's RID-500 local
	// Administrator account renders as "LA"), so the rendered string is
	// environment-dependent and must never be used for equality — the
	// raw conversion is not.
	sid string
	// mask and flags are the ACE's access mask and inheritance flags as
	// stored (the renderer also collapses/canonicalizes those).
	mask  windows.ACCESS_MASK
	flags byte
}

// logDACLTable extracts the DACL's protected bit and every allow ACE.
// Deny entries or exotic ACE types are a mismatch by construction: the
// caller compares the table against the restricted template's table.
func logDACLTable(sd *windows.SECURITY_DESCRIPTOR) (protected bool, aces []logACE, err error) {
	control, _, err := sd.Control()
	if err != nil {
		return false, nil, fmt.Errorf("log DACL: read control bits: %w", err)
	}
	protected = control&windows.SE_DACL_PROTECTED != 0
	dacl, _, err := sd.DACL()
	if err != nil {
		return false, nil, fmt.Errorf("log DACL: read ACL: %w", err)
	}
	if dacl == nil {
		return false, nil, fmt.Errorf("log DACL: no DACL present")
	}
	base := unsafe.Pointer(dacl)
	off := unsafe.Sizeof(windows.ACL{}) // 8-byte ACL header precedes the ACE list
	for i := 0; i < int(dacl.AceCount); i++ {
		head := (*windows.ACE_HEADER)(unsafe.Add(base, off))
		switch head.AceType {
		case windows.ACCESS_ALLOWED_ACE_TYPE:
			ace := (*windows.ACCESS_ALLOWED_ACE)(unsafe.Add(base, off))
			// SidStart marks where the trustee SID begins in the ACE.
			sid := (*windows.SID)(unsafe.Add(base, off+unsafe.Offsetof(ace.SidStart)))
			aces = append(aces, logACE{sid: sid.String(), mask: ace.Mask, flags: head.AceFlags})
		default:
			return false, nil, fmt.Errorf("log DACL: unexpected ACE type %d", head.AceType)
		}
		off += uintptr(head.AceSize)
	}
	return protected, aces, nil
}

// sameLogDACL reports whether the two DACL ACE tables are semantically
// equal — the same multiset of allow ACEs, with ACE flags compared only
// on the inheritance bits the template controls (other flag bits, e.g.
// INHERITED_ACE canonicalization added by the security layer on
// read-back, are not part of the restricted set). The protection bit is
// checked by the caller, which runs both tables through logDACLTable.
// sameLogDACL reports whether the two DACL ACE tables are semantically
// equal: the same multiset of allow ACEs by trustee (raw SID string) and
// access mask. ACE inheritance flags are deliberately NOT compared: the
// target path is a FILE (no child objects to inherit into), and Windows
// strips the object-inheritance bits from file ACEs (observed on
// windows-latest: every template ACE applied with OI|CI reads back flags
// 0x0), so a flags-aware comparison is a fixed point that never
// converges - and the 5-minute recheck would re-apply and Warn forever.
// The stripped form ("applies to the object only") is the semantically
// correct state for the restricted set's purpose. (logACE.flags is kept
// in the struct because the test helper still surfaces it for
// diagnostics.)
func sameLogDACL(want, cur []logACE) bool {
	if len(want) != len(cur) {
		return false
	}
	counts := make(map[logACEKey]int, len(want))
	for _, a := range want {
		counts[logACEKey{sid: a.sid, mask: a.mask}]++
	}
	for _, a := range cur {
		k := logACEKey{sid: a.sid, mask: a.mask}
		counts[k]--
		if counts[k] < 0 {
			return false
		}
	}
	return true
}

// logACEKey is the ACE identity the restricted set is defined by.
type logACEKey struct {
	sid  string
	mask windows.ACCESS_MASK
}

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
	// Compare SEMANTICALLY (protection bit + per-ACE trustees/masks/flags,
	// trustees rendered as raw SIDs), never by rendered SDDL string: the
	// SDDL renderer name-resolves well-known accounts (the runner's
	// RID-500 local Administrator comes back "LA") and canonicalizes ACE
	// flags, so a string comparison never converges on such hosts — and
	// the periodic recheck would re-apply and Warn every 5 minutes
	// forever. Both tables derive from the same walker, so the
	// comparison is a fixed-point for a compliant file.
	wantProtected, wantAces, err := logDACLTable(want)
	if err != nil {
		return false, fmt.Errorf("log DACL: summarize restricted set: %w", err)
	}
	if cur == nil {
		// No descriptor at all: fall through to replace.
	} else if curProtected, curAces, cerr := logDACLTable(cur); cerr == nil && wantProtected && curProtected && sameLogDACL(wantAces, curAces) {
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
