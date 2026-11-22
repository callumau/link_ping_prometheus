//go:build windows

package logging

import (
	"context"
	"fmt"
	"link_ping_prometheus/internal/filetrust"
	"log/slog"
	"os"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// logDACLRecheckInterval is how often the live log file's DACL is
// re-compared against the restricted set. Idempotent, so a compliant
// file costs one GetSecurityInfo read per tick. A var so tests can run
// the ticker at a short interval.
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
// equal: the same multiset of allow ACEs by trustee (raw SID string) and
// access mask. Inheritance flags are excluded because Windows strips OI|CI
// from file ACEs on read-back.
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

func openLogFileForWriteDAC(path string) (*os.File, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(name, windows.READ_CONTROL|windows.WRITE_DAC,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(h), path), nil
}

// reapplyLogDACL re-restricts the live log file's DACL if it drifted.
func reapplyLogDACL(path string) error {
	if path == "" {
		return nil
	}
	f, _, err := filetrust.VerifyExistingRegular(path, 0, openLogFileForWriteDAC)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("log DACL recheck: %w", err)
	}
	defer f.Close()
	changed, err := restrictLogDACLOnHandle(f, true)
	if err != nil {
		return fmt.Errorf("log DACL recheck %q: %w", path, err)
	}
	if changed {
		slog.Warn("Log file had wider permissions; re-applied restricted DACL", "path", path)
	}
	return nil
}

// StartDACLRecheck re-applies the restricted DACL on a fixed ticker.
// The goroutine exits with ctx so it stops on shutdown in every mode.
func StartDACLRecheck(ctx context.Context, path string) {
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

const logACLStaticACEs = "(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"

// logACLSDDL builds the restricted DACL (SYSTEM + Administrators + current process SID).
// Deduplicating the token user against SY/BA ensures sameLogDACL converges.
func logACLSDDL(userSID string) string {
	sddl := "D:P" + logACLStaticACEs
	if userSID != filetrust.SystemSID && userSID != filetrust.AdministratorsSID {
		sddl += "(A;OICI;FA;;;" + userSID + ")"
	}
	return sddl
}

// restrictLogDACL ensures the open log file's DACL restricts access to SYSTEM,
// Administrators, and the current process account (idempotent).
func restrictLogDACL(f *os.File) (changed bool, err error) {
	return restrictLogDACLOnHandle(f, false)
}

func restrictLogDACLOnHandle(f *os.File, hasWriteDAC bool) (changed bool, err error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return false, fmt.Errorf("log DACL: read token user: %w", err)
	}
	want, err := windows.SecurityDescriptorFromString(logACLSDDL(user.User.Sid.String()))
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
	targetHandle := windows.Handle(f.Fd())
	if !hasWriteDAC {
		// f was opened via os.OpenFile (O_WRONLY without WRITE_DAC). Open a
		// WRITE_DAC handle with FILE_FLAG_OPEN_REPARSE_POINT and verify
		// os.SameFile against f before mutating the DACL on the handle,
		// avoiding a by-name SetNamedSecurityInfo race/reparse follow.
		fi, serr := f.Stat()
		if serr != nil {
			return false, fmt.Errorf("log DACL: stat open file: %w", serr)
		}
		name, nerr := windows.UTF16PtrFromString(f.Name())
		if nerr != nil {
			return false, fmt.Errorf("log DACL: path %q: %w", f.Name(), nerr)
		}
		wh, werr := windows.CreateFile(name, windows.READ_CONTROL|windows.WRITE_DAC,
			windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
			nil, windows.OPEN_EXISTING,
			windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
		if werr != nil {
			return false, fmt.Errorf("log DACL: open %q for WRITE_DAC: %w", f.Name(), werr)
		}
		wf := os.NewFile(uintptr(wh), f.Name())
		defer wf.Close()
		wfi, wserr := wf.Stat()
		if wserr != nil {
			return false, fmt.Errorf("log DACL: fstat %q: %w", f.Name(), wserr)
		}
		if !os.SameFile(fi, wfi) {
			return false, fmt.Errorf("log DACL: %q changed before DACL write; refusing", f.Name())
		}
		targetHandle = windows.Handle(wf.Fd())
	}
	if err := windows.SetSecurityInfo(targetHandle, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil); err != nil {
		return false, fmt.Errorf("log DACL: apply restricted ACL to %q: %w", f.Name(), err)
	}
	return true, nil
}
