package filetrust

import "fmt"

// TrustOptions selects the Windows DACL rule enforced when a trusted file is
// opened. On unix, callers check POSIX mode bits directly.
type TrustOptions struct {
	// DenyForeignWrite refuses a DACL granting write access beyond SYSTEM,
	// Administrators, or the current process account.
	DenyForeignWrite bool
	// DenyForeignRead refuses a DACL granting read access beyond those principals.
	DenyForeignRead bool
}

// Well-known SIDs (language-neutral; account names are localized).
const (
	SystemSID         = "S-1-5-18"
	AdministratorsSID = "S-1-5-32-544"
)

// daclACE is a platform-neutral projection of an ACL entry for unit testing.
type daclACE struct {
	SID  string
	Mask uint32
	Type uint8
}

// Windows access bits that constitute write and read (including GENERIC_*).
const (
	daclWriteBits = 0x0002 | 0x0004 | 0x0010 | 0x0100 | 0x10000 | 0x40000 | 0x80000 | 0x40000000 | 0x10000000
	daclReadBits  = 0x0001 | 0x0008 | 0x0080 | 0x00020000 | 0x80000000 | 0x10000000
)

// isNonGrantACEType reports Windows ACE types that only deny, audit, alarm, or
// carry metadata labels rather than granting access. Unknown types fail closed.
func isNonGrantACEType(t uint8) bool {
	switch t {
	case 0x01, 0x02, 0x03, 0x06, 0x07, 0x08, 0x0A, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15:
		return true
	}
	return false
}

// trustedDACLViolation evaluates projected ACEs against opts, failing closed on
// NULL DACLs or unrecognized granting principals.
func trustedDACLViolation(nullDACL bool, aces []daclACE, trusted map[string]bool, opts TrustOptions) error {
	bits := uint32(0)
	what := ""
	if opts.DenyForeignWrite {
		bits |= daclWriteBits
		what = "write"
	}
	if opts.DenyForeignRead {
		bits |= daclReadBits
		what = "read"
	}
	if bits == 0 {
		return nil
	}
	if nullDACL {
		return fmt.Errorf("has no DACL (every local user has full access); restrict it to SYSTEM, Administrators and this account")
	}
	for _, ace := range aces {
		if isNonGrantACEType(ace.Type) || ace.Mask&bits == 0 || trusted[ace.SID] {
			continue
		}
		sid := ace.SID
		if sid == "" {
			sid = "an unrecognised principal"
		}
		return fmt.Errorf("DACL grants %s access to %s; restrict it to SYSTEM, Administrators and this account", what, sid)
	}
	return nil
}
