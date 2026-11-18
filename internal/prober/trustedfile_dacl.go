package prober

import "fmt"

// TrustOptions selects the Windows DACL rule enforced when a trusted file is
// opened. On unix the equivalent rules are the caller's mode-bit checks
// (LoadTargets refuses group/world-writable; the metrics pair refuses a
// group/world-readable key); on Windows those bits are fabricated (os.Stat
// always reports 0666), so the DACL is the only control and it must actually
// be read.
//
// The zero value applies no DACL policy, preserving callers that carry their
// own platform rule.
type TrustOptions struct {
	// DenyForeignWrite refuses a DACL that grants write access to a principal
	// other than SYSTEM, Administrators or the process account: such a
	// principal can rewrite the file the agent trusts (the targets file
	// steers where probes go; the TLS pair is the management-plane identity).
	DenyForeignWrite bool
	// DenyForeignRead refuses a DACL that grants read access beyond those
	// principals: for the metrics TLS private key, reading it is the
	// compromise.
	DenyForeignRead bool
}

// Well-known SIDs, language-neutral (the account names are localized).
const (
	trustedSystemSID         = "S-1-5-18"
	trustedAdministratorsSID = "S-1-5-32-544"
)

// daclACE is the platform-neutral projection of one allow ACE, so the policy
// below is testable without Windows.
type daclACE struct {
	SID  string
	Mask uint32
	Type uint8
}

// Windows access bits that constitute write and read for a file. GENERIC_*
// must be included because an ACE can carry a generic mask and the kernel
// maps it at access time.
const (
	daclWriteBits = 0x0002 | 0x0004 | 0x0010 | 0x0100 | 0x10000 | 0x40000 | 0x80000 | 0x40000000 | 0x10000000
	daclReadBits  = 0x0001 | 0x0008 | 0x0080 | 0x00020000 | 0x80000000 | 0x10000000
)

// trustedDACLViolation evaluates the projected ACEs against the policy. A nil
// DACL (no protection at all) is a violation whenever a rule is requested.
// Unknown/deny-only ACEs are not treated as grants; an allow-type ACE that is
// not the plain ACCESS_ALLOWED type still contributes its mask with an
// unknown SID, so it fails closed rather than being skipped.
func trustedDACLViolation(NULLDACL bool, aces []daclACE, trusted map[string]bool, opts TrustOptions) error {
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
	if NULLDACL {
		return fmt.Errorf("has no DACL (every local user has full access); restrict it to SYSTEM, Administrators and this account")
	}
	for _, ace := range aces {
		// 0x00 ACCESS_ALLOWED and 0x05 ACCESS_ALLOWED_OBJECT are grants.
		// Deny (0x01) and audit (0x02) ACEs only reduce access.
		if ace.Type != 0x00 && ace.Type != 0x05 {
			continue
		}
		if ace.Mask&bits == 0 {
			continue
		}
		if trusted[ace.SID] {
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
