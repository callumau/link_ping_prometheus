//go:build windows

package prober

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// openTrustedFile opens a file read-only. Windows os.OpenFile has no
// O_NOFOLLOW/O_NONBLOCK; the DACL plus the type and owner checks are the
// controls.
func openTrustedFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY, 0)
}

// checkTrustedDACL reads the DACL of the verified descriptor and applies the
// caller's TrustOptions. This is the Windows half of the trust rule: the unix
// mode-bit checks are compiled out here (os.Stat always reports 0666), so
// without this the file is accepted with no access-rule check at all — an
// inherited Users-write ACE on the targets file, or a Users-read ACE on the
// metrics TLS key, would pass silently.
//
// Fail-closed: an unreadable DACL, a NULL DACL (everyone full control) or a
// grant to any principal outside SYSTEM/Administrators/this account is an
// error, exactly like the unix mode refusal.
func checkTrustedDACL(f *os.File, opts TrustOptions) error {
	if !opts.DenyForeignWrite && !opts.DenyForeignRead {
		return nil
	}
	sd, err := windows.GetSecurityInfo(windows.Handle(f.Fd()), windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("read DACL: %w", err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("read DACL: %w", err)
	}
	var aces []daclACE
	if dacl != nil {
		for i := 0; i < int(dacl.AceCount); i++ {
			var ace *windows.ACCESS_ALLOWED_ACE
			if err := windows.GetAce(dacl, uint32(i), &ace); err != nil {
				return fmt.Errorf("read DACL entry %d: %w", i, err)
			}
			// Only a plain ACCESS_ALLOWED ACE carries a SID at SidStart; an
			// object ACE is projected with an empty SID so the policy fails
			// closed instead of skipping a grant it cannot attribute.
			sid := ""
			if ace.Header.AceType == windows.ACCESS_ALLOWED_ACE_TYPE {
				sid = (*windows.SID)(unsafe.Pointer(&ace.SidStart)).String()
			}
			aces = append(aces, daclACE{SID: sid, Mask: uint32(ace.Mask), Type: ace.Header.AceType})
		}
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return fmt.Errorf("read token user: %w", err)
	}
	trusted := map[string]bool{
		trustedSystemSID:         true,
		trustedAdministratorsSID: true,
		user.User.Sid.String():   true,
	}
	return trustedDACLViolation(dacl == nil, aces, trusted, opts)
}

// checkTrustedOwner refuses a file owned by anything other than SYSTEM,
// Administrators or this process's account, because an owner can always
// rewrite the DACL.
func checkTrustedOwner(f *os.File) error {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return fmt.Errorf("read token user: %w", err)
	}
	sd, err := windows.GetSecurityInfo(windows.Handle(f.Fd()), windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("read owner: %w", err)
	}
	if sd == nil {
		return fmt.Errorf("security descriptor is nil")
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return fmt.Errorf("decode owner: %w", err)
	}
	if owner == nil {
		return fmt.Errorf("file has no owner")
	}
	switch owner.String() {
	case trustedSystemSID, trustedAdministratorsSID, user.User.Sid.String():
		return nil
	}
	return fmt.Errorf("is owned by %s, not SYSTEM, Administrators or this account", owner.String())
}
