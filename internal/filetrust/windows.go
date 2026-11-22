//go:build windows

package filetrust

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

func openTrustedFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY, 0)
}

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
		SystemSID:                true,
		AdministratorsSID:        true,
		user.User.Sid.String():   true,
	}
	return trustedDACLViolation(dacl == nil, aces, trusted, opts)
}

// CheckOwner refuses a file owned by anything other than SYSTEM, Administrators,
// or this process account, because an owner can rewrite the DACL.
func CheckOwner(f *os.File) error {
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
	case SystemSID, AdministratorsSID, user.User.Sid.String():
		return nil
	}
	return fmt.Errorf("is owned by %s, not SYSTEM, Administrators or this account", owner.String())
}
