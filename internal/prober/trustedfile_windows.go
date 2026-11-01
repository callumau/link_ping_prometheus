//go:build windows

package prober

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// Well-known SIDs, language-neutral (the account names are localized).
const (
	trustedSystemSID         = "S-1-5-18"
	trustedAdministratorsSID = "S-1-5-32-544"
)

// openTrustedFile opens a file read-only. Windows os.OpenFile has no
// O_NOFOLLOW/O_NONBLOCK; the DACL plus the type and owner checks are the
// controls.
func openTrustedFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY, 0)
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
		return nil
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return fmt.Errorf("decode owner: %w", err)
	}
	if owner == nil {
		return nil
	}
	switch owner.String() {
	case trustedSystemSID, trustedAdministratorsSID, user.User.Sid.String():
		return nil
	}
	return fmt.Errorf("is owned by %s, not SYSTEM, Administrators or this account", owner.String())
}
