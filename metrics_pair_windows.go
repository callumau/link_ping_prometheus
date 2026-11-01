//go:build windows

package main

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// openPairFile opens a metrics TLS file read-only. The DACL, not a mode bit,
// is the control on Windows; the type check and the owner check below are the
// portable parts of the provenance rule.
func openPairFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY, 0)
}

// checkPairOwner refuses a TLS file owned by anything other than SYSTEM,
// Administrators or this process's account, because the owner can always
// rewrite the DACL.
func checkPairOwner(f *os.File) error {
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
	case logACLSystemSID, logACLAdministratorsSID, user.User.Sid.String():
		return nil
	}
	return fmt.Errorf("owned by %s, not SYSTEM, Administrators or this account", owner.String())
}
