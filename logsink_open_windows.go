//go:build windows

package main

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// openLogFileForRepair opens an existing log file for append. Windows has no
// O_NOFOLLOW/O_NONBLOCK equivalents in os.OpenFile; the type check and the
// DACL are the controls there.
func openLogFileForRepair(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
}

// createLogFile creates the log file exclusive-or-fails so a reparse point or
// FIFO raced into place since the Lstat is never adopted.
func createLogFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY|os.O_APPEND, 0o600)
}

// checkLogFileOwner refuses a log file owned by anything other than SYSTEM,
// Administrators or the account this process runs as. An owner keeps implicit
// WRITE_DAC, so a file owned by another local account can always be re-widened
// after the DACL repair.
func checkLogFileOwner(f *os.File) error {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return fmt.Errorf("log owner: read token user: %w", err)
	}
	sd, err := windows.GetSecurityInfo(windows.Handle(f.Fd()), windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("log owner: read owner: %w", err)
	}
	if sd == nil {
		return nil
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return fmt.Errorf("log owner: decode owner: %w", err)
	}
	if owner == nil {
		return nil
	}
	switch owner.String() {
	case logACLSystemSID, logACLAdministratorsSID, user.User.Sid.String():
		return nil
	}
	return fmt.Errorf("log file is owned by %s, not SYSTEM, Administrators or this service account: its owner could re-widen it", owner.String())
}
