//go:build windows

package filetrust

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func setProtectedSDDL(t *testing.T, path, sddl string) {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatalf("parse SDDL %q: %v", sddl, err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatalf("extract DACL from SDDL %q: %v", sddl, err)
	}
	if err := windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil,
	); err != nil {
		t.Fatalf("SetNamedSecurityInfo(%q): %v", sddl, err)
	}
}

func TestReadFileWith_ConditionalACEAndOwnerWindows(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret.key")
	if err := os.WriteFile(path, []byte("secret-key"), 0o600); err != nil {
		t.Fatal(err)
	}

	setProtectedSDDL(t, path, `D:P(A;;FA;;;SY)(A;;FA;;;BA)(XA;;FR;;;WD;(Title=="x"))`)

	if _, _, err := ReadFileWith(path, 1024, TrustOptions{DenyForeignRead: true}); err == nil {
		t.Fatal("ReadFileWith accepted a file with a conditional/callback allow ACE for Everyone")
	}

	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatalf("read token user: %v", err)
	}
	userSID := user.User.Sid.String()
	cleanSDDL := "D:P(A;;FA;;;SY)(A;;FA;;;BA)"
	if userSID != SystemSID && userSID != AdministratorsSID {
		cleanSDDL += "(A;;FA;;;" + userSID + ")"
	}
	setProtectedSDDL(t, path, cleanSDDL)

	data, _, err := ReadFileWith(path, 1024, TrustOptions{DenyForeignRead: true, DenyForeignWrite: true})
	if err != nil {
		t.Fatalf("ReadFileWith rejected clean restricted file: %v", err)
	}
	if string(data) != "secret-key" {
		t.Fatalf("unexpected data %q", data)
	}
}
