//go:build windows

package prober

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

// TestReadTrustedFileWith_ConditionalACEAndOwnerWindows exercises the real
// Windows DACL walker on NTFS: a conditional/callback allow ACE
// (ACCESS_ALLOWED_CALLBACK_ACE_TYPE 0x09) granting read to Everyone must fail
// closed under DenyForeignRead, while a SYSTEM+Administrators DACL passes.
func TestReadTrustedFileWith_ConditionalACEAndOwnerWindows(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret.key")
	if err := os.WriteFile(path, []byte("secret-key"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Apply a conditional allow ACE (XA = ACCESS_ALLOWED_CALLBACK_ACE_TYPE 0x09)
	// for Everyone (WD) alongside SYSTEM/Administrators.
	setProtectedSDDL(t, path, `D:P(A;;FA;;;SY)(A;;FA;;;BA)(XA;;FR;;;WD;(Title=="x"))`)

	if _, _, err := ReadTrustedFileWith(path, 1024, TrustOptions{DenyForeignRead: true}); err == nil {
		t.Fatal("ReadTrustedFileWith accepted a file with a conditional/callback allow ACE for Everyone")
	}

	// Restrict to SYSTEM + Administrators (+ current process user if distinct)
	// and verify it passes.
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatalf("read token user: %v", err)
	}
	userSID := user.User.Sid.String()
	cleanSDDL := "D:P(A;;FA;;;SY)(A;;FA;;;BA)"
	if userSID != "S-1-5-18" && userSID != "S-1-5-32-544" {
		cleanSDDL += "(A;;FA;;;" + userSID + ")"
	}
	setProtectedSDDL(t, path, cleanSDDL)

	data, _, err := ReadTrustedFileWith(path, 1024, TrustOptions{DenyForeignRead: true, DenyForeignWrite: true})
	if err != nil {
		t.Fatalf("ReadTrustedFileWith rejected clean restricted file: %v", err)
	}
	if string(data) != "secret-key" {
		t.Fatalf("unexpected data %q", data)
	}
}
