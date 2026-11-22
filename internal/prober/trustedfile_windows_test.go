//go:build windows

package prober

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

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
	psCmd := `$p = $env:LPP_TEST_KEY; $a = Get-Acl -LiteralPath $p; ` +
		`$a.SetSecurityDescriptorSddlForm('D:P(A;;FA;;;SY)(A;;FA;;;BA)(XA;;FR;;;WD;(Title=="x"))'); ` +
		`Set-Acl -LiteralPath $p -AclObject $a`
	cmd := exec.Command("powershell.exe", "-NoProfile", "-Command", psCmd)
	cmd.Env = append(os.Environ(), "LPP_TEST_KEY="+path)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("set conditional ACE SDDL failed: %v\n%s", err, out)
	}

	if _, _, err := ReadTrustedFileWith(path, 1024, TrustOptions{DenyForeignRead: true}); err == nil {
		t.Fatal("ReadTrustedFileWith accepted a file with a conditional/callback allow ACE for Everyone")
	}

	// Restrict to SYSTEM + Administrators + current process user and verify it passes.
	psClean := `$p = $env:LPP_TEST_KEY; $u = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value; ` +
		`$a = Get-Acl -LiteralPath $p; ` +
		`$a.SetSecurityDescriptorSddlForm("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;$u)"); ` +
		`Set-Acl -LiteralPath $p -AclObject $a`
	cmd2 := exec.Command("powershell.exe", "-NoProfile", "-Command", psClean)
	cmd2.Env = append(os.Environ(), "LPP_TEST_KEY="+path)
	if out, err := cmd2.CombinedOutput(); err != nil {
		t.Fatalf("set clean SDDL failed: %v\n%s", err, out)
	}

	data, _, err := ReadTrustedFileWith(path, 1024, TrustOptions{DenyForeignRead: true, DenyForeignWrite: true})
	if err != nil {
		t.Fatalf("ReadTrustedFileWith rejected clean restricted file: %v", err)
	}
	if string(data) != "secret-key" {
		t.Fatalf("unexpected data %q", data)
	}
}
