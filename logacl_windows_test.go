//go:build windows

package main

import (
	"reflect"
	"regexp"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// testLogTokenUserSID returns the SID of the account the test process runs
// as, i.e. the trustee of the third ACE in the restricted log DACL.
func testLogTokenUserSID(t *testing.T) string {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatalf("read token user: %v", err)
	}
	return user.User.Sid.String()
}

// verifyLogDACLRestricted asserts that path's DACL is the restricted
// protected set from logacl_windows.go: protected from parent inheritance,
// no deny entries, and every ACE a full-access (FA) allow entry for exactly
// one of SYSTEM (SY), Administrators (BA) and the process token user — no
// Everyone/Authenticated Users/Builtin Users trustee. Trustees are accepted
// in both SDDL-alias and raw-SID form; every unrecognized trustee fails the
// check.
func verifyLogDACLRestricted(t *testing.T, path string) {
	t.Helper()
	// Read by path so the check covers what any other process sees.
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("read DACL of %q: %v", path, err)
	}
	if sd == nil {
		t.Fatalf("no security descriptor on %q", path)
	}
	control, _, err := sd.Control()
	if err != nil {
		t.Fatalf("read DACL control bits of %q: %v", path, err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		t.Errorf("DACL of %q is not protected from parent inheritance (control bits %#x)", path, control)
	}
	if dacl, _, err := sd.DACL(); err != nil || dacl == nil {
		t.Fatalf("DACL of %q missing: acl=%v err=%v", path, dacl, err)
	}
	// SDDL ACE: (type;flags;rights;object-guid;inherit-guid;SID)
	ace := regexp.MustCompile(`\(([^();]*;[^();]*;[^();]*;[^();]*;[^();]*;[^()]+)\)`)
	trustees := map[string]bool{}
	sddl := sd.String()
	for _, m := range ace.FindAllStringSubmatch(sddl, -1) {
		fields := strings.Split(m[1], ";")
		if fields[0] != "A" {
			t.Errorf("non-allow ACE %q in the log DACL", m[1])
			continue
		}
		if fields[2] != "FA" {
			t.Errorf("ACE rights %q, want full file access FA: %q", fields[2], m[1])
		}
		switch fields[5] {
		case "SY", "S-1-5-18":
			trustees["SY"] = true
		case "BA", "S-1-5-32-544":
			trustees["BA"] = true
		default:
			trustees[fields[5]] = true
		}
	}
	if len(trustees) == 0 {
		t.Fatalf("no ACEs parsed from %q: %q", path, sddl)
	}
	want := map[string]bool{"SY": true, "BA": true, testLogTokenUserSID(t): true}
	if !reflect.DeepEqual(trustees, want) {
		t.Errorf("log DACL trustees = %v, want exactly %v (sddl %q)", trustees, want, sddl)
	}
}
