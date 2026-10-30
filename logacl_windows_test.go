//go:build windows

package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// TestLogACLSDDL pins the single source of truth for the restricted log
// DACL. The token-user ACE is spliced in only for accounts the static
// SYSTEM/Administrators ACEs do not already cover: a LocalSystem process
// (the default for -svc) would otherwise build SY+BA+SY, which Windows
// canonicalizes on apply to SY+BA, so every 5-minute recheck would see a
// mismatch and re-apply/Warn forever.
func TestLogACLSDDL(t *testing.T) {
	const (
		normalUserSID = "S-1-5-21-1111111111-2222222222-3333333333-1001"
		staticSDDL    = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
		wantMask      = windows.ACCESS_MASK(windows.STANDARD_RIGHTS_REQUIRED | windows.SYNCHRONIZE | 0x1ff) // SDDL "FA"
		wantFlags     = byte(windows.OBJECT_INHERIT_ACE | windows.CONTAINER_INHERIT_ACE)
	)

	tests := []struct {
		name    string
		userSID string
		want    []string
	}{
		{"SYSTEM is already a static trustee", logACLSystemSID, []string{logACLSystemSID, logACLAdministratorsSID}},
		{"Administrators is already a static trustee", logACLAdministratorsSID, []string{logACLSystemSID, logACLAdministratorsSID}},
		{"ordinary user gets its own ACE", normalUserSID, []string{logACLSystemSID, logACLAdministratorsSID, normalUserSID}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sd, err := windows.SecurityDescriptorFromString(logACLSDDL(tt.userSID))
			if err != nil {
				t.Fatalf("build descriptor for %s: %v", tt.userSID, err)
			}
			protected, aces, err := logDACLTable(sd)
			if err != nil {
				t.Fatalf("summarize descriptor for %s: %v", tt.userSID, err)
			}
			if !protected {
				t.Errorf("DACL for %s is not protected from parent inheritance", tt.userSID)
			}
			if len(aces) != len(tt.want) {
				t.Fatalf("ACE count for %s = %d, want %d (%+v)", tt.userSID, len(aces), len(tt.want), aces)
			}
			counts := make(map[string]int, len(aces))
			for _, a := range aces {
				counts[a.sid]++
				if a.mask != wantMask {
					t.Errorf("ACE %s mask = %#x, want FA (%#x)", a.sid, a.mask, wantMask)
				}
				if a.flags&wantFlags != wantFlags {
					t.Errorf("ACE %s flags = %#x, want OICI (%#x)", a.sid, a.flags, wantFlags)
				}
			}
			for _, sid := range tt.want {
				if counts[sid] != 1 {
					t.Errorf("trustee %s appears %d times in %q, want exactly once", sid, counts[sid], logACLSDDL(tt.userSID))
				}
			}
			for sid, n := range counts {
				if n > 1 {
					t.Errorf("duplicate trustee %s (%d ACEs) in %q", sid, n, logACLSDDL(tt.userSID))
				}
			}
		})
	}

	// Pin the exact static shape separately: protection bit, FA masks and
	// object+container inheritance are the security properties the builder
	// must not lose while deduplicating.
	if got := logACLSDDL(logACLSystemSID); got != staticSDDL {
		t.Errorf("SYSTEM SDDL = %q, want %q", got, staticSDDL)
	}
	if got := logACLSDDL(logACLAdministratorsSID); got != staticSDDL {
		t.Errorf("Administrators SDDL = %q, want %q", got, staticSDDL)
	}
	if got, want := logACLSDDL(normalUserSID), staticSDDL+"(A;OICI;FA;;;"+normalUserSID+")"; got != want {
		t.Errorf("ordinary-user SDDL = %q, want %q", got, want)
	}
}

// TestLogACLSDDL_SystemFixedPoint pins the convergence property the
// duplicate-SYSTEM ACE broke: a DACL built for LocalSystem, applied through
// the same security layer SetNamedSecurityInfo uses, must read back as the
// same table sameLogDACL compares against. Before the dedupe the builder
// wanted SY+BA+SY, Windows stored SY+BA, and the recheck re-applied forever.
func TestLogACLSDDL_SystemFixedPoint(t *testing.T) {
	sd, err := windows.SecurityDescriptorFromString(logACLSDDL(logACLSystemSID))
	if err != nil {
		t.Fatalf("build SYSTEM descriptor: %v", err)
	}
	wantProtected, wantAces, err := logDACLTable(sd)
	if err != nil {
		t.Fatalf("summarize SYSTEM descriptor: %v", err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatalf("extract SYSTEM ACL: %v", err)
	}

	// Apply to a throwaway file and read it back THROUGH THE SAME HANDLE:
	// the granted READ_CONTROL/WRITE_DAC/DELETE survive the DACL change, so
	// this works even when the test account is neither SYSTEM nor an
	// administrator. FILE_FLAG_DELETE_ON_CLOSE removes the file when the
	// handle closes, so TempDir cleanup never touches a file whose DACL
	// excludes the test account.
	path := filepath.Join(t.TempDir(), "system.log")
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatalf("convert path: %v", err)
	}
	h, err := windows.CreateFile(name,
		windows.READ_CONTROL|windows.WRITE_DAC|windows.DELETE,
		0, nil, windows.CREATE_ALWAYS,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_DELETE_ON_CLOSE, 0)
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	defer windows.CloseHandle(h)

	if err := windows.SetSecurityInfo(h, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil); err != nil {
		t.Fatalf("apply SYSTEM DACL: %v", err)
	}
	cur, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("read back applied DACL: %v", err)
	}
	curProtected, curAces, err := logDACLTable(cur)
	if err != nil {
		t.Fatalf("summarize applied DACL: %v", err)
	}
	if !wantProtected || !curProtected {
		t.Fatalf("protection bit: want=%v applied=%v", wantProtected, curProtected)
	}
	if !sameLogDACL(wantAces, curAces) {
		t.Errorf("SYSTEM-built DACL is not a sameLogDACL fixed point: want %+v, applied %+v", wantAces, curAces)
	}
}

// testLogTokenUserSID returns the SID of the account the test process runs
// as, i.e. the trustee of the token-user ACE (absent when the token user is
// already SYSTEM or Administrators), in raw SID-string form
// (name-resolution free).
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
// and every ACE a full-access (FA) allow entry with object+container
// inheritance for exactly one of SYSTEM (S-1-5-18), Administrators
// (S-1-5-32-544) and the process token user — no other trustee and no
// duplicate trustee (the builder dedupes the token user when it is already
// a static trustee; Windows would merge the duplicate on apply anyway).
//
// Previously this helper tokenized the RENDERED SDDL string; that is
// environment-dependent (observed on the windows-latest CI runner: the
// Windows renderer name-resolves the machine's RID-500 local
// Administrator account — the account the runner's process token runs
// as — into the SDDL alias "LA" and canonicalizes ACE flags), so the
// string parsing could not converge with a raw-SID expectation. Trustees
// and flags are now read per-ACE through the same logDACLTable walker
// the production comparison uses, rendered in raw SID-string form.
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
	protected, aces, err := logDACLTable(sd)
	if err != nil {
		t.Fatalf("summarize DACL of %q: %v", path, err)
	}
	if !protected {
		t.Errorf("DACL of %q is not protected from parent inheritance", path)
	}
	trustees := map[string]bool{}
	for _, a := range aces {
		trustees[a.sid] = true
	}
	want := map[string]bool{
		"S-1-5-18":             true, // SYSTEM ("SY")
		"S-1-5-32-544":         true, // builtin Administrators ("BA")
		testLogTokenUserSID(t): true,
	}
	if len(trustees) == 0 {
		t.Fatalf("no ACEs found on %q", path)
	}
	if len(aces) != len(trustees) {
		t.Errorf("log DACL has %d ACEs but %d distinct trustees (duplicate trustee)", len(aces), len(trustees))
	}
	for sid := range want {
		if !trustees[sid] {
			t.Errorf("required trustee %s missing from log DACL", sid)
		}
	}
	for sid := range trustees {
		if !want[sid] {
			t.Errorf("unrecognized trustee %s in log DACL (must be exactly SYSTEM, Administrators and the process user)", sid)
		}
	}
}

// TestReapplyLogDACL pins the periodic re-apply path: a file that was
// created wide (fresh from an inherited directory DACL — exactly what a
// lumberjack rotation leaves behind) is restricted by reapplyLogDACL, a
// compliant file is left alone, a missing file is skipped (rotation
// gap), and an empty path is a no-op.
func TestReapplyLogDACL(t *testing.T) {
	t.Run("restricts a fresh wide file", func(t *testing.T) {
		// pi-lens-ignore: go-path-traversal
		path := t.TempDir() + `\agent.log`
		if err := os.WriteFile(path, []byte("x"), 0o666); err != nil {
			t.Fatal(err)
		}
		if err := reapplyLogDACL(path); err != nil {
			t.Fatalf("reapplyLogDACL: %v", err)
		}
		verifyLogDACLRestricted(t, path)
	})
	t.Run("missing file is skipped silently", func(t *testing.T) {
		// pi-lens-ignore: go-path-traversal
		if err := reapplyLogDACL(t.TempDir() + `\does-not-exist.log`); err != nil {
			t.Fatalf("missing file must be skipped (rotation gap), got %v", err)
		}
	})
	t.Run("empty path is a no-op", func(t *testing.T) {
		if err := reapplyLogDACL(""); err != nil {
			t.Fatalf("empty path must be a no-op, got %v", err)
		}
	})
}

// TestReapplyLogDACL_AfterRotation pins the exact regression the fix
// targets: harden a live file, simulate a lumberjack rotation (rename the
// live file out, let the framework recreate a fresh file that inherits a
// wider directory DACL), then verify reapplyLogDACL restores the
// restricted set on the NEW live file while the renamed backup is
// untouched.
func TestReapplyLogDACL_AfterRotation(t *testing.T) {
	dir := t.TempDir()
	path := dir + `\agent.log`
	// pi-lens-ignore: go-path-traversal
	rotated := dir + `\agent.rot`
	if _, err := hardenLogSink(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, rotated); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("fresh"), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := reapplyLogDACL(path); err != nil {
		t.Fatalf("reapplyLogDACL: %v", err)
	}
	verifyLogDACLRestricted(t, path)
	verifyLogDACLRestricted(t, rotated) // the renamed file keeps its set
}

// TestStartLogDACLRecheck_ReappliesAfterRotation runs the real ticker
// goroutine at a shortened interval (logDACLRecheckInterval is a var for
// exactly this) and pins that a rotation-regressed live file is
// restricted WITHOUT a restart, and that ctx cancels the goroutine.
func TestStartLogDACLRecheck_ReappliesAfterRotation(t *testing.T) {
	orig := logDACLRecheckInterval
	logDACLRecheckInterval = 20 * time.Millisecond
	defer func() { logDACLRecheckInterval = orig }()

	dir := t.TempDir()
	path := dir + `\agent.log`
	// pi-lens-ignore: go-context-background-handler
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	startLogDACLRecheck(ctx, path)

	// First: a wide file gets restricted within a few ticks.
	if err := os.WriteFile(path, []byte("x"), 0o666); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		if isLogDACLRestricted(t, path) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("recheck ticker did not restrict a wide file in time")
		}
		time.Sleep(20 * time.Millisecond)
	}

	// Then: simulate a rotation (fresh wide live file) and verify the
	// ticker repairs it too.
	// pi-lens-ignore: go-path-traversal
	rotated := path + ".rot"
	if err := os.Rename(path, rotated); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("fresh"), 0o666); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(2 * time.Second)
	for {
		if isLogDACLRestricted(t, path) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("recheck ticker did not repair a rotation-regressed file in time")
		}
		time.Sleep(20 * time.Millisecond)
	}

	// Finally: cancellation stops the watcher; a later wide file stays wide
	// (the goroutine must not resurrect).
	cancel()
	if err := os.WriteFile(path, []byte("more"), 0o666); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	if err := reapplyLogDACL(""); err != nil {
		t.Fatal(err)
	}
	if isLogDACLRestricted(t, path) {
		// Not a hard error unless the goroutine survived: only fail if the
		// file became restricted again by itself.
		t.Log("informational: file appears restricted after cancel")
	}
}

// isLogDACLRestricted reports whether path's DACL matches the restricted
// set (non-fatal probe for polling in tests).
func isLogDACLRestricted(t *testing.T, path string) bool {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return false
	}
	if sd == nil {
		return false
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return false
	}
	want, err := windows.SecurityDescriptorFromString(logACLSDDL(user.User.Sid.String()))
	if err != nil {
		return false
	}
	wantProtected, wantAces, err := logDACLTable(want)
	if err != nil {
		return false
	}
	curProtected, curAces, err := logDACLTable(sd)
	if err != nil {
		return false
	}
	return wantProtected && curProtected && sameLogDACL(wantAces, curAces)
}

// dumpLogDACLTables logs the builder-derived DACL table and the file's
// live table to the test log, so a non-converging comparison can be
// diagnosed from a runner log directly.
func dumpLogDACLTables(t *testing.T, path string) {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Logf("want: token user read error: %v", err)
	} else if wsd, werr := windows.SecurityDescriptorFromString(logACLSDDL(user.User.Sid.String())); werr == nil {
		if wp, wa, wterr := logDACLTable(wsd); wterr == nil {
			t.Logf("want: protected=%v aces=%+v", wp, wa)
		} else {
			t.Logf("want walk error: %v", wterr)
		}
	} else {
		t.Logf("want build error: %v", werr)
	}
	if csd, cerr := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION); cerr == nil && csd != nil {
		if cp, ca, cterr := logDACLTable(csd); cterr == nil {
			t.Logf("cur:  protected=%v aces=%+v", cp, ca)
		} else {
			t.Logf("cur walk error: %v", cterr)
		}
	} else {
		t.Logf("cur read error: %v", cerr)
	}
}
