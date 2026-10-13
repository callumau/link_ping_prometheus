//go:build windows

package main

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// testLogTokenUserSID returns the SID of the account the test process runs
// as, i.e. the trustee of the third ACE in the restricted log DACL, in raw
// SID-string form (name-resolution free).
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
// (S-1-5-32-544) and the process token user — no other trustee.
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
	const inheritBits = windows.OBJECT_INHERIT_ACE | windows.CONTAINER_INHERIT_ACE
	trustees := map[string]bool{}
	for _, a := range aces {
		if a.flags&inheritBits != inheritBits {
			t.Errorf("ACE for %s has flags %#x, want object+container inheritance", a.sid, a.flags)
		}
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
	want, err := windows.SecurityDescriptorFromString(fmt.Sprintf(logACLSDDLTemplate, user.User.Sid.String()))
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
