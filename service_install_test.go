package main

import (
	"errors"
	"testing"
)

// TestInstallPersistsValidatedArgv pins the regression that made every
// Windows service unstartable: platformInstallService received the array
// installServiceArgs validated and never forwarded it to mgr.CreateService, so
// the SCM ImagePath was a bare executable path. The hook must receive exactly
// the array that was validated (including -svc=run), because install-time
// validation is only meaningful if the validated value is the value the SCM
// replays on every start.
func TestInstallPersistsValidatedArgv(t *testing.T) {
	saveFlags(t)
	t.Setenv("LINK_PING_METRICS_USER", "")
	t.Setenv("LINK_PING_METRICS_PASS", "")
	t.Setenv("LINK_PING_ECHO_SECRET", "")
	t.Setenv("LINK_PING_ECHO_SECRET_OLD", "")
	*flMode = "server"
	*flAllow = "127.0.0.1"
	*flAllowFromTargets = false
	*flTarget, *flTargets = "", ""

	want, err := installServiceArgs()
	if err != nil {
		t.Fatalf("installServiceArgs refused a valid config: %v", err)
	}

	var got []string
	calls := 0
	if err := runServiceInstall(func(args []string) error {
		calls++
		got = append([]string(nil), args...)
		return nil
	}); err != nil {
		t.Fatalf("runServiceInstall: %v", err)
	}
	if calls != 1 {
		t.Fatalf("platform install called %d times, want 1", calls)
	}
	if len(got) != len(want) {
		t.Fatalf("hook received %v, validated array was %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("hook arg %d = %q, validated %q (full: %v vs %v)", i, got[i], want[i], got, want)
		}
	}
	if len(got) == 0 || got[len(got)-1] != "-svc=run" {
		t.Errorf("persisted argument array must end with -svc=run, got %v", got)
	}
	// The array identity is the regression guard. A real CLI run also carries
	// every flag the operator set (flag.Visit); under `go test` the visited
	// set is the test binary's own flags, so asserting a specific -allow here
	// would only pin test-runner bookkeeping, not the install path.
}

// TestInstallHookFailureIsReported keeps the failure path honest: a platform
// error must propagate so handleService exits non-zero (and the SCM recovery
// ladder can fire) instead of printing "Service installed.".
func TestInstallHookFailureIsReported(t *testing.T) {
	saveFlags(t)
	t.Setenv("LINK_PING_METRICS_USER", "")
	t.Setenv("LINK_PING_METRICS_PASS", "")
	t.Setenv("LINK_PING_ECHO_SECRET", "")
	t.Setenv("LINK_PING_ECHO_SECRET_OLD", "")
	*flMode = "server"
	*flAllow = "127.0.0.1"
	*flAllowFromTargets = false
	*flTarget, *flTargets = "", ""

	boom := errors.New("access denied")
	err := runServiceInstall(func([]string) error { return boom })
	if !errors.Is(err, boom) {
		t.Fatalf("runServiceInstall error = %v, want it to wrap %v", err, boom)
	}
}
