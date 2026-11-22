package service

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"link_ping_prometheus/internal/config"
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
	*config.Default.Mode = "server"
	*config.Default.Allow = "127.0.0.1"
	*config.Default.AllowFromTargets = false
	*config.Default.Target, *config.Default.Targets = "", ""

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
// error must propagate so Handle exits non-zero (and the SCM recovery
// ladder can fire) instead of printing "Service installed.".
func TestInstallHookFailureIsReported(t *testing.T) {
	saveFlags(t)
	t.Setenv("LINK_PING_METRICS_USER", "")
	t.Setenv("LINK_PING_METRICS_PASS", "")
	t.Setenv("LINK_PING_ECHO_SECRET", "")
	t.Setenv("LINK_PING_ECHO_SECRET_OLD", "")
	*config.Default.Mode = "server"
	*config.Default.Allow = "127.0.0.1"
	*config.Default.AllowFromTargets = false
	*config.Default.Target, *config.Default.Targets = "", ""

	boom := errors.New("access denied")
	err := runServiceInstall(func([]string) error { return boom })
	if !errors.Is(err, boom) {
		t.Fatalf("runServiceInstall error = %v, want it to wrap %v", err, boom)
	}
}

// TestAbsolutizeFlagValue pins the service-install argument rewriting: path
// flags must be persisted absolute (the SCM's working directory is unrelated
// to the install directory), while every other flag - notably the integer
// log-rotation flags - must be persisted verbatim. Absolutizing
// log-file-max-mb=50 produced "C:\cwd\50", so the service exited 2 at
// flag.Parse with stderr discarded under the SCM: a crash loop with no
// diagnostics at all.
func TestAbsolutizeFlagValue(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	absLog := filepath.Join(cwd, "logs", "agent.log")

	tests := []struct{ name, flag, value, want string }{
		{"int size flag is untouched", "log-file-max-mb", "50", "50"},
		{"int backups flag is untouched", "log-file-max-backups", "0", "0"},
		{"int age flag is untouched", "log-file-max-age", "28", "28"},
		{"relative log path is absolutized", "log-file", filepath.Join("logs", "agent.log"), absLog},
		{"relative targets path is absolutized", "targets", "targets.json", filepath.Join(cwd, "targets.json")},
		{"already absolute path is unchanged", "metrics-tls-cert", absLog, absLog},
		{"empty path value stays empty", "log-file", "", ""},
		{"non-path flag is untouched", "mode", "client", "client"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := absolutizeFlagValue(tc.flag, tc.value); got != tc.want {
				t.Errorf("absolutizeFlagValue(%q, %q) = %q, want %q", tc.flag, tc.value, got, tc.want)
			}
		})
	}
}
