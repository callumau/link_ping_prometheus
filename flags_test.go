package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// pi-lens-ignore: go-test-functions
func TestResolveMetricsAuth(t *testing.T) {
	saveFlags(t)
	// Isolate from any real environment.
	t.Setenv("LINK_PING_METRICS_USER", "")
	t.Setenv("LINK_PING_METRICS_PASS", "")

	reset := func() { *flMetricsBasicAuthUser, *flMetricsBasicAuthPass = "", "" }

	reset()
	if u, p, err := resolveMetricsAuth(); err != nil || u != "" || p != "" {
		t.Errorf("empty pair must be allowed (auth disabled): %q/%q, err %v", u, p, err)
	}

	reset()
	*flMetricsBasicAuthUser = "u"
	if u, p, err := resolveMetricsAuth(); err == nil {
		t.Errorf("user without password must error (would enable empty-password auth), got %q/%q", u, p)
	}

	reset()
	*flMetricsBasicAuthPass = "p"
	if u, p, err := resolveMetricsAuth(); err == nil {
		t.Errorf("password without user must error, got %q/%q", u, p)
	}

	reset()
	*flMetricsBasicAuthUser = "u"
	*flMetricsBasicAuthPass = "p"
	if u, p, err := resolveMetricsAuth(); err != nil || u != "u" || p != "p" {
		t.Errorf("valid pair: got %q/%q, err %v", u, p, err)
	}

	// Flags win over env; env fills in when flags are empty.
	reset()
	t.Setenv("LINK_PING_METRICS_USER", "envu")
	t.Setenv("LINK_PING_METRICS_PASS", "envp")
	if u, p, err := resolveMetricsAuth(); err != nil || u != "envu" || p != "envp" {
		t.Errorf("env fallback: got %q/%q, err %v", u, p, err)
	}

	*flMetricsBasicAuthUser = "flagu"
	if _, _, err := resolveMetricsAuth(); err == nil {
		t.Error("partial flag with env fallback must error with atomic pair semantics (flag+env hybrid not allowed)")
	}
	*flMetricsBasicAuthPass = "flagp"
	if u, p, err := resolveMetricsAuth(); err != nil || u != "flagu" || p != "flagp" {
		t.Errorf("full flag pair should win over env: got %q/%q, err %v", u, p, err)
	}
}

// captureWarns swaps the default slog logger for a buffered text handler so
// tests can assert startup warnings fired. Restores the previous default on
// cleanup (tests are sequential: no parallel test may rely on the default
// logger while the buffer is installed).

// TestResolveMetricsAuthRejectsColonInUser pins the Basic-auth username
// constraint (F6): r.BasicAuth() splits the header at the FIRST colon, so a
// username containing ':' is unreachable — every request 401s and the
// endpoint is permanently locked out. The validation applies to the flag and
// the env fallback alike; an empty user keeps meaning "auth disabled".
func TestResolveMetricsAuthRejectsColonInUser(t *testing.T) {
	saveFlags(t)
	t.Setenv("LINK_PING_METRICS_USER", "")
	t.Setenv("LINK_PING_METRICS_PASS", "")

	for _, tc := range []struct {
		name    string
		user    string
		pass    string
		wantErr bool
	}{
		{"colon in user", "ad:min", "p", true},
		{"plain user", "admin", "p", false},
		{"empty user (auth disabled)", "", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			*flMetricsBasicAuthUser = tc.user
			*flMetricsBasicAuthPass = tc.pass
			_, _, err := resolveMetricsAuth()
			if tc.wantErr && err == nil {
				t.Errorf("user %q must be rejected", tc.user)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("user %q must be accepted, got %v", tc.user, err)
			}
		})
	}

	// Env-derived username gets the same check (flags win only when set).
	t.Run("colon in env user", func(t *testing.T) {
		*flMetricsBasicAuthUser, *flMetricsBasicAuthPass = "", ""
		t.Setenv("LINK_PING_METRICS_USER", "ad:min")
		t.Setenv("LINK_PING_METRICS_PASS", "p")
		if _, _, err := resolveMetricsAuth(); err == nil {
			t.Error("env user containing ':' must be rejected")
		}
	})
}

// TestWarnIgnoredFlags pins the silent-ingestion-gap warnings (F7): flags
// with no effect in the selected mode (and the -targets/-target precedence)
// must log a one-line slog.Warn at startup, and must NOT warn in the modes
// where the flags are actually consumed.

// pi-lens-ignore: go-test-functions
func TestFlagDefaultInt(t *testing.T) {
	// Pins the helper against the current flag defaults so the
	// "rotation flags require -log-file" guard keeps working.
	for name, want := range map[string]int{
		"log-file-max-mb":      *flLogMaxSize,
		"log-file-max-backups": *flLogMaxBackups,
		"log-file-max-age":     *flLogMaxAge,
	} {
		got, err := flagDefaultInt(name)
		if err != nil {
			t.Errorf("flagDefaultInt(%s): %v", name, err)
			continue
		}
		if got != want {
			t.Errorf("flagDefaultInt(%s) = %d, want %d", name, got, want)
		}
	}
}

// TestHardenLogSink pins the log-sink invariant: the agent enforces 0600 on
// the configured log file regardless of provenance (a file placed at the
// configured path by someone else keeps its wider mode while the agent
// appends topology into it) and refuses symlinked log paths (a symlink can
// redirect topology-bearing lines into a file another local user controls).
// Windows: os.Stat reports 0666 for every file regardless of ACL and
// f.Chmod only toggles the read-only attribute, so the POSIX perm-bit
// assertions are unimplementable there — hardenLogSink instead restricts
// the file's DACL (logacl_windows.go) and the Windows branches below assert
// that DACL directly: protected from inheritance, full access only for
// SYSTEM, Administrators and the process token user.

// TestHardenLogSink pins the log-sink invariant: the agent enforces 0600 on
// the configured log file regardless of provenance (a file placed at the
// configured path by someone else keeps its wider mode while the agent
// appends topology into it) and refuses symlinked log paths (a symlink can
// redirect topology-bearing lines into a file another local user controls).
// Windows: os.Stat reports 0666 for every file regardless of ACL and
// f.Chmod only toggles the read-only attribute, so the POSIX perm-bit
// assertions are unimplementable there — hardenLogSink instead restricts
// the file's DACL (logacl_windows.go) and the Windows branches below assert
// that DACL directly: protected from inheritance, full access only for
// SYSTEM, Administrators and the process token user.
func TestHardenLogSink(t *testing.T) {
	t.Run("creates missing file at 0600", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "agent.log")
		if _, err := hardenLogSink(path); err != nil {
			t.Fatalf("hardenLogSink: %v", err)
		}
		if runtime.GOOS == "windows" {
			// Stat reports 0666 on Windows regardless of the create mode, so
			// pin the Windows equivalent: the created file's DACL is the
			// restricted protected set, not the parent directory's inherited
			// grant.
			verifyLogDACLRestricted(t, path)
			return
		}
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat created file: %v", err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("created file mode = %04o, want 0600", fi.Mode().Perm())
		}
	})

	t.Run("repairs pre-existing wide mode", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "agent.log")
		if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
			t.Fatalf("seed file: %v", err)
		}
		repaired, err := hardenLogSink(path)
		if err != nil {
			t.Fatalf("hardenLogSink: %v", err)
		}
		if !repaired {
			t.Error("repaired = false, want true")
		}
		// The content assertion is platform-independent: a repair, perm-bit
		// or DACL alike, must not touch what is already in the file.
		if data, err := os.ReadFile(path); err != nil || string(data) != "x" {
			t.Errorf("file content changed: %q, err %v", data, err)
		}
		if runtime.GOOS == "windows" {
			// The repair on Windows is a DACL restriction, not perm bits —
			// pin exactly that.
			verifyLogDACLRestricted(t, path)
			return
		}
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat repaired file: %v", err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("repaired file mode = %04o, want 0600", fi.Mode().Perm())
		}
	})

	t.Run("keeps a compliant file untouched", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "agent.log")
		if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
			t.Fatalf("seed file: %v", err)
		}
		if runtime.GOOS == "windows" {
			// "compliant" is not observable through os.Stat (always 0666), so
			// pre-apply the log DACL by running hardenLogSink once; the DACL
			// comparison in restrictLogDACL must then report the second run as
			// compliant — pins the idempotence of that comparison.
			if _, err := hardenLogSink(path); err != nil {
				t.Fatalf("pre-limit hardenLogSink: %v", err)
			}
			repaired, err := hardenLogSink(path)
			if err != nil {
				t.Fatalf("hardenLogSink: %v", err)
			}
			if repaired {
				t.Error("repaired = true for an already-restricted DACL")
				// Dump both tables so the runner log pins the exact
				// field the template-vs-file comparison disagrees on.
				dumpLogDACLTables(t, path)
			}
			verifyLogDACLRestricted(t, path)
			return
		}
		repaired, err := hardenLogSink(path)
		if err != nil {
			t.Fatalf("hardenLogSink: %v", err)
		}
		if repaired {
			t.Error("repaired = true for an already-0600 file")
		}
	})

	t.Run("refuses symlink", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "outside.log")
		if err := os.WriteFile(target, []byte("keep"), 0o644); err != nil {
			t.Fatalf("seed target: %v", err)
		}
		path := filepath.Join(dir, "agent.log")
		if err := os.Symlink(target, path); err != nil {
			t.Skipf("symlink not supported here: %v", err)
		}
		_, err := hardenLogSink(path)
		if err == nil {
			t.Fatal("hardenLogSink accepted a symlinked log path")
		}
		if !strings.Contains(err.Error(), "symlink") {
			t.Errorf("error does not mention symlink: %v", err)
		}
		// The linked target must be untouched and the symlink itself must
		// survive (no replace-with-regular-file fallback).
		if data, err := os.ReadFile(target); err != nil || string(data) != "keep" {
			t.Errorf("linked target changed: %q, err %v", data, err)
		}
		if fi, err := os.Lstat(path); err != nil || fi.Mode()&os.ModeSymlink == 0 {
			t.Errorf("symlink replaced or missing: %v, %v", fi, err)
		}
	})
}

// TestAbsolutizeFlagValue pins the service-install argument rewriting: path
// flags must be persisted absolute (the SCM's working directory is unrelated
// to the install directory), while every other flag - notably the integer
// log-rotation flags - must be persisted verbatim. Absolutizing
// log-file-max-mb=50 produced "C:\cwd\50", so the service exited 2 at
// flag.Parse with stderr discarded under the SCM: a crash loop with no
// diagnostics at all.

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

// TestReadyzSemantics pins the liveness/readiness split: /healthz stays
// always-200, while /readyz must report 503 for a client-side agent that has
// never held a working socket (DNS outage, firewall) - alive but probing
// nothing is exactly the failure mode an orchestrator must be able to see.
// socket_age_seconds is set only after a successful dial, so it is the signal
// the gate reads.
